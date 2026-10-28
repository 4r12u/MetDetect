"""Reproducible local corpus survey/curation; sample archives are never executed.

Run from the project root with the project's Python environment. Network reads
are limited to a frozen public package-name reference, never sample URLs.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pypi_metadata_detector.common import DEFAULTS, digest, normalize_name, valid_name
from pypi_metadata_detector.phase1_metadata_extraction.extract import extract_sample
from pypi_metadata_detector.phase2_metadata_analysis.signals import pair_signals, SIGNAL_KEYS, edit_distance

SOURCE = Path(r'D:\Study_cybersecurity\Research_notes\build_Dataset\OSS\tonghopnguondataset')
WORK = ROOT / 'outputs' / 'dataset-build-v1.2-20261025'
DS = ROOT / 'Dataset'
STAMP = '2026-10-25'
TARGET_URL = 'https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages-30-days.min.json'

def now():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def save(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)

def csvread(path):
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))

def csvwrite(path, rows, fields=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)

def bounded_path(base, relative):
    base = Path(base).resolve()
    result = (base / relative).resolve()
    if not result.is_relative_to(base) or result.is_symlink():
        raise ValueError('unsafe_local_path')
    return result

class ReferenceRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urlparse(newurl)
        if u.scheme != 'https' or u.hostname != 'raw.githubusercontent.com':
            raise ValueError('unapproved_reference_redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def targets():
    path = WORK / 'sources' / 'top-pypi-packages-30-days.min.json'
    if not path.exists():
        req = Request(TARGET_URL, headers={'User-Agent': 'AIC211-metadata-dataset-audit/1.2'})
        with build_opener(ReferenceRedirects()).open(req, timeout=45) as response:
            raw = response.read(5_000_001)
        if len(raw) > 5_000_000:
            raise ValueError('reference_size_limit')
        obj = json.loads(raw)
        assert isinstance(obj['rows'], list)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        save(WORK / 'sources' / 'reference_provenance.json', {
            'url': TARGET_URL, 'retrieved_at': now(), 'sha256': sha(path),
            'selection': 'all published rows; frozen before candidate selection or model evaluation',
            'claim': 'name-only SpellBound-inspired screening; not full weekly-popularity SpellBound',
            'snapshot_metadata': {k:v for k,v in obj.items() if k != 'rows'}})
    data = load(path)
    names = sorted({normalize_name(r['project']) for r in data['rows'] if valid_name(r.get('project'))})
    return names

class NameIndex:
    """Index candidate pairs, then use the tool's actual six signal functions.

    Covers all six rules and Levenshtein <= 1 without a quadratic corpus scan.
    Does not compute an unrelated nearest target for non-candidates.
    """
    def __init__(self, names):
        self.names = set(names)
        self.deleted = defaultdict(set)
        self.swaps = defaultdict(set)
        self.words = defaultdict(set)
        for t in names:
            for i in range(len(t)):
                self.deleted[t[:i]+t[i+1:]].add(t)
            for i in range(len(t)-1):
                self.swaps[t[:i]+t[i+1]+t[i]+t[i+2:]].add(t)
            if '-' in t:
                self.words[tuple(sorted(t.split('-')))].add(t)

    def match(self, name):
        n = normalize_name(name)
        if n in self.names:
            return {'exact_reference': True, 'candidate': False, 'matches': []}
        possible = set(self.deleted.get(n, ())) | set(self.swaps.get(n, ()))
        possible.update(self.words.get(tuple(sorted(n.split('-'))), ()))
        for i in range(len(n)):
            shorter = n[:i]+n[i+1:]
            if shorter in self.names:
                possible.add(shorter)
            possible.update(self.deleted.get(shorter, ()))
        m = re.search(r'-?\d+$', n)
        if m:
            # Every possible numeric suffix, including targets ending in digits.
            for i in range(m.start(), len(n)):
                base = n[:i].rstrip('-')
                if base in self.names:
                    possible.add(base)
        matches = []
        for t in sorted(possible):
            flags = pair_signals(n, t)
            distance = edit_distance(n, t, 1)
            if any(flags.values()) or distance <= 1:
                matches.append({'target': t, 'signals': [k for k,v in flags.items() if v],
                                'distance': edit_distance(n,t)})
        return {'exact_reference': False, 'candidate': bool(matches), 'matches': matches}

def survey():
    WORK.mkdir(parents=True, exist_ok=True)
    capture_source_batches()
    names = targets()
    index = NameIndex(names)
    metadata = SOURCE / 'metadata' / 'collection'
    inventory = []
    candidates = []
    benign = []
    evidence_file = metadata / 'artifact_evidence.jsonl'
    print('Reading source evidence inventory...', flush=True)
    with evidence_file.open(encoding='utf-8') as f:
        for line in f:
            e = json.loads(line)
            row = e['row']
            entry = {'sha256':row['SHA256'], 'relative_path':e['relative_path'],
                     'label':row['label'], 'source':row['source'], 'version':row.get('version',''),
                     'year':row.get('year'), 'filename':row['name'],
                     'year_basis':e.get('year_basis'), 'year_evidence':e.get('year_evidence'),
                     'sources':e['sources']}
            if row['label'] == 'benign':
                benign.append(entry)
            elif e['relative_path'].startswith('PyPI_MalRegistry/artifacts/'):
                source = next((s for s in e['sources'] if s['source']=='malregistry'), None)
                if source:
                    entry['name'] = source['name']
                    entry['source_path'] = source['source_path']
                    entry['match'] = index.match(source['name'])
                    inventory.append(entry)
                    if entry['match']['candidate']:
                        candidates.append(entry)
    save(WORK/'malregistry_inventory.json', inventory)
    save(WORK/'typosquatting_candidates.json', candidates)
    save(WORK/'benign_pool.json', benign)
    cols = ['sha256','name','version','filename','relative_path','exact_reference','spellbound_candidate','candidate_targets','spellbound_signals','min_distance','is_typosquatting','review_status']
    exports=[]
    for e in inventory:
        matches=e['match']['matches']
        exports.append({**e,'exact_reference':e['match']['exact_reference'],
                        'spellbound_candidate':e['match']['candidate'],
                        'candidate_targets':';'.join(m['target'] for m in matches),
                        'spellbound_signals':';'.join(sorted({s for m in matches for s in m['signals']})),
                        'min_distance':min((m['distance'] for m in matches),default=''),
                        'is_typosquatting':'unknown','review_status':'heuristic_screen_only'})
    csvwrite(WORK/'malregistry_name_survey.csv',exports,cols)
    csvwrite(WORK/'typosquatting_candidates.csv',[r for r in exports if r['spellbound_candidate']],cols)
    physical=[]
    for p in (SOURCE/'PyPI_MalRegistry'/'artifacts').rglob('*'):
        if p.is_file() and not p.is_symlink() and p.name.lower().endswith(('.whl','.zip','.tar.gz','.tgz','.tar.bz2')):
            physical.append(p.relative_to(SOURCE).as_posix())
    unindexed=sorted(set(physical)-{e['relative_path'] for e in inventory})
    csvwrite(WORK/'malregistry_unindexed_paths.csv',[{'relative_path':p} for p in unindexed],['relative_path'])
    summary={'created_at':now(),'reference_targets':len(names),'inventory_unique_archives':len(inventory),
             'inventory_unique_packages':len({normalize_name(e['name']) for e in inventory}),
             'physical_archive_paths':len(physical),'unindexed_archive_paths':len(unindexed),
             'spellbound_candidates_archives':len(candidates),
             'spellbound_candidates_packages':len({normalize_name(e['name']) for e in candidates}),
             'signals':dict(Counter(s for e in candidates for s in {s for m in e['match']['matches'] for s in m['signals']})),
             'benign_pool':dict(Counter(e['source'] for e in benign)),
             'evidence_input_sha256':sha(evidence_file),
             'note':'Heuristic candidate count is not a confirmed typosquatting count.'}
    save(WORK/'survey_summary.json',summary)
    print(json.dumps(summary,ensure_ascii=True),flush=True)

def capture_source_batches():
    definitions=[('be6b04e2a5ac02feebe5c4efc331d0aa801285ed','2024-03-31',431),
        ('d19c554b36d4957322ae503ae5d415947491462c','2024-04-04',45),
        ('7627b5417d4dfc986a76125efb7927745cc2e284','2024-04-16',56),
        ('0b07d398777626dcb96848978d18c96781e8dbf4','2024-04-21',34),
        ('fd97f1faa01a19585f726691c802683b78f1a35e','2024-05-01',1154)]
    result=[]
    gitdir=SOURCE/'metadata/git/malregistry.git'
    for commit,date,count in definitions:
        proc=subprocess.run(['git','--git-dir',str(gitdir),'diff-tree','--no-commit-id',
             '--raw','--no-abbrev','--diff-filter=A','-r',commit],capture_output=True,text=True,check=True,timeout=60)
        blobs={}
        for line in proc.stdout.splitlines():
            if '\t' in line:
                info,path=line.split('\t',1)
                if path.lower().endswith(('.whl','.zip','.tar.gz','.tgz')):
                    blobs[path]=info.split()[-2]
        result.append({'commit':commit,'date':date,'readme_claimed_packages':count,
            'added_artifacts':len(blobs),'paths':list(blobs),'added_blobs':blobs,
            'evidence_ref':'https://github.com/lxyeternal/pypi_malregistry/commit/'+commit,
            'readme_ref':'https://github.com/lxyeternal/pypi_malregistry/blob/5f2592d2d750a1beb68e8ed1a5a63fcd1905899c/README.md',
            'claim_scope':'Source-reported update batch, not independent behavior verification.'})
    save(WORK/'sources/typosquatting_source_batches.json',result)
    return result

def batch_annotations():
    batches=load(WORK/'sources/typosquatting_source_batches.json')
    if 'added_blobs' not in batches[0]:
        batches=capture_source_batches()
    head={r['path']:r['blob'] for r in load(SOURCE/'metadata/source_snapshots/malregistry_tree.json')['files']}
    mapping={}
    for b in batches:
        # Only batches whose claim is reconciled with the addition list. The
        # May batch counts projects, April batches count archive additions.
        aligned=(len({p.split('/')[0] for p in b['paths']})==b['readme_claimed_packages']
                 or len(b['paths'])==b['readme_claimed_packages'])
        if aligned:
            for p in b['paths']:
                if head.get(p)==b['added_blobs'].get(p):
                    mapping[p]=b
    return mapping

def inspect_entry(entry):
    path=bounded_path(SOURCE,entry['relative_path'])
    result={'entry':entry,'checked_at':now()}
    try:
        if path.stat().st_size > 64*1024*1024:
            raise ValueError('new_archive_size_limit_64MiB')
        actual=sha(path)
        if actual!=entry['sha256']:
            raise ValueError('source_archive_hash_mismatch')
        result['record']=extract_sample({'sample_id':'sha256:'+actual,'path':str(path)},DEFAULTS)
        result['bytes']=path.stat().st_size
    except Exception as exc:
        result['record']={'status':'input_error','reason':type(exc).__name__+': '+str(exc)[:200]}
    return result

def base_exclusions(original_rows):
    previous=load(ROOT/'outputs/Dataset-28be240e1d/extraction.json')
    bad={r['sample_id']:r['status'] for r in previous['samples'] if r['status']!='ok'}
    exceptions=SOURCE/'metadata/collection/label_exceptions.jsonl'
    with exceptions.open(encoding='utf-8') as f:
        for line in f:
            e=json.loads(line)
            if e['reason']=='conflicting_labels':
                bad['sha256:'+e['SHA256']]='conflicting_public_source_labels'
    excluded=[{**r,'exclusion_reason':bad[r['sample_id']],
               'disposition':'Original archive retained on disk; excluded from active v1.2 manifests.'}
              for r in original_rows if r['sample_id'] in bad]
    assert len(excluded)==4,'re-audit the intended base exclusions'
    save(WORK/'base_exclusions.json',excluded)
    csvwrite(WORK/'base_exclusions.csv',excluded)
    return {r['sample_id'] for r in excluded}

def prepare():
    """Read sources and write a proposed selection, without changing Dataset."""
    backup=ROOT/'Dataset_backups'/'v1.1-before-v1.2-20261025'
    original=backup if (backup/'dataset.csv').exists() else DS
    old=csvread(original/'dataset.csv')
    assert len(old)==2292, 'expected the pinned 2292-sample source dataset'
    excluded_ids=base_exclusions(old)
    old=[r for r in old if r['sample_id'] not in excluded_ids]
    old_names={r['normalized_name'] for r in old}
    old_hashes={r['sha256'] for r in old}
    old_index=load(ROOT/'outputs/Dataset-28be240e1d/extraction.json')
    assert {r['sample_id'] for r in old}<={r['sample_id'] for r in old_index['samples']}
    old_md={r['metadata_digest'] for r in old_index['samples'] if r.get('metadata_digest') and r['sample_id'] not in excluded_ids}
    inv=load(WORK/'malregistry_inventory.json')
    batches=batch_annotations()
    for e in inv:
        e['source_typo_batch']=batches.get(e['source_path'])
    # Evidence comes before detector agreement; this avoids building only an
    # easy set of positives that the same detector is guaranteed to find.
    pool=[e for e in inv if e.get('source_typo_batch') or e['match']['candidate']]
    pool.sort(key=lambda e:(not bool(e.get('source_typo_batch')),
                            not e['match']['candidate'],digest('seed42|'+e['sha256'])))
    confirmed=[e for e in inv if e.get('source_typo_batch')]
    csvwrite(WORK/'typosquatting_source_reported.csv',[
        {'sha256':e['sha256'],'name':e['name'],'version':e['version'],
         'relative_path':e['relative_path'],'is_typosquatting':'true',
         'typosquatting_label_basis':'source_reported_update_batch',
         'evidence_ref':e['source_typo_batch']['evidence_ref'],
         'readme_ref':e['source_typo_batch']['readme_ref'],
         'spellbound_candidate':e['match']['candidate'],
         'candidate_targets':';'.join(m['target'] for m in e['match']['matches']),
         'target_package':'','review_status':'source_batch_mapping_verified'} for e in confirmed])
    benign=load(WORK/'benign_pool.json')
    # Assign each multi-source artifact once, preferring independently authored
    # public datasets; labels remain inherited source labels, not safety proof.
    buckets=defaultdict(list)
    for e in benign:
        if e['sha256'] in old_hashes:
            continue
        names={s['source'].lower() for s in e['sources']}
        key=next((x for x in ('omcbench','oscar','pypiguard','pyguard') if x in names),None)
        if key:
            e['chosen_label_source']=key
            buckets[key].append(e)
    for items in buckets.values():
        items.sort(key=lambda e:digest('seed42|'+e['sha256']))
    benign_order=[]
    keys=sorted(buckets)
    i=0
    while any(i<len(buckets[k]) for k in keys):
        for k in keys:
            if i<len(buckets[k]):
                benign_order.append(buckets[k][i])
        i+=1
    needs={'malicious':2000-sum(r['label']=='malicious' for r in old),
           'benign':2000-sum(r['label']=='benign' for r in old)}
    selected=[]; skipped=[]; names=set(old_names); hashes=set(old_hashes); metadata=set(old_md)
    # Names seen with a malicious label are conservatively held out of the new
    # benign selection; no implication is made about other versions' behavior.
    malicious_names={normalize_name(e['name']) for e in inv}
    cachepath=WORK/'candidate_inspections.jsonl'
    cache={}
    if cachepath.exists():
        with cachepath.open(encoding='utf-8') as f:
            for line in f:
                r=json.loads(line);cache[r['entry']['sha256']]=r
    for label,entries in (('malicious',pool),('benign',benign_order)):
        count=0; cursor=0; attempted=0
        while count<needs[label] and cursor<len(entries):
            batch=entries[cursor:cursor+48];cursor+=len(batch)
            pending=[e for e in batch if e['sha256'] not in hashes and e['sha256'] not in cache
                     and (label!='malicious' or normalize_name(e['name']) not in names)]
            with ThreadPoolExecutor(max_workers=6) as executor:
                checked=list(executor.map(inspect_entry,pending))
            with cachepath.open('a',encoding='utf-8') as f:
                for result in checked:
                    cache[result['entry']['sha256']]=result
                    f.write(json.dumps(result,ensure_ascii=True)+'\n')
            for e in batch:
                if count>=needs[label]:
                    break
                if e['sha256'] in hashes:
                    continue
                result=cache.get(e['sha256'])
                if not result:
                    continue
                attempted+=1
                rec=result['record']
                reason=None
                if rec['status']!='ok':
                    reason=rec['status']+': '+rec.get('reason','')
                else:
                    n=normalize_name(rec['metadata']['Name'])
                    if n in names:
                        reason='package_name_already_selected'
                    elif rec['metadata_digest'] in metadata:
                        reason='duplicate_metadata'
                    elif label=='benign' and n in malicious_names:
                        reason='name_also_present_in_malicious_source'
                    elif label=='malicious' and n!=normalize_name(e['name']):
                        reason='source_name_differs_from_metadata'
                if reason:
                    skipped.append({'sha256':e['sha256'],'label':label,'relative_path':e['relative_path'],'reason':reason})
                    continue
                result['entry']=e  # enrich a cached result with the current batch annotation
                result['label']=label
                selected.append(result)
                hashes.add(e['sha256']);names.add(n);metadata.add(rec['metadata_digest']);count+=1
            print(f'Validated additions {label}: {count}/{needs[label]} | inspected {attempted}',flush=True)
        if count!=needs[label]:
            raise ValueError(f'insufficient_eligible_{label}: {count}/{needs[label]}')
    save(WORK/'selection_plan.json',{'created_at':now(),'base_samples':len(old),
         'target_samples':4000,'additions':dict(Counter(r['label'] for r in selected)),
         'source_reported_typo_archives':len(confirmed),
         'source_reported_typo_packages':len({normalize_name(e['name']) for e in confirmed}),
         'selected':selected})
    csvwrite(WORK/'selection_exclusions.csv',skipped,['sha256','label','relative_path','reason'])
    print('Selection ready:',dict(Counter(r['label'] for r in selected)),flush=True)

def typo_annotation(entry, match):
    batch=entry.get('source_typo_batch') if entry else None
    return {'is_typosquatting':'true' if batch else 'unknown',
            'target_package':'',
            'typosquatting_evidence_ref':batch['readme_ref']+';'+batch['evidence_ref'] if batch else '',
            'typosquatting_label_basis':'source_reported_update_batch' if batch else 'not_established',
            'typosquatting_review_status':'source_batch_mapping_verified' if batch else 'not_reviewed',
            'spellbound_candidate':str(bool(match['candidate'])).lower(),
            'candidate_target_package':';'.join(m['target'] for m in match['matches']),
            'spellbound_signals':';'.join(sorted({s for m in match['matches'] for s in m['signals']})),
            'review_notes':('Source labels the update batch as typosquatting; archive membership checked. '
                            'Target remains unconfirmed; no independent behavior verification.' if batch else
                            'Similarity is a detector observation, not a ground-truth label.')}

def commit():
    """Copy validated additions and atomically replace each synchronized table.

    Original tables are backed up once; original sample bytes are never changed.
    A commit marker is only written after all table identities have been checked.
    """
    plan=load(WORK/'selection_plan.json')
    backup=ROOT/'Dataset_backups'/'v1.1-before-v1.2-20261025'
    if not (backup/'backup_complete.json').exists():
        assert len(csvread(DS/'dataset.csv'))==2292
        backup.mkdir(parents=True,exist_ok=True)
        hashes={}
        for p in DS.iterdir():
            if p.is_file():
                shutil.copy2(p,backup/p.name)
                hashes[p.name]=sha(p)
                assert sha(backup/p.name)==hashes[p.name]
        save(backup/'backup_complete.json',{'created_at':now(),'files':hashes,
             'note':'Original archives remain untouched in Dataset/samples.'})
    original={name:csvread(backup/name) for name in
              ('dataset.csv','artifact.csv','label.csv','groups.csv','splits.csv','manifest.csv')}
    assert len(original['dataset.csv'])==2292
    excluded_ids=base_exclusions(original['dataset.csv'])
    original={name:[r for r in table if r['sample_id'] not in excluded_ids] for name,table in original.items()}
    rows=original['dataset.csv']; artifacts=original['artifact.csv']; labels=original['label.csv']
    groups=original['groups.csv']; splits=original['splits.csv']
    index=NameIndex(targets()); batches=batch_annotations()
    inv={e['sha256']:e for e in load(WORK/'malregistry_inventory.json')}
    for e in inv.values():
        e['source_typo_batch']=batches.get(e['source_path'])
    label_by_id={r['sample_id']:r for r in labels}
    provenance=[]
    annfields=None
    for row in rows:
        e=inv.get(row['sha256']) if row['label']=='malicious' else None
        ann=typo_annotation(e,index.match(row['package_name']))
        row.update(ann);annfields=list(ann)
        row['dataset_version']='v1.2'
        row['metadata_status']='pending_fresh_validation'
        lab=label_by_id[row['sample_id']];lab.update(ann)
        if row['label']=='malicious' and e:
            lab['label_status']='source_repository_membership_verified'
            lab['review_status']='source_reference_reviewed'
            row['label_status']=lab['label_status'];row['review_status']=lab['review_status']
            lab['label_source']='["PyPI_MalRegistry"]'
            lab['label_source_refs']=json.dumps(e['sources'],ensure_ascii=True)
            provenance.append({'sample_id':row['sample_id'],'label':row['label'],'origin':'v1.1_retained',
                               'artifact_evidence':e})
        else:
            provenance.append({'sample_id':row['sample_id'],'label':row['label'],'origin':'v1.1_retained',
                               'label_source':lab['label_source'],'label_source_refs':lab['label_source_refs'],
                               'limitation':'Inherited source claim; original ancillary files may be unavailable.'})
    pretty={'omcbench':'OMCBench','oscar':'OSCAR','pypiguard':'PyPiGuard','pyguard':'PyGuard'}
    for number,result in enumerate(plan['selected'],1):
        e=result['entry'];rec=result['record'];md=rec['metadata'];label=result['label']
        n=normalize_name(md['Name']);h=e['sha256'];key='sha256:'+h
        filename=Path(e['relative_path']).name
        if filename!=Path(filename).name or not filename or filename in ('.','..'):
            raise ValueError('invalid_destination_filename')
        relative=Path('samples')/label/n/h[:12]/filename
        dest=bounded_path(DS,relative)
        source=bounded_path(SOURCE,e['relative_path'])
        if dest.exists():
            assert sha(dest)==h,'destination_collision'
        else:
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,dest)
            assert sha(dest)==h,'copied_archive_hash_mismatch'
        chosen='malregistry' if label=='malicious' else e['chosen_label_source']
        source_name='PyPI_MalRegistry' if label=='malicious' else pretty[chosen]
        ann=typo_annotation(e,index.match(md['Name']))
        labelrefs=[s for s in e['sources'] if s['source'].lower()==chosen]
        assert labelrefs,'selected label source must have actual evidence'
        ann['review_notes']+=(' Benign label inherited from the public dataset; not independently behavior-verified.'
                              if label=='benign' else '')
        group='group:'+digest('pypi:'+n)
        common={'sample_id':key,'label':label,'label_status':'source_repository_membership_verified' if label=='malicious'
                else 'inherited_public_dataset_label','review_status':'source_reference_reviewed',
                'scope_status':'in_scope_metadata_present'}
        row={**common,'package_name':md['Name'],'normalized_name':n,'version':md['Version'],
             'split':'','split_group_id':group,'sha256':h,'filename':filename,'source':source_name,
             'artifact_bytes':result['bytes'],'artifact_path':relative.as_posix(),
             'audit_statistics_only':'True','dataset_version':'v1.2','origin':'v1.2_added',
             'parse_status':'not_run_metadata_only','metadata_status':'ok','metadata_digest':rec['metadata_digest'],**ann}
        rows.append(row)
        artifacts.append({'sample_id':key,'Name':md['Name'],'normalized_name':n,'version':md['Version'],
             'ecosystem':'pypi','source':source_name,'publish_year':e.get('year',''),
             'publish_time':'','publish_year_status':e.get('year_basis','unknown'),
             'filename':filename,'artifact_type':'bdist_wheel' if filename.lower().endswith('.whl') else 'source_archive',
             'sha256':h,'artifact_path':relative.as_posix(),'artifact_bytes':result['bytes'],'hash_verified':'True',
             'source_url':('https://github.com/lxyeternal/pypi_malregistry/blob/5f2592d2d750a1beb68e8ed1a5a63fcd1905899c/'+e['source_path']
                           if label=='malicious' else e.get('year_evidence','')),
             'metadata_url':'','source_refs':json.dumps(e['sources'],ensure_ascii=True),
             'acquired_at':'','verified_at':result['checked_at'],
             'local_source_path':str(source),'year_evidence_ref':e.get('year_evidence',''),
             'collection_note':'Copied from local source corpus; no new package download.'})
        labels.append({**common,'label_source':json.dumps([source_name]),'label_source_refs':json.dumps(labelrefs,ensure_ascii=True),
                       'behavior_evidence_ref':'','reviewed_at':now(),**ann})
        groups.append({'sample_id':key,'project_group':'pypi:'+n,'python_tree_sha256':'','ast_tree_sha256':'',
                       'fingerprint_sha256':rec['metadata_digest'],'fingerprint_policy':'canonical_raw_metadata_sha256',
                       'split_group_id':group,'grouping_version':'v1.2-metadata-and-byte-tree',
                       'grouping_reason':'normalized_project; fresh whole-Python-byte-tree audit follows',
                       'group_evidence_ref':'audit/validation.json','file_inventory_ref':''})
        splits.append({'sample_id':key,'name':md['Name'],'status':'not_run_metadata_only','split':'',
                       'split_group_id':group,'seed':42,'split_version':'v1.2-r1'})
        provenance.append({'sample_id':key,'label':label,'origin':'v1.2_added','artifact_evidence':e,
                           'copied_from':str(source),'copied_to':relative.as_posix(),
                           'sha256_verified':h,'label_evidence_refs':labelrefs})
        if number%200==0:
            print(f'Copied verified archives {number}/{len(plan["selected"])}',flush=True)
    assert len(rows)==4000 and Counter(r['label'] for r in rows)=={'benign':2000,'malicious':2000}
    assert len({r['sample_id'] for r in rows})==4000
    assert len({r['normalized_name'] for r in rows})==4000
    # Preserve base splits and allocate additions to the remaining class totals.
    # Fresh byte-tree groups are reconciled in validate before final completion.
    for label in ('benign','malicious'):
        additions=[r for r in rows if r['label']==label and not r['split']]
        additions.sort(key=lambda r:digest('seed42-split|'+r['sample_id']))
        cur=Counter(r['split'] for r in rows if r['label']==label and r['split'])
        cursor=0
        for split,total in (('train',1400),('validation',300),('test',300)):
            for row in additions[cursor:cursor+total-cur[split]]:
                row['split']=split
            cursor+=total-cur[split]
        assert cursor==len(additions)
    rowmap={r['sample_id']:r for r in rows}
    for s in splits:
        s['split']=rowmap[s['sample_id']]['split'];s['split_version']='v1.2-r1'
    tables={'dataset.csv':rows,'artifact.csv':artifacts,'label.csv':labels,'groups.csv':groups,'splits.csv':splits,
            'manifest.csv':[{'sample_id':r['sample_id'],'path':r['artifact_path'],'label':r['label'],'split':r['split']} for r in rows]}
    for filename,items in tables.items():
        assert {r['sample_id'] for r in items}==set(rowmap)
        staged=WORK/'staged_tables'/filename
        csvwrite(staged,items)
    # All candidate tables are complete before replacing any live table.
    for filename in tables:
        shutil.copy2(WORK/'staged_tables'/filename,DS/filename)
    (DS/'provenance').mkdir(exist_ok=True)
    with (DS/'provenance/artifact_sources.jsonl').open('w',encoding='utf-8') as f:
        for r in provenance:
            f.write(json.dumps(r,ensure_ascii=True)+'\n')
    source_dir=DS/'provenance/sources';source_dir.mkdir(parents=True,exist_ok=True)
    for name in ('top-pypi-packages-30-days.min.json','reference_provenance.json','typosquatting_source_batches.json'):
        shutil.copy2(WORK/'sources'/name,source_dir/name)
    snapshots=SOURCE/'metadata/source_snapshots'
    for source,name in (('malregistry','MalRegistry_README.md'),('omcbench','OMCBench_README.md'),('pyguard','PyGuard_README.md')):
        p=snapshots/source/'README.md'
        if p.exists():
            shutil.copy2(p,source_dir/name)
    for name in ('oscar_record.json','pyguard_record.json','malregistry_tree.json','omcbench_tree.json','pypiguard_tree.json'):
        shutil.copy2(snapshots/name,source_dir/name)
    for name in ('malregistry_name_survey.csv','typosquatting_candidates.csv','typosquatting_source_reported.csv',
                 'malregistry_unindexed_paths.csv','selection_exclusions.csv','survey_summary.json'):
        shutil.copy2(WORK/name,DS/'provenance'/name)
    (DS/'audit').mkdir(exist_ok=True)
    shutil.copy2(WORK/'base_exclusions.csv',DS/'audit/base_exclusions.csv')
    save(DS/'build_config.json',{'dataset_version':'v1.2','built_at':now(),'seed':42,'target_samples':4000,
         'balance_target':{'benign':2000,'malicious':2000},'base_samples_retained_active':2292-len(excluded_ids),
         'base_samples_excluded_active':len(excluded_ids),'original_archives_untouched':True,
         'additions':plan['additions'],'selection_policy':'source-reported typosquatting prioritized, independent of detector match; benign source round-robin; unique package names and metadata',
         'label_policy':'Inherited source labels; source references reviewed; no independent behavior verification.',
         'typosquatting_policy':'true only for source-reported update batches reconciled to addition lists; heuristic-only samples unknown; targets remain unconfirmed',
         'feature_policy':'Annotations, labels, sources, hashes, paths and groups are audit only, never classifier inputs.',
         'split_policy':'Initial base splits preserved; fresh byte-tree reconciliation may merge groups and reassign splits.',
         'execution_policy':'No sample execution/import/install/build; no payload/dependency download.',
         'reference':'provenance/sources/reference_provenance.json','previous_tables':str(backup),
         'status':'pending_fresh_validation'})
    save(WORK/'commit_complete.json',{'at':now(),'total':len(rows),'backup':str(backup)})
    print('Dataset tables updated; fresh validation is required.',flush=True)

def byte_tree(path):
    """Path-independent multiset of complete .py byte hashes, audit only.

    No AST, imports, package installation, extraction, or execution. This is
    deliberately not described as semantic/campaign deduplication.
    """
    hashes=[];total=0
    def add(name,stream,size):
        nonlocal total
        if size>8*1024*1024 or total+size>64*1024*1024:
            raise ValueError('byte_tree_budget_exceeded')
        raw=stream.read(size+1)
        if len(raw)!=size:
            raise ValueError('byte_tree_member_size_mismatch')
        total+=size;hashes.append(hashlib.sha256(raw).hexdigest())
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            members=z.infolist()
            if len(members)>DEFAULTS['max_archive_members']:
                raise ValueError('byte_tree_member_limit')
            if sum(m.file_size for m in members)>DEFAULTS['max_unpacked_bytes']:
                raise ValueError('byte_tree_unpacked_limit')
            for m in members:
                if not m.is_dir() and m.filename.lower().endswith('.py'):
                    with z.open(m) as f:
                        add(m.filename,f,m.file_size)
    else:
        with tarfile.open(path,mode='r|*') as t:
            unpacked=0
            for i,m in enumerate(t,1):
                unpacked+=max(m.size,0)
                if i>DEFAULTS['max_archive_members']:
                    raise ValueError('byte_tree_member_limit')
                if unpacked>DEFAULTS['max_unpacked_bytes']:
                    raise ValueError('byte_tree_unpacked_limit')
                if m.isfile() and m.name.lower().endswith('.py'):
                    with t.extractfile(m) as f:
                        add(m.name,f,m.size)
    return {'python_bytes_tree_sha256':digest(sorted(hashes)) if hashes else '',
            'python_files_hashed':len(hashes),'python_bytes_hashed':total,'byte_tree_status':'ok' if hashes else 'no_python_files'}

def validate_one(row):
    p=bounded_path(DS,row['artifact_path'])
    result={'sample_id':row['sample_id'],'expected_sha256':row['sha256'],'checked_at':now()}
    try:
        h=sha(p);result['actual_sha256']=h
        if h!=row['sha256']:
            raise ValueError('dataset_archive_hash_mismatch')
        result['record']=extract_sample({'sample_id':row['sample_id'],'path':str(p)},DEFAULTS)
        try:
            result.update(byte_tree(p))
        except Exception as exc:
            result.update({'python_bytes_tree_sha256':'','byte_tree_status':'unavailable',
                           'byte_tree_reason':type(exc).__name__+': '+str(exc)[:120]})
    except Exception as exc:
        result['record']={'status':'input_error','reason':type(exc).__name__+': '+str(exc)[:200]}
    return result

def validate():
    rows=csvread(DS/'dataset.csv')
    assert len(rows)==4000
    results=[]
    audit=DS/'audit';audit.mkdir(exist_ok=True)
    with ThreadPoolExecutor(max_workers=6) as executor, (audit/'metadata_inventory.jsonl').open('w',encoding='utf-8') as f:
        for i,result in enumerate(executor.map(validate_one,rows),1):
            results.append(result)
            f.write(json.dumps(result,ensure_ascii=True)+'\n')
            if i%250==0:
                print(f'Fresh archive/hash/metadata/byte-tree validation {i}/4000',flush=True)
    resmap={r['sample_id']:r for r in results}
    assert all(r.get('actual_sha256')==r['expected_sha256'] for r in results)
    old=csvread(ROOT/'Dataset_backups/v1.1-before-v1.2-20261025/dataset.csv')
    excluded_ids={r['sample_id'] for r in load(WORK/'base_exclusions.json')}
    assert {r['sample_id'] for r in old}-excluded_ids<={r['sample_id'] for r in rows}
    assert not excluded_ids & {r['sample_id'] for r in rows}
    metadata=defaultdict(list)
    parent={r['sample_id']:r['sample_id'] for r in rows}
    def find(k):
        while parent[k]!=k:
            parent[k]=parent[parent[k]];k=parent[k]
        return k
    def union(a,b):
        a,b=find(a),find(b)
        if a!=b:
            parent[max(a,b)]=min(a,b)
    maps=[{}, {}, {}, {}]
    for row in rows:
        key=row['sample_id'];result=resmap[key];rec=result['record']
        row['metadata_status']=rec['status'];row['metadata_digest']=rec.get('metadata_digest','')
        row['python_bytes_tree_sha256']=result.get('python_bytes_tree_sha256','')
        if rec['status']=='ok':
            assert normalize_name(rec['metadata']['Name'])==row['normalized_name']
            metadata[rec['metadata_digest']].append(row)
        for m,value in zip(maps,(row['normalized_name'],row['split_group_id'],row['metadata_digest'],row['python_bytes_tree_sha256'])):
            if value:
                if value in m:
                    union(key,m[value])
                else:
                    m[value]=key
    assert all(len(v)==1 for v in metadata.values()),'duplicate_raw_metadata_found'
    components=defaultdict(list)
    for row in rows:
        components[find(row['sample_id'])].append(row)
    # Deterministic group allocation, using class counts only. No predictions,
    # detector outcomes, or test scores are consulted. Large groups go first.
    counts={s:Counter() for s in ('train','validation','test')}
    goals={'train':1400,'validation':300,'test':300}
    ordered=sorted(components.values(),key=lambda g:(-len(g),digest('seed42-group|'+min(r['sample_id'] for r in g))))
    split_changes=[]
    for component in ordered:
        sizes=Counter(r['label'] for r in component)
        def score(split):
            # Minimize change in normalized squared class deviation.
            return sum(((counts[split][lab]+n-goals[split])/goals[split])**2-
                       ((counts[split][lab]-goals[split])/goals[split])**2 for lab,n in sizes.items())
        split=min(goals,key=score)
        group_id='group:'+digest(sorted(r['sample_id'] for r in component))
        counts[split].update(sizes)
        for row in component:
            if row['split']!=split:
                split_changes.append({'sample_id':row['sample_id'],'old_split':row['split'],'new_split':split,
                                      'reason':'fresh grouped allocation with whole-Python-byte-tree identity'})
            row['split']=split;row['split_group_id']=group_id
    assert all(counts[s][lab]>0 for s in goals for lab in ('benign','malicious'))
    rowmap={r['sample_id']:r for r in rows}
    splits=csvread(DS/'splits.csv');groups=csvread(DS/'groups.csv')
    for s in splits:
        r=rowmap[s['sample_id']];s.update({'split':r['split'],'split_group_id':r['split_group_id'],
            'split_version':'v1.2-r2-byte-tree','metadata_status':r['metadata_status']})
    for g in groups:
        r=rowmap[g['sample_id']];v=resmap[g['sample_id']]
        g.update({'split_group_id':r['split_group_id'],'python_bytes_tree_sha256':r['python_bytes_tree_sha256'],
                  'metadata_digest':r['metadata_digest'],'byte_tree_status':v['byte_tree_status'],
                  'grouping_version':'v1.2-byte-tree-r2','grouping_reason':'transitive normalized-name, prior-group, exact-metadata, exact whole-Python-file-byte-multiset',
                  'group_evidence_ref':'audit/validation.json'})
    for name,table in (('dataset.csv',rows),('splits.csv',splits),('groups.csv',groups)):
        csvwrite(DS/name,table)
    csvwrite(DS/'manifest.csv',[{'sample_id':r['sample_id'],'path':r['artifact_path'],'label':r['label'],'split':r['split']} for r in rows])
    csvwrite(audit/'split_changes.csv',split_changes,['sample_id','old_split','new_split','reason'])
    failures=[{'sample_id':r['sample_id'],'name':r['package_name'],'label':r['label'],'status':r['metadata_status'],
               'reason':resmap[r['sample_id']]['record'].get('reason','')} for r in rows if r['metadata_status']!='ok']
    csvwrite(audit/'metadata_exclusions.csv',failures,['sample_id','name','label','status','reason'])
    def overlaps(key):
        d=defaultdict(set)
        for r in rows:
            if r.get(key):
                d[r[key]].add(r['split'])
        return sum(len(v)>1 for v in d.values())
    overlap_counts={k:overlaps(k) for k in ('sha256','normalized_name','metadata_digest','split_group_id','python_bytes_tree_sha256')}
    assert not any(overlap_counts.values())
    ids={r['sample_id'] for r in rows}
    for name in ('artifact.csv','label.csv','groups.csv','splits.csv','manifest.csv'):
        table=csvread(DS/name)
        assert len(table)==4000 and {r['sample_id'] for r in table}==ids
    manifest={r['sample_id']:r for r in csvread(DS/'manifest.csv')}
    labeltable={r['sample_id']:r for r in csvread(DS/'label.csv')}
    assert all(manifest[r['sample_id']]['label']==r['label']==labeltable[r['sample_id']]['label'] and
               manifest[r['sample_id']]['split']==r['split'] and manifest[r['sample_id']]['path']==r['artifact_path'] for r in rows)
    summary={'validated_at':now(),'total':len(rows),'labels':dict(Counter(r['label'] for r in rows)),
             'unique_names':len({r['normalized_name'] for r in rows}),'unique_archive_hashes':len({r['sha256'] for r in rows}),
             'archives_hash_verified':len(results),'original_archives_untouched':True,
             'base_samples_retained_active':len(old)-len(excluded_ids),'base_samples_excluded_active':len(excluded_ids),
             'metadata_status':dict(Counter(r['metadata_status'] for r in rows)),
             'eligible_by_label':dict(Counter(r['label'] for r in rows if r['metadata_status']=='ok')),
             'split_counts':{s:dict(counts[s]) for s in goals},
             'eligible_split_counts':{s:dict(Counter(r['label'] for r in rows if r['split']==s and r['metadata_status']=='ok')) for s in goals},
             'cross_split_overlaps':overlap_counts,'exact_metadata_duplicate_groups':sum(len(v)>1 for v in metadata.values()),
             'byte_tree_status':dict(Counter(r['byte_tree_status'] for r in results)),
             'group_count':len(components),'multi_sample_groups':sum(len(v)>1 for v in components.values()),
             'largest_group':max(map(len,components.values())),
             'source_reported_typosquatting':sum(r['is_typosquatting']=='true' for r in rows),
             'typosquatting_unknown':sum(r['is_typosquatting']=='unknown' for r in rows),
             'spellbound_candidates_by_label':dict(Counter(r['label'] for r in rows if r['spellbound_candidate']=='true')),
             'additions_by_source':dict(Counter(r['source'] for r in rows if r['origin']=='v1.2_added')),
             'archive_bytes':sum(int(r['artifact_bytes']) for r in rows),'metadata_exclusions':failures,
             'limitations':['Inherited labels, no independent behavior verification.',
                 'Source batch annotation does not establish an individual target package.',
                 'Byte-identical whole Python trees are grouped; semantic/campaign deduplication is not claimed.',
                 'Expanded dataset contains previously evaluated samples; not a new independent benchmark.']}
    save(audit/'validation.json',summary)
    config=load(DS/'build_config.json');config.update({'status':'validated','validation':'audit/validation.json',
         'split_policy':'seed42 deterministic allocation by class counts after transitive normalized-name, prior-group, metadata and whole-Python-byte-tree grouping',
         'split_version':'v1.2-r2-byte-tree','split_counts':summary['split_counts']})
    save(DS/'build_config.json',config)
    save(WORK/'validation.json',summary)
    print(json.dumps(summary,ensure_ascii=True),flush=True)

def git_blob(path):
    h=hashlib.sha1()  # Git object identity only; SHA256 remains the integrity hash.
    h.update(('blob '+str(path.stat().st_size)+'\0').encode('ascii'))
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()

def finish():
    """Reconcile source evidence, verify CLI contracts, and issue final reports."""
    from pypi_metadata_detector.phase2_metadata_analysis.signals import field_state, STATE_FIELDS
    from pypi_metadata_detector.phase3_preprocessing.dataset import assign_splits
    from pypi_metadata_detector.workflow import collect_samples
    rows=csvread(DS/'dataset.csv');rowmap={r['sample_id']:r for r in rows}
    labels=csvread(DS/'label.csv');labelmap={r['sample_id']:r for r in labels}
    summary=load(DS/'audit/validation.json');survey_stats=load(WORK/'survey_summary.json')
    assert summary['metadata_status']=={'ok':4000},'final active dataset must be fully metadata eligible'
    batches=batch_annotations()
    inv=load(WORK/'malregistry_inventory.json')
    invhash={e['sha256']:e for e in inv}
    membership=[]
    for row in rows:
        if row['is_typosquatting']!='true':
            continue
        e=invhash[row['sha256']];b=batches[e['source_path']]
        actual=git_blob(bounded_path(DS,row['artifact_path']))
        expected=b['added_blobs'][e['source_path']]
        assert actual==expected,'typosquatting batch bytes changed: '+row['sample_id']
        membership.append({'sample_id':row['sample_id'],'name':row['package_name'],'version':row['version'],
             'source_path':e['source_path'],'source_batch_date':b['date'],'source_commit':b['commit'],
             'actual_git_blob':actual,'added_commit_git_blob':expected,'content_membership_verified':'true',
             'is_typosquatting':'true','label_basis':'source_reported_update_batch',
             'target_package':'','evidence_ref':b['evidence_ref'],'readme_ref':b['readme_ref']})
        row['typosquatting_review_status']='source_batch_content_verified'
        labelmap[row['sample_id']]['typosquatting_review_status']='source_batch_content_verified'
    csvwrite(DS/'dataset.csv',rows);csvwrite(DS/'label.csv',labels)
    csvwrite(DS/'audit/typosquatting_membership.csv',membership)
    label_exceptions=SOURCE/'metadata/collection/label_exceptions.jsonl'
    exception_by_hash={};exception_paths={}
    with label_exceptions.open(encoding='utf-8') as f:
        for line in f:
            e=json.loads(line);exception_by_hash[e['SHA256']]=e
            for p in e['paths']:
                exception_paths[p]=e
    with (DS/'provenance/source_label_conflicts.jsonl').open('w',encoding='utf-8') as f:
        for e in exception_by_hash.values():
            f.write(json.dumps(e,ensure_ascii=True)+'\n')
    assert not set(exception_by_hash)&{r['sha256'] for r in rows}
    discarded=[]
    for r in csvread(WORK/'malregistry_unindexed_paths.csv'):
        p=r['relative_path'];h=sha(bounded_path(SOURCE,p));exc=exception_paths.get(p)
        reason='conflicting_public_source_labels' if exc else 'duplicate_hash_in_source_inventory' if h in invhash else 'not_in_curated_source_index'
        discarded.append({'relative_path':p,'sha256':h,'reason':reason})
    csvwrite(DS/'provenance/malregistry_unindexed_paths.csv',discarded)
    # Check actual user-facing discovery and split validation. These only read
    # tables/metadata; no estimator is fit and no model bundle is deserialized.
    discovered=collect_samples(DS)
    assert len(discovered)==4000
    assert {r['sample_id'] for r in discovered}==set(rowmap)
    records=[];states=defaultdict(Counter);text=defaultdict(Counter);classn=Counter()
    with (DS/'audit/metadata_inventory.jsonl').open(encoding='utf-8') as f:
        for line in f:
            result=json.loads(line);row=rowmap[result['sample_id']];rec=result['record'];md=rec['metadata'];lab=row['label']
            assert rec['status']=='ok'
            classn[lab]+=1
            for key in STATE_FIELDS:
                states[(lab,key)][field_state(md.get(key))]+=1
            present=[key for key in ('Summary','Description') if field_state(md.get(key))=='present']
            for key in present:
                text[lab][key]+=1
            text[lab]['both_absent']+=not bool(present)
            original_chars=len('\n'.join(md[k] for k in present))
            text[lab]['would_truncate_100k']+=original_chars>100000
            records.append({'sample_id':row['sample_id'],'group':normalize_name(md['Name']),
                            'metadata_digest':rec['metadata_digest'],'label':lab,'requested_split':row['split']})
    assert len(assign_splits(records,42))==4000
    state_rows=[{'label':lab,'field':key,'state':state,'samples':states[(lab,key)][state],
                 'percentage':round(100*states[(lab,key)][state]/classn[lab],3)}
                for lab in ('benign','malicious') for key in STATE_FIELDS for state in ('missing','empty','placeholder','present')]
    csvwrite(DS/'audit/field_state_distribution.csv',state_rows)
    csvwrite(DS/'audit/text_coverage.csv',[{'label':lab,'samples':classn[lab],**text[lab]} for lab in classn])
    selected_ids=set(rowmap)
    candidate_rows=csvread(WORK/'typosquatting_candidates.csv')
    for r in candidate_rows:
        key='sha256:'+r['sha256'];e=invhash[r['sha256']]
        r['selected_in_v1_2']=str(key in selected_ids).lower()
        r['is_typosquatting']='true' if e['source_path'] in batches else 'unknown'
        r['review_status']='source_reported_batch' if e['source_path'] in batches else 'heuristic_screen_only'
    csvwrite(DS/'provenance/typosquatting_candidates.csv',candidate_rows)
    reported=[]
    for e in inv:
        b=batches.get(e['source_path'])
        if b:
            reported.append({'sha256':e['sha256'],'name':e['name'],'version':e['version'],
                'relative_path':e['relative_path'],'is_typosquatting':'true',
                'label_basis':'source_reported_update_batch','evidence_ref':b['evidence_ref'],
                'readme_ref':b['readme_ref'],'spellbound_candidate':str(e['match']['candidate']).lower(),
                'candidate_targets':';'.join(m['target'] for m in e['match']['matches']),
                'target_package':'','selected_in_v1_2':str('sha256:'+e['sha256'] in selected_ids).lower()})
    csvwrite(DS/'provenance/typosquatting_source_reported.csv',reported)
    for name in ('typosquatting_candidates.csv','typosquatting_source_reported.csv','malregistry_unindexed_paths.csv'):
        shutil.copy2(DS/'provenance'/name,WORK/name)
    shutil.copy2(WORK/'sources/typosquatting_source_batches.json',DS/'provenance/sources/typosquatting_source_batches.json')
    csvwrite(DS/'audit/added_samples.csv',[r for r in rows if r['origin']=='v1.2_added'])
    summary.update({'source_reported_typosquatting':len(membership),'typosquatting_batch_content_verified':len(membership),
        'typosquatting_unknown':4000-len(membership),'public_source_label_conflicts_in_active_dataset':0,
        'cli_manifest_discovery_verified':4000,'phase3_split_contract':'passed',
        'text_coverage':{k:dict(v) for k,v in text.items()},
        'malregistry_unindexed_reasons':dict(Counter(r['reason'] for r in discarded)),
        'source_reported_survey_archives':len(reported),
        'source_reported_survey_packages':len({normalize_name(e['name']) for e in reported}),
        'typo_additions_spellbound_matches':sum(r['label']=='malicious' and r['origin']=='v1.2_added' and r['spellbound_candidate']=='true' for r in rows),
        'label_review_status':dict(Counter(r['review_status'] for r in labels)),
        'base_archive_integrity':'all active original archives freshly verified; excluded originals retained and checked below'})
    original=csvread(ROOT/'Dataset_backups/v1.1-before-v1.2-20261025/dataset.csv')
    excluded=load(WORK/'base_exclusions.json')
    assert all(sha(bounded_path(DS,r['artifact_path']))==r['sha256'] for r in excluded)
    summary['excluded_original_archive_hashes_verified']=len(excluded)
    save(DS/'audit/validation.json',summary);save(WORK/'validation.json',summary)
    report=make_report(rows,summary,survey_stats,reported,excluded)
    (DS/'DATASET_REPORT.md').write_text(report,encoding='utf-8')
    (WORK/'DATASET_REPORT.md').write_text(report,encoding='utf-8')
    write_html_report(report,summary)
    readme=f'''# Dataset v1.2 — metadata PyPI, 4.000 mẫu

Chốt ngày 25/10/2026. Nhãn và split lấy từ CSV, không suy từ tên thư mục.

- 2.000 benign + 2.000 malicious; cả 4.000 mẫu hợp lệ với parser metadata hiện tại.
- Giữ 2.288 mẫu hợp lệ từ v1.1; thêm 883 malicious và 829 benign.
- Bốn mẫu cũ bị loại khỏi manifest vì lỗi metadata hoặc xung đột nhãn nguồn. File gốc vẫn còn; xem `audit/base_exclusions.csv`.
- Train/validation/test: 2.800/600/600. Mỗi tập cân bằng hai lớp.
- 1.024 annotation typosquatting theo nguồn (xem số chính xác trong `audit/validation.json`); không phải xác minh hành vi độc lập.
- Đọc `DATASET_REPORT.md` để biết phạm vi, phương pháp, nguồn và giới hạn.

## Các file

- `manifest.csv`: danh sách đầu vào tool (được ưu tiên trước dataset.csv).
- `dataset.csv`: danh sách mẫu và annotation tổng hợp.
- `artifact.csv`: identity/hash/path/kích thước và nguồn artifact.
- `label.csv`: nhãn, nguồn, phạm vi review, annotation typosquatting.
- `groups.csv`, `splits.csv`: nhóm và split đã chốt.
- `audit/validation.json`: hash, metadata, join CSV và chống giao tập.
- `audit/field_state_distribution.csv`, `audit/text_coverage.csv`: khảo sát metadata.
- `audit/typosquatting_membership.csv`: đối chiếu bytes với commit thêm mẫu.
- `provenance/typosquatting_candidates.csv`: ứng viên từ các dấu hiệu tên.
- `provenance/typosquatting_source_reported.csv`: danh sách được nguồn báo cáo ở cấp đợt cập nhật.
- `provenance/artifact_sources.jsonl`, `provenance/sources/`: nguồn và snapshot để truy vết.
- `checksums.json`: SHA256 các file hiện có, không tự chứa hash của chính nó.

## Giới hạn

Nhãn kế thừa nguồn công bố. `source_reference_reviewed` là kiểm tra tham chiếu/identity, không là phân tích hành vi độc lập. `is_typosquatting=unknown` không đồng nghĩa false. `target_package` chưa xác minh để trống; `candidate_target_package` chỉ là giả thuyết của detector. Không dùng nhãn/source/annotation/hash/path/split làm feature.

Không thực thi/cài/build/import sample hoặc tải payload/dependency. Chỉ đọc metadata và hash bytes file Python phục vụ nhóm chống rò rỉ; không dùng các hash này làm feature. Các cột audit Python/AST cũ được giữ nguyên khi có, không tự tính lại AST cho mẫu mới.

Đây là bản mở rộng có chứa dữ liệu đã được dùng ở các lần đánh giá trước, không phải benchmark test độc lập hoàn toàn mới. Các split đã được chia lại theo nhóm; không so điểm trực tiếp với split cũ như cùng một thí nghiệm.
'''
    readme=readme.replace('1.024 annotation',f"{len(membership):,}".replace(',','.')+' annotation')
    (DS/'README.md').write_text(readme,encoding='utf-8')
    config=load(DS/'build_config.json');config.update({'status':'complete','report':'DATASET_REPORT.md',
        'eligible_samples':4000,'reference_sha256':sha(WORK/'sources/top-pypi-packages-30-days.min.json'),
        'label_conflicts_excluded':2,'metadata_invalid_excluded':2,
        'typosquatting_batch_content_verified':len(membership)})
    save(DS/'build_config.json',config)
    checksums={p.relative_to(DS).as_posix():sha(p) for p in sorted(DS.rglob('*')) if p.is_file() and p.name!='checksums.json'}
    save(DS/'checksums.json',checksums)
    assert all(bounded_path(DS,p).is_file() for p in checksums)
    save(WORK/'complete.json',{'completed_at':now(),'samples':4000,'eligible_samples':4000,
        'checksums_entries':len(checksums),'checksums_sha256':sha(DS/'checksums.json'),
        'report':str(DS/'DATASET_REPORT.md'),'html':str(ROOT/'visual/dataset-v1.2-4000/index.html')})
    print('COMPLETE: 4000/4000 metadata-eligible; synchronized CSVs; reports and checksums written.',flush=True)

def make_report(rows,s,survey,reported,excluded):
    def table(headers,items):
        return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join('---' for _ in headers)+' |']+
                         ['| '+' | '.join(str(x).replace('|','\\|') for x in row)+' |' for row in items])
    additions=[r for r in rows if r['origin']=='v1.2_added']
    source_counts=Counter(r['source'] for r in additions)
    links={'PyPI_MalRegistry':'https://github.com/lxyeternal/pypi_malregistry',
           'OMCBench':'https://github.com/False-Positive-Community/open-malicious-code-benchmark',
           'OSCAR':'https://zenodo.org/records/13746167',
           'PyGuard':'https://github.com/lxyeternal/PyGuard',
           'PyPiGuard':'https://github.com/maurer-labs/pypiguard'}
    # PyPiGuard's actual repository URL is taken from the local pinned tree,
    # never inferred from its display name.
    tree=load(SOURCE/'metadata/source_snapshots/pypiguard_tree.json')
    if tree.get('repository'):
        links['PyPiGuard']='https://github.com/'+tree['repository']
    overlap=len({r['sha256'] for r in reported}&{r['sha256'] for r in csvread(DS/'provenance/typosquatting_candidates.csv')})
    base_count=s['base_samples_retained_active']
    examples=sorted((r for r in additions if r['label']=='malicious'),key=lambda r:(r['spellbound_candidate']!='true',r['normalized_name']))[:12]
    body=f'''# Báo cáo dataset PyPI metadata v1.2

Ngày chốt: **25/10/2026**. Mục tiêu: dataset phục vụ project môn học ứng dụng ML vào bảo mật, phân loại benign/malicious từ metadata và khảo sát tên dễ nhầm. Không có sample nào được cài, build, import hoặc thực thi.

## 1. Kết quả bàn giao

{table(['Hạng mục','Kết quả'],[
    ['Tổng mẫu đang hoạt động trong manifest',4000],['Benign',2000],['Malicious',2000],
    ['Mẫu hợp lệ qua parser metadata',4000],['Mẫu v1.1 giữ trong bộ hoạt động',base_count],
    ['Malicious mới',source_counts['PyPI_MalRegistry']],['Benign mới',sum(v for k,v in source_counts.items() if k!='PyPI_MalRegistry')],
    ['Mẫu cũ đưa ra khỏi manifest',len(excluded)],['Tên package khác nhau',s['unique_names']],
    ['Hash archive khác nhau',s['unique_archive_hashes']],['Dung lượng archive của 4.000 mẫu',str(s['archive_bytes'])+' bytes'],
    ['Nhóm chia tập',s['group_count']]])}

Archive của cả 2.292 mẫu ban đầu vẫn được giữ nguyên trên ổ đĩa. Bốn mẫu không phù hợp được loại khỏi danh sách hoạt động, không xóa file. Vì vậy không dùng số file trong thư mục samples để thay cho số mẫu trong manifest. Các CSV và cấu hình cũ được sao lưu ở `../Dataset_backups/v1.1-before-v1.2-20261025/`.

## 2. Khảo sát kho MalRegistry

{table(['Hạng mục','Số lượng'],[
    ['Đường dẫn archive vật lý trong kho được chỉ định',survey['physical_archive_paths']],
    ['Archive hash riêng, không xung đột nhãn, trong inventory khảo sát',survey['inventory_unique_archives']],
    ['Tên package chuẩn hóa trong inventory',survey['inventory_unique_packages']],
    ['Đường dẫn bị loại khỏi inventory sạch',survey['unindexed_archive_paths']],
    ['Ứng viên theo bộ quy tắc tên — archive',survey['spellbound_candidates_archives']],
    ['Ứng viên theo bộ quy tắc tên — package',survey['spellbound_candidates_packages']],
    ['Được nguồn báo cáo typosquatting và đối chiếu đợt thêm mẫu — archive',len(reported)],
    ['Được nguồn báo cáo typosquatting — package',len({normalize_name(r['name']) for r in reported})],
    ['Giao giữa hai danh sách archive trên',overlap]])}

Số ứng viên từ tên **không phải số typosquatting đã xác minh**. Danh sách source-reported cũng là nhãn kế thừa từ tác giả nguồn; việc rà soát này xác nhận nguồn, phạm vi đợt cập nhật và identity archive, không phân tích lại hành vi từng package.

Các đường dẫn ngoài inventory sạch được phân loại trong `provenance/malregistry_unindexed_paths.csv`: {json.dumps(s['malregistry_unindexed_reasons'],ensure_ascii=False)}. Chúng không được dùng làm mẫu bổ sung.

## 3. Phương pháp tìm ứng viên và bằng chứng annotation

Danh sách tham chiếu gồm **{survey['reference_targets']} tên** từ snapshot [hugovk/top-pypi-packages]({TARGET_URL}), cập nhật nguồn ngày 01/10/2026, tải và chốt trước khi chọn sample hoặc đánh giá model. URL, thời điểm và SHA256 nằm trong `provenance/sources/reference_provenance.json`. Không tạo danh sách target từ nhãn của train/test.

Quy tắc kế thừa sáu tín hiệu tên của [SpellBound](https://arxiv.org/abs/2003.03471): lặp ký tự, thiếu ký tự, đảo ký tự cạnh nhau, đảo thành phần tên, thay ký tự gần bàn phím/giống hình dạng, hậu tố phiên bản. Bổ sung điều kiện Levenshtein <= 1 theo tool hiện tại. Index tăng tốc được kiểm thử đối chiếu với cách so sánh vét cạn. Đây là **SpellBound-inspired name screening**, chưa tái hiện cơ chế popularity/weekly-download đầy đủ của paper.

[README MalRegistry tại commit đã chốt](https://github.com/lxyeternal/pypi_malregistry/blob/5f2592d2d750a1beb68e8ed1a5a63fcd1905899c/README.md) mô tả các đợt typosquatting. Annotation chỉ dùng các đợt 04/04, 16/04 và 01/05/2024 có thể đối chiếu số archive hoặc số project với danh sách bổ sung. Hai đợt 31/03 và 21/04 không được dùng gán true trong bản này do số lượng chưa đối chiếu khớp. Không cộng số ghi trong README rồi coi là số sample đang có.

Với **{s['typosquatting_batch_content_verified']} mẫu source-reported trong dataset cuối**, bytes archive được đối chiếu với Git blob tại commit thêm mẫu, bên cạnh SHA256 archive. Chi tiết: `audit/typosquatting_membership.csv`.

Trong {source_counts['PyPI_MalRegistry']} malicious mới, chỉ **{s['typo_additions_spellbound_matches']}** khớp bộ tín hiệu tên trên snapshot hiện tại. Mẫu được ưu tiên chọn theo nguồn chứng cứ, không bắt buộc detector phải phát hiện được. Khoảng cách nhiều ký tự, tên mục tiêu lịch sử/ngoài reference và phạm vi quy tắc là các khả năng cần khảo sát; không kết luận ngay rằng tất cả phần còn lại là lỗi detector.

Snapshot 15.000 tên chỉ phục vụ đợt khảo sát này. Cấu hình reference của CLI phân tích hiện có không bị thay đổi tự động; kết quả Phase 2 dùng reference khác có thể khác số liệu khảo sát.

## 4. Nguồn các mẫu bổ sung

{table(['Nguồn công bố nhãn','Lớp','Số mẫu mới'],[
    [f'[{k}]({links[k]})','malicious' if k=='PyPI_MalRegistry' else 'benign',v] for k,v in sorted(source_counts.items())])}

Tất cả archive bổ sung được sao chép từ corpus đã có trên máy, kiểm tra lại SHA256 và đọc metadata. Không tải package/dependency/payload mới. Các benign được lựa chọn vòng qua nhiều nguồn, không suy benign chỉ vì còn tồn tại trên PyPI. File representative có thể có nhiều nguồn xác nhận cùng hash; `provenance/artifact_sources.jsonl` giữ các tham chiếu đó.

Nhãn benign kế thừa dataset công bố; không bảo đảm từng mẫu đã được nhóm project xác minh hành vi. `source_reference_reviewed` chỉ có nghĩa đã kiểm tra tham chiếu nguồn và identity. Một số benign cũ vẫn là nguồn kế thừa chưa xác minh độc lập.

## 5. Annotation và các CSV

{table(['Trường','Ý nghĩa'],[
    ['label','benign/malicious; nhãn học có giám sát'],
    ['is_typosquatting','true nếu có nguồn đợt cập nhật đã đối chiếu; còn lại unknown'],
    ['target_package','Để trống khi chưa có chứng cứ xác nhận target'],
    ['typosquatting_evidence_ref','README/commit hỗ trợ nhãn ở phạm vi được công bố'],
    ['typosquatting_label_basis','source_reported_update_batch hoặc not_established'],
    ['typosquatting_review_status','source_batch_content_verified hoặc not_reviewed'],
    ['spellbound_candidate','Quan sát từ bộ quy tắc, không là ground truth'],
    ['candidate_target_package','Target giả thuyết của detector; có thể có nhiều tên'],
    ['metadata_status','Kết quả parser metadata hiện tại'],
    ['python_bytes_tree_sha256','Hash phục vụ nhóm chống rò rỉ; không đưa vào classifier']])}

Có **{s['source_reported_typosquatting']}** mẫu true theo nguồn và **{s['typosquatting_unknown']}** mẫu unknown. Không gán false cho toàn bộ benign hoặc các mẫu detector không cảnh báo. Chưa có annotation âm/target đủ để báo đầy đủ precision/recall/F1 cho nhiệm vụ typosquatting; metric benign/malicious là nhiệm vụ riêng.

`manifest.csv` là đầu vào được tool ưu tiên. Đã đồng bộ tập sample_id, label, đường dẫn và split giữa các bảng; các annotation mới không tự trở thành feature hoặc metric trong code hiện tại. Các cột Python/AST cũ chỉ phục vụ audit, không tạo lại AST cho mẫu mới.

## 6. Split và chống rò rỉ

{table(['Tập','Benign','Malicious','Tổng'],[[name,s['split_counts'][name]['benign'],s['split_counts'][name]['malicious'],sum(s['split_counts'][name].values())] for name in ('train','validation','test')])}

Chia nhóm theo tên chuẩn hóa, nhóm cũ, metadata trùng và toàn bộ multiset hash bytes file Python giống hệt. Không thực thi hoặc parse AST. Có {s['multi_sample_groups']} nhóm nhiều sample; nhóm lớn nhất có {s['largest_group']} sample. Các sample cùng nhóm nằm cùng tập; chia lại bằng seed 42 dựa trên số mẫu/lớp, không dựa vào điểm model hoặc kết quả detector.

Kiểm tra giao tập: {json.dumps(s['cross_split_overlaps'],ensure_ascii=False)}. Byte-tree status: {json.dumps(s['byte_tree_status'],ensure_ascii=False)}. Đây không phải bằng chứng đã loại hết tương đồng ngữ nghĩa hoặc quan hệ chiến dịch.

Toàn bộ split mới đã chốt. Vì chứa các mẫu đã được dùng thử trước đây, bộ này không phải một test độc lập hoàn toàn mới. Phải fit encoder/model lại; không so điểm với split cũ như cùng điều kiện đánh giá.

## 7. Độ đầy đủ metadata

{table(['Lớp','Số mẫu','Summary present','Description present','Cả hai không present','Văn bản vượt giới hạn 100k'],[[lab,2000,s['text_coverage'][lab].get('Summary',0),s['text_coverage'][lab].get('Description',0),s['text_coverage'][lab].get('both_absent',0),s['text_coverage'][lab].get('would_truncate_100k',0)] for lab in ('benign','malicious')])}

Toàn bộ 10 trường × 4 trạng thái theo từng lớp nằm ở `audit/field_state_distribution.csv`. Sự khác biệt về độ đầy đủ metadata là thông tin khảo sát, không tự xác định ý định độc hại. Metadata phản ánh khai báo của publisher, có thể bị làm giả.

## 8. Các mẫu cũ không vào danh sách hoạt động

{table(['Package','Version','Lý do'],[[r['package_name'],r['version'],r['exclusion_reason']] for r in excluded])}

Hai xung đột là **cùng hash archive** nhưng có nguồn gán benign và nguồn gán malicious. Không tự chọn một nhãn. Bằng chứng xung đột nguồn được lưu riêng; cả bốn file gốc vẫn được giữ và kiểm tra hash. Thông tin gốc nằm trong bản backup.

## 9. Một số malicious mới để tra cứu

{table(['Package','Version','SpellBound candidate','Target giả thuyết'],[[r['package_name'],r['version'],r['spellbound_candidate'],r['candidate_target_package'] or 'chưa xác định'] for r in examples])}

Danh sách đầy đủ mẫu bổ sung: `audit/added_samples.csv`. Danh sách ứng viên toàn kho: `provenance/typosquatting_candidates.csv`. Danh sách được nguồn báo cáo toàn kho: `provenance/typosquatting_source_reported.csv`. Không gộp hai danh sách thành một ground truth duy nhất.

## 10. Giới hạn và sử dụng

- Nguồn MalRegistry/PyGuard có quan hệ tác giả và có nhiều archive giao nhau; đa nguồn không đồng nghĩa các nhãn hoàn toàn độc lập.
- Nhóm malicious mới tập trung vào một số đợt thu thập typosquatting năm 2024. Kết quả phù hợp một bộ dữ liệu được bổ sung typosquatting, chưa đại diện mọi malware PyPI hoặc tỷ lệ ngoài thực tế.
- Cân bằng 50/50 thuận tiện cho baseline; precision ngoài thực tế còn phụ thuộc tỷ lệ malicious trong môi trường triển khai.
- Nguồn benign và malicious khác nhau; cần xem khả năng model học dấu vết nguồn/đóng gói. Không dùng source, annotation hoặc thống kê vận hành làm feature.
- Không có phân tích hành vi độc lập, không khẳng định package an toàn tuyệt đối hoặc mọi source-reported target đã được xác nhận.
- Chưa train/evaluate model trên bản v1.2 trong đợt dựng dataset này; không có accuracy/F1 mới được tạo hoặc kế thừa từ bản cũ.

Chạy lại bốn phase vào một output mới, từ thư mục project có môi trường đã kích hoạt:

```powershell
python -m pypi_metadata_detector --extraction .\\Dataset --output .\\outputs\\Dataset-v1.2-4000
python -m pypi_metadata_detector --analysis .\\Dataset --output .\\outputs\\Dataset-v1.2-4000
python -m pypi_metadata_detector --preprocessing .\\Dataset --output .\\outputs\\Dataset-v1.2-4000
python -m pypi_metadata_detector --evaluate .\\Dataset --output .\\outputs\\Dataset-v1.2-4000
```

## 11. Kiểm tra đã hoàn thành

- SHA256 từ bytes của 4.000 archive đang hoạt động; SHA256 bốn archive bị loại vẫn được kiểm tra bảo toàn.
- Đọc lại metadata, không còn sample lỗi trong manifest.
- Không trùng tên chuẩn hóa, hash archive hoặc metadata; không có hash xung đột nhãn nguồn trong bộ hoạt động.
- Sáu CSV có cùng 4.000 sample_id; nhãn, split, path đồng bộ.
- User-facing discovery tìm đúng 4.000 mẫu qua manifest; hợp đồng chia tập Phase 3 kiểm tra đạt.
- Đối chiếu bytes với commit cho annotation typosquatting true; lưu bằng chứng và snapshot.
- Cập nhật checksum theo file thực sự tồn tại, không giữ tham chiếu checksum tới audit/provenance vắng mặt của bản cũ.
'''
    return body

def write_html_report(report,summary):
    """Dependency-free offline report; raw package text is always escaped."""
    out=ROOT/'visual/dataset-v1.2-4000/index.html';out.parent.mkdir(parents=True,exist_ok=True)
    def inline(value):
        escaped=html.escape(value)
        escaped=re.sub(r'\[([^\]]+)\]\((https://[^\s)]+)\)',r'<a href="\2" rel="noreferrer">\1</a>',escaped)
        escaped=re.sub(r'\*\*([^*]+)\*\*',r'<strong>\1</strong>',escaped)
        return re.sub(r'`([^`]+)`',r'<code>\1</code>',escaped)
    sections=[];lines=report.splitlines();i=0
    while i<len(lines):
        line=lines[i]
        if line.startswith('```'):
            code=[];i+=1
            while i<len(lines) and not lines[i].startswith('```'):
                code.append(lines[i]);i+=1
            sections.append('<pre>'+html.escape('\n'.join(code))+'</pre>')
        elif line.startswith('|'):
            group=[]
            while i<len(lines) and lines[i].startswith('|'):
                group.append(lines[i]);i+=1
            cells=lambda s:[inline(c.strip()) for c in s.strip('|').split('|')]
            head=cells(group[0]);body=[cells(s) for s in group[2:]]
            sections.append('<div class="table"><table><thead><tr>'+''.join('<th>'+c+'</th>' for c in head)+
                '</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+c+'</td>' for c in row)+'</tr>' for row in body)+'</tbody></table></div>')
            continue
        elif line.startswith('# '):sections.append('<h1>'+html.escape(line[2:])+'</h1>')
        elif line.startswith('## '):sections.append('<h2>'+html.escape(line[3:])+'</h2>')
        elif line.strip():sections.append('<p>'+inline(line)+'</p>')
        i+=1
    content='''<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Dataset PyPI v1.2 — 4.000 mẫu</title><style>
    body{margin:0;background:#f5f7fa;color:#182333;font:16px/1.65 system-ui,sans-serif}main{max-width:1100px;margin:32px auto;padding:32px;background:white;border-top:6px solid #175b67;border-radius:8px}h1{font-size:32px;line-height:1.25}h2{margin-top:36px;font-size:23px;color:#175b67}.table{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px;margin:16px 0}th,td{padding:10px 12px;border:1px solid #dbe2e8;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf2f4}pre{white-space:pre-wrap;background:#eff3f7;padding:18px;border-radius:6px;overflow-wrap:anywhere}p{overflow-wrap:anywhere}.cards{display:flex;gap:12px;flex-wrap:wrap}.card{padding:16px 24px;background:#eaf2f4;border-radius:8px;flex:1}.card b{display:block;font-size:28px}.note{padding:12px 16px;background:#fff4d9;border-left:4px solid #b68519}@media(max-width:700px){main{margin:0;padding:18px}h1{font-size:26px}}@media print{main{margin:0;padding:0;border:0}body{background:white}table{font-size:10px}h2{break-after:avoid}}
    </style><main><div class="cards"><div class="card"><b>4.000</b>Mẫu hợp lệ</div><div class="card"><b>2.000 / 2.000</b>Benign / Malicious</div><div class="card"><b>0</b>Giao nhóm giữa các tập</div></div><p class="note">Annotation typosquatting kế thừa nguồn công bố. Ứng viên SpellBound là quan sát của detector, không tự trở thành nhãn kiểm chứng.</p>'''+''.join(sections)+'</main></html>'
    out.write_text(content,encoding='utf-8')

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('stage',choices=['survey','prepare','commit','validate','finish'])
    args=parser.parse_args()
    {'survey':survey,'prepare':prepare,'commit':commit,'validate':validate,'finish':finish}[args.stage]()

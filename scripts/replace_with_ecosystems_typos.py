"""Local-only PyPI archive replacement with explicit source-label scope."""
from __future__ import annotations
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('dataset_builder_v12',ROOT/'scripts/build_dataset_v12.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
from pypi_metadata_detector.phase2_metadata_analysis.signals import field_state,STATE_FIELDS
from pypi_metadata_detector.phase3_preprocessing.dataset import assign_splits

DS=ROOT/'Dataset'
WORK=ROOT/'outputs/dataset-replacement-v1.3-20261025'
BACKUP=ROOT/'Dataset_backups/v1.2-before-ecosystems-20261025'
SURVEY=ROOT/'outputs/ecosystems-typosquatting-audit-20261025'
VERSION='v1.3'
COUNT=20

def dump_csv(path,rows,fields=None):
    b.csvwrite(path,rows,fields)

def annotation(source):
    info=b.load(SURVEY/'summary.json')
    return {'is_typosquatting':'true','target_package':source['target_package'],
      'typosquatting_evidence_ref':info['source_url'],
      'typosquatting_label_basis':'external_curated_name_target_mapping',
      'typosquatting_review_status':'catalog_name_mapping_reviewed',
      'typosquatting_evidence_scope':'package_name_only; affected_versions_not_specified',
      'typosquatting_catalog_source':source['source'],
      'typosquatting_catalog_classification':source['classification'],
      'review_notes':'Name-to-target mapping inherited from ecosyste.ms CSV. '
        'Malicious archive label independently inherited from pinned MalRegistry membership. '
        'Upstream CSV has no affected version/hash; no independent behavior verification.'}

def plan():
    WORK.mkdir(parents=True,exist_ok=True)
    baseline=BACKUP if (BACKUP/'backup_complete.json').exists() else DS
    rows=b.csvread(baseline/'dataset.csv')
    assert len(rows)==4000
    names={r['normalized_name'] for r in rows};hashes={r['sha256'] for r in rows}
    inventory=b.load(ROOT/'outputs/dataset-build-v1.2-20261025/malregistry_inventory.json')
    inv=defaultdict(list)
    for e in inventory:inv[b.normalize_name(e['name'])].append(e)
    records={}
    with (baseline/'audit/metadata_inventory.jsonl').open(encoding='utf-8') as f:
        for line in f:
            r=json.loads(line);records[r['sample_id']]=r
    metadata={r['record']['metadata_digest'] for r in records.values()}
    tree_splits=defaultdict(set)
    for row in rows:
        tree=row.get('python_bytes_tree_sha256')
        if tree:tree_splits[tree].add(row['split'])
    source=b.csvread(SURVEY/'pypi_all_comparison.csv')
    assert all(r['ecosystem'].strip().lower()=='pypi' for r in source)
    assert b.sha(SURVEY/'typosquats_source.csv')==b.load(SURVEY/'summary.json')['source_sha256']
    targets=defaultdict(list);excluded=[]
    for s in source:
        n=b.normalize_name(s['malicious_package']);t=b.normalize_name(s['target_package'])
        if n in names:continue
        if n==t:
            excluded.append({'name':s['malicious_package'],'reason':'normalized_name_equals_target'});continue
        if t in {'python','pytorch'}:
            excluded.append({'name':s['malicious_package'],'reason':'target_identity_needs_separate_review'});continue
        if n not in inv:
            excluded.append({'name':s['malicious_package'],'reason':'no_archive_in_clean_local_MalRegistry_inventory'});continue
        targets[t].append(s)
    # Target diversity is fixed before parsing/detector/model evaluation.
    for vals in targets.values():vals.sort(key=lambda r:b.digest('replacement42|'+r['malicious_package']))
    ordered=[]
    for i in range(max(map(len,targets.values()))):
        for t in sorted(targets):
            if i<len(targets[t]):ordered.append(targets[t][i])
    selected=[]
    for s in ordered:
        if len(selected)==COUNT:break
        n=b.normalize_name(s['malicious_package'])
        for e in sorted(inv[n],key=lambda x:b.digest('replacement-version42|'+x['sha256'])):
            if e['sha256'] in hashes:continue
            result=b.inspect_entry(e);rec=result['record']
            reason=None
            if rec['status']!='ok':reason=rec['status']
            elif b.normalize_name(rec['metadata']['Name'])!=n:reason='metadata_name_mismatch'
            elif rec['metadata_digest'] in metadata:reason='duplicate_metadata'
            if reason:
                excluded.append({'name':s['malicious_package'],'version':e['version'],'reason':reason});continue
            try:tree=b.byte_tree(b.bounded_path(b.SOURCE,e['relative_path']))
            except Exception as exc:
                excluded.append({'name':s['malicious_package'],'version':e['version'],'reason':'byte_tree_unavailable: '+str(exc)[:100]});continue
            if tree['python_bytes_tree_sha256'] and tree_splits[tree['python_bytes_tree_sha256']]-{'train'}:
                excluded.append({'name':s['malicious_package'],'version':e['version'],'reason':'same_python_tree_in_frozen_validation_or_test'});continue
            result.update(tree);result['catalog']=s;selected.append(result)
            hashes.add(e['sha256']);metadata.add(rec['metadata_digest']);names.add(n)
            break
    assert len(selected)==COUNT,'not enough eligible replacements'
    group_sizes=Counter(r['split_group_id'] for r in rows)
    removable=[r for r in rows if r['label']=='malicious' and r['split']=='train'
        and r['is_typosquatting']=='unknown' and r['spellbound_candidate']=='false'
        and group_sizes[r['split_group_id']]==1]
    removable.sort(key=lambda r:b.digest('replacement-remove42|'+r['sample_id']))
    removed=removable[:COUNT];assert len(removed)==COUNT
    # Keep original artifacts; only the active manifest is replaced.
    b.save(WORK/'plan.json',{'created_at':b.now(),'version':VERSION,'count':COUNT,
        'before_dataset_sha256':b.sha(baseline/'dataset.csv'),'selected':selected,'removed':removed})
    dump_csv(WORK/'candidate_exclusions.csv',excluded)
    dump_csv(WORK/'planned_replacements.csv',[{'removed_sample_id':old['sample_id'],
        'removed_name':old['package_name'],'added_name':new['record']['metadata']['Name'],
        'added_version':new['record']['metadata']['Version'],'target':new['catalog']['target_package'],
        'split':'train'} for old,new in zip(removed,selected)])
    print(json.dumps({'selected':len(selected),'targets':len({r['catalog']['target_package'] for r in selected}),
        'names':[r['record']['metadata']['Name'] for r in selected]},ensure_ascii=True),flush=True)

def backup():
    if (BACKUP/'backup_complete.json').exists():return
    BACKUP.mkdir(parents=True,exist_ok=True)
    for p in DS.iterdir():
        if p.name=='samples':continue
        if p.is_dir():shutil.copytree(p,BACKUP/p.name,dirs_exist_ok=True)
        elif p.is_file():shutil.copy2(p,BACKUP/p.name)
    previous_visual=ROOT/'visual/dataset-v1.2-4000/index.html'
    if previous_visual.exists():shutil.copy2(previous_visual,BACKUP/'previous_visual.html')
    b.save(BACKUP/'backup_complete.json',{'at':b.now(),'dataset_sha256':b.sha(DS/'dataset.csv'),
        'note':'All non-sample files snapshotted; original sample archives remain untouched.'})

def apply():
    p=b.load(WORK/'plan.json')
    if not (BACKUP/'backup_complete.json').exists():
        assert b.sha(DS/'dataset.csv')==p['before_dataset_sha256']
    backup()
    assert b.sha(BACKUP/'dataset.csv')==p['before_dataset_sha256']
    tables={n:b.csvread(BACKUP/n) for n in ('dataset.csv','artifact.csv','label.csv','groups.csv','splits.csv','manifest.csv')}
    removed={r['sample_id'] for r in p['removed']}
    tables={n:[r for r in t if r['sample_id'] not in removed] for n,t in tables.items()}
    rows=tables['dataset.csv'];rowmap={r['sample_id']:r for r in rows}
    source_rows=b.csvread(SURVEY/'pypi_all_comparison.csv')
    source_by_name={b.normalize_name(r['malicious_package']):r for r in source_rows}
    # Fill mappings for the seven pre-existing malicious names as well; this
    # changes audit annotations only, never features or existing split labels.
    enriched=[]
    for row in rows:
        s=source_by_name.get(row['normalized_name'])
        if s and row['label']=='malicious':
            row.update(annotation(s));enriched.append(row['sample_id'])
    for lab in tables['label.csv']:
        if lab['sample_id'] in enriched:lab.update(annotation(source_by_name[rowmap[lab['sample_id']]['normalized_name']]))
    group_by_tree={r['python_bytes_tree_sha256']:r['split_group_id'] for r in rows if r.get('python_bytes_tree_sha256')}
    name_index=b.NameIndex(b.targets());new_records=[];new_provenance=[]
    replacements=[]
    for old,result in zip(p['removed'],p['selected']):
        e=result['entry'];rec=result['record'];md=rec['metadata'];n=b.normalize_name(md['Name']);h=e['sha256'];key='sha256:'+h
        relative=Path('samples')/'malicious'/n/h[:12]/Path(e['relative_path']).name
        dest=b.bounded_path(DS,relative);dest.parent.mkdir(parents=True,exist_ok=True)
        if not dest.exists():shutil.copy2(b.bounded_path(b.SOURCE,e['relative_path']),dest)
        assert b.sha(dest)==h
        fresh=b.extract_sample({'sample_id':key,'path':str(dest)},b.DEFAULTS)
        assert fresh['status']=='ok' and fresh['metadata_digest']==rec['metadata_digest']
        tree=result['python_bytes_tree_sha256']
        group=group_by_tree.get(tree) if tree else None
        group=group or 'group:'+b.digest([key])
        if tree:group_by_tree[tree]=group
        match=name_index.match(md['Name']);ann=annotation(result['catalog'])
        common={'sample_id':key,'label':'malicious','label_status':'source_repository_membership_verified',
            'review_status':'source_reference_reviewed','scope_status':'in_scope_metadata_present'}
        row={**common,'package_name':md['Name'],'normalized_name':n,'version':md['Version'],'split':'train',
            'split_group_id':group,'sha256':h,'filename':dest.name,'source':'PyPI_MalRegistry',
            'artifact_bytes':result['bytes'],'artifact_path':relative.as_posix(),'audit_statistics_only':'True',
            'dataset_version':VERSION,'origin':'v1.3_ecosystems_replacement','parse_status':'not_run_metadata_only',
            'metadata_status':'ok','metadata_digest':fresh['metadata_digest'],'python_bytes_tree_sha256':tree,
            'spellbound_candidate':str(match['candidate']).lower(),
            'candidate_target_package':';'.join(m['target'] for m in match['matches']),
            'spellbound_signals':';'.join(sorted({s for m in match['matches'] for s in m['signals']})),**ann}
        rows.append(row);rowmap[key]=row
        refs=json.dumps(e['sources'],ensure_ascii=True)
        tables['artifact.csv'].append({'sample_id':key,'Name':md['Name'],'normalized_name':n,'version':md['Version'],
            'ecosystem':'pypi','source':'PyPI_MalRegistry','publish_year':e.get('year',''),'publish_time':'',
            'publish_year_status':e.get('year_basis','unknown'),'filename':dest.name,'artifact_type':'source_archive',
            'sha256':h,'artifact_path':relative.as_posix(),'artifact_bytes':result['bytes'],'hash_verified':'True',
            'source_url':'https://github.com/lxyeternal/pypi_malregistry/blob/5f2592d2d750a1beb68e8ed1a5a63fcd1905899c/'+e['source_path'],
            'metadata_url':'','source_refs':refs,'acquired_at':'','verified_at':b.now(),
            'local_source_path':str(b.bounded_path(b.SOURCE,e['relative_path'])),'year_evidence_ref':e.get('year_evidence',''),
            'collection_note':'Local archive copied; malicious label from MalRegistry; name-target mapping from ecosyste.ms.'})
        tables['label.csv'].append({**common,'label_source':'["PyPI_MalRegistry"]','label_source_refs':refs,
            'behavior_evidence_ref':'','reviewed_at':b.now(),**ann})
        tables['groups.csv'].append({'sample_id':key,'project_group':'pypi:'+n,'python_tree_sha256':'','ast_tree_sha256':'',
            'fingerprint_sha256':fresh['metadata_digest'],'fingerprint_policy':'canonical_raw_metadata_sha256',
            'split_group_id':group,'grouping_version':'v1.3-incremental-byte-tree',
            'grouping_reason':'normalized_name; exact_metadata; whole_python_byte_tree; train-only replacement',
            'group_evidence_ref':'audit/validation.json','file_inventory_ref':'','python_bytes_tree_sha256':tree,
            'metadata_digest':fresh['metadata_digest'],'byte_tree_status':result['byte_tree_status']})
        tables['splits.csv'].append({'sample_id':key,'name':md['Name'],'status':'not_run_metadata_only','split':'train',
            'split_group_id':group,'seed':42,'split_version':'v1.3-train-replacement','metadata_status':'ok'})
        new_records.append({'sample_id':key,'expected_sha256':h,'checked_at':b.now(),'actual_sha256':h,'record':fresh,
            **{k:v for k,v in result.items() if k.startswith('python_') or k.startswith('byte_tree_')}})
        new_provenance.append({'sample_id':key,'label':'malicious','origin':row['origin'],'artifact_evidence':e,
            'typosquatting_catalog':result['catalog'],'evidence_scope':ann['typosquatting_evidence_scope'],
            'source_csv_sha256':b.load(SURVEY/'summary.json')['source_sha256']})
        replacements.append({'removed_sample_id':old['sample_id'],'removed_name':old['package_name'],
            'removed_version':old['version'],'removal_reason':'malicious with unknown typosquatting annotation and no name-screen signal; not proven non-typosquatting',
            'added_sample_id':key,'added_name':md['Name'],'added_version':md['Version'],'target_package':ann['target_package'],
            'source':result['catalog']['source'],'classification':result['catalog']['classification'],'split':'train',
            'removed_artifact_preserved':old['artifact_path']})
    for row in rows:row['dataset_version']=VERSION
    tables['manifest.csv']=[{'sample_id':r['sample_id'],'path':r['artifact_path'],'label':r['label'],'split':r['split']} for r in rows]
    assert len(rows)==4000 and Counter(r['label'] for r in rows)=={'benign':2000,'malicious':2000}
    for n,t in tables.items():
        assert len(t)==4000 and len({r['sample_id'] for r in t})==4000
        dump_csv(WORK/'staged'/n,t)
    for n in tables:shutil.copy2(WORK/'staged'/n,DS/n)
    audit=DS/'audit';audit.mkdir(exist_ok=True)
    dump_csv(audit/'ecosystems_replacements.csv',replacements)
    dump_csv(audit/'ecosystems_existing_enriched.csv',[rowmap[k] for k in enriched])
    with (BACKUP/'audit/metadata_inventory.jsonl').open(encoding='utf-8') as src, (audit/'metadata_inventory.jsonl').open('w',encoding='utf-8') as dst:
        for line in src:
            if json.loads(line)['sample_id'] not in removed:dst.write(line)
        for r in new_records:dst.write(json.dumps(r,ensure_ascii=True)+'\n')
    with (BACKUP/'provenance/artifact_sources.jsonl').open(encoding='utf-8') as src,(DS/'provenance/artifact_sources.jsonl').open('w',encoding='utf-8') as dst:
        for line in src:
            if json.loads(line)['sample_id'] not in removed:dst.write(line)
        for r in new_provenance:dst.write(json.dumps(r,ensure_ascii=True)+'\n')
    sources=DS/'provenance/sources'
    shutil.copy2(SURVEY/'typosquats_source.csv',sources/'ecosystems_typosquats.csv')
    shutil.copy2(SURVEY/'summary.json',sources/'ecosystems_source_provenance.json')
    b.save(WORK/'applied.json',{'at':b.now(),'replaced':COUNT,'existing_mappings_enriched':len(enriched),'backup':str(BACKUP)})
    print('Applied 20 train replacements and enriched 7 existing source mappings.',flush=True)

def finalize():
    rows=b.csvread(DS/'dataset.csv');rowmap={r['sample_id']:r for r in rows}
    old=b.csvread(BACKUP/'dataset.csv');oldmap={r['sample_id']:r for r in old}
    planinfo=b.load(WORK/'plan.json');removed={r['sample_id'] for r in planinfo['removed']}
    added=set(rowmap)-set(oldmap)
    assert set(oldmap)-set(rowmap)==removed and len(added)==COUNT
    assert Counter(r['label'] for r in rows)=={'benign':2000,'malicious':2000}
    assert len({r['normalized_name'] for r in rows})==4000
    assert len({r['sha256'] for r in rows})==4000
    for split in ('validation','test'):
        assert {k for k,r in oldmap.items() if r['split']==split}=={k for k,r in rowmap.items() if r['split']==split}
    assert all(rowmap[k]['label']==oldmap[k]['label'] and rowmap[k]['split']==oldmap[k]['split'] for k in set(oldmap)&set(rowmap))
    for filename in ('artifact.csv','label.csv','groups.csv','splits.csv','manifest.csv'):
        table=b.csvread(DS/filename)
        assert len(table)==4000 and {r['sample_id'] for r in table}==set(rowmap)
        for r in table:
            base=rowmap[r['sample_id']]
            for key in ('label','split','sha256','split_group_id'):
                if key in r:assert r[key]==base[key],(filename,key,r['sample_id'])
            if 'artifact_path' in r:assert r['artifact_path']==base['artifact_path']
            if 'path' in r:assert r['path']==base['artifact_path']
    records={};classn=Counter();text=defaultdict(Counter);states=defaultdict(Counter)
    with (DS/'audit/metadata_inventory.jsonl').open(encoding='utf-8') as f:
        for line in f:
            result=json.loads(line);key=result['sample_id'];records[key]=result
            row=rowmap[key];rec=result['record'];md=rec['metadata'];lab=row['label'];classn[lab]+=1
            assert rec['status']=='ok' and b.digest(md)==row['metadata_digest']==rec['metadata_digest']
            assert b.normalize_name(md['Name'])==row['normalized_name']
            for field in STATE_FIELDS:states[(lab,field)][field_state(md.get(field))]+=1
            present=[k for k in ('Summary','Description') if field_state(md.get(k))=='present']
            for k in present:text[lab][k]+=1
            text[lab]['both_absent']+=not bool(present)
            text[lab]['would_truncate_100k']+=len('\n'.join(md[k] for k in present))>100000
    assert set(records)==set(rowmap)
    assert len({r['record']['metadata_digest'] for r in records.values()})==4000
    overlaps={}
    for field in ('sha256','normalized_name','metadata_digest','split_group_id','python_bytes_tree_sha256'):
        m=defaultdict(set)
        for row in rows:
            if row.get(field):m[row[field]].add(row['split'])
        overlaps[field]=sum(len(v)>1 for v in m.values())
    assert not any(overlaps.values())
    assign_splits([{'sample_id':r['sample_id'],'group':r['normalized_name'],'label':r['label'],
        'metadata_digest':r['metadata_digest'],'requested_split':r['split']} for r in rows],42)
    def verify(row):
        actual=b.sha(b.bounded_path(DS,row['artifact_path']))
        assert actual==row['sha256'],row['sample_id']
        return (row['artifact_path'],actual)
    archive_hashes={}
    with ThreadPoolExecutor(max_workers=8) as executor:
        for i,pair in enumerate(executor.map(verify,rows),1):
            archive_hashes[pair[0]]=pair[1]
            if i%500==0:print(f'Hash validation {i}/4000',flush=True)
    # Removed archives are preserved byte-for-byte, and not listed in active CSVs.
    for row in planinfo['removed']:
        pair=verify(row);archive_hashes[pair[0]]=pair[1]
    conflicts=[json.loads(line) for line in (DS/'provenance/source_label_conflicts.jsonl').open(encoding='utf-8')]
    assert not {r['sha256'] for r in rows}&{r['SHA256'] for r in conflicts}
    splits={s:dict(Counter(r['label'] for r in rows if r['split']==s)) for s in ('train','validation','test')}
    assert all(splits[s]=={'benign':1400 if s=='train' else 300,'malicious':1400 if s=='train' else 300} for s in splits)
    labels=b.csvread(DS/'label.csv');groups=Counter(r['split_group_id'] for r in rows)
    summary={**b.load(BACKUP/'audit/validation.json'),'dataset_version':VERSION,'validated_at':b.now(),
        'total':4000,'archives_hash_verified':4000,'metadata_status':{'ok':4000},
        'archive_bytes':sum(int(r['artifact_bytes']) for r in rows),'split_counts':splits,'eligible_split_counts':splits,
        'cross_split_overlaps':overlaps,'group_count':len(groups),'multi_sample_groups':sum(v>1 for v in groups.values()),
        'largest_group':max(groups.values()),'byte_tree_status':dict(Counter(r['byte_tree_status'] for r in records.values())),
        'source_reported_typosquatting':sum(r['is_typosquatting']=='true' for r in rows),
        'typosquatting_unknown':sum(r['is_typosquatting']=='unknown' for r in rows),
        'catalog_name_mapping_annotations':sum(r['typosquatting_label_basis']=='external_curated_name_target_mapping' for r in rows),
        'catalog_replacements':COUNT,'catalog_existing_mappings_enriched':7,
        'validation_test_membership_preserved':True,'retained_sample_splits_preserved':True,
        'text_coverage':{k:dict(v) for k,v in text.items()},
        'spellbound_candidates_by_label':dict(Counter(r['label'] for r in rows if r['spellbound_candidate']=='true')),
        'label_review_status':dict(Counter(r['review_status'] for r in labels)),
        'new_archives_metadata_freshly_parsed':COUNT,
        'retained_metadata_validation':'canonical digests verified against previously extracted cache; not re-extracted',
        'removed_original_archives_preserved_and_hash_verified':COUNT,
        'public_source_label_conflicts_in_active_dataset':0,
        'phase3_split_contract':'passed','cli_manifest_discovery_verified':None,
        'cli_manifest_note':'six CSV identity/path/label/split contracts verified; no new discovery or training invocation',
        'base_archive_integrity':'v1.2 original files retained; this patch changes active training membership only'}
    # Historical v1.2 fields remain explicitly scoped as historical.
    summary['v1_2_base_samples_retained_active']=summary.pop('base_samples_retained_active',None)
    summary['v1_2_additions_by_source']=summary.pop('additions_by_source',None)
    summary.pop('typo_additions_spellbound_matches',None)
    b.save(DS/'audit/validation.json',summary)
    state_rows=[{'label':lab,'field':field,'state':state,'samples':states[(lab,field)][state],
        'percentage':round(100*states[(lab,field)][state]/classn[lab],3)}
        for lab in ('benign','malicious') for field in STATE_FIELDS for state in ('missing','empty','placeholder','present')]
    dump_csv(DS/'audit/field_state_distribution.csv',state_rows)
    dump_csv(DS/'audit/text_coverage.csv',[{'label':lab,'samples':classn[lab],**text[lab]} for lab in classn])
    dump_csv(DS/'audit/added_samples.csv',[r for r in rows if r['origin'] in {'v1.2_added','v1.3_ecosystems_replacement'}])
    # Source-level annotations remain scoped: this is not independent evidence
    # that a particular release was used in the incident reported upstream.
    catalog=b.csvread(SURVEY/'pypi_all_comparison.csv');byname={r['normalized_name']:r for r in rows}
    for s in catalog:
        match=byname.get(s['normalized_malicious_package'])
        s['in_current_dataset']=str(bool(match)).lower()
        s['matched_samples']=1 if match else 0
        s['matched_labels']=match['label'] if match else ''
        s['matched_versions']=match['version'] if match else ''
        s['matched_splits']=match['split'] if match else ''
        s['matched_sample_ids']=match['sample_id'] if match else ''
        s['current_typo_annotations']=match['is_typosquatting'] if match else ''
    dump_csv(DS/'provenance/ecosystems_pypi_comparison.csv',catalog)
    report=render_report(rows,summary)
    (DS/'DATASET_REPORT.md').write_text(report,encoding='utf-8')
    (WORK/'DATASET_REPORT.md').write_text(report,encoding='utf-8')
    # Reuse the escaped offline renderer, then save under the new dataset version.
    b.write_html_report(report,summary)
    old_html=ROOT/'visual/dataset-v1.2-4000/index.html'
    new_html=ROOT/'visual/dataset-v1.3-4000/index.html';new_html.parent.mkdir(parents=True,exist_ok=True)
    new_html.write_text(old_html.read_text(encoding='utf-8').replace('Dataset PyPI v1.2','Dataset PyPI v1.3'),encoding='utf-8')
    # Restore the prior report at its existing URL.
    if (BACKUP/'previous_visual.html').exists():shutil.copy2(BACKUP/'previous_visual.html',old_html)
    readme=f'''# Dataset {VERSION} — 4.000 mẫu PyPI metadata

Ngày cập nhật: 25/10/2026. 2.000 benign / 2.000 malicious. Train/validation/test: 2.800/600/600.

Thay 20 malicious train chưa có bằng chứng typosquatting bằng 20 archive MalRegistry có mapping tên-target trong CSV ecosyste.ms. Giữ nguyên membership validation/test và split của mọi sample được giữ lại. Bảy tên malicious có sẵn cũng được bổ sung mapping ở phạm vi tên package.

Cả 4.000 archive đã kiểm tra lại SHA256. Metadata của 20 archive mới được đọc bằng parser tool; metadata giữ lại được kiểm tra digest từ cache extraction trước đó. Không thực thi/cài/build/import sample hoặc tải dependency/payload.

Annotation true theo nguồn: {summary['source_reported_typosquatting']}; unknown: {summary['typosquatting_unknown']}. Trong đó 27 annotation có mapping theo tên từ CSV mới, không có affected version/hash ở nguồn. `target_package` là target theo nguồn, chưa được xác minh hành vi độc lập. Các annotation không tự trở thành feature.

Đọc `DATASET_REPORT.md`, `audit/ecosystems_replacements.csv`, `audit/validation.json`. Sáu CSV đã đồng bộ. `manifest.csv` là đầu vào tool ưu tiên. Archive bị thay vẫn nằm trên ổ đĩa nhưng không còn trong manifest; không đếm file trong samples thay cho số mẫu hoạt động. Backup v1.2 ở `../Dataset_backups/v1.2-before-ecosystems-20261025/`.

Thống kê nguồn và file audit v1.2 không được tái diễn giải thành kết quả v1.3. Danh sách mới so nguồn ở `provenance/ecosystems_pypi_comparison.csv`. Model/metric cũ không được tái sử dụng như kết quả cho bản này; chạy bốn phase với output mới.
'''
    (DS/'README.md').write_text(readme,encoding='utf-8')
    config=b.load(BACKUP/'build_config.json');config.update({'dataset_version':VERSION,'updated_at':b.now(),
        'status':'complete','previous_dataset_version':'v1.2','previous_tables':str(BACKUP),
        'replacement_count':COUNT,'replacement_policy':'20 malicious train with unknown typo annotation and no name signal, replaced by local MalRegistry artifacts matching curated PyPI names; preserve validation/test membership',
        'external_catalog_source':b.load(SURVEY/'summary.json')['source_url'],
        'typosquatting_policy':'source batch claims plus curated name-target mappings; affected-version scope not inferred',
        'split_version':'v1.3-train-replacement','split_policy':'v1.2 splits retained for every retained sample; incoming byte-tree identities must not cross frozen validation/test',
        'catalog_name_mapping_annotations':27,'typosquatting_true':summary['source_reported_typosquatting']})
    b.save(DS/'build_config.json',config)
    b.save(WORK/'validation.json',summary)
    checksum={}
    for file in sorted(DS.rglob('*')):
        if file.is_file() and file.name!='checksums.json':
            relative=file.relative_to(DS).as_posix()
            checksum[relative]=archive_hashes.get(relative) or b.sha(file)
    b.save(DS/'checksums.json',checksum)
    b.save(WORK/'complete.json',{'at':b.now(),'version':VERSION,'replaced':20,
        'updated_existing_mappings':7,'active_samples':4000,'checksums_sha256':b.sha(DS/'checksums.json'),
        'report':str(DS/'DATASET_REPORT.md'),'visual':str(new_html)})
    print(json.dumps({k:summary[k] for k in ('total','catalog_replacements','source_reported_typosquatting',
        'typosquatting_unknown','catalog_name_mapping_annotations','cross_split_overlaps','split_counts')},ensure_ascii=True),flush=True)

def render_report(rows,s):
    replacements=b.csvread(DS/'audit/ecosystems_replacements.csv')
    table=['| Package thêm | Version | Target theo CSV | Package thay ra |', '| --- | --- | --- |']
    table+=['| '+' | '.join(r[k] for k in ('added_name','added_version','target_package','removed_name'))+' |' for r in replacements]
    states=s['text_coverage']
    table_text='\n'.join(table)
    return f'''# Báo cáo dataset PyPI metadata v1.3

Ngày cập nhật: 25/10/2026. Dataset hiện có **4.000 mẫu hợp lệ**, gồm **2.000 benign + 2.000 malicious**. Toàn bộ mẫu hoạt động thuộc PyPI.

## 1. Thay thế theo nguồn typosquatting mới

Đã thay **20 mẫu malicious thuộc train** có annotation typosquatting unknown và không khớp tín hiệu tên bằng **20 archive malicious MalRegistry có mapping tên-target trong [CSV ecosyste.ms](https://github.com/ecosyste-ms/typosquatting-dataset/blob/fd0bde98d200efe5c282a07edc4c68fba13252c6/typosquats.csv)**. Các tên mới phủ **17 target khác nhau**. Unknown không có nghĩa chắc chắn không phải typosquatting; tiêu chí thay thế dựa trên thông tin hiện có, không dựa trên dự đoán model.

{table_text}

Archive thay ra được giữ nguyên; sáu CSV hoạt động đã loại các ID đó và thêm ID từ SHA256 archive mới. Không cài, build, import hoặc thực thi sample; không tải package/dependency/payload mới.

## 2. Nguồn, annotation và phạm vi chứng cứ

Malicious label của archive mới kế thừa từ inventory MalRegistry đã chốt, kiểm tra lại bytes SHA256 và identity metadata. Mapping tên-target và classification kế thừa CSV ecosyste.ms tại commit `fd0bde98d200efe5c282a07edc4c68fba13252c6`. Classification được giữ đúng theo nguồn, chưa xác minh từng dạng biến đổi.

CSV upstream không có version/hash hoặc affected-version ranges. Vì vậy `typosquatting_evidence_scope=package_name_only; affected_versions_not_specified`; không khẳng định nguồn đó xác nhận riêng từng version trong bảng. Đây không phải xác minh hành vi độc lập. Các dòng alias sau chuẩn hóa và các target cần xem xét riêng không được chọn trong đợt này.

Đồng thời bổ sung mapping cho bảy tên malicious đã có: beautifulsup4, BeaufifulSoup, colorara, figlets, nmap-python, requesta, opnsea. Chi tiết `audit/ecosystems_existing_enriched.csv`. Nhãn benign/malicious, metadata gốc và split của chúng giữ nguyên.

Tổng annotation true theo nguồn hiện là **{s['source_reported_typosquatting']}**, gồm **1.024** theo đợt cập nhật MalRegistry đã đối chiếu bytes và **27** theo mapping tên-target ecosyste.ms (20 mới + 7 có sẵn). Còn **{s['typosquatting_unknown']} unknown**, không tự gán false. Mapping mục tiêu là thông tin audit, không được tự đưa vào reference/feature bằng nhãn test.

## 3. Split và chống trùng

| Tập | Benign | Malicious | Tổng |
| --- | --- | --- | --- |
| Train | 1400 | 1400 | 2800 |
| Validation | 300 | 300 | 600 |
| Test | 300 | 300 | 600 |

Membership và nhãn benign/malicious của validation/test được giữ nguyên. Split của mọi sample giữ lại không thay đổi. Mẫu mới có toàn bộ Python byte-tree trùng sample ở validation/test bị loại khỏi lựa chọn. Không trùng tên chuẩn hóa, SHA256 hoặc raw metadata; giao tập theo tên/hash/metadata/group/byte-tree đã kiểm tra đều bằng 0. Byte-tree không chứng minh đã loại hết tương đồng ngữ nghĩa hoặc quan hệ chiến dịch.

Có {s['group_count']} nhóm; {s['multi_sample_groups']} nhóm nhiều sample; lớn nhất {s['largest_group']} sample. Trạng thái hash Python tree: {json.dumps(s['byte_tree_status'],ensure_ascii=False)}. Hash chỉ dùng audit/group, không làm feature classifier.

## 4. Kiểm tra metadata và tính nhất quán

- Kiểm tra lại SHA256 từ bytes của cả 4.000 archive hoạt động; kiểm tra bảo toàn 20 archive thay ra.
- Đọc lại metadata của 20 archive mới bằng parser hiện tại; kiểm tra canonical digest metadata giữ lại từ extraction cache. Không gọi đây là re-extraction toàn bộ dataset.
- Bốn nghìn metadata hợp lệ, không trùng digest, không có hash xung đột nhãn giữa các nguồn đã biết.
- Sáu CSV cùng tập 4.000 sample_id; path, label, split, group nhất quán. Hợp đồng chia tập Phase 3 kiểm tra đạt.

| Lớp | Summary present | Description present | Cả hai không present |
| --- | --- | --- | --- |
| Benign | {states['benign'].get('Summary',0)} | {states['benign'].get('Description',0)} | {states['benign'].get('both_absent',0)} |
| Malicious | {states['malicious'].get('Summary',0)} | {states['malicious'].get('Description',0)} | {states['malicious'].get('both_absent',0)} |

Chi tiết 10 trường × 4 trạng thái ở `audit/field_state_distribution.csv`; kết quả kiểm tra tại `audit/validation.json`.

## 5. Danh sách file và lịch sử

- `dataset.csv`, `artifact.csv`, `label.csv`, `groups.csv`, `splits.csv`, `manifest.csv`: bộ dữ liệu hoạt động mới; manifest là đầu vào được tool ưu tiên.
- `audit/ecosystems_replacements.csv`: 20 cặp thay thế và archive cũ được bảo toàn.
- `provenance/ecosystems_pypi_comparison.csv`: đối chiếu 95 dòng nguồn PyPI với dataset sau cập nhật; có 27 tên trùng.
- `provenance/sources/ecosystems_typosquats.csv`: snapshot nguồn đầy đủ; provenance ghi rõ chỉ PyPI được đưa vào dataset.
- `checksums.json`: hash các file thực sự tồn tại; không dùng số file samples thay cho số mẫu trong manifest.
- Backup đầy đủ file metadata/bảng/báo cáo v1.2: `../Dataset_backups/v1.2-before-ecosystems-20261025/`; các archive gốc không bị xóa.

Dataset v1.2 trước đó được xây từ 2.292 mẫu nền: loại bốn mẫu không hợp lệ khỏi manifest, thêm 883 malicious và 829 benign. Những thống kê khảo sát kho MalRegistry v1.2 vẫn lưu như bằng chứng lịch sử, không coi là số liệu lựa chọn mới. Bản v1.3 chỉ thay 20 sample train và bổ sung annotation nguồn như mô tả ở trên.

## 6. Giới hạn và chạy tiếp

Nhãn vẫn kế thừa nguồn công bố. Cân bằng 50/50 không phản ánh tỷ lệ malicious ngoài thực tế. Dataset được bổ sung typosquatting và có thể chịu thiên lệch nguồn/chiến dịch; không suy rộng thành phát hiện toàn bộ malware PyPI. Không có nhãn âm typosquatting được xác minh đầy đủ để báo precision/recall/F1 cho nhiệm vụ riêng đó.

Đợt này không train hoặc đánh giá lại model. Kết quả cũ thuộc dataset cũ; validation/test đã được sử dụng trước đây nên không trở thành test độc lập mới chỉ vì thay train.

Chạy bốn phase vào output mới từ thư mục project, môi trường đã kích hoạt:

```powershell
python -m pypi_metadata_detector --extraction .\\Dataset --output .\\outputs\\Dataset-v1.3-4000
python -m pypi_metadata_detector --analysis .\\Dataset --output .\\outputs\\Dataset-v1.3-4000
python -m pypi_metadata_detector --preprocessing .\\Dataset --output .\\outputs\\Dataset-v1.3-4000
python -m pypi_metadata_detector --evaluate .\\Dataset --output .\\outputs\\Dataset-v1.3-4000
```
'''

if __name__=='__main__':
    if sys.argv[1]=='plan':plan()
    elif sys.argv[1]=='apply':apply()
    elif sys.argv[1]=='finalize':finalize()

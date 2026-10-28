"""Complete a compact label table using source evidence and TypoGard rules.

Sample archives are never opened or executed. Binary labels have explicitly
recorded operational meanings; detector output is not independent ground truth.
"""
from __future__ import annotations
import csv
from collections import Counter,defaultdict
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pypi_metadata_detector.common import normalize_name

DS=ROOT/'Dataset'
OUT=ROOT/'outputs/label-review-spellbound-20261025'
BACKUP=ROOT/'Dataset_backups/v1.3-before-label-review-20261025'
VERSION='v1.4'
FIELDS=['sample_id','package_name','version','label','is_typosquatting','target_package','evidence','label_method']
SOURCE_METHODS={'source_reported_update_batch','external_curated_name_target_mapping'}
RULE_NAMES=('repeated_characters','omitted_chars','swapped_characters','swapped_words','common_typos','version_numbers')

def now():return datetime.now(timezone.utc).isoformat()
def read(path):
    with Path(path).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def save(path,obj):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');tmp.replace(path)
def write(path,rows,fields=None):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.tmp')
    with tmp.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields or list(dict.fromkeys(k for r in rows for k in r)),extrasaction='ignore')
        w.writeheader();w.writerows(rows)
    tmp.replace(path)
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

class SpellBoundRules:
    def __init__(self,reference):
        path=ROOT/'scripts/vendor/typogard_name_rules.py'
        spec=importlib.util.spec_from_file_location('reviewed_typogard_name_rules',path)
        self.rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.rules)
        ranked=[];seen=set()
        for r in sorted(reference['rows'],key=lambda r:-int(r['download_count'])):
            name=normalize_name(r['project'])
            if name not in seen:ranked.append(name);seen.add(name)
        self.rules.popular_package_list=ranked
        self.rules.popular_package_set=set(ranked)
        self.rank={n:i for i,n in enumerate(ranked)}
    def check(self,name):
        n=normalize_name(name)
        if n in self.rank:
            return {'normalized_name':n,'exact_popular_name':True,'flagged':False,'targets':[],'signals':{},'best_target':'none'}
        targets=self.rules.get_typosquatting_targets(n)
        signals={}
        for key in RULE_NAMES:
            fn=getattr(self.rules,key)
            matches=fn(n) if key=='version_numbers' else fn(n,return_all=True)
            signals[key]=sorted(set(matches),key=lambda t:self.rank[t])
        all_matches={t for values in signals.values() for t in values}
        assert set(targets)<=all_matches
        assert bool(targets)==bool(all_matches)
        targets=sorted(set(targets),key=lambda t:self.rank[t])
        return {'normalized_name':n,'exact_popular_name':False,'flagged':bool(targets),
                'targets':targets,'signals':signals,'best_target':targets[0] if targets else 'none'}

def assign_label(row,prior,result,audit_ref):
    """Benign=0 by user convention; sources outrank detector non-detection."""
    if row['label']=='benign':return 0,'none','none','benign_assumption'
    prior_method=prior.get('typosquatting_label_basis') or prior.get('label_method')
    source_positive=str(prior.get('is_typosquatting','')).lower() in {'true','1'} and prior_method in SOURCE_METHODS
    if source_positive:
        evidence=prior.get('typosquatting_evidence_ref') or prior.get('evidence')
        if not evidence or evidence=='none':raise ValueError('source-positive label needs a source evidence reference')
        return 1,prior.get('target_package') or 'none',evidence,prior_method
    if result['flagged']:return 1,result['best_target'],audit_ref,'spellbound_heuristic'
    return 0,'none',audit_ref,'not_flagged_by_spellbound'

def review():
    OUT.mkdir(parents=True,exist_ok=True)
    base=BACKUP if (BACKUP/'snapshot.json').exists() else DS
    dataset=read(base/'dataset.csv');labels=read(base/'label.csv')
    prior_by_id={r['sample_id']:r for r in labels}
    assert len(dataset)==len(labels)==4000
    assert {r['sample_id'] for r in dataset}==set(prior_by_id)
    refpath=DS/'provenance/sources/top-pypi-packages-30-days.min.json'
    reference=json.loads(refpath.read_text(encoding='utf-8'))
    engine=SpellBoundRules(reference)
    reviewed=[];audit=[]
    for i,row in enumerate(dataset,1):
        prior=prior_by_id[row['sample_id']]
        assert row['label']==prior['label']
        result=engine.check(row['package_name'])
        audit_ref='audit/spellbound_label_review.jsonl:'+str(i)
        value,target,evidence,method=assign_label(row,prior,result,audit_ref)
        reviewed.append({'sample_id':row['sample_id'],'package_name':row['package_name'],
            'version':row['version'],'label':row['label'],'is_typosquatting':value,
            'target_package':target,'evidence':evidence,'label_method':method})
        audit.append({'sample_id':row['sample_id'],'package_name':row['package_name'],'label':row['label'],
            'split':row['split'],'upstream':'mt3443/typogard','upstream_commit':'9c106362605c920126736993100a213c9448961e',
            'reference_sha256':sha(refpath) if i==1 else None,'reference_targets':len(engine.rank),
            'prior_is_typosquatting':prior.get('is_typosquatting'),'prior_method':prior.get('typosquatting_label_basis'),
            'prior_target':prior.get('target_package'),**result,'final_is_typosquatting':value,
            'label_method':method,'evidence':evidence,'label_target':target,
            'evidence_scope':prior.get('typosquatting_evidence_scope','') if method in SOURCE_METHODS else
                'user_assumption' if method=='benign_assumption' else 'rule_derived; not independently confirmed'})
        if i%500==0:print(f'TypoGard author name rules reviewed {i}/4000',flush=True)
    summary={'reviewed_at':now(),'dataset_version':VERSION,'samples':4000,
        'schema':FIELDS,'labels':dict(Counter(r['label'] for r in reviewed)),
        'typosquatting_by_label':{lab:dict(Counter(str(r['is_typosquatting']) for r in reviewed if r['label']==lab)) for lab in ('benign','malicious')},
        'label_methods':dict(Counter(r['label_method'] for r in reviewed)),
        'detector_flagged_by_label':dict(Counter(r['label'] for r in audit if r['flagged'])),
        'reviewed_malicious':sum(r['label']=='malicious' for r in audit),
        'reviewed_benign':sum(r['label']=='benign' for r in audit),
        'source_positive_not_flagged':sum(r['label_method'] in SOURCE_METHODS and not r['flagged'] for r in audit),
        'target_mapped_labels':sum(r['target_package']!='none' for r in reviewed),
        'reference':{'path':str(refpath.relative_to(DS)),'sha256':sha(refpath),'snapshot_date':reference.get('last_update'),
            'ranking':'descending monthly download_count; frozen independently before this label review','targets':len(engine.rank)},
        'engine':{'repository':'https://github.com/mt3443/typogard','commit':'9c106362605c920126736993100a213c9448961e',
            'source_sha256':'e793599b1fc9456991f0e61b16209c60d4dfe39f28498478b6191b441a1b2d23',
            'pure_functions':list(RULE_NAMES),'normalization':'PyPA lowercase and collapse [-_.]+ to -',
            'scope':'original pure name functions; no npm dependency fetching; no 2020 weekly-download-threshold reproduction; no added Levenshtein fallback'},
        'zero_meaning':{'benign':'0 by user dataset convention; not independent negative review',
            'malicious':'0 means neither source-confirmed nor flagged by this frozen rule/reference configuration'},
        'metric_caution':'Rule-derived labels cannot independently evaluate the same detector; benign zeros are user assumptions.',
        'prior_label_csv_sha256':sha(base/'label.csv'),'prior_dataset_csv_sha256':sha(base/'dataset.csv')}
    write(OUT/'label.csv',reviewed,FIELDS)
    with (OUT/'spellbound_label_review.jsonl').open('w',encoding='utf-8') as f:
        for r in audit:f.write(json.dumps(r,ensure_ascii=True)+'\n')
    write(OUT/'spellbound_label_review.csv',[{'sample_id':r['sample_id'],'package_name':r['package_name'],
        'label':r['label'],'split':r['split'],'detector_flagged':int(r['flagged']),
        'signals':';'.join(k for k,v in r['signals'].items() if v),'candidate_targets':';'.join(r['targets']),
        'prior_is_typosquatting':r['prior_is_typosquatting'],'final_is_typosquatting':r['final_is_typosquatting'],
        'label_method':r['label_method']} for r in audit])
    save(OUT/'summary.json',summary)
    print(json.dumps(summary,ensure_ascii=True),flush=True)

def apply_review():
    summary=json.loads((OUT/'summary.json').read_text(encoding='utf-8'))
    planned=read(OUT/'label.csv')
    if not (BACKUP/'snapshot.json').exists():
        assert sha(DS/'label.csv')==summary['prior_label_csv_sha256']
        assert sha(DS/'dataset.csv')==summary['prior_dataset_csv_sha256']
        BACKUP.mkdir(parents=True,exist_ok=True)
        saved={}
        for rel in ('label.csv','dataset.csv','checksums.json','build_config.json','README.md',
                    'DATASET_REPORT.md','audit/validation.json'):
            src=DS/rel
            if src.is_file():
                dest=BACKUP/rel;dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(src,dest);saved[rel]=sha(src)
        save(BACKUP/'snapshot.json',{'saved_at':now(),'files':saved,
             'note':'Labels/annotations only; no archive or split membership changes.'})
    assert sha(BACKUP/'label.csv')==summary['prior_label_csv_sha256']
    old_rows=read(BACKUP/'dataset.csv');old_labels=read(BACKUP/'label.csv')
    labels={r['sample_id']:r for r in planned};old={r['sample_id']:r for r in old_rows}
    assert len(planned)==4000 and set(labels)==set(old)
    assert list(planned[0])==FIELDS
    assert all(all(str(r[k]).strip() for k in FIELDS) for r in planned),'no blank label cells'
    assert all(r['is_typosquatting'] in {'0','1'} for r in planned)
    audit={}
    with (OUT/'spellbound_label_review.jsonl').open(encoding='utf-8') as f:
        for line in f:
            r=json.loads(line);audit[r['sample_id']]=r
    for row in old_rows:
        lab=labels[row['sample_id']];assert row['label']==lab['label']
        row['dataset_version']=VERSION
        row['is_typosquatting']=lab['is_typosquatting']
        row['target_package']=lab['target_package']
        row['typosquatting_evidence_ref']=lab['evidence']
        row['typosquatting_label_basis']=lab['label_method']
        row['typosquatting_review_status']=('user_assumption' if lab['label']=='benign' else
            row['typosquatting_review_status'] if lab['label_method'] in SOURCE_METHODS else 'rule_reviewed')
        if lab['label_method']=='benign_assumption':
            row['typosquatting_evidence_scope']='user_dataset_convention; not independent negative verification'
        elif lab['label_method']=='spellbound_heuristic':
            row['typosquatting_evidence_scope']='rule_derived_name_similarity; target_inferred; not independent intent confirmation'
        elif lab['label_method']=='not_flagged_by_spellbound':
            row['typosquatting_evidence_scope']='not_flagged_on_frozen_reference; not proof of absence'
        row['label_method']=lab['label_method']
        row['spellbound_review_candidate']=str(int(audit[row['sample_id']]['flagged']))
    # Store the full former provenance table, keeping the active label table small.
    provenance=DS/'provenance';provenance.mkdir(exist_ok=True)
    shutil.copy2(BACKUP/'label.csv',provenance/'label_provenance_before_v1.4.csv')
    write(OUT/'staged_dataset.csv',old_rows)
    for name,source in (('label.csv',OUT/'label.csv'),('dataset.csv',OUT/'staged_dataset.csv')):
        shutil.copy2(source,DS/name)
    audit_dir=DS/'audit';audit_dir.mkdir(exist_ok=True)
    for name in ('spellbound_label_review.csv','spellbound_label_review.jsonl'):
        shutil.copy2(OUT/name,audit_dir/name)
    save(audit_dir/'label_review_summary.json',summary)
    source_dir=provenance/'sources/typogard';source_dir.mkdir(parents=True,exist_ok=True)
    for name in ('typogard_npm.py','README.md','LICENSE'):
        shutil.copy2(OUT/'sources'/name,source_dir/name)
    shutil.copy2(ROOT/'scripts/vendor/SOURCE.json',source_dir/'SOURCE.json')
    # Preserve existing sample IDs, class labels, split assignment and artifact paths.
    for name in ('manifest.csv','splits.csv','artifact.csv','groups.csv'):
        table=read(DS/name)
        assert len(table)==4000 and {r['sample_id'] for r in table}==set(labels)
        for item in table:
            r=old[item['sample_id']]
            if 'label' in item:assert item['label']==r['label']
            if 'split' in item:assert item['split']==r['split']
            if 'path' in item:assert item['path']==r['artifact_path']
    assert all(labels[r['sample_id']]['is_typosquatting']=='0' and labels[r['sample_id']]['evidence']=='none' for r in old_rows if r['label']=='benign')
    for lab in planned:
        if lab['evidence'].startswith('audit/spellbound_label_review.jsonl:'):
            line_no=int(lab['evidence'].rsplit(':',1)[1])
            # Row ordering is identical across dataset, label CSV and JSONL audit.
            assert planned[line_no-1]['sample_id']==lab['sample_id']
    validation=json.loads((BACKUP/'audit/validation.json').read_text(encoding='utf-8'))
    validation.update({'dataset_version':VERSION,'label_reviewed_at':summary['reviewed_at'],
        'source_reported_typosquatting':sum(r['label_method'] in SOURCE_METHODS for r in planned),
        'operational_typosquatting_positive':sum(r['is_typosquatting']=='1' for r in planned),
        'operational_typosquatting_negative':sum(r['is_typosquatting']=='0' for r in planned),
        'typosquatting_unknown':0,'label_methods':summary['label_methods'],
        'spellbound_author_rules_flagged_by_label':summary['detector_flagged_by_label'],
        'label_table_fields':FIELDS,'label_schema':'LABEL_SCHEMA.md',
        'label_review_scope':'name rules and source-label provenance only; no new archive rehash or extraction',
        'label_membership_class_labels_and_splits_unchanged':True})
    save(audit_dir/'validation.json',validation)
    config=json.loads((BACKUP/'build_config.json').read_text(encoding='utf-8'))
    config.update({'dataset_version':VERSION,'updated_at':now(),'previous_dataset_version':'v1.3',
        'previous_tables':str(BACKUP),'label_schema':str(DS/'LABEL_SCHEMA.md'),
        'typosquatting_policy':'benign=0 by user convention; keep source positives; remaining malicious use original TypoGard name rules; non-detection is operational 0',
        'typosquatting_true':validation['operational_typosquatting_positive'],
        'typosquatting_source_supported':validation['source_reported_typosquatting'],
        'typosquatting_heuristic_supported':summary['label_methods']['spellbound_heuristic'],
        'reference_sha256':summary['reference']['sha256']})
    save(DS/'build_config.json',config)
    schema=render_schema(summary)
    (DS/'LABEL_SCHEMA.md').write_text(schema,encoding='utf-8')
    report=render_report(summary,validation)
    (DS/'DATASET_REPORT.md').write_text(report,encoding='utf-8')
    (OUT/'REPORT.md').write_text(report+'\n\n'+schema,encoding='utf-8')
    readme=f'''# Dataset {VERSION} — PyPI metadata, 4.000 mẫu

Ngày cập nhật 25/10/2026. 2.000 benign / 2.000 malicious. Membership, artifact, nhãn benign/malicious và split không đổi so với v1.3. Train/validation/test: 2.800/600/600.

`label.csv` được rút gọn còn tám cột, toàn bộ is_typosquatting là 0/1. Benign=0 và evidence=none theo quy ước người dùng. Malicious giữ 1.051 nhãn dương có nguồn, thêm 110 nhãn heuristic; 839 mẫu không được TypoGard cảnh báo được ghi 0 có phương pháp rõ ràng. Không hiểu 0 của nhóm cuối là bằng chứng chắc chắn không typosquatting.

Đọc `LABEL_SCHEMA.md` để biết ý nghĩa từng cột và năm phương pháp gán nhãn. `DATASET_REPORT.md` tổng kết bản hiện tại. Provenance cũ giữ ở `provenance/label_provenance_before_v1.4.csv`; backup ở `../Dataset_backups/v1.3-before-label-review-20261025/`.

`audit/spellbound_label_review.csv` là bảng rà soát dễ đọc; JSONL cùng tên giữ mọi match và tham chiếu chi tiết. Mã sáu hàm gốc được chốt theo commit, lưu cùng license trong provenance/sources/typogard/. Snapshot PyPI 15.000 tên không lấy từ nhãn test. CLI classifier vẫn dùng cấu hình reference của riêng nó; không tự đổi feature engine hoặc target list từ nhãn.

Không dùng nhãn heuristic để báo độ chính xác độc lập cho cùng detector tạo nhãn. Nhãn benign=0 là quy ước dataset, không được coi là review âm độc lập. Không cài/build/import/thực thi sample hoặc tải dependency/payload.

Manifest vẫn là danh sách đầu vào tool ưu tiên. Những archive không hoạt động còn trên ổ đĩa phục vụ đối chiếu; không đếm file trong samples thay số dòng manifest. Artifact checksum cũ được giữ vì bytes không đổi; checksum các file bảng/tài liệu thay đổi được cập nhật.
'''
    (DS/'README.md').write_text(readme,encoding='utf-8')
    checks=json.loads((BACKUP/'checksums.json').read_text(encoding='utf-8'))
    updates=['label.csv','dataset.csv','build_config.json','README.md','DATASET_REPORT.md','LABEL_SCHEMA.md',
        'audit/validation.json','audit/label_review_summary.json','audit/spellbound_label_review.csv',
        'audit/spellbound_label_review.jsonl','provenance/label_provenance_before_v1.4.csv']
    updates+=['provenance/sources/typogard/'+n for n in ('typogard_npm.py','README.md','LICENSE','SOURCE.json')]
    for name in updates:checks[name]=sha(DS/name)
    save(DS/'checksums.json',checks)
    save(OUT/'complete.json',{'completed_at':now(),'dataset_version':VERSION,'samples':4000,
        'label_methods':summary['label_methods'],'table_fields':FIELDS,'backup':str(BACKUP),
        'artifacts_membership_class_labels_splits_unchanged':True,'checksums_sha256':sha(DS/'checksums.json')})
    print('APPLIED: compact labels, 4000 complete binary annotations, provenance retained, checksums updated.',flush=True)

def render_schema(s):
    return '''# Hợp đồng label.csv — v1.4

Quyết định người dùng ngày 25/10/2026: benign được quy ước không typosquatting (0), evidence=none; malicious được rà soát bằng SpellBound/TypoGard để hoàn thiện bảng. Nhãn benign/malicious ban đầu giữ nguyên.

| Cột | Ý nghĩa |
| --- | --- |
| sample_id | ID gắn với SHA256 artifact; khóa join các bảng |
| package_name | Tên package gốc từ dataset |
| version | Version dạng chuỗi |
| label | benign hoặc malicious — nhiệm vụ classifier chính |
| is_typosquatting | 0/1 theo chính sách dưới đây |
| target_package | Target từ nguồn hoặc giả thuyết detector; none nếu chưa xác định |
| evidence | URL nguồn hoặc vị trí dòng audit; benign luôn là chuỗi none |
| label_method | Cơ sở gán nhãn, bắt buộc giữ khi dùng dữ liệu |

| label_method | is_typosquatting | Ý nghĩa |
| --- | --- | --- |
| benign_assumption | 0 | Quy ước người dùng; không phải review âm độc lập |
| source_reported_update_batch | 1 | MalRegistry công bố đợt typosquatting; có đối chiếu archive với commit |
| external_curated_name_target_mapping | 1 | Mapping tên-target trong ecosyste.ms; nguồn không chỉ rõ version/hash |
| spellbound_heuristic | 1 | Hàm tên gốc TypoGard cảnh báo; target là giả thuyết, chưa xác minh intent |
| not_flagged_by_spellbound | 0 | Không có nhãn nguồn dương và không được bộ quy tắc/reference này cảnh báo; không chứng minh không typosquatting |

Không còn ô trống hoặc unknown trong bảng hoạt động. Tính đầy đủ của bảng không có nghĩa mọi nhãn đều được xác minh độc lập. Muốn chỉ dùng nhãn có nguồn thì lọc hai label_method source_reported_update_batch và external_curated_name_target_mapping. Không dùng nhãn tạo từ detector để tự báo precision/recall/F1 độc lập cho detector đó.

Các trường JSON provenance dài, scope/parse review cũ và ghi chú kỹ thuật được chuyển khỏi label.csv, giữ nguyên trong provenance/label_provenance_before_v1.4.csv và backup. Thông tin nguồn không bị xóa. dataset.csv giữ annotation đồng bộ; các cột audit cũ khác trong bảng đó vẫn là lịch sử.

Evidence dạng audit/spellbound_label_review.jsonl:N trỏ tới dòng N (đếm từ 1, không có header); dòng đó có sample_id để xác nhận. Có CSV audit cùng tên để đọc thuận tiện. Với nhãn nguồn dương nhưng không biết target, target_package=none; không tự nhận target đoán làm target đã xác nhận. Với heuristic, target_package là target được quy tắc chọn theo thứ tự độ phổ biến.

Engine dùng nguyên thân sáu hàm của mt3443/typogard commit 9c106362605c920126736993100a213c9448961e. Adapter chỉ nạp các hàm tên và hằng số đã đọc; không chạy CLI npm hoặc lấy dependency. Tên input/reference chuẩn hóa theo PyPA. Reference là snapshot 15.000 tên xếp theo monthly download_count ngày 01/10/2026. Không tái hiện ngưỡng weekly-download năm 2020 và không thêm Levenshtein fallback vào review này.

Các annotation này không tự được đưa vào X, không làm thay đổi nhãn benign/malicious hoặc split. Phase 2 của classifier chưa được thay engine theo review này.
'''

def render_report(s,v):
    return f'''# Dataset PyPI metadata v1.4 — hoàn thiện bảng nhãn

Chốt ngày 25/10/2026. **4.000 mẫu**, gồm **2.000 benign + 2.000 malicious**. So với v1.3 không thay artifact, sample_id, nhãn benign/malicious, membership hoặc split. Lần này chỉ sửa annotation, rút gọn label.csv và cập nhật tài liệu/checksum.

## 1. Bảng nhãn mới

label.csv có tám cột: sample_id, package_name, version, label, is_typosquatting, target_package, evidence, label_method. Không còn ô trống hoặc unknown. File provenance đầy đủ trước chỉnh sửa vẫn được giữ riêng.

| Lớp | Typosquatting 1 | Typosquatting 0 |
| --- | --- | --- |
| Benign | 0 | 2000 |
| Malicious | 1161 | 839 |
| Tổng | 1161 | 2839 |

| Cơ sở nhãn | Số mẫu |
| --- | --- |
| Benign=0 theo quy ước người dùng, evidence=none | 2000 |
| Nguồn MalRegistry công bố theo đợt cập nhật | 1024 |
| Nguồn ecosyste.ms có mapping tên-target | 27 |
| Heuristic từ hàm tên gốc TypoGard | 110 |
| Không có bằng chứng nguồn dương và không được TypoGard cảnh báo | 839 |

0 của 839 malicious là **không được cảnh báo trong cấu hình này**, không phải bằng chứng chắc chắn không typosquatting. Benign=0 là quy ước của dataset theo yêu cầu, không suy ra rằng benign không bao giờ có tên gần giống. label_method giữ rõ mức chứng cứ.

## 2. Rà soát SpellBound/TypoGard

Mã tác giả [TypoGard](https://github.com/mt3443/typogard) xác nhận đây là công cụ được gọi SpellBound trong paper. Dùng commit 9c106362605c920126736993100a213c9448961e, chỉ các hàm tên gốc: repeated_characters, omitted_chars, swapped_characters, swapped_words, common_typos, version_numbers. Thân hàm được giữ nguyên, có license MIT; wrapper chuẩn hóa tên PyPI và nạp snapshot 15.000 tên theo độ phổ biến tháng đã chốt.

Đã rà soát cả 2.000 malicious và kiểm tra thêm 2.000 benign cho audit. Detector cảnh báo **142 malicious và 16 benign**. Trong 142 malicious có 32 mẫu đã có bằng chứng nguồn và 110 mẫu mới được gán nhãn heuristic. **1.019 mẫu có bằng chứng nguồn không được cảnh báo** vẫn giữ 1; không dùng non-detection để xóa bằng chứng cũ. Benign vẫn giữ 0 và evidence=none theo quy ước, dù 16 tên có cảnh báo.

Đây là dùng hàm tên gốc với reference PyPI hiện tại, không phải chạy npm dependency CLI hoặc tái hiện đầy đủ thí nghiệm/ngưỡng lượt tải hàng tuần năm 2020. Không có thêm Levenshtein fallback. Mã nguồn đầy đủ, commit, SHA256 và license giữ ở provenance/sources/typogard/.

## 3. Tính toàn vẹn và pipeline

| Tập | Benign | Malicious | Tổng |
| --- | --- | --- | --- |
| Train | 1400 | 1400 | 2800 |
| Validation | 300 | 300 | 600 |
| Test | 300 | 300 | 600 |

Artifact, metadata gốc và split giữ nguyên. Các kiểm tra hash/metadata/archive của v1.3 tiếp tục được lưu với thời điểm cũ; không tuyên bố vừa đọc lại toàn bộ archive. Lần cập nhật này kiểm tra join các bảng, nhãn benign/malicious, split, schema nhãn mới, vị trí evidence và checksum của các file thay đổi.

Source: 2.000 malicious từ MalRegistry; benign gồm 1.171 mẫu nền lấy archive PyPI, OSCAR 233, PyGuard 225, PyPiGuard 214, OMCBench 157. Nhãn kế thừa nguồn, không phải toàn bộ được xác minh hành vi độc lập. Cả 4.000 mẫu đạt parser metadata ở audit trước đó; không đổi raw metadata trong lần này.

Bốn nghìn tên/hash archive khác nhau, 3.995 nhóm. Không giao tên/hash/metadata/group hoặc byte-tree được đo giữa các tập theo audit lưu từ v1.3. Không khẳng định đã kiểm tra hết tương đồng ngữ nghĩa/campaign. Annotation nguồn, assumption và heuristic không được đưa tự động vào classifier. Không chạy/cài/build/import sample hoặc tải dependency/payload.

## 4. Sử dụng và giới hạn

- Đọc LABEL_SCHEMA.md trước khi dùng is_typosquatting làm mục tiêu học/đánh giá.
- Nhãn heuristic 110 và benign assumption 2000 không phải ground truth độc lập; tránh dùng chúng để tự đánh giá chính bộ quy tắc tạo nhãn.
- Target ở 110 heuristic là giả thuyết; target nguồn có thể chưa chỉ rõ affected version/hash; target chưa biết giữ none.
- Review chỉ xét tín hiệu tên và nguồn đã có, không phân tích payload để chứng minh intent.
- Phase 2 hiện có vẫn dùng engine/reference được cấu hình riêng; review nhãn này không âm thầm đổi feature implementation.
- Chưa train/evaluate model lại ở bản v1.4. Nhãn classifier chính và raw feature inputs giữ nguyên.

Chi tiết dễ đọc: audit/spellbound_label_review.csv; mọi match: audit/spellbound_label_review.jsonl. Provenance cũ: provenance/label_provenance_before_v1.4.csv. Backup: ../Dataset_backups/v1.3-before-label-review-20261025/.
'''

if __name__=='__main__':
    if sys.argv[1]=='review':review()
    elif sys.argv[1]=='apply':apply_review()

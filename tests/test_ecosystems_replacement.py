import importlib.util
from pathlib import Path

path=Path(__file__).resolve().parents[1]/'scripts/replace_with_ecosystems_typos.py'
spec=importlib.util.spec_from_file_location('ecosystems_replacement',path)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_catalog_annotation_does_not_claim_version_verification(monkeypatch):
    monkeypatch.setattr(module.b,'load',lambda _: {'source_url':'https://example.com/pinned.csv'})
    r=module.annotation({'target_package':'requests','source':'public-catalog','classification':'omission'})
    assert r['target_package']=='requests'
    assert r['typosquatting_label_basis']=='external_curated_name_target_mapping'
    assert 'affected_versions_not_specified' in r['typosquatting_evidence_scope']
    assert 'no independent behavior verification' in r['review_notes']

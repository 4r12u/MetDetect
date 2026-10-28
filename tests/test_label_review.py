import ast
import importlib.util
from pathlib import Path
import pytest

path=Path(__file__).resolve().parents[1]/'scripts/review_dataset_labels.py'
spec=importlib.util.spec_from_file_location('label_review',path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def test_benign_convention_overrides_detector_without_fabricating_evidence():
    assert m.assign_label({'label':'benign'},{},{'flagged':True,'best_target':'requests'},'audit:1')==(0,'none','none','benign_assumption')


def test_non_detection_does_not_erase_source_positive():
    prior={'is_typosquatting':'true','typosquatting_label_basis':'source_reported_update_batch',
           'typosquatting_evidence_ref':'https://example.org/source','target_package':''}
    assert m.assign_label({'label':'malicious'},prior,{'flagged':False},'audit:2')==(1,'none','https://example.org/source','source_reported_update_batch')


def test_unknown_malicious_match_is_explicitly_heuristic():
    result=m.assign_label({'label':'malicious'},{'is_typosquatting':'unknown'},
                          {'flagged':True,'best_target':'requests'},'audit:3')
    assert result==(1,'requests','audit:3','spellbound_heuristic')


def test_zero_is_non_detection_with_audit_not_confirmed_absence():
    assert m.assign_label({'label':'malicious'},{'is_typosquatting':'unknown'},
                          {'flagged':False},'audit:4')==(0,'none','audit:4','not_flagged_by_spellbound')


def test_source_positive_requires_evidence():
    with pytest.raises(ValueError,match='source evidence'):
        m.assign_label({'label':'malicious'},{'is_typosquatting':'true',
          'typosquatting_label_basis':'source_reported_update_batch'}, {'flagged':False},'audit:5')


def engine():
    return m.SpellBoundRules({'rows':[{'project':n,'download_count':100-i} for i,n in enumerate(
        ['requests','python-nmap','abcd','my_package'])]})


@pytest.mark.parametrize('name,signal',[('requestss','repeated_characters'),('reqests','omitted_chars'),
    ('requsets','swapped_characters'),('nmap-python','swapped_words'),('requesta','common_typos'),('requests2','version_numbers')])
def test_original_rules_are_used(name,signal):
    result=engine().check(name)
    assert result['flagged'] and result['signals'][signal]


def test_upstream_short_name_guard_and_version_limit_are_preserved():
    e=engine()
    assert not e.check('abc')['flagged']
    assert not e.check('requests12')['flagged']
    assert e.check('my.package')['exact_popular_name']


def test_vendor_has_no_cli_network_or_process_imports():
    path=m.ROOT/'scripts/vendor/typogard_name_rules.py'
    tree=ast.parse(path.read_text(encoding='utf-8'))
    allowed={'re','typing','itertools'}
    for node in tree.body:
        if isinstance(node,ast.Import):assert all(x.name in allowed for x in node.names)
        if isinstance(node,ast.ImportFrom):assert node.module in allowed
    assert not any(isinstance(n,ast.FunctionDef) and n.name in {'main','get_all_transitive_dependencies'} for n in tree.body)

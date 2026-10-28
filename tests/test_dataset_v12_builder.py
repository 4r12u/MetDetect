"""Check survey indexing against exhaustive reference rules, not label guesses."""
import importlib.util
from pathlib import Path
import random
import zipfile

import pytest

path=Path(__file__).resolve().parents[1]/'scripts/build_dataset_v12.py'
spec=importlib.util.spec_from_file_location('dataset_v12_builder',path)
builder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def test_index_matches_exhaustive_six_rules_and_distance():
    targets=['requests','urllib3','numpy','python-nmap','my-other-package',
             'urllib','urllib33','abc123','abc','a-b-c','b-a-c','openssl']
    index=builder.NameIndex(targets)
    suspects={'requestss','reqests','requsets','requesta','requests123',
              'nmap-python','other-my-package','urllib333','abc1234','c-a-b',
              'completely-unrelated','requests','requesvs','numby','Requests'}
    rng=random.Random(42)
    for target in targets:
        for _ in range(20):
            i=rng.randrange(len(target))
            suspects.add(target[:i]+target[i+1:])
            suspects.add(target[:i]+rng.choice('a-z019')+target[i:])
            suspects.add(target[:i]+rng.choice('a-z019')+target[i+1:])
    for suspect in suspects:
        normalized=builder.normalize_name(suspect)
        actual=index.match(suspect)
        expected=set() if normalized in targets else {
            t for t in targets if any(builder.pair_signals(normalized,t).values())
            or builder.edit_distance(normalized,t)<=1}
        assert {m['target'] for m in actual['matches']}==expected,suspect
        assert actual['candidate']==bool(expected)


def test_heuristic_does_not_become_ground_truth():
    match={'candidate':True,'matches':[{'target':'requests','signals':['omitted_character'],'distance':1}]}
    annotation=builder.typo_annotation(None,match)
    assert annotation['spellbound_candidate']=='true'
    assert annotation['is_typosquatting']=='unknown'
    assert annotation['target_package']==''
    assert annotation['candidate_target_package']=='requests'


def test_local_path_cannot_escape_source(tmp_path):
    with pytest.raises(ValueError,match='unsafe_local_path'):
        builder.bounded_path(tmp_path,'../outside')


def test_byte_tree_groups_identical_code_with_different_paths(tmp_path):
    archives=[]
    for prefix in ('one','different-package'):
        p=tmp_path/(prefix+'.zip')
        with zipfile.ZipFile(p,'w') as z:
            z.writestr(prefix+'/module.py',b'print("never executed")\n')
            z.writestr(prefix+'/PKG-INFO','Name: '+prefix)
        archives.append(p)
    a,b=map(builder.byte_tree,archives)
    assert a['python_bytes_tree_sha256']==b['python_bytes_tree_sha256']
    assert a['python_files_hashed']==1


def test_empty_python_tree_is_not_a_shared_group(tmp_path):
    p=tmp_path/'metadata-only.zip'
    with zipfile.ZipFile(p,'w') as z:
        z.writestr('PKG-INFO','Name: example')
    assert builder.byte_tree(p)['python_bytes_tree_sha256']==''

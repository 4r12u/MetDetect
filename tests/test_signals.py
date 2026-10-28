import pytest
from pypi_metadata_detector.common import DEFAULTS
from pypi_metadata_detector.phase2_metadata_analysis.reference import default_reference
from pypi_metadata_detector.phase2_metadata_analysis.signals import analyze_record, edit_distance, field_state, name_signals, pair_signals
from pypi_metadata_detector.phase1_metadata_extraction.extract import parse_metadata
from pypi_metadata_detector.common import digest
from conftest import metadata_bytes

@pytest.mark.parametrize("value,state", [(None,"missing"), ("","empty"), ("None","placeholder"),
                                        ("unknown","placeholder"), ([], "empty"), (["", "MIT"],"present")])
def test_field_states(value,state):
    assert field_state(value) == state

@pytest.mark.parametrize("suspect,target,key", [
    ("requestss","requests","repeated_character"),
    ("requsts","requests","omitted_character"),
    ("reqeusts","requests","swapped_adjacent_character"),
    ("mysql-python","python-mysql","swapped_words"),
    ("requesta","requests","keyboard_or_visual_substitution"),
    ("requests-2","requests","version_suffix")])
def test_six_name_signals(suspect,target,key):
    assert pair_signals(suspect,target)[key]

def test_equivalent_names_not_typosquatting():
    value = name_signals("Scikit_Learn", ("scikit-learn",), 1)
    assert value["exact_target"] and not value["suspected_typosquatting"]

def test_nearest_and_rule_matches_are_distinct():
    value = name_signals("mysql-python", ("python-mysql", "mysql-pythons"), 1)
    assert value["nearest_target"] == "mysql-pythons"
    assert value["swapped_words"]
    assert edit_distance("kitten", "sitting") == 3

def test_registry_and_raw_identifiers_do_not_enter_features():
    metadata, _ = parse_metadata(metadata_bytes(extra="Author: UNKNOWN\nHome-page: http://127.0.0.1/private\n"))
    record = {"sample_id": "x", "status": "ok", "metadata": metadata, "metadata_digest": digest(metadata)}
    result = analyze_record(record, DEFAULTS, default_reference())
    assert result["registry"]["name_inventory"] == "unavailable"
    assert result["states"]["Author"] == "placeholder"
    assert not {"label", "name", "version", "author", "pypi_found", "http_status"} & result["features"].keys()
    assert result["lexical"] == {}

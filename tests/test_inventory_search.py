import pytest

from pypi_metadata_detector.common import ToolError
from pypi_metadata_detector.common import digest, read_json, write_json
from pypi_metadata_detector.cli import main
from pypi_metadata_detector.phase2_metadata_analysis.inventory_search import inventory_search_report, search_inventory
from pypi_metadata_detector.phase2_metadata_analysis.reference import default_reference


def test_inventory_search_finds_edits_excludes_self_and_does_not_force_a_match():
    inventory = {"tensrflow", "tensorflow", "requests", "reqeusts"}
    result = search_inventory("Tensrflow", inventory)
    assert result["name_in_snapshot"]
    assert [item["target"] for item in result["candidates"]] == ["tensorflow"]
    assert "omitted_character" in result["candidates"][0]["signals"]
    assert search_inventory("reqeusts", inventory)["candidates"][0]["target"] == "requests"
    assert search_inventory("completely-unrelated", inventory)["candidates"] == []


def test_inventory_search_requires_snapshot_and_valid_inputs():
    with pytest.raises(ToolError):
        inventory_search_report(default_reference(), ["requests"])
    with pytest.raises(ToolError):
        search_inventory("../invalid", set())
    with pytest.raises(ToolError):
        search_inventory("requests", set(), 0)


def test_candidates_are_deterministic_and_truncation_is_visible():
    row = search_inventory("cat", {"dat", "car", "fat", "cat"}, limit=2)
    assert row["candidate_count"] == 3
    assert row["truncated"]
    assert [item["target"] for item in row["candidates"]] == ["car", "dat"]


@pytest.mark.parametrize("name,target,signal", [
    ("requestss", "requests", "repeated_character"),
    ("tensrflow", "tensorflow", "omitted_character"),
    ("requiremetns", "requirements", "swapped_adjacent_character"),
    ("mysql-python", "python-mysql", "swapped_words"),
    ("1odash", "lodash", "keyboard_or_visual_substitution"),
    ("requests-123", "requests", "version_suffix"),
])
def test_each_rule_reaches_the_inventory(name, target, signal):
    result = search_inventory(name, {name, target})
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["target"] == target
    assert signal in result["candidates"][0]["signals"]
    assert result["flags"][signal]


@pytest.mark.parametrize("name,target,signal", [
    ("requestss", "requests", "repeated_character"),
    ("tensrflow", "tensorflow", "omitted_character"),
    ("requiremetns", "requirements", "swapped_adjacent_character"),
    ("mysql-python", "python-mysql", "swapped_words"),
    ("1odash", "lodash", "keyboard_or_visual_substitution"),
    ("requests-123", "requests", "version_suffix"),
])
def test_rule_is_reported_in_phase2_features(name, target, signal):
    from pypi_metadata_detector.common import DEFAULTS
    from pypi_metadata_detector.phase1_metadata_extraction.extract import parse_metadata
    from pypi_metadata_detector.phase2_metadata_analysis.signals import analyze_record
    from conftest import metadata_bytes
    metadata, _ = parse_metadata(metadata_bytes(name))
    record = {"sample_id": name, "status": "ok", "metadata": metadata, "metadata_digest": digest(metadata)}
    ref = default_reference([])
    ref.update(name_matching_mode="inventory", name_matching_algorithm="spellbound-signals-2",
               index_available=True, names=[name, target])
    ref["sha256"] = digest({k: v for k, v in ref.items() if k != "sha256"})
    result = analyze_record(record, DEFAULTS, ref)
    assert result["typosquatting"]["nearest_target"] == target
    assert result["typosquatting"][signal]
    assert result["features"]["name_" + signal] == 1
    assert result["features"]["name_typo_candidate"] == 1


def test_unrelated_substitution_does_not_trigger_generic_distance():
    assert search_inventory("buffer", {"buxfer"})["candidate_count"] == 0


def test_flags_not_lost_when_display_candidates_are_truncated():
    result = search_inventory("requestss", {"requests", "requestsss", "requestas"}, limit=1)
    assert result["truncated"]
    assert result["flags"]["repeated_character"]


def test_many_word_components_do_not_lose_swapped_words():
    suspect = "a-b-c-d-e-f-g-h"
    target = "h-g-f-e-d-c-b-a"
    assert search_inventory(suspect, {target})["flags"]["swapped_words"]


def test_cli_search_uses_inventory_and_preserves_existing_report(tmp_path):
    ref = default_reference(["pillow"])
    ref.update(names=["tensrflow", "tensorflow"], index_available=True,
               source="https://pypi.org/simple/", created_at="2026-01-01")
    ref["sha256"] = digest({key: value for key, value in ref.items() if key != "sha256"})
    write_json(tmp_path / "reference.json", ref)
    output = tmp_path / "report.json"
    args = ["reference", "search", "--references", str(tmp_path), "--name", "tensrflow",
            "--output", str(output), "--quiet"]
    assert main(args) == 0
    report = read_json(output)
    assert report["reference_sha256"] == ref["sha256"]
    assert report["results"][0]["candidates"][0]["target"] == "tensorflow"
    before = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == before

import csv
from urllib.error import HTTPError
import pytest
from pypi_metadata_detector.cli import main
from pypi_metadata_detector.common import DEFAULTS, Progress, ToolError, discover, read_json, write_json
from pypi_metadata_detector.phase1_metadata_extraction.extract import extract_run
from pypi_metadata_detector.phase2_metadata_analysis.reference import default_reference, get_json, load_reference, sync_reference
from conftest import metadata_bytes

def test_reference_checksum_and_url_allowlist(tmp_path):
    ref=default_reference()
    write_json(tmp_path/"reference.json",ref)
    assert load_reference(tmp_path)["targets"]==ref["targets"]
    ref["targets"].append("modified")
    write_json(tmp_path/"reference.json",ref)
    with pytest.raises(ToolError,match="checksum"):
        load_reference(tmp_path)
    with pytest.raises(ToolError,match="official_url"):
        get_json("http://127.0.0.1/private")

def test_registry_404_is_unavailable_not_malicious(tmp_path,monkeypatch):
    from pypi_metadata_detector.phase2_metadata_analysis import reference
    path=tmp_path/"PKG-INFO"; path.write_bytes(metadata_bytes())
    run=tmp_path/"run"
    extract_run(discover(path),run,DEFAULTS,Progress(True))
    def fake_get(url,*args,**kwargs):
        if url.endswith("/simple/"):
            return {"projects":[{"name":"example"}]},"123"
        raise HTTPError(url,404,"missing",{},None)
    monkeypatch.setattr(reference,"get_json",fake_get)
    ref=sync_reference(tmp_path/"refs",run=run)
    assert ref["releases"]["example|0.1"]["status"]=="unavailable"
    assert ref["index_available"]
    assert "malicious" not in str(ref["releases"])

def test_cli_without_labels_extract_analyze_and_training_error(tmp_path,capsys):
    path=tmp_path/"PKG-INFO"; path.write_bytes(metadata_bytes())
    run=tmp_path/"run"
    assert main(["extract","--input",str(path),"--output",str(run)])==0
    output=capsys.readouterr().out
    assert "[1/1]" in output and "Phase: 1" in output
    with (run/"manifest_template.csv").open(encoding="utf-8-sig",newline="") as stream:
        row=next(csv.DictReader(stream))
    assert row["label"]=="" and row["split"]==""
    assert main(["analyze","--run",str(run),"--quiet"])==0
    assert main(["train","--run",str(run),"--quiet"])==2
    assert "labels_required" in capsys.readouterr().err

def test_unpacked_distribution_is_one_sample(tmp_path):
    folder=tmp_path/"package"; info=folder/"example-0.1.dist-info"; info.mkdir(parents=True)
    (info/"METADATA").write_bytes(metadata_bytes())
    (folder/"example").mkdir()
    assert len(discover(folder))==1

def test_cli_scan_does_not_fit(training_run,tmp_path,monkeypatch):
    from pypi_metadata_detector.phase4_ml_classification.model import train_run
    from pypi_metadata_detector.phase3_preprocessing.preprocess import FeatureEncoder
    run,manifest,_=training_run
    train_run(run,manifest,Progress(True))
    path=tmp_path/"PKG-INFO"; path.write_bytes(metadata_bytes("unseen"))
    def fail(*args,**kwargs):
        raise AssertionError("Scan must not fit preprocessing")
    monkeypatch.setattr(FeatureEncoder,"fit",fail)
    assert main(["scan","--input",str(path),"--bundle",str(run/"bundle.joblib"),
                 "--output",str(tmp_path/"scan"),"--quiet"])==0

def test_automatic_group_split_keeps_versions_together():
    from pypi_metadata_detector.phase3_preprocessing.dataset import assign_splits
    records=[]
    for label in ("benign","malicious"):
        for i in range(10):
            for v in range(2):
                records.append({"label":label,"requested_split":None,"metadata_digest":f"{label}-{i}-{v}",
                                "group":f"{label}-{i}"})
    splits=assign_splits(records,42)
    assert set(splits)=={"train","validation","test"}
    by_group={}
    for row,split in zip(records,splits):
        assert row["group"] not in by_group or by_group[row["group"]]==split
        by_group[row["group"]]=split

import json
import pytest
from pypi_metadata_detector.common import DEFAULTS, Progress, ToolError, read_json, sample_folder, write_json
from pypi_metadata_detector.phase1_metadata_extraction.extract import extract_run
from pypi_metadata_detector.phase3_preprocessing.dataset import assign_splits, load_eligible
from pypi_metadata_detector.phase4_ml_classification.model import (bundle_reference, evaluate_run, load_bundle,
                                        predict_run, train_run)
from pypi_metadata_detector.phase2_metadata_analysis.reference import default_reference
from pypi_metadata_detector.phase2_metadata_analysis.signals import analyze_run
from conftest import metadata_bytes

def test_train_evaluate_and_bundle_reload(training_run):
    run, manifest, _ = training_run
    progress = Progress(True)
    bundle = train_run(run, manifest, progress)
    assert "onlyheldouttoken" not in bundle["encoder"].text_.vocabulary_
    loaded = load_bundle(run/"bundle.joblib")
    result = evaluate_run(run, loaded, manifest, "test", progress)
    assert result["models"][loaded["selected_model"]]["samples"] == 6
    records, _, _ = load_eligible(run, manifest)
    matrix = bundle["encoder"].transform(records)
    assert (bundle["models"]["rf"].predict(matrix) == loaded["models"]["rf"].predict(matrix)).all()
    assert set(loaded["models"]) == {"rf", "dt"}

def test_labels_can_be_attached_after_extraction(training_run):
    run, manifest, _ = training_run
    extraction = read_json(run/"extraction.json")
    for row in extraction["samples"]:
        row["label"] = None
    write_json(run/"extraction.json",extraction)
    with pytest.raises(ToolError, match="labels_required"):
        load_eligible(run)
    records, _, _ = load_eligible(run, manifest)
    assert len(records) == 24

def test_group_overlap_and_identical_metadata_conflicting_labels():
    records = [
        {"label":label,"requested_split":split,"metadata_digest":str(i),"group":group}
        for i,(label,split,group) in enumerate([
            ("benign","train","same"),("malicious","train","a"),
            ("benign","validation","same"),("malicious","validation","b"),
            ("benign","test","c"),("malicious","test","d")])]
    with pytest.raises(ToolError, match="overlap"):
        assign_splits(records,42)

def test_changed_metadata_detected(training_run):
    run, manifest, _ = training_run
    sample=read_json(run/"extraction.json")["samples"][0]
    p=sample_folder(run,sample["sample_id"])/"metadata.json"
    record=read_json(p); record["metadata"]["Summary"]="edited"
    write_json(p,record)
    with pytest.raises(ToolError,match="modified"):
        load_eligible(run,manifest)

def test_scan_mixed_inputs_without_labels(training_run,tmp_path):
    run, manifest, config = training_run
    progress=Progress(True)
    bundle=train_run(run,manifest,progress)
    path=tmp_path/"new"/"PKG-INFO"; path.parent.mkdir(); path.write_bytes(metadata_bytes("newpackage"))
    missing=tmp_path/"missing"; missing.mkdir()
    output=tmp_path/"scan"
    samples=[{"sample_id":"good","path":str(path),"label":None,"split":None},
             {"sample_id":"missing","path":str(missing),"label":None,"split":None}]
    extract_run(samples,output,config,progress)
    analyze_run(output,config,bundle_reference(bundle),progress)
    summary=predict_run(output,bundle,progress)
    assert summary["ok"]==1 and summary["not_predicted"]==1
    bad=read_json(sample_folder(output,"missing")/"prediction.json")
    assert bad["predicted_label"] is None

def test_tampered_bundle_rejected(training_run):
    run,manifest,_=training_run
    train_run(run,manifest,Progress(True))
    with (run/"bundle.joblib").open("ab") as stream: stream.write(b"modified")
    with pytest.raises(ToolError,match="checksum"):
        load_bundle(run/"bundle.joblib")

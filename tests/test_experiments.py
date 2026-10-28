import csv
import json

import numpy as np
import pytest
from scipy.sparse import csr_matrix

from pypi_metadata_detector.cli import main
from pypi_metadata_detector.common import Progress, ToolError, read_json, write_json
from pypi_metadata_detector.phase3_preprocessing.artifacts import preprocess_run, file_digest
from pypi_metadata_detector.phase3_preprocessing.preprocess import FeatureEncoder
from pypi_metadata_detector.phase4_ml_classification import experiments as exp
from pypi_metadata_detector.phase4_ml_classification.estimators import (
    binary_scores, load_training_config, make_estimator, top_features, default_training_config,
)
from pypi_metadata_detector.phase4_ml_classification.model import load_bundle, predict_run, bundle_reference
from pypi_metadata_detector.phase1_metadata_extraction.extract import extract_run
from pypi_metadata_detector.phase2_metadata_analysis.signals import analyze_run
from pypi_metadata_detector.reporting import build_report, write_visual
from conftest import metadata_bytes


@pytest.fixture
def prepared(training_run):
    run, _, _ = training_run
    preprocess_run(run, Progress(True))
    return run


def config_file(tmp_path, models=None, **kwargs):
    path = tmp_path / "training.json"
    write_json(path, {"models": models or {"dt": {}, "lr": {}, "svm": {}, "cnb": {}}, **kwargs})
    return path


def test_six_models_validation_test_and_no_refit(prepared, tmp_path, monkeypatch):
    pytest.importorskip("xgboost")
    config = config_file(tmp_path, {"dt": {}, "rf": {"params": {"n_estimators": 5}},
                                   "lr": {}, "svm": {}, "cnb": {},
                                   "xgb": {"params": {"n_estimators": 5, "max_depth": 2}}},
                         thresholds={"probability": [0.3, 0.7], "decision": [-0.5, 0.5]})
    before = file_digest(prepared / "encoder.joblib")
    def no_fit(*args, **kwargs):
        raise AssertionError("shared encoder must never refit")
    monkeypatch.setattr(FeatureEncoder, "fit", no_fit)
    summary = exp.train_experiment(prepared, Progress(True), config, "six")
    folder = prepared / "experiments" / "six"
    assert len(summary["best_trials"]) == 6
    assert not (folder / "test_metrics.json").exists()
    assert before == file_digest(prepared / "encoder.joblib")
    bundle = load_bundle(folder / "bundle.joblib")
    assert set(bundle["models"]) == {"dt", "rf", "lr", "svm", "cnb", "xgb"}
    assert bundle["models"]["lr"]["scale"].n_samples_seen_ == 12
    monkeypatch.setattr(type(bundle["models"]["dt"]), "fit", no_fit)
    result = exp.test_experiment(prepared, Progress(True), "six")
    assert result["selected_model"] == summary["selected_model"]
    assert all(m["samples"] == 6 and m["average_precision"] is not None for m in result["models"].values())
    assert result["models"]["svm"]["score_kind"] == "decision"
    test_hash = file_digest(folder / "test_metrics.json")
    assert exp.test_experiment(prepared, Progress(True), "six") == result
    assert file_digest(folder / "test_metrics.json") == test_hash
    report = build_report(prepared, "six")
    assert len(report["top_features"]) == 6 and report["experiment"]["test_evaluated"]
    assert sum(bool(r["predicted_label"]) for r in report["rows"]) == 12
    page = write_visual(report, tmp_path / "report.html")
    assert "Top Feature" in page.read_text("utf-8")


def test_tuning_isolated_does_not_use_test_matrix(prepared, tmp_path, monkeypatch):
    config = config_file(tmp_path, {"dt": {"grid": {"max_depth": [1, 3]}}, "lr": {"grid": {"C": [0.1, 1.0]}}})
    original = exp.load_prepared
    def protected(*args, **kwargs):
        prep, records, excluded, analysis, prepared_data = original(*args, **kwargs)
        prepared_data[3].pop("test")  # Any test access during training would now fail.
        return prep, records, excluded, analysis, prepared_data
    monkeypatch.setattr(exp, "load_prepared", protected)
    first = exp.train_experiment(prepared, Progress(True), config, "first")
    assert first["trial_count"] == 4
    folder = prepared / "experiments" / "first"
    bundle_hash = file_digest(folder / "bundle.joblib")
    exp.train_experiment(prepared, Progress(True), config, "second")
    assert file_digest(folder / "bundle.joblib") == bundle_hash
    with pytest.raises(FileExistsError):
        exp.train_experiment(prepared, Progress(True), config, "first")


@pytest.mark.parametrize("patch", [
    {"models": {"unknown": {}}}, {"jobs": 0}, {"models": {"dt": {"params": {"evil": 1}}}},
    {"thresholds": {"probability": [1.5]}}, {"models": {"dt": {"grid": {"max_depth": [1, 2]}}}, "max_trials": 1},
    {"models": {"dt": {"params": {"max_depth": {"nested": 1}}}}}, {"top_k": True},
])
def test_invalid_config_rejected(tmp_path, patch):
    path = tmp_path / "bad.json"
    write_json(path, patch)
    with pytest.raises(ToolError):
        load_training_config(path)


def test_failed_trials_preserved_and_not_selected(prepared, tmp_path):
    config = config_file(tmp_path, {"dt": {"grid": {"max_depth": [-1, 2]}}})
    summary = exp.train_experiment(prepared, Progress(True), config, "partial")
    assert summary["failed_trials"] == 1
    trials = read_json(prepared / "experiments" / "partial" / "trials.json")
    assert trials[0]["status"] == "failed" and summary["best_trials"]["dt"] == 2


def test_nonconverged_excluded(prepared, tmp_path):
    config = config_file(tmp_path, {"svm": {"params": {"max_iter": 1, "tol": 1e-15}}, "dt": {}})
    summary = exp.train_experiment(prepared, Progress(True), config, "convergence")
    assert "svm" not in summary["best_trials"]
    assert summary["not_converged_trials"] == 1


def test_stale_data_hidden_and_test_rejected(prepared, tmp_path):
    exp.train_experiment(prepared, Progress(True), config_file(tmp_path), "stale")
    report = read_json(prepared / "preprocessing.json")
    report["features"] += 1
    write_json(prepared / "preprocessing.json", report)
    assert build_report(prepared)["metrics"] == {}
    with pytest.raises(ToolError):
        exp.test_experiment(prepared, Progress(True), "stale")


@pytest.mark.parametrize("bad", ["../outside", "..", "a/b", "C:\\escape", "a.b"])
def test_experiment_path_rejects_escape(tmp_path, bad):
    with pytest.raises(ToolError):
        exp.experiment_path(tmp_path, bad)


def test_rankings_ties_and_lower_is_better():
    ranks = exp.rankings({"a": {"malicious_f1": .8, "fit_seconds": 2},
                          "b": {"malicious_f1": .8, "fit_seconds": 1}})
    assert [r["rank"] for r in ranks["malicious_f1"]] == [1, 1]
    assert ranks["fit_seconds"][0]["model"] == "b"


def test_cli_explicit_test_and_svm_inference(prepared, tmp_path):
    config = config_file(tmp_path, {"svm": {}})
    assert main(["--evaluate", str(prepared), "--train-config", str(config), "--experiment", "svm-only", "--quiet"]) == 0
    assert main(["--evaluate", str(prepared), "--test", "--quiet"]) == 2
    assert main(["--evaluate", str(prepared), "--experiment", "svm-only", "--test", "--quiet"]) == 0
    assert main(["--metric", str(prepared), "--experiment", "svm-only", "--quiet"]) == 0
    bundle = load_bundle(prepared / "experiments" / "svm-only" / "bundle.joblib")
    path = tmp_path / "PKG-INFO"
    path.write_bytes(metadata_bytes("newpackage"))
    run = tmp_path / "scan"
    extract_run([{"sample_id": "new", "path": str(path), "label": None, "split": None}], run, bundle["config"], Progress(True))
    analyze_run(run, bundle["config"], bundle_reference(bundle), Progress(True))
    assert predict_run(run, bundle, Progress(True))["ok"] == 1
    with (run / "predictions.csv").open(encoding="utf-8-sig") as stream:
        assert list(csv.DictReader(stream))[0]["score_kind"] == "decision"


def test_top_features_signed_and_grouping():
    X = csr_matrix([[0, 1], [1, 0], [0, 2], [2, 0]])
    model = make_estimator("lr", {}, default_training_config()).fit(X, [0, 1, 0, 1])
    data = top_features(model, ["meta:name_distance", "text:safe"], 20)
    directions = {r["feature"]: r["direction"] for r in data["features"]}
    assert directions == {"meta:name_distance": "malicious", "text:safe": "benign"}
    assert {r["group"] for r in data["features"]} == {"name", "text"}

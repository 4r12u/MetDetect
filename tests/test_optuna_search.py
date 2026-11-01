"""Exercise Optuna through Phase 4 without touching real sample data or held-out test."""
import pytest

from pypi_metadata_detector.cli import main
from pypi_metadata_detector.common import Progress, ToolError, read_json, write_json
from pypi_metadata_detector.phase3_preprocessing.artifacts import preprocess_run
from pypi_metadata_detector.phase4_ml_classification import experiments
from pypi_metadata_detector.phase4_ml_classification.model import load_bundle
from pypi_metadata_detector.phase4_ml_classification.optuna_search import load_optuna_config
from pypi_metadata_detector.reporting import build_report, write_visual


def optuna_config(tmp_path, trials=3):
    path = tmp_path / "optuna.json"
    write_json(path, {"n_trials": trials, "sampler_seed": 42, "space": {
        "n_estimators": {"type": "int", "low": 3, "high": 8},
        "max_depth": {"type": "int", "low": 1, "high": 3},
        "subsample": {"type": "float", "low": 0.5, "high": 1.0}}})
    return path


def base_config(tmp_path):
    path = tmp_path / "base.json"
    write_json(path, {"models": {"xgb": {"params": {"n_estimators": 5, "max_depth": 2,
                                                      "subsample": 0.8, "learning_rate": 0.1}}}})
    return path


def test_optuna_experiment_warm_start_validation_bundle_and_dashboard(training_run, tmp_path, monkeypatch):
    pytest.importorskip("optuna")
    pytest.importorskip("xgboost")
    run, _, _ = training_run
    preprocess_run(run, Progress(True))
    original = experiments.load_prepared
    def no_test(*args, **kwargs):
        result = original(*args, **kwargs)
        result[4][3].pop("test")
        return result
    monkeypatch.setattr(experiments, "load_prepared", no_test)
    summary = experiments.train_experiment(run, Progress(True), base_config(tmp_path), "optuna-test",
                                           optuna_path=optuna_config(tmp_path))
    folder = run / "experiments" / "optuna-test"
    trials = read_json(folder / "trials.json")
    assert len(trials) == 3 and all(t["status"] == "success" for t in trials)
    assert trials[0]["params"] == {"n_estimators": 5, "max_depth": 2, "subsample": 0.8, "learning_rate": 0.1}
    assert summary["optimization"]["baseline_enqueued"] and not summary["test_evaluated"]
    assert summary["optimization"]["objective_split"] == "validation"
    assert not (folder / "test_metrics.json").exists()
    best = max(trials, key=lambda trial: trial["metrics"]["malicious_f1"])
    assert summary["best_trials"]["xgb"] == best["trial"]
    bundle = load_bundle(folder / "bundle.joblib")
    assert bundle["selected_model"] == "xgb"
    assert bundle["models"]["xgb"].get_params()["max_depth"] == best["params"]["max_depth"]
    report = build_report(run, "optuna-test")
    assert len(report["trials"]) == 3 and "test" not in report["metrics"]
    page = write_visual(report, tmp_path / "report.html")
    document = page.read_text(encoding="utf-8")
    assert "__REPORT_DATA__" not in document and "optuna-tpe" in document


def test_optuna_failed_trial_is_recorded_and_search_continues(training_run, tmp_path, monkeypatch):
    pytest.importorskip("optuna")
    pytest.importorskip("xgboost")
    run, _, _ = training_run
    preprocess_run(run, Progress(True))
    original = experiments.make_estimator
    calls = []
    def sometimes_fail(*args):
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("fixture failure")
        return original(*args)
    monkeypatch.setattr(experiments, "make_estimator", sometimes_fail)
    result = experiments.train_experiment(run, Progress(True), base_config(tmp_path), "optuna-fail",
                                          optuna_path=optuna_config(tmp_path, 2))
    assert result["trial_count"] == 2 and result["failed_trials"] == 1
    assert [t["status"] for t in read_json(run / "experiments/optuna-fail/trials.json")] == ["failed", "success"]


def test_optuna_cli_and_separate_test(training_run, tmp_path, monkeypatch):
    pytest.importorskip("optuna")
    pytest.importorskip("xgboost")
    from pypi_metadata_detector import workflow
    monkeypatch.setattr(workflow, "PROJECT_ROOT", tmp_path)
    run, _, _ = training_run
    preprocess_run(run, Progress(True))
    assert main(["--evaluate", str(run), "--train-config", str(base_config(tmp_path)),
                 "--optuna", str(optuna_config(tmp_path, 2)), "--experiment", "optuna-cli", "--quiet"]) == 0
    assert not (run / "experiments/optuna-cli/test_metrics.json").exists()
    assert main(["--evaluate", str(run), "--experiment", "optuna-cli", "--test", "--quiet"]) == 0
    assert (run / "experiments/optuna-cli/test_metrics.json").exists()
    assert main(["--evaluate", str(run), "--experiment", "optuna-cli", "--test", "--optuna",
                 str(optuna_config(tmp_path)), "--quiet"]) == 2


def test_optuna_rejects_config_without_xgb_before_creating_experiment(training_run, tmp_path):
    run, _, _ = training_run
    wrong = tmp_path / "lr-only.json"
    write_json(wrong, {"models": {"lr": {}}})
    with pytest.raises(ToolError, match="must_include_xgb"):
        experiments.train_experiment(run, Progress(True), wrong, "invalid", optuna_path=optuna_config(tmp_path))
    assert not (run / "experiments/invalid").exists()


@pytest.mark.parametrize("space", [
    {"unknown": {"type": "float", "low": 0, "high": 1}},
    {"max_depth": {"type": "int", "low": 1, "high": 100}},
    {"subsample": {"type": "float", "low": 0, "high": 1}},
    {"learning_rate": {"type": "float", "low": 0.1, "high": 0.1}},
    {"n_estimators": {"type": "int", "low": 1.5, "high": 10}},
])
def test_optuna_config_rejects_invalid_spaces(tmp_path, space):
    path = tmp_path / "bad.json"
    write_json(path, {"n_trials": 3, "sampler_seed": 42, "space": space})
    with pytest.raises(ToolError):
        load_optuna_config(path)

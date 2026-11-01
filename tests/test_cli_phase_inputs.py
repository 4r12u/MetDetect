from pathlib import Path

import pytest

from pypi_metadata_detector.cli import main
from pypi_metadata_detector.common import Progress, ToolError, read_json, write_json
from pypi_metadata_detector.phase3_preprocessing.artifacts import preprocess_run, file_digest
from pypi_metadata_detector.phase4_ml_classification.estimators import load_training_config, select_models
from pypi_metadata_detector import workflow


def test_output_chain_folder_and_previous_phase_files(training_run, tmp_path, monkeypatch, inventory_reference):
    run, _, _ = training_run
    monkeypatch.setattr(workflow, "PROJECT_ROOT", tmp_path)
    assert main(["--analysis", str(run / "extraction.json"), "--quiet"]) == 0
    assert main(["--preprocessing", str(run / "analysis.json"), "--quiet"]) == 0
    before = file_digest(run / "encoder.joblib")
    assert main(["--evaluate", str(run / "preprocessing.json"), "--model", "lr,dt",
                 "--experiment", "two", "--metric", str(run), "--quiet"]) == 0
    folder = run / "experiments" / "two"
    summary = read_json(folder / "experiment.json")
    assert list(summary["training_config"]["models"]) == ["lr", "dt"]
    assert len(summary["best_trials"]) == 2
    assert not (folder / "test_metrics.json").exists()
    assert before == file_digest(run / "encoder.joblib")
    assert main(["--evaluate", str(run), "--experiment", "two", "--test", "--quiet"]) == 0
    assert main(["--metric", str(run / "preprocessing.json"), "--experiment", "two", "--quiet"]) == 0


def test_model_override_keeps_grid_and_counts_only_selected(tmp_path):
    config = tmp_path / "train.json"
    write_json(config, {"max_trials": 1, "models": {"dt": {"grid": {"max_depth": [1, 2]}},
                                                  "lr": {"params": {"C": 2.0}}}})
    result = load_training_config(config, "lr")
    assert result["models"] == {"lr": {"params": {"C": 2.0}}}
    with pytest.raises(ToolError, match="trial_budget"):
        load_training_config(config, "dt")
    # CLI can add a known algorithm absent from the file, using documented defaults.
    assert load_training_config(config, "svm")["models"] == {"svm": {}}
    assert list(load_training_config(None, "all")["models"]) == ["dt", "rf", "lr", "svm", "cnb", "xgb"]


@pytest.mark.parametrize("value", ["", "dt,", "dt,dt", "unknown", "dt,all", "dt;payload", "../lr"])
def test_invalid_model_selection(value):
    with pytest.raises(ToolError, match="model_selection"):
        select_models(value)


@pytest.mark.parametrize("args", [
    ["--analysis", "somewhere", "--model", "dt"],
    ["--evaluate", "somewhere", "--model", "dt", "--test", "--experiment", "old"],
    ["--metric", "--model", "lr"],
])
def test_model_selection_rejected_outside_new_training(args, capsys):
    assert main(args) == 2
    assert "--model" in capsys.readouterr().err


def test_wrong_phase_file_or_moved_output_rejected(training_run, tmp_path):
    run, _, _ = training_run
    before = file_digest(run / "extraction.json")
    assert main(["--preprocessing", str(run / "extraction.json"), "--quiet"]) == 2
    assert main(["--analysis", str(run), "--output", str(tmp_path / "other"), "--quiet"]) == 2
    assert main(["--analysis", str(run / "extraction.json"), "--output", str(tmp_path / "other"), "--quiet"]) == 2
    assert main(["--extraction", str(run / "extraction.json"), "--quiet"]) == 2
    assert before == file_digest(run / "extraction.json")
    assert not (tmp_path / "other").exists()


def test_unknown_model_does_not_create_experiment(training_run):
    run, _, _ = training_run
    preprocess_run(run, Progress(True))
    assert main(["--evaluate", str(run), "--model", "unknown", "--experiment", "bad", "--quiet"]) == 2
    assert not (run / "experiments" / "bad").exists()


def test_folder_chain_does_not_need_original_dataset(training_run, monkeypatch, inventory_reference):
    run, _, _ = training_run
    def no_discovery(*args, **kwargs):
        raise AssertionError("later phases must not rediscover raw samples")
    monkeypatch.setattr(workflow, "collect_samples", no_discovery)
    assert main(["--analysis", str(run), "--references", str(inventory_reference), "--quiet"]) == 0
    assert main(["--preprocessing", str(run), "--quiet"]) == 0
    assert main(["--evaluate", str(run), "--model", "dt", "--experiment", "folder", "--quiet"]) == 0

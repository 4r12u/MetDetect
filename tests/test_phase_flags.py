import csv
import json
from pathlib import Path

import pytest

from pypi_metadata_detector.cli import main
from pypi_metadata_detector.common import Progress, ToolError, read_json, write_json
from pypi_metadata_detector.phase3_preprocessing.artifacts import file_digest, load_prepared
from pypi_metadata_detector.phase3_preprocessing.preprocess import FeatureEncoder
from pypi_metadata_detector.phase4_ml_classification.model import train_run
from pypi_metadata_detector.reporting import build_report, write_visual
from pypi_metadata_detector import workflow
from conftest import metadata_bytes


@pytest.fixture
def flags_dataset(training_run, tmp_path, monkeypatch):
    from pypi_metadata_detector.phase4_ml_classification import estimators
    defaults = estimators.default_training_config()
    defaults["models"] = {"dt": {}, "rf": {"params": {"n_estimators": 5}}}
    monkeypatch.setattr(estimators, "default_training_config", lambda: defaults.copy())
    _, manifest, config = training_run
    monkeypatch.setattr(workflow, "PROJECT_ROOT", tmp_path)
    source = tmp_path / "data"
    with manifest.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        row["artifact_path"] = Path(row.pop("path")).relative_to(source).as_posix()
    with (source / "dataset.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["sample_id", "artifact_path", "label", "split"])
        writer.writeheader()
        writer.writerows(rows)
    config_path = tmp_path / "config.json"
    write_json(config_path, config)
    assert main(["--extraction", str(source), "--config", str(config_path), "--quiet"]) == 0
    return source, workflow.run_path(source)


def test_four_flags_train_once_and_generate_metrics_html(flags_dataset, tmp_path, monkeypatch):
    source, run = flags_dataset
    extraction = read_json(run / "extraction.json")
    assert extraction["total"] == 24
    assert {s["label"] for s in extraction["samples"]} == {"benign", "malicious"}
    assert main(["--analysis", str(source), "--quiet"]) == 0
    assert main(["--preprocessing", str(source), "--quiet"]) == 0
    assert not (run / "bundle.joblib").exists()
    report, records, _, _, prepared = load_prepared(run)
    assert report["split_counts"] == {"train": 12, "validation": 6, "test": 6}
    assert "onlyheldouttoken" not in prepared[2].text_.vocabulary_
    encoder_hash = file_digest(run / "encoder.joblib")

    def no_fit(*args, **kwargs):
        raise AssertionError("Phase 4 must consume fitted Phase 3 artifacts")

    monkeypatch.setattr(FeatureEncoder, "fit", no_fit)
    assert main(["--evaluate", str(source), "--metric", "--visual", "--quiet"]) == 0
    assert file_digest(run / "encoder.joblib") == encoder_hash
    experiment = read_json(run / "experiments" / "latest.json")["experiment_id"]
    folder = run / "experiments" / experiment
    metrics = read_json(folder / "metrics.json")
    assert "test" not in metrics["metrics"]
    assert metrics["metrics"]["validation"]["models"]["rf"]["samples"] == 6
    assert sum(bool(r["predicted_label"]) for r in metrics["rows"]) == 6
    assert set(metrics["phases"].values()) == {"complete"}
    visual = tmp_path / "visual" / run.name / experiment / "index.html"
    assert visual.is_file()
    document = visual.read_text(encoding="utf-8")
    assert "__REPORT_DATA__" not in document and "Confusion matrix" in document
    assert main(["--metric", "--visual", "--quiet"]) == 0
    assert main(["--evaluate", str(source), "--experiment", experiment, "--test", "--quiet"]) == 0
    assert build_report(run)["metrics"]["test"]["models"]["rf"]["samples"] == 6


def test_phase_prerequisites_and_unlabelled_sample(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(workflow, "PROJECT_ROOT", tmp_path)
    sample = tmp_path / "PKG-INFO"
    sample.write_bytes(metadata_bytes())
    assert main(["--analysis", str(sample)]) == 2
    assert "--extraction" in capsys.readouterr().err
    assert main(["--extraction", str(sample), "--quiet"]) == 0
    assert main(["--evaluate", str(sample)]) == 2
    assert "--analysis" in capsys.readouterr().err
    assert main(["--analysis", str(sample), "--quiet"]) == 0
    assert main(["--preprocessing", str(sample)]) == 2
    assert "--bundle" in capsys.readouterr().err
    assert main(["--metric", str(sample), "--quiet"]) == 0
    report = read_json(workflow.run_path(sample) / "metrics.json")
    assert report["metrics"] == {} and report["rows"][0]["predicted_label"] is None


def test_single_sample_inference_never_fits(training_run, tmp_path, monkeypatch):
    run, manifest, _ = training_run
    train_run(run, manifest, Progress(True))
    monkeypatch.setattr(workflow, "PROJECT_ROOT", tmp_path)
    sample = tmp_path / "new" / "PKG-INFO"
    sample.parent.mkdir()
    sample.write_bytes(metadata_bytes("newexample"))
    bundle = run / "bundle.joblib"

    def no_fit(*args, **kwargs):
        raise AssertionError("Inference must never fit")

    monkeypatch.setattr(FeatureEncoder, "fit", no_fit)
    for phase in ("extraction", "analysis", "preprocessing", "evaluate"):
        assert main(["--" + phase, str(sample), "--bundle", str(bundle), "--quiet"]) == 0
    report = build_report(workflow.run_path(sample))
    assert report["metrics"] == {}
    assert report["preprocessing"]["mode"] == "inference"
    assert report["rows"][0]["predicted_label"] in {"benign", "malicious"}
    assert report["rows"][0]["label"] is None


def test_rerun_extraction_hides_old_scores(flags_dataset):
    source, run = flags_dataset
    for flag in ("analysis", "preprocessing", "evaluate"):
        assert main(["--" + flag, str(source), "--quiet"]) == 0
    assert build_report(run)["metrics"]
    assert main(["--extraction", str(source), "--quiet"]) == 0
    report = build_report(run)
    assert report["phases"]["2"] == report["phases"]["3"] == report["phases"]["4"] == "stale"
    assert report["metrics"] == {} and all(r["predicted_label"] is None for r in report["rows"])
    assert main(["--evaluate", str(source), "--quiet"]) == 2


def test_recursive_inputs_and_manifest_selection(tmp_path):
    dataset = tmp_path / "nested"
    info = dataset / "class" / "package" / "package.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_bytes(metadata_bytes())
    archive = dataset / "other" / "package.whl"
    archive.parent.mkdir()
    archive.write_bytes(b"not executed")
    samples = workflow.collect_samples(dataset)
    assert len(samples) == 2
    assert {Path(s["path"]).name for s in samples} == {"package", "package.whl"}


def test_cached_preprocessing_detects_tampering(flags_dataset):
    source, run = flags_dataset
    for flag in ("analysis", "preprocessing"):
        assert main(["--" + flag, str(source), "--quiet"]) == 0
    with (run / "X_train.npz").open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ToolError, match="checksum"):
        load_prepared(run)
    assert build_report(run)["phases"]["3"] == "stale"


def test_html_escapes_untrusted_metadata(tmp_path):
    payload = '</script><script>alert("metadata")</script>'
    report = {"run": str(tmp_path), "rows": [{"name": payload}], "metrics": {}}
    page = write_visual(report, tmp_path / "report.html")
    text = page.read_text(encoding="utf-8")
    assert payload not in text
    start = text.index('<script type="application/json" id="report-data">') + len('<script type="application/json" id="report-data">')
    embedded = json.loads(text[start:text.index('</script>', start)])
    assert embedded["rows"][0]["name"] == payload
    assert "innerHTML" not in text


def test_manifest_relative_escape_rejected(tmp_path):
    path = tmp_path / "manifest.csv"
    path.write_text("sample_id,path,label\ns,../outside.whl,benign\n", encoding="utf-8")
    with pytest.raises(ToolError, match="path_escape"):
        workflow.collect_samples(path)


def test_select_single_artifact_keeps_dataset_identity(flags_dataset):
    source, _ = flags_dataset
    rows = workflow.collect_samples(source)
    selected = workflow.collect_samples(Path(rows[0]["path"]))
    assert selected == [rows[0]]


def test_no_metric_path_reports_no_latest(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(workflow, "PROJECT_ROOT", tmp_path)
    assert main(["--metric"]) == 2
    assert "PATH" in capsys.readouterr().err


def test_full_training_then_inference_without_refitting(flags_dataset, tmp_path, monkeypatch):
    source, _ = flags_dataset
    run = tmp_path / "full-train"
    assert main(["--full", str(source), "--output", str(run), "--model", "dt",
                 "--experiment", "showcase", "--metric", "--visual", "--quiet"]) == 0
    folder = run / "experiments" / "showcase"
    assert (folder / "bundle.joblib").is_file()
    assert (folder / "validation_metrics.json").is_file()
    assert not (folder / "test_metrics.json").exists()
    assert (tmp_path / "visual" / run.name / "showcase" / "index.html").is_file()

    def no_fit(*args, **kwargs):
        raise AssertionError("Full inference must not train or refit preprocessing")

    monkeypatch.setattr(FeatureEncoder, "fit", no_fit)
    from pypi_metadata_detector.phase4_ml_classification import experiments
    monkeypatch.setattr(experiments, "make_estimator", no_fit)
    sample = tmp_path / "new" / "PKG-INFO"
    sample.parent.mkdir()
    sample.write_bytes(metadata_bytes("newexample"))
    scan = tmp_path / "full-scan"
    assert main(["--full", str(sample), "--output", str(scan), "--bundle",
                 str(folder / "bundle.joblib"), "--metric", "--visual", "--quiet"]) == 0
    report = build_report(scan)
    assert report["preprocessing"]["mode"] == "inference"
    assert report["rows"][0]["predicted_label"] in {"benign", "malicious"}
    assert (tmp_path / "visual" / scan.name / "index.html").is_file()


def test_full_rejects_existing_output_and_stops_on_extraction_error(tmp_path, monkeypatch):
    monkeypatch.setattr(workflow, "PROJECT_ROOT", tmp_path)
    sample = tmp_path / "PKG-INFO"
    sample.write_text("Metadata-Version: 2.1\nVersion: 1.0\n", encoding="utf-8")
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    assert main(["--full", str(sample), "--output", str(existing), "--quiet"]) == 2
    assert marker.read_text(encoding="utf-8") == "keep"
    run = tmp_path / "failed"
    assert main(["--full", str(sample), "--output", str(run), "--quiet"]) != 0
    assert (run / "extraction.json").is_file()
    assert not (run / "analysis.json").exists()


def test_short_full_creates_separate_runs_without_automatic_dashboard(flags_dataset, tmp_path):
    source, _ = flags_dataset
    assert main(["-f", str(source), "-m", "dt", "--quiet"]) == 0
    train = Path(read_json(tmp_path / "outputs" / "latest.json")["run"])
    experiment = read_json(train / "experiments" / "latest.json")["experiment_id"]
    bundle = train / "experiments" / experiment / "bundle.joblib"
    assert bundle.is_file()
    assert not (tmp_path / "visual").exists()

    sample = tmp_path / "new" / "PKG-INFO"
    sample.parent.mkdir()
    sample.write_bytes(metadata_bytes("newexample"))
    assert main(["-f", str(sample), "-b", str(bundle), "--quiet"]) == 0
    scan = Path(read_json(tmp_path / "outputs" / "latest.json")["run"])
    assert train != scan and bundle.is_file()
    assert read_json(scan / "preprocessing.json")["mode"] == "inference"
    assert (scan / "predictions.csv").is_file()
    assert not (tmp_path / "visual").exists()

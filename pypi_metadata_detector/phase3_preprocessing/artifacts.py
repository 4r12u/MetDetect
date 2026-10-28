"""Persist Phase 3 separately; Phase 4 must consume the same fitted data."""
import hashlib
from importlib.metadata import version
from pathlib import Path

import joblib
from scipy.sparse import load_npz, save_npz

from ..common import ToolError, digest, read_json, write_csv, write_json
from .dataset import assign_splits, load_eligible
from .preprocess import prepare_training


def source_digest(records, analysis):
    return digest({"records": records, "analysis": analysis})


def file_digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def preprocess_run(run, progress, bundle=None):
    run = Path(run)
    # Removing the completion marker first makes interrupted reruns visibly incomplete.
    (run / "preprocessing.json").unlink(missing_ok=True)
    records, excluded, analysis = load_eligible(run, require_labels=bundle is None)
    if bundle is None:
        splits, parts, encoder, matrices = prepare_training(records, analysis["config"], progress)
        mode, training_id = "training", None
    else:
        if analysis["config"] != bundle["config"] or analysis["target_fingerprint"] != bundle["target_fingerprint"]:
            raise ToolError("preprocessing_bundle_config_or_targets_mismatch")
        encoder = bundle["encoder"]
        splits, parts = ["inference"] * len(records), {"inference": records}
        matrices = {"inference": encoder.transform(records)}
        mode, training_id = "inference", bundle["training_id"]
        progress.say(f"Phase 3 | Transform bằng model đã lưu | Samples: {len(records)} | Không fit lại")
    encoder_path = run / "encoder.joblib"
    joblib.dump(encoder, encoder_path, compress=3)
    files = {"encoder.joblib": file_digest(encoder_path)}
    for name, matrix in matrices.items():
        filename = "X_" + name + ".npz"
        save_npz(run / filename, matrix)
        files[filename] = file_digest(run / filename)
    mapping = [{"sample_id": r["sample_id"], "package": r["name"], "label": r["label"], "split": split,
                "group": r["group"], "metadata_digest": r["metadata_digest"]} for r, split in zip(records, splits)]
    write_csv(run / "splits.csv", mapping, ["sample_id", "package", "label", "split", "group", "metadata_digest"])
    write_json(run / "feature_names.json", encoder.feature_names_)
    report = {"schema_version": "preprocessing-1", "mode": mode, "training_id": training_id,
              "source_digest": source_digest(records, analysis), "files": files, "splits": splits,
              "sklearn_version": version("scikit-learn"), "samples": len(records), "excluded": excluded,
              "features": len(encoder.feature_names_), "split_counts": {n: len(p) for n, p in parts.items()}}
    write_json(run / "preprocessing.json", report)
    progress.say(f"Phase 3 hoàn thành | Đủ điều kiện: {len(records)} | Bị loại: {len(excluded)} | Đã lưu X và encoder")
    return report


def load_prepared(run, bundle=None):
    run = Path(run)
    if not (run / "preprocessing.json").is_file():
        raise ToolError("Chưa có Phase 3. Chạy --preprocessing với cùng đường dẫn trước.")
    report = read_json(run / "preprocessing.json")
    if report.get("schema_version") != "preprocessing-1" or report["sklearn_version"] != version("scikit-learn"):
        raise ToolError("preprocessing_version_mismatch")
    if report.get("mode") not in {"training", "inference"}:
        raise ToolError("preprocessing_mode_mismatch")
    inference = report["mode"] == "inference"
    if inference and (bundle is None or bundle["training_id"] != report["training_id"]):
        raise ToolError("Phase 3 dùng --bundle; Phase 4 cần cùng --bundle đó.")
    if not inference and bundle is not None:
        raise ToolError("Muốn dự đoán bằng --bundle, chạy lại Phase 3 với --bundle đó.")
    records, excluded, analysis = load_eligible(run, require_labels=not inference)
    if source_digest(records, analysis) != report["source_digest"]:
        raise ToolError("Dữ liệu Phase 1/2 hoặc nhãn đã đổi; chạy lại --preprocessing.")
    names = ("inference",) if inference else ("train", "validation", "test")
    expected_files = {"encoder.joblib"} | {"X_" + n + ".npz" for n in names}
    if set(report["files"]) != expected_files:
        raise ToolError("preprocessing_file_contract_mismatch")
    for filename, checksum in report["files"].items():
        path = run / filename
        if not path.is_file() or path.stat().st_size > 536_870_912 or file_digest(path) != checksum:
            raise ToolError("preprocessing_checksum_mismatch: " + filename)
    # This is our local Phase 3 artifact, never a file selected from the sample dataset.
    encoder = joblib.load(run / "encoder.joblib")
    splits = report["splits"]
    if len(splits) != len(records) or set(splits) != set(names):
        raise ToolError("preprocessing_split_mismatch")
    if not inference and splits != assign_splits(records, analysis["config"]["seed"]):
        raise ToolError("preprocessing_splits_changed; rerun Phase 3")
    parts = {name: [r for r, split in zip(records, splits) if split == name] for name in names}
    matrices = {name: load_npz(run / ("X_" + name + ".npz")) for name in names}
    if any(matrices[n].shape != (len(parts[n]), report["features"]) for n in names):
        raise ToolError("preprocessing_matrix_shape_mismatch")
    return report, records, excluded, analysis, (splits, parts, encoder, matrices)

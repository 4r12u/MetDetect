"""Group-aware training, validation selection, held-out evaluation and offline scan."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
from pathlib import Path
import uuid

import joblib
from scipy.sparse import save_npz
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score

from ..common import LABELS, ToolError, digest, discover, normalize_name, read_json, sample_folder, write_csv, write_json
from ..phase3_preprocessing.preprocess import prepare_training
from ..phase3_preprocessing.dataset import load_eligible
from ..phase2_metadata_analysis.reference import default_reference, target_fingerprint
from ..phase2_metadata_analysis.signals import FEATURE_VERSION

def metrics(y_true, predictions, scores=None):
    report = classification_report(y_true, predictions, labels=[0, 1], target_names=["benign", "malicious"],
                                   output_dict=True, zero_division=0)
    result = {"samples": len(y_true), "classification_report": report,
            "confusion_matrix": confusion_matrix(y_true, predictions, labels=[0, 1]).tolist(),
            "confusion_matrix_order": ["benign", "malicious"]}
    result.update(malicious_f1=report["malicious"]["f1-score"], malicious_recall=report["malicious"]["recall"],
                  malicious_precision=report["malicious"]["precision"], macro_f1=report["macro avg"]["f1-score"],
                  accuracy=report["accuracy"], false_positives=result["confusion_matrix"][0][1],
                  false_negatives=result["confusion_matrix"][1][0], roc_auc=None, average_precision=None)
    if scores is not None and len(set(y_true)) == 2:
        result.update(roc_auc=float(roc_auc_score(y_true, scores)),
                      average_precision=float(average_precision_score(y_true, scores)))
    return result

def train_run(run, manifest, progress, prepared=None):
    run = Path(run)
    records, excluded, analysis = load_eligible(run, manifest)
    config = analysis["config"]
    splits, parts, encoder, matrices = prepared if prepared is not None else prepare_training(records, config, progress)
    models = {
        "rf": RandomForestClassifier(n_estimators=config["rf_trees"], max_depth=config["rf_max_depth"],
                                    min_samples_leaf=config["min_samples_leaf"], class_weight=config["class_weight"],
                                    random_state=config["seed"], n_jobs=config["jobs"]),
        "dt": DecisionTreeClassifier(max_depth=config["dt_max_depth"], min_samples_leaf=config["min_samples_leaf"],
                                    class_weight=config["class_weight"], random_state=config["seed"]),
    }
    y_train = [LABELS[r["label"]] for r in parts["train"]]
    y_val = [LABELS[r["label"]] for r in parts["validation"]]
    validation = {}
    for name, model in models.items():
        progress.say(f"Phase 4 | Model: {name.upper()} | Status: TRAINING")
        model.fit(matrices["train"], y_train)
        validation[name] = metrics(y_val, model.predict(matrices["validation"]))
        progress.say(f"Phase 4 | Model: {name.upper()} | Status: COMPLETE | Validation F1(malicious): " +
                     f"{validation[name]['classification_report']['malicious']['f1-score']:.4f}")
    selected = max(models, key=lambda name: validation[name]["classification_report"]["malicious"]["f1-score"])
    training_id = uuid.uuid4().hex
    identities = {r["sample_id"]: {"label": r["label"], "metadata_digest": r["metadata_digest"],
                                 "split": split, "group": r["group"]} for r, split in zip(records, splits)}
    bundle = {"schema_version": "metadata-model-1", "feature_version": FEATURE_VERSION,
              "training_id": training_id, "config": config, "encoder": encoder, "models": models,
              "selected_model": selected, "targets": analysis["targets"],
              "name_reference": analysis.get("name_reference"),
              "target_fingerprint": analysis["target_fingerprint"], "reference_sha256": analysis["reference_sha256"],
              "identities": identities, "created_at": datetime.now(timezone.utc).isoformat(),
              "classes": LABELS, "sklearn_version": version("scikit-learn")}
    bundle_path = run / "bundle.joblib"
    joblib.dump(bundle, bundle_path, compress=3)
    bundle_path.with_suffix(".joblib.sha256").write_text(hashlib.sha256(bundle_path.read_bytes()).hexdigest() + "\n", encoding="ascii")
    for name, matrix in matrices.items():
        save_npz(run / ("X_" + name + ".npz"), matrix)
    mapping = [{"sample_id": r["sample_id"], "package": r["name"], "label": r["label"], "split": split,
                "group": r["group"], "metadata_digest": r["metadata_digest"]} for r, split in zip(records, splits)]
    write_csv(run / "splits.csv", mapping, ["sample_id", "package", "label", "split", "group", "metadata_digest"])
    write_json(run / "feature_names.json", encoder.feature_names_)
    write_json(run / "validation_metrics.json", {"training_id": training_id, "selected_model": selected, "models": validation})
    write_json(run / "training.json", {"training_id": training_id, "selected_model": selected,
                                      "samples": len(records), "excluded": excluded,
                                      "split_counts": dict(Counter(splits)), "config": config})
    # A retrain invalidates the previous test result; never leave stale metrics next to a new bundle.
    (run / "test_metrics.json").unlink(missing_ok=True)
    progress.say(f"Huấn luyện hoàn thành | Model được chọn bằng validation: {selected.upper()} | Bundle: {bundle_path}")
    return bundle

def load_bundle(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 536_870_912:
        raise ToolError("bundle_missing_or_size_limit")
    checksum_path = path.with_suffix(".joblib.sha256")
    if not checksum_path.is_file() or checksum_path.read_text("ascii").strip() != hashlib.sha256(path.read_bytes()).hexdigest():
        raise ToolError("bundle_checksum_mismatch")
    # Only a user-specified, locally trusted bundle is loaded. A checksum is integrity, not authentication.
    bundle = joblib.load(path)
    if bundle.get("schema_version") != "metadata-model-1" or bundle.get("feature_version") != FEATURE_VERSION:
        raise ToolError("unsupported_model_bundle")
    if bundle.get("classes") != LABELS or bundle["sklearn_version"] != version("scikit-learn"):
        raise ToolError("bundle_classes_or_sklearn_version_mismatch")
    for model in bundle["models"].values():
        if list(model.classes_) != [0, 1]:
            raise ToolError("model_class_mapping_mismatch")
    return bundle

def evaluate_run(run, bundle, manifest, split, progress):
    run = Path(run)
    records, excluded, analysis = load_eligible(run, manifest)
    if analysis["config"] != bundle["config"] or analysis["target_fingerprint"] != bundle["target_fingerprint"]:
        raise ToolError("evaluation_config_or_reference_mismatch")
    if set(r["sample_id"] for r in records) != set(bundle["identities"]):
        raise ToolError("evaluation_samples_differ_from_training_run")
    chosen = []
    for record in records:
        expected = bundle["identities"][record["sample_id"]]
        if record["label"] != expected["label"] or record["metadata_digest"] != expected["metadata_digest"]:
            raise ToolError("evaluation_labels_or_metadata_changed")
        if expected["split"] == split:
            chosen.append(record)
    if not chosen:
        raise ToolError("empty_evaluation_split")
    X = bundle["encoder"].transform(chosen)
    y = [LABELS[r["label"]] for r in chosen]
    from .estimators import model_outputs
    reports = {name: metrics(y, *model_outputs(bundle, name, X)[:2]) for name in bundle["models"]}
    result = {"training_id": bundle["training_id"], "split": split, "selected_model": bundle["selected_model"],
              "models": reports, "excluded": excluded}
    write_json(run / (split + "_metrics.json"), result)
    selected = reports[bundle["selected_model"]]
    progress.say(f"Đánh giá {split} | Samples: {len(chosen)} | Model: {bundle['selected_model'].upper()} | " +
                 f"F1(malicious): {selected['classification_report']['malicious']['f1-score']:.4f}")
    return result

def predict_run(run, bundle, progress, prepared_matrix=None):
    run = Path(run)
    extraction = read_json(run / "extraction.json")
    analysis = read_json(run / "analysis.json")
    if analysis["config"] != bundle["config"] or analysis["target_fingerprint"] != bundle["target_fingerprint"]:
        raise ToolError("scan_config_or_reference_mismatch")
    if analysis["extract_id"] != extraction["extract_id"]:
        raise ToolError("analysis_stale")
    try:
        records, _, _ = load_eligible(run, require_labels=False)
    except ToolError as exc:
        if str(exc) != "no_eligible_metadata_samples":
            raise
        records = []
    predictions = {}
    if records:
        from .estimators import model_outputs
        X = prepared_matrix if prepared_matrix is not None else bundle["encoder"].transform(records)
        values, probabilities, score_kind = model_outputs(bundle, bundle["selected_model"], X)
        for record, value, probability in zip(records, values, probabilities):
            predictions[record["sample_id"]] = {
                "sample_id": record["sample_id"], "name": record["name"], "version": record["version"],
                "status": "ok", "predicted_label": "malicious" if int(value) else "benign",
                "malicious_score": float(probability), "true_label": record["label"],
                "score_kind": score_kind,
                "model": bundle["selected_model"], "typosquatting": record["signals"]["typosquatting"],
                "unknown_fields": record["signals"]["unknown_fields"],
                "registry": record["signals"]["registry"],
                "text_truncated": record["signals"]["text_truncated"],
            }
    rows = []
    for position, sample in enumerate(extraction["samples"], 1):
        result = predictions.get(sample["sample_id"], {
            "sample_id": sample["sample_id"], "status": "not_predicted", "predicted_label": None,
            "malicious_score": None, "true_label": sample.get("label"),
            "reason": read_json(sample_folder(run, sample["sample_id"]) / "status.json")})
        result["training_id"] = bundle["training_id"]
        write_json(sample_folder(run, sample["sample_id"]) / "prediction.json", result)
        rows.append({"sample_id": result["sample_id"], "name": result.get("name"),
                     "version": result.get("version"), "status": result["status"],
                     "predicted_label": result["predicted_label"], "malicious_score": result["malicious_score"],
                     "score_kind": result.get("score_kind"),
                     "true_label": result.get("true_label"),
                     "typosquatting_candidate": result.get("typosquatting", {}).get("suspected_typosquatting"),
                     "nearest_target": result.get("typosquatting", {}).get("nearest_target")})
        progress.item(position, extraction["total"], result.get("name", sample["sample_id"]), 4,
                      result["status"].upper(), 0, str(result["predicted_label"]))
    write_csv(run / "predictions.csv", rows, list(rows[0]) if rows else [])
    summary = {"phase": 4, "total": len(rows), "ok": len(predictions),
               "not_predicted": len(rows)-len(predictions), "model": bundle["selected_model"],
               "training_id": bundle["training_id"]}
    write_json(run / "run_summary.json", summary)
    progress.say(f"Scan hoàn thành | Thành công: {len(predictions)}/{len(rows)} | Chưa dự đoán: {len(rows)-len(predictions)}")
    return summary

def bundle_reference(bundle):
    return bundle.get("name_reference") or default_reference(bundle["targets"])

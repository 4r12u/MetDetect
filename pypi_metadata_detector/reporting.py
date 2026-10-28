"""Terminal metrics and an offline HTML report. Reading reports never loads models."""
from collections import Counter
from datetime import datetime, timezone
import html
import json
from pathlib import Path

from .common import ToolError, digest, read_json, sample_folder


def _build_report_base(run):
    run = Path(run).resolve()
    extraction = read_json(run / "extraction.json")
    phases = {"1": "complete", "2": "not_run", "3": "not_run", "4": "not_run"}
    warnings, reports = [], {}
    input_info = read_json(run / "input.json") if (run / "input.json").is_file() else {}
    if input_info.get("synthetic"):
        warnings.append("Dữ liệu minh họa synthetic: metric chỉ kiểm tra chức năng, không là hiệu quả phát hiện thực.")
    analysis = read_json(run / "analysis.json") if (run / "analysis.json").is_file() else None
    if analysis:
        phases["2"] = "complete" if analysis["extract_id"] == extraction["extract_id"] else "stale"
    prep = read_json(run / "preprocessing.json") if (run / "preprocessing.json").is_file() else None
    if prep:
        phases["3"] = "stale"
        if phases["2"] == "complete":
            from .phase3_preprocessing.artifacts import file_digest, source_digest
            from .phase3_preprocessing.dataset import load_eligible
            try:
                records, _, current = load_eligible(run, require_labels=prep["mode"] == "training")
                files = {"encoder.joblib", "X_inference.npz"} if prep["mode"] == "inference" else {
                    "encoder.joblib", "X_train.npz", "X_validation.npz", "X_test.npz"}
                if (source_digest(records, current) == prep["source_digest"] and set(prep["files"]) == files
                        and all(file_digest(run / f) == value for f, value in prep["files"].items())):
                    phases["3"] = "complete"
            except (ToolError, OSError, KeyError, ValueError):
                pass
    phase4 = read_json(run / "phase4.json") if (run / "phase4.json").is_file() else None
    if phase4:
        phases["4"] = "stale"
        if phases["3"] == "complete" and phase4["preprocessing_digest"] == digest(prep):
            phases["4"] = "complete"
            for split in ("validation", "test"):
                path = run / (split + "_metrics.json")
                if path.is_file():
                    value = read_json(path)
                    if value["training_id"] == phase4["training_id"]:
                        reports[split] = value
    for name, status in phases.items():
        if status == "stale":
            warnings.append(f"Phase {name}: kết quả cũ không còn khớp dữ liệu; cần chạy lại.")
    analysis_rows = {s["sample_id"]: s for s in analysis["samples"]} if phases["2"] == "complete" else {}
    rows = []
    for sample in extraction["samples"]:
        folder = sample_folder(run, sample["sample_id"])
        record = read_json(folder / "metadata.json")
        metadata = record.get("metadata", {})
        row = {"sample_id": sample["sample_id"], "name": metadata.get("Name", Path(sample["path"]).name),
               "version": metadata.get("Version"), "label": sample.get("label"), "split": sample.get("split"),
               "extraction": sample["status"], "analysis": analysis_rows.get(sample["sample_id"], {}).get("status"),
               "reason": record.get("reason"), "predicted_label": None, "malicious_score": None, "score_kind": None,
               "typosquatting": None, "nearest_target": None, "unknown_fields": []}
        if row["analysis"] == "ok":
            signals = read_json(folder / "signals.json")
            if digest(signals) == analysis_rows[sample["sample_id"]]["signals_digest"]:
                row.update(typosquatting=signals["typosquatting"]["suspected_typosquatting"],
                           nearest_target=signals["typosquatting"]["nearest_target"], unknown_fields=signals["unknown_fields"])
        if phases["4"] == "complete" and (folder / "prediction.json").is_file():
            prediction = read_json(folder / "prediction.json")
            if prediction.get("training_id") == phase4["training_id"]:
                row.update(predicted_label=prediction.get("predicted_label"), malicious_score=prediction.get("malicious_score"),
                           score_kind=prediction.get("score_kind", "probability"))
        rows.append(row)
    if phases["3"] == "complete" and prep["mode"] == "training":
        for row, split in zip([r for r in rows if r["analysis"] == "ok"], prep["splits"]):
            row["split"] = split
    return {"schema_version": "report-1", "generated_at": datetime.now(timezone.utc).isoformat(),
            "run": str(run), "source": input_info.get("source"), "synthetic": input_info.get("synthetic", False),
            "phases": phases, "warnings": warnings, "total": extraction["total"],
            "extraction": {key: extraction[key] for key in ("ok", "partial", "skipped", "failed")},
            "labels": dict(Counter(row["label"] or "unlabelled" for row in rows)),
            "splits": dict(Counter(row["split"] or "unassigned" for row in rows)),
            "preprocessing": {k: prep[k] for k in ("mode", "samples", "features", "excluded", "split_counts")}
                if phases["3"] == "complete" else None,
            "reference": {"targets": len(analysis["targets"]), "sha256": analysis["reference_sha256"]}
                if phases["2"] == "complete" else None,
            "metrics": reports, "rows": rows,
            "note": "Tín hiệu typosquatting tách biệt nhãn malicious. Score decision là điểm quyết định, không phải xác suất. Score probability chưa được calibration. Prediction toàn dataset gồm cả train; metric test chỉ tính trên held-out test."}


def build_report(run, experiment_id=None):
    report = _build_report_base(run)
    run = Path(run).resolve()
    if experiment_id is None and not (run / "experiments" / "latest.json").is_file():
        return report
    # Inference has its own Phase 4 marker; old experiment results must not mask a scan.
    if report["preprocessing"] and report["preprocessing"]["mode"] == "inference" and experiment_id is None:
        return report
    from .phase4_ml_classification.experiments import resolve_experiment
    folder = resolve_experiment(run, experiment_id)
    summary = read_json(folder / "experiment.json")
    report["experiment"] = summary
    report["metrics"] = {}
    for row in report["rows"]:
        row.update(predicted_label=None, malicious_score=None, score_kind=None)
    prep = read_json(run / "preprocessing.json") if (run / "preprocessing.json").is_file() else {}
    if report["phases"]["3"] != "complete" or digest(prep) != summary["preprocessing_digest"]:
        report["phases"]["4"] = "stale"
        report["warnings"].append("Thí nghiệm không khớp dữ liệu Phase 3 hiện tại; metric được ẩn.")
        return report
    report["phases"]["4"] = "complete"
    report["warnings"] = [w for w in report["warnings"] if not w.startswith("Phase 4:")]
    report["top_features"] = read_json(folder / "top_features.json")
    report["trials"] = read_json(folder / "trials.json")
    report["errors"] = {}
    rows = {r["sample_id"]: r for r in report["rows"]}
    for split in ("validation", "test"):
        path = folder / (split + "_metrics.json")
        if not path.is_file():
            continue
        result = read_json(path)
        if result["training_id"] != summary["training_id"]:
            raise ToolError("experiment_metrics_mismatch")
        report["metrics"][split] = result
        report["errors"][split] = read_json(folder / (split + "_errors.json"))
        for pred in read_json(folder / (split + "_predictions.json")):
            if pred["model"] == summary["selected_model"] and pred["sample_id"] in rows:
                rows[pred["sample_id"]].update(predicted_label=pred["predicted_label"],
                    malicious_score=pred["score"], score_kind=pred["score_kind"])
    report["experiment"]["test_evaluated"] = "test" in report["metrics"]
    report["note"] = ("Chọn model/tham số/ngưỡng bằng validation. Test chỉ chạy khi yêu cầu riêng. "
                      "Bảng sample hiển thị model đã chọn trên các tập đã đánh giá; train không có prediction ở báo cáo này. "
                      "Score decision là điểm quyết định, không là xác suất. Nhãn malicious và typosquatting tách biệt.")
    return report


def print_report(report, progress):
    progress.say(f"Kết quả | Tổng: {report['total']} | " + " | ".join(f"{k}: {v}" for k, v in report["extraction"].items()))
    progress.say("Các phase | " + " | ".join(f"{k}: {v}" for k, v in report["phases"].items()))
    for warning in report["warnings"]:
        progress.say(warning)
    if report.get("experiment"):
        e = report["experiment"]
        progress.say(f"Experiment: {e['experiment_id']} | Selection: {e['selection_metric']} | Test: {'đã chạy' if e['test_evaluated'] else 'chưa chạy'}")
    if report["preprocessing"]:
        p = report["preprocessing"]
        progress.say(f"Phase 3 | Features: {p['features']} | Đủ điều kiện: {p['samples']} | Bị loại: {len(p['excluded'])}")
    if not report["metrics"]:
        progress.say("Chưa có metric đánh giá có nhãn hợp lệ. Sample không nhãn chỉ có prediction sau Phase 4.")
    predicted = [row for row in report["rows"] if row["predicted_label"]]
    if predicted:
        counts = Counter(row["predicted_label"] for row in predicted)
        progress.say(f"Prediction | Đã dự đoán: {len(predicted)}/{report['total']} | Benign: {counts['benign']} | Malicious: {counts['malicious']}")
        if len(report["rows"]) <= 10:
            for position, row in enumerate(predicted, 1):
                progress.item(position, report["total"], row["name"], 4, row["predicted_label"], 0,
                              f"score: {row['malicious_score']:.4f} | Typosquat: {row['typosquatting']}")
    for split, result in report["metrics"].items():
        progress.say(f"{split} | Model chọn bằng validation: {result['selected_model'].upper()}")
        for model, metric in result["models"].items():
            score = metric["classification_report"]["malicious"]
            progress.say(f"  {model.upper()} | N: {metric['samples']} | Precision: {score['precision']:.4f} | "
                         f"Recall: {score['recall']:.4f} | F1: {score['f1-score']:.4f} | "
                         f"Accuracy: {metric['classification_report']['accuracy']:.4f} | CM: {metric['confusion_matrix']}")
        for metric, ranking in result.get("rankings", {}).items():
            winners = [r["model"].upper() for r in ranking if r["rank"] == 1]
            if winners:
                progress.say(f"  Top {metric}: {', '.join(winners)} | {ranking[0]['value']:.4f}")
    for name, data in report.get("top_features", {}).items():
        progress.say(f"Top Feature {name.upper()} ({data['method']}): " +
                     ", ".join(r["feature"] for r in data["features"][:5]))


def write_visual(report, target):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(report, ensure_ascii=False, allow_nan=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    template = Path(__file__).with_name("report.html").read_text(encoding="utf-8")
    document = template.replace("__TITLE__", html.escape(Path(report["run"]).name)).replace("__REPORT_DATA__", data)
    target.write_text(document, encoding="utf-8")
    return target.resolve()

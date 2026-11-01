"""Immutable Phase 4 experiments over cached Phase 3 data, with explicit held-out test."""
from datetime import datetime, timezone
from importlib.metadata import version, PackageNotFoundError
from itertools import product
from pathlib import Path
import platform
import math
import re
import time
import uuid
import warnings

import joblib
import numpy as np
from sklearn.exceptions import ConvergenceWarning

from .. import __version__
from ..common import LABELS, ToolError, digest, read_json, write_csv, write_json
from ..phase2_metadata_analysis.signals import FEATURE_VERSION
from ..phase3_preprocessing.artifacts import file_digest, load_prepared
from .estimators import (RANK_METRICS, binary_scores, load_training_config, make_estimator,
                         model_outputs, top_features)
from .model import load_bundle, metrics


def experiment_path(run, experiment_id):
    if not isinstance(experiment_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", experiment_id):
        raise ToolError("invalid_experiment_id")
    base = (Path(run) / "experiments").resolve()
    path = base / experiment_id
    if not path.resolve().is_relative_to(base):
        raise ToolError("experiment_path_escape")
    return path


def resolve_experiment(run, experiment_id=None):
    if experiment_id is None:
        marker = Path(run) / "experiments" / "latest.json"
        if not marker.is_file():
            raise ToolError("no_experiment; run --evaluate PATH first")
        experiment_id = read_json(marker)["experiment_id"]
    path = experiment_path(run, experiment_id)
    if not (path / "experiment.json").is_file():
        raise ToolError("experiment_not_complete: " + experiment_id)
    return path


def rankings(reports):
    result = {}
    for metric in RANK_METRICS:
        candidates = [(name, report[metric]) for name, report in reports.items() if report.get(metric) is not None]
        minimize = metric in {"fit_seconds", "predict_seconds", "false_positives", "false_negatives"}
        candidates.sort(key=lambda row: (row[1] if minimize else -row[1], row[0]))
        result[metric] = [{"rank": 1 + sum(v < value if minimize else v > value for _, v in candidates),
                           "model": name, "value": value} for name, value in candidates]
    return result


def write_results(folder, split, reports, selected, training_id):
    result = {"training_id": training_id, "split": split, "selected_model": selected,
              "models": reports, "rankings": rankings(reports)}
    write_json(folder / (split + "_metrics.json"), result)
    write_csv(folder / (split + "_leaderboard.csv"),
              [{"model": name, **{k: m.get(k) for k in RANK_METRICS},
                "threshold": m.get("threshold"), "score_kind": m.get("score_kind")} for name, m in reports.items()],
              ["model", *RANK_METRICS, "threshold", "score_kind"])
    return result


def prediction_rows(name, records, predictions, scores, kind, threshold):
    rows = []
    for record, pred, score in zip(records, predictions, scores):
        truth = record["label"]
        predicted = "malicious" if int(pred) else "benign"
        outcome = ("TP" if pred else "FN") if truth == "malicious" else ("FP" if pred else "TN")
        rows.append({"sample_id": record["sample_id"], "package": record["name"], "model": name,
                     "true_label": truth, "predicted_label": predicted, "outcome": outcome,
                     "score": float(score), "score_kind": kind, "threshold": threshold})
    return rows


def write_predictions(folder, split, rows):
    columns = ["sample_id", "package", "model", "true_label", "predicted_label", "outcome", "score", "score_kind", "threshold"]
    write_csv(folder / (split + "_predictions.csv"), rows, columns)
    write_json(folder / (split + "_predictions.json"), rows)
    errors = [r for r in rows if r["outcome"] in {"FP", "FN"}]
    write_csv(folder / (split + "_errors.csv"), errors, columns)
    write_json(folder / (split + "_errors.json"), errors)


def environment():
    packages = {}
    for name in ("scikit-learn", "numpy", "scipy", "joblib", "xgboost"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = None
    return {"python": platform.python_version(), "platform": platform.platform(),
            "tool_version": __version__, "packages": packages}


def train_experiment(run, progress, config_path=None, experiment_id=None, model_selection=None,
                     optuna_path=None, loaded_prepared=None):
    run = Path(run).resolve()
    if optuna_path and config_path:
        supplied = read_json(config_path, 131_072)
        if isinstance(supplied, dict) and "models" in supplied and (
                not isinstance(supplied["models"], dict) or "xgb" not in supplied["models"]):
            raise ToolError("optuna_train_config_must_include_xgb")
    config = load_training_config(config_path, model_selection or ("xgb" if optuna_path else None))
    study, optimization, warm_started = None, None, False
    if optuna_path:
        if list(config["models"]) != ["xgb"] or config["models"]["xgb"].get("grid"):
            raise ToolError("optuna_requires_xgb_without_grid")
        from .optuna_search import load_optuna_config, make_study
        optimization = load_optuna_config(optuna_path)
        study, warm_started = make_study(optimization, config["models"]["xgb"].get("params", {}))
    prep, records, excluded, analysis, prepared = loaded_prepared if loaded_prepared is not None else load_prepared(run)
    if prep["mode"] != "training":
        raise ToolError("experiments_require_training_preprocessing")
    experiment_id = experiment_id or (datetime.now(timezone.utc).strftime("exp-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8])
    folder = experiment_path(run, experiment_id)
    folder.mkdir(parents=True, exist_ok=False)
    write_json(folder / "training_config.json", config)
    if optimization:
        write_json(folder / "optuna_config.json", {**optimization, "baseline_enqueued": warm_started})
    write_json(folder / "status.json", {"status": "running", "experiment_id": experiment_id})
    splits, parts, encoder, matrices = prepared
    train_y = [LABELS[r["label"]] for r in parts["train"]]
    val_y = [LABELS[r["label"]] for r in parts["validation"]]
    selected_metric = config["selection_metric"]
    trials, best, models, thresholds, report_models = [], {}, {}, {}, {}
    total = sum(np.prod([len(v) for v in spec.get("grid", {}).values()], dtype=int)
                for spec in config["models"].values())
    if study:
        total = optimization["n_trials"]
    # Test matrices may be integrity-checked/loaded, but are never passed to a model during tuning.
    for name, spec in config["models"].items():
        grid = spec.get("grid", {})
        combinations = range(total) if study else product(*grid.values())
        for combination in combinations:
            if study:
                from .optuna_search import suggest
                optuna_trial = study.ask()
                params = {**spec.get("params", {}), **suggest(optuna_trial, optimization)}
            else:
                optuna_trial = None
                params = {**spec.get("params", {}), **dict(zip(grid, combination))}
            trial = {"trial": len(trials)+1, "model": name, "params": params, "status": "failed"}
            if optuna_trial is not None:
                trial["optuna_number"] = optuna_trial.number
            start = time.perf_counter()
            progress.say(f"Phase 4 | Trial: {trial['trial']}/{total} | Model: {name.upper()} | TRAINING | Params: {params}")
            try:
                model = make_estimator(name, params, config)
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    model.fit(matrices["train"], train_y)
                fit_time = time.perf_counter() - start
                trial["warnings"] = [str(w.message) for w in caught]
                trial["converged"] = not any(issubclass(w.category, ConvergenceWarning) for w in caught)
                start_predict = time.perf_counter()
                scores, kind = binary_scores(model, matrices["validation"])
                default_predictions = model.predict(matrices["validation"])
                predict_time = time.perf_counter() - start_predict
                candidates = [None, *config["thresholds"].get(kind, [])]
                scored = []
                for threshold in candidates:
                    preds = default_predictions if threshold is None else (scores >= threshold).astype(int)
                    scored.append((threshold, metrics(val_y, preds, scores)))
                threshold, report = max(scored, key=lambda pair: pair[1][selected_metric])
                report.update(fit_seconds=fit_time, predict_seconds=predict_time, threshold=threshold, score_kind=kind)
                trial.update(status="success", metrics=report, fit_seconds=fit_time,
                             effective_params=model.get_params(deep=True) if not hasattr(model, "steps") else model[-1].get_params())
                # Persist JSON-friendly primitive parameters only (Pipeline objects never enter JSON).
                trial["effective_params"] = {k: v for k, v in trial["effective_params"].items()
                                             if v is None or type(v) in (str, int, float, bool)}
                # XGBoost's default missing-value sentinel is NaN; encode it explicitly in JSON metadata.
                trial["effective_params"] = {k: ("NaN" if isinstance(v, float) and math.isnan(v) else
                                                  str(v) if isinstance(v, float) and not math.isfinite(v) else v)
                                             for k, v in trial["effective_params"].items()}
                if trial["converged"] and (name not in best or report[selected_metric] > best[name]["metrics"][selected_metric]):
                    best[name], models[name], thresholds[name], report_models[name] = trial, model, threshold, report
                progress.say(f"Phase 4 | Trial: {trial['trial']}/{total} | {name.upper()} | SUCCESS | "
                             f"{selected_metric}: {report[selected_metric]:.4f} | Time: {fit_time:.2f}s" +
                             (" | WARNING: not converged; excluded from selection" if not trial["converged"] else ""))
            except (ValueError, TypeError, RuntimeError, ImportError) as exc:
                trial.update(error=type(exc).__name__ + ": " + str(exc), seconds=time.perf_counter()-start)
                progress.say(f"Phase 4 | Trial: {trial['trial']} | {name.upper()} | FAILED | {trial['error']}")
            if optuna_trial is not None:
                if trial["status"] == "success" and trial.get("converged"):
                    study.tell(optuna_trial, trial["metrics"][selected_metric])
                else:
                    from optuna.trial import TrialState
                    study.tell(optuna_trial, state=TrialState.FAIL)
            trials.append(trial)
            write_json(folder / "trials.json", trials)
    write_csv(folder / "trials.csv", [{"trial": t["trial"], "model": t["model"], "status": t["status"],
              "params": str(t["params"]), "converged": t.get("converged"), "error": t.get("error"),
              **{k: t.get("metrics", {}).get(k) for k in RANK_METRICS}} for t in trials],
              ["trial", "model", "status", "params", "converged", *RANK_METRICS, "error"])
    if not models:
        write_json(folder / "status.json", {"status": "failed", "reason": "no_converged_successful_models"})
        raise ToolError("no_successful_models; inspect " + str(folder / "trials.json"))
    selected = max(models, key=lambda name: report_models[name][selected_metric])
    training_id = uuid.uuid4().hex
    identities = {r["sample_id"]: {"label": r["label"], "metadata_digest": r["metadata_digest"],
                  "split": split, "group": r["group"]} for r, split in zip(records, splits)}
    bundle = {"schema_version": "metadata-model-1", "feature_version": FEATURE_VERSION,
              "training_id": training_id, "config": analysis["config"], "training_config": config,
              "encoder": encoder, "models": models, "thresholds": thresholds, "selected_model": selected,
              "targets": analysis["targets"], "target_fingerprint": analysis["target_fingerprint"],
              "name_reference": analysis.get("name_reference"),
              "reference_sha256": analysis["reference_sha256"], "identities": identities,
              "created_at": datetime.now(timezone.utc).isoformat(), "classes": LABELS,
              "sklearn_version": version("scikit-learn"), "environment": environment()}
    path = folder / "bundle.joblib"
    joblib.dump(bundle, path, compress=3)
    path.with_suffix(".joblib.sha256").write_text(file_digest(path)+"\n", encoding="ascii")
    validation = write_results(folder, "validation", report_models, selected, training_id)
    rows = []
    for name in models:
        preds, scores, kind = model_outputs(bundle, name, matrices["validation"])
        rows.extend(prediction_rows(name, parts["validation"], preds, scores, kind, thresholds[name]))
    write_predictions(folder, "validation", rows)
    features = {name: top_features(model, encoder.feature_names_, config["top_k"]) for name, model in models.items()}
    write_json(folder / "top_features.json", features)
    write_csv(folder / "top_features.csv", [{"model": name, "method": data["method"], **row}
              for name, data in features.items() for row in data["features"]],
              ["model", "method", "rank", "feature", "group", "importance", "signed_weight", "direction"])
    # Store the exact split and feature mapping used by every trial.
    write_csv(folder / "splits.csv", [{"sample_id": r["sample_id"], "group": r["group"],
              "label": r["label"], "split": s} for r, s in zip(records, splits)], ["sample_id", "group", "label", "split"])
    write_json(folder / "feature_names.json", encoder.feature_names_)
    summary = {"schema_version": "experiment-1", "experiment_id": experiment_id, "training_id": training_id,
               "created_at": bundle["created_at"], "run": str(run), "source_digest": prep["source_digest"],
               "preprocessing_digest": digest(prep), "dataset_identity": digest(identities),
               "selection_metric": selected_metric, "selected_model": selected, "training_config": config,
               "split_counts": prep["split_counts"], "features": prep["features"], "excluded": excluded,
               "environment": bundle["environment"], "best_trials": {n: t["trial"] for n, t in best.items()},
               "trial_count": len(trials), "failed_trials": sum(t["status"] == "failed" for t in trials),
               "not_converged_trials": sum(t.get("converged") is False for t in trials),
               "test_evaluated": False}
    if optimization:
        summary["optimization"] = {"method": "optuna-tpe", "optuna_version": version("optuna"),
                                   "sampler_seed": optimization["sampler_seed"],
                                   "space": optimization["space"], "baseline_enqueued": warm_started,
                                   "objective_split": "validation", "cross_validation": False}
    write_json(folder / "experiment.json", summary)
    write_json(folder / "status.json", {"status": "complete", "experiment_id": experiment_id})
    write_json(folder.parent / "latest.json", {"experiment_id": experiment_id})
    progress.say(f"Phase 4 hoàn thành | Experiment: {experiment_id} | Chọn bằng validation: {selected.upper()}")
    progress.say(f"Bundle: {path}\nTest chưa chạy. Khi chốt: --evaluate PATH --experiment {experiment_id} --test")
    return summary


def test_experiment(run, progress, experiment_id=None):
    folder = resolve_experiment(run, experiment_id)
    summary = read_json(folder / "experiment.json")
    prep, records, _, _, prepared = load_prepared(run)
    if digest(prep) != summary["preprocessing_digest"] or prep["source_digest"] != summary["source_digest"]:
        raise ToolError("experiment_data_changed; use original Phase 3 data")
    if (folder / "test_metrics.json").is_file():
        progress.say("Test đã chạy; dùng lại kết quả đã lưu, không huấn luyện lại.")
        return read_json(folder / "test_metrics.json")
    bundle = load_bundle(folder / "bundle.joblib")
    if bundle["training_id"] != summary["training_id"]:
        raise ToolError("experiment_bundle_mismatch")
    if any(summary["environment"]["packages"].get(p) != environment()["packages"].get(p)
           for p in ("numpy", "scipy", "xgboost")):
        raise ToolError("experiment_environment_changed; restore training package versions")
    _, parts, _, matrices = prepared
    y = [LABELS[r["label"]] for r in parts["test"]]
    reports, rows = {}, []
    validation = read_json(folder / "validation_metrics.json")
    for name in bundle["models"]:
        start = time.perf_counter()
        preds, scores, kind = model_outputs(bundle, name, matrices["test"])
        report = metrics(y, preds, scores)
        report.update(predict_seconds=time.perf_counter()-start,
                      fit_seconds=validation["models"][name]["fit_seconds"],
                      threshold=bundle["thresholds"][name], score_kind=kind)
        reports[name] = report
        rows.extend(prediction_rows(name, parts["test"], preds, scores, kind, bundle["thresholds"][name]))
    write_predictions(folder, "test", rows)
    result = write_results(folder, "test", reports, summary["selected_model"], summary["training_id"])
    progress.say(f"Test hoàn thành | {len(y)} samples | Model đã chốt bằng validation: {summary['selected_model'].upper()}")
    return result

"""Bounded model configuration and consistent binary scores; no dynamic code loading."""
import math

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from ..common import ToolError, read_json

MODEL_PARAMS = {
    "rf": {"n_estimators", "max_depth", "min_samples_leaf", "min_samples_split", "max_features", "class_weight"},
    "dt": {"max_depth", "min_samples_leaf", "min_samples_split", "max_features", "class_weight", "criterion"},
    "lr": {"C", "max_iter", "class_weight", "tol"},
    "svm": {"C", "max_iter", "class_weight", "tol"},
    "cnb": {"alpha", "norm", "fit_prior"},
    "xgb": {"n_estimators", "max_depth", "learning_rate", "subsample", "colsample_bytree",
            "min_child_weight", "reg_alpha", "reg_lambda", "scale_pos_weight"},
}
SELECT_METRICS = ("malicious_f1", "malicious_recall", "malicious_precision", "macro_f1", "accuracy",
                  "roc_auc", "average_precision")
RANK_METRICS = SELECT_METRICS + ("fit_seconds", "predict_seconds", "false_positives", "false_negatives")


def default_training_config():
    return {"seed": 42, "jobs": 1, "selection_metric": "malicious_f1", "max_trials": 50, "top_k": 20,
            "thresholds": {},
            "models": {"dt": {}, "rf": {}, "lr": {}, "svm": {}, "cnb": {}, "xgb": {}}}


def select_models(value):
    """Parse CLI names without importing or evaluating user-supplied code."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ToolError("invalid_model_selection")
    names = [n.strip().lower() for n in value.split(",")]
    if names == ["all"]:
        return ["dt", "rf", "lr", "svm", "cnb", "xgb"]
    if not names or any(n not in MODEL_PARAMS for n in names) or len(names) != len(set(names)):
        raise ToolError("invalid_model_selection; use dt, rf, lr, svm, cnb, xgb or all (comma-separated)")
    return names


def load_training_config(path=None, model_selection=None):
    config = default_training_config()
    supplied = read_json(path, 131_072) if path else {}
    if not isinstance(supplied, dict) or set(supplied) - set(config):
        raise ToolError("unknown_training_config_keys")
    config.update(supplied)
    for key, low, high in (("seed", 0, 2**32-1), ("jobs", 1, 64), ("max_trials", 1, 100), ("top_k", 1, 200)):
        if type(config[key]) is not int or not low <= config[key] <= high:
            raise ToolError("invalid_training_config: " + key)
    if config["selection_metric"] not in SELECT_METRICS:
        raise ToolError("invalid_selection_metric")
    thresholds = config["thresholds"]
    if not isinstance(thresholds, dict) or set(thresholds) - {"probability", "decision"}:
        raise ToolError("invalid_thresholds")
    for kind, values in thresholds.items():
        if not isinstance(values, list) or not 1 <= len(values) <= 31:
            raise ToolError("thresholds_require_1_to_31_values")
        if any(type(v) not in (int, float) or not math.isfinite(v) or
               kind == "probability" and not 0 <= v <= 1 for v in values):
            raise ToolError("invalid_threshold_value")
    models = config["models"]
    if not isinstance(models, dict) or not models or set(models) - set(MODEL_PARAMS):
        raise ToolError("invalid_model_list")
    counts = {}
    for name, spec in models.items():
        if not isinstance(spec, dict) or set(spec) - {"params", "grid"}:
            raise ToolError("invalid_model_spec: " + name)
        params, grid = spec.get("params", {}), spec.get("grid", {})
        if not isinstance(params, dict) or not isinstance(grid, dict) or (set(params) | set(grid)) - MODEL_PARAMS[name]:
            raise ToolError("unsupported_model_parameter: " + name)
        count = 1
        for values in grid.values():
            if not isinstance(values, list) or not 1 <= len(values) <= 20:
                raise ToolError("invalid_parameter_grid: " + name)
            count *= len(values)
        for value in list(params.values()) + [v for values in grid.values() for v in values]:
            if value is not None and (type(value) not in (str, int, float, bool) or
                                      isinstance(value, float) and not math.isfinite(value)):
                raise ToolError("invalid_parameter_value: " + name)
        counts[name] = count
    selected = select_models(model_selection)
    if selected is not None:
        # CLI chooses algorithms; matching JSON specs retain parameters/grids. Missing specs use defaults.
        config["models"] = {name: models.get(name, {}) for name in selected}
    total = sum(counts.get(name, 1) for name in config["models"])
    if total > config["max_trials"]:
        raise ToolError(f"trial_budget_exceeded: {total} > {config['max_trials']}; reduce grid or raise max_trials (<=100)")
    return config


def make_estimator(name, params, config):
    seed, jobs = config["seed"], config["jobs"]
    defaults = {
        "rf": {"n_estimators": 150, "min_samples_leaf": 2, "class_weight": "balanced"},
        "dt": {"max_depth": 12, "min_samples_leaf": 2, "class_weight": "balanced"},
        "lr": {"C": 1.0, "max_iter": 3000, "class_weight": "balanced", "solver": "liblinear"},
        "svm": {"C": 1.0, "max_iter": 5000, "class_weight": "balanced", "dual": "auto"},
        "cnb": {"alpha": 1.0},
        "xgb": {"n_estimators": 150, "max_depth": 4, "learning_rate": 0.1,
                "tree_method": "hist", "objective": "binary:logistic", "eval_metric": "logloss",
                "importance_type": "gain", "device": "cpu"},
    }
    values = {**defaults[name], **params}
    if name != "cnb":
        values["random_state"] = seed
    if name in {"rf", "xgb"}:
        values["n_jobs"] = jobs
    if name == "xgb":
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise ToolError('xgboost_not_installed: python -m pip install -e ".[ml]"') from exc
        estimator = XGBClassifier(**values)
    else:
        constructor = {"rf": RandomForestClassifier, "dt": DecisionTreeClassifier,
                       "lr": LogisticRegression, "svm": LinearSVC, "cnb": ComplementNB}[name]
        estimator = constructor(**values)
    # Sparse-safe, fitted by Pipeline.fit on X_train only; never change the shared Phase 3 encoder.
    if name in {"lr", "svm"}:
        estimator = Pipeline([("scale", MaxAbsScaler()), ("classifier", estimator)])
    return estimator


def binary_scores(model, X):
    if list(model.classes_) != [0, 1]:
        raise ToolError("model_class_mapping_mismatch")
    if hasattr(model, "predict_proba"):
        scores, kind = model.predict_proba(X)[:, 1], "probability"
    elif hasattr(model, "decision_function"):
        scores, kind = model.decision_function(X), "decision"
    else:
        raise ToolError("model_has_no_binary_score")
    scores = np.asarray(scores, dtype=float).reshape(-1)
    if len(scores) != X.shape[0] or not np.isfinite(scores).all():
        raise ToolError("invalid_model_scores")
    return scores, kind


def model_outputs(bundle, name, X):
    model = bundle["models"][name]
    scores, kind = binary_scores(model, X)
    threshold = bundle.get("thresholds", {}).get(name)
    predictions = model.predict(X) if threshold is None else (scores >= threshold).astype(int)
    return predictions, scores, kind


def top_features(model, feature_names, limit):
    estimator = model.steps[-1][1] if isinstance(model, Pipeline) else model
    if hasattr(estimator, "feature_importances_"):
        weights = np.asarray(estimator.feature_importances_)
        method = "xgboost_gain" if estimator.__class__.__name__ == "XGBClassifier" else "tree_impurity_decrease"
        signed = False
    elif hasattr(estimator, "coef_"):
        weights = np.asarray(estimator.coef_)[0]
        method, signed = "linear_coefficient_on_train_scaled_input", True
    elif isinstance(estimator, ComplementNB):
        weights = estimator.feature_log_prob_[1] - estimator.feature_log_prob_[0]
        method, signed = "complement_nb_class_weight_difference", True
    else:
        return {"method": "unavailable", "features": []}
    rows = []
    for index in sorted(range(len(weights)), key=lambda i: (-abs(float(weights[i])), feature_names[i]))[:limit]:
        weight = float(weights[index])
        feature = feature_names[index]
        group = "text" if feature.startswith("text:") else "name" if feature.startswith("meta:name_") else "metadata"
        rows.append({"rank": len(rows)+1, "feature": feature, "group": group, "importance": abs(weight),
                     "signed_weight": weight if signed else None,
                     "direction": ("malicious" if weight > 0 else "benign" if weight < 0 else "neutral") if signed else "unsigned"})
    return {"method": method, "features": rows,
            "note": "Global model ranking, not a local explanation or causal evidence. Raw importance values are not comparable across models. Linear weights refer to train-scaled inputs."}

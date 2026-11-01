"""Bounded and reproducible Optuna search space for XGBoost."""
import math

from ..common import ToolError, read_json

# Bound resources and reject arbitrary estimator arguments from user input.
LIMITS = {"n_estimators": ("int", 1, 2000), "max_depth": ("int", 1, 12),
          "learning_rate": ("float", 0.001, 1.0), "subsample": ("float", 0.05, 1.0),
          "colsample_bytree": ("float", 0.05, 1.0), "min_child_weight": ("float", 0.0, 100.0),
          "reg_alpha": ("float", 0.0, 100.0), "reg_lambda": ("float", 0.0, 100.0),
          "scale_pos_weight": ("float", 0.01, 100.0)}


def load_optuna_config(path):
    value = read_json(path, 65_536)
    if not isinstance(value, dict) or set(value) != {"n_trials", "sampler_seed", "space"}:
        raise ToolError("invalid_optuna_config")
    if type(value["n_trials"]) is not int or not 1 <= value["n_trials"] <= 100:
        raise ToolError("optuna_n_trials_must_be_1_to_100")
    if type(value["sampler_seed"]) is not int or not 0 <= value["sampler_seed"] <= 2**32 - 1:
        raise ToolError("invalid_optuna_sampler_seed")
    space = value["space"]
    if not isinstance(space, dict) or not space or set(space) - set(LIMITS):
        raise ToolError("invalid_optuna_search_space")
    for name, spec in space.items():
        if not isinstance(spec, dict) or set(spec) - {"type", "low", "high", "log"} or not {"type", "low", "high"} <= set(spec):
            raise ToolError("invalid_optuna_parameter: " + name)
        kind, minimum, maximum = LIMITS[name]
        low, high = spec["low"], spec["high"]
        if (spec["type"] != kind or type(low) not in (int, float) or type(high) not in (int, float)
                or not math.isfinite(low) or not math.isfinite(high) or not minimum <= low < high <= maximum
                or kind == "int" and (type(low) is not int or type(high) is not int)
                or type(spec.get("log", False)) is not bool or spec.get("log", False) and low <= 0):
            raise ToolError("invalid_optuna_parameter: " + name)
    return value


def make_study(config, base_params):
    try:
        import optuna
    except ImportError as exc:
        raise ToolError('optuna_not_installed: python -m pip install -e ".[optuna]"') from exc
    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=config["sampler_seed"]))
    # Enqueue the user's baseline only when every searched value is explicitly specified and in bounds.
    warm = {name: base_params.get(name) for name in config["space"]}
    if all(type(warm[k]) in (int, float) and not isinstance(warm[k], bool)
           and spec["low"] <= warm[k] <= spec["high"]
           and (spec["type"] != "int" or type(warm[k]) is int)
           for k, spec in config["space"].items()):
        study.enqueue_trial(warm)
        return study, True
    return study, False


def suggest(trial, config):
    result = {}
    for name, spec in config["space"].items():
        if spec["type"] == "int":
            result[name] = trial.suggest_int(name, spec["low"], spec["high"], log=spec.get("log", False))
        else:
            result[name] = trial.suggest_float(name, spec["low"], spec["high"], log=spec.get("log", False))
    return result

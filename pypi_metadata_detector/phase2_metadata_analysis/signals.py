"""Deterministic metadata features and explainable package-name comparisons."""
from collections import Counter
from functools import lru_cache
import math
from pathlib import Path
import re
import time

from ..common import (PLACEHOLDERS, ToolError, digest, normalize_name, read_json, sample_folder,
                     write_csv, write_json)
from .reference import target_fingerprint

SIGNAL_KEYS = ("repeated_character", "omitted_character", "swapped_adjacent_character",
               "swapped_words", "keyboard_or_visual_substitution", "version_suffix")
STATE_FIELDS = ("Summary", "Description", "Author", "Author-email", "Home-page", "Project-URL",
                "License", "License-Expression", "Requires-Python", "Requires-Dist")
FEATURE_VERSION = "metadata-features-1"

def field_state(value):
    if value is None:
        return "missing"
    values = value if isinstance(value, list) else [value]
    if not values or all(not str(v).strip() for v in values):
        return "empty"
    nonempty = [str(v).strip().casefold() for v in values if str(v).strip()]
    return "placeholder" if all(v in PLACEHOLDERS for v in nonempty) else "present"

def edit_distance(left, right, cutoff=None):
    if left == right:
        return 0
    if cutoff is not None and abs(len(left) - len(right)) > cutoff:
        return cutoff + 1
    if len(left) > len(right):
        left, right = right, left
    previous = list(range(len(left) + 1))
    for i, rchar in enumerate(right, 1):
        current = [i]
        for j, lchar in enumerate(left, 1):
            current.append(min(current[-1] + 1, previous[j] + 1,
                               previous[j - 1] + (lchar != rchar)))
        if cutoff is not None and min(current) > cutoff:
            return cutoff + 1
        previous = current
    return previous[-1]

KEYBOARD = {}
for row_index, (row, offset) in enumerate((("qwertyuiop", 0), ("asdfghjkl", .25), ("zxcvbnm", .75))):
    for column, character in enumerate(row):
        KEYBOARD[character] = (column + offset, row_index)
VISUAL_GROUPS = ("1li", "0o", "5s", "2z", "8b")

def similar_character(left, right):
    if any(left in group and right in group for group in VISUAL_GROUPS):
        return True
    if left in KEYBOARD and right in KEYBOARD:
        x, y = KEYBOARD[left]
        a, b = KEYBOARD[right]
        return abs(y - b) <= 1 and abs(x - a) <= 1.25
    return False

def pair_signals(suspect, target):
    result = dict.fromkeys(SIGNAL_KEYS, False)
    if suspect == target:
        return result
    if len(suspect) == len(target) + 1:
        result["repeated_character"] = any(
            suspect[i] == suspect[i-1] and suspect[:i] + suspect[i+1:] == target for i in range(1, len(suspect)))
    if len(suspect) == len(target) - 1:
        result["omitted_character"] = edit_distance(suspect, target, 1) == 1
    if len(suspect) == len(target):
        result["swapped_adjacent_character"] = any(
            target[:i] + target[i+1] + target[i] + target[i+2:] == suspect for i in range(len(target)-1))
        differences = [(a, b) for a, b in zip(suspect, target) if a != b]
        result["keyboard_or_visual_substitution"] = len(differences) == 1 and similar_character(*differences[0])
    a, b = suspect.split("-"), target.split("-")
    result["swapped_words"] = len(a) > 1 and len(a) == len(b) and a != b and sorted(a) == sorted(b)
    result["version_suffix"] = (suspect.startswith(target) and
                                re.fullmatch(r"-?\d+", suspect[len(target):]) is not None)
    return result

@lru_cache(maxsize=20_000)
def name_signals(name, targets, threshold):
    suspect = normalize_name(name)
    if suspect in targets:
        return {"nearest_target": suspect, "edit_distance": 0, "exact_target": True,
                "suspected_typosquatting": False, "matches": [], **dict.fromkeys(SIGNAL_KEYS, False)}
    best_name, best_distance = None, None
    flags = dict.fromkeys(SIGNAL_KEYS, False)
    matches = []
    for target in targets:
        if best_distance is None or abs(len(suspect) - len(target)) <= best_distance:
            distance = edit_distance(suspect, target, best_distance)
            if best_distance is None or distance < best_distance:
                best_name, best_distance = target, distance
        current = pair_signals(suspect, target)
        for key in SIGNAL_KEYS:
            flags[key] = flags[key] or current[key]
        if any(current.values()):
            matches.append({"target": target, "signals": [k for k, v in current.items() if v]})
    return {"nearest_target": best_name, "edit_distance": best_distance, "exact_target": False,
            "suspected_typosquatting": any(flags.values()) or
                (best_distance is not None and 0 < best_distance <= threshold),
            "matches": matches[:20], **flags}

def compare_registry(metadata, reference, names):
    name = normalize_name(metadata["Name"])
    from packaging.version import Version
    release = reference.get("releases", {}).get(name + "|" + str(Version(metadata["Version"])))
    inventory = "match" if name in names else "not_in_snapshot" if reference["index_available"] else "unavailable"
    result = {"name_inventory": inventory, "release": "unavailable", "author": "unavailable",
              "author_email": "unavailable", "note": "Declared metadata comparison; not publisher authentication."}
    if release:
        result["release"] = release["status"]
        if release["status"] == "available":
            result["release"] = "match"
            for source, dest in (("Author", "author"), ("Author-email", "author_email")):
                left, right = metadata.get(source), release.get(source)
                if field_state(left) == field_state(right) == "present":
                    result[dest] = "match" if left.strip().casefold() == right.strip().casefold() else "mismatch"
    return result

def analyze_record(record, config, reference, names=None, fingerprint=None):
    if record.get("status") != "ok":
        raise ToolError("metadata_not_eligible")
    metadata = record["metadata"]
    states = {key: field_state(metadata.get(key)) for key in STATE_FIELDS}
    features = {}
    for key, state in states.items():
        for category in ("missing", "empty", "placeholder", "present"):
            features[key.lower().replace("-", "_") + "_" + category] = int(state == category)
    features["has_license"] = int(any(states[k] == "present" for k in ("License", "License-Expression")))
    features["has_project_url"] = int(any(states[k] == "present" for k in ("Home-page", "Project-URL")))
    if reference.get("name_matching_mode") == "inventory":
        from .inventory_search import search_inventory, search_inventory_legacy
        new_rules = reference.get("name_matching_algorithm") == "spellbound-signals-2"
        if not new_rules and config["typo_distance"] > 1:
            raise ToolError("inventory_search_supports_distance_at_most_one")
        search = search_inventory if new_rules else search_inventory_legacy
        found = search(metadata["Name"], names if names is not None else set(reference["names"]), 1000)
        candidates = found["candidates"] if new_rules else [item for item in found["candidates"] if item["signals"] or
                      0 < item["edit_distance"] <= config["typo_distance"]]
        flags = found["flags"] if new_rules else {key: any(key in item["signals"] for item in candidates) for key in SIGNAL_KEYS}
        best = candidates[0] if candidates else None
        typo = {"nearest_target": best["target"] if best else None,
                "edit_distance": best["edit_distance"] if best else None, "exact_target": False,
                "suspected_typosquatting": bool(candidates),
                "matches": [{"target": item["target"], "signals": item["signals"]} for item in candidates[:20]],
                "candidate_count": found["candidate_count"], "candidates_truncated": found["truncated"], **flags}
    else:
        typo = name_signals(metadata["Name"], tuple(reference["targets"]), config["typo_distance"])
    features["name_distance"] = typo["edit_distance"] if typo["edit_distance"] is not None else -1
    features["name_exact_target"] = int(typo["exact_target"])
    for key in SIGNAL_KEYS:
        features["name_" + key] = int(typo[key])
    features["name_typo_candidate"] = int(typo["suspected_typosquatting"])
    lexical = {}
    if config["lexical_experiment"]:
        for key in ("Summary", "Description"):
            value = metadata.get(key) or ""
            # Explicit prefix budget prevents large descriptions dominating resources.
            value = value[:config["max_text_chars"]]
            counts = Counter(value)
            total = len(value)
            entropy = -sum((n/total) * math.log2(n/total) for n in counts.values()) if total else 0.
            statistics = {"entropy": entropy,
                          "digit_ratio": sum(c.isdigit() for c in value)/total if total else 0.,
                          "other_ratio": sum(not c.isalnum() and not c.isspace() for c in value)/total if total else 0.}
            lexical[key] = {"chars_measured": total, "truncated": len(metadata.get(key) or "") > total, **statistics}
            for stat, val in statistics.items():
                features["lexical_" + key.lower() + "_" + stat] = val
    parts = [metadata[key] for key in ("Summary", "Description") if field_state(metadata.get(key)) == "present"]
    raw_text = "\n".join(parts)
    text = raw_text[:config["max_text_chars"]]
    return {"schema_version": FEATURE_VERSION, "sample_id": record["sample_id"],
            "metadata_digest": record["metadata_digest"], "states": states,
            "unknown_fields": [key for key, state in states.items() if state != "present"],
            "typosquatting": typo, "registry": compare_registry(metadata, reference, names if names is not None else set(reference["names"])),
            "lexical": lexical, "features": features, "text": text,
            "text_truncated": len(raw_text) > len(text), "text_original_chars": len(raw_text),
            "config_digest": digest(config), "reference_sha256": reference["sha256"],
            "target_fingerprint": fingerprint if fingerprint is not None else target_fingerprint(reference)}

def analyze_run(run, config, reference, progress):
    run = Path(run)
    extraction = read_json(run / "extraction.json")
    if extraction["config"] != config:
        raise ToolError("config_differs_from_extraction; rerun extract with this config")
    names = set(reference["names"])
    fingerprint = target_fingerprint(reference)
    if reference.get("name_matching_mode") == "inventory" and (not reference.get("index_available") or not names):
        raise ToolError("pypi_inventory_unavailable_sync_reference_first")
    if (reference.get("name_matching_mode") == "inventory" and
            reference.get("name_matching_algorithm") != "spellbound-signals-2" and config["typo_distance"] > 1):
        raise ToolError("inventory_search_supports_distance_at_most_one")
    rows, index = [], []
    progress.say(f"Chạy Phase 2 | Samples: {extraction['total']} | " +
                 (f"PyPI inventory: {len(names)}" if reference.get("name_matching_mode") == "inventory"
                  else f"Targets: {len(reference['targets'])}") + " | Offline")
    counts = {"ok": 0, "partial": 0, "skipped": 0, "failed": 0}
    for position, sample in enumerate(extraction["samples"], 1):
        started = time.monotonic()
        folder = sample_folder(run, sample["sample_id"])
        record = read_json(folder / "metadata.json")
        if sample["status"] != "ok":
            counts["skipped"] += 1
            index.append({"sample_id": sample["sample_id"], "status": "skipped", "reason": sample["status"]})
            progress.item(position, extraction["total"], sample["sample_id"], 2, "SKIPPED",
                          time.monotonic() - started, sample["status"])
            continue
        try:
            if record.get("metadata_digest") != digest(record["metadata"]) or record["metadata_digest"] != sample["metadata_digest"]:
                raise ToolError("metadata_changed_since_extraction")
            signals = analyze_record(record, config, reference, names, fingerprint)
            write_json(folder / "signals.json", signals)
            write_json(folder / "status.json", {"phase": 2, "status": "ok"})
            index.append({"sample_id": sample["sample_id"], "status": "ok", "signals_digest": digest(signals)})
            rows.append({"sample_id": sample["sample_id"], **signals["features"]})
            counts["ok"] += 1
            progress.item(position, extraction["total"], record["metadata"]["Name"], 2, "OK",
                          time.monotonic()-started, "Typosquat: " + str(signals["typosquatting"]["suspected_typosquatting"]))
        except Exception as exc:
            counts["failed"] += 1
            error = type(exc).__name__ + ": " + str(exc)[:250]
            write_json(folder / "status.json", {"phase": 2, "status": "failed", "reason": error})
            index.append({"sample_id": sample["sample_id"], "status": "failed", "reason": error})
            progress.item(position, extraction["total"], sample["sample_id"], 2, "FAILED", time.monotonic()-started, error)
    report = {"schema_version": "analysis-1", "extract_id": extraction["extract_id"],
              "config": config, "reference_sha256": reference["sha256"],
              "target_fingerprint": fingerprint, "targets": reference["targets"],
              "name_reference": reference if reference.get("name_matching_mode") == "inventory" else None,
              "samples": index, "total": extraction["total"], **counts}
    write_json(run / "analysis.json", report)
    write_json(run / "run_summary.json", {"phase": 2, "total": extraction["total"], **counts})
    if rows:
        write_csv(run / "features.csv", rows, ["sample_id"] + sorted(rows[0].keys() - {"sample_id"}))
    progress.say("Phase 2 hoàn thành | " + " | ".join(f"{k}: {v}" for k, v in counts.items()))
    return report

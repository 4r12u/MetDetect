"""Small shared IO, configuration, sample discovery and progress helpers."""
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time

DEFAULTS = {
    "seed": 42, "max_metadata_bytes": 2_097_152, "max_archive_members": 20_000,
    "max_archive_bytes": 536_870_912, "max_unpacked_bytes": 536_870_912,
    "max_candidates": 32, "max_text_chars": 100_000, "max_features": 3000,
    "ngram_max": 2, "typo_distance": 1, "lexical_experiment": False,
    "rf_trees": 150, "rf_max_depth": None, "dt_max_depth": 12,
    "min_samples_leaf": 2, "class_weight": "balanced", "jobs": 1,
}
LABELS = {"benign": 0, "malicious": 1}
PLACEHOLDERS = {"unknown", "none", "n/a", "not available", "null"}
STATUS_FAILED = {"input_error", "invalid_metadata", "metadata_conflict"}

class ToolError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()

def read_json(path, limit=268_435_456):
    path = Path(path)
    if path.stat().st_size > limit:
        raise ToolError("json_size_limit")
    return json.loads(path.read_text(encoding="utf-8-sig"))

def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
        except BaseException:
            stream.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

def write_csv(path, rows, columns):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # CSV is an exported report, not executable spreadsheet content.
            safe = {key: ("'" + val if isinstance(val, str) and val and val[0] in "=+-@\t\r" else val)
                    for key, val in row.items()}
            writer.writerow(safe)

def normalize_name(name):
    return re.sub(r"[-_.]+", "-", str(name).strip()).lower()

def valid_name(name):
    return isinstance(name, str) and len(name) <= 200 and re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name) is not None

def sample_folder(run, sample_id):
    base = Path(run).resolve()
    path = base / "samples" / hashlib.sha256(str(sample_id).encode()).hexdigest()[:24]
    if not path.resolve().is_relative_to(base):
        raise ToolError("output_path_escape")
    return path

def load_config(path=None):
    result = dict(DEFAULTS)
    if path:
        supplied = read_json(path, 65_536)
        if not isinstance(supplied, dict) or set(supplied) - set(result):
            raise ToolError("unknown_config_keys")
        result.update(supplied)
    for key in result:
        if key in ("lexical_experiment",):
            if not isinstance(result[key], bool):
                raise ToolError("config_boolean_required: " + key)
        elif key in ("rf_max_depth", "dt_max_depth"):
            if result[key] is not None and (type(result[key]) is not int or result[key] < 1):
                raise ToolError("invalid_config: " + key)
        elif key == "class_weight":
            if result[key] not in (None, "balanced"):
                raise ToolError("invalid_class_weight")
        elif type(result[key]) is not int or result[key] < (0 if key in ("seed", "typo_distance") else 1):
            raise ToolError("invalid_config: " + key)
    if result["typo_distance"] > 2 or result["ngram_max"] > 2:
        raise ToolError("unsupported_distance_or_ngram")
    return result

def archive_path(path):
    return str(path).lower().endswith((".whl", ".zip", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz"))

def discover(input_path=None, manifest=None):
    samples = []
    if manifest:
        manifest = Path(manifest).resolve()
        with manifest.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or not {"sample_id", "path"} <= set(reader.fieldnames):
                raise ToolError("manifest_requires_sample_id_and_path")
            for row in reader:
                label = row.get("label", "").strip().lower()
                label = {"0": "benign", "1": "malicious"}.get(label, label)
                if label and label not in LABELS:
                    raise ToolError("invalid_label: " + row.get("sample_id", ""))
                if not row.get("path") or not row.get("sample_id"):
                    raise ToolError("empty_manifest_identity")
                samples.append({"sample_id": row["sample_id"], "path": str((manifest.parent / row["path"]).resolve()),
                                "label": label or None, "split": row.get("split", "").strip() or None})
    else:
        if not input_path:
            raise ToolError("input_or_manifest_required")
        path = Path(input_path).resolve()
        if path.is_file():
            paths = [path]
        elif path.is_dir():
            entries = sorted(path.iterdir(), key=lambda p: p.name.casefold())
            # A folder containing its own metadata represents a single sample.
            has_info_folder = any(p.is_dir() and not p.is_symlink() and
                                  p.name.lower().endswith((".dist-info", ".egg-info")) and
                                  any((p / n).is_file() for n in ("METADATA", "PKG-INFO")) for p in entries)
            if has_info_folder or any(p.name.lower() in ("pkg-info", "metadata") for p in entries if p.is_file()):
                paths = [path]
            else:
                paths = [p for p in entries if not p.is_symlink() and
                         (p.is_dir() and not p.name.startswith(".") or p.is_file() and
                          (archive_path(p) or p.name.lower() in ("pkg-info", "metadata")))]
        else:
            raise ToolError("input_not_found")
        for path in paths:
            samples.append({"sample_id": "sample-" + hashlib.sha256(str(path).encode()).hexdigest()[:20],
                            "path": str(path), "label": None, "split": None})
    ids = [s["sample_id"] for s in samples]
    if not samples or len(ids) != len(set(ids)):
        raise ToolError("empty_dataset_or_duplicate_sample_id")
    return samples

class Progress:
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.started = time.monotonic()

    def say(self, message):
        if not self.quiet:
            try:
                print(message, flush=True)
            except UnicodeEncodeError:
                print(message.encode("ascii", "replace").decode(), flush=True)

    def item(self, index, total, package, phase, status, seconds, detail=""):
        # Untrusted metadata cannot inject terminal escape sequences or new log lines.
        package = "".join(c if c.isprintable() else "?" for c in str(package))[:100]
        detail = "".join(c if c.isprintable() else "?" for c in str(detail))[:180]
        self.say(f"[{index}/{total}] Package: {package} | Phase: {phase} | Status: {status} | Time: {seconds:.1f}s" +
                 (" | " + detail if detail else ""))


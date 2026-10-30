"""Explicit official-PyPI synchronization; normal analysis is entirely offline."""
from datetime import datetime, timezone
from pathlib import Path
import csv
import hashlib
import json
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from packaging.version import Version
from ..common import ToolError, digest, normalize_name, read_json, sample_folder, valid_name, write_json

DEMO_TARGETS = ["requests", "numpy", "pandas", "flask", "django", "scipy", "matplotlib",
                "scikit-learn", "setuptools", "pip", "urllib3", "certifi", "pillow", "pyyaml",
                "beautifulsoup4", "cryptography", "pytest", "sqlalchemy", "fastapi", "pydantic",
                "httpx", "aiohttp", "click", "jinja2", "six", "tqdm", "packaging", "wheel"]

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ToolError("pypi_redirect_rejected")

def default_reference(targets=None):
    value = {"schema_version": "reference-1", "source": "bundled_example_targets",
             "created_at": None, "serial": None, "names": [], "index_available": False,
             "targets": sorted(set(targets if targets is not None else DEMO_TARGETS)), "releases": {}}
    value["sha256"] = digest(value)
    return value

def target_fingerprint(reference):
    return digest({"signal_version": "name-signals-1", "targets": sorted(reference["targets"])})

def read_targets(path):
    path = Path(path)
    if path.stat().st_size > 2_097_152:
        raise ToolError("target_file_size_limit")
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or "name" not in reader.fieldnames:
                raise ToolError("targets_csv_requires_name")
            names = [row["name"].strip() for row in reader if row.get("name", "").strip()]
    else:
        names = [line.strip() for line in path.read_text("utf-8-sig").splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
    if not names or len(names) > 5000 or any(not valid_name(n) for n in names):
        raise ToolError("targets_require_1_to_5000_valid_names")
    return sorted({normalize_name(n) for n in names})

def load_reference(path=None):
    if not path:
        return default_reference()
    path = Path(path)
    value = read_json(path / "reference.json" if path.is_dir() else path)
    if value.get("schema_version") != "reference-1":
        raise ToolError("unsupported_reference_schema")
    checksum = value.get("sha256")
    if checksum != digest({k: v for k, v in value.items() if k != "sha256"}):
        raise ToolError("reference_checksum_mismatch")
    if not isinstance(value.get("names"), list) or not isinstance(value.get("releases"), dict):
        raise ToolError("invalid_reference_contents")
    targets = value.get("targets", [])
    if not targets or len(targets) > 5000 or any(not valid_name(n) or normalize_name(n) != n for n in targets):
        raise ToolError("invalid_reference_targets")
    return value


def create_top_reference(snapshot_path, output, top=3000, extra_targets=None, sync_index=False, progress=None,
                         provenance_path=None):
    """Build a new frozen target snapshot; optionally fetch the official inventory."""
    if type(top) is not int or not 1 <= top <= 5000:
        raise ToolError("top_must_be_between_1_and_5000")
    source = Path(snapshot_path)
    if source.stat().st_size > 16_777_216:
        raise ToolError("top_snapshot_size_limit")
    raw = source.read_bytes()
    snapshot = json.loads(raw.decode("utf-8-sig"))
    rows = snapshot.get("rows") if isinstance(snapshot, dict) else None
    if not isinstance(rows, list) or len(rows) < top:
        raise ToolError("top_snapshot_has_too_few_rows")
    selected, last_count = [], None
    for position, row in enumerate(rows):
        if not isinstance(row, dict) or not valid_name(row.get("project")):
            raise ToolError("invalid_top_snapshot_project")
        count = row.get("download_count")
        if type(count) is not int or count < 0 or (last_count is not None and count > last_count):
            raise ToolError("top_snapshot_requires_descending_download_counts")
        if position < top:
            selected.append(normalize_name(row["project"]))
        last_count = count
    if len(set(selected)) != top:
        raise ToolError("duplicate_top_snapshot_project")
    extras = read_targets(extra_targets) if extra_targets else []
    targets = sorted(set(selected) | set(extras))
    if len(targets) > 5000:
        raise ToolError("targets_require_1_to_5000_valid_names")
    destination = Path(output).resolve()
    if destination.exists():
        raise ToolError("reference_output_must_be_new")
    snapshot_hash = hashlib.sha256(raw).hexdigest()
    provenance = read_json(provenance_path, 65_536) if provenance_path else {}
    if not isinstance(provenance, dict) or (provenance_path and provenance.get("sha256") != snapshot_hash):
        raise ToolError("top_snapshot_provenance_checksum_mismatch")
    reference = default_reference(targets)
    reference.update(source="offline_no_pypi_inventory", created_at=datetime.now(timezone.utc).isoformat())
    reference["target_provenance"] = {
        "selection": "first_rows_in_descending_download_count", "top_count": top,
        "snapshot_filename": source.name, "snapshot_sha256": snapshot_hash,
        "snapshot_last_update": snapshot.get("last_update"), "snapshot_source": snapshot.get("source"),
        "snapshot_url": provenance.get("url"), "snapshot_retrieved_at": provenance.get("retrieved_at"),
        "download_period": provenance.get("download_period"),
        "provenance_sha256": hashlib.sha256(Path(provenance_path).read_bytes()).hexdigest() if provenance_path else None,
        "supplemental_count": len(set(extras) - set(selected)),
        "supplemental_sha256": hashlib.sha256(Path(extra_targets).read_bytes()).hexdigest() if extra_targets else None,
        "note": "Popularity is a target-selection source, not a benign label or classifier feature.",
    }
    if sync_index:
        if progress:
            progress.say("Reference | Đang lấy inventory từ PyPI official...")
        result, serial = get_json("https://pypi.org/simple/", "application/vnd.pypi.simple.v1+json")
        if not isinstance(result, dict) or not isinstance(result.get("projects"), list):
            raise ToolError("invalid_pypi_index")
        names = sorted({normalize_name(p["name"]) for p in result["projects"]
                        if isinstance(p, dict) and valid_name(p.get("name"))})
        if not names:
            raise ToolError("empty_pypi_index")
        reference.update(source="https://pypi.org/simple/", created_at=datetime.now(timezone.utc).isoformat(),
                         serial=serial, names=names, index_available=True)
    reference["sha256"] = digest({k: v for k, v in reference.items() if k != "sha256"})
    destination.mkdir(parents=True, exist_ok=False)
    write_json(destination / "reference.json", reference)
    if progress:
        progress.say(f"Reference | Targets: {len(targets)} | Inventory: {len(reference['names'])} | {destination}")
    return reference

def get_json(url, accept="application/json", limit=268_435_456):
    # URL construction belongs to this module. Never follow a URL found in a sample.
    if not url.startswith("https://pypi.org/") or "@" in url:
        raise ToolError("pypi_official_url_required")
    request = Request(url, headers={"Accept": accept, "Accept-Encoding": "identity",
                                   "User-Agent": "AIC211-PyPI-Metadata-Detector/1.0 (academic project)"})
    with build_opener(NoRedirect()).open(request, timeout=60) as response:
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ToolError("pypi_response_size_limit")
        return json.loads(raw), response.headers.get("X-PyPI-Last-Serial")

def sync_reference(output, targets=None, run=None, progress=None):
    if progress:
        progress.say("Reference | Đang lấy danh sách tên từ PyPI official...")
    result, serial = get_json("https://pypi.org/simple/", "application/vnd.pypi.simple.v1+json")
    if not isinstance(result.get("projects"), list):
        raise ToolError("invalid_pypi_index")
    names = sorted({normalize_name(p["name"]) for p in result["projects"]
                    if isinstance(p, dict) and valid_name(p.get("name"))})
    if not names:
        raise ToolError("empty_pypi_index")
    reference = default_reference(read_targets(targets) if targets else None)
    reference.update(source="https://pypi.org/simple/", created_at=datetime.now(timezone.utc).isoformat(),
                     serial=serial, names=names, index_available=True, releases={})
    samples = read_json(Path(run) / "extraction.json")["samples"] if run else []
    wanted = {}
    for sample in samples:
        if sample["status"] != "ok":
            continue
        record = read_json(sample_folder(run, sample["sample_id"]) / "metadata.json")
        metadata = record["metadata"]
        name, version = normalize_name(metadata["Name"]), str(Version(metadata["Version"]))
        wanted[name + "|" + version] = (name, version)
    for index, (key, (name, version)) in enumerate(wanted.items(), 1):
        try:
            body, _ = get_json("https://pypi.org/pypi/" + quote(name, safe="") + "/" +
                               quote(version, safe="") + "/json", limit=8_388_608)
            info = body["info"]
            if normalize_name(info["name"]) != name or Version(info["version"]) != Version(version):
                raise ToolError("pypi_release_identity_mismatch")
            entry = {"status": "available", "Name": info["name"], "Version": info["version"],
                     "Author": info.get("author"), "Author-email": info.get("author_email")}
        except HTTPError as exc:
            entry = {"status": "unavailable" if exc.code == 404 else "lookup_error", "http_status": exc.code}
        except Exception as exc:
            entry = {"status": "lookup_error", "reason": type(exc).__name__ + ": " + str(exc)[:150]}
        reference["releases"][key] = entry
        if progress:
            progress.item(index, len(wanted), name, "reference", entry["status"].upper(), 0)
    reference["sha256"] = digest({k: v for k, v in reference.items() if k != "sha256"})
    write_json(Path(output) / "reference.json", reference)
    if progress:
        progress.say(f"Reference hoàn thành | Names: {len(names)} | Targets: {len(reference['targets'])} | Releases: {len(wanted)}")
    return reference

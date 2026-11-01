"""Explicit official-PyPI synchronization; normal analysis is entirely offline."""
from datetime import datetime, timezone
from pathlib import Path
import csv
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
    if reference.get("name_matching_mode") == "inventory":
        version = reference.get("name_matching_algorithm", "inventory-single-edit-1")
        return digest({"signal_version": version, "names": sorted(reference["names"])})
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
    if (not isinstance(targets, list) or (not targets and value.get("name_matching_mode") != "inventory") or
            len(targets) > 5000 or any(not valid_name(n) or normalize_name(n) != n for n in targets)):
        raise ToolError("invalid_reference_targets")
    return value



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
    if targets:
        raise ToolError("sync_inventory_does_not_use_static_targets")
    if (Path(output) / "reference.json").exists():
        raise ToolError("reference_output_must_be_new")
    if progress:
        progress.say("Reference | Đang lấy danh sách tên từ PyPI official...")
    result, serial = get_json("https://pypi.org/simple/", "application/vnd.pypi.simple.v1+json")
    if not isinstance(result.get("projects"), list):
        raise ToolError("invalid_pypi_index")
    names = sorted({normalize_name(p["name"]) for p in result["projects"]
                    if isinstance(p, dict) and valid_name(p.get("name"))})
    if not names:
        raise ToolError("empty_pypi_index")
    reference = default_reference([])
    reference.update(source="https://pypi.org/simple/", created_at=datetime.now(timezone.utc).isoformat(),
                     serial=serial, names=names, index_available=True, releases={},
                     name_matching_mode="inventory", name_matching_algorithm="spellbound-signals-2")
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
        progress.say(f"Reference hoàn thành | PyPI inventory: {len(names)} | Releases: {len(wanted)}")
    return reference

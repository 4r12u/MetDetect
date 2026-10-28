"""Read metadata members as inert bytes; never extract or execute package code."""
from email.parser import Parser
from email.policy import compat32
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import uuid
import zipfile

from packaging.utils import parse_sdist_filename, parse_wheel_filename
from packaging.version import Version, InvalidVersion

from ..common import (ToolError, archive_path, digest, normalize_name, sample_folder,
                     valid_name, write_json)

FIELDS = ["Metadata-Version", "Name", "Version", "Summary", "Home-page", "Author",
          "Author-email", "License", "License-Expression", "Description", "Requires-Python"]
MULTI = ["Project-URL", "Requires-Dist", "Classifier", "Keywords"]

def metadata_member(name):
    return PurePosixPath(name.replace("\\", "/")).name.lower() in ("pkg-info", "metadata")

def check_member(name):
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(p in ("..", ".") or ":" in p for p in path.parts):
        raise ToolError("unsafe_metadata_member")
    return normalized

def read_limited(stream, limit):
    value = stream.read(limit + 1)
    if len(value) > limit:
        raise ToolError("metadata_size_limit")
    return value

def parse_metadata(raw):
    try:
        text = raw.decode("utf-8-sig", errors="strict")
    except UnicodeError as exc:
        raise ToolError("metadata_not_utf8") from exc
    message = Parser(policy=compat32).parsestr(text)
    metadata = {}
    for key in FIELDS:
        values = message.get_all(key, [])
        if len(values) > 1 and key != "Description":
            raise ToolError("duplicate_single_metadata_field: " + key)
        metadata[key] = str(values[0]) if values else None
    body = message.get_payload()
    if isinstance(body, list):
        raise ToolError("multipart_metadata_not_supported")
    if isinstance(body, str) and body:
        metadata["Description"] = body
    for key in MULTI:
        metadata[key] = [str(v) for v in message.get_all(key, [])]
    if message.defects:
        raise ToolError("malformed_metadata_headers: " + type(message.defects[0]).__name__)
    if not valid_name(metadata["Name"]):
        raise ToolError("invalid_or_missing_name")
    if not metadata["Metadata-Version"] or not metadata["Version"]:
        raise ToolError("missing_required_metadata_version")
    try:
        Version(metadata["Version"])
    except InvalidVersion as exc:
        raise ToolError("invalid_package_version") from exc
    # Header audit excludes duplicated full Description.
    headers = {}
    for key, value in message.items():
        if key.casefold() != "description":
            headers.setdefault(key, []).append(str(value))
    return metadata, headers

def expected_identity(path):
    try:
        if path.name.lower().endswith(".whl"):
            name, version, _, _ = parse_wheel_filename(path.name)
            return normalize_name(name), str(version)
        name, version = parse_sdist_filename(path.name)
        return normalize_name(name), str(version)
    except (ValueError, InvalidVersion):
        return None

def candidate_rank(name):
    path = PurePosixPath(name.replace("\\", "/"))
    # Root PKG-INFO or one wrapper directory outranks nested vendored egg-info.
    depth = len(path.parts)
    return (depth, 0 if path.name.lower() == "pkg-info" else 1)

def collect_candidates(path, config):
    if path.is_symlink():
        raise ToolError("symlink_input_rejected")
    limit = config["max_metadata_bytes"]
    candidates = []
    total_bytes = 0

    def add(name, stream):
        nonlocal total_bytes
        name = check_member(name)
        if len(candidates) >= config["max_candidates"]:
            raise ToolError("metadata_candidate_limit")
        raw = read_limited(stream, limit)
        total_bytes += len(raw)
        if total_bytes > limit * config["max_candidates"]:
            raise ToolError("metadata_total_size_limit")
        candidates.append((name, raw))

    if path.is_dir():
        scanned = 0
        for current, dirs, files in os.walk(path, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink() and d not in (".venv", ".git")]
            for name in files:
                scanned += 1
                if scanned > config["max_archive_members"]:
                    raise ToolError("directory_member_limit")
                candidate = Path(current) / name
                if metadata_member(name):
                    if candidate.is_symlink():
                        raise ToolError("symlink_metadata_rejected")
                    with candidate.open("rb") as stream:
                        add(candidate.relative_to(path).as_posix(), stream)
    elif not archive_path(path):
        if not metadata_member(path.name):
            raise ToolError("expected_metadata_or_package_archive")
        with path.open("rb") as stream:
            add(path.name, stream)
    else:
        if path.stat().st_size > config["max_archive_bytes"]:
            raise ToolError("archive_size_limit")
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                if len(members) > config["max_archive_members"]:
                    raise ToolError("archive_member_limit")
                if sum(m.file_size for m in members) > config["max_unpacked_bytes"]:
                    raise ToolError("archive_unpacked_limit")
                for member in members:
                    if not member.is_dir() and metadata_member(member.filename):
                        if stat.S_ISLNK(member.external_attr >> 16):
                            raise ToolError("symlink_metadata_rejected")
                        if member.file_size > limit:
                            raise ToolError("metadata_size_limit")
                        with archive.open(member) as stream:
                            add(member.filename, stream)
        else:
            with tarfile.open(path, mode="r|*") as archive:
                unpacked = 0
                for index, member in enumerate(archive, 1):
                    unpacked += max(member.size, 0)
                    if index > config["max_archive_members"] or unpacked > config["max_unpacked_bytes"]:
                        raise ToolError("archive_resource_limit")
                    if metadata_member(member.name) and not member.isdir():
                        if not member.isfile() or member.issym() or member.islnk():
                            raise ToolError("unsafe_metadata_member_type")
                        if member.size > limit:
                            raise ToolError("metadata_size_limit")
                        with archive.extractfile(member) as stream:
                            add(member.name, stream)
    return candidates

def extract_sample(sample, config):
    path = Path(sample["path"])
    if not path.exists():
        raise ToolError("input_not_found")
    candidates = collect_candidates(path, config)
    if not candidates:
        return {"status": "missing_metadata", "reason": "No PKG-INFO/METADATA found"}
    parsed, errors = [], []
    primary_rank = min(candidate_rank(member) for member, _ in candidates)
    for member, raw in candidates:
        try:
            metadata, headers = parse_metadata(raw)
            parsed.append((member, metadata, headers, hashlib.sha256(raw).hexdigest()))
        except ToolError as exc:
            errors.append({"member": member, "reason": str(exc)})
    if any(candidate_rank(e["member"]) == primary_rank for e in errors):
        return {"status": "invalid_metadata", "reason": "Primary metadata is invalid", "candidate_errors": errors}
    if not parsed:
        return {"status": "invalid_metadata", "reason": "No valid metadata candidate", "candidate_errors": errors}
    expected = expected_identity(path) if path.is_file() and archive_path(path) else None
    if expected:
        matching = [p for p in parsed if (normalize_name(p[1]["Name"]), str(Version(p[1]["Version"]))) == expected]
        if not matching:
            return {"status": "metadata_conflict", "reason": "Archive identity differs from metadata"}
        parsed = matching
    best_rank = min(candidate_rank(p[0]) for p in parsed)
    primary = [p for p in parsed if candidate_rank(p[0]) == best_rank]
    if len({digest(p[1]) for p in primary}) != 1:
        return {"status": "metadata_conflict", "reason": "Conflicting primary metadata candidates"}
    member, metadata, headers, raw_hash = sorted(primary, key=lambda p: p[0])[0]
    return {"schema_version": "metadata-1", "sample_id": sample["sample_id"], "status": "ok",
            "source": {"input": str(path), "metadata_member": member, "sha256": raw_hash},
            "metadata": metadata, "raw_headers": headers, "candidate_errors": errors,
            "metadata_sources": [m for m, _ in candidates], "metadata_digest": digest(metadata)}

def extract_run(samples, output, config, progress):
    run = Path(output).resolve()
    if any(Path(s["path"]).resolve() == run for s in samples):
        raise ToolError("output_must_not_replace_input")
    progress.say(f"Chạy Phase 1 | Xác minh đầu vào: {len(samples)} sample")
    extract_id = uuid.uuid4().hex
    index, counts = [], {"ok": 0, "partial": 0, "skipped": 0, "failed": 0}
    for position, sample in enumerate(samples, 1):
        started = time.monotonic()
        try:
            result = extract_sample(sample, config)
        except Exception as exc:
            result = {"sample_id": sample["sample_id"], "status": "input_error",
                      "reason": type(exc).__name__ + ": " + str(exc)[:300]}
        result["sample_id"] = sample["sample_id"]
        folder = sample_folder(run, sample["sample_id"])
        write_json(folder / "metadata.json", result)
        write_json(folder / "status.json", {"phase": 1, "status": result["status"], "reason": result.get("reason")})
        state = "ok" if result["status"] == "ok" else "skipped" if result["status"] == "missing_metadata" else "failed"
        counts[state] += 1
        index.append({**sample, "status": result["status"], "metadata_digest": result.get("metadata_digest")})
        name = result.get("metadata", {}).get("Name", Path(sample["path"]).name)
        progress.item(position, len(samples), name, 1, result["status"].upper(),
                      time.monotonic() - started, result.get("reason", ""))
    report = {"schema_version": "extraction-1", "extract_id": extract_id,
              "config": config, "samples": index, "total": len(samples), **counts}
    write_json(run / "extraction.json", report)
    write_json(run / "run_summary.json", {"phase": 1, "total": len(samples), **counts})
    progress.say("Phase 1 hoàn thành | " + " | ".join(f"{k}: {v}" for k, v in counts.items()))
    return report

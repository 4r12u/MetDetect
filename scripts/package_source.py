"""Build a source-only ZIP with checksums; never package samples, environments or private outputs."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def package_source(root, destination):
    root = Path(root).resolve()
    destination = Path(destination).resolve()
    from pypi_metadata_detector import __version__
    prefix = "aic211-pypi-metadata-detector-" + __version__ + "-source"
    roots = ("pypi_metadata_detector", "configs", "docs", "tests", "scripts", "examples")
    files = [root / n for n in ("README.md", "AGENTS.md", "pyproject.toml", "requirements.txt",
                                "requirements-tested.txt", ".gitignore") if (root / n).is_file()]
    for folder in roots:
        for path in (root / folder).rglob("*"):
            if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
                continue
            if {"__pycache__", ".pytest_cache", "history"}.intersection(path.relative_to(root).parts):
                continue
            if path.suffix.lower() in {".py", ".json", ".md", ".txt", ".html", ".csv", ".toml"} or path.name == "LICENSE":
                files.append(path)
    checksums = {}
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError("Refuse to overwrite an existing release: " + str(destination))
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(set(files)):
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            checksums[relative] = hashlib.sha256(data).hexdigest()
            archive.writestr(prefix + "/" + relative, data)
        archive.writestr(prefix + "/SOURCE_CHECKSUMS.json", json.dumps(checksums, indent=2)+"\n")
    with zipfile.ZipFile(destination) as archive:
        bad = archive.testzip()
        if bad:
            raise ValueError("ZIP integrity error: " + bad)
        for relative, expected in checksums.items():
            if hashlib.sha256(archive.read(prefix + "/" + relative)).hexdigest() != expected:
                raise ValueError("ZIP checksum mismatch: " + relative)
    checksum = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(destination.suffix + ".sha256").write_text(checksum + "  " + destination.name + "\n", encoding="ascii")
    return {"zip": str(destination), "sha256": checksum, "files": len(checksums), "bytes": destination.stat().st_size,
            "excluded": ["Dataset", "Dataset_backups", ".venv", "outputs", "visual", "docs/history", "caches"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(package_source(Path(__file__).resolve().parents[1], args.output), indent=2))

import hashlib
import json
import zipfile

import pytest

from scripts.package_source import package_source


def test_source_release_excludes_samples_and_verifies_checksums(tmp_path):
    root = tmp_path / "project"
    for name in ("Dataset", ".venv", "outputs", "visual", "pypi_metadata_detector", "scripts/vendor", "docs/history"):
        (root / name).mkdir(parents=True)
    (root / "Dataset/sample.py").write_text("never package or run", encoding="utf-8")
    (root / "outputs/private.json").write_text("{}", encoding="utf-8")
    (root / "docs/history/old.md").write_text("old", encoding="utf-8")
    (root / "pypi_metadata_detector/__init__.py").write_text("# source", encoding="utf-8")
    (root / "scripts/vendor/LICENSE").write_text("license", encoding="utf-8")
    archive = tmp_path / "release.zip"
    report = package_source(root, archive)
    with zipfile.ZipFile(archive) as source:
        names = source.namelist()
        assert not any("/Dataset/" in n or "/outputs/" in n or "/history/" in n for n in names)
        assert any(n.endswith("/LICENSE") for n in names)
        checksum_path = next(n for n in names if n.endswith("/SOURCE_CHECKSUMS.json"))
        prefix = checksum_path.removesuffix("SOURCE_CHECKSUMS.json")
        checksums = json.loads(source.read(checksum_path))
        assert len(checksums) == report["files"]
        for name, value in checksums.items():
            assert hashlib.sha256(source.read(prefix+name)).hexdigest() == value
    with pytest.raises(FileExistsError):
        package_source(root, archive)

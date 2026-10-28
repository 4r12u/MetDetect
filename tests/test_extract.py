import io
import tarfile
import zipfile
import pytest

from pypi_metadata_detector.common import DEFAULTS, ToolError
from pypi_metadata_detector.phase1_metadata_extraction.extract import extract_sample, parse_metadata
from conftest import metadata_bytes

def sample(path):
    return {"sample_id": "fixture", "path": str(path)}

def test_multiline_unicode_body_and_repeated_fields():
    raw = metadata_bytes(extra="Summary: second\n")
    with pytest.raises(ToolError, match="duplicate_single"):
        parse_metadata(raw)
    raw = ("Metadata-Version: 2.4\nName: example\nVersion: 0.1\n"
           "Summary: Thư viện\n tiếp theo\nProject-URL: Source, https://example.test\n"
           "Project-URL: Docs, https://docs.example.test\nLicense-Expression: MIT\n\n"
           "Mô tả nhiều dòng\nDòng thứ hai").encode("utf-8")
    metadata, _ = parse_metadata(raw)
    assert "Thư viện" in metadata["Summary"]
    assert metadata["Description"] == "Mô tả nhiều dòng\nDòng thứ hai"
    assert len(metadata["Project-URL"]) == 2
    assert metadata["License"] is None and metadata["License-Expression"] == "MIT"

def test_missing_empty_and_literal_none_remain_distinct():
    metadata, _ = parse_metadata(metadata_bytes(extra="Author: None\nLicense:\n"))
    assert metadata["Author"] == "None"
    assert metadata["License"] == ""
    assert metadata["Author-email"] is None

def test_wheel_is_read_without_executing_sample(tmp_path):
    path = tmp_path / "example-0.1-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("example-0.1.dist-info/METADATA", metadata_bytes())
        archive.writestr("setup.py", "raise RuntimeError('SAMPLE MUST NEVER EXECUTE')")
    result = extract_sample(sample(path), DEFAULTS)
    assert result["status"] == "ok"
    assert result["metadata"]["Name"] == "example"

def test_sdist_primary_metadata_beats_vendored(tmp_path):
    path = tmp_path / "example-0.1.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, data in [("example-0.1/PKG-INFO", metadata_bytes()),
                           ("example-0.1/vendor/other.egg-info/PKG-INFO", metadata_bytes("other"))]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    assert extract_sample(sample(path), DEFAULTS)["metadata"]["Name"] == "example"

def test_archive_traversal_is_rejected(tmp_path):
    path = tmp_path / "example-0.1.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../PKG-INFO", metadata_bytes())
    with pytest.raises(ToolError, match="unsafe_metadata_member"):
        extract_sample(sample(path), DEFAULTS)

def test_metadata_size_limit_and_missing(tmp_path):
    path = tmp_path / "PKG-INFO"
    path.write_bytes(metadata_bytes(description="x" * 1000))
    with pytest.raises(ToolError, match="metadata_size_limit"):
        extract_sample(sample(path), {**DEFAULTS, "max_metadata_bytes": 100})
    empty = tmp_path / "empty"
    empty.mkdir()
    assert extract_sample(sample(empty), DEFAULTS)["status"] == "missing_metadata"

def test_conflicting_candidates_not_arbitrarily_merged(tmp_path):
    path = tmp_path / "example-0.1.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("first/PKG-INFO", metadata_bytes(description="first"))
        archive.writestr("other/PKG-INFO", metadata_bytes(description="second"))
    assert extract_sample(sample(path), DEFAULTS)["status"] == "metadata_conflict"

def test_invalid_primary_not_replaced_by_vendored(tmp_path):
    folder = tmp_path / "distribution"
    folder.mkdir()
    (folder / "PKG-INFO").write_bytes(b"Metadata-Version: 2.1\nName: broken\n\n")
    vendored = folder / "vendor/other.egg-info"
    vendored.mkdir(parents=True)
    (vendored / "PKG-INFO").write_bytes(metadata_bytes("other"))
    assert extract_sample(sample(folder), DEFAULTS)["status"] == "invalid_metadata"

def test_zip_archive_mislabeled_as_tar_gz(tmp_path):
    path = tmp_path / "example-0.1-py3-none-any.tar.gz"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("example-0.1.dist-info/METADATA", metadata_bytes())
    assert extract_sample(sample(path), DEFAULTS)["status"] == "ok"

def test_directory_named_metadata_is_not_a_metadata_file(tmp_path):
    path = tmp_path / "example-0.1.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo("example-0.1/METADATA")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        data = metadata_bytes()
        member = tarfile.TarInfo("example-0.1/METADATA/example.dist-info/METADATA")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    assert extract_sample(sample(path), DEFAULTS)["status"] == "ok"

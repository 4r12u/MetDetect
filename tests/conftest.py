import csv
from pathlib import Path
import pytest
from pypi_metadata_detector.common import DEFAULTS, Progress, discover
from pypi_metadata_detector.phase1_metadata_extraction.extract import extract_run
from pypi_metadata_detector.phase2_metadata_analysis.reference import default_reference
from pypi_metadata_detector.phase2_metadata_analysis.signals import analyze_run

def metadata_bytes(name="example", version="0.1", extra="", description="Sample description"):
    return (f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: Useful library\n" +
            extra + "\n" + description).encode("utf-8")

@pytest.fixture
def training_run(tmp_path):
    samples = tmp_path / "data"
    samples.mkdir()
    entries = []
    for label in ("benign", "malicious"):
        for i in range(12):
            folder = samples / (label + str(i))
            folder.mkdir()
            name = ("normal" if label == "benign" else "odd") + str(i)
            split = "train" if i < 6 else "validation" if i < 9 else "test"
            description = ("reliable scientific utility" if label == "benign" else "strange imitation shortcut")
            if split == "test":
                description += " onlyheldouttoken"
            path = folder / "PKG-INFO"
            extra = "Author: Developer\nLicense: MIT\n" if label == "benign" else "Author: UNKNOWN\nLicense: UNKNOWN\n"
            path.write_bytes(metadata_bytes(name=name, extra=extra, description=description))
            entries.append({"sample_id": label + str(i), "path": str(path), "label": label, "split": split})
    manifest = tmp_path / "manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["sample_id", "path", "label", "split"])
        writer.writeheader()
        writer.writerows(entries)
    config = {**DEFAULTS, "rf_trees": 10, "min_samples_leaf": 1}
    run = tmp_path / "run"
    progress = Progress(quiet=True)
    extract_run(discover(manifest=manifest), run, config, progress)
    analyze_run(run, config, default_reference(), progress)
    return run, manifest, config

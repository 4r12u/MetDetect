"""Generate clearly synthetic metadata for a functional CLI demo, never a real benchmark."""
import argparse
import csv
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Create 24 synthetic metadata samples with explicit labels/splits")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    base = Path(args.output).resolve()
    if base.exists() and any(base.iterdir()):
        parser.error("Output must be absent or empty; existing data will not be overwritten")
    base.mkdir(parents=True, exist_ok=True)
    rows = []
    for label in ("benign", "malicious"):
        for index in range(12):
            identity = label + str(index)
            folder = base / identity
            folder.mkdir()
            description = ("reliable scientific utility" if label == "benign" else "strange imitation shortcut")
            author = "Demo Developer" if label == "benign" else "UNKNOWN"
            license_value = "MIT" if label == "benign" else "UNKNOWN"
            text = (f"Metadata-Version: 2.1\nName: demo-{identity}\nVersion: 0.1\n"
                    f"Summary: Synthetic demonstration only\nAuthor: {author}\nLicense: {license_value}\n\n"
                    f"{description}\nThese labels are invented to test software, not evidence about a real package.\n")
            (folder / "PKG-INFO").write_text(text, encoding="utf-8")
            rows.append({"sample_id": identity, "path": identity + "/PKG-INFO", "label": label,
                         "split": "train" if index < 6 else "validation" if index < 9 else "test"})
    with (base / "manifest.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["sample_id", "path", "label", "split"])
        writer.writeheader()
        writer.writerows(rows)
    (base / "README.txt").write_text("SYNTHETIC FUNCTIONAL DEMO ONLY. Do not report its metrics as detection effectiveness.\n", encoding="utf-8")
    print(f"Created 24 SYNTHETIC samples: {base / 'manifest.csv'}")

if __name__ == "__main__":
    main()


"""Phase 3: eligible rows, label attachment and package-group data splits."""
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from ..common import LABELS, ToolError, digest, discover, normalize_name, read_json, sample_folder
from ..phase2_metadata_analysis.signals import FEATURE_VERSION

def load_eligible(run, manifest=None, require_labels=True):
    run = Path(run)
    extraction, analysis = read_json(run / "extraction.json"), read_json(run / "analysis.json")
    if extraction["extract_id"] != analysis["extract_id"]:
        raise ToolError("analysis_stale; rerun analyze")
    original = {s["sample_id"]: s for s in extraction["samples"]}
    labels = original
    if manifest:
        supplied = discover(manifest=manifest)
        labels = {s["sample_id"]: s for s in supplied}
        if set(labels) != set(original):
            raise ToolError("label_manifest_sample_ids_differ_from_extraction")
        if any(Path(labels[k]["path"]).resolve() != Path(original[k]["path"]).resolve() for k in original):
            raise ToolError("label_manifest_paths_differ_from_extraction")
    records, excluded = [], []
    for sample in analysis["samples"]:
        key = sample["sample_id"]
        if sample["status"] != "ok":
            excluded.append({"sample_id": key, "reason": sample.get("reason", sample["status"])})
            continue
        folder = sample_folder(run, key)
        record, signals = read_json(folder / "metadata.json"), read_json(folder / "signals.json")
        if (digest(signals) != sample["signals_digest"] or record["metadata_digest"] != digest(record["metadata"])
                or signals["metadata_digest"] != record["metadata_digest"]
                or signals["metadata_digest"] != original[key]["metadata_digest"]):
            raise ToolError("run_data_modified: " + key)
        if signals["schema_version"] != FEATURE_VERSION or signals["target_fingerprint"] != analysis["target_fingerprint"]:
            raise ToolError("signals_contract_mismatch")
        if signals["config_digest"] != digest(analysis["config"]):
            raise ToolError("signals_config_mismatch")
        label = labels[key].get("label")
        if require_labels and label not in LABELS:
            raise ToolError("labels_required; fill label column in manifest_template.csv and use --manifest")
        records.append({"sample_id": key, "name": record["metadata"]["Name"], "version": record["metadata"]["Version"],
                        "group": normalize_name(record["metadata"]["Name"]), "metadata_digest": record["metadata_digest"],
                        "features": signals["features"], "text": signals["text"], "label": label,
                        "requested_split": labels[key].get("split"), "signals": signals})
    if not records:
        raise ToolError("no_eligible_metadata_samples")
    return records, excluded, analysis

def assign_splits(records, seed):
    fingerprints = {}
    for record in records:
        fingerprint = record["metadata_digest"]
        if fingerprint in fingerprints and fingerprints[fingerprint] != record["label"]:
            raise ToolError("identical_metadata_has_conflicting_labels; metadata cannot distinguish these samples")
        fingerprints[fingerprint] = record["label"]
    requested = [r["requested_split"] for r in records]
    if any(requested):
        if not all(requested) or set(requested) - {"train", "validation", "test"}:
            raise ToolError("provide_train_validation_test_split_for_every_eligible_sample")
        splits = list(requested)
    else:
        y = np.array([LABELS[r["label"]] for r in records])
        groups = np.array([r["group"] for r in records])
        minimum = min(len(set(groups[y == label])) for label in (0, 1))
        if minimum < 3:
            raise ToolError("need_at_least_3_package_groups_per_class_for_automatic_split")
        folds = min(7, minimum)
        splits = None
        # Only label/group distribution is used to obtain non-empty splits; no model/test score is inspected.
        for attempt in range(10):
            splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed + attempt)
            fold_indices = [test for _, test in splitter.split(np.zeros(len(y)), y, groups)]
            candidate = ["train"] * len(records)
            for name, indices in (("test", fold_indices[0]), ("validation", fold_indices[1])):
                for index in indices:
                    candidate[index] = name
            if all({records[i]["label"] for i, split in enumerate(candidate) if split == name}
                   == set(LABELS) for name in ("train", "validation", "test")):
                splits = candidate
                break
        if splits is None:
            raise ToolError("cannot_create_group_split_with_both_classes; provide_explicit_splits")
    group_splits, duplicate_splits = {}, {}
    for record, split in zip(records, splits):
        for mapping, key in ((group_splits, record["group"]), (duplicate_splits, record["metadata_digest"])):
            if key in mapping and mapping[key] != split:
                raise ToolError("package_or_duplicate_metadata_overlap_between_splits")
            mapping[key] = split
    for name in ("train", "validation", "test"):
        labels = {r["label"] for r, split in zip(records, splits) if split == name}
        if labels != set(LABELS):
            raise ToolError("each_split_requires_both_classes: " + name)
    return splits

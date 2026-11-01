"""Rule-based matching over a frozen PyPI name inventory."""
import string
from itertools import permutations
from pathlib import Path

from ..common import ToolError, normalize_name, valid_name, write_json
from .signals import edit_distance, pair_signals, SIGNAL_KEYS

ALPHABET = string.ascii_lowercase + string.digits + "-"


def search_inventory_legacy(name, inventory, limit=20):
    if not valid_name(name):
        raise ToolError("invalid_package_name")
    if not 1 <= limit <= 1000:
        raise ToolError("candidate_limit_must_be_1_to_1000")
    name = normalize_name(name)
    candidates = set()
    for i in range(len(name)):
        candidates.add(name[:i] + name[i + 1:])
        for char in ALPHABET:
            candidates.add(name[:i] + char + name[i + 1:])
        if i + 1 < len(name):
            candidates.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    for i in range(len(name) + 1):
        for char in ALPHABET:
            candidates.add(name[:i] + char + name[i:])
    candidates.discard(name)
    hits = candidates.intersection(inventory)
    ranked = []
    for target in hits:
        flags = pair_signals(name, target)
        ranked.append({"target": target, "edit_distance": edit_distance(name, target),
                       "signals": [key for key, value in flags.items() if value]})
    ranked.sort(key=lambda item: (item["edit_distance"], item["target"]))
    return {"name": name, "name_in_snapshot": name in inventory, "candidate_count": len(ranked),
            "candidates": ranked[:limit], "truncated": len(ranked) > limit}


def search_inventory(name, inventory, limit=20):
    """Generate candidates for each supported rule, then test inventory membership."""
    if not valid_name(name):
        raise ToolError("invalid_package_name")
    if not 1 <= limit <= 1000:
        raise ToolError("candidate_limit_must_be_1_to_1000")
    name = normalize_name(name)
    candidates = set()
    for i in range(1, len(name)):
        if name[i] == name[i - 1]:
            candidates.add(name[:i] + name[i + 1:])
    for i in range(len(name) + 1):
        for char in ALPHABET:
            candidates.add(name[:i] + char + name[i:])
    for i in range(len(name)):
        for char in ALPHABET:
            candidates.add(name[:i] + char + name[i + 1:])
        if i + 1 < len(name):
            candidates.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    # The suffix may contain multiple digits; each valid split is a possible target.
    for i in range(1, len(name)):
        if name[i:].isdigit():
            candidates.add(name[:i].rstrip("-"))
    words = name.split("-")
    if len(words) > 1:
        if len(words) <= 7:
            candidates.update("-".join(parts) for parts in permutations(words))
        else:
            # Avoid factorial growth on untrusted long names without silently missing a match.
            key = sorted(words)
            candidates.update(item for item in inventory if item.count("-") == len(words) - 1
                              and sorted(item.split("-")) == key)
    candidates.discard(name)
    ranked = []
    flags = dict.fromkeys(SIGNAL_KEYS, False)
    for target in candidates.intersection(inventory):
        current = pair_signals(name, target)
        signals = [key for key, enabled in current.items() if enabled]
        if not signals:
            continue
        for key in signals:
            flags[key] = True
        ranked.append({"target": target, "edit_distance": edit_distance(name, target), "signals": signals})
    ranked.sort(key=lambda item: (item["edit_distance"], item["target"]))
    return {"name": name, "name_in_snapshot": name in inventory, "candidate_count": len(ranked),
            "candidates": ranked[:limit], "truncated": len(ranked) > limit, "flags": flags}


def inventory_search_report(reference, names, limit=20):
    if not reference.get("index_available") or not reference.get("names"):
        raise ToolError("pypi_inventory_unavailable_sync_reference_first")
    inventory = set(reference["names"])
    return {"schema_version": "inventory-search-1", "algorithm": "spellbound-signals-2",
            "reference_sha256": reference["sha256"], "snapshot_source": reference["source"],
            "snapshot_created_at": reference["created_at"], "snapshot_serial": reference.get("serial"),
            "inventory_size": len(inventory), "candidate_limit": limit,
            "note": "Similarity candidates only; neither target identity nor maliciousness is established.",
            "results": [search_inventory(name, inventory, limit) for name in names]}


def save_report(path, report):
    destination = Path(path)
    if destination.exists():
        raise ToolError("inventory_search_output_must_be_new")
    write_json(destination, report)

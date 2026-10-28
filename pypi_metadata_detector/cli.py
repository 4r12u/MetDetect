"""Human-readable CLI for metadata extraction, signals, training and scanning."""
import argparse
from pathlib import Path
import sys

from . import __version__
from .common import Progress, ToolError, discover, load_config, read_json, write_csv, write_json
from .phase1_metadata_extraction.extract import extract_run
from .phase2_metadata_analysis.reference import default_reference, load_reference, read_targets, sync_reference
from .phase2_metadata_analysis.signals import analyze_run

def parser():
    root = argparse.ArgumentParser(description="PyPI metadata-only detector: metadata + name signals + RF/DT.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    ref = commands.add_parser("reference", help="Create or explicitly synchronize an offline PyPI reference")
    actions = ref.add_subparsers(dest="action", required=True)
    for action in ("init", "sync"):
        sub = actions.add_parser(action)
        sub.add_argument("--output", default="references")
        sub.add_argument("--targets", help="CSV with name column, or one target per line")
        sub.add_argument("--quiet", action="store_true")
        if action == "sync":
            sub.add_argument("--run", help="Also retrieve exact-version metadata for this extraction run")
    extract = commands.add_parser("extract", help="Phase 1: read PKG-INFO/METADATA without executing samples")
    source = extract.add_mutually_exclusive_group(required=True)
    source.add_argument("--input")
    source.add_argument("--manifest")
    extract.add_argument("--output", default="outputs/metadata-run")
    extract.add_argument("--config")
    analyze = commands.add_parser("analyze", help="Phase 2: deterministic metadata and name features")
    analyze.add_argument("--run", required=True)
    analyze.add_argument("--references")
    analyze.add_argument("--config")
    train = commands.add_parser("train", help="Phase 3/4: train-only encoding, RF/DT and validation selection")
    train.add_argument("--run", required=True)
    train.add_argument("--manifest", help="Attach labels/splits using the original sample_id and path")
    evaluate = commands.add_parser("evaluate", help="Evaluate a fitted bundle; never fit on evaluation data")
    evaluate.add_argument("--run", required=True)
    evaluate.add_argument("--bundle", required=True, help="Locally trusted bundle produced by this tool")
    evaluate.add_argument("--manifest")
    evaluate.add_argument("--split", choices=["validation", "test"], default="test")
    scan = commands.add_parser("scan", help="Extract/analyze/transform/predict with a fitted bundle, offline")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--input")
    source.add_argument("--manifest")
    scan.add_argument("--output", default="outputs/metadata-scan")
    scan.add_argument("--bundle", required=True, help="Locally trusted bundle produced by this tool")
    scan.add_argument("--references")
    for command in (extract, analyze, train, evaluate, scan):
        command.add_argument("--quiet", action="store_true")
    return root

def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    argv = list(sys.argv[1:] if argv is None else argv)
    legacy = bool(argv and argv[0] in {"reference", "extract", "analyze", "train", "evaluate", "scan"})
    if not legacy:
        from .workflow import execute, flag_parser
        flag_args = flag_parser().parse_args(argv)
        try:
            return execute(flag_args)
        except (ToolError, OSError, ValueError, KeyError, TypeError) as exc:
            print("ERROR | " + type(exc).__name__ + ": " + str(exc), file=sys.stderr, flush=True)
            return 2
    args = parser().parse_args(argv)
    progress = Progress(args.quiet)
    try:
        if args.command == "reference":
            if args.action == "init":
                reference = default_reference(read_targets(args.targets) if args.targets else None)
                write_json(Path(args.output) / "reference.json", reference)
                progress.say(f"Reference offline | Targets: {len(reference['targets'])} | Registry inventory: chưa có")
            else:
                sync_reference(args.output, args.targets, args.run, progress)
            return 0
        if args.command == "extract":
            config = load_config(args.config)
            samples = discover(args.input, args.manifest)
            result = extract_run(samples, args.output, config, progress)
            write_csv(Path(args.output) / "manifest_template.csv",
                      [{"sample_id": s["sample_id"], "path": s["path"], "label": s["label"] or "",
                        "split": s["split"] or ""} for s in samples], ["sample_id", "path", "label", "split"])
            progress.say("Nhãn để trống nếu chưa có | Template: " + str(Path(args.output) / "manifest_template.csv"))
            return int(result["failed"] > 0)
        if args.command == "analyze":
            extraction = read_json(Path(args.run) / "extraction.json")
            config = load_config(args.config) if args.config else extraction["config"]
            reference = load_reference(args.references)
            if not args.references:
                progress.say("Reference: tên ví dụ có sẵn; registry lookup chưa khả dụng. Dùng reference sync để lấy PyPI.")
            result = analyze_run(args.run, config, reference, progress)
            return int(result["failed"] > 0 or result["ok"] == 0)
        from .phase4_ml_classification.model import bundle_reference, evaluate_run, load_bundle, predict_run, train_run
        if args.command == "train":
            train_run(args.run, args.manifest, progress)
            return 0
        bundle = load_bundle(args.bundle)
        if args.command == "evaluate":
            evaluate_run(args.run, bundle, args.manifest, args.split, progress)
            return 0
        if args.command == "scan":
            reference = load_reference(args.references) if args.references else bundle_reference(bundle)
            from .phase2_metadata_analysis.reference import target_fingerprint
            if target_fingerprint(reference) != bundle["target_fingerprint"]:
                raise ToolError("scan_reference_targets_differ_from_training")
            samples = discover(args.input, args.manifest)
            extract_run(samples, args.output, bundle["config"], progress)
            analyze_run(args.output, bundle["config"], reference, progress)
            result = predict_run(args.output, bundle, progress)
            return int(result["not_predicted"] > 0)
    except (ToolError, OSError, ValueError, KeyError, TypeError) as exc:
        print("ERROR | " + type(exc).__name__ + ": " + str(exc), file=sys.stderr, flush=True)
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())

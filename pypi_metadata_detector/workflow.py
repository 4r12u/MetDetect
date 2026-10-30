"""Short phase flags, automatic input selection and deterministic output folders."""
import argparse
import csv
from pathlib import Path
import re
import uuid

from . import __version__
from .common import (LABELS, Progress, ToolError, archive_path, digest, load_config,
                     read_json, write_csv, write_json)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if not (PROJECT_ROOT / "pyproject.toml").is_file():
    PROJECT_ROOT = Path.cwd()  # Installed wheels write reports in the working project, not site-packages.
PHASE_FLAGS = ("extraction", "analysis", "preprocessing", "evaluate")
PHASE_INPUTS = {"analysis": "extraction.json", "preprocessing": "analysis.json", "evaluate": "preprocessing.json"}
RESULT_FILES = {"extraction.json", "analysis.json", "preprocessing.json"}


def flag_parser():
    parser = argparse.ArgumentParser(description="PyPI Metadata Detector — Phase 1 đọc sample; Phase 2–4 nhận output bước trước.")
    parser.add_argument("--version", action="version", version=__version__)
    phases = parser.add_mutually_exclusive_group()
    for flag, help_text in zip(PHASE_FLAGS, ("Phase 1: đọc dataset/sample gốc; --output chọn thư mục kết quả",
                                           "Phase 2: nhận thư mục Phase 1 hoặc extraction.json",
                                           "Phase 3: nhận thư mục Phase 2 hoặc analysis.json",
                                           "Phase 4: nhận thư mục Phase 3 hoặc preprocessing.json; chọn --model")):
        phases.add_argument("--" + flag, metavar="PATH", help=help_text)
    phases.add_argument("-f", "--full", metavar="PATH", help="Chạy liên tiếp Phase 1–4 từ dataset/sample gốc")
    parser.add_argument("--metric", nargs="?", const="", metavar="PATH", help="Hiện metric/kết quả; bỏ PATH để dùng lần chạy gần nhất")
    parser.add_argument("--visual", nargs="?", const="", metavar="PATH", help="Tạo HTML offline; bỏ PATH để dùng lần chạy gần nhất")
    parser.add_argument("-o", "--output", metavar="RUN_DIR", help="Thay thư mục run mặc định trong outputs")
    parser.add_argument("--visual-dir", help="Thay thư mục gốc visual")
    parser.add_argument("--manifest", help="Manifest nhãn tùy chọn; mặc định tự nhận manifest.csv hoặc dataset.csv")
    parser.add_argument("-b", "--bundle", help="Model local tin cậy dùng cho sample/dataset mới; dùng cùng model ở Phase 1–4")
    parser.add_argument("--references", help="Snapshot PyPI offline; mặc định dùng references/reference.json nếu có")
    parser.add_argument("--config", help="Cấu hình cho Phase 1/2")
    parser.add_argument("--train-config", help="JSON model/tham số/grid riêng cho Phase 4; không đổi Phase 1–3")
    parser.add_argument("-m", "--model", "--models", metavar="CODE[,CODE...]",
                        help="Model Phase 4: dt, rf, lr, svm, cnb, xgb; ví dụ --model dt,lr hoặc --model all")
    parser.add_argument("--experiment", metavar="ID", help="ID thí nghiệm mới hoặc chọn thí nghiệm cho --metric/--visual/--test")
    parser.add_argument("--test", action="store_true", help="Chỉ đánh giá test của --experiment đã chốt; không train/tune")
    parser.add_argument("--quiet", action="store_true")
    parser.epilog = "Lệnh reference sync/init và các subcommand 1.0.1 vẫn được hỗ trợ."
    return parser


def run_path(source, output=None):
    source = Path(source).resolve()
    if output:
        return Path(output).resolve()
    if source.is_file() and source.name in RESULT_FILES:
        return source.parent
    if source.is_dir() and (source / "extraction.json").is_file():
        return source
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", source.name).strip("-")[:60] or "sample"
    return PROJECT_ROOT / "outputs" / (slug + "-" + digest(str(source).casefold())[:10])


def read_manifest(path):
    path = Path(path).resolve()
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames or []
        path_column = "path" if "path" in fields else "artifact_path"
        if "sample_id" not in fields or path_column not in fields:
            raise ToolError("manifest_requires_sample_id_and_path_or_artifact_path")
        rows = []
        for row in reader:
            key, raw_path = row["sample_id"], row[path_column]
            label = (row.get("label") or "").strip().lower()
            label = {"0": "benign", "1": "malicious"}.get(label, label)
            split = (row.get("split") or "").strip()
            if not key or not raw_path or label and label not in LABELS or split and split not in {"train", "validation", "test"}:
                raise ToolError("invalid_manifest_row: " + str(key))
            raw = Path(raw_path)
            resolved = (path.parent / raw).resolve()
            if not raw.is_absolute() and not resolved.is_relative_to(path.parent):
                raise ToolError("manifest_relative_path_escape")
            rows.append({"sample_id": key, "path": str(resolved), "label": label or None, "split": split or None})
    if not rows or len(rows) != len({r["sample_id"] for r in rows}):
        raise ToolError("empty_dataset_or_duplicate_sample_id")
    if len(rows) != len({r["path"] for r in rows}):
        raise ToolError("duplicate_artifact_path_in_manifest")
    return rows


def select_rows(rows, source):
    return [r for r in rows if Path(r["path"]) == source or source.is_dir() and Path(r["path"]).is_relative_to(source)]


def collect_samples(source, manifest=None):
    """Manifest wins; recursively discover archives otherwise, without executing samples."""
    source = Path(source).resolve()
    if not source.exists():
        raise ToolError("input_not_found: " + str(source))
    if manifest:
        rows = read_manifest(manifest)
        chosen = rows if source == Path(manifest).resolve() else select_rows(rows, source)
        if not chosen:
            raise ToolError("manifest_has_no_samples_for_input")
        return chosen
    if source.is_file() and source.suffix.lower() == ".csv":
        return read_manifest(source)
    start = source if source.is_dir() else source.parent
    for folder in [start, *list(start.parents)[:8]]:
        for filename in ("manifest.csv", "dataset.csv"):
            table = folder / filename
            if table.is_file():
                chosen = select_rows(read_manifest(table), source)
                if chosen:
                    return chosen
    paths = []

    def visit(path):
        if path.is_symlink() or not path.resolve().is_relative_to(source):
            return
        if path.is_file():
            if archive_path(path) or path.name.lower() in {"metadata", "pkg-info"}:
                paths.append(path)
            return
        entries = sorted(path.iterdir(), key=lambda p: p.name.casefold())
        has_metadata = any(p.is_file() and p.name.lower() in {"metadata", "pkg-info"} for p in entries)
        has_info = any(p.is_dir() and p.name.lower().endswith((".dist-info", ".egg-info")) and
                       any((p / n).is_file() for n in ("METADATA", "PKG-INFO")) for p in entries)
        if has_metadata or has_info:
            paths.append(path)
        else:
            for child in entries:
                if not child.name.startswith("."):
                    visit(child)

    if source.is_file():
        paths = [source]
    else:
        visit(source)
    if not paths:
        raise ToolError("Không tìm thấy archive hoặc PKG-INFO/METADATA trong đầu vào.")
    return [{"sample_id": "sample-" + digest(str(p))[:20], "path": str(p), "label": None, "split": None} for p in paths]


def require_phase(run, filename, flag):
    if not (run / filename).is_file():
        raise ToolError(f"Thiếu {filename} trong {run}. Chạy {flag} trước, rồi truyền thư mục output của bước đó.")


def execute_full(args):
    """Run the existing phase workflow in order, stopping on an unsuccessful phase."""
    if args.test:
        raise ToolError("--full không chạy test; dùng --evaluate RUN --experiment ID --test sau khi chốt model.")
    if args.bundle and (args.model or args.train_config or args.experiment):
        raise ToolError("--full --bundle không dùng --model, --train-config hoặc --experiment.")
    if args.metric not in (None, "") or args.visual not in (None, ""):
        raise ToolError("Với --full, dùng --metric/--visual không kèm PATH.")
    run = (Path(args.output).resolve() if args.output else
           PROJECT_ROOT / "outputs" / ("full-" + uuid.uuid4().hex))
    if run.exists() and (not run.is_dir() or any(run.iterdir())):
        raise ToolError("--full cần thư mục output mới hoặc rỗng để không ghi đè kết quả cũ.")
    if args.model or args.train_config:
        from .phase4_ml_classification.estimators import load_training_config
        load_training_config(args.train_config, args.model)
    for phase in PHASE_FLAGS:
        values = vars(args).copy()
        values["full"] = None
        for flag in PHASE_FLAGS:
            values[flag] = str(args.full if phase == "extraction" else run) if flag == phase else None
        values["output"] = str(run) if phase == "extraction" else None
        values["manifest"] = args.manifest if phase == "extraction" else None
        values["config"] = args.config if phase in ("extraction", "analysis") else None
        values["references"] = args.references if phase == "analysis" else None
        for key in ("model", "train_config", "experiment", "metric", "visual"):
            values[key] = getattr(args, key) if phase == "evaluate" else None
        Progress(args.quiet).say(f"Chạy toàn bộ | Phase {PHASE_FLAGS.index(phase) + 1}: {phase}")
        result = execute(argparse.Namespace(**values))
        if result:
            Progress(args.quiet).say(f"Dừng tại Phase {PHASE_FLAGS.index(phase) + 1}; xem trạng thái trong {run}")
            return result
    return 0


def execute(args):
    from .phase1_metadata_extraction.extract import extract_run
    from .phase2_metadata_analysis.reference import load_reference
    from .phase2_metadata_analysis.signals import analyze_run

    if args.full:
        return execute_full(args)
    progress = Progress(args.quiet)
    phase = next((flag for flag in PHASE_FLAGS if getattr(args, flag)), None)
    if args.model and (phase != "evaluate" or args.test or args.bundle):
        raise ToolError("--model chỉ dùng với --evaluate để huấn luyện; --test/--bundle dùng model đã chốt.")
    if args.train_config and (phase != "evaluate" or args.test or args.bundle):
        raise ToolError("--train-config chỉ dùng với --evaluate để tạo thí nghiệm mới.")
    if args.test and (phase != "evaluate" or not args.experiment or args.bundle):
        raise ToolError("Test cần --evaluate PATH --experiment ID --test; không dùng --bundle.")
    if args.experiment and (phase not in (None, "evaluate") or args.bundle):
        raise ToolError("--experiment dùng với --evaluate hoặc --metric/--visual, không dùng --bundle.")
    sources = [v for v in (getattr(args, phase) if phase else None, args.metric, args.visual) if v]
    normalized = [Path(p).resolve().parent if Path(p).is_file() and Path(p).name in RESULT_FILES
                  else Path(p).resolve() for p in sources]
    if normalized and len(set(normalized)) > 1:
        raise ToolError("Các flag phải dùng cùng một đường dẫn đầu vào.")
    if not sources:
        if args.metric is None and args.visual is None:
            raise ToolError("Chọn --extraction/--analysis/--preprocessing/--evaluate hoặc --metric/--visual.")
        if args.output:
            run = Path(args.output).resolve()
        else:
            latest = PROJECT_ROOT / "outputs" / "latest.json"
            if not latest.is_file():
                raise ToolError("Chưa có lần chạy gần nhất. Truyền PATH sau --metric/--visual.")
            run = Path(read_json(latest)["run"]).resolve()
        source = run
    else:
        source = Path(sources[0]).resolve()
        if not source.exists():
            raise ToolError("input_not_found: " + str(source))
        if phase == "extraction" and source.is_file() and source.name in RESULT_FILES:
            raise ToolError("Phase 1 cần dataset/sample gốc, không đọc lại file kết quả của tool.")
        if phase in PHASE_INPUTS and source.is_file() and source.name in RESULT_FILES:
            if source.name != PHASE_INPUTS[phase]:
                raise ToolError(f"--{phase} cần {PHASE_INPUTS[phase]} hoặc thư mục output của phase trước.")
        if source.is_file() and source.name in RESULT_FILES and args.output and Path(args.output).resolve() != source.parent:
            raise ToolError("Khi đọc file kết quả, không đổi --output; dùng thư mục chứa file để giữ đủ artifact liên quan.")
        if source.is_dir() and (source / "extraction.json").is_file() and args.output and Path(args.output).resolve() != source:
            raise ToolError("Các phase sau bổ sung vào thư mục output đang đọc; không chuyển --output sang thư mục khác.")
        run = run_path(source, args.output)
    if run == source and not (run / "extraction.json").is_file():
        raise ToolError("output_must_not_replace_input")
    progress.say("Kết quả: " + str(run))
    result_code = 0
    bundle = None
    if args.bundle:
        from .phase4_ml_classification.model import load_bundle
        bundle = load_bundle(args.bundle)
    if phase == "extraction":
        if (run / "extraction.json").is_file() and source == run:
            raise ToolError("Phase 1 cần đường dẫn sample/dataset gốc, không dùng thư mục output.")
        samples = collect_samples(source, args.manifest)
        if any(Path(s["path"]) == run or Path(s["path"]).is_dir() and run.is_relative_to(Path(s["path"])) for s in samples):
            raise ToolError("output_must_be_outside_sample_directory")
        config = bundle["config"] if bundle else load_config(args.config)
        if bundle and args.config and load_config(args.config) != config:
            raise ToolError("config_must_match_bundle")
        synthetic = False
        notice = source / "README.txt" if source.is_dir() else source.parent / "README.txt"
        if notice.is_file():
            with notice.open(encoding="utf-8", errors="replace") as stream:
                synthetic = stream.read(128).startswith("SYNTHETIC FUNCTIONAL DEMO ONLY")
        write_json(run / "input.json", {"source": str(source), "samples_digest": digest(samples), "synthetic": synthetic})
        result = extract_run(samples, run, config, progress)
        write_csv(run / "manifest_template.csv", samples, ["sample_id", "path", "label", "split"])
        result_code = int(result["failed"] > 0 or result["ok"] == 0)
    elif phase:
        require_phase(run, "extraction.json", "--extraction")
        if run != source and not (source.is_file() and source.name in RESULT_FILES):
            progress.say(f"Đường dẫn dataset kiểu cũ được hỗ trợ. Các phase sau nên nhận output: {run}")
        if args.manifest:
            raise ToolError("Để đổi manifest/nhãn, chạy lại --extraction --manifest trước.")
        if phase == "analysis":
            extraction = read_json(run / "extraction.json")
            config = load_config(args.config) if args.config else extraction["config"]
            if bundle:
                from .phase4_ml_classification.model import bundle_reference
                from .phase2_metadata_analysis.reference import target_fingerprint
                reference = load_reference(args.references) if args.references else bundle_reference(bundle)
                if config != bundle["config"] or target_fingerprint(reference) != bundle["target_fingerprint"]:
                    raise ToolError("analysis_config_and_targets_must_match_bundle")
            else:
                default_path = PROJECT_ROOT / "references" / "reference.json"
                reference_path = args.references or (default_path if default_path.is_file() else None)
                reference = load_reference(reference_path)
                if reference_path is None:
                    progress.say("Reference: tập tên ví dụ; chưa sync inventory PyPI. Có thể dùng reference sync một lần.")
            result = analyze_run(run, config, reference, progress)
            result_code = int(result["failed"] > 0 or result["ok"] == 0)
        else:
            require_phase(run, "analysis.json", "--analysis")
            if args.config or args.references:
                raise ToolError("Cấu hình/reference đã lưu ở Phase 2; đổi chúng bằng --analysis rồi chạy lại Phase 3.")
            from .phase3_preprocessing.artifacts import load_prepared, preprocess_run
            if phase == "preprocessing":
                try:
                    preprocess_run(run, progress, bundle)
                except ToolError as exc:
                    if "labels_required" in str(exc):
                        raise ToolError("Dataset train cần manifest có nhãn. Sample mới dùng --bundle MODEL ở Phase 1–4.") from exc
                    raise
            else:
                require_phase(run, "preprocessing.json", "--preprocessing")
                report, records, excluded, analysis, prepared = load_prepared(run, bundle)
                from .phase4_ml_classification.model import predict_run
                if report["mode"] == "training":
                    progress.say("Phase 4 | Dùng X và encoder đã lưu từ Phase 3")
                    from .phase4_ml_classification.experiments import train_experiment, test_experiment
                    if args.test:
                        test_experiment(run, progress, args.experiment)
                    else:
                        experiment = train_experiment(run, progress, args.train_config, args.experiment, args.model)
                        args.experiment = experiment["experiment_id"]
                else:
                    if args.train_config or args.test or args.experiment:
                        raise ToolError("Inference --bundle không dùng tùy chọn huấn luyện/thí nghiệm.")
                    summary = predict_run(run, bundle, progress, prepared_matrix=prepared[3]["inference"])
                    write_json(run / "phase4.json", {"training_id": bundle["training_id"], "mode": report["mode"],
                               "source_digest": report["source_digest"], "preprocessing_digest": digest(report)})
                    result_code = int(summary["not_predicted"] > 0)
    require_phase(run, "extraction.json", "--extraction")
    if phase and phase != "evaluate":
        following = {"extraction": "analysis", "analysis": "preprocessing", "preprocessing": "evaluate"}[phase]
        suffix = " --model dt" if following == "evaluate" and bundle is None else ""
        bundle_arg = f' --bundle "{Path(args.bundle).resolve()}"' if args.bundle else ""
        progress.say(f'Bước tiếp: python -m pypi_metadata_detector --{following} "{run}"{suffix}{bundle_arg}')
    write_json(PROJECT_ROOT / "outputs" / "latest.json", {"run": str(run)})
    if args.metric is not None or args.visual is not None:
        from .reporting import build_report, print_report, write_visual
        report = build_report(run, args.experiment)
        from .phase4_ml_classification.experiments import resolve_experiment
        experiment_folder = resolve_experiment(run, args.experiment) if report.get("experiment") else None
        write_json((experiment_folder or run) / "metrics.json", report)
        if args.metric is not None:
            print_report(report, progress)
        if args.visual is not None:
            target = Path(args.visual_dir).resolve() if args.visual_dir else PROJECT_ROOT / "visual"
            visual_folder = target / run.name
            if experiment_folder:
                visual_folder = visual_folder / experiment_folder.name
            html = write_visual(report, visual_folder / "index.html")
            progress.say("Báo cáo HTML: " + str(html))
    return result_code

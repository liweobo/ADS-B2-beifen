"""Run the full benchmark and immediately apply the strict publication gate."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from adsb.benchmark import parse_seed_list, run_multi_seed_benchmark
from adsb.publication_preflight import run_publication_preflight, write_preflight_report
from adsb.train_constants import WINDOW_SIZE
from adsb.verify_artifacts import build_verification_report, write_verification_report


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run and verify an ADS-B publication benchmark.")
    parser.add_argument("--csv", default="sample_adsb_decoded.csv", help="Input ADS-B CSV path.")
    parser.add_argument(
        "--seeds",
        default="42,43,44,45,46",
        help="Comma-separated independent seeds. Strict verification requires at least five.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs") / "publication_benchmark",
        help="Benchmark artifact directory.",
    )
    parser.add_argument("--window-size", type=int, default=WINDOW_SIZE, help="Sliding-window length in time steps.")
    parser.add_argument(
        "--save-models",
        action="store_true",
        help="Save per-seed checkpoints. This can consume substantial disk space.",
    )
    parser.add_argument(
        "--include-ablation",
        action="store_true",
        help="Run ablation exports inside each seed. This substantially increases runtime.",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Verification report directory; defaults to --output-dir.",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip the data coverage preflight and start training immediately.",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Do not reuse completed per-seed benchmark artifacts in the output directory.",
    )
    parser.add_argument(
        "--force-rerun",
        action="store_true",
        help="Rerun all benchmark seeds even if matching completed per-seed artifacts exist.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    seeds = parse_seed_list(args.seeds)
    preflight_json: str | None = None
    if not args.skip_preflight:
        preflight = run_publication_preflight(
            seeds=seeds,
            csv_path=args.csv,
            window_size=args.window_size,
            num_aircraft=None,
            min_seeds=5,
            require_full_data=True,
        )
        preflight_paths = write_preflight_report(preflight, args.report_dir or args.output_dir)
        preflight_json = preflight_paths["json"]
        print(f"preflight_json={preflight_paths['json']}")
        print(f"preflight_markdown={preflight_paths['markdown']}")
        if not preflight.get("passed"):
            print("PREFLIGHT FAILED")
            for error in preflight.get("errors", []):
                print(error)
            return 1
        print("PREFLIGHT PASSED")

    manifest_path = run_multi_seed_benchmark(
        seeds=seeds,
        csv_path=args.csv,
        output_dir=args.output_dir,
        num_aircraft=None,
        window_size=args.window_size,
        max_epochs=None,
        save_models=args.save_models,
        run_ablation=args.include_ablation,
        deterministic=True,
        capture_logs=True,
        resume=not args.no_resume,
        force_rerun=args.force_rerun,
    )
    benchmark_dir = manifest_path.parent
    report = build_verification_report(
        benchmark_dir,
        publication_ready=True,
        preflight_report=preflight_json,
    )
    report_paths = write_verification_report(report, report_dir=args.report_dir or benchmark_dir)
    print(f"report_json={report_paths['json']}")
    print(f"report_markdown={report_paths['markdown']}")
    if not report.get("passed"):
        print("PUBLICATION GATE FAILED")
        for error in report.get("errors", []):
            print(error)
        return 1
    print("PUBLICATION GATE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

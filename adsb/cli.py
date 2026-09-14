"""Command-line entry points for training, inference, and benchmarks."""

from __future__ import annotations

import argparse
from pathlib import Path

from adsb.benchmark import parse_seed_list, run_multi_seed_benchmark
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.experiment import main as run_experiment
from adsb.inference import run_checkpoint_on_new_csv
from adsb.train_constants import (
    EVAL_ATTACK_EPS,
    INJECT_RATIO,
    SEED,
    TRAJECTORY_ADV_EPS_DEFAULT,
    WINDOW_SIZE,
)
from adsb.utils import set_seed
from adsb.verify_artifacts import build_verification_report, write_verification_report


def _ascii_safe(value: object) -> str:
    return str(value).encode("ascii", errors="backslashreplace").decode("ascii")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ADS-B anomaly detection experiments and publication benchmarks."
    )
    parser.add_argument("--csv", type=str, default="sample_adsb_decoded.csv", help="Input ADS-B CSV path.")
    parser.add_argument(
        "--num-aircraft",
        type=int,
        default=None,
        metavar="N",
        help="Randomly keep N aircraft identities; by default all aircraft are used.",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=WINDOW_SIZE,
        metavar="T",
        help="Sliding-window length in time steps.",
    )
    parser.add_argument(
        "--max-epochs",
        type=int,
        default=None,
        metavar="N",
        help="Optional epoch cap for a single training run; useful for smoke tests.",
    )
    parser.add_argument(
        "--skip-ablation",
        action="store_true",
        help="Skip the Table V ablation study.",
    )
    parser.add_argument(
        "--figures-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Directory for generated figures.",
    )
    parser.add_argument(
        "--no-save-models",
        action="store_true",
        help="Do not write model checkpoints.",
    )
    parser.add_argument(
        "--checkpoint-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Directory for model checkpoints.",
    )

    parser.add_argument(
        "--benchmark-seeds",
        type=str,
        default=None,
        metavar="S1,S2,...",
        help="Run multiple seeds and aggregate mean/std/95%% CI.",
    )
    parser.add_argument(
        "--benchmark-output-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Output directory for multi-seed benchmark artifacts.",
    )
    parser.add_argument(
        "--benchmark-max-epochs",
        type=int,
        default=None,
        metavar="N",
        help="Optional epoch cap for each benchmark seed.",
    )
    parser.add_argument(
        "--benchmark-save-models",
        action="store_true",
        help="Save per-seed checkpoints during benchmark runs.",
    )
    parser.add_argument(
        "--benchmark-nondeterministic",
        action="store_true",
        help="Use the faster nondeterministic CUDA configuration during benchmark runs.",
    )
    parser.add_argument(
        "--benchmark-stream-logs",
        action="store_true",
        help="Stream per-seed training logs to the console instead of run.log files.",
    )
    parser.add_argument(
        "--benchmark-no-resume",
        action="store_true",
        help="Do not reuse completed per-seed benchmark artifacts in the output directory.",
    )
    parser.add_argument(
        "--benchmark-force-rerun",
        action="store_true",
        help="Rerun all benchmark seeds even if matching completed per-seed artifacts exist.",
    )
    parser.add_argument(
        "--verify-benchmark",
        type=Path,
        default=None,
        metavar="DIR",
        help="Verify an existing multi-seed benchmark directory and exit.",
    )
    parser.add_argument(
        "--verify-require-physical-metrics",
        action="store_true",
        help="Fail verification if physical metrics are missing for attack settings.",
    )
    parser.add_argument(
        "--verify-allow-missing-logs",
        action="store_true",
        help="Do not require per-seed run.log files during verification.",
    )
    parser.add_argument(
        "--verify-min-seeds",
        type=int,
        default=None,
        metavar="N",
        help="Fail verification if the benchmark has fewer than N independent seeds.",
    )
    parser.add_argument(
        "--verify-strict-publication",
        action="store_true",
        help="Require publication-ready settings: >=5 seeds, physical metrics, primary claims, full data/epochs, deterministic, and logs.",
    )
    parser.add_argument(
        "--verify-require-primary-claims",
        action="store_true",
        help="Fail if the primary CAT-AD claims are not supported by paired mean improvements.",
    )
    parser.add_argument(
        "--verify-write-report",
        action="store_true",
        help="Write verification_report.json and verification_report.md.",
    )
    parser.add_argument(
        "--verify-preflight-report",
        type=Path,
        default=None,
        metavar="PATH",
        help="Optional preflight_report.json to verify against the benchmark manifest and include in the report.",
    )
    parser.add_argument(
        "--verify-report-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Directory for verification reports; defaults to --verify-benchmark.",
    )

    parser.add_argument(
        "--test-checkpoint",
        type=Path,
        default=None,
        metavar="PATH.pt",
        help="Inference-only mode: load a checkpoint and evaluate it on --csv.",
    )
    parser.add_argument(
        "--test-inject-ratio",
        type=float,
        default=INJECT_RATIO,
        help="Anomaly injection ratio for --test-checkpoint evaluation.",
    )
    parser.add_argument(
        "--test-eval-eps",
        type=float,
        default=EVAL_ATTACK_EPS,
        help="PGD/Phys-PGD epsilon for --test-checkpoint evaluation.",
    )
    parser.add_argument(
        "--test-no-inject",
        action="store_true",
        help="Do not inject anomalies in --test-checkpoint mode.",
    )
    parser.add_argument(
        "--skip-trajectory",
        action="store_true",
        help="Skip trajectory comparison figures in --test-checkpoint mode.",
    )
    parser.add_argument(
        "--trajectory-sample-index",
        type=int,
        default=0,
        help="Test sample index for trajectory comparison figures.",
    )
    parser.add_argument(
        "--trajectory-adv-eps",
        type=float,
        default=TRAJECTORY_ADV_EPS_DEFAULT,
        help="PGD/Phys-PGD epsilon for trajectory comparison figures.",
    )
    return parser.parse_args()


def main_entry() -> None:
    args = parse_args()
    if args.verify_benchmark is not None:
        report = build_verification_report(
            args.verify_benchmark,
            require_physical_metrics=args.verify_require_physical_metrics,
            require_logs=not args.verify_allow_missing_logs,
            min_seeds=args.verify_min_seeds,
            require_primary_claims=args.verify_require_primary_claims,
            publication_ready=args.verify_strict_publication,
            preflight_report=args.verify_preflight_report,
        )
        if args.verify_write_report:
            paths = write_verification_report(
                report,
                report_dir=args.verify_report_dir or args.verify_benchmark,
            )
            print(f"report_json={paths['json']}")
            print(f"report_markdown={paths['markdown']}")
        if not report.get("passed"):
            print("VERIFY FAILED")
            print(_ascii_safe("\n".join(report.get("errors", []))))
            raise SystemExit(1)
        summary = report["summary"]
        print("VERIFY PASSED")
        print(f"benchmark_dir={summary['benchmark_dir']}")
        print(f"seeds={','.join(str(seed) for seed in summary['seeds'])}")
        print(f"aggregate_rows={summary['num_aggregate_rows']}")
        print(f"comparison_rows={summary['num_comparison_rows']}")
        for warning in summary["warnings"]:
            print(f"WARNING: {warning}")
        return

    if args.benchmark_seeds is not None:
        run_multi_seed_benchmark(
            seeds=parse_seed_list(args.benchmark_seeds),
            csv_path=args.csv,
            output_dir=args.benchmark_output_dir,
            num_aircraft=args.num_aircraft,
            window_size=args.window_size,
            max_epochs=args.benchmark_max_epochs,
            save_models=args.benchmark_save_models,
            run_ablation=not args.skip_ablation,
            deterministic=not args.benchmark_nondeterministic,
            capture_logs=not args.benchmark_stream_logs,
            resume=not args.benchmark_no_resume,
            force_rerun=args.benchmark_force_rerun,
        )
        return

    if args.test_checkpoint is not None:
        set_seed(SEED)
        dev = resolve_device()
        configure_cuda_training(dev)
        run_checkpoint_on_new_csv(
            args.test_checkpoint,
            args.csv,
            device=dev,
            num_aircraft=args.num_aircraft,
            inject_ratio=args.test_inject_ratio,
            eval_eps=args.test_eval_eps,
            inject_for_metrics=not args.test_no_inject,
            figures_dir=args.figures_dir,
            trajectory_compare=not args.skip_trajectory,
            trajectory_sample_index=args.trajectory_sample_index,
            trajectory_adv_eps=args.trajectory_adv_eps,
            window_size=args.window_size,
        )
        return

    _ = run_experiment(
        run_ablation_plots=not args.skip_ablation,
        csv_path=args.csv,
        num_aircraft=args.num_aircraft,
        figures_dir=args.figures_dir,
        save_models=not args.no_save_models,
        checkpoint_dir=args.checkpoint_dir,
        window_size=args.window_size,
        max_epochs=args.max_epochs,
    )

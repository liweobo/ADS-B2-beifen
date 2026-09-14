from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import adsb.benchmark as benchmark_module
from adsb.benchmark import _paired_comparison_rows, parse_seed_list
from adsb.benchmark_status import build_benchmark_status, write_benchmark_status_report
from adsb.publication_preflight import _label_errors
from adsb.verify_artifacts import (
    VerificationError,
    build_verification_report,
    verify_benchmark_dir,
    write_verification_report,
)


def _write_csv(path: Path, rows: list[dict[str, object]], headers: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _digest_ids(ids: list[str]) -> str:
    digest = hashlib.sha256()
    for value in sorted(ids):
        digest.update(value.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _aircraft_manifest(ids: list[str]) -> dict[str, object]:
    return {"count": len(ids), "sha256": _digest_ids(ids), "ids": sorted(ids)}


def _window_summary(total: int, malicious: int) -> dict[str, object]:
    return {
        "total_windows": total,
        "normal_windows": total - malicious,
        "malicious_windows": malicious,
        "malicious_ratio": malicious / total,
    }


def _split_summary(seed: int, *, overlap: bool = False) -> dict[str, object]:
    train = [f"s{seed}_train_a", f"s{seed}_train_b"]
    validation = [f"s{seed}_val_a"]
    test = [f"s{seed}_test_a"]
    if overlap:
        test = [train[0], f"s{seed}_test_a"]
    train_set = set(train)
    val_set = set(validation)
    test_set = set(test)
    return {
        "random_state": seed,
        "window_size": 15,
        "malicious_label_min_points": 5,
        "inject_ratio": 0.03,
        "per_attack_ratio": 0.03,
        "anomaly_types": ["d", "s", "p"],
        "aircraft": {
            "train": _aircraft_manifest(train),
            "validation": _aircraft_manifest(validation),
            "test": _aircraft_manifest(test),
            "overlap_counts": {
                "train_validation": len(train_set & val_set),
                "train_test": len(train_set & test_set),
                "validation_test": len(val_set & test_set),
            },
        },
        "windows": {
            "train": _window_summary(10, 1),
            "validation": _window_summary(8, 1),
            "test_mixed_attack": _window_summary(12, 1),
            "test_no_injection": _window_summary(12, 0),
            "per_attack": {
                "Gradual drift only": _window_summary(12, 1),
                "Position shift only": _window_summary(12, 1),
                "Kinematic spoofing only": _window_summary(12, 1),
            },
        },
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_integrity(root: Path, paths: list[Path]) -> dict[str, object]:
    entries = []
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda p: p.as_posix()):
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        sha = _sha256_file(path)
        entries.append(
            {
                "path": str(path),
                "benchmark_relative_path": rel,
                "project_relative_path": rel,
                "size_bytes": size,
                "sha256": sha,
            }
        )
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(sha.encode("ascii"))
        digest.update(b"\0")
    return {
        "algorithm": "sha256(benchmark_relative_path, size_bytes, file_sha256)",
        "file_count": len(entries),
        "sha256": digest.hexdigest(),
        "files": entries,
    }


class BenchmarkStatsTest(unittest.TestCase):
    def test_parse_seed_list_rejects_duplicates(self) -> None:
        self.assertEqual(parse_seed_list("1,2,3"), [1, 2, 3])
        with self.assertRaises(ValueError):
            parse_seed_list("1,2,1")

    def test_paired_comparison_improvement_direction(self) -> None:
        rows = [
            {"seed": 1, "model": "Baseline", "setting": "Clean", "metric": "f1", "value": 0.70},
            {"seed": 1, "model": "Proposed", "setting": "Clean", "metric": "f1", "value": 0.80},
            {"seed": 2, "model": "Baseline", "setting": "Clean", "metric": "f1", "value": 0.60},
            {"seed": 2, "model": "Proposed", "setting": "Clean", "metric": "f1", "value": 0.75},
            {"seed": 1, "model": "Baseline", "setting": "Clean", "metric": "far", "value": 0.20},
            {"seed": 1, "model": "Proposed", "setting": "Clean", "metric": "far", "value": 0.10},
            {"seed": 2, "model": "Baseline", "setting": "Clean", "metric": "far", "value": 0.40},
            {"seed": 2, "model": "Proposed", "setting": "Clean", "metric": "far", "value": 0.25},
        ]
        out = {(row["setting"], row["metric"]): row for row in _paired_comparison_rows(rows)}
        self.assertAlmostEqual(float(out[("Clean", "f1")]["mean_improvement"]), 0.125)
        self.assertAlmostEqual(float(out[("Clean", "far")]["mean_improvement"]), 0.125)
        self.assertEqual(out[("Clean", "far")]["improvement_definition"], "Baseline - Proposed")
        self.assertIn("p_holm", out[("Clean", "f1")])
        self.assertIn("q_bh_fdr", out[("Clean", "f1")])
        self.assertIn("cohens_dz", out[("Clean", "f1")])
        self.assertGreaterEqual(float(out[("Clean", "f1")]["p_holm"]), float(out[("Clean", "f1")]["p_two_sided_sign_flip"]))


class ArtifactVerifierTest(unittest.TestCase):
    def test_benchmark_resume_reuses_completed_seed_artifacts(self) -> None:
        def fake_result(**kwargs):
            seed = int(kwargs["seed"])
            metrics = {}
            for model in ("Baseline", "Proposed"):
                for setting in ("Clean", "Standard PGD", "Projection-based phys-PGD", "Penalty-based phys-PGD"):
                    metrics[(model, setting)] = {
                        "accuracy": 0.5,
                        "precision": 0.5,
                        "recall": 0.5,
                        "f1": 0.5,
                        "asr": 0.5,
                        "far": 0.5,
                    }
            return {
                "seed": seed,
                "csv_path": str(kwargs["csv_path"]),
                "num_aircraft": kwargs["num_aircraft"],
                "window_size": int(kwargs["window_size"]),
                "device": "cpu",
                "deterministic": bool(kwargs["deterministic"]),
                "epochs": 0,
                "data_summary": {
                    "csv_path": str(kwargs["csv_path"]),
                    "rows_loaded": 100,
                    "rows_after_filter": 90,
                    "rows_after_subset": 90,
                    "aircraft_loaded": 4,
                    "aircraft_after_filter": 4,
                    "aircraft_after_subset": 4,
                },
                "split_summary": _split_summary(seed),
                "metrics": metrics,
                "thresholds": {"baseline": 0.5, "proposed": 0.5},
                "validation_f1": {"baseline": 0.5, "proposed": 0.5},
                "artifacts": {"tables": [], "figures": [], "data": [], "table5_summary": None},
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            csv_path = root / "synthetic.csv"
            csv_path.write_text("ts,icao,lat,lon,spd,hdg,alt\n", encoding="utf-8")
            output_dir = root / "benchmark"
            with mock.patch("adsb.benchmark.run_experiment", side_effect=fake_result) as mocked:
                benchmark_module.run_multi_seed_benchmark(
                    seeds=[11, 12],
                    csv_path=csv_path,
                    output_dir=output_dir,
                    max_epochs=0,
                    capture_logs=False,
                    resume=True,
                )
                self.assertEqual([call.kwargs["seed"] for call in mocked.call_args_list], [11, 12])
                self.assertTrue((output_dir / "runs" / "seed_11" / "run_record.json").exists())
                self.assertTrue((output_dir / "runs" / "seed_12" / "per_seed_metrics_long.csv").exists())

                mocked.reset_mock()
                benchmark_module.run_multi_seed_benchmark(
                    seeds=[11, 12],
                    csv_path=csv_path,
                    output_dir=output_dir,
                    max_epochs=0,
                    capture_logs=False,
                    resume=True,
                )
                self.assertEqual(mocked.call_count, 0)
                manifest = json.loads((output_dir / "benchmark_manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["resume"]["resumed_seeds"], [11, 12])
                self.assertEqual(manifest["resume"]["executed_seeds"], [])
                status = build_benchmark_status(output_dir)
                self.assertEqual(status["summary"]["completed_seeds"], 2)
                self.assertEqual(status["summary"]["resumed_in_last_manifest"], 2)
                self.assertEqual(status["summary"]["executed_in_last_manifest"], 0)
                seed_status = {row["seed"]: row for row in status["seeds"]}
                self.assertEqual(seed_status[11]["state"], "complete")
                self.assertTrue(seed_status[11]["metrics_exists"])
                self.assertTrue(seed_status[11]["signature_matches_manifest"])
                status_paths = write_benchmark_status_report(status, output_dir)
                self.assertTrue((output_dir / "benchmark_status.json").exists())
                self.assertTrue((output_dir / "benchmark_status.md").exists())
                self.assertEqual(status_paths["json"].replace("\\", "/").split("/")[-1], "benchmark_status.json")

                benchmark_module.run_multi_seed_benchmark(
                    seeds=[11, 12],
                    csv_path=csv_path,
                    output_dir=output_dir,
                    max_epochs=0,
                    capture_logs=False,
                    resume=True,
                    force_rerun=True,
                )
                self.assertEqual([call.kwargs["seed"] for call in mocked.call_args_list], [11, 12])

    def test_preflight_split_errors_detect_publication_data_issues(self) -> None:
        self.assertEqual(_label_errors(_split_summary(7), 7), [])

        bad = _split_summary(8, overlap=True)
        bad["window_size"] = 3
        bad["malicious_label_min_points"] = 4
        bad["windows"]["train"] = _window_summary(10, 0)
        errors = _label_errors(bad, 8)
        self.assertTrue(any("malicious_label_min_points" in error for error in errors))
        self.assertTrue(any("window_size" in error for error in errors))
        self.assertTrue(any("aircraft leakage" in error for error in errors))
        self.assertTrue(any("train must contain" in error for error in errors))

    def test_verifier_accepts_complete_core_benchmark(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = [1, 2]
            long_rows = []
            aggregate_rows = []
            comparison_rows = []
            wide_rows = []
            for seed in seeds:
                for model in ("Baseline", "Proposed"):
                    for setting in ("Clean", "Standard PGD", "Projection-based phys-PGD", "Penalty-based phys-PGD"):
                        wide = {"seed": seed, "model": model, "setting": setting}
                        for metric in ("accuracy", "precision", "recall", "f1", "asr", "far"):
                            value = 0.5
                            long_rows.append(
                                {"seed": seed, "model": model, "setting": setting, "metric": metric, "value": value}
                            )
                            wide[metric] = value
                        wide_rows.append(wide)
            for model in ("Baseline", "Proposed"):
                for setting in ("Clean", "Standard PGD", "Projection-based phys-PGD", "Penalty-based phys-PGD"):
                    for metric in ("accuracy", "precision", "recall", "f1", "asr", "far"):
                        aggregate_rows.append(
                            {
                                "model": model,
                                "setting": setting,
                                "metric": metric,
                                "n": 2,
                                "mean": 0.5,
                                "std": 0.0,
                                "stderr": 0.0,
                                "ci95_low": 0.5,
                                "ci95_high": 0.5,
                                "ci95_half_width": 0.0,
                                "mean_pm_std": "0.5000 +/- 0.0000",
                                "mean_pm_ci95": "0.5000 +/- 0.0000",
                            }
                        )
            for setting, metrics in {
                "Clean": ("f1", "far"),
                "Standard PGD": ("f1", "asr"),
                "Projection-based phys-PGD": ("f1", "asr"),
                "Penalty-based phys-PGD": ("f1", "asr"),
            }.items():
                for metric in metrics:
                    comparison_rows.append(
                        {
                            "setting": setting,
                            "metric": metric,
                            "n": 2,
                            "direction": "higher_is_better",
                            "improvement_definition": "Proposed - Baseline",
                            "mean_improvement": 0.0,
                            "std_improvement": 0.0,
                            "cohens_dz": 0.0,
                            "median_improvement": 0.0,
                            "ci95_low": 0.0,
                            "ci95_high": 0.0,
                            "p_two_sided_sign_flip": 1.0,
                            "p_holm": 1.0,
                            "q_bh_fdr": 1.0,
                            "significant_holm_0_05": False,
                            "significant_bh_fdr_0_05": False,
                            "p_value_method": "degenerate",
                            "win_rate": 0.0,
                            "tie_rate": 1.0,
                            "raw_mean_delta_proposed_minus_baseline": 0.0,
                            "seeds": "1,2",
                        }
                    )

            _write_csv(root / "per_seed_metrics_long.csv", long_rows, ["seed", "model", "setting", "metric", "value"])
            _write_csv(
                root / "per_seed_metrics_wide.csv",
                wide_rows,
                ["seed", "model", "setting", "accuracy", "precision", "recall", "f1", "asr", "far"],
            )
            _write_csv(
                root / "aggregate_summary.csv",
                aggregate_rows,
                [
                    "model",
                    "setting",
                    "metric",
                    "n",
                    "mean",
                    "std",
                    "stderr",
                    "ci95_low",
                    "ci95_high",
                    "ci95_half_width",
                    "mean_pm_std",
                    "mean_pm_ci95",
                ],
            )
            _write_csv(
                root / "paired_comparisons.csv",
                comparison_rows,
                [
                    "setting",
                    "metric",
                    "n",
                    "direction",
                    "improvement_definition",
                    "mean_improvement",
                    "std_improvement",
                    "cohens_dz",
                    "median_improvement",
                    "ci95_low",
                    "ci95_high",
                    "p_two_sided_sign_flip",
                    "p_holm",
                    "q_bh_fdr",
                    "significant_holm_0_05",
                    "significant_bh_fdr_0_05",
                    "p_value_method",
                    "win_rate",
                    "tie_rate",
                    "raw_mean_delta_proposed_minus_baseline",
                    "seeds",
                ],
            )
            (root / "aggregate_selected_summary.tex").write_text("table", encoding="utf-8")
            (root / "paired_comparisons.tex").write_text("table", encoding="utf-8")
            integrity_paths = [
                root / "per_seed_metrics_long.csv",
                root / "per_seed_metrics_wide.csv",
                root / "aggregate_summary.csv",
                root / "aggregate_selected_summary.tex",
                root / "paired_comparisons.csv",
                root / "paired_comparisons.tex",
            ]
            for seed in seeds:
                run_dir = root / "runs" / f"seed_{seed}"
                run_dir.mkdir(parents=True)
                (run_dir / "run.log").write_text("log", encoding="utf-8")
                integrity_paths.append(run_dir / "run.log")
            manifest = {
                "config": {"seeds": seeds, "csv_path": "synthetic.csv", "window_size": 15, "num_aircraft": None},
                "invocation": {
                    "argv": ["conda", "run", "-n", "testtorch", "python", "-m", "adsb.run"],
                    "python_executable": "test-prefix\\python.exe",
                    "working_directory": str(root),
                },
                "environment": {
                    "torch": "test",
                    "cuda_available": True,
                    "conda": {
                        "default_env": "testtorch",
                        "prefix": "test-prefix",
                        "python_executable": "test-prefix\\python.exe",
                    },
                    "packages": {
                        "package_count": 5,
                        "sha256": "2" * 64,
                        "key_packages": {
                            "torch": "test",
                            "numpy": "test",
                            "pandas": "test",
                            "scikit-learn": "test",
                            "matplotlib": "test",
                        },
                    },
                },
                "provenance": {
                    "data": {"sha256": "0" * 64, "size_bytes": 1},
                    "code": {"sha256": "1" * 64, "file_count": 1},
                    "hyperparameters": {"EPOCHS": 30, "LR": 1e-3, "ADV_TRAIN_EPS": 0.1},
                },
                "artifact_integrity": _artifact_integrity(root, integrity_paths),
                "runs": [
                    {
                        "seed": seed,
                        "run_dir": str(root / "runs" / f"seed_{seed}"),
                        "run_dir_benchmark_relative": f"runs/seed_{seed}",
                        "log_path": str(root / "runs" / f"seed_{seed}" / "run.log"),
                        "log_path_benchmark_relative": f"runs/seed_{seed}/run.log",
                        "data_summary": {
                            "csv_path": "synthetic.csv",
                            "rows_loaded": 100,
                            "rows_after_filter": 90,
                            "rows_after_subset": 90,
                            "aircraft_loaded": 4,
                            "aircraft_after_filter": 4,
                            "aircraft_after_subset": 4,
                        },
                        "split_summary": _split_summary(seed),
                    }
                    for seed in seeds
                ],
            }
            (root / "benchmark_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            summary = verify_benchmark_dir(root)
            self.assertEqual(summary["seeds"], seeds)
            self.assertEqual(summary["num_comparison_rows"], 8)
            self.assertTrue(any(not claim["passed"] for claim in summary["primary_claims"]))
            report = build_verification_report(root)
            self.assertTrue(report["passed"])
            report_paths = write_verification_report(report, report_dir=root)
            self.assertTrue((root / "verification_report.json").exists())
            self.assertTrue((root / "verification_report.md").exists())
            self.assertEqual(report_paths["json"].replace("\\", "/").split("/")[-1], "verification_report.json")
            self.assertEqual(verify_benchmark_dir(root, min_seeds=2)["seeds"], seeds)
            preflight_report = {
                "schema_version": 1,
                "created_at_utc": "2026-01-01T00:00:00+00:00",
                "passed": True,
                "options": {
                    "csv_path": "synthetic.csv",
                    "seeds": seeds,
                    "window_size": 15,
                    "require_full_data": True,
                },
                "dataset_summary": {
                    "rows_loaded": 100,
                    "rows_after_filter": 90,
                    "aircraft_loaded": 4,
                    "aircraft_after_filter": 4,
                },
                "runs": [
                    {
                        "seed": seed,
                        "passed": True,
                        "data_summary": {
                            "aircraft_after_filter": 4,
                            "aircraft_after_subset": 4,
                        },
                    }
                    for seed in seeds
                ],
            }
            preflight_path = root / "preflight_report.json"
            preflight_path.write_text(json.dumps(preflight_report), encoding="utf-8")
            report_with_preflight = build_verification_report(root, preflight_report=preflight_path)
            self.assertTrue(report_with_preflight["passed"])
            self.assertEqual(report_with_preflight["preflight"]["seeds"], seeds)
            self.assertEqual(report_with_preflight["preflight"]["num_runs"], len(seeds))
            negative_complete = verify_benchmark_dir(root, require_primary_claims=True)
            self.assertTrue(any("claim diagnostic failed" in warning for warning in negative_complete["warnings"]))
            claim_report = build_verification_report(root, require_primary_claims=True)
            self.assertTrue(claim_report["passed"])
            self.assertFalse(claim_report["errors"])
            self.assertTrue(claim_report["diagnostics"]["primary_claims"])
            self.assertTrue(any(not claim["passed"] for claim in claim_report["diagnostics"]["primary_claims"]))
            with tempfile.TemporaryDirectory() as copied_tmp:
                copied_root = Path(copied_tmp) / "copied_benchmark"
                import shutil

                shutil.copytree(root, copied_root)
                self.assertEqual(verify_benchmark_dir(copied_root)["seeds"], seeds)
            with self.assertRaises(VerificationError):
                verify_benchmark_dir(root, min_seeds=3)
            with self.assertRaises(VerificationError):
                verify_benchmark_dir(root, publication_ready=True)
            strict_report = build_verification_report(root, publication_ready=True)
            self.assertFalse(strict_report["passed"])
            self.assertTrue(any("CUBLAS_WORKSPACE_CONFIG" in error for error in strict_report["errors"]))

            manifest["runs"][0]["split_summary"] = _split_summary(seeds[0], overlap=True)
            (root / "benchmark_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(VerificationError):
                verify_benchmark_dir(root)
            failed_report = build_verification_report(root)
            self.assertFalse(failed_report["passed"])
            self.assertTrue(any("aircraft leakage" in error for error in failed_report["errors"]))

            manifest["runs"][0]["split_summary"] = _split_summary(seeds[0])
            (root / "benchmark_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with (root / "paired_comparisons.tex").open("a", encoding="utf-8") as f:
                f.write("\nmodified")
            failed_report = build_verification_report(root)
            self.assertFalse(failed_report["passed"])
            self.assertTrue(any("artifact sha256 mismatch" in error for error in failed_report["errors"]))

    def test_verifier_rejects_missing_paired_comparisons(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "benchmark_manifest.json").write_text("{}", encoding="utf-8")
            for name in (
                "per_seed_metrics_long.csv",
                "per_seed_metrics_wide.csv",
                "aggregate_summary.csv",
                "aggregate_selected_summary.tex",
                "paired_comparisons.tex",
            ):
                (root / name).write_text("x", encoding="utf-8")
            with self.assertRaises(VerificationError):
                verify_benchmark_dir(root)


if __name__ == "__main__":
    unittest.main()

"""Artifact verification for publication experiments."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adsb.anomalies import MALICIOUS_LABEL_MIN_POINTS
from adsb.publication_claims import PRIMARY_CLAIMS, primary_claim_manifest


EXPECTED_MODELS = ("Baseline", "Proposed")
EXPECTED_SETTINGS = (
    "Clean",
    "Standard PGD",
    "Projection-based phys-PGD",
    "Penalty-based phys-PGD",
)
CORE_METRICS = ("accuracy", "precision", "recall", "f1", "asr", "far")
PHYSICAL_METRICS = (
    "pvr",
    "pv_asr",
    "pre_attack_pvr",
    "start_valid_rate",
    "introduced_pvr_start_valid",
    "conditional_asr_start_valid",
    "conditional_pv_asr_start_valid",
    "position_vr",
    "alt_vr",
    "vel_vr",
    "head_vr",
)
RATE_METRICS = set(CORE_METRICS) | set(PHYSICAL_METRICS)
PUBLICATION_MIN_SEEDS = 5
CUBLAS_WORKSPACE_CONFIGS = {":4096:8", ":16:8"}
BENCHMARK_ARTIFACTS = (
    "per_seed_metrics_long.csv",
    "per_seed_metrics_wide.csv",
    "aggregate_summary.csv",
    "aggregate_selected_summary.tex",
    "paired_comparisons.csv",
    "paired_comparisons.tex",
    "benchmark_manifest.json",
)

COMPARISON_METRICS = {
    "Clean": ("f1", "far"),
    "Standard PGD": ("f1", "asr"),
    "Projection-based phys-PGD": (
        "f1",
        "asr",
        "introduced_pvr_start_valid",
        "conditional_pv_asr_start_valid",
    ),
    "Penalty-based phys-PGD": (
        "f1",
        "asr",
        "introduced_pvr_start_valid",
        "conditional_pv_asr_start_valid",
    ),
}

class VerificationError(RuntimeError):
    pass


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(_ascii_safe(message))


def _ascii_safe(value: Any) -> str:
    text = str(value)
    return text.encode("ascii", errors="backslashreplace").decode("ascii")


def _display_path(path: str | Path) -> str:
    text = str(path)
    return _ascii_safe(text.replace("\\", "/"))


def _float_or_none(value: Any) -> float | None:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _manifest_seed_set(manifest: dict[str, Any]) -> set[int]:
    return {int(seed) for seed in manifest.get("config", {}).get("seeds", [])}


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def _positive_int(value: Any) -> bool:
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False


def _in_range(value: float | None, low: float, high: float) -> bool:
    return value is not None and low <= value <= high


def _int_or_none(value: Any) -> int | None:
    try:
        out = int(value)
    except (TypeError, ValueError):
        return None
    return out


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def _primary_claim_results(comparison_index: dict[tuple[str, str], dict[str, str]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for claim in PRIMARY_CLAIMS:
        setting = str(claim["setting"])
        metric = str(claim["metric"])
        relation = str(claim["relation"])
        threshold = float(claim["threshold"])
        row = comparison_index.get((setting, metric))
        mean = _float_or_none(row.get("mean_improvement")) if row is not None else None
        if row is None:
            passed = False
            reason = "missing paired comparison row"
        elif mean is None:
            passed = False
            reason = "non-numeric mean_improvement"
        elif relation == "positive":
            passed = mean > threshold
            reason = f"mean_improvement={mean:.6g} must be > {threshold:.6g}"
        else:
            passed = mean >= threshold
            reason = f"mean_improvement={mean:.6g} must be >= {threshold:.6g}"
        results.append(
            {
                "setting": setting,
                "metric": metric,
                "description": str(claim["description"]),
                "relation": relation,
                "threshold": threshold,
                "mean_improvement": mean,
                "passed": bool(passed),
                "reason": "ok" if passed else reason,
            }
        )
    return results


def _primary_claim_diagnostics(root: Path) -> list[dict[str, Any]]:
    path = root / "paired_comparisons.csv"
    if not path.exists() or not path.is_file():
        return []
    try:
        rows = _read_csv(path)
    except (OSError, csv.Error, UnicodeDecodeError):
        return []
    comparison_index = {
        (row.get("setting", ""), row.get("metric", "")): row
        for row in rows
    }
    return _primary_claim_results(comparison_index)


def _sha256_values(values: list[Any]) -> str:
    digest = hashlib.sha256()
    for value in sorted(str(item) for item in values):
        digest.update(value.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_preflight_report(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    report_path = Path(path)
    if not report_path.exists() or not report_path.is_file():
        raise VerificationError(f"preflight report does not exist: {_display_path(report_path)}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"failed to read preflight report {_display_path(report_path)}: {exc}") from exc
    if not isinstance(report, dict):
        raise VerificationError(f"preflight report must be a JSON object: {_display_path(report_path)}")
    report["_report_path"] = str(report_path)
    report["_report_sha256"] = _sha256_file(report_path)
    return report


def _verify_preflight_report(
    preflight_report: dict[str, Any] | None,
    manifest: dict[str, Any],
    errors: list[str],
) -> dict[str, Any] | None:
    if preflight_report is None:
        return None
    config = manifest.get("config", {})
    options = preflight_report.get("options", {})
    runs = preflight_report.get("runs", [])
    expected_seeds = sorted(_manifest_seed_set(manifest))
    observed_seeds = sorted(int(seed) for seed in options.get("seeds", [])) if isinstance(options, dict) else []
    run_seeds = sorted(int(run.get("seed")) for run in runs if isinstance(run, dict) and run.get("seed") is not None)
    _require(preflight_report.get("passed") is True, "preflight report did not pass", errors)
    _require(observed_seeds == expected_seeds, f"preflight seeds {observed_seeds} != manifest seeds {expected_seeds}", errors)
    _require(run_seeds == expected_seeds, f"preflight run seeds {run_seeds} != manifest seeds {expected_seeds}", errors)
    if isinstance(config, dict) and isinstance(options, dict):
        _require(
            str(options.get("csv_path")) == str(config.get("csv_path")),
            f"preflight csv_path {options.get('csv_path')} != manifest csv_path {config.get('csv_path')}",
            errors,
        )
        _require(
            _int_or_none(options.get("window_size")) == _int_or_none(config.get("window_size")),
            f"preflight window_size {options.get('window_size')} != manifest window_size {config.get('window_size')}",
            errors,
        )
        _require(
            options.get("require_full_data") is True,
            "preflight report must require full data for publication verification",
            errors,
        )

    for run in runs if isinstance(runs, list) else []:
        if not isinstance(run, dict):
            continue
        seed = _int_or_none(run.get("seed"))
        _require(run.get("passed") is True, f"preflight run seed {seed} did not pass", errors)
        data = run.get("data_summary", {})
        if isinstance(data, dict):
            aircraft_after_filter = _int_or_none(data.get("aircraft_after_filter"))
            aircraft_after_subset = _int_or_none(data.get("aircraft_after_subset"))
            _require(
                aircraft_after_filter is not None
                and aircraft_after_subset is not None
                and aircraft_after_subset == aircraft_after_filter,
                f"preflight run seed {seed} does not prove full aircraft usage",
                errors,
            )
    return {
        "report_path": _display_path(preflight_report.get("_report_path", "")),
        "report_sha256": preflight_report.get("_report_sha256"),
        "passed": bool(preflight_report.get("passed")),
        "created_at_utc": preflight_report.get("created_at_utc"),
        "seeds": observed_seeds,
        "num_runs": len(runs) if isinstance(runs, list) else 0,
        "dataset_summary": preflight_report.get("dataset_summary", {}),
    }


def _verify_artifact_integrity(manifest: dict[str, Any], benchmark_root: Path, errors: list[str]) -> None:
    integrity = manifest.get("artifact_integrity", {})
    _require(isinstance(integrity, dict) and bool(integrity), "manifest missing artifact_integrity", errors)
    if not isinstance(integrity, dict):
        return
    files = integrity.get("files", [])
    _require(isinstance(files, list) and bool(files), "artifact_integrity.files must be a non-empty list", errors)
    if not isinstance(files, list):
        return
    file_count = _int_or_none(integrity.get("file_count"))
    _require(file_count == len(files), f"artifact_integrity.file_count {file_count} != {len(files)} files", errors)
    _require(_is_sha256(integrity.get("sha256")), "artifact_integrity.sha256 is not a SHA-256 digest", errors)

    digest = hashlib.sha256()
    seen_paths: set[str] = set()
    for entry in files:
        _require(isinstance(entry, dict), "artifact_integrity file entry must be an object", errors)
        if not isinstance(entry, dict):
            continue
        benchmark_rel = str(entry.get("benchmark_relative_path", "")).replace("\\", "/")
        path_text = str(entry.get("path", ""))
        rel_text = benchmark_rel or str(entry.get("project_relative_path", path_text)).replace("\\", "/")
        path = (benchmark_root / benchmark_rel) if benchmark_rel else Path(path_text)
        _require(bool(benchmark_rel or path_text), "artifact_integrity file entry missing path", errors)
        _require(rel_text not in seen_paths, f"duplicate artifact integrity path: {rel_text}", errors)
        seen_paths.add(rel_text)
        _require(path.exists() and path.is_file(), f"artifact integrity path missing: {_display_path(path)}", errors)
        if not path.exists() or not path.is_file():
            continue
        size = int(path.stat().st_size)
        stored_size = _int_or_none(entry.get("size_bytes"))
        stored_sha = entry.get("sha256")
        _require(stored_size == size, f"artifact size mismatch for {rel_text}: {stored_size} != {size}", errors)
        _require(_is_sha256(stored_sha), f"artifact sha256 invalid for {rel_text}", errors)
        actual_sha = _sha256_file(path)
        _require(stored_sha == actual_sha, f"artifact sha256 mismatch for {rel_text}", errors)
        digest.update(rel_text.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(actual_sha.encode("ascii"))
        digest.update(b"\0")

    if _is_sha256(integrity.get("sha256")):
        _require(integrity.get("sha256") == digest.hexdigest(), "artifact_integrity aggregate sha256 mismatch", errors)


def _verify_id_manifest(aircraft: dict[str, Any], name: str, errors: list[str]) -> set[str]:
    entry = aircraft.get(name, {})
    _require(isinstance(entry, dict), f"manifest run split_summary.aircraft.{name} must be an object", errors)
    if not isinstance(entry, dict):
        return set()

    ids = entry.get("ids")
    _require(isinstance(ids, list), f"manifest run split_summary.aircraft.{name}.ids must be a list", errors)
    if not isinstance(ids, list):
        ids = []
    values = [str(item) for item in ids]
    value_set = set(values)
    count = _int_or_none(entry.get("count"))
    digest = entry.get("sha256")
    _require(count == len(values) and count > 0, f"invalid aircraft count for split {name}", errors)
    _require(len(value_set) == len(values), f"duplicate aircraft ids in split {name}", errors)
    _require(_is_sha256(digest), f"invalid aircraft digest for split {name}", errors)
    if _is_sha256(digest):
        _require(digest == _sha256_values(values), f"aircraft digest mismatch for split {name}", errors)
    return value_set


def _verify_label_summary(
    summary: Any,
    name: str,
    errors: list[str],
    *,
    require_malicious: bool,
) -> None:
    _require(isinstance(summary, dict), f"manifest run split_summary.windows.{name} must be an object", errors)
    if not isinstance(summary, dict):
        return
    total = _int_or_none(summary.get("total_windows"))
    normal = _int_or_none(summary.get("normal_windows"))
    malicious = _int_or_none(summary.get("malicious_windows"))
    ratio = _float_or_none(summary.get("malicious_ratio"))
    _require(total is not None and total > 0, f"{name} total_windows must be positive", errors)
    _require(normal is not None and normal >= 0, f"{name} normal_windows must be non-negative", errors)
    _require(malicious is not None and malicious >= 0, f"{name} malicious_windows must be non-negative", errors)
    if total is not None and normal is not None and malicious is not None:
        _require(normal + malicious == total, f"{name} normal+malicious windows must equal total", errors)
        expected = float(malicious / total) if total > 0 else 0.0
        _require(ratio is not None and abs(ratio - expected) <= 1e-9, f"{name} malicious_ratio is inconsistent", errors)
    if require_malicious:
        _require(malicious is not None and malicious > 0, f"{name} must contain at least one malicious window", errors)


def _verify_run_split_summary(
    run: dict[str, Any],
    config: dict[str, Any],
    *,
    publication_ready: bool,
    errors: list[str],
) -> None:
    seed = _int_or_none(run.get("seed"))
    split = run.get("split_summary", {})
    _require(isinstance(split, dict) and bool(split), f"run seed {seed} missing split_summary", errors)
    if not isinstance(split, dict):
        return

    random_state = _int_or_none(split.get("random_state"))
    _require(random_state == seed, f"split_summary.random_state {random_state} != run seed {seed}", errors)
    split_window = _int_or_none(split.get("window_size"))
    config_window = _int_or_none(config.get("window_size"))
    _require(split_window is not None and split_window > 0, f"invalid split_summary.window_size for seed {seed}", errors)
    if config_window is not None:
        _require(split_window == config_window, f"split window_size {split_window} != config window_size {config_window}", errors)
    label_min_points = _int_or_none(split.get("malicious_label_min_points"))
    if label_min_points is None:
        _require(
            not publication_ready,
            f"publication-ready verification requires split_summary.malicious_label_min_points={MALICIOUS_LABEL_MIN_POINTS}",
            errors,
        )
    else:
        _require(
            label_min_points == MALICIOUS_LABEL_MIN_POINTS,
            f"split_summary.malicious_label_min_points {label_min_points} != expected {MALICIOUS_LABEL_MIN_POINTS}",
            errors,
        )
    if publication_ready and split_window is not None:
        _require(
            split_window >= MALICIOUS_LABEL_MIN_POINTS,
            f"publication-ready verification requires window_size >= malicious label threshold {MALICIOUS_LABEL_MIN_POINTS}",
            errors,
        )

    aircraft = split.get("aircraft", {})
    _require(isinstance(aircraft, dict), f"split_summary.aircraft must be an object for seed {seed}", errors)
    if isinstance(aircraft, dict):
        train_ids = _verify_id_manifest(aircraft, "train", errors)
        val_ids = _verify_id_manifest(aircraft, "validation", errors)
        test_ids = _verify_id_manifest(aircraft, "test", errors)
        overlap_counts = aircraft.get("overlap_counts", {})
        _require(isinstance(overlap_counts, dict), f"split_summary.aircraft.overlap_counts must be an object for seed {seed}", errors)
        expected_overlaps = {
            "train_validation": len(train_ids & val_ids),
            "train_test": len(train_ids & test_ids),
            "validation_test": len(val_ids & test_ids),
        }
        for name, expected in expected_overlaps.items():
            observed = _int_or_none(overlap_counts.get(name)) if isinstance(overlap_counts, dict) else None
            _require(observed == expected, f"aircraft overlap {name} stored as {observed} but recomputed as {expected}", errors)
            _require(expected == 0, f"aircraft leakage detected in {name}: {expected} overlapping ids", errors)

    windows = split.get("windows", {})
    _require(isinstance(windows, dict), f"split_summary.windows must be an object for seed {seed}", errors)
    if not isinstance(windows, dict):
        return
    for name in ("train", "validation", "test_mixed_attack"):
        _verify_label_summary(windows.get(name), name, errors, require_malicious=publication_ready)
    _verify_label_summary(windows.get("test_no_injection"), "test_no_injection", errors, require_malicious=False)
    no_injection = windows.get("test_no_injection", {})
    if isinstance(no_injection, dict):
        _require(
            _int_or_none(no_injection.get("malicious_windows")) == 0,
            "test_no_injection must not contain malicious windows",
            errors,
        )

    per_attack = windows.get("per_attack", {})
    _require(isinstance(per_attack, dict) and bool(per_attack), f"split_summary.windows.per_attack missing for seed {seed}", errors)
    if isinstance(per_attack, dict):
        for name, summary in per_attack.items():
            _verify_label_summary(
                summary,
                f"per_attack.{name}",
                errors,
                require_malicious=publication_ready,
            )


def _verify_run_data_summary(
    run: dict[str, Any],
    config: dict[str, Any],
    *,
    publication_ready: bool,
    errors: list[str],
) -> None:
    if not publication_ready:
        return
    seed = _int_or_none(run.get("seed"))
    summary = run.get("data_summary", {})
    _require(isinstance(summary, dict) and bool(summary), f"run seed {seed} missing data_summary", errors)
    if not isinstance(summary, dict):
        return

    rows_loaded = _int_or_none(summary.get("rows_loaded"))
    rows_after_filter = _int_or_none(summary.get("rows_after_filter"))
    rows_after_subset = _int_or_none(summary.get("rows_after_subset"))
    aircraft_loaded = _int_or_none(summary.get("aircraft_loaded"))
    aircraft_after_filter = _int_or_none(summary.get("aircraft_after_filter"))
    aircraft_after_subset = _int_or_none(summary.get("aircraft_after_subset"))
    for name, value in (
        ("rows_loaded", rows_loaded),
        ("rows_after_filter", rows_after_filter),
        ("rows_after_subset", rows_after_subset),
        ("aircraft_loaded", aircraft_loaded),
        ("aircraft_after_filter", aircraft_after_filter),
        ("aircraft_after_subset", aircraft_after_subset),
    ):
        _require(value is not None and value > 0, f"run seed {seed} data_summary.{name} must be positive", errors)

    if rows_loaded is not None and rows_after_filter is not None:
        _require(
            rows_loaded >= rows_after_filter,
            f"run seed {seed} data_summary rows_loaded < rows_after_filter",
            errors,
        )
    if rows_after_filter is not None and rows_after_subset is not None:
        _require(
            rows_after_filter >= rows_after_subset,
            f"run seed {seed} data_summary rows_after_filter < rows_after_subset",
            errors,
        )
    if aircraft_loaded is not None and aircraft_after_filter is not None:
        _require(
            aircraft_loaded >= aircraft_after_filter,
            f"run seed {seed} data_summary aircraft_loaded < aircraft_after_filter",
            errors,
        )
    if aircraft_after_filter is not None and aircraft_after_subset is not None:
        _require(
            aircraft_after_filter >= aircraft_after_subset,
            f"run seed {seed} data_summary aircraft_after_filter < aircraft_after_subset",
            errors,
        )
    if config.get("num_aircraft") is None and aircraft_after_filter is not None and aircraft_after_subset is not None:
        _require(
            aircraft_after_subset == aircraft_after_filter,
            f"run seed {seed} data_summary indicates aircraft subsetting despite config.num_aircraft=null",
            errors,
        )


def _verify_provenance(manifest: dict[str, Any], errors: list[str]) -> None:
    provenance = manifest.get("provenance", {})
    _require(isinstance(provenance, dict) and bool(provenance), "manifest missing provenance", errors)
    if not isinstance(provenance, dict):
        return

    data = provenance.get("data", {})
    _require(isinstance(data, dict) and bool(data), "manifest missing provenance.data", errors)
    if isinstance(data, dict):
        _require(_is_sha256(data.get("sha256")), "manifest provenance.data.sha256 is not a SHA-256 digest", errors)
        _require(_positive_int(data.get("size_bytes")), "manifest provenance.data.size_bytes must be positive", errors)

    code = provenance.get("code", {})
    _require(isinstance(code, dict) and bool(code), "manifest missing provenance.code", errors)
    if isinstance(code, dict):
        _require(_is_sha256(code.get("sha256")), "manifest provenance.code.sha256 is not a SHA-256 digest", errors)
        _require(_positive_int(code.get("file_count")), "manifest provenance.code.file_count must be positive", errors)

    hyperparameters = provenance.get("hyperparameters", {})
    _require(
        isinstance(hyperparameters, dict) and bool(hyperparameters),
        "manifest missing provenance.hyperparameters",
        errors,
    )
    if isinstance(hyperparameters, dict):
        for name in ("EPOCHS", "LR", "ADV_TRAIN_EPS"):
            _require(name in hyperparameters, f"manifest provenance.hyperparameters missing {name}", errors)


def _verify_environment(manifest: dict[str, Any], errors: list[str]) -> None:
    environment = manifest.get("environment", {})
    _require(isinstance(environment, dict) and bool(environment), "manifest missing environment", errors)
    if not isinstance(environment, dict):
        return
    _require(bool(environment.get("torch")), "manifest missing environment.torch", errors)
    conda = environment.get("conda", {})
    _require(isinstance(conda, dict) and bool(conda), "manifest missing environment.conda", errors)
    if isinstance(conda, dict):
        _require(bool(conda.get("default_env")), "environment.conda.default_env missing", errors)
        _require(bool(conda.get("python_executable")), "environment.conda.python_executable missing", errors)

    packages = environment.get("packages", {})
    _require(isinstance(packages, dict) and bool(packages), "manifest missing environment.packages", errors)
    if not isinstance(packages, dict):
        return
    _require(_positive_int(packages.get("package_count")), "environment.packages.package_count must be positive", errors)
    _require(_is_sha256(packages.get("sha256")), "environment.packages.sha256 is not a SHA-256 digest", errors)
    key_packages = packages.get("key_packages", {})
    _require(isinstance(key_packages, dict) and bool(key_packages), "environment.packages.key_packages missing", errors)
    if isinstance(key_packages, dict):
        for name in ("torch", "numpy", "pandas", "scikit-learn", "matplotlib"):
            _require(bool(key_packages.get(name)), f"environment.packages.key_packages missing {name}", errors)


def _verify_invocation(manifest: dict[str, Any], errors: list[str]) -> None:
    invocation = manifest.get("invocation", {})
    _require(isinstance(invocation, dict) and bool(invocation), "manifest missing invocation", errors)
    if not isinstance(invocation, dict):
        return
    argv = invocation.get("argv")
    _require(isinstance(argv, list) and bool(argv), "manifest invocation.argv must be a non-empty list", errors)
    _require(bool(invocation.get("python_executable")), "manifest invocation.python_executable missing", errors)
    _require(bool(invocation.get("working_directory")), "manifest invocation.working_directory missing", errors)


def _verify_publication_config(manifest: dict[str, Any], errors: list[str]) -> None:
    config = manifest.get("config", {})
    _require(isinstance(config, dict), "manifest config must be an object", errors)
    if not isinstance(config, dict):
        return
    _require(config.get("max_epochs") is None, "publication-ready verification requires config.max_epochs to be null", errors)
    _require(config.get("num_aircraft") is None, "publication-ready verification requires config.num_aircraft to be null", errors)
    _require(config.get("deterministic") is True, "publication-ready verification requires deterministic=True", errors)
    conda = manifest.get("environment", {}).get("conda", {})
    default_env = conda.get("default_env") if isinstance(conda, dict) else None
    _require(default_env == "testtorch", "publication-ready verification requires CONDA_DEFAULT_ENV=testtorch", errors)
    environment = manifest.get("environment", {})
    if isinstance(environment, dict) and environment.get("cuda_available") is True:
        determinism = environment.get("determinism", {})
        _require(
            isinstance(determinism, dict) and bool(determinism),
            "publication-ready CUDA verification requires environment.determinism",
            errors,
        )
        if isinstance(determinism, dict):
            cublas_config = determinism.get("cublas_workspace_config")
            _require(
                cublas_config in CUBLAS_WORKSPACE_CONFIGS,
                (
                    "publication-ready CUDA verification requires "
                    f"CUBLAS_WORKSPACE_CONFIG in {sorted(CUBLAS_WORKSPACE_CONFIGS)}, got {cublas_config!r}"
                ),
                errors,
            )
            _require(
                determinism.get("torch_deterministic_algorithms") is True,
                "publication-ready verification requires torch deterministic algorithms to be enabled",
                errors,
            )
            _require(
                determinism.get("torch_deterministic_algorithms_warn_only") is False,
                "publication-ready verification requires torch deterministic algorithms warn_only=False",
                errors,
            )
            _require(
                determinism.get("cudnn_deterministic") is True,
                "publication-ready verification requires cudnn_deterministic=True",
                errors,
            )
            _require(
                determinism.get("cudnn_benchmark") is False,
                "publication-ready verification requires cudnn_benchmark=False",
                errors,
            )
            _require(
                determinism.get("cuda_matmul_allow_tf32") is False,
                "publication-ready verification requires cuda_matmul_allow_tf32=False",
                errors,
            )
            _require(
                determinism.get("cudnn_allow_tf32") is False,
                "publication-ready verification requires cudnn_allow_tf32=False",
                errors,
            )
    statistics = manifest.get("statistics", {})
    _require(isinstance(statistics, dict), "manifest statistics must be an object", errors)
    if isinstance(statistics, dict):
        _require(
            statistics.get("primary_claims") == primary_claim_manifest(),
            "publication-ready verification requires manifest statistics.primary_claims to match the verifier claim spec",
            errors,
        )


def verify_benchmark_dir(
    benchmark_dir: str | Path,
    *,
    require_physical_metrics: bool = False,
    require_logs: bool = True,
    min_seeds: int | None = None,
    require_primary_claims: bool = False,
    publication_ready: bool = False,
) -> dict[str, Any]:
    root = Path(benchmark_dir)
    errors: list[str] = []
    warnings: list[str] = []
    if publication_ready:
        require_physical_metrics = True
        require_logs = True
        min_seeds = max(PUBLICATION_MIN_SEEDS, int(min_seeds or 0))

    _require(root.exists() and root.is_dir(), f"benchmark directory does not exist: {_display_path(root)}", errors)
    for name in BENCHMARK_ARTIFACTS:
        path = root / name
        _require(path.exists() and path.stat().st_size > 0, f"missing or empty artifact: {name}", errors)
    if errors:
        raise VerificationError("\n".join(errors))

    manifest_path = root / "benchmark_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    config = manifest.get("config", {})
    seeds = _manifest_seed_set(manifest)
    _require(bool(seeds), "manifest config.seeds is empty", errors)
    if min_seeds is not None:
        _require(len(seeds) >= int(min_seeds), f"benchmark has {len(seeds)} seeds but requires at least {int(min_seeds)}", errors)
    _verify_invocation(manifest, errors)
    _verify_environment(manifest, errors)
    _verify_provenance(manifest, errors)
    _verify_artifact_integrity(manifest, root, errors)
    if publication_ready:
        _verify_publication_config(manifest, errors)

    long_rows = _read_csv(root / "per_seed_metrics_long.csv")
    wide_rows = _read_csv(root / "per_seed_metrics_wide.csv")
    aggregate_rows = _read_csv(root / "aggregate_summary.csv")
    comparison_rows = _read_csv(root / "paired_comparisons.csv")
    _require(bool(long_rows), "per_seed_metrics_long.csv has no rows", errors)
    _require(bool(wide_rows), "per_seed_metrics_wide.csv has no rows", errors)
    _require(bool(aggregate_rows), "aggregate_summary.csv has no rows", errors)
    _require(bool(comparison_rows), "paired_comparisons.csv has no rows", errors)

    long_seeds = {int(row["seed"]) for row in long_rows if row.get("seed")}
    _require(long_seeds == seeds, f"long CSV seeds {sorted(long_seeds)} != manifest seeds {sorted(seeds)}", errors)
    for idx, row in enumerate(long_rows, start=2):
        metric = row.get("metric", "")
        value = _float_or_none(row.get("value"))
        _require(value is not None, f"non-numeric per-seed value at per_seed_metrics_long.csv:{idx}", errors)
        if metric in RATE_METRICS:
            _require(_in_range(value, 0.0, 1.0), f"per-seed {metric} out of [0,1] at row {idx}: {value}", errors)

    aggregate_index = {
        (row.get("model", ""), row.get("setting", ""), row.get("metric", "")): row
        for row in aggregate_rows
    }
    required_metrics = set(CORE_METRICS)
    if require_physical_metrics:
        required_metrics.update(PHYSICAL_METRICS)
    for model in EXPECTED_MODELS:
        for setting in EXPECTED_SETTINGS:
            for metric in sorted(required_metrics):
                if setting == "Clean" and metric in PHYSICAL_METRICS:
                    continue
                key = (model, setting, metric)
                _require(key in aggregate_index, f"missing aggregate row: {model} | {setting} | {metric}", errors)
                if key in aggregate_index:
                    row = aggregate_index[key]
                    mean = _float_or_none(row.get("mean"))
                    std = _float_or_none(row.get("std"))
                    n = int(float(row.get("n", "0") or 0))
                    _require(mean is not None, f"non-numeric mean: {model} | {setting} | {metric}", errors)
                    _require(std is not None and std >= 0.0, f"invalid std: {model} | {setting} | {metric}", errors)
                    if metric in RATE_METRICS:
                        _require(_in_range(mean, 0.0, 1.0), f"aggregate mean out of [0,1]: {model} | {setting} | {metric}", errors)
                    _require(n == len(seeds), f"n={n} but expected {len(seeds)}: {model} | {setting} | {metric}", errors)

    if not require_physical_metrics:
        for model in EXPECTED_MODELS:
            for setting in EXPECTED_SETTINGS:
                if setting == "Clean":
                    continue
                missing = [
                    metric
                    for metric in PHYSICAL_METRICS
                    if (model, setting, metric) not in aggregate_index
                ]
                if missing:
                    warnings.append(
                        f"physical metrics missing for {model} | {setting}: {', '.join(missing)}"
                    )

    comparison_index = {
        (row.get("setting", ""), row.get("metric", "")): row
        for row in comparison_rows
    }
    primary_claims = _primary_claim_results(comparison_index)
    for setting, metrics in COMPARISON_METRICS.items():
        for metric in metrics:
            if metric in PHYSICAL_METRICS and not require_physical_metrics:
                continue
            key = (setting, metric)
            _require(key in comparison_index, f"missing paired comparison row: {setting} | {metric}", errors)
            if key in comparison_index:
                row = comparison_index[key]
                n = int(float(row.get("n", "0") or 0))
                mean = _float_or_none(row.get("mean_improvement"))
                std = _float_or_none(row.get("std_improvement"))
                dz = _float_or_none(row.get("cohens_dz"))
                p_value = _float_or_none(row.get("p_two_sided_sign_flip"))
                p_holm = _float_or_none(row.get("p_holm"))
                q_bh = _float_or_none(row.get("q_bh_fdr"))
                sig_holm = _bool_or_none(row.get("significant_holm_0_05"))
                sig_bh = _bool_or_none(row.get("significant_bh_fdr_0_05"))
                win_rate = _float_or_none(row.get("win_rate"))
                tie_rate = _float_or_none(row.get("tie_rate"))
                _require(n == len(seeds), f"paired comparison n={n} but expected {len(seeds)}: {setting} | {metric}", errors)
                _require(mean is not None, f"non-numeric paired mean: {setting} | {metric}", errors)
                _require(std is not None and std >= 0.0, f"invalid paired std: {setting} | {metric}", errors)
                if std is not None and std > 1e-12:
                    _require(dz is not None, f"non-numeric paired Cohen dz: {setting} | {metric}", errors)
                _require(_in_range(mean, -1.0, 1.0), f"paired mean out of [-1,1]: {setting} | {metric}", errors)
                _require(_in_range(p_value, 0.0, 1.0), f"paired p-value out of [0,1]: {setting} | {metric}", errors)
                _require(_in_range(p_holm, 0.0, 1.0), f"paired Holm p out of [0,1]: {setting} | {metric}", errors)
                _require(_in_range(q_bh, 0.0, 1.0), f"paired BH q out of [0,1]: {setting} | {metric}", errors)
                if p_value is not None and p_holm is not None:
                    _require(p_holm + 1e-12 >= p_value, f"Holm p is smaller than raw p: {setting} | {metric}", errors)
                if p_holm is not None:
                    _require(sig_holm == (p_holm <= 0.05), f"Holm significance flag mismatch: {setting} | {metric}", errors)
                if q_bh is not None:
                    _require(sig_bh == (q_bh <= 0.05), f"BH-FDR significance flag mismatch: {setting} | {metric}", errors)
                _require(_in_range(win_rate, 0.0, 1.0), f"paired win_rate out of [0,1]: {setting} | {metric}", errors)
                _require(_in_range(tie_rate, 0.0, 1.0), f"paired tie_rate out of [0,1]: {setting} | {metric}", errors)

    if require_primary_claims:
        for claim in primary_claims:
            if not bool(claim["passed"]):
                warnings.append(
                    f"claim diagnostic failed (does not affect artifact completeness): "
                    f"{claim['setting']} | {claim['metric']} | {claim['reason']}"
                )

    runs = manifest.get("runs", [])
    _require(len(runs) == len(seeds), f"manifest has {len(runs)} runs but {len(seeds)} seeds", errors)
    for run in runs:
        seed = int(run.get("seed"))
        run_rel = str(run.get("run_dir_benchmark_relative") or "")
        run_dir = (root / run_rel) if run_rel else Path(str(run.get("run_dir", "")))
        _require(seed in seeds, f"run seed {seed} not listed in config.seeds", errors)
        _verify_run_split_summary(
            run,
            config if isinstance(config, dict) else {},
            publication_ready=publication_ready,
            errors=errors,
        )
        _verify_run_data_summary(
            run,
            config if isinstance(config, dict) else {},
            publication_ready=publication_ready,
            errors=errors,
        )
        _require(run_dir.exists(), f"run_dir does not exist for seed {seed}: {_display_path(run_dir)}", errors)
        log_rel = str(run.get("log_path_benchmark_relative") or "")
        log_path = str(root / log_rel) if log_rel else run.get("log_path")
        if require_logs:
            _require(bool(log_path), f"log_path missing for seed {seed}", errors)
            if log_path:
                log = Path(str(log_path))
                _require(
                    log.exists() and log.stat().st_size > 0,
                    f"missing or empty log for seed {seed}: {_display_path(log)}",
                    errors,
                )

    if errors:
        raise VerificationError("\n".join(errors))
    return {
        "benchmark_dir": _display_path(root),
        "seeds": sorted(seeds),
        "num_long_rows": len(long_rows),
        "num_wide_rows": len(wide_rows),
        "num_aggregate_rows": len(aggregate_rows),
        "num_comparison_rows": len(comparison_rows),
        "primary_claims": primary_claims,
        "warnings": warnings,
    }


def build_verification_report(
    benchmark_dir: str | Path,
    *,
    require_physical_metrics: bool = False,
    require_logs: bool = True,
    min_seeds: int | None = None,
    require_primary_claims: bool = False,
    publication_ready: bool = False,
    preflight_report: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(benchmark_dir)
    options = {
        "require_physical_metrics": bool(require_physical_metrics),
        "require_logs": bool(require_logs),
        "min_seeds": int(min_seeds) if min_seeds is not None else None,
        "require_primary_claims": bool(require_primary_claims),
        "publication_ready": bool(publication_ready),
        "preflight_report": _display_path(preflight_report) if preflight_report is not None else None,
    }
    report: dict[str, Any] = {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_dir": _display_path(root),
        "options": options,
    }
    try:
        summary = verify_benchmark_dir(
            root,
            require_physical_metrics=require_physical_metrics,
            require_logs=require_logs,
            min_seeds=min_seeds,
            require_primary_claims=require_primary_claims,
            publication_ready=publication_ready,
        )
        preflight_summary = None
        if preflight_report is not None:
            manifest_path = root / "benchmark_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            preflight_errors: list[str] = []
            preflight_summary = _verify_preflight_report(
                _load_preflight_report(preflight_report),
                manifest,
                preflight_errors,
            )
            if preflight_errors:
                raise VerificationError("\n".join(preflight_errors))
    except VerificationError as exc:
        diagnostics = {"primary_claims": _primary_claim_diagnostics(root)}
        report.update(
            {
                "status": "failed",
                "passed": False,
                "summary": {},
                "diagnostics": diagnostics,
                "warnings": [],
                "errors": [_ascii_safe(line) for line in str(exc).splitlines() if line.strip()],
            }
        )
        return report

    report.update(
        {
            "status": "passed",
            "passed": True,
            "summary": summary,
            "preflight": preflight_summary,
            "diagnostics": {"primary_claims": summary.get("primary_claims", [])},
            "warnings": summary.get("warnings", []),
            "errors": [],
        }
    )
    return report


def _verification_report_markdown(report: dict[str, Any]) -> str:
    status = "PASSED" if report.get("passed") else "FAILED"
    options = report.get("options", {})
    summary = report.get("summary", {})
    lines = [
        "# ADS-B Benchmark Verification Report",
        "",
        f"- Status: {status}",
        f"- Generated UTC: {_ascii_safe(report.get('created_at_utc', ''))}",
        f"- Benchmark directory: {_ascii_safe(report.get('benchmark_dir', ''))}",
        f"- Strict publication gate: {bool(options.get('publication_ready'))}",
        f"- Require physical metrics: {bool(options.get('require_physical_metrics'))}",
        f"- Require logs: {bool(options.get('require_logs'))}",
        f"- Require primary claims: {bool(options.get('require_primary_claims'))}",
        f"- Minimum seeds: {options.get('min_seeds')}",
        f"- Preflight report: {_ascii_safe(options.get('preflight_report'))}",
        "",
    ]
    if summary:
        lines.extend(
            [
                "## Summary",
                "",
                f"- Seeds: {','.join(str(seed) for seed in summary.get('seeds', []))}",
                f"- Long rows: {summary.get('num_long_rows')}",
                f"- Wide rows: {summary.get('num_wide_rows')}",
                f"- Aggregate rows: {summary.get('num_aggregate_rows')}",
                f"- Paired comparison rows: {summary.get('num_comparison_rows')}",
                "",
            ]
        )
        primary_claims = summary.get("primary_claims", [])
        if primary_claims:
            lines.extend(["## Primary Claims", ""])
            for claim in primary_claims:
                mark = "PASS" if claim.get("passed") else "FAIL"
                mean = claim.get("mean_improvement")
                mean_text = "--" if mean is None else f"{float(mean):.6g}"
                lines.append(
                    f"- {mark}: {claim.get('setting')} | {claim.get('metric')} | "
                    f"mean_improvement={mean_text} | {claim.get('description')}"
                )
            lines.append("")
        preflight = report.get("preflight")
        if preflight:
            lines.extend(
                [
                    "## Preflight",
                    "",
                    f"- Status: {'PASSED' if preflight.get('passed') else 'FAILED'}",
                    f"- Report: {_ascii_safe(preflight.get('report_path', ''))}",
                    f"- Report SHA-256: {_ascii_safe(preflight.get('report_sha256', ''))}",
                    f"- Seeds: {','.join(str(seed) for seed in preflight.get('seeds', []))}",
                    f"- Runs: {preflight.get('num_runs')}",
                    "",
                ]
            )
    else:
        primary_claims = report.get("diagnostics", {}).get("primary_claims", [])
        if primary_claims:
            lines.extend(["## Primary Claims", ""])
            for claim in primary_claims:
                mark = "PASS" if claim.get("passed") else "FAIL"
                mean = claim.get("mean_improvement")
                mean_text = "--" if mean is None else f"{float(mean):.6g}"
                reason = claim.get("reason", "")
                lines.append(
                    f"- {mark}: {claim.get('setting')} | {claim.get('metric')} | "
                    f"mean_improvement={mean_text} | {reason} | {claim.get('description')}"
                )
            lines.append("")

    warnings = report.get("warnings", [])
    lines.extend(["## Warnings", ""])
    if warnings:
        lines.extend(f"- {_ascii_safe(warning)}" for warning in warnings)
    else:
        lines.append("- None")
    lines.append("")

    errors = report.get("errors", [])
    lines.extend(["## Errors", ""])
    if errors:
        lines.extend(f"- {_ascii_safe(error)}" for error in errors)
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def write_verification_report(
    report: dict[str, Any],
    *,
    report_dir: str | Path | None = None,
) -> dict[str, str]:
    target = Path(report_dir) if report_dir is not None else Path(str(report.get("benchmark_dir", ".")))
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / "verification_report.json"
    md_path = target / "verification_report.md"
    json_path.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
    md_path.write_text(_verification_report_markdown(report), encoding="utf-8")
    return {
        "json": _display_path(json_path),
        "markdown": _display_path(md_path),
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify ADS-B publication experiment artifacts.")
    parser.add_argument("--benchmark-dir", type=Path, required=True)
    parser.add_argument(
        "--require-physical-metrics",
        action="store_true",
        help="Fail if PVR/PV-ASR/sub-violation metrics are missing for attack settings.",
    )
    parser.add_argument(
        "--allow-missing-logs",
        action="store_true",
        help="Do not require per-seed run.log files.",
    )
    parser.add_argument(
        "--min-seeds",
        type=int,
        default=None,
        metavar="N",
        help="Fail if the benchmark has fewer than N independent seeds.",
    )
    parser.add_argument(
        "--strict-publication",
        action="store_true",
        help="Require publication-ready settings: >=5 seeds, physical metrics, primary claims, full data/epochs, deterministic, and logs.",
    )
    parser.add_argument(
        "--require-primary-claims",
        action="store_true",
        help="Fail if the primary CAT-AD claims are not supported by paired mean improvements.",
    )
    parser.add_argument(
        "--write-report",
        action="store_true",
        help="Write verification_report.json and verification_report.md.",
    )
    parser.add_argument(
        "--preflight-report",
        type=Path,
        default=None,
        metavar="PATH",
        help="Optional preflight_report.json to verify against the benchmark manifest and include in the report.",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Directory for verification reports; defaults to --benchmark-dir.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    report = build_verification_report(
        args.benchmark_dir,
        require_physical_metrics=args.require_physical_metrics,
        require_logs=not args.allow_missing_logs,
        min_seeds=args.min_seeds,
        require_primary_claims=args.require_primary_claims,
        publication_ready=args.strict_publication,
        preflight_report=args.preflight_report,
    )
    if args.write_report:
        paths = write_verification_report(report, report_dir=args.report_dir or args.benchmark_dir)
        print(f"report_json={paths['json']}")
        print(f"report_markdown={paths['markdown']}")

    if not report.get("passed"):
        print("VERIFY FAILED")
        print("\n".join(report.get("errors", [])))
        raise SystemExit(1)

    summary = report["summary"]
    print("VERIFY PASSED")
    print(f"benchmark_dir={summary['benchmark_dir']}")
    print(f"seeds={','.join(str(seed) for seed in summary['seeds'])}")
    print(f"long_rows={summary['num_long_rows']}")
    print(f"wide_rows={summary['num_wide_rows']}")
    print(f"aggregate_rows={summary['num_aggregate_rows']}")
    print(f"comparison_rows={summary['num_comparison_rows']}")
    for warning in summary["warnings"]:
        print(f"WARNING: {_ascii_safe(warning)}")


if __name__ == "__main__":
    main()


__all__ = [
    "VerificationError",
    "build_verification_report",
    "verify_benchmark_dir",
    "write_verification_report",
]

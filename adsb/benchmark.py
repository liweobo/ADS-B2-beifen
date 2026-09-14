"""Multi-seed publication benchmark runner for ADS-B experiments."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata as importlib_metadata
import itertools
import json
import math
import os
import platform
import subprocess
import sys
from collections import defaultdict
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import torch

from adsb.publication_claims import primary_claim_manifest
import adsb.train_constants as train_constants
from adsb.experiment import main as run_experiment
from adsb.paper_naming import metric_display_name, model_display_name, setting_display_name
from adsb.paths import default_project_root
from adsb.train_constants import SEED, WINDOW_SIZE


MAIN_TABLE_METRICS = (
    "accuracy",
    "precision",
    "recall",
    "f1",
    "asr",
    "far",
    "pvr",
    "pv_asr",
    "pre_attack_pvr",
    "start_valid_rate",
    "start_valid_count",
    "physical_malicious_count",
    "introduced_pvr_start_valid",
    "conditional_asr_start_valid",
    "conditional_pv_asr_start_valid",
    "position_vr",
    "alt_vr",
    "vel_vr",
    "head_vr",
)

T_CRITICAL_975 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    21: 2.080,
    22: 2.074,
    23: 2.069,
    24: 2.064,
    25: 2.060,
    26: 2.056,
    27: 2.052,
    28: 2.048,
    29: 2.045,
    30: 2.042,
}

SELECTED_TEX_METRICS = {
    "Clean": ("f1", "far"),
    "Standard PGD": ("f1", "asr"),
    "Projection-based phys-PGD": ("f1", "asr", "conditional_pv_asr_start_valid"),
    "Penalty-based phys-PGD": ("f1", "asr", "conditional_pv_asr_start_valid"),
}

LOWER_BETTER_METRICS = {
    "asr",
    "far",
    "pvr",
    "pv_asr",
    "position_vr",
    "alt_vr",
    "vel_vr",
    "head_vr",
    "introduced_pvr_start_valid",
    "conditional_asr_start_valid",
    "conditional_pv_asr_start_valid",
}

COMPARISON_METRICS = {
    "Clean": ("f1", "far"),
    "Standard PGD": ("f1", "asr"),
    "Projection-based phys-PGD": (
        "f1",
        "asr",
        "introduced_pvr_start_valid",
        "conditional_asr_start_valid",
        "conditional_pv_asr_start_valid",
    ),
    "Penalty-based phys-PGD": (
        "f1",
        "asr",
        "introduced_pvr_start_valid",
        "conditional_asr_start_valid",
        "conditional_pv_asr_start_valid",
    ),
}


def parse_seed_list(text: str | Iterable[int]) -> list[int]:
    if isinstance(text, str):
        parts = [p.strip() for p in text.replace(";", ",").split(",")]
        seeds = [int(p) for p in parts if p]
    else:
        seeds = [int(s) for s in text]
    if not seeds:
        raise ValueError("At least one seed is required.")
    if len(set(seeds)) != len(seeds):
        raise ValueError(f"Duplicate seeds are not allowed: {seeds}")
    return seeds


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _format_float(value: float | None, digits: int = 4) -> str:
    if value is None or not math.isfinite(float(value)):
        return "--"
    return f"{float(value):.{digits}f}"


def _ci_multiplier(n: int) -> float:
    if n <= 1:
        return 0.0
    return T_CRITICAL_975.get(n - 1, 1.960)


def _metric_label(metric: str) -> str:
    aliases = {
        "accuracy": "Accuracy",
        "precision": "Precision",
        "recall": "Recall",
        "f1": "F1",
        "asr": "ASR",
        "far": "FAR",
        "pvr": "PVR",
        "pv_asr": "PV-ASR",
        "pre_attack_pvr": "Pre-attack PVR",
        "start_valid_rate": "Valid-start rate",
        "introduced_pvr_start_valid": "New-PVR|valid-start",
        "conditional_asr_start_valid": "ASR|valid-start",
        "conditional_pv_asr_start_valid": "PV-ASR|valid-start",
        "position_vr": "Position VR",
        "alt_vr": "Alt. VR",
        "vel_vr": "Vel. VR",
        "head_vr": "Head. VR",
    }
    return metric_display_name(aliases.get(metric, metric))


def _write_csv(path: Path, rows: list[dict[str, Any]], headers: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _flatten_run(result: dict[str, Any]) -> list[dict[str, Any]]:
    seed = int(result["seed"])
    rows: list[dict[str, Any]] = []
    for key, metrics in result["metrics"].items():
        model, setting = key
        for metric, value in metrics.items():
            numeric = _numeric(value)
            if numeric is None:
                continue
            rows.append(
                {
                    "seed": seed,
                    "model": str(model),
                    "setting": str(setting),
                    "metric": str(metric),
                    "value": numeric,
                }
            )
    return rows


def _wide_rows(long_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[int, str, str], dict[str, Any]] = {}
    for row in long_rows:
        key = (int(row["seed"]), str(row["model"]), str(row["setting"]))
        out = grouped.setdefault(
            key,
            {
                "seed": int(row["seed"]),
                "model": str(row["model"]),
                "setting": str(row["setting"]),
            },
        )
        out[str(row["metric"])] = float(row["value"])
    return [grouped[key] for key in sorted(grouped)]


def _aggregate_rows(long_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for row in long_rows:
        grouped[(str(row["model"]), str(row["setting"]), str(row["metric"]))].append(float(row["value"]))

    rows: list[dict[str, Any]] = []
    for model, setting, metric in sorted(grouped):
        values = np.asarray(grouped[(model, setting, metric)], dtype=np.float64)
        n = int(values.size)
        mean = float(values.mean())
        std = float(values.std(ddof=1)) if n > 1 else 0.0
        stderr = std / math.sqrt(n) if n > 1 else 0.0
        ci95_half_width = _ci_multiplier(n) * stderr if n > 1 else 0.0
        rows.append(
            {
                "model": model,
                "setting": setting,
                "metric": metric,
                "n": n,
                "mean": mean,
                "std": std,
                "stderr": stderr,
                "ci95_low": mean - ci95_half_width,
                "ci95_high": mean + ci95_half_width,
                "ci95_half_width": ci95_half_width,
                "mean_pm_std": f"{_format_float(mean)} +/- {_format_float(std)}",
                "mean_pm_ci95": f"{_format_float(mean)} +/- {_format_float(ci95_half_width)}",
            }
        )
    return rows


def _stable_seed(*parts: str) -> int:
    value = 2166136261
    for part in parts:
        for ch in str(part):
            value ^= ord(ch)
            value = (value * 16777619) % (2**32)
    return value


def _bootstrap_ci(values: np.ndarray, *, seed: int, iters: int = 10000) -> tuple[float, float]:
    if values.size == 0:
        return 0.0, 0.0
    if values.size == 1:
        val = float(values[0])
        return val, val
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, values.size, size=(iters, values.size))
    means = values[idx].mean(axis=1)
    lo, hi = np.quantile(means, [0.025, 0.975])
    return float(lo), float(hi)


def _sign_flip_p_value(values: np.ndarray, *, seed: int, max_exact_n: int = 16, iters: int = 20000) -> tuple[float, str]:
    if values.size == 0:
        return 1.0, "none"
    observed = abs(float(values.mean()))
    if observed <= 1e-12:
        return 1.0, "degenerate"
    if values.size <= max_exact_n:
        total = 0
        extreme = 0
        for signs in itertools.product((-1.0, 1.0), repeat=int(values.size)):
            total += 1
            stat = abs(float((values * np.asarray(signs, dtype=np.float64)).mean()))
            if stat >= observed - 1e-12:
                extreme += 1
        return float(extreme / total), "exact_sign_flip"

    rng = np.random.default_rng(seed)
    signs = rng.choice(np.asarray([-1.0, 1.0], dtype=np.float64), size=(iters, values.size))
    stats = np.abs((signs * values[None, :]).mean(axis=1))
    p_value = (float((stats >= observed - 1e-12).sum()) + 1.0) / (float(iters) + 1.0)
    return p_value, f"monte_carlo_sign_flip_{iters}"


def _cohens_dz(values: np.ndarray) -> float | None:
    if values.size <= 1:
        return None
    std = float(values.std(ddof=1))
    if std <= 1e-12:
        return 0.0 if abs(float(values.mean())) <= 1e-12 else None
    return float(values.mean() / std)


def _add_multiple_comparison_corrections(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return rows
    p_values = [
        min(1.0, max(0.0, float(row.get("p_two_sided_sign_flip", 1.0))))
        for row in rows
    ]
    m = len(p_values)
    order = sorted(range(m), key=lambda idx: p_values[idx])

    holm = [1.0] * m
    running_holm = 0.0
    for rank, idx in enumerate(order, start=1):
        adjusted = (m - rank + 1) * p_values[idx]
        running_holm = max(running_holm, adjusted)
        holm[idx] = min(1.0, running_holm)

    bh = [1.0] * m
    running_bh = 1.0
    for rank, idx in reversed(list(enumerate(order, start=1))):
        adjusted = p_values[idx] * m / rank
        running_bh = min(running_bh, adjusted)
        bh[idx] = min(1.0, running_bh)

    for idx, row in enumerate(rows):
        row["p_holm"] = holm[idx]
        row["q_bh_fdr"] = bh[idx]
        row["significant_holm_0_05"] = bool(holm[idx] <= 0.05)
        row["significant_bh_fdr_0_05"] = bool(bh[idx] <= 0.05)
    return rows


def _paired_comparison_rows(long_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values: dict[tuple[int, str, str, str], float] = {}
    seeds: set[int] = set()
    for row in long_rows:
        seed = int(row["seed"])
        seeds.add(seed)
        values[(seed, str(row["model"]), str(row["setting"]), str(row["metric"]))] = float(row["value"])

    rows: list[dict[str, Any]] = []
    for setting, metrics in COMPARISON_METRICS.items():
        for metric in metrics:
            paired: list[float] = []
            raw_deltas: list[float] = []
            used_seeds: list[int] = []
            for seed in sorted(seeds):
                b_key = (seed, "Baseline", setting, metric)
                p_key = (seed, "Proposed", setting, metric)
                if b_key not in values or p_key not in values:
                    continue
                baseline = values[b_key]
                proposed = values[p_key]
                raw_delta = proposed - baseline
                improvement = baseline - proposed if metric in LOWER_BETTER_METRICS else raw_delta
                raw_deltas.append(raw_delta)
                paired.append(improvement)
                used_seeds.append(seed)
            if not paired:
                continue

            improvement_values = np.asarray(paired, dtype=np.float64)
            raw_delta_values = np.asarray(raw_deltas, dtype=np.float64)
            n = int(improvement_values.size)
            seed_for_stats = _stable_seed(setting, metric)
            ci_low, ci_high = _bootstrap_ci(improvement_values, seed=seed_for_stats)
            p_value, p_method = _sign_flip_p_value(improvement_values, seed=seed_for_stats + 17)
            std = float(improvement_values.std(ddof=1)) if n > 1 else 0.0
            dz = _cohens_dz(improvement_values)
            rows.append(
                {
                    "setting": setting,
                    "metric": metric,
                    "n": n,
                    "direction": "lower_is_better" if metric in LOWER_BETTER_METRICS else "higher_is_better",
                    "improvement_definition": (
                        "Baseline - Proposed" if metric in LOWER_BETTER_METRICS else "Proposed - Baseline"
                    ),
                    "mean_improvement": float(improvement_values.mean()),
                    "std_improvement": std,
                    "cohens_dz": dz,
                    "median_improvement": float(np.median(improvement_values)),
                    "ci95_low": ci_low,
                    "ci95_high": ci_high,
                    "p_two_sided_sign_flip": p_value,
                    "p_value_method": p_method,
                    "win_rate": float((improvement_values > 1e-12).mean()),
                    "tie_rate": float((np.abs(improvement_values) <= 1e-12).mean()),
                    "raw_mean_delta_proposed_minus_baseline": float(raw_delta_values.mean()),
                    "seeds": ",".join(str(seed) for seed in used_seeds),
                }
            )
    return _add_multiple_comparison_corrections(rows)


def _tex_escape(text: str) -> str:
    return (
        str(text)
        .replace("\\", r"\textbackslash{}")
        .replace("&", r"\&")
        .replace("%", r"\%")
        .replace("_", r"\_")
    )


def _write_selected_tex(path: Path, aggregate_rows: list[dict[str, Any]]) -> None:
    lookup = {
        (str(row["model"]), str(row["setting"]), str(row["metric"])): row
        for row in aggregate_rows
    }

    def mean_ci(model: str, setting: str, metric: str) -> str:
        row = lookup.get((model, setting, metric))
        if row is None:
            return "--"
        def compact(value: float) -> str:
            return f"{value:.4f}" if 0.0 < abs(value) < 0.001 else f"{value:.3f}"

        mean = compact(float(row["mean"]))
        half_width = compact(float(row["ci95_half_width"]))
        return f"{mean} ({half_width})"

    settings = (
        "Clean",
        "Standard PGD",
        "Projection-based phys-PGD",
        "Penalty-based phys-PGD",
    )
    lines = [
        r"\begin{table*}[!ht]",
        r"\centering",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{3pt}",
        r"\renewcommand{\arraystretch}{1.10}",
        r"\caption{Multi-seed detection and robustness summary over five matched aircraft splits/seeds. Entries are mean (95\% confidence-interval half-width).}",
        r"\label{tab:multiseed_summary}",
        r"\begin{tabular}{lcccc}",
        r"\toprule",
        r"Setting & F1-score $\uparrow$ & ASR $\downarrow$ & PV-ASR$\mid V_0$ $\downarrow$ & FAR $\downarrow$ \\",
        r"\midrule",
    ]
    for model in ("Baseline", "Proposed"):
        lines.append(rf"\multicolumn{{5}}{{l}}{{\textbf{{{_tex_escape(model_display_name(model))}}}}} \\")
        for setting in settings:
            f1 = mean_ci(model, setting, "f1")
            asr = mean_ci(model, setting, "asr") if setting != "Clean" else "--"
            pv_asr = (
                mean_ci(model, setting, "conditional_pv_asr_start_valid")
                if setting in {"Projection-based phys-PGD", "Penalty-based phys-PGD"}
                else "--"
            )
            far = mean_ci(model, setting, "far") if setting == "Clean" else "--"
            lines.append(
                f"{_tex_escape(setting_display_name(setting, short=True))} & {f1} & {asr} & {pv_asr} & {far} " + r"\\"
            )
        if model == "Baseline":
            lines.append(r"\midrule")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\vspace{1mm}",
            r"\begin{minipage}{0.98\textwidth}",
            r"\footnotesize $V_0$ denotes anomalous samples satisfying every audited constraint before perturbation. "
            r"Confidence intervals use the Student $t$ multiplier and are not clipped to $[0,1]$. "
            r"Unpert., Norm-PGD, Proj. Phys-PGD, and Penalty Phys-PGD denote unperturbed evaluation, norm-bounded PGD, "
            r"Projection-based Phys-PGD, and Penalty-based Phys-PGD, respectively.",
            r"\end{minipage}",
            r"\end{table*}",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_paired_comparisons_tex(
    path: Path,
    comparison_rows: list[dict[str, Any]],
    *,
    require_all_primary: bool = False,
) -> None:
    effect_headers = ["Setting", "Metric", "n", "Mean Improvement", "95% CI"]
    inference_headers = ["Setting", "Metric", "p", "Holm p", "BH q", "dz"]
    primary_keys = (
        ("Clean", "f1"),
        ("Standard PGD", "asr"),
        ("Projection-based phys-PGD", "asr"),
        ("Penalty-based phys-PGD", "asr"),
        ("Projection-based phys-PGD", "conditional_pv_asr_start_valid"),
        ("Penalty-based phys-PGD", "conditional_pv_asr_start_valid"),
    )
    comparison_lookup = {
        (str(row["setting"]), str(row["metric"])): row for row in comparison_rows
    }
    missing_primary = [key for key in primary_keys if key not in comparison_lookup]
    if require_all_primary and missing_primary:
        missing_text = ", ".join(f"{setting} | {metric}" for setting, metric in missing_primary)
        raise ValueError(f"Missing primary paired comparisons: {missing_text}")

    rendered_rows: list[dict[str, str]] = []
    for key in primary_keys:
        row = comparison_lookup.get(key)
        if row is None:
            continue
        rendered_rows.append(
            {
                "Setting": setting_display_name(str(row["setting"]), short=True),
                "Metric": (
                    "PV-ASR|V0"
                    if str(row["metric"]) == "conditional_pv_asr_start_valid"
                    else _metric_label(str(row["metric"]))
                ),
                "n": str(int(row["n"])),
                "Mean Improvement": _format_float(float(row["mean_improvement"])),
                "95% CI": (
                    f"[{_format_float(float(row['ci95_low']))}, "
                    f"{_format_float(float(row['ci95_high']))}]"
                ),
                "p": _format_float(float(row["p_two_sided_sign_flip"])),
                "Holm p": _format_float(float(row["p_holm"])),
                "BH q": _format_float(float(row["q_bh_fdr"])),
                "dz": _format_float(_numeric(row.get("cohens_dz"))),
            }
        )
    if not rendered_rows:
        raise ValueError("No pre-specified primary paired comparisons are available")

    complete_primary_set = len(rendered_rows) == len(primary_keys)
    caption = (
        r"\caption{Paired multi-seed comparison of CAT-AD against BiLSTM-ERM for the six pre-specified primary claims}"
        if complete_primary_set
        else rf"\caption{{Paired multi-seed comparison of CAT-AD against BiLSTM-ERM for {len(rendered_rows)} available pre-specified primary claims}}"
    )
    table_scope_note = (
        r"this paper-facing table shows only the six pre-specified primary comparisons"
        if complete_primary_set
        else rf"this benchmark table shows the {len(rendered_rows)} available pre-specified primary comparisons"
    )

    lines = [
        r"\begin{table*}[!ht]",
        r"\centering",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{3pt}",
        r"\renewcommand{\arraystretch}{1.10}",
        caption,
        r"\label{tab:paired_multiseed_comparison}",
        r"\textit{(a) Effect estimates}\par\smallskip",
        r"\begin{tabular}{llccc}",
        r"\toprule",
        " & ".join(_tex_escape(header) for header in effect_headers) + r" \\",
        r"\midrule",
    ]
    for row in rendered_rows:
        lines.append(" & ".join(_tex_escape(row[h]) for h in effect_headers) + r" \\")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\par\medskip",
            r"\textit{(b) Multiplicity-adjusted inference}\par\smallskip",
            r"\begin{tabular}{llcccc}",
            r"\toprule",
            " & ".join(_tex_escape(header) for header in inference_headers) + r" \\",
            r"\midrule",
        ]
    )
    for row in rendered_rows:
        lines.append(" & ".join(_tex_escape(row[h]) for h in inference_headers) + r" \\")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\vspace{1mm}",
            r"\begin{minipage}{0.98\textwidth}",
            r"\footnotesize BiLSTM-ERM denotes the BiLSTM trained by empirical risk minimization. "
            r"Positive improvement means CAT-AD is better than BiLSTM-ERM. "
            r"For F1-score, improvement is CAT-AD minus the baseline; for ASR, FAR, PVR, and PV-ASR, "
            r"improvement is the baseline minus CAT-AD. Raw p-values are two-sided paired sign-flip tests; "
            rf"Holm p and BH q correct across all archived paired comparisons; {table_scope_note}. "
            r"The complete result is retained in the archived CSV. dz is paired Cohen's $d_z$.",
            r"\end{minipage}",
            r"\end{table*}",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _git_commit(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return None
    commit = proc.stdout.strip()
    return commit or None


def _package_snapshot() -> dict[str, Any]:
    packages: dict[str, str] = {}
    for dist in importlib_metadata.distributions():
        name = dist.metadata.get("Name")
        if not name:
            continue
        packages[str(name).lower()] = str(dist.version)

    rows = [{"name": name, "version": version} for name, version in sorted(packages.items())]
    digest = hashlib.sha256()
    for row in rows:
        digest.update(f"{row['name']}=={row['version']}\n".encode("utf-8"))

    key_names = ("torch", "numpy", "pandas", "scikit-learn", "matplotlib")
    return {
        "source": "importlib.metadata.distributions",
        "python_executable": sys.executable,
        "package_count": len(rows),
        "sha256": digest.hexdigest(),
        "key_packages": {name: packages.get(name) for name in key_names},
        "packages": rows,
    }


def _conda_manifest() -> dict[str, Any]:
    return {
        "default_env": os.environ.get("CONDA_DEFAULT_ENV"),
        "prefix": os.environ.get("CONDA_PREFIX"),
        "python_executable": sys.executable,
    }


def _determinism_manifest() -> dict[str, Any]:
    warn_only = None
    if hasattr(torch, "is_deterministic_algorithms_warn_only_enabled"):
        try:
            warn_only = bool(torch.is_deterministic_algorithms_warn_only_enabled())
        except Exception:
            warn_only = None
    return {
        "cublas_workspace_config": os.environ.get("CUBLAS_WORKSPACE_CONFIG"),
        "torch_deterministic_algorithms": bool(torch.are_deterministic_algorithms_enabled()),
        "torch_deterministic_algorithms_warn_only": warn_only,
        "cudnn_deterministic": bool(torch.backends.cudnn.deterministic),
        "cudnn_benchmark": bool(torch.backends.cudnn.benchmark),
        "cuda_matmul_allow_tf32": bool(torch.backends.cuda.matmul.allow_tf32),
        "cudnn_allow_tf32": bool(torch.backends.cudnn.allow_tf32),
    }


def _environment_manifest(root: Path) -> dict[str, Any]:
    return {
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "torch": torch.__version__,
        "cuda_available": bool(torch.cuda.is_available()),
        "cuda_version": torch.version.cuda,
        "cudnn_version": torch.backends.cudnn.version(),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "git_commit": _git_commit(root),
        "conda": _conda_manifest(),
        "determinism": _determinism_manifest(),
        "packages": _package_snapshot(),
    }


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(val) for key, val in sorted(value.items(), key=lambda item: str(item[0]))}
    return repr(value)


def _resolve_input_path(path: str | Path, root: Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate.resolve()
    rooted = root / candidate
    if rooted.exists():
        return rooted.resolve()
    return candidate.resolve()


def _data_manifest(csv_path: str | Path, project_root: Path) -> dict[str, Any]:
    data_path = _resolve_input_path(csv_path, project_root)
    if not data_path.exists():
        return {
            "path": _display_path(data_path, project_root),
            "absolute_path": str(data_path),
            "exists": False,
            "size_bytes": 0,
            "mtime_utc": None,
            "sha256": None,
        }
    stat = data_path.stat()
    return {
        "path": _display_path(data_path, project_root),
        "absolute_path": str(data_path),
        "exists": True,
        "size_bytes": int(stat.st_size),
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "sha256": _sha256_file(data_path),
    }


def _artifact_entry(path: Path, project_root: Path, benchmark_root: Path) -> dict[str, Any]:
    stat = path.stat()
    try:
        benchmark_relative = str(path.resolve().relative_to(benchmark_root.resolve())).replace("\\", "/")
    except ValueError:
        benchmark_relative = _display_path(path, project_root).replace("\\", "/")
    return {
        "path": str(path.resolve()),
        "benchmark_relative_path": benchmark_relative,
        "project_relative_path": _display_path(path, project_root).replace("\\", "/"),
        "size_bytes": int(stat.st_size),
        "sha256": _sha256_file(path),
    }


def _artifact_integrity(paths: Iterable[Path], project_root: Path, benchmark_root: Path) -> dict[str, Any]:
    entries = [
        _artifact_entry(path, project_root, benchmark_root)
        for path in sorted(set(paths), key=lambda p: str(p.resolve()))
    ]
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(str(entry["benchmark_relative_path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry["size_bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry["sha256"]).encode("ascii"))
        digest.update(b"\0")
    return {
        "algorithm": "sha256(benchmark_relative_path, size_bytes, file_sha256)",
        "file_count": len(entries),
        "sha256": digest.hexdigest(),
        "files": entries,
    }


def _iter_code_fingerprint_files(project_root: Path) -> list[Path]:
    source_roots = ("adsb", "tools", "tests")
    suffixes = {".py", ".md", ".txt", ".toml", ".yaml", ".yml"}
    files: list[Path] = []
    for name in source_roots:
        root = project_root / name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts:
                continue
            if path.suffix.lower() in suffixes:
                files.append(path)

    for name in ("AGENTS.md", "EXPERIMENTS.md", "requirements.txt"):
        path = project_root / name
        if path.exists() and path.is_file():
            files.append(path)

    return sorted(set(files), key=lambda p: _display_path(p, project_root).replace("\\", "/"))


def _code_fingerprint(project_root: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    entries: list[dict[str, Any]] = []
    for path in _iter_code_fingerprint_files(project_root):
        rel = _display_path(path, project_root).replace("\\", "/")
        file_sha = _sha256_file(path)
        size = int(path.stat().st_size)
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_sha.encode("ascii"))
        digest.update(b"\0")
        entries.append({"path": rel, "size_bytes": size, "sha256": file_sha})
    return {
        "algorithm": "sha256(relative_path, size_bytes, file_sha256)",
        "sha256": digest.hexdigest(),
        "file_count": len(entries),
        "files": entries,
    }


def _hyperparameter_manifest(max_epochs: int | None) -> dict[str, Any]:
    params = {
        name: _json_safe(getattr(train_constants, name))
        for name in sorted(dir(train_constants))
        if name.isupper()
    }
    if max_epochs is not None:
        params["EPOCHS"] = int(max_epochs)
        params["effective_overrides"] = {"EPOCHS": int(max_epochs)}
    else:
        params["effective_overrides"] = {}
    return params


def _provenance_manifest(project_root: Path, csv_path: str | Path, max_epochs: int | None) -> dict[str, Any]:
    return {
        "data": _data_manifest(csv_path, project_root),
        "code": _code_fingerprint(project_root),
        "hyperparameters": _hyperparameter_manifest(max_epochs),
    }


def _invocation_manifest(project_root: Path) -> dict[str, Any]:
    cwd = Path.cwd().resolve()
    return {
        "argv": [str(arg) for arg in sys.argv],
        "python_executable": sys.executable,
        "working_directory": str(cwd),
        "working_directory_project_relative": _display_path(cwd, project_root),
    }


def _benchmark_relative(path: Path, benchmark_root: Path) -> str:
    return str(path.resolve().relative_to(benchmark_root.resolve())).replace("\\", "/")


def _benchmark_config(
    *,
    seeds: list[int],
    csv_path: str | Path,
    num_aircraft: int | None,
    window_size: int,
    max_epochs: int | None,
    save_models: bool,
    run_ablation: bool,
    deterministic: bool,
    capture_logs: bool,
) -> dict[str, Any]:
    return {
        "seeds": seeds,
        "csv_path": str(csv_path),
        "num_aircraft": num_aircraft,
        "window_size": int(window_size),
        "max_epochs": max_epochs,
        "save_models": bool(save_models),
        "run_ablation": bool(run_ablation),
        "deterministic": bool(deterministic),
        "capture_logs": bool(capture_logs),
    }


def _resume_signature(config: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "config": config,
        "data_sha256": provenance.get("data", {}).get("sha256"),
        "code_sha256": provenance.get("code", {}).get("sha256"),
        "hyperparameters": provenance.get("hyperparameters", {}),
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
    return {
        "algorithm": "sha256(config, data_sha256, code_sha256, hyperparameters)",
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _read_seed_metrics(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return [
        {
            "seed": int(row["seed"]),
            "model": row["model"],
            "setting": row["setting"],
            "metric": row["metric"],
            "value": float(row["value"]),
        }
        for row in rows
    ]


def _load_completed_seed_run(
    *,
    run_dir: Path,
    output_dir: Path,
    seed: int,
    capture_logs: bool,
    signature: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    record_path = run_dir / "run_record.json"
    metrics_path = run_dir / "per_seed_metrics_long.csv"
    if not record_path.exists() or not metrics_path.exists():
        return None
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
        rows = _read_seed_metrics(metrics_path)
    except (OSError, json.JSONDecodeError, ValueError, KeyError):
        return None
    if not isinstance(record, dict):
        return None
    if record.get("completed") is not True or int(record.get("seed", -1)) != int(seed):
        return None
    if record.get("resume_signature", {}).get("sha256") != signature.get("sha256"):
        return None
    if not rows or {int(row["seed"]) for row in rows} != {int(seed)}:
        return None
    if capture_logs:
        log_rel = str(record.get("log_path_benchmark_relative") or "")
        log_path = (output_dir / log_rel) if log_rel else Path(str(record.get("log_path", "")))
        if not log_path.exists() or log_path.stat().st_size <= 0:
            return None
    return record, rows


def run_multi_seed_benchmark(
    *,
    seeds: Iterable[int] = (SEED, SEED + 1, SEED + 2),
    csv_path: str | Path = "sample_adsb_decoded.csv",
    output_dir: str | Path | None = None,
    num_aircraft: int | None = None,
    window_size: int = WINDOW_SIZE,
    max_epochs: int | None = None,
    save_models: bool = False,
    run_ablation: bool = False,
    deterministic: bool = True,
    capture_logs: bool = True,
    resume: bool = True,
    force_rerun: bool = False,
) -> Path:
    seeds = parse_seed_list(seeds)
    project_root = default_project_root()
    output_dir = Path(output_dir) if output_dir is not None else project_root / "outputs" / "multiseed_benchmark"
    output_dir.mkdir(parents=True, exist_ok=True)
    runs_dir = output_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    config = _benchmark_config(
        seeds=seeds,
        csv_path=csv_path,
        num_aircraft=num_aircraft,
        window_size=window_size,
        max_epochs=max_epochs,
        save_models=save_models,
        run_ablation=run_ablation,
        deterministic=deterministic,
        capture_logs=capture_logs,
    )
    provenance = _provenance_manifest(project_root, csv_path, max_epochs)
    signature = _resume_signature(config, provenance)

    all_long_rows: list[dict[str, Any]] = []
    run_records: list[dict[str, Any]] = []
    resumed_seeds: list[int] = []
    executed_seeds: list[int] = []
    long_headers = ["seed", "model", "setting", "metric", "value"]
    for seed in seeds:
        run_dir = runs_dir / f"seed_{seed}"
        log_path = run_dir / "run.log"
        record_path = run_dir / "run_record.json"
        seed_metrics_path = run_dir / "per_seed_metrics_long.csv"
        run_dir.mkdir(parents=True, exist_ok=True)

        if resume and not force_rerun:
            completed = _load_completed_seed_run(
                run_dir=run_dir,
                output_dir=output_dir,
                seed=seed,
                capture_logs=capture_logs,
                signature=signature,
            )
            if completed is not None:
                record, rows = completed
                resumed_seeds.append(int(seed))
                run_records.append(record)
                all_long_rows.extend(rows)
                print(f"\n=== Multi-seed benchmark run: seed={seed} already complete; reusing cached artifacts ===")
                continue

        record_path.unlink(missing_ok=True)
        seed_metrics_path.unlink(missing_ok=True)
        print(f"\n=== Multi-seed benchmark run: seed={seed} ===")
        if capture_logs:
            print(f"Writing detailed run log to {_display_path(log_path, project_root)}")
        with ExitStack() as stack:
            if capture_logs:
                log_file = stack.enter_context(log_path.open("w", encoding="utf-8"))
                stack.enter_context(redirect_stdout(log_file))
                stack.enter_context(redirect_stderr(log_file))
            result = run_experiment(
                run_ablation_plots=run_ablation,
                csv_path=str(csv_path),
                figures_dir=run_dir / "figures",
                num_aircraft=num_aircraft,
                save_models=save_models,
                checkpoint_dir=run_dir / "checkpoints",
                window_size=window_size,
                seed=seed,
                deterministic=deterministic,
                max_epochs=max_epochs,
                output_root=run_dir,
                make_paper_exports=False,
            )
        executed_seeds.append(int(seed))
        run_rows = _flatten_run(result)
        _write_csv(seed_metrics_path, run_rows, long_headers)
        record = {
            "seed": seed,
            "completed": True,
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            "resume_signature": signature,
            "run_dir": str(run_dir.resolve()),
            "run_dir_benchmark_relative": _benchmark_relative(run_dir, output_dir),
            "log_path": str(log_path.resolve()) if capture_logs else None,
            "log_path_benchmark_relative": (
                _benchmark_relative(log_path, output_dir)
                if capture_logs
                else None
            ),
            "metrics_path": str(seed_metrics_path.resolve()),
            "metrics_path_benchmark_relative": _benchmark_relative(seed_metrics_path, output_dir),
            "thresholds": result.get("thresholds", {}),
            "validation_f1": result.get("validation_f1", {}),
            "data_summary": result.get("data_summary", {}),
            "split_summary": result.get("split_summary", {}),
            "artifacts": result.get("artifacts", {}),
        }
        record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        run_records.append(record)
        all_long_rows.extend(run_rows)

    long_path = output_dir / "per_seed_metrics_long.csv"
    _write_csv(long_path, all_long_rows, long_headers)

    wide_path = output_dir / "per_seed_metrics_wide.csv"
    wide_headers = ["seed", "model", "setting", *MAIN_TABLE_METRICS]
    wide_rows = _wide_rows(all_long_rows)
    _write_csv(wide_path, wide_rows, wide_headers)

    aggregate = _aggregate_rows(all_long_rows)
    aggregate_path = output_dir / "aggregate_summary.csv"
    aggregate_headers = [
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
    ]
    _write_csv(aggregate_path, aggregate, aggregate_headers)

    tex_path = output_dir / "aggregate_selected_summary.tex"
    _write_selected_tex(tex_path, aggregate)

    comparison_rows = _paired_comparison_rows(all_long_rows)
    comparison_path = output_dir / "paired_comparisons.csv"
    comparison_headers = [
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
    ]
    _write_csv(comparison_path, comparison_rows, comparison_headers)

    comparison_tex_path = output_dir / "paired_comparisons.tex"
    _write_paired_comparisons_tex(comparison_tex_path, comparison_rows)
    integrity_paths = [
        long_path,
        wide_path,
        aggregate_path,
        tex_path,
        comparison_path,
        comparison_tex_path,
    ]
    for run in run_records:
        log_path_value = run.get("log_path")
        if log_path_value:
            integrity_paths.append(Path(str(log_path_value)))
        metrics_path_value = run.get("metrics_path")
        if metrics_path_value:
            integrity_paths.append(Path(str(metrics_path_value)))
        record_path = runs_dir / f"seed_{run['seed']}" / "run_record.json"
        if record_path.exists():
            integrity_paths.append(record_path)

    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "config": config,
        "resume": {
            "enabled": bool(resume),
            "force_rerun": bool(force_rerun),
            "resumed_seeds": resumed_seeds,
            "executed_seeds": executed_seeds,
            "signature": signature,
        },
        "invocation": _invocation_manifest(project_root),
        "environment": _environment_manifest(project_root),
        "statistics": {
            "aggregate_ci": "mean +/- Student-t 95% confidence interval across seeds",
            "paired_ci": "nonparametric bootstrap 95% confidence interval over paired seed differences",
            "paired_p_value": "two-sided paired sign-flip test; exact for n<=16, Monte Carlo otherwise",
            "paired_effect_size": "paired Cohen's dz = mean paired improvement divided by its sample standard deviation",
            "multiple_comparison_correction": (
                "Holm family-wise error correction and Benjamini-Hochberg FDR correction "
                "computed across all rows in paired_comparisons.csv"
            ),
            "positive_improvement": (
                "CAT-AD better than baseline; Proposed-Baseline for higher-is-better metrics, "
                "Baseline-Proposed for lower-is-better metrics"
            ),
            "primary_claims": primary_claim_manifest(),
        },
        "provenance": provenance,
        "runs": run_records,
        "artifact_integrity": _artifact_integrity(integrity_paths, project_root, output_dir),
        "artifacts": {
            "per_seed_long_csv": str(long_path.resolve()),
            "per_seed_wide_csv": str(wide_path.resolve()),
            "aggregate_csv": str(aggregate_path.resolve()),
            "aggregate_tex": str(tex_path.resolve()),
            "paired_comparisons_csv": str(comparison_path.resolve()),
            "paired_comparisons_tex": str(comparison_tex_path.resolve()),
        },
    }
    manifest_path = output_dir / "benchmark_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nSaved multi-seed benchmark manifest: {_display_path(manifest_path, project_root)}")
    return manifest_path


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a multi-seed ADS-B publication benchmark.")
    parser.add_argument("--seeds", default=f"{SEED},{SEED + 1},{SEED + 2}")
    parser.add_argument("--csv", default="sample_adsb_decoded.csv")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--num-aircraft", type=int, default=None)
    parser.add_argument("--window-size", type=int, default=WINDOW_SIZE)
    parser.add_argument("--max-epochs", type=int, default=None)
    parser.add_argument("--save-models", action="store_true")
    parser.add_argument("--include-ablation", action="store_true")
    parser.add_argument("--nondeterministic", action="store_true")
    parser.add_argument("--stream-logs", action="store_true")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--force-rerun", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    run_multi_seed_benchmark(
        seeds=parse_seed_list(args.seeds),
        csv_path=args.csv,
        output_dir=args.output_dir,
        num_aircraft=args.num_aircraft,
        window_size=args.window_size,
        max_epochs=args.max_epochs,
        save_models=args.save_models,
        run_ablation=args.include_ablation,
        deterministic=not args.nondeterministic,
        capture_logs=not args.stream_logs,
        resume=not args.no_resume,
        force_rerun=args.force_rerun,
    )


if __name__ == "__main__":
    main()


__all__ = ["parse_seed_list", "run_multi_seed_benchmark"]

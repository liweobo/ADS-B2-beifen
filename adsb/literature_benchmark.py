"""Same-condition benchmark for concrete published ADS-B anomaly models."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import torch

from adsb.benchmark import parse_seed_list
from adsb.data import filter_data, load_data
from adsb.dataloading import prepare_train_val_test_loaders
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.literature_models import LITERATURE_MODEL_SPECS, build_literature_model
from adsb.literature_training import train_literature_detector
from adsb.train_constants import (
    EPOCHS,
    EVAL_ATTACK_EPS,
    PGD_ALPHA,
    PGD_STEPS,
    PHYS_PENALTY_FINAL_PROJECTION,
    PHYS_PENALTY_LAMBDA_GAMMA,
    PHYS_PENALTY_LAMBDA_MAX,
    PHYS_PENALTY_PROJECTION_START_RATIO,
    PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
    PHYS_PENALTY_USE_SOFT_PROJECTION,
    PHYS_PENALTY_W_ALTITUDE,
    PHYS_PENALTY_W_HEADING,
    PHYS_PENALTY_W_LATLON,
    PHYS_PENALTY_W_SPEED,
    WINDOW_SIZE,
)
from adsb.training import evaluate, pick_best_threshold
from adsb.utils import set_seed


SETTINGS: tuple[tuple[str, str | None], ...] = (
    ("Clean", None),
    ("Standard PGD", "pgd"),
    ("Projection-based phys-PGD", "phys"),
    ("Penalty-based phys-PGD", "phys_penalty"),
)

SELECTED_COLUMNS: tuple[tuple[str, str, str, bool], ...] = (
    ("Clean", "f1", r"Unpert. F1-score $\uparrow$", True),
    ("Clean", "far", r"Unpert. FAR $\downarrow$", False),
    ("Standard PGD", "asr", r"Norm-PGD ASR $\downarrow$", False),
    (
        "Projection-based phys-PGD",
        "conditional_pv_asr_start_valid",
        r"Proj. PV-ASR$\mid V_0$ $\downarrow$",
        False,
    ),
    (
        "Penalty-based phys-PGD",
        "conditional_pv_asr_start_valid",
        r"Penalty PV-ASR$\mid V_0$ $\downarrow$",
        False,
    ),
)

REFERENCE_NAME_MAP = {"Baseline": "BiLSTM-ERM", "Proposed": "CAT-AD"}
PUBLICATION_WINDOW = {
    "start": "2019-07-15",
    "end": "2026-07-15",
    "basis": "rolling seven-year window anchored to the manuscript revision date",
}
LITERATURE_INCLUSION_CRITERIA = [
    "peer-reviewed ADS-B message- or trajectory-level anomaly detector published within the window",
    "defining architecture and training objective are sufficiently specified for protocol alignment",
    "accepts decoded trajectory variables available in the archived benchmark without additional sensors",
    "represents a distinct recent anomaly-detection design; the set is representative, not exhaustive",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _portable_path(path: Path, root: Path) -> str:
    """Return a non-identifying path suitable for archived metadata."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return f"external/{path.name}"


def _write_csv(path: Path, rows: list[dict[str, Any]], headers: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _stable_model_seed(seed: int, key: str) -> int:
    digest = hashlib.sha256(f"{seed}:{key}".encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "little") % (2**31 - 1)


def _config_fingerprint(root: Path, *, dataset_sha256: str, epochs: int, model_keys: list[str]) -> str:
    digest = hashlib.sha256()
    digest.update(dataset_sha256.encode("ascii"))
    digest.update(str(int(epochs)).encode("ascii"))
    digest.update(",".join(model_keys).encode("utf-8"))
    for relative in (
        "adsb/literature_models.py",
        "adsb/literature_training.py",
        "adsb/literature_benchmark.py",
        "adsb/dataloading.py",
        "adsb/anomalies.py",
        "adsb/attacks.py",
        "adsb/training.py",
        "adsb/train_constants.py",
    ):
        path = root / relative
        digest.update(relative.encode("utf-8"))
        digest.update(_sha256(path).encode("ascii"))
    return digest.hexdigest()


def _assert_matching_reference_split(reference_dir: Path, seed: int, split_summary: dict[str, Any]) -> None:
    record_path = reference_dir / "runs" / f"seed_{seed}" / "run_record.json"
    if not record_path.exists():
        raise FileNotFoundError(f"Missing CAT-AD reference run record: {record_path}")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    expected = record["split_summary"]
    for split in ("train", "validation", "test"):
        current_hash = split_summary["aircraft"][split]["sha256"]
        reference_hash = expected["aircraft"][split]["sha256"]
        if current_hash != reference_hash:
            raise RuntimeError(
                f"Seed {seed} {split} aircraft split does not match the reference benchmark: "
                f"{current_hash} != {reference_hash}"
            )
    if split_summary["windows"] != expected["windows"]:
        raise RuntimeError(f"Seed {seed} window/label counts do not match the reference benchmark.")


def _evaluate_detector(model, loader, *, threshold: float, mode: str | None, device, mean, std):
    return evaluate(
        model,
        loader,
        device=device,
        threshold=threshold,
        mode=mode,
        m=mean if mode is not None else None,
        s=std if mode is not None else None,
        adv_eps=EVAL_ATTACK_EPS,
        pgd_alpha=PGD_ALPHA,
        pgd_steps=PGD_STEPS,
        phys_penalty_lambda_max=PHYS_PENALTY_LAMBDA_MAX,
        phys_penalty_lambda_gamma=PHYS_PENALTY_LAMBDA_GAMMA,
        phys_penalty_use_lambda_schedule=PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
        phys_penalty_w_speed=PHYS_PENALTY_W_SPEED,
        phys_penalty_w_altitude=PHYS_PENALTY_W_ALTITUDE,
        phys_penalty_w_latlon=PHYS_PENALTY_W_LATLON,
        phys_penalty_w_heading=PHYS_PENALTY_W_HEADING,
        phys_penalty_use_soft_projection=PHYS_PENALTY_USE_SOFT_PROJECTION,
        phys_penalty_projection_start_ratio=PHYS_PENALTY_PROJECTION_START_RATIO,
        phys_penalty_final_projection=PHYS_PENALTY_FINAL_PROJECTION,
        physical_m=mean,
        physical_s=std,
    )


def _flatten_metrics(seed: int, model_name: str, by_setting: dict[str, dict[str, float]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for setting, metrics in by_setting.items():
        for metric, value in metrics.items():
            if isinstance(value, (int, float, np.integer, np.floating)) and math.isfinite(float(value)):
                rows.append(
                    {
                        "seed": int(seed),
                        "model": model_name,
                        "setting": setting,
                        "metric": metric,
                        "value": float(value),
                    }
                )
    return rows


def _run_seed(
    *,
    seed: int,
    filtered_df,
    dataset_record_path: str,
    output_dir: Path,
    reference_dir: Path,
    model_keys: list[str],
    epochs: int,
    device: torch.device,
    config_fingerprint: str,
    force: bool,
) -> dict[str, Any]:
    run_dir = output_dir / "runs" / f"seed_{seed}"
    record_path = run_dir / "run_record.json"
    if record_path.exists() and not force:
        cached = json.loads(record_path.read_text(encoding="utf-8"))
        if cached.get("completed") and cached.get("config_fingerprint") == config_fingerprint:
            print(f"Reusing completed literature baseline seed {seed}: {record_path}")
            return cached

    set_seed(seed)
    pack = prepare_train_val_test_loaders(
        filtered_df,
        pin_memory=device.type == "cuda",
        random_state=seed,
        window_size=WINDOW_SIZE,
    )
    _assert_matching_reference_split(reference_dir, seed, pack.split_summary)
    mean, std = pack.norm_mean, pack.norm_std
    run_dir.mkdir(parents=True, exist_ok=True)
    metric_rows: list[dict[str, Any]] = []
    model_records: dict[str, Any] = {}

    spec_by_key = {spec.key: spec for spec in LITERATURE_MODEL_SPECS}
    for key in model_keys:
        spec = spec_by_key[key]
        model_seed = _stable_model_seed(seed, key)
        set_seed(model_seed)
        print(f"\n=== Seed {seed} | {spec.display_name} | model_seed={model_seed} ===")
        model = build_literature_model(
            key,
            sequence_length=WINDOW_SIZE,
            norm_mean=mean,
            norm_std=std,
            device=device,
        )
        model, training_metadata = train_literature_detector(
            model,
            pack.train_loader_clean,
            pack.val_loader_clean,
            device=device,
            epochs=epochs,
        )
        threshold, val_f1 = pick_best_threshold(model, pack.val_loader, device=device)
        setting_metrics: dict[str, dict[str, float]] = {}
        for setting, attack_mode in SETTINGS:
            print(f"Evaluating {spec.display_name}: {setting}")
            setting_metrics[setting] = _evaluate_detector(
                model,
                pack.test_loader,
                threshold=threshold,
                mode=attack_mode,
                device=device,
                mean=mean,
                std=std,
            )
        metric_rows.extend(_flatten_metrics(seed, spec.display_name, setting_metrics))
        model_dir = run_dir / key
        model_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_path = model_dir / "checkpoint.pt"
        torch.save(
            {
                "model_key": key,
                "model_seed": model_seed,
                "state_dict": model.state_dict(),
                "threshold": float(threshold),
                "validation_f1": float(val_f1),
                "normalization_mean": mean,
                "normalization_std": std,
                "window_size": WINDOW_SIZE,
            },
            checkpoint_path,
        )
        model_records[key] = {
            "display_name": spec.display_name,
            "citation_key": spec.citation_key,
            "doi": spec.doi,
            "implementation_basis": spec.implementation_basis,
            "model_seed": model_seed,
            "threshold": float(threshold),
            "validation_f1": float(val_f1),
            "training": training_metadata,
            "checkpoint": str(checkpoint_path.relative_to(output_dir)).replace("\\", "/"),
            "metrics": setting_metrics,
        }
        _write_json(model_dir / "metrics.json", model_records[key])
        del model
        if device.type == "cuda":
            torch.cuda.empty_cache()

    metrics_path = run_dir / "per_seed_metrics_long.csv"
    _write_csv(metrics_path, metric_rows, ["seed", "model", "setting", "metric", "value"])
    record = {
        "completed": True,
        "completed_at_utc": _utc_now(),
        "seed": int(seed),
        "dataset": dataset_record_path,
        "config_fingerprint": config_fingerprint,
        "split_summary": pack.split_summary,
        "models": model_records,
        "metrics": metric_rows,
        "metrics_path": str(metrics_path.relative_to(output_dir)).replace("\\", "/"),
    }
    _write_json(record_path, record)
    return record


def _read_reference_rows(reference_dir: Path, seeds: set[int]) -> list[dict[str, Any]]:
    path = reference_dir / "per_seed_metrics_long.csv"
    rows: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for raw in csv.DictReader(handle):
            seed = int(raw["seed"])
            if seed not in seeds or raw["model"] not in REFERENCE_NAME_MAP:
                continue
            rows.append(
                {
                    "seed": seed,
                    "model": REFERENCE_NAME_MAP[raw["model"]],
                    "setting": raw["setting"],
                    "metric": raw["metric"],
                    "value": float(raw["value"]),
                }
            )
    return rows


def _ci_multiplier(n: int) -> float:
    # Two-sided 95% Student-t critical values, sufficient for the seed counts
    # accepted by this benchmark; use the asymptotic value thereafter.
    table = {
        2: 12.706,
        3: 4.303,
        4: 3.182,
        5: 2.776,
        6: 2.571,
        7: 2.447,
        8: 2.365,
        9: 2.306,
        10: 2.262,
    }
    return table.get(n, 1.96 if n > 30 else 2.0)


def _aggregate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[float]] = {}
    for row in rows:
        groups.setdefault((row["model"], row["setting"], row["metric"]), []).append(float(row["value"]))
    output: list[dict[str, Any]] = []
    for (model, setting, metric), values in sorted(groups.items()):
        array = np.asarray(values, dtype=np.float64)
        n = int(array.size)
        mean = float(array.mean())
        std = float(array.std(ddof=1)) if n > 1 else 0.0
        half = _ci_multiplier(n) * std / math.sqrt(n) if n > 1 else 0.0
        output.append(
            {
                "model": model,
                "setting": setting,
                "metric": metric,
                "n": n,
                "mean": mean,
                "std": std,
                "ci95_low": mean - half,
                "ci95_high": mean + half,
                "ci95_half_width": half,
            }
        )
    return output


def _paired_vs_catad(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values = {
        (int(row["seed"]), row["model"], row["setting"], row["metric"]): float(row["value"])
        for row in rows
    }
    baselines = sorted({row["model"] for row in rows if row["model"] != "CAT-AD"})
    seeds = sorted({int(row["seed"]) for row in rows})
    output: list[dict[str, Any]] = []
    for baseline in baselines:
        for setting, metric, _label, higher_better in SELECTED_COLUMNS:
            deltas: list[float] = []
            for seed in seeds:
                cat_key = (seed, "CAT-AD", setting, metric)
                base_key = (seed, baseline, setting, metric)
                if cat_key not in values or base_key not in values:
                    continue
                delta = values[cat_key] - values[base_key]
                deltas.append(delta if higher_better else -delta)
            if not deltas:
                continue
            array = np.asarray(deltas, dtype=np.float64)
            output.append(
                {
                    "baseline": baseline,
                    "setting": setting,
                    "metric": metric,
                    "direction": "positive means CAT-AD better",
                    "n": int(array.size),
                    "mean_improvement": float(array.mean()),
                    "wins": int((array > 0).sum()),
                    "ties": int((array == 0).sum()),
                    "losses": int((array < 0).sum()),
                }
            )
    return output


def _tex_model_name(model: str) -> str:
    mapping = {
        "BiLSTM-ERM": r"BiLSTM-ERM",
        "Standard BiLSTM": r"BiLSTM-ERM",
        "Fried--Last Differenced LSTM-AE": r"Fried--Last Differenced LSTM-AE~\cite{fried2021autoencoders}",
        "Fried--Last diff. LSTM-AE": r"Fried--Last Differenced LSTM-AE~\cite{fried2021autoencoders}",
        "VAE--SVDD": r"VAE--SVDD~\cite{luo2021vaesvdd}",
        "Contextual AE": r"Contextual AE~\cite{chevrot2022cae}",
        "CAT-AD": r"CAT-AD",
    }
    return mapping[model]


def _write_selected_tex(path: Path, aggregate: list[dict[str, Any]]) -> None:
    model_aliases = {
        "Standard BiLSTM": "BiLSTM-ERM",
        "Fried--Last diff. LSTM-AE": "Fried--Last Differenced LSTM-AE",
    }
    normalized: list[dict[str, Any]] = []
    for row in aggregate:
        item = dict(row)
        item["model"] = model_aliases.get(str(item["model"]), str(item["model"]))
        normalized.append(item)
    index = {(row["model"], row["setting"], row["metric"]): row for row in normalized}
    preferred_order = [
        "BiLSTM-ERM",
        "Fried--Last Differenced LSTM-AE",
        "VAE--SVDD",
        "Contextual AE",
        "CAT-AD",
    ]
    available_models = {row["model"] for row in normalized}
    order = [model for model in preferred_order if model in available_models]
    seed_count = max(int(row["n"]) for row in aggregate)
    best: dict[tuple[str, str], float] = {}
    for setting, metric, _label, higher_better in SELECTED_COLUMNS:
        candidates = [
            index[(model, setting, metric)]["mean"]
            for model in order
            if (model, setting, metric) in index
        ]
        best[(setting, metric)] = max(candidates) if higher_better else min(candidates)

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        rf"\caption{{Exploratory cross-family attack diagnostic over {seed_count} aircraft-level split{'s' if seed_count != 1 else ''}; these attack columns are excluded from the manuscript's robustness claims. Entries are mean $\pm$ 95\% confidence-interval half-width.}}",
        r"\label{tab:literature_baselines}",
        r"\small",
        r"\setlength{\tabcolsep}{4.2pt}",
        r"\begin{tabular}{lccccc}",
        r"\toprule",
        "Model & " + " & ".join(column[2] for column in SELECTED_COLUMNS) + r" \\",
        r"\midrule",
    ]
    for model in order:
        cells = [_tex_model_name(model)]
        for setting, metric, _label, _higher_better in SELECTED_COLUMNS:
            if (model, setting, metric) not in index:
                cells.append("--")
                continue
            row = index[(model, setting, metric)]
            value = f"{row['mean']:.3f} $\\pm$ {row['ci95_half_width']:.3f}"
            if math.isclose(float(row["mean"]), best[(setting, metric)], rel_tol=0.0, abs_tol=5e-7):
                value = r"\textbf{" + value + "}"
            cells.append(value)
        lines.append(" & ".join(cells) + r" \\")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\begin{minipage}{0.98\textwidth}",
            r"\footnotesize Unpert. denotes unperturbed evaluation; Norm-PGD denotes norm-bounded PGD without physical constraints; Proj. and Pen. denote Projection-based and Penalty-based Phys-PGD. All methods use the same normalized 15-step windows, aircraft splits, mixed validation split for threshold selection, attacked test samples, perturbation budgets, and metric code. Published one-class models use the normal-only view of the shared training windows, whereas the supervised detectors use the corresponding injected/labeled view. Because the classifier-PGD optimizer did not pass cross-objective step-size validation, the attack columns are retained only as archived diagnostics and are not robustness evidence. PV-ASR$\mid V_0$ is conditioned on pre-attack-valid anomalous trajectories.",
            r"\end{minipage}",
            r"\end{table*}",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_literature_benchmark(
    *,
    csv_path: str | Path,
    seeds: Iterable[int],
    output_dir: str | Path,
    reference_dir: str | Path,
    model_keys: Iterable[str] | None = None,
    epochs: int = EPOCHS,
    force: bool = False,
) -> dict[str, Any]:
    root = Path.cwd().resolve()
    dataset_path = Path(csv_path).resolve()
    out = Path(output_dir).resolve()
    reference = Path(reference_dir).resolve()
    seed_list = [int(seed) for seed in seeds]
    if not seed_list or len(set(seed_list)) != len(seed_list):
        raise ValueError("Seeds must be a non-empty list of unique integers.")
    keys = list(model_keys or [spec.key for spec in LITERATURE_MODEL_SPECS])
    known = {spec.key for spec in LITERATURE_MODEL_SPECS}
    unknown = sorted(set(keys) - known)
    if unknown:
        raise ValueError(f"Unknown literature model keys: {unknown}")
    dataset_sha = _sha256(dataset_path)

    reference_manifest_path = reference / "benchmark_manifest.json"
    reference_manifest = json.loads(reference_manifest_path.read_text(encoding="utf-8"))
    reference_sha = reference_manifest["provenance"]["data"]["sha256"]
    if dataset_sha != reference_sha:
        raise RuntimeError(
            f"Dataset SHA-256 differs from CAT-AD reference benchmark: {dataset_sha} != {reference_sha}"
        )

    fingerprint = _config_fingerprint(root, dataset_sha256=dataset_sha, epochs=epochs, model_keys=keys)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    filtered_df = filter_data(load_data(dataset_path))
    out.mkdir(parents=True, exist_ok=True)
    dataset_record_path = _portable_path(dataset_path, root)
    records: list[dict[str, Any]] = []
    for seed in seed_list:
        records.append(
            _run_seed(
                seed=seed,
                filtered_df=filtered_df,
                dataset_record_path=dataset_record_path,
                output_dir=out,
                reference_dir=reference,
                model_keys=keys,
                epochs=int(epochs),
                device=device,
                config_fingerprint=fingerprint,
                force=force,
            )
        )

    literature_rows = [row for record in records for row in record["metrics"]]
    reference_rows = _read_reference_rows(reference, set(seed_list))
    all_rows = reference_rows + literature_rows
    aggregate = _aggregate(all_rows)
    paired = _paired_vs_catad(all_rows)

    long_path = out / "per_seed_metrics_long.csv"
    aggregate_path = out / "aggregate_summary.csv"
    paired_path = out / "paired_vs_catad.csv"
    tex_path = out / "table_literature_baselines.tex"
    _write_csv(long_path, all_rows, ["seed", "model", "setting", "metric", "value"])
    _write_csv(
        aggregate_path,
        aggregate,
        ["model", "setting", "metric", "n", "mean", "std", "ci95_low", "ci95_high", "ci95_half_width"],
    )
    _write_csv(
        paired_path,
        paired,
        ["baseline", "setting", "metric", "direction", "n", "mean_improvement", "wins", "ties", "losses"],
    )
    _write_selected_tex(tex_path, aggregate)

    manifest = {
        "completed": True,
        "created_at_utc": _utc_now(),
        "objective": "same-condition reproduction comparison with concrete published ADS-B models",
        "config_fingerprint": fingerprint,
        "publication_window": PUBLICATION_WINDOW,
        "literature_inclusion_criteria": LITERATURE_INCLUSION_CRITERIA,
        "dataset": {
            "path": dataset_record_path,
            "sha256": dataset_sha,
            "reference_sha256_match": True,
        },
        "seeds": seed_list,
        "device": str(device),
        "environment": {
            "python": sys.version,
            "python_executable": sys.executable,
            "platform": platform.platform(),
            "torch": torch.__version__,
            "cuda_available": torch.cuda.is_available(),
        },
        "common_protocol": {
            "window_size": WINDOW_SIZE,
            "input_features": "12 normalized raw+differential ADS-B channels",
            "aircraft_level_splits": True,
            "clean_training_views": True,
            "threshold_selection": "same mixed validation split; maximum F1",
            "test_split": "same injected anomalous windows as CAT-AD reference runs",
            "eval_attack_eps": EVAL_ATTACK_EPS,
            "pgd_alpha": PGD_ALPHA,
            "pgd_steps": PGD_STEPS,
            "settings": [setting for setting, _ in SETTINGS],
            "metric_implementation": "adsb.training.evaluate",
        },
        "model_reimplementations": [spec.__dict__ for spec in LITERATURE_MODEL_SPECS if spec.key in keys],
        "reference_benchmark": {
            "path": _portable_path(reference, root),
            "manifest_sha256": _sha256(reference_manifest_path),
            "metrics_sha256": _sha256(reference / "per_seed_metrics_long.csv"),
            "models_imported": REFERENCE_NAME_MAP,
            "per_seed_split_hashes_verified": True,
        },
        "runs": [
            {
                "seed": record["seed"],
                "record": f"runs/seed_{record['seed']}/run_record.json",
            }
            for record in records
        ],
        "artifacts": {
            str(path.relative_to(out)).replace("\\", "/"): _sha256(path)
            for path in (long_path, aggregate_path, paired_path, tex_path)
        },
    }
    _write_json(out / "literature_benchmark_manifest.json", manifest)
    print(f"\nLiterature benchmark complete: {out}")
    print(f"Table: {tex_path}")
    return manifest


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default="sample_adsb_decoded.csv")
    parser.add_argument("--seeds", default="42,43,44,45,46")
    parser.add_argument("--output-dir", default="outputs/literature_benchmark")
    parser.add_argument("--reference-benchmark", default="outputs/publication_benchmark")
    parser.add_argument("--models", default=",".join(spec.key for spec in LITERATURE_MODEL_SPECS))
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    run_literature_benchmark(
        csv_path=args.csv,
        seeds=parse_seed_list(args.seeds),
        output_dir=args.output_dir,
        reference_dir=args.reference_benchmark,
        model_keys=[part.strip() for part in args.models.split(",") if part.strip()],
        epochs=args.epochs,
        force=args.force,
    )


if __name__ == "__main__":
    main()

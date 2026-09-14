"""Formal C0-01 P1 step-convergence audit.

The runner is intentionally resumable and result-direction independent.  It
trains only the two preregistered detectors and evaluates only the 160 P1
configurations.  P2--P6 functionality is not present in this module.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import os
import shutil
import sys
import tempfile
import traceback
from contextlib import redirect_stdout
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from adsb.anomalies import inject
from adsb.attack_audit import AttackConfig, run_attack
from adsb.checkpoints import (
    CheckpointIdentity,
    CheckpointIdentityError,
    checkpoint_manifest_path,
    code_fingerprint,
    load_verified_detector_checkpoint,
    normalization_hash,
    save_detector_checkpoint,
    sha256_file,
    sha256_json,
)
from adsb.data import filter_data, load_data, subset_df_by_aircraft
from adsb.dataloading import _build_split_raw_windows, prepare_train_val_test_loaders
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.model_factory import make_detector, train_common_kwargs
from adsb.paths import default_project_root
from adsb.train_constants import (
    ADV_CE_CLASS_WEIGHTS,
    ADV_PROJECT_PHYSICAL,
    ADV_TRAIN_EPS,
    ADV_TRAIN_LAMBDA,
    ADV_WARMUP_EPOCHS,
    BASELINE_CE_CLASS_WEIGHTS,
    INJECT_RATIO,
    PER_ATTACK_INJECT_RATIO,
    PGD_ALPHA,
    PGD_STEPS,
    PHYS_FEAT_LAMBDA,
    PHYS_OUT_LAMBDA,
    PHYS_PENALTY_FINAL_PROJECTION,
    PHYS_PENALTY_LAMBDA_GAMMA,
    PHYS_PENALTY_LAMBDA_MAX,
    PHYS_PENALTY_PROJECTION_START_RATIO,
    PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
    PHYS_PENALTY_USE_SOFT_PROJECTION,
    PHYS_TEMPERATURE,
    TRAIN_VAL_TEST_HOLDOUT_FRACTION,
    TRAIN_VAL_TEST_VAL_FRACTION,
    WINDOW_SIZE,
)
from adsb.training import pick_best_threshold, train_adv_with_val, train_with_val
from adsb.utils import set_seed

P1_SCHEMA = "adsb.c001-p1-results.v1"
SEEDS = (42, 43, 44, 45, 46)
MODELS = ("BiLSTM-ERM", "CAT-AD")
ATTACKS = ("norm_pgd", "phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd")
STEPS = (5, 10, 20, 50)
PHYSICAL_ATTACKS = {"phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temp = Path(name)
    try:
        temp.write_bytes(_canonical_bytes(value) + b"\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _atomic_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temp = Path(name)
    try:
        pd.DataFrame(rows).to_csv(temp, index=False)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _json_safe(value: Any) -> Any:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        value = float(value)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


class _Tee:
    def __init__(self, path: Path):
        self.file = path.open("a", encoding="utf-8", buffering=1)

    def write(self, value: str) -> int:
        sys.__stdout__.write(value)
        self.file.write(value)
        return len(value)

    def flush(self) -> None:
        sys.__stdout__.flush()
        self.file.flush()

    def close(self) -> None:
        self.file.close()


def _hash_array(digest: "hashlib._Hash", value: Any) -> None:
    array = np.ascontiguousarray(np.asarray(value))
    digest.update(str(array.shape).encode("ascii"))
    digest.update(str(array.dtype).encode("ascii"))
    digest.update(array.tobytes(order="C"))


def _sample_manifest_hash(metadata_by_split: dict[str, dict[str, np.ndarray]]) -> str:
    digest = hashlib.sha256()
    keys = (
        "sample_id",
        "aircraft_id",
        "segment_id",
        "window_start",
        "anomaly_bitmask",
        "seed",
        "split",
        "original_label",
    )
    for split in ("train", "validation", "test"):
        metadata = metadata_by_split[split]
        for index in range(len(metadata["sample_id"])):
            row = {key: _json_safe(metadata[key][index]) for key in keys}
            digest.update(_canonical_bytes(row))
            digest.update(b"\n")
    return digest.hexdigest()


def _dataset_hash(pack: Any) -> str:
    digest = hashlib.sha256()
    for name, loader in (
        ("train", pack.train_loader),
        ("validation", pack.val_loader),
        ("test", pack.test_loader),
    ):
        digest.update(name.encode("ascii"))
        _hash_array(digest, loader.dataset.X.numpy())
        _hash_array(digest, loader.dataset.y.numpy())
        metadata = pack.audit_metadata[name]
        _hash_array(digest, metadata["sample_id"].astype("U64"))
        _hash_array(digest, metadata["anomaly_bitmask"])
    return digest.hexdigest()


def _split_hash(pack: Any) -> str:
    payload = {
        "window_size": int(pack.window_size),
        "aircraft": pack.split_summary["aircraft"],
    }
    return sha256_json(payload)


def _injection_config(seed: int) -> dict[str, Any]:
    return {
        "schema": "adsb.injection-config.v1",
        "ratio": float(INJECT_RATIO),
        "per_attack_ratio": float(PER_ATTACK_INJECT_RATIO),
        "anomaly_types": ["d", "s", "p"],
        "malicious_label_min_points": 5,
        "seed_policy": {
            "train": int(seed + 101),
            "validation": int(seed + 202),
            "test": int(seed + 303),
        },
    }


def _metadata_distribution(metadata: dict[str, np.ndarray]) -> dict[int, int]:
    values, counts = np.unique(metadata["anomaly_bitmask"], return_counts=True)
    return {int(value): int(count) for value, count in zip(values, counts)}


def _aircraft_counts(metadata: dict[str, np.ndarray], labels: np.ndarray) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for aircraft in sorted(set(str(value) for value in metadata["aircraft_id"])):
        mask = metadata["aircraft_id"] == aircraft
        result[aircraft] = {
            "total_windows": int(mask.sum()),
            "anomaly_windows": int(np.asarray(labels)[mask].sum()),
        }
    return result


def _legacy_injection_version(df: pd.DataFrame, seed: int) -> dict[str, Any]:
    aircraft_ids = np.unique(df["icao"])
    trv, test = train_test_split(
        aircraft_ids, test_size=TRAIN_VAL_TEST_HOLDOUT_FRACTION, random_state=seed
    )
    train, validation = train_test_split(
        trv, test_size=TRAIN_VAL_TEST_VAL_FRACTION, random_state=seed
    )
    rng = np.random.RandomState(seed)
    output: dict[str, Any] = {}
    for split, ids in (("train", train), ("validation", validation), ("test", test)):
        raw, _prev, track_ids, starts = _build_split_raw_windows(df, ids, window_size=WINDOW_SIZE)
        _attacked, labels, metadata = inject(
            raw,
            ratio=INJECT_RATIO,
            anomaly_types=("d", "s", "p"),
            track_ids=track_ids,
            window_starts=starts,
            random_state=rng,
            return_metadata=True,
        )
        aircraft = np.asarray([str(value).rsplit("_", 1)[0] for value in track_ids])
        output[split] = {
            "total_windows": int(len(labels)),
            "anomaly_windows": int(labels.sum()),
            "anomaly_bitmask_distribution": {
                str(key): value for key, value in _metadata_distribution({"anomaly_bitmask": metadata["anomaly_bitmask"]}).items()
            },
            "per_aircraft": _aircraft_counts({"aircraft_id": aircraft}, labels),
        }
    return output


def build_data_version(
    df: pd.DataFrame,
    seed: int,
    *,
    pin_memory: bool,
    output_dir: Path,
    legacy_root: Path,
) -> tuple[Any, dict[str, Any], list[dict[str, Any]]]:
    pack = prepare_train_val_test_loaders(
        df, pin_memory=pin_memory, random_state=seed, window_size=WINDOW_SIZE
    )
    dataset_hash = _dataset_hash(pack)
    split_hash = _split_hash(pack)
    sample_hash = _sample_manifest_hash(pack.audit_metadata)
    injection = _injection_config(seed)
    norm_hash = normalization_hash(pack.norm_mean, pack.norm_std)
    new_splits: dict[str, Any] = {}
    for split, loader in (
        ("train", pack.train_loader),
        ("validation", pack.val_loader),
        ("test", pack.test_loader),
    ):
        labels = loader.dataset.y.numpy()
        metadata = pack.audit_metadata[split]
        new_splits[split] = {
            "total_windows": int(len(labels)),
            "anomaly_windows": int(labels.sum()),
            "window_fraction": float(len(labels) / sum(len(item.dataset.y) for item in (pack.train_loader, pack.val_loader, pack.test_loader))),
            "anomaly_bitmask_distribution": {
                str(key): value for key, value in _metadata_distribution(metadata).items()
            },
            "per_aircraft": _aircraft_counts(metadata, labels),
        }
    legacy = _legacy_injection_version(df, seed)
    archived_path = legacy_root / "runs" / f"seed_{seed}" / "run_record.json"
    archived = json.loads(archived_path.read_text(encoding="utf-8")) if archived_path.exists() else None
    archived_counts_match_regeneration = None
    if archived is not None:
        archived_windows = archived["split_summary"]["windows"]
        archived_counts_match_regeneration = all(
            int(archived_windows[key]["malicious_windows"]) == int(legacy[split]["anomaly_windows"])
            for split, key in (("train", "train"), ("validation", "validation"), ("test", "test_mixed_attack"))
        )
    manifest = {
        "schema_version": "adsb.c001-data-version.v1",
        "seed": int(seed),
        "created_at_utc": _now(),
        "dataset_hash": dataset_hash,
        "source_csv_sha256": sha256_file(default_project_root() / "sample_adsb_decoded.csv"),
        "injection_config": injection,
        "injection_config_hash": sha256_json(injection),
        "split_hash": split_hash,
        "normalization_hash": norm_hash,
        "sample_manifest_hash": sample_hash,
        "new_explicit_seed_version": new_splits,
        "legacy_regenerated_version": legacy,
        "archived_legacy_counts_match_regeneration": archived_counts_match_regeneration,
        "legacy_and_new_are_same_experiment_version": False,
    }
    _atomic_json(output_dir / "data" / f"seed_{seed}" / "data_version_manifest.json", manifest)
    comparison_rows: list[dict[str, Any]] = []
    for split in ("train", "validation", "test"):
        for metric in ("total_windows", "anomaly_windows"):
            old = int(legacy[split][metric])
            new = int(new_splits[split][metric])
            comparison_rows.append(
                {"seed": seed, "split": split, "scope": "split", "item": metric, "old": old, "new": new, "difference": new - old}
            )
        all_aircraft = sorted(set(legacy[split]["per_aircraft"]) | set(new_splits[split]["per_aircraft"]))
        for aircraft in all_aircraft:
            for metric in ("total_windows", "anomaly_windows"):
                old = int(legacy[split]["per_aircraft"].get(aircraft, {}).get(metric, 0))
                new = int(new_splits[split]["per_aircraft"].get(aircraft, {}).get(metric, 0))
                comparison_rows.append(
                    {"seed": seed, "split": split, "scope": f"aircraft:{aircraft}", "item": metric, "old": old, "new": new, "difference": new - old}
                )
        masks = sorted(
            set(legacy[split]["anomaly_bitmask_distribution"])
            | set(new_splits[split]["anomaly_bitmask_distribution"])
        )
        for bitmask in masks:
            old = int(legacy[split]["anomaly_bitmask_distribution"].get(bitmask, 0))
            new = int(new_splits[split]["anomaly_bitmask_distribution"].get(bitmask, 0))
            comparison_rows.append(
                {"seed": seed, "split": split, "scope": "anomaly_bitmask", "item": bitmask, "old": old, "new": new, "difference": new - old}
            )
    return pack, manifest, comparison_rows


def _training_config(model_name: str, seed: int) -> dict[str, Any]:
    config = {
        "schema_version": "adsb.c001-training-config.v1",
        "seed": int(seed),
        "model": model_name,
        "epochs": 30,
        "early_stop_patience": 6,
        "window_size": WINDOW_SIZE,
        "deterministic": True,
        "training_attack_id": None if model_name == "BiLSTM-ERM" else "phys_hybrid_pgd",
    }
    if model_name == "CAT-AD":
        config["attack_parameters"] = {
            "epsilon": ADV_TRAIN_EPS,
            "alpha": PGD_ALPHA,
            "steps": PGD_STEPS,
            "adv_lambda": ADV_TRAIN_LAMBDA,
            "warmup_epochs": ADV_WARMUP_EPOCHS,
            "lambda_phys_max": PHYS_PENALTY_LAMBDA_MAX,
            "lambda_phys_gamma": PHYS_PENALTY_LAMBDA_GAMMA,
            "use_lambda_schedule": PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
            "use_soft_projection": PHYS_PENALTY_USE_SOFT_PROJECTION,
            "projection_start_ratio": PHYS_PENALTY_PROJECTION_START_RATIO,
            "final_projection": PHYS_PENALTY_FINAL_PROJECTION,
            "phys_out_lambda": PHYS_OUT_LAMBDA,
            "phys_feat_lambda": PHYS_FEAT_LAMBDA,
            "phys_temperature": PHYS_TEMPERATURE,
        }
    return config


def _predict_logits(model: torch.nn.Module, tensor: torch.Tensor, device: torch.device, batch_size: int = 256) -> np.ndarray:
    rows: list[np.ndarray] = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(tensor), batch_size):
            batch = tensor[start : start + batch_size].to(device=device, dtype=torch.float32)
            rows.append(model(batch).float().cpu().numpy())
    return np.concatenate(rows, axis=0) if rows else np.empty((0, 2), dtype=np.float32)


def _metrics(labels: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict[str, Any]:
    labels = np.asarray(labels, dtype=np.int64)
    pred = (np.asarray(probabilities) >= float(threshold)).astype(np.int64)
    cm = confusion_matrix(labels, pred, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in cm.ravel())
    precision = float(precision_score(labels, pred, zero_division=0))
    recall = float(recall_score(labels, pred, zero_division=0))
    f1 = float(f1_score(labels, pred, zero_division=0))
    far = float(fp / (fp + tn)) if fp + tn else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "far": far,
        "threshold_asr": 1.0 - recall,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def _probabilities(logits: np.ndarray) -> np.ndarray:
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return (exp / exp.sum(axis=1, keepdims=True))[:, 1]


def train_or_load_model(
    *,
    seed: int,
    model_name: str,
    pack: Any,
    data_manifest: dict[str, Any],
    output_dir: Path,
    device: torch.device,
    project_root: Path,
    train_attack_manifest_hash: str,
) -> tuple[torch.nn.Module | None, float | None, dict[str, Any]]:
    slug = "bilstm_erm" if model_name == "BiLSTM-ERM" else "cat_ad"
    run_dir = output_dir / "training" / f"seed_{seed}" / slug
    run_dir.mkdir(parents=True, exist_ok=True)
    status_path = run_dir / "status.json"
    checkpoint_path = run_dir / "checkpoint.pt"
    config = _training_config(model_name, seed)
    identity = CheckpointIdentity(
        split_hash=data_manifest["split_hash"],
        dataset_hash=data_manifest["dataset_hash"],
        config_hash=sha256_json(config),
        code_fingerprint=code_fingerprint(project_root),
        train_attack_manifest_hash=train_attack_manifest_hash,
    )
    if status_path.exists() and checkpoint_path.exists():
        status = json.loads(status_path.read_text(encoding="utf-8"))
        if status.get("status") == "completed":
            try:
                model, threshold, _m, _s, _dim = load_verified_detector_checkpoint(
                    checkpoint_path,
                    device,
                    expected_identity=identity,
                    expected_norm_mean=pack.norm_mean,
                    expected_norm_std=pack.norm_std,
                )
                return model, threshold, status
            except CheckpointIdentityError as exc:
                invalidated = run_dir / "invalidated"
                invalidated.mkdir(exist_ok=True)
                prior_hash = status.get("checkpoint_sha256", "unknown")[:12]
                os.replace(checkpoint_path, invalidated / f"checkpoint_{prior_hash}.pt")
                sidecar = checkpoint_manifest_path(checkpoint_path)
                if sidecar.exists():
                    os.replace(sidecar, invalidated / f"checkpoint_{prior_hash}.pt.manifest.json")
                os.replace(status_path, invalidated / f"status_{prior_hash}.json")
                _atomic_json(
                    invalidated / f"invalidation_{prior_hash}.json",
                    {
                        "schema_version": "adsb.c001-checkpoint-invalidation.v1",
                        "invalidated_at_utc": _now(),
                        "reason": str(exc),
                        "new_expected_identity": asdict(identity),
                    },
                )
    tee = _Tee(run_dir / "training.log")
    status: dict[str, Any]
    try:
        with redirect_stdout(tee):
            print(f"P1 training start seed={seed} model={model_name} at {_now()}")
            model = make_detector(device)
            common = train_common_kwargs(device)
            if model_name == "BiLSTM-ERM":
                model = train_with_val(
                    model,
                    pack.train_loader,
                    pack.val_loader,
                    class_weights=BASELINE_CE_CLASS_WEIGHTS,
                    **common,
                )
            else:
                model = train_adv_with_val(
                    model,
                    pack.train_loader,
                    pack.val_loader,
                    pack.norm_mean,
                    pack.norm_std,
                    adv_eps=ADV_TRAIN_EPS,
                    adv_lambda=ADV_TRAIN_LAMBDA,
                    warmup_epochs=ADV_WARMUP_EPOCHS,
                    pgd_steps=PGD_STEPS,
                    pgd_alpha=PGD_ALPHA,
                    project_physical=ADV_PROJECT_PHYSICAL,
                    use_penalty_phys_pgd_train=True,
                    lambda_phys_max=PHYS_PENALTY_LAMBDA_MAX,
                    lambda_phys_gamma=PHYS_PENALTY_LAMBDA_GAMMA,
                    use_lambda_schedule=PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
                    use_soft_projection=PHYS_PENALTY_USE_SOFT_PROJECTION,
                    projection_start_ratio=PHYS_PENALTY_PROJECTION_START_RATIO,
                    final_projection=PHYS_PENALTY_FINAL_PROJECTION,
                    phys_out_lambda=PHYS_OUT_LAMBDA,
                    phys_feat_lambda=PHYS_FEAT_LAMBDA,
                    phys_temperature=PHYS_TEMPERATURE,
                    class_weights=ADV_CE_CLASS_WEIGHTS,
                    early_stop_metric="clean_f1",
                    **common,
                )
            threshold, validation_f1 = pick_best_threshold(model, pack.val_loader, device=device)
            before_logits = _predict_logits(model, pack.test_loader.dataset.X, device)
            save_detector_checkpoint(
                checkpoint_path,
                model,
                input_dim=12,
                threshold=threshold,
                norm_mean=pack.norm_mean,
                norm_std=pack.norm_std,
                identity=identity,
            )
            loaded, loaded_threshold, _m, _s, _dim = load_verified_detector_checkpoint(
                checkpoint_path,
                device,
                expected_identity=identity,
                expected_norm_mean=pack.norm_mean,
                expected_norm_std=pack.norm_std,
            )
            after_logits = _predict_logits(loaded, pack.test_loader.dataset.X, device)
            max_abs = float(np.max(np.abs(before_logits - after_logits)))
            logits_consistent = bool(np.allclose(before_logits, after_logits, atol=1e-6, rtol=1e-6))
            if not logits_consistent or float(loaded_threshold) != float(threshold):
                raise RuntimeError(f"checkpoint round-trip mismatch: logits max_abs={max_abs}")
            status = {
                "schema_version": "adsb.c001-retraining-run.v1",
                "status": "completed",
                "seed": seed,
                "model": model_name,
                "completed_at_utc": _now(),
                "checkpoint": str(checkpoint_path.relative_to(output_dir).as_posix()),
                "checkpoint_sha256": sha256_file(checkpoint_path),
                "checkpoint_manifest_sha256": sha256_file(checkpoint_manifest_path(checkpoint_path)),
                "identity": asdict(identity),
                "normalization_hash": normalization_hash(pack.norm_mean, pack.norm_std),
                "threshold": float(threshold),
                "validation_f1": float(validation_f1),
                "roundtrip_logits_consistent": logits_consistent,
                "roundtrip_logits_max_abs": max_abs,
                "train_config": config,
            }
            _atomic_json(status_path, status)
            return loaded, float(threshold), status
    except Exception as exc:
        status = {
            "schema_version": "adsb.c001-retraining-run.v1",
            "status": "failed",
            "seed": seed,
            "model": model_name,
            "failed_at_utc": _now(),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "identity": asdict(identity),
            "train_config": config,
        }
        _atomic_json(status_path, status)
        return None, None, status
    finally:
        tee.close()


def clean_reproduction(
    model: torch.nn.Module,
    threshold: float,
    *,
    seed: int,
    model_name: str,
    pack: Any,
    device: torch.device,
    identity_status: dict[str, Any],
    output_dir: Path,
) -> tuple[dict[str, Any], np.ndarray, np.ndarray]:
    labels = pack.test_loader.dataset.y.numpy().astype(np.int64)
    logits = _predict_logits(model, pack.test_loader.dataset.X, device)
    probs = _probabilities(logits)
    threshold_metrics = _metrics(labels, probs, threshold)
    argmax_pred = logits.argmax(axis=1)
    argmax_metrics = {
        "precision": float(precision_score(labels, argmax_pred, zero_division=0)),
        "recall": float(recall_score(labels, argmax_pred, zero_division=0)),
        "f1": float(f1_score(labels, argmax_pred, zero_division=0)),
    }
    anomaly_probs = probs[labels == 1]
    normal_probs = probs[labels == 0]
    row = {
        "seed": seed,
        "model": model_name,
        "threshold": float(threshold),
        **threshold_metrics,
        "argmax_precision": argmax_metrics["precision"],
        "argmax_recall": argmax_metrics["recall"],
        "argmax_f1": argmax_metrics["f1"],
        "anomaly_prob_mean": float(anomaly_probs.mean()),
        "anomaly_prob_median": float(np.median(anomaly_probs)),
        "normal_prob_mean": float(normal_probs.mean()),
        "normal_prob_median": float(np.median(normal_probs)),
        "checkpoint_identity_verified": True,
        "roundtrip_logits_consistent": bool(identity_status["roundtrip_logits_consistent"]),
        "reproduced": True,
    }
    metadata = pack.audit_metadata["test"]
    samples = pd.DataFrame(
        {
            "seed": seed,
            "model": model_name,
            "sample_id": metadata["sample_id"],
            "aircraft_id": metadata["aircraft_id"],
            "original_label": labels,
            "p_anomaly": probs,
            "threshold_prediction": (probs >= threshold).astype(np.int64),
            "argmax_prediction": argmax_pred,
        }
    )
    samples.to_csv(
        output_dir / "clean" / f"seed_{seed}_{'erm' if model_name == 'BiLSTM-ERM' else 'catad'}_samples.csv.gz",
        index=False,
        compression="gzip",
    )
    return row, logits, probs


def _attack_config(attack_id: str, steps: int, seed: int, projection: dict[str, Any]) -> AttackConfig:
    return AttackConfig(
        attack_id=attack_id,
        loss="targeted_ce",
        steps=steps,
        alpha=0.03,
        epsilon=0.1,
        initialization="clean",
        restarts=1,
        projection_schedule=(
            "strict_every_step"
            if attack_id == "phys_projection_pgd"
            else ("late_plus_final" if attack_id == "phys_hybrid_pgd" else "none")
        ),
        seed=seed,
        budget_abs_tol=float(projection["budget_abs_tol"]),
        kinematic_rel_tol=float(projection["kinematic_rel_tol"]),
        projection_residual_tol=float(projection["projection_residual_tol"]),
        maximum_alternating_projection_iterations=int(projection["alternating_projection_max_iterations"]),
        feasible_random_resampling_count=int(projection["feasible_random_max_resamples"]),
    )


def _candidate_or_nan(value: torch.Tensor | None, clean: torch.Tensor) -> np.ndarray:
    if value is None:
        return np.full(tuple(clean.shape), np.nan, dtype=np.float32)
    return value.detach().float().cpu().numpy()


def _predict_candidate(model: torch.nn.Module, candidate: torch.Tensor, device: torch.device) -> np.ndarray:
    return _probabilities(_predict_logits(model, candidate.detach().cpu(), device))


def run_attack_configuration(
    *,
    seed: int,
    model_name: str,
    model: torch.nn.Module,
    threshold: float,
    pack: Any,
    clean_probs: np.ndarray,
    attack_id: str,
    steps: int,
    projection: dict[str, Any],
    audit_manifest: dict[str, Any],
    checkpoint_status: dict[str, Any],
    output_dir: Path,
    device: torch.device,
) -> dict[str, Any]:
    slug = "erm" if model_name == "BiLSTM-ERM" else "catad"
    config = _attack_config(attack_id, steps, seed, projection)
    task_payload = {
        "attack_config_hash": config.config_hash,
        "p1_audit_manifest_hash": audit_manifest["config_hash"],
        "evaluation_batch_size": int(audit_manifest["matrix"]["evaluation_batch_size"]),
        "checkpoint_sha256": checkpoint_status["checkpoint_sha256"],
        "split_hash": checkpoint_status["identity"]["split_hash"],
        "threshold": float(threshold),
    }
    task_hash = hashlib.sha256(_canonical_bytes(task_payload)).hexdigest()
    task_dir = output_dir / "attack_runs" / f"seed_{seed}" / slug / attack_id / f"k{steps}"
    task_dir.mkdir(parents=True, exist_ok=True)
    summary_path = task_dir / "summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if summary.get("status") in {"completed", "failed"} and summary.get("task_hash") == task_hash:
            return summary

    metadata = pack.audit_metadata["test"]
    labels = pack.test_loader.dataset.y.numpy().astype(np.int64)
    X = pack.test_loader.dataset.X
    malicious_indices = np.flatnonzero(labels == 1)
    clean_mal_probs = clean_probs[malicious_indices]
    clean_mal_pred = clean_mal_probs >= threshold
    batch_size = int(audit_manifest["matrix"]["evaluation_batch_size"])
    if batch_size < 1:
        raise ValueError("matrix.evaluation_batch_size must be a positive integer")
    candidate_names = (
        "final_iterate",
        "best_target_loss_iterate",
        "first_threshold_success_iterate",
        "first_argmax_success_iterate",
        "best_feasible_successful_iterate",
        "best_feasible_iterate",
    )
    candidate_parts: dict[str, list[np.ndarray]] = {name: [] for name in candidate_names}
    final_main_probs_parts: list[np.ndarray] = []
    best_main_probs_parts: list[np.ndarray] = []
    final_raw_probs_parts: list[np.ndarray] = []
    best_raw_probs_parts: list[np.ndarray] = []
    final_feasible_parts: list[np.ndarray] = []
    best_feasible_parts: list[np.ndarray] = []
    source_valid_parts: list[np.ndarray] = []
    per_step_path = task_dir / "per_step.csv.gz"
    projection_path = task_dir / "projection_status.csv.gz"
    per_step_handle = gzip.open(per_step_path, "wt", encoding="utf-8", newline="")
    projection_handle = gzip.open(projection_path, "wt", encoding="utf-8", newline="")
    per_step_writer: csv.DictWriter | None = None
    projection_writer: csv.DictWriter | None = None
    determinism_probe_pass = True
    init_failures = 0
    try:
        for batch_start in range(0, len(malicious_indices), batch_size):
            indices = malicious_indices[batch_start : batch_start + batch_size]
            clean_batch_cpu = X[indices]
            clean_batch = clean_batch_cpu.to(device=device, dtype=torch.float32)
            label_batch = torch.ones(len(indices), dtype=torch.long, device=device)
            result = run_attack(
                model,
                clean_batch,
                label_batch,
                norm_mean=pack.norm_mean,
                norm_std=pack.norm_std,
                frozen_threshold=threshold,
                config=config,
            )
            init_failures += sum(not item.success for item in result.initialization_status)
            for name in candidate_names:
                candidate_parts[name].append(_candidate_or_nan(getattr(result, name), clean_batch))
            initial_diag = next(
                item for item in result.per_step_diagnostics if int(item["restart_id"]) == 0 and int(item["step"]) == 0
            )
            source_valid_parts.append(np.asarray(initial_diag["kinematic_valid"], dtype=bool))
            final_raw = result.final_iterate
            best_raw = result.best_target_loss_iterate
            if best_raw is None:
                best_raw = clean_batch.clone()
            final_raw_probs = _predict_candidate(model, final_raw, device)
            best_raw_probs = _predict_candidate(model, best_raw, device)
            final_raw_probs_parts.append(final_raw_probs)
            best_raw_probs_parts.append(best_raw_probs)
            if attack_id in PHYSICAL_ATTACKS:
                final_valid = result.final_feasible.detach().cpu().numpy().astype(bool)
                best_feasible_tensor = result.best_feasible_iterate
                if best_feasible_tensor is None:
                    best_feasible_tensor = torch.full_like(clean_batch, float("nan"))
                best_valid = np.isfinite(best_feasible_tensor.detach().cpu().numpy()).all(axis=(1, 2))
                final_main = final_raw.detach().clone()
                final_main[~torch.as_tensor(final_valid, device=device)] = clean_batch[~torch.as_tensor(final_valid, device=device)]
                best_main = best_feasible_tensor.detach().clone()
                best_valid_tensor = torch.as_tensor(best_valid, device=device)
                best_main[~best_valid_tensor] = clean_batch[~best_valid_tensor]
            else:
                final_valid = np.ones(len(indices), dtype=bool)
                best_valid = np.ones(len(indices), dtype=bool)
                final_main = final_raw
                best_main = best_raw
            final_feasible_parts.append(final_valid)
            best_feasible_parts.append(best_valid)
            final_main_probs_parts.append(_predict_candidate(model, final_main, device))
            best_main_probs_parts.append(_predict_candidate(model, best_main, device))

            clean_pred_batch = clean_mal_pred[batch_start : batch_start + len(indices)]
            for diag in result.per_step_diagnostics:
                array_keys = [key for key, value in diag.items() if isinstance(value, list)]
                for local_index, global_index in enumerate(indices):
                    row: dict[str, Any] = {
                        "seed": seed,
                        "model": model_name,
                        "attack": attack_id,
                        "steps": steps,
                        "task_hash": task_hash,
                        "attack_config_hash": config.config_hash,
                        "sample_id": str(metadata["sample_id"][global_index]),
                        "aircraft_id": str(metadata["aircraft_id"][global_index]),
                        "original_label": 1,
                    }
                    for key in array_keys:
                        row[key] = _json_safe(diag[key][local_index])
                    attacked_pred = float(diag["p_anomaly"][local_index]) >= threshold
                    row["clean_tp_to_attacked_fn"] = bool(clean_pred_batch[local_index] and not attacked_pred)
                    row["clean_fn_to_attacked_tp"] = bool((not clean_pred_batch[local_index]) and attacked_pred)
                    if per_step_writer is None:
                        per_step_writer = csv.DictWriter(per_step_handle, fieldnames=list(row.keys()))
                        per_step_writer.writeheader()
                    per_step_writer.writerow(row)
                    if attack_id in PHYSICAL_ATTACKS:
                        projection_row = {
                            key: row[key]
                            for key in row
                            if key
                            in {
                                "seed", "model", "attack", "steps", "task_hash", "sample_id", "aircraft_id",
                                "step", "budget_valid", "kinematic_valid", "budget_residual", "kinematic_residual",
                                "domain_residual", "projection_residual", "projection_iterations", "projection_converged",
                                "projection_reason", "projection_source_valid", "projection_independently_checked",
                                "feasible", "linf_raw6_normalized", "kinematic_latitude_rel_violation",
                                "kinematic_longitude_rel_violation", "kinematic_altitude_rel_violation",
                                "kinematic_speed_rel_violation", "kinematic_heading_rel_violation",
                            }
                        }
                        if projection_writer is None:
                            projection_writer = csv.DictWriter(projection_handle, fieldnames=list(projection_row.keys()))
                            projection_writer.writeheader()
                        projection_writer.writerow(projection_row)

            # Determinism probe: the first full batch is rerun under the same
            # task hash and must reproduce final and best candidates exactly.
            if batch_start == 0:
                replay = run_attack(
                    model,
                    clean_batch,
                    label_batch,
                    norm_mean=pack.norm_mean,
                    norm_std=pack.norm_std,
                    frozen_threshold=threshold,
                    config=config,
                )
                determinism_probe_pass = bool(
                    torch.equal(result.final_iterate, replay.final_iterate)
                    and (
                        result.best_target_loss_iterate is None
                        and replay.best_target_loss_iterate is None
                        or (
                            result.best_target_loss_iterate is not None
                            and replay.best_target_loss_iterate is not None
                            and torch.equal(result.best_target_loss_iterate, replay.best_target_loss_iterate)
                        )
                    )
                )
                if not determinism_probe_pass:
                    raise RuntimeError("determinism replay mismatch on first complete batch")
    finally:
        per_step_handle.close()
        projection_handle.close()

    arrays = {name: np.concatenate(parts, axis=0) for name, parts in candidate_parts.items()}
    arrays["sample_id"] = metadata["sample_id"][malicious_indices]
    candidate_path = task_dir / "candidate_iterates.npz"
    np.savez_compressed(candidate_path, **arrays)
    final_main_probs = np.concatenate(final_main_probs_parts)
    best_main_probs = np.concatenate(best_main_probs_parts)
    final_raw_probs = np.concatenate(final_raw_probs_parts)
    best_raw_probs = np.concatenate(best_raw_probs_parts)
    final_valid = np.concatenate(final_feasible_parts)
    best_valid = np.concatenate(best_feasible_parts)
    source_valid = np.concatenate(source_valid_parts)
    full_final_probs = clean_probs.copy()
    full_best_probs = clean_probs.copy()
    full_final_probs[malicious_indices] = final_main_probs
    full_best_probs[malicious_indices] = best_main_probs
    final_metrics = _metrics(labels, full_final_probs, threshold)
    best_metrics = _metrics(labels, full_best_probs, threshold)
    clean_metrics = _metrics(labels, clean_probs, threshold)
    final_pred_mal = final_main_probs >= threshold
    best_pred_mal = best_main_probs >= threshold
    clean_tp_to_final_fn = int((clean_mal_pred & ~final_pred_mal).sum())
    clean_fn_to_final_tp = int((~clean_mal_pred & final_pred_mal).sum())
    clean_tp_to_best_fn = int((clean_mal_pred & ~best_pred_mal).sum())
    clean_fn_to_best_tp = int((~clean_mal_pred & best_pred_mal).sum())
    sample_rows: list[dict[str, Any]] = []
    mal_lookup = {int(index): pos for pos, index in enumerate(malicious_indices)}
    for index in range(len(labels)):
        pos = mal_lookup.get(index)
        if pos is None:
            final_probability = best_probability = float(clean_probs[index])
            final_is_valid = best_is_valid = True
            attacked = False
        else:
            final_probability = float(final_main_probs[pos])
            best_probability = float(best_main_probs[pos])
            final_is_valid = bool(final_valid[pos])
            best_is_valid = bool(best_valid[pos])
            attacked = True
        clean_prediction = bool(clean_probs[index] >= threshold)
        final_prediction = bool(final_probability >= threshold)
        best_prediction = bool(best_probability >= threshold)
        sample_rows.append(
            {
                "seed": seed,
                "model": model_name,
                "attack": attack_id,
                "steps": steps,
                "task_hash": task_hash,
                "attack_config_hash": config.config_hash,
                "sample_id": str(metadata["sample_id"][index]),
                "aircraft_id": str(metadata["aircraft_id"][index]),
                "segment_id": str(metadata["segment_id"][index]),
                "window_start": int(metadata["window_start"][index]),
                "anomaly_bitmask": int(metadata["anomaly_bitmask"][index]),
                "original_label": int(labels[index]),
                "attacked": attacked,
                "clean_p_anomaly": float(clean_probs[index]),
                "final_p_anomaly": final_probability,
                "best_p_anomaly": best_probability,
                "raw_final_p_anomaly": None if pos is None else float(final_raw_probs[pos]),
                "raw_best_p_anomaly": None if pos is None else float(best_raw_probs[pos]),
                "clean_prediction": int(clean_prediction),
                "final_prediction": int(final_prediction),
                "best_prediction": int(best_prediction),
                "final_feasible": final_is_valid,
                "best_feasible": best_is_valid,
                "clean_tp_to_final_fn": bool(labels[index] == 1 and clean_prediction and not final_prediction),
                "clean_fn_to_final_tp": bool(labels[index] == 1 and not clean_prediction and final_prediction),
                "clean_tp_to_best_fn": bool(labels[index] == 1 and clean_prediction and not best_prediction),
                "clean_fn_to_best_tp": bool(labels[index] == 1 and not clean_prediction and best_prediction),
            }
        )
    pd.DataFrame(sample_rows).to_csv(
        task_dir / "per_sample.csv.gz", index=False, compression="gzip"
    )
    per_aircraft = []
    sample_frame = pd.DataFrame(sample_rows)
    for aircraft, group in sample_frame.groupby("aircraft_id", sort=True):
        metric = _metrics(
            group["original_label"].to_numpy(), group["best_p_anomaly"].to_numpy(), threshold
        )
        per_aircraft.append({"aircraft_id": aircraft, "n": len(group), **metric})
    overall_from_aircraft = {
        key: sum(int(row[key]) for row in per_aircraft)
        for key in ("tn", "fp", "fn", "tp")
    }
    aircraft_reproduction_pass = all(overall_from_aircraft[key] == int(best_metrics[key]) for key in overall_from_aircraft)
    normal_unchanged = bool(
        np.array_equal(full_final_probs[labels == 0], clean_probs[labels == 0])
        and np.array_equal(full_best_probs[labels == 0], clean_probs[labels == 0])
    )
    identity_checks = {
        "recall_plus_final_threshold_asr": abs(final_metrics["recall"] + final_metrics["threshold_asr"] - 1.0) <= 1e-12,
        "recall_plus_best_threshold_asr": abs(best_metrics["recall"] + best_metrics["threshold_asr"] - 1.0) <= 1e-12,
        "normal_samples_byte_unchanged": normal_unchanged,
        "final_far_equals_clean_far": final_metrics["far"] == clean_metrics["far"],
        "best_far_equals_clean_far": best_metrics["far"] == clean_metrics["far"],
        "attacked_normal_sample_count_zero": int(((labels == 0) & sample_frame["attacked"].to_numpy()).sum()) == 0,
        "per_aircraft_counts_reproduce_overall": aircraft_reproduction_pass,
        "determinism_probe_first_batch": determinism_probe_pass,
        "transition_final_recall_correspondence": int(final_metrics["tp"] - clean_metrics["tp"])
        == clean_fn_to_final_tp - clean_tp_to_final_fn,
        "transition_best_recall_correspondence": int(best_metrics["tp"] - clean_metrics["tp"])
        == clean_fn_to_best_tp - clean_tp_to_best_fn,
    }
    final_target_ce = float(np.mean(-np.log(np.clip(1.0 - final_main_probs, 1e-12, 1.0))))
    best_target_ce = float(np.mean(-np.log(np.clip(1.0 - best_main_probs, 1e-12, 1.0))))
    final_margin = float(np.mean(np.log(np.clip(1.0 - final_main_probs, 1e-12, 1.0)) - np.log(np.clip(final_main_probs, 1e-12, 1.0))))
    best_margin = float(np.mean(np.log(np.clip(1.0 - best_main_probs, 1e-12, 1.0)) - np.log(np.clip(best_main_probs, 1e-12, 1.0))))
    summary = {
        "schema_version": P1_SCHEMA,
        "status": "completed",
        "completed_at_utc": _now(),
        "seed": seed,
        "model": model_name,
        "attack": attack_id,
        "steps": steps,
        "task_hash": task_hash,
        "task_identity": task_payload,
        "p1_audit_manifest_hash": audit_manifest["config_hash"],
        "evaluation_batch_size": batch_size,
        "attack_config": asdict(config),
        "attack_config_hash": config.config_hash,
        "checkpoint_sha256": checkpoint_status["checkpoint_sha256"],
        "threshold": float(threshold),
        "support": {
            "total": int(len(labels)),
            "normal": int((labels == 0).sum()),
            "anomaly": int((labels == 1).sum()),
            "attacked_normal": 0,
            "initialization_failures": int(init_failures),
            "final_feasible": int(final_valid.sum()),
            "final_infeasible": int((~final_valid).sum()),
            "best_feasible": int(best_valid.sum()),
            "best_infeasible": int((~best_valid).sum()),
            "source_valid_v0": int(source_valid.sum()),
            "source_invalid": int((~source_valid).sum()),
        },
        "clean_metrics": clean_metrics,
        "final_metrics": final_metrics,
        "best_metrics": best_metrics,
        "final_target_ce": final_target_ce,
        "best_target_ce": best_target_ce,
        "final_margin_z_normal_minus_z_anomaly": final_margin,
        "best_margin_z_normal_minus_z_anomaly": best_margin,
        "transitions": {
            "final_clean_tp_to_attack_fn": clean_tp_to_final_fn,
            "final_clean_fn_to_attack_tp": clean_fn_to_final_tp,
            "best_clean_tp_to_attack_fn": clean_tp_to_best_fn,
            "best_clean_fn_to_attack_tp": clean_fn_to_best_tp,
        },
        "identity_checks": identity_checks,
        "identity_pass": all(identity_checks.values()),
        "artifacts": {
            "candidate_iterates": {"path": "candidate_iterates.npz", "sha256": sha256_file(candidate_path)},
            "per_sample": {"path": "per_sample.csv.gz", "sha256": sha256_file(task_dir / "per_sample.csv.gz")},
            "per_step": {"path": "per_step.csv.gz", "sha256": sha256_file(per_step_path)},
            "projection_status": {"path": "projection_status.csv.gz", "sha256": sha256_file(projection_path)},
        },
    }
    _atomic_json(summary_path, summary)
    return summary


def _write_failed_run(output_dir: Path, record: dict[str, Any]) -> None:
    path = output_dir / "p1_failed_runs.jsonl"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(_json_safe(record), sort_keys=True, ensure_ascii=False) + "\n")


def _concatenate_gzip_csv(inputs: list[Path], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(output, "wt", encoding="utf-8", newline="") as target:
        wrote_header = False
        for path in inputs:
            if not path.exists() or path.stat().st_size == 0:
                continue
            with gzip.open(path, "rt", encoding="utf-8", newline="") as source:
                header = source.readline()
                if not header:
                    continue
                if not wrote_header:
                    target.write(header)
                    wrote_header = True
                shutil.copyfileobj(source, target)


def _figure_seed_lines(
    frame: pd.DataFrame,
    *,
    y_columns: tuple[str, ...],
    title: str,
    ylabel: str,
    output_base: Path,
) -> None:
    fig, axes = plt.subplots(2, 2, figsize=(11, 8), sharex=True)
    for axis, attack in zip(axes.flat, ATTACKS):
        subset = frame[frame["attack"] == attack]
        for model, color in (("BiLSTM-ERM", "#1f77b4"), ("CAT-AD", "#d62728")):
            model_rows = subset[subset["model"] == model]
            for seed, seed_rows in model_rows.groupby("seed"):
                seed_rows = seed_rows.sort_values("steps")
                for index, column in enumerate(y_columns):
                    axis.plot(
                        seed_rows["steps"],
                        seed_rows[column],
                        color=color,
                        alpha=0.28,
                        linestyle="-" if index == 0 else "--",
                    )
            means = model_rows.groupby("steps", as_index=False)[list(y_columns)].mean()
            for index, column in enumerate(y_columns):
                axis.plot(
                    means["steps"], means[column], color=color, linewidth=2.2,
                    linestyle="-" if index == 0 else "--",
                    label=f"{model} {column}" if attack == ATTACKS[0] else None,
                )
        axis.set_title(attack)
        axis.grid(alpha=0.25)
        axis.set_xticks(STEPS)
    axes[1, 0].set_xlabel("PGD steps")
    axes[1, 1].set_xlabel("PGD steps")
    axes[0, 0].set_ylabel(ylabel)
    axes[1, 0].set_ylabel(ylabel)
    fig.suptitle(title)
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, fontsize=8)
    fig.tight_layout(rect=(0, 0.06, 1, 0.96))
    fig.savefig(output_base.with_suffix(".pdf"), bbox_inches="tight")
    fig.savefig(output_base.with_suffix(".svg"), bbox_inches="tight")
    plt.close(fig)


def generate_figures(step_frame: pd.DataFrame, per_step_frame: pd.DataFrame, figures_dir: Path) -> None:
    figures_dir.mkdir(parents=True, exist_ok=True)
    _figure_seed_lines(step_frame, y_columns=("best_target_ce",), title="Target CE versus steps", ylabel="Target CE", output_base=figures_dir / "target_ce_vs_steps")
    _figure_seed_lines(step_frame, y_columns=("best_margin",), title="Targeted margin versus steps", ylabel="z_normal - z_anomaly", output_base=figures_dir / "targeted_margin_vs_steps")
    _figure_seed_lines(step_frame, y_columns=("final_asr", "best_asr"), title="Final and best ASR versus steps", ylabel="ASR", output_base=figures_dir / "final_best_asr_vs_steps")
    _figure_seed_lines(step_frame, y_columns=("best_recall", "best_f1"), title="Recall and F1 versus steps", ylabel="Score", output_base=figures_dir / "recall_f1_vs_steps")
    _figure_seed_lines(step_frame, y_columns=("best_tp_to_fn_rate", "best_fn_to_tp_rate"), title="Clean prediction transitions versus steps", ylabel="Rate among anomalous windows", output_base=figures_dir / "clean_transitions_vs_steps")
    if not per_step_frame.empty:
        grouped = per_step_frame.groupby(["seed", "model", "attack", "steps"], as_index=False).agg(
            pre_projection_loss=("pre_projection_loss", "mean"),
            post_projection_loss=("post_projection_loss", "mean"),
            projection_convergence_rate=("projection_converged", "mean"),
            projection_failure_rate=("projection_converged", lambda x: 1.0 - float(np.mean(x))),
            linf_raw=("linf_raw6_normalized", "max"),
            linf_difference=("linf_difference6_normalized", "max"),
            linf_full=("linf_full12_normalized", "max"),
        )
        _figure_seed_lines(grouped, y_columns=("pre_projection_loss", "post_projection_loss"), title="Projection pre/post target loss", ylabel="Target loss", output_base=figures_dir / "projection_pre_post_loss")
        _figure_seed_lines(grouped, y_columns=("projection_convergence_rate", "projection_failure_rate"), title="Projection convergence and failure", ylabel="Rate", output_base=figures_dir / "projection_convergence_failure")
        _figure_seed_lines(grouped, y_columns=("linf_raw", "linf_difference", "linf_full"), title="Perturbation distances versus steps", ylabel="Normalized L-infinity", output_base=figures_dir / "perturbation_distances_vs_steps")


def finalize_outputs(
    output_dir: Path,
    *,
    p1_config: dict[str, Any],
    projection_config: dict[str, Any],
    data_manifests: list[dict[str, Any]],
    data_comparison: list[dict[str, Any]],
    retraining_rows: list[dict[str, Any]],
    clean_rows: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
) -> dict[str, Any]:
    _atomic_json(output_dir / "retraining_manifest.json", {"schema_version": P1_SCHEMA, "runs": retraining_rows})
    _atomic_csv(output_dir / "checkpoint_integrity.csv", [
        {
            "seed": row["seed"],
            "model": row["model"],
            "status": row["status"],
            "checkpoint_sha256": row.get("checkpoint_sha256"),
            "split_hash": row.get("identity", {}).get("split_hash"),
            "dataset_hash": row.get("identity", {}).get("dataset_hash"),
            "normalization_hash": row.get("normalization_hash"),
            "train_config_hash": row.get("identity", {}).get("config_hash"),
            "train_attack_manifest_hash": row.get("identity", {}).get("train_attack_manifest_hash"),
            "code_fingerprint": row.get("identity", {}).get("code_fingerprint"),
            "roundtrip_logits_consistent": row.get("roundtrip_logits_consistent", False),
        }
        for row in retraining_rows
    ])
    _atomic_csv(output_dir / "data_version_comparison.csv", data_comparison)
    _atomic_csv(output_dir / "clean_checkpoint_metrics.csv", clean_rows)
    successful = [row for row in summaries if row.get("status") == "completed"]
    long_rows: list[dict[str, Any]] = []
    transition_rows: list[dict[str, Any]] = []
    final_best_rows: list[dict[str, Any]] = []
    direction_rows: list[dict[str, Any]] = []
    for row in successful:
        anomaly_n = int(row["support"]["anomaly"])
        long_rows.append(
            {
                "seed": row["seed"], "model": row["model"], "attack": row["attack"], "steps": row["steps"],
                "final_asr": row["final_metrics"]["threshold_asr"], "best_asr": row["best_metrics"]["threshold_asr"],
                "best_recall": row["best_metrics"]["recall"], "best_f1": row["best_metrics"]["f1"],
                "final_recall": row["final_metrics"]["recall"], "final_f1": row["final_metrics"]["f1"],
                "final_target_ce": row["final_target_ce"], "best_target_ce": row["best_target_ce"],
                "final_margin": row["final_margin_z_normal_minus_z_anomaly"],
                "best_margin": row["best_margin_z_normal_minus_z_anomaly"],
                "best_tp_to_fn_rate": row["transitions"]["best_clean_tp_to_attack_fn"] / anomaly_n,
                "best_fn_to_tp_rate": row["transitions"]["best_clean_fn_to_attack_tp"] / anomaly_n,
                "identity_pass": row["identity_pass"], "task_hash": row["task_hash"],
            }
        )
        transition_rows.append(
            {
                "seed": row["seed"], "model": row["model"], "attack": row["attack"], "steps": row["steps"],
                "clean_tp_to_attack_fn": row["transitions"]["best_clean_tp_to_attack_fn"],
                "clean_fn_to_attack_tp": row["transitions"]["best_clean_fn_to_attack_tp"],
                "recall_change": row["best_metrics"]["recall"] - row["clean_metrics"]["recall"],
            }
        )
        final_best_rows.append(
            {
                "seed": row["seed"], "model": row["model"], "attack": row["attack"], "steps": row["steps"],
                "final_asr": row["final_metrics"]["threshold_asr"], "best_asr": row["best_metrics"]["threshold_asr"],
                "difference": row["best_metrics"]["threshold_asr"] - row["final_metrics"]["threshold_asr"],
            }
        )
        direction_rows.append(
            {
                "seed": row["seed"], "model": row["model"], "attack": row["attack"], "steps": row["steps"],
                "asr_change_from_clean": row["best_metrics"]["threshold_asr"] - row["clean_metrics"]["threshold_asr"],
                "recall_change_from_clean": row["best_metrics"]["recall"] - row["clean_metrics"]["recall"],
                "f1_change_from_clean": row["best_metrics"]["f1"] - row["clean_metrics"]["f1"],
            }
        )
    _atomic_csv(output_dir / "step_convergence_long.csv", long_rows)
    _atomic_csv(output_dir / "transition_matrices.csv", transition_rows)
    _atomic_csv(output_dir / "final_vs_best.csv", final_best_rows)
    _atomic_csv(output_dir / "per_seed_direction.csv", direction_rows)
    sample_inputs = sorted(output_dir.glob("attack_runs/seed_*/*/*/k*/per_sample.csv.gz"))
    step_inputs = sorted(output_dir.glob("attack_runs/seed_*/*/*/k*/per_step.csv.gz"))
    projection_inputs = sorted(output_dir.glob("attack_runs/seed_*/*/*/k*/projection_status.csv.gz"))
    _concatenate_gzip_csv(sample_inputs, output_dir / "per_sample_attack_records.csv.gz")
    _concatenate_gzip_csv(step_inputs, output_dir / "per_step_convergence.csv.gz")
    _concatenate_gzip_csv(projection_inputs, output_dir / "projection_status.csv.gz")
    long_frame = pd.DataFrame(long_rows)
    per_step_usecols = [
        "seed", "model", "attack", "steps", "pre_projection_loss", "post_projection_loss",
        "projection_converged", "linf_raw6_normalized", "linf_difference6_normalized", "linf_full12_normalized",
    ]
    per_step_chunks = []
    if (output_dir / "per_step_convergence.csv.gz").exists():
        for chunk in pd.read_csv(output_dir / "per_step_convergence.csv.gz", usecols=per_step_usecols, chunksize=250000):
            per_step_chunks.append(
                chunk.groupby(["seed", "model", "attack", "steps"], as_index=False).agg(
                    pre_projection_loss=("pre_projection_loss", "mean"),
                    post_projection_loss=("post_projection_loss", "mean"),
                    projection_converged=("projection_converged", "mean"),
                    linf_raw6_normalized=("linf_raw6_normalized", "max"),
                    linf_difference6_normalized=("linf_difference6_normalized", "max"),
                    linf_full12_normalized=("linf_full12_normalized", "max"),
                )
            )
    per_step_frame = pd.concat(per_step_chunks, ignore_index=True) if per_step_chunks else pd.DataFrame()
    if not per_step_frame.empty:
        per_step_frame = per_step_frame.groupby(["seed", "model", "attack", "steps"], as_index=False).mean(numeric_only=True)
        per_step_frame["projection_converged"] = per_step_frame["projection_converged"].astype(float)
    generate_figures(long_frame, per_step_frame, output_dir / "figures")

    checkpoint_gate = len(retraining_rows) == 10 and all(
        row.get("status") == "completed" and row.get("roundtrip_logits_consistent") for row in retraining_rows
    )
    data_gate = len(data_manifests) == 5 and all(
        manifest.get("dataset_hash") and manifest.get("split_hash") and manifest.get("normalization_hash")
        and manifest.get("sample_manifest_hash") and manifest.get("injection_config_hash")
        for manifest in data_manifests
    )
    expected = 160
    all_records_present = len(summaries) == expected
    all_completed_or_failed = all(row.get("status") in {"completed", "failed"} for row in summaries)
    identity_pass = all(row.get("status") == "failed" or row.get("identity_pass") for row in summaries)
    failed_count = sum(row.get("status") == "failed" for row in summaries)
    v0_consistent = True
    for seed in SEEDS:
        counts = {
            int(row["support"]["source_valid_v0"])
            for row in successful
            if int(row["seed"]) == seed
        }
        if len(counts) > 1:
            v0_consistent = False
    p1_integrity = bool(
        all_records_present and all_completed_or_failed and identity_pass and failed_count == 0 and v0_consistent
    )
    gate = {
        "schema_version": "adsb.c001-p1-integrity-gate.v1",
        "checkpoint_integrity_gate": "PASS" if checkpoint_gate else "FAIL",
        "data_identity_gate": "PASS" if data_gate else "FAIL",
        "p1_integrity_gate": "PASS" if p1_integrity else "FAIL",
        "expected_configurations": expected,
        "recorded_configurations": len(summaries),
        "completed_configurations": len(successful),
        "failed_configurations_retained": failed_count,
        "all_identity_checks_pass": identity_pass,
        "v0_denominator_consistent_within_seed": v0_consistent,
        "result_direction_used_for_scheduling": False,
    }
    _atomic_json(output_dir / "p1_integrity_gate.json", gate)
    verdict = "IMPLEMENTATION FAILURE"
    convergence_evidence: dict[str, Any] = {}
    if checkpoint_gate and data_gate and p1_integrity and not long_frame.empty:
        strongest = long_frame.groupby(["seed", "model", "steps"], as_index=False).agg(
            strongest_best_asr=("best_asr", "max"), median_target_ce=("best_target_ce", "median")
        )
        pivot_asr = strongest.pivot(index=["seed", "model"], columns="steps", values="strongest_best_asr")
        pivot_loss = strongest.pivot(index=["seed", "model"], columns="steps", values="median_target_ce")
        asr_increment = pivot_asr[50] - pivot_asr[20]
        loss_decrease = (pivot_loss[20] - pivot_loss[50]) / pivot_loss[20].abs().clip(lower=1e-12)
        asr_ok = bool((asr_increment < 0.01).all())
        loss_ok = bool((loss_decrease < 0.01).all())
        verdict = "CONVERGED BY 20" if asr_ok and loss_ok else "NOT CONVERGED"
        convergence_evidence = {
            "per_seed_model_strongest_asr_increment_k20_to_k50": {
                f"{seed}|{model}": float(value) for (seed, model), value in asr_increment.items()
            },
            "per_seed_model_relative_median_target_loss_decrease_k20_to_k50": {
                f"{seed}|{model}": float(value) for (seed, model), value in loss_decrease.items()
            },
            "asr_standard_met": asr_ok,
            "target_loss_standard_met": loss_ok,
        }
    verdict_payload = {
        "schema_version": "adsb.c001-p1-step-convergence-verdict.v1",
        "verdict": verdict,
        "attack_adequacy_final_pass_allowed": False,
        "evidence": convergence_evidence,
    }
    _atomic_json(output_dir / "p1_step_convergence_verdict.json", verdict_payload)
    manifest = {
        "schema_version": P1_SCHEMA,
        "created_at_utc": _now(),
        "p1_config": p1_config,
        "projection_config": projection_config,
        "data_versions": data_manifests,
        "checkpoint_gate": gate["checkpoint_integrity_gate"],
        "data_gate": gate["data_identity_gate"],
        "integrity_gate": gate["p1_integrity_gate"],
        "step_convergence_verdict": verdict,
        "p2_to_p6_executed": False,
    }
    _atomic_json(output_dir / "p1_manifest.json", manifest)
    report_lines = [
        "# C0-01 P1 Step-Convergence Audit",
        "",
        f"- Checkpoint Integrity Gate: **{gate['checkpoint_integrity_gate']}**",
        f"- Data Identity Gate: **{gate['data_identity_gate']}**",
        f"- P1 Integrity Gate: **{gate['p1_integrity_gate']}**",
        f"- Step-Convergence Verdict: **{verdict}**",
        "- Final Attack Adequacy PASS: **not permitted at P1**",
        "- P2--P6 executed: **no**",
        "",
        "## Configuration completeness",
        "",
        f"Recorded {len(summaries)}/{expected} configurations; failures retained: {failed_count}.",
        "",
        "## Interpretation boundary",
        "",
        "These results apply only to clean-start, single-restart targeted CE with epsilon=0.1 and alpha=0.03. "
        "They do not resolve step-size, restart, loss, transfer, or gradient-free adequacy.",
    ]
    (output_dir / "p1_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    artifact_rows = []
    for path in sorted((item for item in output_dir.rglob("*") if item.is_file()), key=lambda p: p.as_posix()):
        if path.name == "artifact_hashes.json":
            continue
        artifact_rows.append(
            {"path": path.relative_to(output_dir).as_posix(), "size_bytes": path.stat().st_size, "sha256": sha256_file(path)}
        )
    _atomic_json(output_dir / "artifact_hashes.json", {"schema_version": P1_SCHEMA, "artifacts": artifact_rows})
    return {"gate": gate, "verdict": verdict_payload, "manifest": manifest}


def run_p1(
    *,
    csv_path: Path = Path("sample_adsb_decoded.csv"),
    output_dir: Path = Path("outputs/attack_audit_c001/p1"),
) -> dict[str, Any]:
    project_root = default_project_root()
    csv_path = (project_root / csv_path).resolve() if not csv_path.is_absolute() else csv_path.resolve()
    output_dir = (project_root / output_dir).resolve() if not output_dir.is_absolute() else output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "clean").mkdir(exist_ok=True)
    failed_path = output_dir / "p1_failed_runs.jsonl"
    failed_path.touch(exist_ok=True)
    config_root = project_root / "configs" / "attack_audit_c001"
    p1_config = json.loads((config_root / "p1_audit_manifest.json").read_text(encoding="utf-8"))
    projection_config = json.loads((config_root / "projection_config.json").read_text(encoding="utf-8"))
    for payload, name in ((p1_config, "p1_audit_manifest"), (projection_config, "projection_config")):
        expected_hash = payload.get("config_hash")
        actual_hash = hashlib.sha256(_canonical_bytes({key: value for key, value in payload.items() if key != "config_hash"})).hexdigest()
        if expected_hash != actual_hash:
            raise RuntimeError(f"{name} hash mismatch")
        def contains_null(value: Any) -> bool:
            if value is None:
                return True
            if isinstance(value, dict):
                return any(contains_null(item) for item in value.values())
            if isinstance(value, list):
                return any(contains_null(item) for item in value)
            return False
        if contains_null(payload):
            raise RuntimeError(f"{name} contains unresolved null fields")
    if p1_config["matrix"]["expected_configurations"] != 160:
        raise RuntimeError("P1 manifest must schedule exactly 160 configurations")
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    loaded = load_data(csv_path)
    filtered = filter_data(loaded)
    df = subset_df_by_aircraft(filtered, max_aircraft=None, random_state=42)
    train_attack_manifest_hash = sha256_file(config_root / "train_attack_manifest.json")
    data_manifests: list[dict[str, Any]] = []
    data_comparison: list[dict[str, Any]] = []
    retraining_rows: list[dict[str, Any]] = []
    clean_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    legacy_root = project_root / "outputs" / "publication_benchmark"
    for seed in SEEDS:
        print(f"\n=== P1 repeated split {seed}: data version ===", flush=True)
        set_seed(seed)
        pack, data_manifest, comparison = build_data_version(
            df,
            seed,
            pin_memory=device.type == "cuda",
            output_dir=output_dir,
            legacy_root=legacy_root,
        )
        data_manifests.append(data_manifest)
        data_comparison.extend(comparison)
        for model_name in MODELS:
            print(f"\n=== P1 repeated split {seed}: {model_name} ===", flush=True)
            model, threshold, training_status = train_or_load_model(
                seed=seed,
                model_name=model_name,
                pack=pack,
                data_manifest=data_manifest,
                output_dir=output_dir,
                device=device,
                project_root=project_root,
                train_attack_manifest_hash=train_attack_manifest_hash,
            )
            retraining_rows.append(training_status)
            if model is None or threshold is None:
                _write_failed_run(output_dir, training_status)
                for attack_id in ATTACKS:
                    for steps in STEPS:
                        failure = {
                            "schema_version": P1_SCHEMA,
                            "status": "failed",
                            "seed": seed,
                            "model": model_name,
                            "attack": attack_id,
                            "steps": steps,
                            "reason": "checkpoint_training_failed",
                        }
                        summaries.append(failure)
                        _write_failed_run(output_dir, failure)
                continue
            clean_row, _clean_logits, clean_probs = clean_reproduction(
                model,
                threshold,
                seed=seed,
                model_name=model_name,
                pack=pack,
                device=device,
                identity_status=training_status,
                output_dir=output_dir,
            )
            clean_rows.append(clean_row)
            for attack_id in ATTACKS:
                for steps in STEPS:
                    print(f"P1 attack seed={seed} model={model_name} attack={attack_id} steps={steps}", flush=True)
                    try:
                        summary = run_attack_configuration(
                            seed=seed,
                            model_name=model_name,
                            model=model,
                            threshold=threshold,
                            pack=pack,
                            clean_probs=clean_probs,
                            attack_id=attack_id,
                            steps=steps,
                            projection=projection_config,
                            audit_manifest=p1_config,
                            checkpoint_status=training_status,
                            output_dir=output_dir,
                            device=device,
                        )
                    except Exception as exc:
                        summary = {
                            "schema_version": P1_SCHEMA,
                            "status": "failed",
                            "seed": seed,
                            "model": model_name,
                            "attack": attack_id,
                            "steps": steps,
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                            "traceback": traceback.format_exc(),
                        }
                        task_dir = output_dir / "attack_runs" / f"seed_{seed}" / ("erm" if model_name == "BiLSTM-ERM" else "catad") / attack_id / f"k{steps}"
                        _atomic_json(task_dir / "summary.json", summary)
                        _write_failed_run(output_dir, summary)
                    summaries.append(summary)
            del model
            if device.type == "cuda":
                torch.cuda.empty_cache()
    return finalize_outputs(
        output_dir,
        p1_config=p1_config,
        projection_config=projection_config,
        data_manifests=data_manifests,
        data_comparison=data_comparison,
        retraining_rows=retraining_rows,
        clean_rows=clean_rows,
        summaries=summaries,
    )


def main() -> int:
    try:
        result = run_p1()
    except Exception:
        traceback.print_exc()
        return 1
    print(json.dumps(_json_safe(result["gate"]), indent=2, ensure_ascii=False))
    print(json.dumps(_json_safe(result["verdict"]), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

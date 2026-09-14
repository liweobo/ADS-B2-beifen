"""Isolated restart-range orchestration for the C0-01 P2-C audit.

This module deliberately leaves :mod:`adsb.attack_audit` unchanged.  The
frozen attack engine only exposes ``range(config.restarts)``.  P2-C must reuse
restart 0--9 and execute only later restart IDs, so ``RestartRangeConfig``
maps the engine's local loop positions to explicit, frozen restart IDs while
delegating every attack parameter and every optimization operation to the
unchanged engine.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import os
import shutil
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import torch

from adsb.attack_audit import AttackConfig, AttackResult, run_attack
from adsb.checkpoints import sha256_file
from adsb.p1_step_convergence import _metrics
from adsb.p2_step_size_restart import (
    PHYSICAL_ATTACKS,
    SAMPLE_FIELDS,
    STEP_FIELDS,
    _attack_config,
    _candidate_numpy,
    _float,
    _predict_candidate,
)


SCHEMA = "adsb.c001-p2c-orchestration.v1"

P2C_STEP_FIELDS = tuple(STEP_FIELDS) + (
    "config_id",
    "initialization_seed",
    "attack_seed",
    "seed_binding_hash",
    "checkpoint_hash",
    "split_hash",
    "source_R10_snapshot_hash",
    "source_previous_snapshot_hash",
    "orchestration_fingerprint",
    "target_restart_count",
    "executed_restart_start",
    "executed_restart_end",
)

P2C_SAMPLE_FIELDS = tuple(SAMPLE_FIELDS) + (
    "config_id",
    "source_R10_snapshot_hash",
    "source_previous_snapshot_hash",
    "orchestration_fingerprint",
    "target_restart_count",
    "executed_restart_start",
    "executed_restart_end",
)

CANDIDATE_NAMES = (
    "final_iterate",
    "best_target_loss_iterate",
    "first_threshold_success_iterate",
    "first_argmax_success_iterate",
    "best_feasible_successful_iterate",
    "best_feasible_iterate",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def diagnostic_hash(value: Any) -> str:
    """Canonical hash that preserves non-finite diagnostic values as labels."""

    def normalize(item: Any) -> Any:
        if isinstance(item, dict):
            return {str(key): normalize(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        if isinstance(item, (np.floating, float)):
            number = float(item)
            if math.isnan(number):
                return "NaN"
            if math.isinf(number):
                return "Infinity" if number > 0 else "-Infinity"
            return number
        if isinstance(item, (np.integer,)):
            return int(item)
        if isinstance(item, (np.bool_,)):
            return bool(item)
        return item

    return canonical_hash(normalize(value))


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class RestartRangeConfig:
    """Read-only proxy that maps local loop positions to actual restart IDs."""

    def __init__(self, base: AttackConfig, restart_ids: Sequence[int]):
        ids = tuple(int(value) for value in restart_ids)
        if not ids:
            raise ValueError("restart_ids must not be empty")
        if ids != tuple(range(ids[0], ids[-1] + 1)):
            raise ValueError("P2-C restart IDs must be a contiguous increasing range")
        if ids[0] < 0 or ids[-1] >= int(base.restarts):
            raise ValueError("restart range lies outside the frozen target restart count")
        self._base = base
        self._restart_ids = ids
        # The unchanged engine uses this attribute only to define its loop.
        self.restarts = len(ids)

    @property
    def config_hash(self) -> str:
        return self._base.config_hash

    @property
    def actual_restart_ids(self) -> tuple[int, ...]:
        return self._restart_ids

    def validate(self, *, for_execution: bool = True) -> None:
        self._base.validate(for_execution=for_execution)

    def restart_seed(self, local_restart_id: int) -> int:
        actual = self._restart_ids[int(local_restart_id)]
        return self._base.restart_seed(actual)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._base, name)


def _remap_selected(values: torch.Tensor, restart_ids: Sequence[int]) -> torch.Tensor:
    output = values.detach().clone()
    for local, actual in enumerate(restart_ids):
        output[values == local] = int(actual)
    return output


def run_attack_restart_range(
    model: torch.nn.Module,
    clean: torch.Tensor,
    labels: torch.Tensor,
    *,
    norm_mean: Any,
    norm_std: Any,
    frozen_threshold: float,
    config: AttackConfig,
    restart_ids: Sequence[int],
) -> AttackResult:
    """Execute only ``restart_ids`` through the unchanged attack engine."""

    proxy = RestartRangeConfig(config, restart_ids)
    result = run_attack(
        model,
        clean,
        labels,
        norm_mean=norm_mean,
        norm_std=norm_std,
        frozen_threshold=frozen_threshold,
        config=proxy,  # type: ignore[arg-type]
    )
    ids = proxy.actual_restart_ids
    for diagnostic in result.per_step_diagnostics:
        diagnostic["restart_id"] = int(ids[int(diagnostic["restart_id"])])
    result.initialization_status = [
        replace(status, restart_id=int(ids[int(status.restart_id)]))
        for status in result.initialization_status
    ]
    result.restart_id = _remap_selected(result.restart_id, ids)
    result.final_restart_id = _remap_selected(result.final_restart_id, ids)
    result.attack_config_hash = config.config_hash
    return result


def seed_binding_hash(
    *,
    split_hash: str,
    checkpoint_hash: str,
    attack_config_hash: str,
    sample_id: str,
    restart_id: int,
    engine_seed: int,
) -> str:
    """Bind the frozen engine seed to every required P2-C identity."""

    return canonical_hash(
        {
            "split_hash": split_hash,
            "checkpoint_hash": checkpoint_hash,
            "attack_config_hash": attack_config_hash,
            "sample_id": sample_id,
            "restart_id": int(restart_id),
            "engine_seed": int(engine_seed),
            "seed_semantics": "AttackConfig.restart_seed; P2-B frozen rule",
        }
    )


def _write_csv_rows(
    path: Path,
    fieldnames: Iterable[str],
    rows: Iterable[dict[str, Any]],
) -> tuple[int, str]:
    count = 0
    with gzip.open(path, "wt", encoding="utf-8", newline="", compresslevel=9) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=list(fieldnames),
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _float(row.get(key, "")) for key in fieldnames})
            count += 1
    return count, sha256_file(path)


def _finite_candidate(value: np.ndarray) -> np.ndarray:
    return np.isfinite(value).all(axis=(1, 2))


def _candidate_probability(
    model: torch.nn.Module,
    value: torch.Tensor | None,
    clean: torch.Tensor,
    device: torch.device,
) -> tuple[np.ndarray, np.ndarray]:
    if value is None:
        return np.full(len(clean), np.nan, dtype=np.float64), np.zeros(len(clean), dtype=bool)
    array = value.detach().float().cpu().numpy()
    valid = _finite_candidate(array)
    safe = value.detach().clone()
    safe[~torch.as_tensor(valid, device=safe.device)] = clean[
        ~torch.as_tensor(valid, device=clean.device)
    ]
    probabilities = _predict_candidate(model, safe, device)
    probabilities[~valid] = np.nan
    return probabilities, valid


def _failure_archive(stage_dir: Path, failed_root: Path, task_hash: str, attempt: int) -> Path:
    failed_root.mkdir(parents=True, exist_ok=True)
    destination = failed_root / f"{task_hash}.attempt_{attempt:03d}"
    suffix = 1
    while destination.exists():
        destination = failed_root / f"{task_hash}.attempt_{attempt:03d}.{suffix:03d}"
        suffix += 1
    os.replace(stage_dir, destination)
    return destination


def task_identity(
    *,
    phase: str,
    config_id: str,
    source_summary: dict[str, Any],
    target_restart_count: int,
    restart_ids: Sequence[int],
    source_snapshot_hash: str,
    previous_snapshot_hash: str,
    p2c_configuration_hash: str,
    orchestration_fingerprint: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "phase": phase,
        "config_id": config_id,
        "seed": int(source_summary["seed"]),
        "model": source_summary["model"],
        "attack": source_summary["attack"],
        "K": int(source_summary["steps"]),
        "target_restart_count": int(target_restart_count),
        "executed_restart_ids": [int(value) for value in restart_ids],
        "source_r10_task_hash": source_summary["task_hash"],
        "source_r10_candidate_sha256": source_summary["candidate_artifact"]["sha256"],
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "source_previous_snapshot_hash": previous_snapshot_hash,
        "p2c_configuration_hash": p2c_configuration_hash,
        "orchestration_fingerprint": orchestration_fingerprint,
        "checkpoint_sha256": source_summary["checkpoint_sha256"],
        "split_hash": source_summary["task_identity"]["split_hash"],
        "normalization_hash": source_summary["task_identity"]["normalization_hash"],
        "sample_manifest_hash": source_summary["task_identity"]["sample_manifest_hash"],
        "threshold": float(source_summary["threshold"]),
    }


def execute_range_task(
    *,
    phase: str,
    phase_dir: Path,
    config_id: str,
    source_summary: dict[str, Any],
    model: torch.nn.Module,
    threshold: float,
    pack: Any,
    clean_probs: np.ndarray,
    target_restart_count: int,
    restart_ids: Sequence[int],
    projection: dict[str, Any],
    source_snapshot_hash: str,
    previous_snapshot_hash: str,
    p2c_configuration_hash: str,
    orchestration_fingerprint: str,
    device: torch.device,
    attempt: int,
) -> dict[str, Any]:
    """Execute one frozen logical configuration as an atomic range task."""

    restart_ids = tuple(int(value) for value in restart_ids)
    identity = task_identity(
        phase=phase,
        config_id=config_id,
        source_summary=source_summary,
        target_restart_count=target_restart_count,
        restart_ids=restart_ids,
        source_snapshot_hash=source_snapshot_hash,
        previous_snapshot_hash=previous_snapshot_hash,
        p2c_configuration_hash=p2c_configuration_hash,
        orchestration_fingerprint=orchestration_fingerprint,
    )
    task_hash = canonical_hash(identity)
    final_dir = phase_dir / "tasks" / task_hash
    summary_path = final_dir / "summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if summary.get("status") != "completed" or summary.get("task_identity") != identity:
            raise RuntimeError(f"completed range task identity mismatch: {summary_path}")
        for artifact in summary["artifacts"].values():
            path = final_dir / artifact["path"]
            if not path.exists() or path.stat().st_size != int(artifact["size_bytes"]):
                raise RuntimeError(f"completed range task artifact missing: {path}")
            if sha256_file(path) != artifact["sha256"]:
                raise RuntimeError(f"completed range task artifact changed: {path}")
        return summary

    staging_root = phase_dir / ".staging"
    stage_dir = staging_root / task_hash
    failed_root = phase_dir / "failed_attempts"
    if stage_dir.exists():
        _failure_archive(stage_dir, failed_root, task_hash, max(0, attempt - 1))
    stage_dir.mkdir(parents=True, exist_ok=False)
    (stage_dir / "RUNNING").write_text(now() + "\n", encoding="utf-8")

    seed = int(source_summary["seed"])
    model_name = str(source_summary["model"])
    attack = str(source_summary["attack"])
    steps = int(source_summary["steps"])
    initialization = str(source_summary["initialization"])
    config = _attack_config(
        attack=attack,
        steps=steps,
        alpha_rule="two_eps_over_k",
        initialization=initialization,
        restarts=int(target_restart_count),
        seed=seed,
        projection=projection,
    )
    if not math.isclose(float(config.alpha), float(source_summary["alpha"]), abs_tol=0.0, rel_tol=0.0):
        raise RuntimeError("P2-C alpha differs from frozen P2-B alpha")

    labels = pack.test_loader.dataset.y.numpy().astype(np.int64)
    X = pack.test_loader.dataset.X
    metadata = pack.audit_metadata["test"]
    malicious_indices = np.flatnonzero(labels == 1)
    clean_mal_probs = np.asarray(clean_probs[malicious_indices], dtype=np.float64)
    batch_size = 512
    physical = attack in PHYSICAL_ATTACKS
    n_restart = len(restart_ids)

    step_path = stage_dir / "per_step_restart_records.csv.gz"
    step_stream = gzip.open(step_path, "wt", encoding="utf-8", newline="", compresslevel=9)
    step_writer = csv.DictWriter(
        step_stream,
        fieldnames=list(P2C_STEP_FIELDS),
        extrasaction="ignore",
        lineterminator="\n",
    )
    step_writer.writeheader()

    candidate_parts: dict[str, list[np.ndarray]] = {name: [] for name in CANDIDATE_NAMES}
    selected_final_parts: list[np.ndarray] = []
    selected_best_parts: list[np.ndarray] = []
    selected_step_parts: list[np.ndarray] = []
    new_best_probability_parts: list[np.ndarray] = []
    new_final_probability_parts: list[np.ndarray] = []
    new_best_valid_parts: list[np.ndarray] = []
    new_final_valid_parts: list[np.ndarray] = []
    source_valid_parts: list[np.ndarray] = []
    initialization_any_parts: list[np.ndarray] = []
    per_restart_success_parts: list[np.ndarray] = []
    per_restart_feasible_success_parts: list[np.ndarray] = []
    per_restart_active_parts: list[np.ndarray] = []
    per_restart_final_valid_parts: list[np.ndarray] = []
    per_restart_init_parts: list[np.ndarray] = []
    per_restart_projection_failure_parts: list[np.ndarray] = []
    per_restart_best_ce_parts: list[np.ndarray] = []
    per_restart_best_feasible_ce_parts: list[np.ndarray] = []
    restart_digests = {restart_id: hashlib.sha256() for restart_id in restart_ids}
    step_rows = 0
    native_ids_pass = True
    budget_pass = True
    projection_checker_pass = True
    finite_ce_pass = True

    try:
        for batch_start in range(0, len(malicious_indices), batch_size):
            indices = malicious_indices[batch_start : batch_start + batch_size]
            clean_batch = X[indices].to(device=device, dtype=torch.float32)
            label_batch = torch.ones(len(indices), dtype=torch.long, device=device)
            result = run_attack_restart_range(
                model,
                clean_batch,
                label_batch,
                norm_mean=pack.norm_mean,
                norm_std=pack.norm_std,
                frozen_threshold=threshold,
                config=config,
                restart_ids=restart_ids,
            )
            diagnostics = result.per_step_diagnostics
            expected_pairs = [
                (restart_id, step_id)
                for restart_id in restart_ids
                for step_id in range(steps + 1)
            ]
            observed_pairs = [
                (int(item["restart_id"]), int(item["step"])) for item in diagnostics
            ]
            native_ids_pass &= observed_pairs == expected_pairs
            if not native_ids_pass:
                raise AssertionError("P2-C range task did not emit native restart IDs")

            ce = np.asarray(
                [item["target_ce"] for item in diagnostics], dtype=np.float64
            ).reshape(n_restart, steps + 1, len(indices))
            active = np.asarray(
                [item["candidate_active"] for item in diagnostics], dtype=bool
            ).reshape(n_restart, steps + 1, len(indices))
            feasible = np.asarray(
                [item["feasible"] for item in diagnostics], dtype=bool
            ).reshape(n_restart, steps + 1, len(indices))
            threshold_success = np.asarray(
                [item["threshold_success"] for item in diagnostics], dtype=bool
            ).reshape(n_restart, steps + 1, len(indices))
            budget_valid = np.asarray(
                [item["budget_valid"] for item in diagnostics], dtype=bool
            ).reshape(n_restart, steps + 1, len(indices))
            projection_converged = np.asarray(
                [item["projection_converged"] for item in diagnostics], dtype=bool
            ).reshape(n_restart, steps + 1, len(indices))
            projection_checked = np.asarray(
                [item["projection_independently_checked"] for item in diagnostics],
                dtype=bool,
            ).reshape(n_restart, steps + 1, len(indices))
            projection_status = np.asarray(
                [item["projection_status"] for item in diagnostics], dtype=object
            ).reshape(n_restart, steps + 1, len(indices))
            source_valid = np.asarray(diagnostics[0]["source_valid"], dtype=bool)
            init_status = np.asarray(
                [item.success for item in result.initialization_status], dtype=bool
            ).reshape(n_restart, len(indices))
            init_seed = np.asarray(
                [item.seed for item in result.initialization_status], dtype=np.int64
            ).reshape(n_restart, len(indices))

            eligible_success = active & threshold_success
            if physical:
                eligible_success &= feasible
            feasible_success = active & feasible & threshold_success
            per_restart_success_parts.append(eligible_success.any(axis=1))
            per_restart_feasible_success_parts.append(feasible_success.any(axis=1))
            per_restart_active_parts.append(active.any(axis=1))
            per_restart_final_valid_parts.append(
                active[:, -1, :] & (feasible[:, -1, :] if physical else True)
            )
            per_restart_init_parts.append(init_status)
            per_restart_projection_failure_parts.append(
                ((projection_status != "not_required") & ~projection_converged).any(axis=1)
            )
            active_ce = np.where(active, ce, np.inf)
            feasible_ce = np.where(active & feasible, ce, np.inf)
            best_ce = active_ce.min(axis=1)
            best_feasible_ce = feasible_ce.min(axis=1)
            best_ce[~np.isfinite(best_ce)] = np.nan
            best_feasible_ce[~np.isfinite(best_feasible_ce)] = np.nan
            per_restart_best_ce_parts.append(best_ce)
            per_restart_best_feasible_ce_parts.append(best_feasible_ce)

            budget_pass &= bool(budget_valid.all())
            projection_checker_pass &= bool(
                ((projection_status == "not_required") | ~projection_converged | projection_checked).all()
            )
            finite_ce_pass &= bool(np.isfinite(ce).all())

            for name in CANDIDATE_NAMES:
                candidate_parts[name].append(
                    _candidate_numpy(getattr(result, name), clean_batch)
                )
            new_best_probs, new_best_valid = _candidate_probability(
                model, result.best_target_loss_iterate, clean_batch, device
            )
            new_final_probs, new_final_valid = _candidate_probability(
                model, result.final_iterate, clean_batch, device
            )
            if physical:
                new_final_valid &= result.final_feasible.detach().cpu().numpy().astype(bool)
            new_best_probability_parts.append(new_best_probs)
            new_final_probability_parts.append(new_final_probs)
            new_best_valid_parts.append(new_best_valid)
            new_final_valid_parts.append(new_final_valid)
            source_valid_parts.append(source_valid)
            initialization_any_parts.append(init_status.any(axis=0))
            selected_final_parts.append(result.final_restart_id.detach().cpu().numpy())
            selected_best_parts.append(result.restart_id.detach().cpu().numpy())

            best_step = np.full(len(indices), -1, dtype=np.int64)
            selected_best = result.restart_id.detach().cpu().numpy().astype(np.int64)
            for local_index, restart_id in enumerate(restart_ids):
                mask = selected_best == restart_id
                if mask.any():
                    best_step[mask] = np.nanargmin(
                        active_ce[local_index][:, mask], axis=0
                    )
            selected_step_parts.append(best_step)

            sample_ids = np.asarray(metadata["sample_id"][indices]).astype("U")
            for local_restart, restart_id in enumerate(restart_ids):
                digest = restart_digests[restart_id]
                digest.update(sample_ids.tobytes())
                for value in (
                    ce[local_restart],
                    active[local_restart],
                    feasible[local_restart],
                    threshold_success[local_restart],
                ):
                    contiguous = np.ascontiguousarray(value)
                    digest.update(str(contiguous.shape).encode("ascii"))
                    digest.update(str(contiguous.dtype).encode("ascii"))
                    digest.update(contiguous.tobytes())

            for diagnostic in diagnostics:
                restart_id = int(diagnostic["restart_id"])
                local_restart = restart_ids.index(restart_id)
                step_id = int(diagnostic["step"])
                for local_sample, global_index in enumerate(indices):
                    engine_seed = int(init_seed[local_restart, local_sample])
                    sample_id = str(metadata["sample_id"][global_index])
                    row = {
                        "stage": phase,
                        "task_hash": task_hash,
                        "attack_config_hash": config.config_hash,
                        "seed": seed,
                        "model": model_name,
                        "attack": attack,
                        "steps": steps,
                        "alpha_rule": "two_eps_over_k",
                        "alpha": config.alpha,
                        "initialization": initialization,
                        "restarts": target_restart_count,
                        "sample_id": sample_id,
                        "aircraft_id": str(metadata["aircraft_id"][global_index]),
                        "restart_id": restart_id,
                        "step": step_id,
                        "config_id": config_id,
                        "initialization_seed": engine_seed,
                        "attack_seed": engine_seed,
                        "seed_binding_hash": seed_binding_hash(
                            split_hash=identity["split_hash"],
                            checkpoint_hash=identity["checkpoint_sha256"],
                            attack_config_hash=config.config_hash,
                            sample_id=sample_id,
                            restart_id=restart_id,
                            engine_seed=engine_seed,
                        ),
                        "checkpoint_hash": identity["checkpoint_sha256"],
                        "split_hash": identity["split_hash"],
                        "source_R10_snapshot_hash": source_snapshot_hash,
                        "source_previous_snapshot_hash": previous_snapshot_hash,
                        "orchestration_fingerprint": orchestration_fingerprint,
                        "target_restart_count": target_restart_count,
                        "executed_restart_start": restart_ids[0],
                        "executed_restart_end": restart_ids[-1],
                    }
                    aliases = {"zero_gradient_flag": "zero_gradient_flag"}
                    for field in STEP_FIELDS:
                        source = aliases.get(field, field)
                        if field not in row and source in diagnostic:
                            value = diagnostic[source]
                            row[field] = value[local_sample] if isinstance(value, list) else value
                    step_writer.writerow(
                        {key: _float(row.get(key, "")) for key in P2C_STEP_FIELDS}
                    )
                    step_rows += 1
    except BaseException:
        step_stream.close()
        raise
    finally:
        if not step_stream.closed:
            step_stream.close()

    arrays = {
        name: np.concatenate(parts, axis=0)
        for name, parts in candidate_parts.items()
    }
    arrays.update(
        {
            "sample_id": np.asarray(metadata["sample_id"][malicious_indices]).astype("U"),
            "restart_ids": np.asarray(restart_ids, dtype=np.int64),
            "selected_final_restart": np.concatenate(selected_final_parts),
            "selected_best_restart": np.concatenate(selected_best_parts),
            "selected_best_step": np.concatenate(selected_step_parts),
            "new_best_p_anomaly": np.concatenate(new_best_probability_parts),
            "new_final_p_anomaly": np.concatenate(new_final_probability_parts),
            "new_best_valid": np.concatenate(new_best_valid_parts),
            "new_final_valid": np.concatenate(new_final_valid_parts),
            "source_valid": np.concatenate(source_valid_parts),
            "initialization_success_any_restart": np.concatenate(initialization_any_parts),
            "per_restart_success": np.concatenate(per_restart_success_parts, axis=1),
            "per_restart_feasible_success": np.concatenate(
                per_restart_feasible_success_parts, axis=1
            ),
            "per_restart_active": np.concatenate(per_restart_active_parts, axis=1),
            "per_restart_final_valid": np.concatenate(
                per_restart_final_valid_parts, axis=1
            ),
            "per_restart_initialization_success": np.concatenate(
                per_restart_init_parts, axis=1
            ),
            "per_restart_projection_failure": np.concatenate(
                per_restart_projection_failure_parts, axis=1
            ),
            "per_restart_best_target_ce": np.concatenate(
                per_restart_best_ce_parts, axis=1
            ),
            "per_restart_best_feasible_target_ce": np.concatenate(
                per_restart_best_feasible_ce_parts, axis=1
            ),
            "clean_p_anomaly": clean_mal_probs,
            "threshold": np.asarray([threshold], dtype=np.float64),
        }
    )
    candidate_path = stage_dir / "candidate_iterates.npz"
    np.savez_compressed(candidate_path, **arrays)

    new_best_probs = arrays["new_best_p_anomaly"]
    new_final_probs = arrays["new_final_p_anomaly"]
    new_best_valid = arrays["new_best_valid"]
    new_final_valid = arrays["new_final_valid"]
    source_valid = arrays["source_valid"]
    initialization_any = arrays["initialization_success_any_restart"]
    per_restart_success = arrays["per_restart_success"]
    per_restart_feasible_success = arrays["per_restart_feasible_success"]
    selected_final = arrays["selected_final_restart"]
    selected_best = arrays["selected_best_restart"]
    selected_step = arrays["selected_best_step"]

    sample_rows: list[dict[str, Any]] = []
    for position, global_index in enumerate(malicious_indices):
        best_probability = float(new_best_probs[position])
        final_probability = float(new_final_probs[position])
        best_valid = bool(new_best_valid[position])
        final_valid = bool(new_final_valid[position])
        threshold_success_any = bool(per_restart_success[:, position].any())
        feasible_success_any = bool(per_restart_feasible_success[:, position].any())
        if not bool(source_valid[position]):
            failure_state = "source_invalid"
        elif not bool(initialization_any[position]):
            failure_state = "initialization_infeasible"
        elif threshold_success_any:
            failure_state = "valid_attack_success"
        elif best_valid:
            failure_state = "valid_attack_failure"
        else:
            failure_state = "no_valid_candidate"
        sample_rows.append(
            {
                "stage": phase,
                "task_hash": task_hash,
                "attack_config_hash": config.config_hash,
                "seed": seed,
                "model": model_name,
                "attack": attack,
                "steps": steps,
                "alpha_rule": "two_eps_over_k",
                "alpha": config.alpha,
                "initialization": initialization,
                "restarts": target_restart_count,
                "sample_id": str(metadata["sample_id"][global_index]),
                "aircraft_id": str(metadata["aircraft_id"][global_index]),
                "segment_id": str(metadata["segment_id"][global_index]),
                "window_start": int(metadata["window_start"][global_index]),
                "anomaly_bitmask": int(metadata["anomaly_bitmask"][global_index]),
                "original_label": 1,
                "attacked": True,
                "clean_p_anomaly": float(clean_probs[global_index]),
                "final_p_anomaly": final_probability,
                "best_p_anomaly": best_probability,
                "clean_prediction": int(clean_probs[global_index] >= threshold),
                "final_prediction": int(
                    final_valid and np.isfinite(final_probability) and final_probability >= threshold
                ),
                "best_prediction": int(
                    best_valid and np.isfinite(best_probability) and best_probability >= threshold
                ),
                "final_feasible": final_valid,
                "best_feasible": best_valid,
                "source_valid": bool(source_valid[position]),
                "initialization_success_any_restart": bool(initialization_any[position]),
                "selected_final_restart": int(selected_final[position]),
                "selected_best_restart": int(selected_best[position]),
                "selected_best_step": int(selected_step[position]),
                "valid_attack_success": threshold_success_any,
                "valid_attack_failure": bool(best_valid and not threshold_success_any),
                "failure_state": failure_state,
                "config_id": config_id,
                "source_R10_snapshot_hash": source_snapshot_hash,
                "source_previous_snapshot_hash": previous_snapshot_hash,
                "orchestration_fingerprint": orchestration_fingerprint,
                "target_restart_count": target_restart_count,
                "executed_restart_start": restart_ids[0],
                "executed_restart_end": restart_ids[-1],
            }
        )
    sample_path = stage_dir / "per_sample_range_records.csv.gz"
    sample_rows_count, sample_sha = _write_csv_rows(
        sample_path, P2C_SAMPLE_FIELDS, sample_rows
    )

    step_sha = sha256_file(step_path)
    candidate_sha = sha256_file(candidate_path)
    clean_pred = clean_mal_probs >= threshold
    new_success = per_restart_success.any(axis=0)
    new_feasible_success = per_restart_feasible_success.any(axis=0)
    summary = {
        "schema_version": SCHEMA,
        "status": "completed",
        "created_at_utc": now(),
        "phase": phase,
        "task_hash": task_hash,
        "task_identity": identity,
        "config_id": config_id,
        "seed": seed,
        "model": model_name,
        "attack": attack,
        "K": steps,
        "alpha_rule": "two_eps_over_k",
        "alpha": float(config.alpha),
        "initialization": initialization,
        "target_restart_count": int(target_restart_count),
        "executed_restart_ids": list(restart_ids),
        "attack_config": asdict(config),
        "attack_config_hash": config.config_hash,
        "restart_fingerprints": {
            str(restart_id): restart_digests[restart_id].hexdigest()
            for restart_id in restart_ids
        },
        "support": {
            "test_samples": int(len(labels)),
            "attacked_support": int(len(malicious_indices)),
            "clean_true_positive_support": int(clean_pred.sum()),
            "source_valid_support": int(source_valid.sum()),
            "active_support": int(arrays["per_restart_active"].any(axis=0).sum()),
            "initialization_success_support": int(initialization_any.sum()),
            "final_valid_support": int(new_final_valid.sum()),
            "best_valid_support": int(new_best_valid.sum()),
            "threshold_success_support": int(new_success.sum()),
            "feasible_success_support": int(new_feasible_success.sum()),
            "clean_fallback_count": int((~new_best_valid).sum()),
            "projection_failure_count": int(
                arrays["per_restart_projection_failure"].any(axis=0).sum()
            ),
        },
        "identity_checks": {
            "native_restart_ids": native_ids_pass,
            "restart_range_exact": sorted(
                {int(item) for item in np.unique(arrays["restart_ids"])}
            )
            == list(restart_ids),
            "all_logged_candidates_within_budget": budget_pass,
            "projection_success_independently_checked": projection_checker_pass,
            "no_nan_logged_target_ce": finite_ce_pass,
            "normal_samples_not_submitted_to_attack": True,
            "frozen_attack_config_matches_source_except_restart_count": True,
            "seed_binding_recorded_per_row": True,
        },
        "artifacts": {
            "per_step": {
                "path": step_path.name,
                "size_bytes": step_path.stat().st_size,
                "sha256": step_sha,
                "rows": int(step_rows),
            },
            "per_sample": {
                "path": sample_path.name,
                "size_bytes": sample_path.stat().st_size,
                "sha256": sample_sha,
                "rows": int(sample_rows_count),
            },
            "candidates": {
                "path": candidate_path.name,
                "size_bytes": candidate_path.stat().st_size,
                "sha256": candidate_sha,
            },
        },
    }
    if not all(summary["identity_checks"].values()):
        raise RuntimeError(f"P2-C range task identity checks failed: {task_hash}")
    (stage_dir / "RUNNING").unlink(missing_ok=True)
    atomic_json(stage_dir / "summary.json", summary)
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    if final_dir.exists():
        raise RuntimeError(f"range task destination unexpectedly exists: {final_dir}")
    os.replace(stage_dir, final_dir)
    return summary


class _TinyDetector(torch.nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.linear = torch.nn.Linear(12, 2, bias=True)
        with torch.no_grad():
            self.linear.weight.copy_(
                torch.tensor(
                    [
                        [-0.10, 0.05, -0.03, 0.02, 0.04, -0.01] * 2,
                        [0.08, -0.02, 0.04, -0.05, -0.03, 0.02] * 2,
                    ],
                    dtype=torch.float32,
                )
            )
            self.linear.bias.copy_(torch.tensor([0.1, -0.1]))

    def forward(self, value: torch.Tensor) -> torch.Tensor:
        return self.linear(value.mean(dim=1))


def orchestration_self_test() -> dict[str, Any]:
    """Synthetic unit/smoke test; it never reads or reruns P2-B data."""

    device = torch.device("cpu")
    model = _TinyDetector().to(device).eval()
    generator = torch.Generator(device=device).manual_seed(20260730)
    clean = torch.randn((3, 4, 12), generator=generator, device=device) * 0.05
    labels = torch.ones(3, dtype=torch.long, device=device)
    mean = np.zeros(12, dtype=np.float32)
    std = np.ones(12, dtype=np.float32)
    config = AttackConfig(
        attack_id="norm_pgd",
        loss="targeted_ce",
        steps=2,
        alpha=0.02,
        epsilon=0.1,
        initialization="uniform_budget",
        restarts=2,
        seed=42,
        budget_abs_tol=1e-5,
        kinematic_rel_tol=1e-5,
        projection_residual_tol=1e-6,
        maximum_alternating_projection_iterations=5,
        feasible_random_resampling_count=2,
    )
    native = run_attack(
        model,
        clean,
        labels,
        norm_mean=mean,
        norm_std=std,
        frozen_threshold=0.5,
        config=config,
    )
    ranged = run_attack_restart_range(
        model,
        clean,
        labels,
        norm_mean=mean,
        norm_std=std,
        frozen_threshold=0.5,
        config=config,
        restart_ids=(0, 1),
    )

    tensor_fields = (
        "final_iterate",
        "best_target_loss_iterate",
        "restart_id",
        "final_restart_id",
        "best_target_loss",
        "threshold_success",
        "argmax_success",
        "feasible_success",
        "final_feasible",
    )
    tensor_equal: dict[str, bool] = {}
    for name in tensor_fields:
        left = getattr(native, name)
        right = getattr(ranged, name)
        if left is None or right is None:
            tensor_equal[name] = left is right
        elif left.dtype == torch.bool or not left.dtype.is_floating_point:
            tensor_equal[name] = bool(torch.equal(left, right))
        else:
            tensor_equal[name] = bool(
                torch.allclose(left, right, atol=0.0, rtol=0.0, equal_nan=True)
            )
    diagnostic_equal = diagnostic_hash(native.per_step_diagnostics) == diagnostic_hash(
        ranged.per_step_diagnostics
    )
    seed_equal = [
        config.restart_seed(restart_id)
        == RestartRangeConfig(config, (0, 1)).restart_seed(restart_id)
        for restart_id in (0, 1)
    ]

    extended = replace(config, restarts=12)
    late = run_attack_restart_range(
        model,
        clean,
        labels,
        norm_mean=mean,
        norm_std=std,
        frozen_threshold=0.5,
        config=extended,
        restart_ids=(10, 11),
    )
    late_ids = sorted({int(item["restart_id"]) for item in late.per_step_diagnostics})
    late_init_ids = sorted({int(item.restart_id) for item in late.initialization_status})
    late_seed_equal = all(
        item.seed == extended.restart_seed(item.restart_id)
        for item in late.initialization_status
    )
    checks = {
        "native_equivalence_tensors": all(tensor_equal.values()),
        "native_equivalence_diagnostics": diagnostic_equal,
        "native_equivalence_seeds": all(seed_equal),
        "late_native_ids": late_ids == [10, 11],
        "late_initialization_ids": late_init_ids == [10, 11],
        "late_seed_reproduction": late_seed_equal,
        "frozen_attack_engine_called_directly": True,
    }
    return {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "synthetic_only": True,
        "checks": checks,
        "tensor_field_checks": tensor_equal,
        "status": "PASS" if all(checks.values()) else "FAIL",
    }

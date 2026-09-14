"""Formal C0-01 P2 step-size, initialization, and restart audit.

This runner is deliberately limited to P2.  It reuses the ten identity-checked
P1 checkpoints, refuses any data/checkpoint/freeze mismatch, retains every
direction, and never schedules P3--P6 work.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import os
import shutil
import traceback
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

from adsb.attack_audit import AttackConfig, AttackResult, run_attack
from adsb.checkpoints import (
    CheckpointIdentity,
    checkpoint_manifest_path,
    code_fingerprint,
    load_verified_detector_checkpoint,
    normalization_hash,
    sha256_file,
)
from adsb.data import filter_data, load_data, subset_df_by_aircraft
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.p1_step_convergence import (
    _atomic_json,
    _canonical_bytes,
    _json_safe,
    _metrics,
    _predict_logits,
    _probabilities,
    build_data_version,
)
from adsb.paths import default_project_root
from adsb.utils import set_seed


P2_SCHEMA = "adsb.c001-p2-results.v1"
SEEDS = (42, 43, 44, 45, 46)
MODELS = ("BiLSTM-ERM", "CAT-AD")
ATTACKS = ("norm_pgd", "phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd")
PHYSICAL_ATTACKS = {"phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd"}
STEPS = (20, 50)
ALPHA_RULES = ("fixed_003", "eps_over_k", "two_eps_over_k", "eps_over_4")
RANDOM_INITIALIZATION = {
    "norm_pgd": "uniform_budget",
    "phys_projection_pgd": "feasible_random",
    "phys_penalty_pgd": "uniform_budget",
    "phys_hybrid_pgd": "feasible_random",
}
ALL_INITIALIZATIONS = {
    attack: ("clean", RANDOM_INITIALIZATION[attack]) for attack in ATTACKS
}


STEP_FIELDS = (
    "stage",
    "task_hash",
    "attack_config_hash",
    "seed",
    "model",
    "attack",
    "steps",
    "alpha_rule",
    "alpha",
    "initialization",
    "restarts",
    "sample_id",
    "aircraft_id",
    "restart_id",
    "step",
    "target_ce",
    "target_margin",
    "p_normal",
    "p_anomaly",
    "gradient_l1",
    "gradient_l2",
    "gradient_linf",
    "zero_gradient_flag",
    "pre_projection_target_ce",
    "post_projection_target_ce",
    "pre_projection_margin",
    "post_projection_margin",
    "projection_residual",
    "projection_iterations",
    "projection_status",
    "projection_converged",
    "projection_independently_checked",
    "initialization_status",
    "initialization_success",
    "initialization_attempts",
    "linf_raw6_normalized",
    "linf_difference6_normalized",
    "linf_full12_normalized",
    "raw_boundary_saturation_rate",
    "raw_latitude_saturated",
    "raw_longitude_saturated",
    "raw_altitude_saturated",
    "raw_speed_saturated",
    "raw_heading_sin_saturated",
    "raw_heading_cos_saturated",
    "threshold_success",
    "argmax_success",
    "clean_tp_to_attack_fn",
    "clean_fn_to_attack_tp",
    "final_candidate",
    "best_loss_candidate",
    "first_threshold_success_step",
    "first_threshold_success_restart",
    "first_argmax_success_step",
    "first_argmax_success_restart",
    "best_feasible_success_step",
    "best_feasible_success_restart",
    "candidate_active",
    "source_valid",
    "post_valid",
    "budget_valid",
    "kinematic_valid",
    "feasible_success",
    "budget_residual",
    "kinematic_residual",
    "domain_residual",
    "kinematic_latitude_rel_violation",
    "kinematic_longitude_rel_violation",
    "kinematic_altitude_rel_violation",
    "kinematic_speed_rel_violation",
    "kinematic_heading_rel_violation",
)

SAMPLE_FIELDS = (
    "stage",
    "task_hash",
    "attack_config_hash",
    "seed",
    "model",
    "attack",
    "steps",
    "alpha_rule",
    "alpha",
    "initialization",
    "restarts",
    "sample_id",
    "aircraft_id",
    "segment_id",
    "window_start",
    "anomaly_bitmask",
    "original_label",
    "attacked",
    "clean_p_anomaly",
    "final_p_anomaly",
    "best_p_anomaly",
    "clean_prediction",
    "final_prediction",
    "best_prediction",
    "final_feasible",
    "best_feasible",
    "source_valid",
    "initialization_success_any_restart",
    "selected_final_restart",
    "selected_best_restart",
    "selected_best_step",
    "first_threshold_success_step",
    "first_argmax_success_step",
    "best_feasible_success_step",
    "source_invalid",
    "initialization_infeasible",
    "projection_not_converged",
    "budget_invalid",
    "kinematic_invalid",
    "valid_attack_failure",
    "valid_attack_success",
    "clean_tp_to_final_fn",
    "clean_fn_to_final_tp",
    "clean_tp_to_best_fn",
    "clean_fn_to_best_tp",
    "failure_state",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _contains_null(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, dict):
        return any(_contains_null(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_null(item) for item in value)
    return False


def _boolean_checks_pass(value: dict[str, Any]) -> bool:
    checks = [item for item in value.values() if isinstance(item, bool)]
    return bool(checks) and all(checks)


def _alpha(rule: str, steps: int, epsilon: float = 0.1) -> float:
    if rule == "fixed_003":
        return 0.03
    if rule == "eps_over_k":
        return float(epsilon) / int(steps)
    if rule == "two_eps_over_k":
        return 2.0 * float(epsilon) / int(steps)
    if rule == "eps_over_4":
        return float(epsilon) / 4.0
    raise ValueError(f"unknown alpha rule: {rule}")


def _attack_config(
    *,
    attack: str,
    steps: int,
    alpha_rule: str,
    initialization: str,
    restarts: int,
    seed: int,
    projection: dict[str, Any],
) -> AttackConfig:
    return AttackConfig(
        attack_id=attack,
        loss="targeted_ce",
        steps=int(steps),
        alpha=_alpha(alpha_rule, steps),
        epsilon=0.1,
        initialization=initialization,
        restarts=int(restarts),
        target_label=0,
        normal_class=0,
        anomaly_class=1,
        budget_scope="normalized_raw6",
        derived_difference_consistency="recomputed_from_raw",
        projection_schedule=(
            "strict_every_step"
            if attack == "phys_projection_pgd"
            else ("late_plus_final" if attack == "phys_hybrid_pgd" else "none")
        ),
        seed=int(seed),
        budget_abs_tol=float(projection["budget_abs_tol"]),
        kinematic_rel_tol=float(projection["kinematic_rel_tol"]),
        projection_residual_tol=float(projection["projection_residual_tol"]),
        maximum_alternating_projection_iterations=int(
            projection["alternating_projection_max_iterations"]
        ),
        feasible_random_resampling_count=int(projection["feasible_random_max_resamples"]),
    )


def _logical_config_id(
    *,
    seed: int,
    model: str,
    attack: str,
    steps: int,
    alpha_rule: str,
    initialization: str,
) -> str:
    return _canonical_hash(
        {
            "stage": "p2a",
            "seed": int(seed),
            "model": model,
            "attack": attack,
            "steps": int(steps),
            "alpha_rule": alpha_rule,
            "initialization": initialization,
            "restarts": 1,
        }
    )


def _float(value: Any) -> Any:
    if isinstance(value, (np.bool_, bool)):
        return int(bool(value))
    if isinstance(value, (np.integer, int)):
        return int(value)
    if isinstance(value, (np.floating, float)):
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return number
        return format(number, ".9g")
    return value


def _write_rows(path: Path, fieldnames: Iterable[str], rows: Iterable[dict[str, Any]], *, header: bool) -> tuple[int, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with gzip.open(path, "wt", encoding="utf-8", newline="", compresslevel=9) as stream:
        writer = csv.DictWriter(stream, fieldnames=list(fieldnames), extrasaction="ignore", lineterminator="\n")
        if header:
            writer.writeheader()
        for row in rows:
            writer.writerow({key: _float(row.get(key, "")) for key in fieldnames})
            count += 1
    return count, sha256_file(path)


class AggregateStore:
    """Crash-recoverable append-only gzip-member aggregates.

    A task first creates two complete gzip fragments.  The fragments are
    appended as independent gzip members; only the first member contains the
    CSV header.  The ledger is atomically advanced after both appends.  On a
    resumed process, any unledgered tail is truncated before work continues.
    """

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.step_path = output_dir / "per_step_restart_records.csv.gz"
        self.sample_path = output_dir / "per_sample_attack_records.csv.gz"
        self.ledger_path = output_dir / "aggregation_ledger.json"
        if self.ledger_path.exists():
            self.ledger = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        else:
            self.ledger = {
                "schema_version": "adsb.c001-p2-aggregation-ledger.v1",
                "step_size_bytes": 0,
                "sample_size_bytes": 0,
                "tasks": {},
            }
        self._truncate_to_ledger(self.step_path, int(self.ledger["step_size_bytes"]))
        self._truncate_to_ledger(self.sample_path, int(self.ledger["sample_size_bytes"]))

    @staticmethod
    def _truncate_to_ledger(path: Path, size: int) -> None:
        if not path.exists():
            if size != 0:
                raise RuntimeError(f"aggregate missing but ledger expects {size} bytes: {path}")
            return
        current = path.stat().st_size
        if current < size:
            raise RuntimeError(f"aggregate shorter than ledger: {path} {current} < {size}")
        if current > size:
            with path.open("r+b") as stream:
                stream.truncate(size)

    @property
    def is_empty(self) -> bool:
        return not bool(self.ledger["tasks"])

    def has_task(self, task_hash: str) -> bool:
        return task_hash in self.ledger["tasks"]

    @staticmethod
    def _append(destination: Path, source: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("ab") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output, length=8 * 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())

    def commit(
        self,
        *,
        task_hash: str,
        step_fragment: Path,
        sample_fragment: Path,
        step_rows: int,
        sample_rows: int,
        step_sha256: str,
        sample_sha256: str,
    ) -> dict[str, Any]:
        if self.has_task(task_hash):
            return self.ledger["tasks"][task_hash]
        self._append(self.step_path, step_fragment)
        self._append(self.sample_path, sample_fragment)
        entry = {
            "step_rows": int(step_rows),
            "sample_rows": int(sample_rows),
            "step_member_sha256": step_sha256,
            "sample_member_sha256": sample_sha256,
            "step_size_bytes_after": self.step_path.stat().st_size,
            "sample_size_bytes_after": self.sample_path.stat().st_size,
            "committed_at_utc": _now(),
        }
        updated = json.loads(json.dumps(self.ledger))
        updated["tasks"][task_hash] = entry
        updated["step_size_bytes"] = entry["step_size_bytes_after"]
        updated["sample_size_bytes"] = entry["sample_size_bytes_after"]
        _atomic_json(self.ledger_path, updated)
        self.ledger = updated
        return entry


def _checkpoint_slug(model: str) -> str:
    return "bilstm_erm" if model == "BiLSTM-ERM" else "cat_ad"


def _model_slug(model: str) -> str:
    return "erm" if model == "BiLSTM-ERM" else "catad"


def _candidate_numpy(value: torch.Tensor | None, clean: torch.Tensor) -> np.ndarray:
    if value is None:
        return np.full(tuple(clean.shape), np.nan, dtype=np.float32)
    return value.detach().float().cpu().numpy()


def _predict_candidate(model: torch.nn.Module, candidate: torch.Tensor, device: torch.device) -> np.ndarray:
    return _probabilities(_predict_logits(model, candidate.detach().cpu(), device))


def _update_digest(digest: "hashlib._Hash", value: Any) -> None:
    array = np.ascontiguousarray(np.asarray(value))
    digest.update(str(array.shape).encode("ascii"))
    digest.update(str(array.dtype).encode("ascii"))
    digest.update(array.tobytes(order="C"))


def _selection_indices(result: AttackResult, *, physical: bool) -> dict[str, np.ndarray]:
    diagnostics = result.per_step_diagnostics
    restarts = max(int(item["restart_id"]) for item in diagnostics) + 1
    steps = max(int(item["step"]) for item in diagnostics)
    batch = len(diagnostics[0]["target_ce"])
    expected = [(restart, step) for restart in range(restarts) for step in range(steps + 1)]
    observed = [(int(item["restart_id"]), int(item["step"])) for item in diagnostics]
    if observed != expected:
        raise AssertionError("native restart_id/step sequence is incomplete or out of order")
    ce = np.asarray([item["target_ce"] for item in diagnostics], dtype=np.float64)
    active = np.asarray([item["candidate_active"] for item in diagnostics], dtype=bool)
    feasible = np.asarray([item["feasible"] for item in diagnostics], dtype=bool)
    threshold = np.asarray([item["threshold_success"] for item in diagnostics], dtype=bool)
    argmax = np.asarray([item["argmax_success"] for item in diagnostics], dtype=bool)
    restart_values = np.asarray([item["restart_id"] for item in diagnostics], dtype=np.int64)
    step_values = np.asarray([item["step"] for item in diagnostics], dtype=np.int64)

    def choose(mask: np.ndarray, *, first: bool = False) -> np.ndarray:
        output = np.full(batch, -1, dtype=np.int64)
        for sample in range(batch):
            indices = np.flatnonzero(mask[:, sample])
            if len(indices):
                output[sample] = int(indices[0] if first else indices[np.argmin(ce[indices, sample])])
        return output

    valid = active & (feasible if physical else True)
    return {
        "best_loss": choose(active),
        "final": choose(valid & (step_values[:, None] == steps)),
        "first_threshold": choose(active & threshold, first=True),
        "first_argmax": choose(active & argmax, first=True),
        "best_feasible_success": choose(active & feasible & threshold),
        "best_feasible": choose(active & feasible),
        "restart_values": restart_values,
        "step_values": step_values,
    }


def _summary_path(output_dir: Path, task_hash: str) -> Path:
    return output_dir / "tasks" / task_hash / "summary.json"


def _commit_ready_summary(summary_path: Path, summary: dict[str, Any], store: AggregateStore) -> dict[str, Any]:
    task_hash = str(summary["task_hash"])
    fragments = summary["staged_fragments"]
    if not store.has_task(task_hash):
        step_fragment = Path(fragments["per_step"]["absolute_path"])
        sample_fragment = Path(fragments["per_sample"]["absolute_path"])
        for path, record in ((step_fragment, fragments["per_step"]), (sample_fragment, fragments["per_sample"])):
            if not path.exists() or sha256_file(path) != record["sha256"]:
                raise RuntimeError(f"ready-to-commit fragment missing or changed: {path}")
        entry = store.commit(
            task_hash=task_hash,
            step_fragment=step_fragment,
            sample_fragment=sample_fragment,
            step_rows=int(fragments["per_step"]["rows"]),
            sample_rows=int(fragments["per_sample"]["rows"]),
            step_sha256=str(fragments["per_step"]["sha256"]),
            sample_sha256=str(fragments["per_sample"]["sha256"]),
        )
    else:
        entry = store.ledger["tasks"][task_hash]
    completed = dict(summary)
    completed["status"] = "completed"
    completed["completed_at_utc"] = _now()
    completed["aggregate_entry"] = entry
    completed.pop("staged_fragments", None)
    _atomic_json(summary_path, completed)
    stage_dir = summary_path.parents[2] / ".staging" / task_hash
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    return completed


def run_configuration(
    *,
    stage: str,
    seed: int,
    model_name: str,
    model: torch.nn.Module,
    threshold: float,
    pack: Any,
    clean_probs: np.ndarray,
    attack: str,
    steps: int,
    alpha_rule: str,
    initialization: str,
    restarts: int,
    projection: dict[str, Any],
    p2_config: dict[str, Any],
    p2_code_fingerprint: str,
    checkpoint_status: dict[str, Any],
    data_manifest: dict[str, Any],
    output_dir: Path,
    store: AggregateStore,
    device: torch.device,
) -> dict[str, Any]:
    config = _attack_config(
        attack=attack,
        steps=steps,
        alpha_rule=alpha_rule,
        initialization=initialization,
        restarts=restarts,
        seed=seed,
        projection=projection,
    )
    task_identity = {
        "stage": stage,
        "seed": int(seed),
        "model": model_name,
        "attack_config_hash": config.config_hash,
        "p2_config_hash": p2_config["config_hash"],
        "p2_code_fingerprint": p2_code_fingerprint,
        "checkpoint_sha256": checkpoint_status["checkpoint_sha256"],
        "checkpoint_manifest_sha256": checkpoint_status["checkpoint_manifest_sha256"],
        "dataset_hash": data_manifest["dataset_hash"],
        "split_hash": data_manifest["split_hash"],
        "normalization_hash": data_manifest["normalization_hash"],
        "sample_manifest_hash": data_manifest["sample_manifest_hash"],
        "threshold": float(threshold),
        "evaluation_batch_size": int(p2_config["identity"]["evaluation_batch_size"]),
    }
    logical_config_id = (
        _logical_config_id(
            seed=seed,
            model=model_name,
            attack=attack,
            steps=steps,
            alpha_rule=alpha_rule,
            initialization=initialization,
        )
        if stage == "p2a" and restarts == 1
        else None
    )
    task_identity["logical_config_id"] = logical_config_id
    task_hash = _canonical_hash(task_identity)
    summary_path = _summary_path(output_dir, task_hash)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    if summary_path.exists():
        prior = json.loads(summary_path.read_text(encoding="utf-8"))
        if prior.get("task_hash") != task_hash:
            raise RuntimeError(f"task summary hash mismatch: {summary_path}")
        if prior.get("status") == "completed" and store.has_task(task_hash):
            return prior
        if prior.get("status") == "ready_to_commit":
            return _commit_ready_summary(summary_path, prior, store)
        if prior.get("status") == "completed" and not store.has_task(task_hash):
            raise RuntimeError("completed task is absent from aggregate ledger")

    labels = pack.test_loader.dataset.y.numpy().astype(np.int64)
    X = pack.test_loader.dataset.X
    metadata = pack.audit_metadata["test"]
    malicious_indices = np.flatnonzero(labels == 1)
    clean_mal_probs = clean_probs[malicious_indices]
    clean_mal_pred = clean_mal_probs >= threshold
    batch_size = int(p2_config["identity"]["evaluation_batch_size"])
    physical = attack in PHYSICAL_ATTACKS

    stage_dir = output_dir / ".staging" / task_hash
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)
    step_fragment = stage_dir / "per_step.csv.gz"
    sample_fragment = stage_dir / "per_sample.csv.gz"
    step_stream = gzip.open(step_fragment, "wt", encoding="utf-8", newline="", compresslevel=9)
    step_writer = csv.DictWriter(
        step_stream,
        fieldnames=list(STEP_FIELDS),
        extrasaction="ignore",
        lineterminator="\n",
    )
    if store.is_empty:
        step_writer.writeheader()

    candidate_names = (
        "final_iterate",
        "best_target_loss_iterate",
        "first_threshold_success_iterate",
        "first_argmax_success_iterate",
        "best_feasible_successful_iterate",
        "best_feasible_iterate",
    )
    candidate_parts: dict[str, list[np.ndarray]] = {name: [] for name in candidate_names}
    final_probs_parts: list[np.ndarray] = []
    best_probs_parts: list[np.ndarray] = []
    final_valid_parts: list[np.ndarray] = []
    best_valid_parts: list[np.ndarray] = []
    source_valid_parts: list[np.ndarray] = []
    init_any_parts: list[np.ndarray] = []
    projection_failure_parts: list[np.ndarray] = []
    budget_invalid_parts: list[np.ndarray] = []
    kinematic_invalid_parts: list[np.ndarray] = []
    selected_final_restart_parts: list[np.ndarray] = []
    selected_best_restart_parts: list[np.ndarray] = []
    selected_best_step_parts: list[np.ndarray] = []
    first_threshold_step_parts: list[np.ndarray] = []
    first_argmax_step_parts: list[np.ndarray] = []
    best_feasible_success_step_parts: list[np.ndarray] = []
    per_restart_success_parts: list[np.ndarray] = []

    restart_digests = [hashlib.sha256() for _ in range(restarts)]
    step_rows = 0
    native_index_pass = True
    budget_pass = True
    feasible_init_pass = True
    projection_checker_pass = True
    finite_error_count = 0
    rebound_count = rebound_total = 0
    reversal_count = reversal_total = 0
    success_loss_count = success_loss_total = 0
    boundary_duration_sum = boundary_duration_total = 0
    boundary_hit_steps: list[int] = []
    projection_damage_sum = projection_damage_total = 0
    projection_pre_ce_sum = projection_post_ce_sum = 0.0
    projection_reversal_count = projection_reversal_total = 0
    projection_call_count = projection_converged_count = projection_source_valid_count = 0
    initialization_failure_events = 0

    try:
        for batch_start in range(0, len(malicious_indices), batch_size):
            indices = malicious_indices[batch_start : batch_start + batch_size]
            clean_batch = X[indices].to(device=device, dtype=torch.float32)
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
            selection = _selection_indices(result, physical=physical)
            diagnostics = result.per_step_diagnostics
            diag_restarts = np.asarray([item["restart_id"] for item in diagnostics], dtype=np.int64)
            diag_steps = np.asarray([item["step"] for item in diagnostics], dtype=np.int64)
            expected_pairs = [(r, s) for r in range(restarts) for s in range(steps + 1)]
            observed_pairs = list(zip(diag_restarts.tolist(), diag_steps.tolist()))
            native_index_pass &= observed_pairs == expected_pairs
            if not native_index_pass:
                raise AssertionError("P2 requires native, complete step/restart_id values")

            ce = np.asarray([item["target_ce"] for item in diagnostics], dtype=np.float64).reshape(
                restarts, steps + 1, len(indices)
            )
            margin = np.asarray(
                [item["z_normal_minus_z_anomaly"] for item in diagnostics], dtype=np.float64
            ).reshape(restarts, steps + 1, len(indices))
            threshold_success = np.asarray(
                [item["threshold_success"] for item in diagnostics], dtype=bool
            ).reshape(restarts, steps + 1, len(indices))
            boundary = np.asarray(
                [item["raw_boundary_saturation_rate"] for item in diagnostics], dtype=np.float64
            ).reshape(restarts, steps + 1, len(indices))
            pre_ce = np.asarray(
                [item["pre_projection_target_ce"] for item in diagnostics], dtype=np.float64
            ).reshape(restarts, steps + 1, len(indices))
            post_ce = np.asarray(
                [item["post_projection_target_ce"] for item in diagnostics], dtype=np.float64
            ).reshape(restarts, steps + 1, len(indices))
            projection_status = np.asarray(
                [item["projection_status"] for item in diagnostics], dtype=object
            ).reshape(restarts, steps + 1, len(indices))
            projection_converged = np.asarray(
                [item["projection_converged"] for item in diagnostics], dtype=bool
            ).reshape(restarts, steps + 1, len(indices))
            projection_checked = np.asarray(
                [item["projection_independently_checked"] for item in diagnostics], dtype=bool
            ).reshape(restarts, steps + 1, len(indices))
            source_valid = np.asarray(diagnostics[0]["source_valid"], dtype=bool)
            feasible = np.asarray([item["feasible"] for item in diagnostics], dtype=bool)
            budget_valid = np.asarray([item["budget_valid"] for item in diagnostics], dtype=bool)
            kinematic_valid = np.asarray([item["kinematic_valid"] for item in diagnostics], dtype=bool)
            init_success = np.asarray(
                [item.success for item in result.initialization_status], dtype=bool
            ).reshape(restarts, len(indices))
            initialization_failure_events += int((~init_success).sum())
            init_any = init_success.any(axis=0)

            rebound_count += int((ce[:, 1:] > ce[:, :-1]).sum())
            rebound_total += int(ce[:, 1:].size)
            delta_margin = margin[:, 1:] - margin[:, :-1]
            if delta_margin.shape[1] > 1:
                reversal_count += int(((delta_margin[:, :-1] > 0) & (delta_margin[:, 1:] < 0)).sum())
                reversal_total += int(delta_margin[:, 1:].size)
            success_loss_count += int((threshold_success[:, :-1].any(axis=1) & ~threshold_success[:, -1]).sum())
            success_loss_total += int(restarts * len(indices))
            boundary_duration_sum += int((boundary > 0).sum())
            boundary_duration_total += int(boundary.size)
            for restart_id in range(restarts):
                for sample in range(len(indices)):
                    hits = np.flatnonzero(boundary[restart_id, :, sample] > 0)
                    if len(hits):
                        boundary_hit_steps.append(int(hits[0]))
            update_slice = (slice(None), slice(0, steps), slice(None))
            damage = post_ce[update_slice] - pre_ce[update_slice]
            finite_damage = np.isfinite(damage)
            projection_damage_sum += float(damage[finite_damage].sum())
            projection_damage_total += int(finite_damage.sum())
            improved = pre_ce[update_slice] < ce[update_slice]
            reversed_by_projection = improved & (post_ce[update_slice] >= ce[update_slice])
            projection_reversal_count += int(reversed_by_projection.sum())
            projection_reversal_total += int(improved.sum())
            actual_projection = projection_status != "not_required"
            projection_call_count += int(actual_projection.sum())
            projection_converged_count += int((actual_projection & projection_converged).sum())
            projection_source_valid_count += int((actual_projection & source_valid[None, None, :]).sum())
            projection_pre_ce_sum += float(pre_ce[actual_projection].sum())
            projection_post_ce_sum += float(post_ce[actual_projection].sum())
            projection_checker_pass &= bool((~projection_converged | projection_checked).all())
            finite_error_count += int((~np.isfinite(ce)).sum())
            budget_pass &= bool(budget_valid.all())
            if initialization == "feasible_random":
                init_rows = np.arange(restarts) * (steps + 1)
                init_feasible = feasible[init_rows]
                feasible_init_pass &= bool((~init_success | init_feasible.reshape(restarts, len(indices))).all())

            for restart_id in range(restarts):
                restart_mask = diag_restarts == restart_id
                restart_digests[restart_id].update(
                    np.asarray(metadata["sample_id"][indices]).astype("U").tobytes()
                )
                for values in (ce[restart_id], margin[restart_id], threshold_success[restart_id]):
                    _update_digest(restart_digests[restart_id], values)
                _update_digest(
                    restart_digests[restart_id],
                    feasible[restart_mask],
                )

            for name in candidate_names:
                candidate_parts[name].append(_candidate_numpy(getattr(result, name), clean_batch))

            final_valid = (result.final_restart_id >= 0).detach().cpu().numpy().astype(bool)
            if physical:
                final_valid &= result.final_feasible.detach().cpu().numpy().astype(bool)
            final_tensor = result.final_iterate.detach().clone()
            final_valid_tensor = torch.as_tensor(final_valid, device=device)
            final_tensor[~final_valid_tensor] = clean_batch[~final_valid_tensor]

            if physical:
                best_tensor = result.best_feasible_iterate
                if best_tensor is None:
                    best_tensor = torch.full_like(clean_batch, float("nan"))
                best_valid = np.isfinite(best_tensor.detach().cpu().numpy()).all(axis=(1, 2))
            else:
                best_tensor = result.best_target_loss_iterate
                if best_tensor is None:
                    best_tensor = torch.full_like(clean_batch, float("nan"))
                best_valid = (result.restart_id >= 0).detach().cpu().numpy().astype(bool)
            best_main = best_tensor.detach().clone()
            best_valid_tensor = torch.as_tensor(best_valid, device=device)
            best_main[~best_valid_tensor] = clean_batch[~best_valid_tensor]
            final_probs_parts.append(_predict_candidate(model, final_tensor, device))
            best_probs_parts.append(_predict_candidate(model, best_main, device))
            final_valid_parts.append(final_valid)
            best_valid_parts.append(best_valid)
            source_valid_parts.append(source_valid)
            init_any_parts.append(init_any)
            active_cube = np.asarray(
                [item["candidate_active"] for item in diagnostics], dtype=bool
            ).reshape(restarts, steps + 1, len(indices))
            feasible_cube = feasible.reshape(restarts, steps + 1, len(indices))
            success_eligible = active_cube & threshold_success
            if physical:
                success_eligible &= feasible_cube
            per_restart_success_parts.append(success_eligible.any(axis=1))
            projection_failure_parts.append(
                ((projection_status != "not_required") & ~projection_converged).any(axis=(0, 1))
            )
            budget_invalid_parts.append((~budget_valid).any(axis=0))
            kinematic_invalid_parts.append((~kinematic_valid).any(axis=0))

            final_indices = selection["final"]
            best_indices = selection["best_feasible"] if physical else selection["best_loss"]
            first_threshold_indices = selection["first_threshold"]
            first_argmax_indices = selection["first_argmax"]
            best_success_indices = selection["best_feasible_success"]

            def selected_values(indices_array: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
                selected_restart = np.full(len(indices_array), -1, dtype=np.int64)
                selected_step = np.full(len(indices_array), -1, dtype=np.int64)
                ok = indices_array >= 0
                selected_restart[ok] = selection["restart_values"][indices_array[ok]]
                selected_step[ok] = selection["step_values"][indices_array[ok]]
                return selected_restart, selected_step

            selected_final_restart, _selected_final_step = selected_values(final_indices)
            selected_best_restart, selected_best_step = selected_values(best_indices)
            first_threshold_restart, first_threshold_step = selected_values(first_threshold_indices)
            first_argmax_restart, first_argmax_step = selected_values(first_argmax_indices)
            best_success_restart, best_success_step = selected_values(best_success_indices)
            selected_final_restart_parts.append(selected_final_restart)
            selected_best_restart_parts.append(selected_best_restart)
            selected_best_step_parts.append(selected_best_step)
            first_threshold_step_parts.append(first_threshold_step)
            first_argmax_step_parts.append(first_argmax_step)
            best_feasible_success_step_parts.append(best_success_step)

            clean_pred_batch = clean_mal_pred[batch_start : batch_start + len(indices)]
            for diag_index, diag in enumerate(diagnostics):
                restart_id = int(diag["restart_id"])
                step_id = int(diag["step"])
                if (restart_id, step_id) != expected_pairs[diag_index]:
                    raise AssertionError("step/restart_id was not written natively by the runner")
                for local_index, global_index in enumerate(indices):
                    attacked_pred = float(diag["p_anomaly"][local_index]) >= threshold
                    row = {
                        "stage": stage,
                        "task_hash": task_hash,
                        "attack_config_hash": config.config_hash,
                        "seed": seed,
                        "model": model_name,
                        "attack": attack,
                        "steps": steps,
                        "alpha_rule": alpha_rule,
                        "alpha": config.alpha,
                        "initialization": initialization,
                        "restarts": restarts,
                        "sample_id": str(metadata["sample_id"][global_index]),
                        "aircraft_id": str(metadata["aircraft_id"][global_index]),
                        "restart_id": restart_id,
                        "step": step_id,
                        "target_ce": diag["target_ce"][local_index],
                        "target_margin": diag["z_normal_minus_z_anomaly"][local_index],
                        "p_normal": diag["p_normal"][local_index],
                        "p_anomaly": diag["p_anomaly"][local_index],
                        "clean_tp_to_attack_fn": bool(clean_pred_batch[local_index] and not attacked_pred),
                        "clean_fn_to_attack_tp": bool((not clean_pred_batch[local_index]) and attacked_pred),
                        "final_candidate": bool(final_indices[local_index] == diag_index),
                        "best_loss_candidate": bool(selection["best_loss"][local_index] == diag_index),
                        "first_threshold_success_step": int(first_threshold_step[local_index]),
                        "first_threshold_success_restart": int(first_threshold_restart[local_index]),
                        "first_argmax_success_step": int(first_argmax_step[local_index]),
                        "first_argmax_success_restart": int(first_argmax_restart[local_index]),
                        "best_feasible_success_step": int(best_success_step[local_index]),
                        "best_feasible_success_restart": int(best_success_restart[local_index]),
                    }
                    aliases = {
                        "projection_status": "projection_status",
                        "zero_gradient_flag": "zero_gradient_flag",
                    }
                    for field in STEP_FIELDS:
                        source = aliases.get(field, field)
                        if field not in row and source in diag and isinstance(diag[source], list):
                            row[field] = diag[source][local_index]
                    step_writer.writerow({key: _float(row.get(key, "")) for key in STEP_FIELDS})
                    step_rows += 1
    finally:
        step_stream.close()

    arrays = {name: np.concatenate(parts, axis=0) for name, parts in candidate_parts.items()}
    arrays["sample_id"] = np.asarray(metadata["sample_id"][malicious_indices])
    arrays["selected_final_restart"] = np.concatenate(selected_final_restart_parts)
    arrays["selected_best_restart"] = np.concatenate(selected_best_restart_parts)
    arrays["selected_best_step"] = np.concatenate(selected_best_step_parts)
    candidate_path = summary_path.parent / "candidate_iterates.npz"

    final_probs = np.concatenate(final_probs_parts)
    best_probs = np.concatenate(best_probs_parts)
    final_valid = np.concatenate(final_valid_parts)
    best_valid = np.concatenate(best_valid_parts)
    source_valid = np.concatenate(source_valid_parts)
    init_any = np.concatenate(init_any_parts)
    projection_failure = np.concatenate(projection_failure_parts)
    any_budget_invalid = np.concatenate(budget_invalid_parts)
    any_kinematic_invalid = np.concatenate(kinematic_invalid_parts)
    selected_final_restart = np.concatenate(selected_final_restart_parts)
    selected_best_restart = np.concatenate(selected_best_restart_parts)
    selected_best_step = np.concatenate(selected_best_step_parts)
    first_threshold_step = np.concatenate(first_threshold_step_parts)
    first_argmax_step = np.concatenate(first_argmax_step_parts)
    best_success_step = np.concatenate(best_feasible_success_step_parts)
    per_restart_success = np.concatenate(per_restart_success_parts, axis=1)
    arrays["final_p_anomaly"] = final_probs
    arrays["best_p_anomaly"] = best_probs
    arrays["final_valid"] = final_valid
    arrays["best_valid"] = best_valid
    arrays["source_valid"] = source_valid
    arrays["initialization_success_any_restart"] = init_any
    arrays["per_restart_success"] = per_restart_success
    np.savez_compressed(candidate_path, **arrays)

    full_final_probs = clean_probs.copy()
    full_best_probs = clean_probs.copy()
    full_final_probs[malicious_indices] = final_probs
    full_best_probs[malicious_indices] = best_probs
    clean_metrics = _metrics(labels, clean_probs, threshold)
    final_metrics = _metrics(labels, full_final_probs, threshold)
    best_metrics = _metrics(labels, full_best_probs, threshold)
    clean_pred = clean_mal_probs >= threshold
    final_pred = final_probs >= threshold
    best_pred = best_probs >= threshold
    final_tp_fn = int((clean_pred & ~final_pred).sum())
    final_fn_tp = int((~clean_pred & final_pred).sum())
    best_tp_fn = int((clean_pred & ~best_pred).sum())
    best_fn_tp = int((~clean_pred & best_pred).sum())
    final_ce_each = -np.log(np.clip(1.0 - final_probs, 1e-12, 1.0))
    best_ce_each = -np.log(np.clip(1.0 - best_probs, 1e-12, 1.0))
    final_margin_each = np.log(np.clip(1.0 - final_probs, 1e-12, 1.0)) - np.log(
        np.clip(final_probs, 1e-12, 1.0)
    )
    best_margin_each = np.log(np.clip(1.0 - best_probs, 1e-12, 1.0)) - np.log(
        np.clip(best_probs, 1e-12, 1.0)
    )
    best_not_weaker = bool((best_ce_each <= final_ce_each + 1e-6).all())
    pv_denominator = int(source_valid.sum()) if physical else int(len(malicious_indices))
    pv_success = int((source_valid & best_valid & ~best_pred).sum()) if physical else int((~best_pred).sum())
    pv_asr = float(pv_success / pv_denominator) if pv_denominator else float("nan")
    restart_success_counts = per_restart_success.sum(axis=1).astype(int)
    restart_zero = per_restart_success[0]
    overlap_with_restart_zero = [
        int((restart_zero & per_restart_success[restart_id]).sum()) for restart_id in range(restarts)
    ]
    new_vs_restart_zero = [
        int((~restart_zero & per_restart_success[restart_id]).sum()) for restart_id in range(restarts)
    ]
    selected_restart_distribution = {
        str(restart_id): int((selected_best_restart == restart_id).sum()) for restart_id in range(restarts)
    }

    sample_rows: list[dict[str, Any]] = []
    malicious_lookup = {int(index): position for position, index in enumerate(malicious_indices)}
    for index in range(len(labels)):
        position = malicious_lookup.get(index)
        if position is None:
            attacked = False
            final_probability = best_probability = float(clean_probs[index])
            final_is_valid = best_is_valid = True
            source_is_valid = True
            init_is_valid = True
            selected_final = selected_best = selected_step = -1
            first_t = first_a = best_success = -1
            source_invalid = init_infeasible = projection_not_converged = False
            budget_invalid = kinematic_invalid = False
            valid_success = valid_failure = False
            failure_state = "not_attacked_normal_control"
        else:
            attacked = True
            final_probability = float(final_probs[position])
            best_probability = float(best_probs[position])
            final_is_valid = bool(final_valid[position])
            best_is_valid = bool(best_valid[position])
            source_is_valid = bool(source_valid[position])
            init_is_valid = bool(init_any[position])
            selected_final = int(selected_final_restart[position])
            selected_best = int(selected_best_restart[position])
            selected_step = int(selected_best_step[position])
            first_t = int(first_threshold_step[position])
            first_a = int(first_argmax_step[position])
            best_success = int(best_success_step[position])
            source_invalid = bool(physical and not source_is_valid)
            init_infeasible = bool(not init_is_valid)
            projection_not_converged = bool(projection_failure[position])
            budget_invalid = bool(any_budget_invalid[position])
            kinematic_invalid = bool(any_kinematic_invalid[position])
            valid_success = bool(best_is_valid and best_probability < threshold)
            valid_failure = bool(best_is_valid and not valid_success)
            if source_invalid:
                failure_state = "source_invalid"
            elif init_infeasible:
                failure_state = "initialization_infeasible"
            elif valid_success:
                failure_state = "valid_attack_success"
            elif valid_failure:
                failure_state = "valid_attack_failure"
            elif projection_not_converged:
                failure_state = "projection_not_converged"
            elif budget_invalid:
                failure_state = "budget_invalid"
            elif kinematic_invalid:
                failure_state = "kinematic_invalid"
            else:
                failure_state = "no_valid_candidate"
        clean_prediction = bool(clean_probs[index] >= threshold)
        final_prediction = bool(final_probability >= threshold)
        best_prediction = bool(best_probability >= threshold)
        sample_rows.append(
            {
                "stage": stage,
                "task_hash": task_hash,
                "attack_config_hash": config.config_hash,
                "seed": seed,
                "model": model_name,
                "attack": attack,
                "steps": steps,
                "alpha_rule": alpha_rule,
                "alpha": config.alpha,
                "initialization": initialization,
                "restarts": restarts,
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
                "clean_prediction": int(clean_prediction),
                "final_prediction": int(final_prediction),
                "best_prediction": int(best_prediction),
                "final_feasible": final_is_valid,
                "best_feasible": best_is_valid,
                "source_valid": source_is_valid,
                "initialization_success_any_restart": init_is_valid,
                "selected_final_restart": selected_final,
                "selected_best_restart": selected_best,
                "selected_best_step": selected_step,
                "first_threshold_success_step": first_t,
                "first_argmax_success_step": first_a,
                "best_feasible_success_step": best_success,
                "source_invalid": source_invalid,
                "initialization_infeasible": init_infeasible,
                "projection_not_converged": projection_not_converged,
                "budget_invalid": budget_invalid,
                "kinematic_invalid": kinematic_invalid,
                "valid_attack_failure": valid_failure,
                "valid_attack_success": valid_success,
                "clean_tp_to_final_fn": bool(labels[index] == 1 and clean_prediction and not final_prediction),
                "clean_fn_to_final_tp": bool(labels[index] == 1 and not clean_prediction and final_prediction),
                "clean_tp_to_best_fn": bool(labels[index] == 1 and clean_prediction and not best_prediction),
                "clean_fn_to_best_tp": bool(labels[index] == 1 and not clean_prediction and best_prediction),
                "failure_state": failure_state,
            }
        )
    sample_rows_count, sample_sha = _write_rows(
        sample_fragment, SAMPLE_FIELDS, sample_rows, header=store.is_empty
    )
    step_sha = sha256_file(step_fragment)

    normal_unchanged = bool(
        np.array_equal(full_final_probs[labels == 0], clean_probs[labels == 0])
        and np.array_equal(full_best_probs[labels == 0], clean_probs[labels == 0])
    )
    identity_checks = {
        "recall_plus_final_threshold_asr": abs(final_metrics["recall"] + final_metrics["threshold_asr"] - 1.0) <= 1e-12,
        "recall_plus_best_threshold_asr": abs(best_metrics["recall"] + best_metrics["threshold_asr"] - 1.0) <= 1e-12,
        "normal_samples_bitwise_unchanged": normal_unchanged,
        "final_far_equals_clean_far": final_metrics["far"] == clean_metrics["far"],
        "best_far_equals_clean_far": best_metrics["far"] == clean_metrics["far"],
        "attacked_normal_sample_count_zero": True,
        "transition_final_recall_correspondence": int(final_metrics["tp"] - clean_metrics["tp"]) == final_fn_tp - final_tp_fn,
        "transition_best_recall_correspondence": int(best_metrics["tp"] - clean_metrics["tp"]) == best_fn_tp - best_tp_fn,
        "native_step_restart_ids": native_index_pass,
        "best_iterate_not_weaker_than_final": best_not_weaker,
        "all_logged_candidates_within_budget": budget_pass,
        "feasible_random_initializations_in_intersection": feasible_init_pass,
        "projection_success_independently_checked": projection_checker_pass,
        "no_nan_target_ce": finite_error_count == 0,
    }
    summary = {
        "schema_version": P2_SCHEMA,
        "status": "ready_to_commit",
        "created_at_utc": _now(),
        "stage": stage,
        "task_hash": task_hash,
        "logical_config_id": logical_config_id,
        "execution_status": "executed",
        "reused_from": None,
        "task_identity": task_identity,
        "seed": seed,
        "model": model_name,
        "attack": attack,
        "steps": steps,
        "alpha_rule": alpha_rule,
        "alpha": float(config.alpha),
        "initialization": initialization,
        "restarts": restarts,
        "attack_config": asdict(config),
        "attack_config_hash": config.config_hash,
        "checkpoint_sha256": checkpoint_status["checkpoint_sha256"],
        "threshold": float(threshold),
        "support": {
            "total": int(len(labels)),
            "normal": int((labels == 0).sum()),
            "anomaly": int((labels == 1).sum()),
            "attacked_normal": 0,
            "v0": int(source_valid.sum()),
            "source_invalid": int((~source_valid).sum()),
            "initialized_any_restart": int(init_any.sum()),
            "initialization_infeasible": int((~init_any).sum()),
            "initialization_failure_events": int(initialization_failure_events),
            "final_valid": int(final_valid.sum()),
            "best_valid": int(best_valid.sum()),
            "projection_not_converged_any": int(projection_failure.sum()),
            "valid_attack_success": int((best_valid & ~best_pred).sum()),
            "valid_attack_failure": int((best_valid & best_pred).sum()),
        },
        "clean_metrics": clean_metrics,
        "final_metrics": final_metrics,
        "best_metrics": best_metrics,
        "pv_asr_v0": pv_asr,
        "pv_success": pv_success,
        "pv_denominator_v0": pv_denominator,
        "final_target_ce_mean": float(final_ce_each.mean()),
        "final_target_ce_median": float(np.median(final_ce_each)),
        "best_target_ce_mean": float(best_ce_each.mean()),
        "best_target_ce_median": float(np.median(best_ce_each)),
        "final_target_margin_mean": float(final_margin_each.mean()),
        "best_target_margin_mean": float(best_margin_each.mean()),
        "final_best_asr_gap": float(best_metrics["threshold_asr"] - final_metrics["threshold_asr"]),
        "final_best_target_ce_gap": float(final_ce_each.mean() - best_ce_each.mean()),
        "transitions": {
            "final_clean_tp_to_attack_fn": final_tp_fn,
            "final_clean_fn_to_attack_tp": final_fn_tp,
            "best_clean_tp_to_attack_fn": best_tp_fn,
            "best_clean_fn_to_attack_tp": best_fn_tp,
        },
        "overshoot": {
            "target_loss_rebound_rate": float(rebound_count / rebound_total) if rebound_total else 0.0,
            "margin_reversal_rate": float(reversal_count / reversal_total) if reversal_total else 0.0,
            "margin_reversal_count": int(reversal_count),
            "success_loss_rate": float(success_loss_count / success_loss_total) if success_loss_total else 0.0,
            "boundary_hit_step_median": float(np.median(boundary_hit_steps)) if boundary_hit_steps else None,
            "boundary_saturation_duration": float(boundary_duration_sum / boundary_duration_total) if boundary_duration_total else 0.0,
            "projection_damage_mean": float(projection_damage_sum / projection_damage_total) if projection_damage_total else 0.0,
            "projection_reversal_rate": float(projection_reversal_count / projection_reversal_total) if projection_reversal_total else 0.0,
        },
        "projection": {
            "calls": int(projection_call_count),
            "converged": int(projection_converged_count),
            "source_valid_calls": int(projection_source_valid_count),
            "convergence_rate": float(projection_converged_count / projection_call_count) if projection_call_count else 1.0,
            "pre_target_ce_mean": float(projection_pre_ce_sum / projection_call_count) if projection_call_count else None,
            "post_target_ce_mean": float(projection_post_ce_sum / projection_call_count) if projection_call_count else None,
        },
        "restart_diagnostics": {
            "success_counts_by_restart": restart_success_counts.tolist(),
            "overlap_with_restart_zero": overlap_with_restart_zero,
            "new_successes_vs_restart_zero": new_vs_restart_zero,
            "union_success_count": int(per_restart_success.any(axis=0).sum()),
            "intersection_success_count": int(per_restart_success.all(axis=0).sum()),
            "selected_strongest_restart_distribution": selected_restart_distribution,
        },
        "restart_fingerprints": [digest.hexdigest() for digest in restart_digests],
        "identity_checks": identity_checks,
        "identity_pass": all(identity_checks.values()),
        "candidate_artifact": {
            "path": str(candidate_path.relative_to(output_dir).as_posix()),
            "sha256": sha256_file(candidate_path),
            "size_bytes": candidate_path.stat().st_size,
        },
        "staged_fragments": {
            "per_step": {
                "absolute_path": str(step_fragment),
                "rows": int(step_rows),
                "sha256": step_sha,
                "size_bytes": step_fragment.stat().st_size,
            },
            "per_sample": {
                "absolute_path": str(sample_fragment),
                "rows": int(sample_rows_count),
                "sha256": sample_sha,
                "size_bytes": sample_fragment.stat().st_size,
            },
        },
    }
    _atomic_json(summary_path, summary)
    return _commit_ready_summary(summary_path, summary, store)


def _append_failed(output_dir: Path, record: dict[str, Any]) -> None:
    path = output_dir / "failed_runs.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(_json_safe(record), sort_keys=True, ensure_ascii=False) + "\n")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_config_hash(payload: dict[str, Any], name: str) -> None:
    expected = payload.get("config_hash")
    actual = _canonical_hash({key: value for key, value in payload.items() if key != "config_hash"})
    if expected != actual:
        raise RuntimeError(f"{name} hash mismatch: expected={expected} actual={actual}")
    if _contains_null(payload):
        raise RuntimeError(f"{name} contains an unresolved null field")


def initialize_freeze(project_root: Path, output_dir: Path) -> dict[str, Any]:
    config_root = project_root / "configs" / "attack_audit_c001"
    p2_config = _load_json(config_root / "p2_audit_manifest.json")
    projection = _load_json(config_root / "projection_config.json")
    _validate_config_hash(p2_config, "p2_audit_manifest")
    _validate_config_hash(projection, "projection_config")
    p1_root = project_root / "outputs" / "attack_audit_c001" / "p1"
    p1_gate = _load_json(p1_root / "p1_integrity_gate.json")
    p1_verdict = _load_json(p1_root / "p1_step_convergence_verdict.json")
    required = {
        "checkpoint_integrity_gate": "PASS",
        "data_identity_gate": "PASS",
        "p1_integrity_gate": "PASS",
    }
    if any(p1_gate.get(key) != value for key, value in required.items()):
        raise RuntimeError("P1 prerequisite gate is not PASS")
    if p1_verdict.get("verdict") != "NOT CONVERGED":
        raise RuntimeError("P2 requires the frozen P1 NOT CONVERGED verdict")
    if int(p2_config["p2_a"]["logical_configurations"]) != 640:
        raise RuntimeError("P2-A manifest must contain exactly 640 logical configurations")
    execution_fingerprint = code_fingerprint(project_root)
    freeze = {
        "schema_version": "adsb.c001-p2-configuration-freeze.v1",
        "created_at_utc": _now(),
        "p2_config": p2_config,
        "p2_config_hash": p2_config["config_hash"],
        "projection_config": projection,
        "projection_config_hash": projection["config_hash"],
        "p2_execution_code_fingerprint": execution_fingerprint,
        "p1_integrity_gate_sha256": sha256_file(p1_root / "p1_integrity_gate.json"),
        "p1_step_verdict_sha256": sha256_file(p1_root / "p1_step_convergence_verdict.json"),
        "p1_artifact_manifest_sha256": sha256_file(p1_root / "artifact_hashes.json"),
        "result_direction_used_for_scheduling": False,
        "p3_to_p6_executed": False,
    }
    freeze["freeze_hash"] = _canonical_hash(freeze)
    freeze_path = output_dir / "p2_configuration_freeze.json"
    if freeze_path.exists():
        prior = _load_json(freeze_path)
        for key in (
            "p2_config_hash",
            "projection_config_hash",
            "p2_execution_code_fingerprint",
            "p1_integrity_gate_sha256",
            "p1_step_verdict_sha256",
            "p1_artifact_manifest_sha256",
        ):
            if prior.get(key) != freeze.get(key):
                raise RuntimeError(f"immutable P2 freeze changed at {key}")
        freeze = prior
    else:
        _atomic_json(freeze_path, freeze)
    _atomic_json(
        output_dir / "p2_alpha_selection_rules.json",
        {
            "schema_version": "adsb.c001-p2-alpha-selection.v1",
            "p2_config_hash": p2_config["config_hash"],
            "rules": p2_config["alpha_selection"],
            "large_scale_projection_failure_operationalization": (
                "exclude only when fewer than half of logged projection calls converge; "
                "identity failures and non-finite target CE are always excluded"
            ),
            "asr_tie_policy": "secondary criteria apply only to an exact pooled success-count tie",
            "result_direction_or_cat_ad_advantage_used": False,
        },
    )
    return {"p2_config": p2_config, "projection": projection, "freeze": freeze, "p1_root": p1_root}


def _prepare_dataframe(project_root: Path) -> pd.DataFrame:
    loaded = load_data(project_root / "sample_adsb_decoded.csv")
    filtered = filter_data(loaded)
    return subset_df_by_aircraft(filtered, max_aircraft=None, random_state=42)


def build_logical_configuration_manifest(
    *,
    output_dir: Path,
    p1_root: Path,
    p2_config: dict[str, Any],
    projection: dict[str, Any],
    p2_code_fingerprint: str,
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for seed in SEEDS:
        p1_data = _load_json(p1_root / "data" / f"seed_{seed}" / "data_version_manifest.json")
        for model in MODELS:
            checkpoint_status = _load_json(
                p1_root / "training" / f"seed_{seed}" / _checkpoint_slug(model) / "status.json"
            )
            for attack in ATTACKS:
                for steps in STEPS:
                    for alpha_rule in ALPHA_RULES:
                        for initialization in ALL_INITIALIZATIONS[attack]:
                            config = _attack_config(
                                attack=attack,
                                steps=steps,
                                alpha_rule=alpha_rule,
                                initialization=initialization,
                                restarts=1,
                                seed=seed,
                                projection=projection,
                            )
                            logical_id = _logical_config_id(
                                seed=seed,
                                model=model,
                                attack=attack,
                                steps=steps,
                                alpha_rule=alpha_rule,
                                initialization=initialization,
                            )
                            p1_summary_path = (
                                p1_root
                                / "attack_runs"
                                / f"seed_{seed}"
                                / _model_slug(model)
                                / attack
                                / f"k{steps}"
                                / "summary.json"
                            )
                            candidate = alpha_rule == "fixed_003" and initialization == "clean" and p1_summary_path.exists()
                            source_hash = sha256_file(p1_summary_path) if candidate else ""
                            checks: dict[str, bool] = {
                                "checkpoint_sha256": False,
                                "dataset_hash": False,
                                "split_hash": False,
                                "normalization_hash": False,
                                "sample_manifest_hash": False,
                                "code_fingerprint": False,
                                "attack_id": False,
                                "K": False,
                                "epsilon": False,
                                "alpha": False,
                                "initialization": False,
                                "loss": False,
                                "threshold": False,
                                "budget_scope": False,
                                "projection_configuration": False,
                                "candidate_selection_policy": False,
                                "config_hash": False,
                            }
                            if candidate:
                                p1_summary = _load_json(p1_summary_path)
                                p1_attack = p1_summary["attack_config"]
                                checks.update(
                                    {
                                        "checkpoint_sha256": p1_summary["checkpoint_sha256"] == checkpoint_status["checkpoint_sha256"],
                                        "dataset_hash": checkpoint_status["identity"]["dataset_hash"] == p1_data["dataset_hash"],
                                        "split_hash": checkpoint_status["identity"]["split_hash"] == p1_data["split_hash"],
                                        "normalization_hash": checkpoint_status["normalization_hash"] == p1_data["normalization_hash"],
                                        "sample_manifest_hash": bool(p1_data.get("sample_manifest_hash")),
                                        "code_fingerprint": checkpoint_status["identity"]["code_fingerprint"] == p2_code_fingerprint,
                                        "attack_id": p1_attack["attack_id"] == attack,
                                        "K": int(p1_attack["steps"]) == steps,
                                        "epsilon": float(p1_attack["epsilon"]) == float(config.epsilon),
                                        "alpha": float(p1_attack["alpha"]) == float(config.alpha),
                                        "initialization": p1_attack["initialization"] == initialization,
                                        "loss": p1_attack["loss"] == config.loss,
                                        "threshold": float(p1_summary["threshold"]) == float(checkpoint_status["threshold"]),
                                        "budget_scope": p1_attack["budget_scope"] == config.budget_scope,
                                        "projection_configuration": all(
                                            p1_attack.get(key) == asdict(config).get(key)
                                            for key in (
                                                "projection_schedule",
                                                "budget_abs_tol",
                                                "kinematic_rel_tol",
                                                "projection_residual_tol",
                                                "maximum_alternating_projection_iterations",
                                                "feasible_random_resampling_count",
                                            )
                                        ),
                                        # P1 did not freeze this policy as an explicit identity field.
                                        "candidate_selection_policy": p1_summary.get("candidate_selection_policy")
                                        == p2_config["threat_model"]["candidate_policy"],
                                        "config_hash": p1_summary["attack_config_hash"] == config.config_hash,
                                    }
                                )
                            reusable = candidate and all(checks.values())
                            rows.append(
                                {
                                    "logical_config_id": logical_id,
                                    "seed": seed,
                                    "model": model,
                                    "attack": attack,
                                    "K": steps,
                                    "alpha_rule": alpha_rule,
                                    "alpha": config.alpha,
                                    "initialization": initialization,
                                    "restarts": 1,
                                    "attack_config_hash": config.config_hash,
                                    "execution_status": "reused" if reusable else "scheduled_new",
                                    "reused_from": "P1" if reusable else "",
                                    "source_artifact_hash": source_hash,
                                    "independent_metric_recalculation_status": "pending" if reusable else "not_applicable_new_execution",
                                    "reuse_eligible": reusable,
                                    "reuse_checks": json.dumps(checks, sort_keys=True),
                                    "task_hash": "",
                                }
                            )
    frame = pd.DataFrame(rows)
    if len(frame) != 640 or frame["logical_config_id"].nunique() != 640:
        raise RuntimeError("P2 logical configuration manifest does not contain exactly 640 unique records")
    frame.to_csv(output_dir / "p2_logical_configuration_manifest.csv", index=False)
    return frame


def update_logical_configuration_status(output_dir: Path) -> pd.DataFrame:
    path = output_dir / "p2_logical_configuration_manifest.csv"
    frame = pd.read_csv(path, dtype={"logical_config_id": str, "task_hash": str})
    summaries = {
        row["logical_config_id"]: row
        for row in _all_summaries(output_dir, status="completed")
        if row.get("stage") == "p2a" and row.get("logical_config_id")
    }
    for index, row in frame.iterrows():
        logical_id = str(row["logical_config_id"])
        if row["execution_status"] == "reused":
            continue
        summary = summaries.get(logical_id)
        if summary is not None:
            frame.at[index, "execution_status"] = "executed"
            frame.at[index, "task_hash"] = summary["task_hash"]
            frame.at[index, "independent_metric_recalculation_status"] = "not_applicable_new_execution"
    frame.to_csv(path, index=False)
    return frame


def prepare_seed(
    *,
    project_root: Path,
    output_dir: Path,
    p1_root: Path,
    dataframe: pd.DataFrame,
    seed: int,
    device: torch.device,
) -> tuple[Any, dict[str, Any]]:
    set_seed(seed)
    pack, manifest, _comparison = build_data_version(
        dataframe,
        seed,
        pin_memory=device.type == "cuda",
        output_dir=output_dir,
        legacy_root=project_root / "outputs" / "publication_benchmark",
    )
    p1_manifest = _load_json(p1_root / "data" / f"seed_{seed}" / "data_version_manifest.json")
    identity_fields = (
        "dataset_hash",
        "source_csv_sha256",
        "injection_config_hash",
        "split_hash",
        "normalization_hash",
        "sample_manifest_hash",
    )
    checks = {field: manifest.get(field) == p1_manifest.get(field) for field in identity_fields}
    if not all(checks.values()):
        raise RuntimeError(f"P2 data identity differs from P1 for seed {seed}: {checks}")
    return pack, {"manifest": manifest, "identity_checks": checks}


def load_p1_model(
    *,
    p1_root: Path,
    seed: int,
    model_name: str,
    pack: Any,
    device: torch.device,
) -> tuple[torch.nn.Module, float, dict[str, Any], np.ndarray, dict[str, Any]]:
    slug = _checkpoint_slug(model_name)
    run_dir = p1_root / "training" / f"seed_{seed}" / slug
    status = _load_json(run_dir / "status.json")
    checkpoint_path = run_dir / "checkpoint.pt"
    sidecar_path = checkpoint_manifest_path(checkpoint_path)
    if status.get("status") != "completed":
        raise RuntimeError(f"P1 checkpoint is not completed: seed={seed} model={model_name}")
    hash_checks = {
        "checkpoint_sha256": sha256_file(checkpoint_path) == status["checkpoint_sha256"],
        "checkpoint_manifest_sha256": sha256_file(sidecar_path) == status["checkpoint_manifest_sha256"],
        "normalization_hash": normalization_hash(pack.norm_mean, pack.norm_std) == status["normalization_hash"],
    }
    expected_identity = CheckpointIdentity(**status["identity"])
    model, threshold, _mean, _std, _dim = load_verified_detector_checkpoint(
        checkpoint_path,
        device,
        expected_identity=expected_identity,
        expected_norm_mean=pack.norm_mean,
        expected_norm_std=pack.norm_std,
    )
    hash_checks["threshold"] = float(threshold) == float(status["threshold"])
    if not all(hash_checks.values()):
        raise RuntimeError(f"P1 checkpoint identity mismatch: seed={seed} model={model_name} {hash_checks}")
    logits = _predict_logits(model, pack.test_loader.dataset.X, device)
    clean_probs = _probabilities(logits)
    clean_file = p1_root / "clean" / f"seed_{seed}_{_model_slug(model_name)}_samples.csv.gz"
    archived = pd.read_csv(clean_file)
    sample_ids = np.asarray(pack.audit_metadata["test"]["sample_id"]).astype(str)
    probability_max_abs = float(np.max(np.abs(archived["p_anomaly"].to_numpy() - clean_probs)))
    clean_checks = {
        "sample_order": np.array_equal(archived["sample_id"].astype(str).to_numpy(), sample_ids),
        "labels": np.array_equal(
            archived["original_label"].to_numpy(dtype=np.int64),
            pack.test_loader.dataset.y.numpy().astype(np.int64),
        ),
        "probabilities_within_csv_roundtrip_tolerance": np.allclose(
            archived["p_anomaly"].to_numpy(), clean_probs, atol=1e-7, rtol=1e-7
        ),
    }
    if not all(clean_checks.values()):
        raise RuntimeError(
            f"P2 clean reproduction differs from P1: seed={seed} model={model_name} "
            f"checks={clean_checks} max_abs={probability_max_abs}"
        )
    return model, float(threshold), status, clean_probs, {
        **hash_checks,
        **clean_checks,
        "clean_probability_max_abs_csv_roundtrip": probability_max_abs,
        "clean_probability_atol": 1e-7,
        "clean_probability_rtol": 1e-7,
    }


def _all_summaries(output_dir: Path, *, status: str | None = None) -> list[dict[str, Any]]:
    summaries = []
    task_root = output_dir / "tasks"
    if not task_root.exists():
        return summaries
    for path in sorted(task_root.glob("*/summary.json")):
        row = _load_json(path)
        if status is None or row.get("status") == status:
            summaries.append(row)
    return summaries


def _write_progress_manifest(
    output_dir: Path,
    *,
    freeze: dict[str, Any],
    phase: str,
    checkpoint_rows: list[dict[str, Any]],
) -> None:
    completed = _all_summaries(output_dir, status="completed")
    payload = {
        "schema_version": P2_SCHEMA,
        "updated_at_utc": _now(),
        "phase": phase,
        "p2_config_hash": freeze["p2_config_hash"],
        "p2_freeze_hash": freeze["freeze_hash"],
        "p2_execution_code_fingerprint": freeze["p2_execution_code_fingerprint"],
        "completed_unique_tasks": len(completed),
        "completed_p2a_tasks": sum(row.get("stage") == "p2a" for row in completed),
        "completed_p2b_tasks": sum(row.get("stage") == "p2b" for row in completed),
        "checkpoint_identity_rows": checkpoint_rows,
        "p3_to_p6_executed": False,
        "paper_modified": False,
    }
    logical_path = output_dir / "p2_logical_configuration_manifest.csv"
    if logical_path.exists():
        logical = pd.read_csv(logical_path)
        payload.update(
            {
                "logical_configuration_manifest": logical_path.name,
                "logical_configurations": int(len(logical)),
                "reused_p1_configurations": int((logical["execution_status"] == "reused").sum()),
                "scheduled_or_executed_new_configurations": int(
                    logical["execution_status"].isin(["scheduled_new", "executed"]).sum()
                ),
            }
        )
    _atomic_json(output_dir / "p2_manifest.json", payload)


def run_p2a(project_root: Path, output_dir: Path) -> None:
    context = initialize_freeze(project_root, output_dir)
    p2_config = context["p2_config"]
    projection = context["projection"]
    freeze = context["freeze"]
    p1_root = context["p1_root"]
    store = AggregateStore(output_dir)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    dataframe = _prepare_dataframe(project_root)
    checkpoint_rows: list[dict[str, Any]] = []
    for seed in SEEDS:
        print(f"\n=== P2-A repeated split {seed}: identity ===", flush=True)
        pack, data_status = prepare_seed(
            project_root=project_root,
            output_dir=output_dir,
            p1_root=p1_root,
            dataframe=dataframe,
            seed=seed,
            device=device,
        )
        for model_name in MODELS:
            model, threshold, checkpoint_status, clean_probs, model_checks = load_p1_model(
                p1_root=p1_root,
                seed=seed,
                model_name=model_name,
                pack=pack,
                device=device,
            )
            checkpoint_rows.append(
                {"seed": seed, "model": model_name, "data": data_status["identity_checks"], "checkpoint": model_checks}
            )
            for attack in ATTACKS:
                for steps in STEPS:
                    for alpha_rule in ALPHA_RULES:
                        for initialization in ALL_INITIALIZATIONS[attack]:
                            print(
                                f"P2-A seed={seed} model={model_name} attack={attack} "
                                f"K={steps} alpha={alpha_rule} init={initialization} R=1",
                                flush=True,
                            )
                            try:
                                run_configuration(
                                    stage="p2a",
                                    seed=seed,
                                    model_name=model_name,
                                    model=model,
                                    threshold=threshold,
                                    pack=pack,
                                    clean_probs=clean_probs,
                                    attack=attack,
                                    steps=steps,
                                    alpha_rule=alpha_rule,
                                    initialization=initialization,
                                    restarts=1,
                                    projection=projection,
                                    p2_config=p2_config,
                                    p2_code_fingerprint=freeze["p2_execution_code_fingerprint"],
                                    checkpoint_status=checkpoint_status,
                                    data_manifest=data_status["manifest"],
                                    output_dir=output_dir,
                                    store=store,
                                    device=device,
                                )
                            except Exception as exc:
                                failure = {
                                    "schema_version": P2_SCHEMA,
                                    "status": "failed",
                                    "stage": "p2a",
                                    "seed": seed,
                                    "model": model_name,
                                    "attack": attack,
                                    "steps": steps,
                                    "alpha_rule": alpha_rule,
                                    "initialization": initialization,
                                    "restarts": 1,
                                    "error_type": type(exc).__name__,
                                    "error": str(exc),
                                    "traceback": traceback.format_exc(),
                                    "failed_at_utc": _now(),
                                }
                                _append_failed(output_dir, failure)
                                print(json.dumps(_json_safe(failure), ensure_ascii=False), flush=True)
                            _write_progress_manifest(
                                output_dir,
                                freeze=freeze,
                                phase="p2a_running",
                                checkpoint_rows=checkpoint_rows,
                            )
            del model
            if device.type == "cuda":
                torch.cuda.empty_cache()
    p2a = [row for row in _all_summaries(output_dir, status="completed") if row.get("stage") == "p2a"]
    if len(p2a) != 640:
        raise RuntimeError(f"P2-A incomplete: completed {len(p2a)}/640")
    if not all(row.get("identity_pass") for row in p2a):
        raise RuntimeError("P2-A contains an integrity failure")
    logical = update_logical_configuration_status(output_dir)
    if len(logical) != 640 or not logical["execution_status"].isin(["executed", "reused"]).all():
        raise RuntimeError("P2-A logical manifest is incomplete after execution")
    _write_progress_manifest(output_dir, freeze=freeze, phase="p2a_complete", checkpoint_rows=checkpoint_rows)


def select_attack_alphas(output_dir: Path, p2_config: dict[str, Any]) -> dict[str, Any]:
    p2a = [row for row in _all_summaries(output_dir, status="completed") if row.get("stage") == "p2a"]
    if len(p2a) != 640:
        raise RuntimeError(f"alpha selection requires 640 completed P2-A tasks, found {len(p2a)}")
    selection: dict[str, Any] = {
        "schema_version": "adsb.c001-p2-selected-configs.v1",
        "selected_at_utc": _now(),
        "p2_config_hash": p2_config["config_hash"],
        "selection_scope": p2_config["alpha_selection"]["scope"],
        "cat_ad_advantage_used": False,
        "attacks": {},
    }
    for attack in ATTACKS:
        candidates = []
        for rule in ALPHA_RULES:
            rows = [row for row in p2a if row["attack"] == attack and row["alpha_rule"] == rule]
            success = sum(int(row["support"]["valid_attack_success"]) for row in rows)
            denominator = sum(int(row["support"]["anomaly"]) for row in rows)
            pooled_asr = float(success / denominator) if denominator else float("nan")
            weighted_ce = sum(
                float(row["best_target_ce_mean"]) * int(row["support"]["anomaly"]) for row in rows
            ) / denominator
            weighted_margin = sum(
                float(row["best_target_margin_mean"]) * int(row["support"]["anomaly"]) for row in rows
            ) / denominator
            mean_gap = float(np.mean([row["final_best_asr_gap"] for row in rows]))
            mean_rebound = float(np.mean([row["overshoot"]["target_loss_rebound_rate"] for row in rows]))
            projection_calls = sum(int(row["projection"]["calls"]) for row in rows)
            projection_converged = sum(int(row["projection"]["converged"]) for row in rows)
            projection_rate = float(projection_converged / projection_calls) if projection_calls else 1.0
            excluded_reasons = []
            if not all(row.get("identity_pass") for row in rows):
                excluded_reasons.append("integrity_failure")
            if not all(math.isfinite(float(row["best_target_ce_mean"])) for row in rows):
                excluded_reasons.append("non_finite_target_ce")
            if projection_calls and projection_rate < 0.5:
                excluded_reasons.append("large_scale_projection_failure")
            candidates.append(
                {
                    "alpha_rule": rule,
                    "pooled_valid_best_asr": pooled_asr,
                    "pooled_success_count": success,
                    "pooled_denominator": denominator,
                    "weighted_best_target_ce": weighted_ce,
                    "weighted_best_target_margin": weighted_margin,
                    "mean_final_best_asr_gap": mean_gap,
                    "mean_rebound_rate": mean_rebound,
                    "projection_convergence_rate": projection_rate,
                    "excluded": bool(excluded_reasons),
                    "excluded_reasons": excluded_reasons,
                }
            )
        eligible = [row for row in candidates if not row["excluded"]]
        if not eligible:
            raise RuntimeError(f"all alpha rules excluded for attack {attack}")
        selected = sorted(
            eligible,
            key=lambda row: (
                -int(row["pooled_success_count"]),
                float(row["weighted_best_target_ce"]),
                -float(row["weighted_best_target_margin"]),
                float(row["mean_final_best_asr_gap"]),
                float(row["mean_rebound_rate"]),
                str(row["alpha_rule"]),
            ),
        )[0]
        selection["attacks"][attack] = {
            "selected_alpha_rule": selected["alpha_rule"],
            "selected_evidence": selected,
            "all_alpha_rules": candidates,
        }
    selection["selection_hash"] = _canonical_hash(selection)
    _atomic_json(output_dir / "selected_attack_configs.json", selection)
    return selection


def _find_task(
    summaries: list[dict[str, Any]],
    *,
    seed: int,
    model: str,
    attack: str,
    steps: int,
    alpha_rule: str,
    initialization: str,
    restarts: int,
) -> dict[str, Any]:
    matches = [
        row
        for row in summaries
        if row.get("seed") == seed
        and row.get("model") == model
        and row.get("attack") == attack
        and row.get("steps") == steps
        and row.get("alpha_rule") == alpha_rule
        and row.get("initialization") == initialization
        and row.get("restarts") == restarts
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one task, found {len(matches)} for {seed}/{model}/{attack}/K{steps}/{alpha_rule}/{initialization}/R{restarts}"
        )
    return matches[0]


def _set_restart_inclusion(summary: dict[str, Any], prior: dict[str, Any], expected: int, output_dir: Path) -> dict[str, Any]:
    fingerprint_pass = summary["restart_fingerprints"][:expected] == prior["restart_fingerprints"][:expected]
    monotonic_asr = float(summary["best_metrics"]["threshold_asr"]) + 1e-12 >= float(
        prior["best_metrics"]["threshold_asr"]
    )
    monotonic_ce = float(summary["best_target_ce_mean"]) <= float(prior["best_target_ce_mean"]) + 1e-7
    updated = dict(summary)
    updated["restart_inclusion_check"] = {
        "prior_task_hash": prior["task_hash"],
        "expected_contained_restarts": expected,
        "fingerprints_equal": fingerprint_pass,
        "best_asr_not_weaker": monotonic_asr,
        "best_target_ce_not_higher": monotonic_ce,
        "pass": fingerprint_pass and monotonic_asr and monotonic_ce,
    }
    _atomic_json(_summary_path(output_dir, summary["task_hash"]), updated)
    if not updated["restart_inclusion_check"]["pass"]:
        raise RuntimeError("restart candidate-set inclusion invariant failed")
    return updated


def run_p2b(project_root: Path, output_dir: Path) -> None:
    context = initialize_freeze(project_root, output_dir)
    p2_config = context["p2_config"]
    projection = context["projection"]
    freeze = context["freeze"]
    p1_root = context["p1_root"]
    selection = select_attack_alphas(output_dir, p2_config)
    store = AggregateStore(output_dir)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    dataframe = _prepare_dataframe(project_root)
    checkpoint_rows: list[dict[str, Any]] = []

    for seed in SEEDS:
        pack, data_status = prepare_seed(
            project_root=project_root,
            output_dir=output_dir,
            p1_root=p1_root,
            dataframe=dataframe,
            seed=seed,
            device=device,
        )
        for model_name in MODELS:
            model, threshold, checkpoint_status, clean_probs, model_checks = load_p1_model(
                p1_root=p1_root,
                seed=seed,
                model_name=model_name,
                pack=pack,
                device=device,
            )
            checkpoint_rows.append(
                {"seed": seed, "model": model_name, "data": data_status["identity_checks"], "checkpoint": model_checks}
            )
            for attack in ATTACKS:
                alpha_rule = selection["attacks"][attack]["selected_alpha_rule"]
                initialization = RANDOM_INITIALIZATION[attack]
                for steps in STEPS:
                    print(
                        f"P2-B seed={seed} model={model_name} attack={attack} K={steps} "
                        f"alpha={alpha_rule} init={initialization} R=5",
                        flush=True,
                    )
                    try:
                        summary = run_configuration(
                            stage="p2b",
                            seed=seed,
                            model_name=model_name,
                            model=model,
                            threshold=threshold,
                            pack=pack,
                            clean_probs=clean_probs,
                            attack=attack,
                            steps=steps,
                            alpha_rule=alpha_rule,
                            initialization=initialization,
                            restarts=5,
                            projection=projection,
                            p2_config=p2_config,
                            p2_code_fingerprint=freeze["p2_execution_code_fingerprint"],
                            checkpoint_status=checkpoint_status,
                            data_manifest=data_status["manifest"],
                            output_dir=output_dir,
                            store=store,
                            device=device,
                        )
                        prior = _find_task(
                            _all_summaries(output_dir, status="completed"),
                            seed=seed,
                            model=model_name,
                            attack=attack,
                            steps=steps,
                            alpha_rule=alpha_rule,
                            initialization=initialization,
                            restarts=1,
                        )
                        _set_restart_inclusion(summary, prior, 1, output_dir)
                    except Exception as exc:
                        failure = {
                            "schema_version": P2_SCHEMA,
                            "status": "failed",
                            "stage": "p2b",
                            "seed": seed,
                            "model": model_name,
                            "attack": attack,
                            "steps": steps,
                            "alpha_rule": alpha_rule,
                            "initialization": initialization,
                            "restarts": 5,
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                            "traceback": traceback.format_exc(),
                            "failed_at_utc": _now(),
                        }
                        _append_failed(output_dir, failure)
                        print(json.dumps(_json_safe(failure), ensure_ascii=False), flush=True)
                    _write_progress_manifest(
                        output_dir,
                        freeze=freeze,
                        phase="p2b_r5_running",
                        checkpoint_rows=checkpoint_rows,
                    )
            del model
            if device.type == "cuda":
                torch.cuda.empty_cache()

    summaries = _all_summaries(output_dir, status="completed")
    r10_triggers: dict[str, bool] = {}
    trigger_evidence: dict[str, list[dict[str, Any]]] = {}
    for attack in ATTACKS:
        alpha_rule = selection["attacks"][attack]["selected_alpha_rule"]
        initialization = RANDOM_INITIALIZATION[attack]
        evidence = []
        for seed in SEEDS:
            for model_name in MODELS:
                for steps in STEPS:
                    r1 = _find_task(
                        summaries,
                        seed=seed,
                        model=model_name,
                        attack=attack,
                        steps=steps,
                        alpha_rule=alpha_rule,
                        initialization=initialization,
                        restarts=1,
                    )
                    r5 = _find_task(
                        summaries,
                        seed=seed,
                        model=model_name,
                        attack=attack,
                        steps=steps,
                        alpha_rule=alpha_rule,
                        initialization=initialization,
                        restarts=5,
                    )
                    increment = float(r5["best_metrics"]["threshold_asr"] - r1["best_metrics"]["threshold_asr"])
                    evidence.append(
                        {"seed": seed, "model": model_name, "steps": steps, "r1_to_r5_best_asr_increment": increment}
                    )
        r10_triggers[attack] = any(row["r1_to_r5_best_asr_increment"] >= 0.005 for row in evidence)
        trigger_evidence[attack] = evidence
    selection["r10_triggers"] = r10_triggers
    selection["r10_trigger_evidence"] = trigger_evidence
    selection["selection_hash"] = _canonical_hash({key: value for key, value in selection.items() if key != "selection_hash"})
    _atomic_json(output_dir / "selected_attack_configs.json", selection)

    for attack in ATTACKS:
        if not r10_triggers[attack]:
            continue
        alpha_rule = selection["attacks"][attack]["selected_alpha_rule"]
        initialization = RANDOM_INITIALIZATION[attack]
        for seed in SEEDS:
            pack, data_status = prepare_seed(
                project_root=project_root,
                output_dir=output_dir,
                p1_root=p1_root,
                dataframe=dataframe,
                seed=seed,
                device=device,
            )
            for model_name in MODELS:
                model, threshold, checkpoint_status, clean_probs, model_checks = load_p1_model(
                    p1_root=p1_root,
                    seed=seed,
                    model_name=model_name,
                    pack=pack,
                    device=device,
                )
                for steps in STEPS:
                    print(
                        f"P2-B conditional R10 seed={seed} model={model_name} attack={attack} "
                        f"K={steps} alpha={alpha_rule}",
                        flush=True,
                    )
                    try:
                        summary = run_configuration(
                            stage="p2b",
                            seed=seed,
                            model_name=model_name,
                            model=model,
                            threshold=threshold,
                            pack=pack,
                            clean_probs=clean_probs,
                            attack=attack,
                            steps=steps,
                            alpha_rule=alpha_rule,
                            initialization=initialization,
                            restarts=10,
                            projection=projection,
                            p2_config=p2_config,
                            p2_code_fingerprint=freeze["p2_execution_code_fingerprint"],
                            checkpoint_status=checkpoint_status,
                            data_manifest=data_status["manifest"],
                            output_dir=output_dir,
                            store=store,
                            device=device,
                        )
                        prior = _find_task(
                            _all_summaries(output_dir, status="completed"),
                            seed=seed,
                            model=model_name,
                            attack=attack,
                            steps=steps,
                            alpha_rule=alpha_rule,
                            initialization=initialization,
                            restarts=5,
                        )
                        _set_restart_inclusion(summary, prior, 5, output_dir)
                    except Exception as exc:
                        failure = {
                            "schema_version": P2_SCHEMA,
                            "status": "failed",
                            "stage": "p2b",
                            "seed": seed,
                            "model": model_name,
                            "attack": attack,
                            "steps": steps,
                            "alpha_rule": alpha_rule,
                            "initialization": initialization,
                            "restarts": 10,
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                            "traceback": traceback.format_exc(),
                            "failed_at_utc": _now(),
                        }
                        _append_failed(output_dir, failure)
                        print(json.dumps(_json_safe(failure), ensure_ascii=False), flush=True)
                    _write_progress_manifest(
                        output_dir,
                        freeze=freeze,
                        phase="p2b_r10_running",
                        checkpoint_rows=checkpoint_rows,
                    )
                del model
                if device.type == "cuda":
                    torch.cuda.empty_cache()
    _write_progress_manifest(output_dir, freeze=freeze, phase="p2b_complete", checkpoint_rows=checkpoint_rows)


def _candidate_payload(output_dir: Path, summary: dict[str, Any]) -> dict[str, np.ndarray]:
    path = output_dir / summary["candidate_artifact"]["path"]
    if sha256_file(path) != summary["candidate_artifact"]["sha256"]:
        raise RuntimeError(f"candidate artifact hash mismatch: {path}")
    with np.load(path, allow_pickle=False) as data:
        return {key: data[key] for key in data.files}


def _task_row(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "Seed": summary["seed"],
        "Model": summary["model"],
        "Attack": summary["attack"],
        "K": summary["steps"],
        "Init": summary["initialization"],
        "Alpha rule": summary["alpha_rule"],
        "Alpha": summary["alpha"],
        "Restarts": summary["restarts"],
        "Final ASR": summary["final_metrics"]["threshold_asr"],
        "Best ASR": summary["best_metrics"]["threshold_asr"],
        "PV-ASR | V0": summary["pv_asr_v0"],
        "Recall": summary["best_metrics"]["recall"],
        "F1": summary["best_metrics"]["f1"],
        "Target CE": summary["best_target_ce_mean"],
        "Median Target CE": summary["best_target_ce_median"],
        "Margin": summary["best_target_margin_mean"],
        "Final-Best ASR Gap": summary["final_best_asr_gap"],
        "Task Hash": summary["task_hash"],
        "Config Hash": summary["attack_config_hash"],
        "Identity Pass": summary["identity_pass"],
    }


def _build_tables(
    output_dir: Path,
    summaries: list[dict[str, Any]],
    selection: dict[str, Any],
) -> dict[str, pd.DataFrame]:
    p2a = [row for row in summaries if row["stage"] == "p2a"]
    step_frame = pd.DataFrame([_task_row(row) for row in p2a])
    step_frame.to_csv(output_dir / "step_size_audit_long.csv", index=False)

    overshoot_rows = []
    projection_rows = []
    transition_rows = []
    for summary in summaries:
        overshoot_rows.append(
            {
                **_task_row(summary),
                "Rebound rate": summary["overshoot"]["target_loss_rebound_rate"],
                "Margin reversal count": summary["overshoot"]["margin_reversal_count"],
                "Margin reversal rate": summary["overshoot"]["margin_reversal_rate"],
                "Success loss rate": summary["overshoot"]["success_loss_rate"],
                "Boundary hit step median": summary["overshoot"]["boundary_hit_step_median"],
                "Boundary duration": summary["overshoot"]["boundary_saturation_duration"],
                "Projection damage": summary["overshoot"]["projection_damage_mean"],
                "Projection reversal rate": summary["overshoot"]["projection_reversal_rate"],
            }
        )
        if summary["attack"] in PHYSICAL_ATTACKS:
            projection_rows.append(
                {
                    "Seed": summary["seed"],
                    "Model": summary["model"],
                    "Attack": summary["attack"],
                    "K": summary["steps"],
                    "Alpha rule": summary["alpha_rule"],
                    "Alpha": summary["alpha"],
                    "Init": summary["initialization"],
                    "Restarts": summary["restarts"],
                    "Pre-loss": summary["projection"]["pre_target_ce_mean"],
                    "Post-loss": summary["projection"]["post_target_ce_mean"],
                    "Projection damage": summary["overshoot"]["projection_damage_mean"],
                    "Projection calls": summary["projection"]["calls"],
                    "Converged": summary["projection"]["converged"],
                    "Convergence rate": summary["projection"]["convergence_rate"],
                    "Initialization infeasible": summary["support"]["initialization_infeasible"],
                    "Source invalid": summary["support"]["source_invalid"],
                }
            )
        transition_rows.append(
            {
                "Seed": summary["seed"],
                "Model": summary["model"],
                "Attack": summary["attack"],
                "K": summary["steps"],
                "Alpha rule": summary["alpha_rule"],
                "Alpha": summary["alpha"],
                "Init": summary["initialization"],
                "Restarts": summary["restarts"],
                "TP->FN": summary["transitions"]["best_clean_tp_to_attack_fn"],
                "FN->TP": summary["transitions"]["best_clean_fn_to_attack_tp"],
                "Recall change": summary["best_metrics"]["recall"] - summary["clean_metrics"]["recall"],
            }
        )
    overshoot_frame = pd.DataFrame(overshoot_rows)
    overshoot_frame.to_csv(output_dir / "overshoot_diagnostics.csv", index=False)
    projection_frame = pd.DataFrame(projection_rows)
    projection_frame.to_csv(output_dir / "projection_effects.csv", index=False)
    transition_frame = pd.DataFrame(transition_rows)
    transition_frame.to_csv(output_dir / "prediction_transitions.csv", index=False)

    initialization_rows = []
    for seed in SEEDS:
        for model in MODELS:
            for attack in ATTACKS:
                random_init = RANDOM_INITIALIZATION[attack]
                for steps in STEPS:
                    for rule in ALPHA_RULES:
                        clean = _find_task(
                            p2a,
                            seed=seed,
                            model=model,
                            attack=attack,
                            steps=steps,
                            alpha_rule=rule,
                            initialization="clean",
                            restarts=1,
                        )
                        random = _find_task(
                            p2a,
                            seed=seed,
                            model=model,
                            attack=attack,
                            steps=steps,
                            alpha_rule=rule,
                            initialization=random_init,
                            restarts=1,
                        )
                        clean_payload = _candidate_payload(output_dir, clean)
                        random_payload = _candidate_payload(output_dir, random)
                        clean_success = clean_payload["best_valid"] & (
                            clean_payload["best_p_anomaly"] < clean["threshold"]
                        )
                        random_success = random_payload["best_valid"] & (
                            random_payload["best_p_anomaly"] < random["threshold"]
                        )
                        initialization_rows.append(
                            {
                                "Seed": seed,
                                "Model": model,
                                "Attack": attack,
                                "K": steps,
                                "Alpha rule": rule,
                                "Alpha": clean["alpha"],
                                "Clean ASR": clean["best_metrics"]["threshold_asr"],
                                "Random ASR": random["best_metrics"]["threshold_asr"],
                                "Difference": random["best_metrics"]["threshold_asr"] - clean["best_metrics"]["threshold_asr"],
                                "Target-loss difference": random["best_target_ce_mean"] - clean["best_target_ce_mean"],
                                "Final-best gap difference": random["final_best_asr_gap"] - clean["final_best_asr_gap"],
                                "Init failures": random["support"]["initialization_infeasible"],
                                "Projection convergence rate": random["projection"]["convergence_rate"],
                                "Success overlap": int((clean_success & random_success).sum()),
                                "Random-only success": int((~clean_success & random_success).sum()),
                                "Clean-only success": int((clean_success & ~random_success).sum()),
                                "Clean task hash": clean["task_hash"],
                                "Random task hash": random["task_hash"],
                            }
                        )
    initialization_frame = pd.DataFrame(initialization_rows)
    initialization_frame.to_csv(output_dir / "initialization_audit.csv", index=False)

    restart_rows = []
    for seed in SEEDS:
        for model in MODELS:
            for attack in ATTACKS:
                rule = selection["attacks"][attack]["selected_alpha_rule"]
                initialization = RANDOM_INITIALIZATION[attack]
                for steps in STEPS:
                    r1 = _find_task(
                        summaries,
                        seed=seed,
                        model=model,
                        attack=attack,
                        steps=steps,
                        alpha_rule=rule,
                        initialization=initialization,
                        restarts=1,
                    )
                    r5 = _find_task(
                        summaries,
                        seed=seed,
                        model=model,
                        attack=attack,
                        steps=steps,
                        alpha_rule=rule,
                        initialization=initialization,
                        restarts=5,
                    )
                    r10_matches = [
                        row
                        for row in summaries
                        if row.get("seed") == seed
                        and row.get("model") == model
                        and row.get("attack") == attack
                        and row.get("steps") == steps
                        and row.get("alpha_rule") == rule
                        and row.get("initialization") == initialization
                        and row.get("restarts") == 10
                    ]
                    r10 = r10_matches[0] if r10_matches else None
                    r5_diag = r5["restart_diagnostics"]
                    restart_rows.append(
                        {
                            "Seed": seed,
                            "Model": model,
                            "Attack": attack,
                            "K": steps,
                            "Alpha rule": rule,
                            "R1 ASR": r1["best_metrics"]["threshold_asr"],
                            "R5 ASR": r5["best_metrics"]["threshold_asr"],
                            "R10 ASR": None if r10 is None else r10["best_metrics"]["threshold_asr"],
                            "R1->R5": r5["best_metrics"]["threshold_asr"] - r1["best_metrics"]["threshold_asr"],
                            "R5->R10": None if r10 is None else r10["best_metrics"]["threshold_asr"] - r5["best_metrics"]["threshold_asr"],
                            "R1->R5 target CE improvement": r1["best_target_ce_mean"] - r5["best_target_ce_mean"],
                            "R5->R10 target CE improvement": None if r10 is None else r5["best_target_ce_mean"] - r10["best_target_ce_mean"],
                            "R5 union successes": r5_diag["union_success_count"],
                            "R5 intersection successes": r5_diag["intersection_success_count"],
                            "R5 new successes beyond restart 0": int(
                                sum(r5_diag["new_successes_vs_restart_zero"][1:])
                            ),
                            "R5 selected restart distribution": json.dumps(
                                r5_diag["selected_strongest_restart_distribution"], sort_keys=True
                            ),
                            "R1 task hash": r1["task_hash"],
                            "R5 task hash": r5["task_hash"],
                            "R10 task hash": None if r10 is None else r10["task_hash"],
                        }
                    )
    restart_frame = pd.DataFrame(restart_rows)
    restart_frame.to_csv(output_dir / "restart_audit.csv", index=False)

    per_seed_rows = []
    for attack in ATTACKS:
        selected_rule = selection["attacks"][attack]["selected_alpha_rule"]
        for seed in SEEDS:
            rule_scores = []
            for rule in ALPHA_RULES:
                rows = [
                    row for row in p2a if row["attack"] == attack and row["seed"] == seed and row["alpha_rule"] == rule
                ]
                success = sum(int(row["support"]["valid_attack_success"]) for row in rows)
                denominator = sum(int(row["support"]["anomaly"]) for row in rows)
                rule_scores.append((success, rule, success / denominator if denominator else float("nan")))
            local = sorted(rule_scores, key=lambda item: (-item[0], item[1]))[0]
            per_seed_rows.append(
                {
                    "Seed": seed,
                    "Attack": attack,
                    "Globally selected alpha rule": selected_rule,
                    "Per-seed envelope alpha rule": local[1],
                    "Per-seed pooled best ASR": local[2],
                    "Matches global": local[1] == selected_rule,
                    "Selection rule": "pooled success count across both models, K, and both initializations",
                }
            )
    per_seed_frame = pd.DataFrame(per_seed_rows)
    per_seed_frame.to_csv(output_dir / "per_seed_selected_configuration.csv", index=False)
    return {
        "step": step_frame,
        "overshoot": overshoot_frame,
        "initialization": initialization_frame,
        "restart": restart_frame,
        "projection": projection_frame,
        "transition": transition_frame,
        "per_seed": per_seed_frame,
    }


def _save_figure(fig: plt.Figure, figures_dir: Path, name: str) -> None:
    figures_dir.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(figures_dir / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(figures_dir / f"{name}.svg", bbox_inches="tight")
    plt.close(fig)


def _alpha_axis(frame: pd.DataFrame) -> np.ndarray:
    order = {rule: index for index, rule in enumerate(ALPHA_RULES)}
    return frame["Alpha rule"].map(order).to_numpy(dtype=float)


def generate_figures(tables: dict[str, pd.DataFrame], figures_dir: Path) -> None:
    step = tables["step"]
    overshoot = tables["overshoot"]
    initialization = tables["initialization"]
    restart = tables["restart"]
    projection = tables["projection"]
    transition = tables["transition"]
    per_seed = tables["per_seed"]

    def alpha_panels(frame: pd.DataFrame, y: str, name: str, ylabel: str) -> None:
        fig, axes = plt.subplots(2, 2, figsize=(11, 7), sharex=True)
        for axis, attack in zip(axes.flat, ATTACKS):
            subset = frame[frame["Attack"] == attack]
            for (model, k), group in subset.groupby(["Model", "K"]):
                med = group.groupby("Alpha rule", sort=False)[y].median().reindex(ALPHA_RULES)
                axis.plot(range(len(ALPHA_RULES)), med, marker="o", label=f"{model}, K={k}")
                axis.scatter(_alpha_axis(group), group[y], s=8, alpha=0.22)
            axis.set_title(attack)
            axis.set_xticks(range(len(ALPHA_RULES)), ALPHA_RULES, rotation=25, ha="right")
            axis.set_ylabel(ylabel)
        axes[0, 0].legend(fontsize=7)
        _save_figure(fig, figures_dir, name)

    alpha_panels(step, "Best ASR", "asr_vs_alpha_by_k", "Best ASR")
    alpha_panels(step, "Target CE", "target_ce_vs_alpha", "Target CE")
    alpha_panels(step, "Final-Best ASR Gap", "final_best_gap_vs_alpha", "Final-best ASR gap")
    alpha_panels(overshoot, "Rebound rate", "rebound_rate_vs_alpha", "Target-CE rebound rate")

    fig, axis = plt.subplots(figsize=(7, 6))
    for model, group in initialization.groupby("Model"):
        axis.scatter(group["Clean ASR"], group["Random ASR"], s=18, alpha=0.5, label=model)
    limits = [
        min(initialization["Clean ASR"].min(), initialization["Random ASR"].min()),
        max(initialization["Clean ASR"].max(), initialization["Random ASR"].max()),
    ]
    axis.plot(limits, limits, color="black", linewidth=1)
    axis.set_xlabel("Clean-start best ASR")
    axis.set_ylabel("Random-start best ASR")
    axis.legend()
    _save_figure(fig, figures_dir, "clean_vs_random_initialization_asr")

    fig, axes = plt.subplots(2, 2, figsize=(11, 7), sharex=True, sharey=True)
    for axis, attack in zip(axes.flat, ATTACKS):
        group = restart[restart["Attack"] == attack]
        for _, row in group.iterrows():
            xs = [1, 5] + ([10] if pd.notna(row["R10 ASR"]) else [])
            ys = [row["R1 ASR"], row["R5 ASR"]] + ([row["R10 ASR"]] if pd.notna(row["R10 ASR"]) else [])
            axis.plot(xs, ys, alpha=0.22, marker="o", markersize=3)
        axis.set_title(attack)
        axis.set_xlabel("Restarts")
        axis.set_ylabel("Best ASR")
    _save_figure(fig, figures_dir, "restart_asr")

    fig, axis = plt.subplots(figsize=(8, 5))
    for attack, group in restart.groupby("Attack"):
        overlap = group["R5 intersection successes"] / group["R5 union successes"].replace(0, np.nan)
        axis.scatter(np.full(len(group), ATTACKS.index(attack)), overlap, alpha=0.5, label=attack)
    axis.set_xticks(range(len(ATTACKS)), ATTACKS, rotation=25, ha="right")
    axis.set_ylabel("R5 success intersection / union")
    _save_figure(fig, figures_dir, "successful_sample_overlap_across_restarts")

    fig, axis = plt.subplots(figsize=(7, 6))
    valid_projection = projection.dropna(subset=["Pre-loss", "Post-loss"])
    axis.scatter(valid_projection["Pre-loss"], valid_projection["Post-loss"], s=18, alpha=0.45)
    if len(valid_projection):
        limits = [
            min(valid_projection["Pre-loss"].min(), valid_projection["Post-loss"].min()),
            max(valid_projection["Pre-loss"].max(), valid_projection["Post-loss"].max()),
        ]
        axis.plot(limits, limits, color="black", linewidth=1)
    axis.set_xlabel("Pre-projection target CE")
    axis.set_ylabel("Post-projection target CE")
    _save_figure(fig, figures_dir, "pre_post_projection_target_loss_shift")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    p2a_transition = transition[transition["Restarts"] == 1]
    for attack, group in p2a_transition.groupby("Attack"):
        axes[0].scatter(_alpha_axis(group), group["TP->FN"], alpha=0.25, label=attack)
        axes[1].scatter(_alpha_axis(group), group["FN->TP"], alpha=0.25, label=attack)
    for axis, title in zip(axes, ("TP->FN", "FN->TP")):
        axis.set_xticks(range(len(ALPHA_RULES)), ALPHA_RULES, rotation=25, ha="right")
        axis.set_title(title)
        axis.set_ylabel("Sample count")
    axes[0].legend(fontsize=7)
    _save_figure(fig, figures_dir, "prediction_transitions_vs_alpha")

    fig, axes = plt.subplots(2, 2, figsize=(11, 7), sharex=True)
    p2a_overshoot = overshoot[overshoot["Restarts"] == 1]
    for axis, attack in zip(axes.flat, ATTACKS):
        group = p2a_overshoot[p2a_overshoot["Attack"] == attack]
        for seed, seed_group in group.groupby("Seed"):
            med = seed_group.groupby("K")["Boundary duration"].mean()
            axis.plot(med.index, med.values, marker="o", alpha=0.55, label=str(seed))
        axis.set_title(attack)
        axis.set_xlabel("K")
        axis.set_ylabel("Boundary saturation duration")
    axes[0, 0].legend(fontsize=7, title="Seed")
    _save_figure(fig, figures_dir, "raw_boundary_saturation_vs_steps")

    fig, axis = plt.subplots(figsize=(9, 5))
    rule_index = {rule: index for index, rule in enumerate(ALPHA_RULES)}
    for attack_index, attack in enumerate(ATTACKS):
        group = per_seed[per_seed["Attack"] == attack]
        xs = np.full(len(group), attack_index)
        ys = group["Per-seed envelope alpha rule"].map(rule_index)
        axis.scatter(xs, ys, s=40, alpha=0.7)
        selected = rule_index[group["Globally selected alpha rule"].iloc[0]]
        axis.scatter([attack_index], [selected], marker="*", s=180, color="black")
    axis.set_xticks(range(len(ATTACKS)), ATTACKS, rotation=25, ha="right")
    axis.set_yticks(range(len(ALPHA_RULES)), ALPHA_RULES)
    axis.set_ylabel("Alpha rule (points: seeds; star: global selection)")
    _save_figure(fig, figures_dir, "per_seed_selected_alpha_consistency")


def _evaluate_gates(
    output_dir: Path,
    summaries: list[dict[str, Any]],
    selection: dict[str, Any],
    tables: dict[str, pd.DataFrame],
    context: dict[str, Any],
) -> dict[str, Any]:
    freeze = context["freeze"]
    p2_config = context["p2_config"]
    manifest = _load_json(output_dir / "p2_manifest.json")
    checkpoint_rows = manifest.get("checkpoint_identity_rows", [])
    checkpoint_pass = len(checkpoint_rows) >= 10 and all(
        _boolean_checks_pass(row[scope]) for row in checkpoint_rows for scope in ("data", "checkpoint")
    )
    checkpoint_gate = {
        "schema_version": "adsb.c001-p2-checkpoint-gate.v1",
        "gate": "PASS" if checkpoint_pass else "FAIL",
        "verified_rows": len(checkpoint_rows),
        "checks": checkpoint_rows,
    }
    _atomic_json(output_dir / "p2_checkpoint_identity_gate.json", checkpoint_gate)

    current_code = code_fingerprint(default_project_root())
    freeze_pass = (
        current_code == freeze["p2_execution_code_fingerprint"]
        and p2_config["config_hash"] == freeze["p2_config_hash"]
        and not _contains_null(p2_config)
    )
    freeze_gate = {
        "schema_version": "adsb.c001-p2-freeze-gate.v1",
        "gate": "PASS" if freeze_pass else "FAIL",
        "current_code_fingerprint": current_code,
        "frozen_code_fingerprint": freeze["p2_execution_code_fingerprint"],
        "p2_config_hash": p2_config["config_hash"],
        "unresolved_nulls": _contains_null(p2_config),
    }
    _atomic_json(output_dir / "p2_configuration_freeze_gate.json", freeze_gate)

    p2a = [row for row in summaries if row["stage"] == "p2a"]
    p2b_r5 = [row for row in summaries if row["stage"] == "p2b" and row["restarts"] == 5]
    p2b_r10 = [row for row in summaries if row["stage"] == "p2b" and row["restarts"] == 10]
    expected_r10 = 20 * sum(bool(value) for value in selection.get("r10_triggers", {}).values())
    store = AggregateStore(output_dir)
    ledger_hashes = set(store.ledger["tasks"])
    completed_hashes = {row["task_hash"] for row in summaries}
    candidate_hash_pass = all(
        sha256_file(output_dir / row["candidate_artifact"]["path"]) == row["candidate_artifact"]["sha256"]
        for row in summaries
    )
    inclusion_pass = all(
        row.get("restart_inclusion_check", {}).get("pass", False)
        for row in summaries
        if row["stage"] == "p2b"
    )
    integrity_checks = {
        "p2a_640_completed": len(p2a) == 640,
        "p2b_r5_80_completed": len(p2b_r5) == 80,
        "conditional_r10_complete": len(p2b_r10) == expected_r10,
        "all_task_identity_checks_pass": all(row["identity_pass"] for row in summaries),
        "restart_candidate_sets_nested": inclusion_pass,
        "aggregate_ledger_matches_completed_tasks": ledger_hashes == completed_hashes,
        "candidate_artifact_hashes_match": candidate_hash_pass,
        "native_step_restart_ids": all(row["identity_checks"]["native_step_restart_ids"] for row in summaries),
        "result_direction_used_for_scheduling": False,
        "p3_to_p6_executed": False,
    }
    logical = update_logical_configuration_status(output_dir)
    integrity_checks["logical_640_records_present"] = len(logical) == 640 and logical["logical_config_id"].nunique() == 640
    integrity_checks["all_logical_records_executed_or_reused"] = bool(
        logical["execution_status"].isin(["executed", "reused"]).all()
    )
    integrity_pass = all(
        value for key, value in integrity_checks.items() if key not in {"result_direction_used_for_scheduling", "p3_to_p6_executed"}
    ) and not integrity_checks["result_direction_used_for_scheduling"] and not integrity_checks["p3_to_p6_executed"]
    integrity_gate = {
        "schema_version": "adsb.c001-p2-integrity-gate.v1",
        "gate": "PASS" if integrity_pass else "FAIL",
        "completed_unique_tasks": len(summaries),
        "expected_p2a": 640,
        "expected_p2b_r5": 80,
        "expected_conditional_r10": expected_r10,
        "checks": integrity_checks,
    }
    _atomic_json(output_dir / "p2_integrity_gate.json", integrity_gate)

    restart_frame = tables["restart"]
    strongest_restart = 10 if restart_frame["R10 ASR"].notna().all() else 5
    stability_rows = []
    for seed in SEEDS:
        for model in MODELS:
            for attack in ATTACKS:
                rule = selection["attacks"][attack]["selected_alpha_rule"]
                initialization = RANDOM_INITIALIZATION[attack]
                k20 = _find_task(
                    summaries,
                    seed=seed,
                    model=model,
                    attack=attack,
                    steps=20,
                    alpha_rule=rule,
                    initialization=initialization,
                    restarts=strongest_restart,
                )
                k50 = _find_task(
                    summaries,
                    seed=seed,
                    model=model,
                    attack=attack,
                    steps=50,
                    alpha_rule=rule,
                    initialization=initialization,
                    restarts=strongest_restart,
                )
                asr_increment = k50["best_metrics"]["threshold_asr"] - k20["best_metrics"]["threshold_asr"]
                ce20 = float(k20["best_target_ce_median"])
                ce50 = float(k50["best_target_ce_median"])
                relative_ce_decrease = max(0.0, (ce20 - ce50) / max(abs(ce20), 1e-12))
                gap_increase = float(k50["final_best_asr_gap"] - k20["final_best_asr_gap"])
                stability_rows.append(
                    {
                        "seed": seed,
                        "model": model,
                        "attack": attack,
                        "alpha_rule": rule,
                        "restarts": strongest_restart,
                        "k20_to_k50_asr_increment": asr_increment,
                        "relative_median_target_ce_decrease": relative_ce_decrease,
                        "final_best_gap_increase": gap_increase,
                        "asr_pass": asr_increment < 0.01,
                        "target_ce_pass": relative_ce_decrease < 0.01,
                        "gap_pass": gap_increase < 0.01,
                    }
                )
    alpha_neighbor_checks = {}
    for attack in ATTACKS:
        rows = selection["attacks"][attack]["all_alpha_rules"]
        selected_asr = selection["attacks"][attack]["selected_evidence"]["pooled_valid_best_asr"]
        alpha_neighbor_checks[attack] = any(
            not row["excluded"]
            and row["alpha_rule"] != selection["attacks"][attack]["selected_alpha_rule"]
            and selected_asr - row["pooled_valid_best_asr"] < 0.01
            for row in rows
        )
    step_pass = all(
        row["asr_pass"] and row["target_ce_pass"] and row["gap_pass"] for row in stability_rows
    ) and all(alpha_neighbor_checks.values())
    step_gate = {
        "schema_version": "adsb.c001-p2-step-size-gate.v1",
        "gate": "PASS" if step_pass else "FAIL",
        "strongest_restart_count_used": strongest_restart,
        "per_seed_model_attack": stability_rows,
        "not_dependent_on_single_alpha_rule": alpha_neighbor_checks,
    }
    _atomic_json(output_dir / "p2_step_size_gate.json", step_gate)

    initialization_frame = tables["initialization"]
    material = initialization_frame[initialization_frame["Difference"] >= 0.005]
    initialization_pass = material.empty
    initialization_gate = {
        "schema_version": "adsb.c001-p2-initialization-gate.v1",
        "gate": "PASS" if initialization_pass else "FAIL",
        "material_asr_increment_operational_threshold": 0.005,
        "materially_stronger_random_start_configurations": material.to_dict(orient="records"),
        "evaluated_pairs": len(initialization_frame),
    }
    _atomic_json(output_dir / "p2_initialization_gate.json", initialization_gate)

    all_r10 = restart_frame["R10 ASR"].notna().all()
    if not all_r10:
        restart_verdict = "INCONCLUSIVE"
    elif bool((restart_frame["R5->R10"] < 0.005).all()):
        restart_verdict = "PASS"
    else:
        restart_verdict = "FAIL"
    restart_gate = {
        "schema_version": "adsb.c001-p2-restart-gate.v1",
        "gate": restart_verdict,
        "r10_executed_for_every_attack_family": bool(all_r10),
        "max_r5_to_r10_best_asr_increment": None if not all_r10 else float(restart_frame["R5->R10"].max()),
        "threshold": 0.005,
        "per_configuration": restart_frame.to_dict(orient="records"),
    }
    _atomic_json(output_dir / "p2_restart_gate.json", restart_gate)
    return {
        "checkpoint": checkpoint_gate,
        "freeze": freeze_gate,
        "integrity": integrity_gate,
        "step_size": step_gate,
        "initialization": initialization_gate,
        "restart": restart_gate,
    }


def _refresh_artifact_hashes(output_dir: Path) -> None:
    artifacts = []
    for path in sorted(
        (
            item
            for item in output_dir.rglob("*")
            if item.is_file()
            and item.name != "artifact_hashes.json"
            and ".staging" not in item.parts
        ),
        key=lambda item: item.relative_to(output_dir).as_posix(),
    ):
        artifacts.append(
            {
                "path": path.relative_to(output_dir).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    _atomic_json(
        output_dir / "artifact_hashes.json",
        {"schema_version": P2_SCHEMA, "artifacts": artifacts},
    )


def finalize_p2(project_root: Path, output_dir: Path) -> dict[str, Any]:
    context = initialize_freeze(project_root, output_dir)
    p2_config = context["p2_config"]
    selection = _load_json(output_dir / "selected_attack_configs.json")
    summaries = _all_summaries(output_dir, status="completed")
    tables = _build_tables(output_dir, summaries, selection)
    generate_figures(tables, output_dir / "figures")
    gates = _evaluate_gates(output_dir, summaries, selection, tables, context)

    step_frame = tables["step"]
    overshoot = tables["overshoot"]
    initialization = tables["initialization"]
    restart = tables["restart"]
    selected_lines = [
        f"- {attack}: `{selection['attacks'][attack]['selected_alpha_rule']}`"
        for attack in ATTACKS
    ]
    fixed = overshoot[(overshoot["Alpha rule"] == "fixed_003") & (overshoot["Restarts"] == 1)]
    other = overshoot[(overshoot["Alpha rule"] != "fixed_003") & (overshoot["Restarts"] == 1)]
    fixed_rebound = float(fixed["Rebound rate"].mean())
    other_rebound = float(other["Rebound rate"].mean())
    init_material = int((initialization["Difference"] >= 0.005).sum())
    r1_r5_max = float(restart["R1->R5"].max())
    r5_r10_max = float(restart["R5->R10"].max()) if restart["R5->R10"].notna().any() else None
    selected_random = []
    for attack in ATTACKS:
        rule = selection["attacks"][attack]["selected_alpha_rule"]
        selected_random.extend(
            row
            for row in summaries
            if row["attack"] == attack
            and row["alpha_rule"] == rule
            and row["initialization"] == RANDOM_INITIALIZATION[attack]
            and row["restarts"] == (10 if selection.get("r10_triggers", {}).get(attack) else 5)
        )
    recall_rise = sum(
        row["best_metrics"]["recall"] > row["clean_metrics"]["recall"] for row in selected_random
    )
    fn_tp_total = sum(row["transitions"]["best_clean_fn_to_attack_tp"] for row in selected_random)
    tp_fn_total = sum(row["transitions"]["best_clean_tp_to_attack_fn"] for row in selected_random)
    step_gate = gates["step_size"]["gate"]
    k100_required = step_gate != "PASS"
    p3_allowed = (
        gates["checkpoint"]["gate"] == "PASS"
        and gates["freeze"]["gate"] == "PASS"
        and gates["integrity"]["gate"] == "PASS"
        and not k100_required
    )
    report_lines = [
        "# C0-01 P2 Step-Size, Initialization, and Restart Audit",
        "",
        "## Decision",
        "",
        f"- Checkpoint Identity Gate: **{gates['checkpoint']['gate']}**",
        f"- P2 Configuration Freeze Gate: **{gates['freeze']['gate']}**",
        f"- P2 Integrity Gate: **{gates['integrity']['gate']}**",
        f"- Step-Size Stability Gate: **{gates['step_size']['gate']}**",
        f"- Initialization Adequacy Gate: **{gates['initialization']['gate']}**",
        f"- Restart Adequacy Gate: **{gates['restart']['gate']}**",
        f"- Direct entry to P3 permitted: **{'yes' if p3_allowed else 'no'}**",
        f"- K=100 or a convergence-style stopping audit required before P3: **{'yes' if k100_required else 'no'}**",
        "- P3--P6 executed: **no**",
        "- Paper modified: **no**",
        "",
        "## Selected alpha rules",
        "",
        *selected_lines,
        "",
        "The selection used pooled attack success across both models and all repeated splits. CAT-AD advantage or disadvantage was not a selection criterion.",
        "",
        "## Overshoot and initialization",
        "",
        f"The mean target-CE rebound rate was {fixed_rebound:.6f} for fixed_003 and {other_rebound:.6f} across the other P2-A rules. "
        "The configuration-level tables, projection damage, margin reversals, boundary duration, and final-best gaps determine whether this is substantive rather than the mean alone.",
        f"Random initialization increased best ASR by at least 0.005 in {init_material}/{len(initialization)} paired configurations.",
        "",
        "## Restarts",
        "",
        f"The maximum R1-to-R5 best-ASR increment was {r1_r5_max:.6f}.",
        (
            "R10 was not executed for every attack family, so restart adequacy cannot PASS."
            if r5_r10_max is None
            else f"The maximum observed R5-to-R10 best-ASR increment was {r5_r10_max:.6f}."
        ),
        "",
        "## Recall/F1 transition diagnosis",
        "",
        f"Under the selected random-start strongest-restart configurations, Recall exceeded clean Recall in {recall_rise}/{len(selected_random)} tasks. "
        f"Across these tasks, clean FN-to-attacked TP transitions totaled {fn_tp_total}, while TP-to-FN transitions totaled {tp_fn_total}.",
        "[CLAIM TOO STRONG] Recall/F1 increases are not evidence of robustness or beneficial attacks; they must be interpreted with target CE, margin, ASR, candidate selection, and projection transitions.",
        "",
        "## Interpretation boundary",
        "",
        "[DATA CONFLICT] P2 uses the explicit-injection-seed v2 data identity and must not be pooled with legacy paper results.",
        "[EXPERIMENT REQUIRED] P2 does not test margin/CW, transfer, holdout, or gradient-free attacks and cannot authorize a final Attack Adequacy PASS.",
        "[AUTHOR VERIFY] Before any manuscript update, authors must map every legacy clean-start, single-restart, fixed-alpha ASR/PV-ASR value to its exact source table and keep it suspended if P2 found a stronger configuration.",
    ]
    (output_dir / "p2_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    manifest = _load_json(output_dir / "p2_manifest.json")
    manifest.update(
        {
            "updated_at_utc": _now(),
            "phase": "p2_complete",
            "completed_unique_tasks": len(summaries),
            "completed_p2a_tasks": sum(row["stage"] == "p2a" for row in summaries),
            "completed_p2b_r5_tasks": sum(row["stage"] == "p2b" and row["restarts"] == 5 for row in summaries),
            "completed_p2b_r10_tasks": sum(row["stage"] == "p2b" and row["restarts"] == 10 for row in summaries),
            "gates": {key: value["gate"] for key, value in gates.items()},
            "selected_alpha_rules": {
                attack: selection["attacks"][attack]["selected_alpha_rule"] for attack in ATTACKS
            },
            "r10_triggers": selection.get("r10_triggers", {}),
            "direct_p3_entry_permitted": p3_allowed,
            "k100_required_before_p3": k100_required,
            "p3_to_p6_executed": False,
            "paper_modified": False,
        }
    )
    _atomic_json(output_dir / "p2_manifest.json", manifest)
    if not (output_dir / "failed_runs.jsonl").exists():
        (output_dir / "failed_runs.jsonl").touch()
    _refresh_artifact_hashes(output_dir)
    return {"gates": gates, "manifest": manifest}


def run_preflight(project_root: Path, output_dir: Path) -> dict[str, Any]:
    context = initialize_freeze(project_root, output_dir)
    logical = build_logical_configuration_manifest(
        output_dir=output_dir,
        p1_root=context["p1_root"],
        p2_config=context["p2_config"],
        projection=context["projection"],
        p2_code_fingerprint=context["freeze"]["p2_execution_code_fingerprint"],
    )
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    dataframe = _prepare_dataframe(project_root)
    rows = []
    for seed in SEEDS:
        pack, data_status = prepare_seed(
            project_root=project_root,
            output_dir=output_dir,
            p1_root=context["p1_root"],
            dataframe=dataframe,
            seed=seed,
            device=device,
        )
        for model in MODELS:
            loaded, threshold, status, _clean, checks = load_p1_model(
                p1_root=context["p1_root"],
                seed=seed,
                model_name=model,
                pack=pack,
                device=device,
            )
            rows.append({"seed": seed, "model": model, "data": data_status["identity_checks"], "checkpoint": checks})
            del loaded
            if device.type == "cuda":
                torch.cuda.empty_cache()
    gate = {
        "schema_version": "adsb.c001-p2-preflight.v1",
        "gate": "PASS" if len(rows) == 10 and all(
            _boolean_checks_pass(row[scope]) for row in rows for scope in ("data", "checkpoint")
        ) else "FAIL",
        "rows": rows,
        "p2_config_hash": context["p2_config"]["config_hash"],
        "p2_execution_code_fingerprint": context["freeze"]["p2_execution_code_fingerprint"],
        "logical_configurations": int(len(logical)),
        "reuse_eligible_configurations": int(logical["reuse_eligible"].sum()),
        "new_executions_required": int((~logical["reuse_eligible"]).sum()),
    }
    _atomic_json(output_dir / "p2_preflight_gate.json", gate)
    _write_progress_manifest(output_dir, freeze=context["freeze"], phase="preflight_complete", checkpoint_rows=rows)
    return gate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        choices=("preflight", "p2a", "p2b", "finalize", "all"),
        default="all",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/attack_audit_c001/p2"))
    arguments = parser.parse_args(argv)
    project_root = default_project_root()
    output_dir = arguments.output_dir
    if not output_dir.is_absolute():
        output_dir = (project_root / output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        if arguments.phase in {"preflight", "all"}:
            gate = run_preflight(project_root, output_dir)
            print(json.dumps(_json_safe(gate), indent=2, ensure_ascii=False), flush=True)
            if gate["gate"] != "PASS":
                return 1
        if arguments.phase in {"p2a", "all"}:
            run_p2a(project_root, output_dir)
        if arguments.phase in {"p2b", "all"}:
            run_p2b(project_root, output_dir)
        if arguments.phase in {"finalize", "all"}:
            result = finalize_p2(project_root, output_dir)
            print(json.dumps(_json_safe(result["manifest"]), indent=2, ensure_ascii=False), flush=True)
        return 0
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

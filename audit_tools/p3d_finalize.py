"""Independent reaggregation and diagnostic finalization for C0-01 P3-D.

The finalizer never executes an attack.  It reads immutable CE evidence and
completed Margin/CW task members, independently rebuilds success memberships
and candidate summaries, applies the frozen P2-C v2 semantics, and emits the
diagnostic-only gates and report.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import math
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

import numpy as np
import pandas as pd

from adsb.checkpoints import code_fingerprint, sha256_file
from adsb.p2_step_size_restart import STEP_FIELDS
from audit_tools.p3d_runner import (
    ATTACKS,
    CW_KAPPA,
    EXPECTED_ATTACK_FINGERPRINT,
    EXPECTED_P2C_POSTHOC,
    EXPECTED_R40_SNAPSHOT,
    INVENTORY_FIELDS,
    LOSSES,
    MODELS,
    R,
    SEEDS,
    STEPS,
    atomic_csv,
    atomic_json,
    canonical_hash,
    load_json,
    paths,
    read_inventory,
    source_files,
    verify_p2d_manifest,
)


PHYSICAL = {"phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd"}
MATERIAL = 0.01
CEILING_HEADROOM = 0.01


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "t", "yes"}


def as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def unit_id(seed: int, model: str, attack: str, steps: int) -> str:
    return canonical_hash({"seed": int(seed), "model": model, "attack": attack, "K": int(steps), "alpha_rule": "two_eps_over_k", "initialization": {"norm_pgd": "uniform_budget", "phys_projection_pgd": "feasible_random", "phys_penalty_pgd": "uniform_budget", "phys_hybrid_pgd": "feasible_random"}[attack]})


def atomic_dataframe(path: Path, frame: pd.DataFrame, *, compression: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    frame.to_csv(temp, index=False, compression=compression)
    os.replace(temp, path)


def task_member_bytes(raw_root: Path, task_hash: str, kind: str) -> bytes:
    ledger = load_json(raw_root / "aggregation_ledger.json")
    key = "step_size_bytes_after" if kind == "step" else "sample_size_bytes_after"
    filename = "per_step_restart_records.csv.gz" if kind == "step" else "per_sample_attack_records.csv.gz"
    entries = sorted(ledger["tasks"].items(), key=lambda item: int(item[1][key]))
    previous = 0
    for current_hash, entry in entries:
        end = int(entry[key])
        if current_hash == task_hash:
            with (raw_root / filename).open("rb") as stream:
                stream.seek(previous)
                data = stream.read(end - previous)
            expected = entry["step_member_sha256" if kind == "step" else "sample_member_sha256"]
            observed = hashlib.sha256(data).hexdigest()
            if observed != expected:
                raise RuntimeError(f"{kind} gzip member hash mismatch for {task_hash}")
            return data
        previous = end
    raise KeyError(f"task absent from aggregate ledger: {task_hash}")


def iter_csv_member(data: bytes, fields: Iterable[str]) -> Iterator[dict[str, str]]:
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as compressed:
        with io.TextIOWrapper(compressed, encoding="utf-8", newline="") as text:
            reader = csv.DictReader(text, fieldnames=list(fields))
            for row in reader:
                if row.get(next(iter(fields))) == next(iter(fields)):
                    continue
                yield row


def inspect_task(project_root: Path, loss_name: str, task_hash: str) -> dict[str, Any]:
    p = paths(project_root)
    loss_root = p["p3"] / loss_name
    raw_root = loss_root / "raw_results"
    summary_path = raw_root / "tasks" / task_hash / "summary.json"
    summary = load_json(summary_path)
    npz_path = raw_root / summary["candidate_artifact"]["path"]
    if sha256_file(npz_path) != summary["candidate_artifact"]["sha256"]:
        raise RuntimeError(f"candidate artifact hash mismatch: {task_hash}")
    with np.load(npz_path, allow_pickle=False) as arrays:
        sample_ids = arrays["sample_id"].astype(str)
        reported_restart = arrays["per_restart_success"].astype(bool)
    if reported_restart.shape != (R, len(sample_ids)):
        raise RuntimeError(f"restart array shape mismatch: {task_hash} {reported_restart.shape}")

    physical = summary["attack"] in PHYSICAL
    steps = int(summary["steps"])
    positions = {sample_id: index for index, sample_id in enumerate(sample_ids)}
    independent_restart = np.zeros_like(reported_restart)
    source_valid = np.zeros(len(sample_ids), dtype=bool)
    source_seen = np.zeros(len(sample_ids), dtype=bool)
    any_actual = np.zeros(len(sample_ids), dtype=bool)
    any_budget = np.zeros(len(sample_ids), dtype=bool)
    any_kinematic = np.zeros(len(sample_ids), dtype=bool)
    any_valid = np.zeros(len(sample_ids), dtype=bool)
    final_valid = np.zeros((R, len(sample_ids)), dtype=bool)
    fallback_projection = np.zeros(len(sample_ids), dtype=bool)
    init_success = np.zeros((R, len(sample_ids)), dtype=bool)
    best_rank: list[tuple[float, int, int] | None] = [None] * len(sample_ids)
    best_values: list[tuple[float, float] | None] = [None] * len(sample_ids)
    success_rank: list[tuple[float, int, int] | None] = [None] * len(sample_ids)
    success_values: list[tuple[float, float] | None] = [None] * len(sample_ids)
    pair_seen: set[tuple[int, int, int]] = set()
    duplicates = 0
    row_count = 0
    restarts_seen: set[int] = set()
    steps_by_restart: dict[int, set[int]] = defaultdict(set)
    threshold_value = float(summary["threshold"])

    for row in iter_csv_member(task_member_bytes(raw_root, task_hash, "step"), STEP_FIELDS):
        row_count += 1
        sample_id = str(row["sample_id"])
        if sample_id not in positions:
            raise RuntimeError(f"unknown sample in step member: {sample_id}")
        idx = positions[sample_id]
        restart = int(row["restart_id"])
        step = int(row["step"])
        pair = (idx, restart, step)
        if pair in pair_seen:
            duplicates += 1
        pair_seen.add(pair)
        restarts_seen.add(restart)
        steps_by_restart[restart].add(step)
        active = as_bool(row["candidate_active"])
        budget = as_bool(row["budget_valid"])
        kinematic = as_bool(row["kinematic_valid"])
        threshold_success = as_bool(row["threshold_success"])
        valid = active and budget and (kinematic if physical else True)
        formal = valid and threshold_success
        source = as_bool(row["source_valid"])
        if source_seen[idx] and source_valid[idx] != source:
            raise RuntimeError(f"source_valid changes within task: {task_hash} {sample_id}")
        source_seen[idx] = True
        source_valid[idx] = source
        any_actual[idx] |= active
        any_budget[idx] |= active and budget
        any_kinematic[idx] |= active and (kinematic if physical else True)
        any_valid[idx] |= valid
        if step == steps:
            final_valid[restart, idx] |= valid
        independent_restart[restart, idx] |= formal
        init_success[restart, idx] |= as_bool(row["initialization_success"])
        status = str(row["projection_status"])
        if status and status != "not_required" and not as_bool(row["projection_converged"]):
            fallback_projection[idx] = True
        ce = as_float(row["target_ce"])
        target_margin = as_float(row["target_margin"])
        # Margin/CW minimize z_anomaly-z_normal, equivalent to maximizing the
        # archived z_normal-z_anomaly target_margin.  CW ties use the same
        # untruncated ranking value.
        rank = (-target_margin, restart, step)
        if active and math.isfinite(target_margin) and (best_rank[idx] is None or rank < best_rank[idx]):
            best_rank[idx] = rank
            best_values[idx] = (ce, target_margin)
        if formal and math.isfinite(target_margin) and (success_rank[idx] is None or rank < success_rank[idx]):
            success_rank[idx] = rank
            success_values[idx] = (ce, target_margin)
        p_anomaly = as_float(row["p_anomaly"])
        if math.isfinite(p_anomaly) and (p_anomaly < threshold_value) != threshold_success:
            raise RuntimeError(f"threshold identity mismatch: {task_hash} {sample_id} r{restart} s{step}")

    expected_rows = len(sample_ids) * R * (steps + 1)
    restart_complete = row_count == expected_rows and duplicates == 0 and restarts_seen == set(range(R)) and all(steps_by_restart[r] == set(range(steps + 1)) for r in range(R))
    metric_identity = np.array_equal(independent_restart, reported_restart)
    independent_union = independent_restart.any(axis=0)
    reported_union = reported_restart.any(axis=0)
    candidate_preservation = np.array_equal(independent_union, reported_union)
    fallback_event = (~final_valid).sum(axis=0)
    fallback_ever = fallback_event > 0
    fallback_only = ~any_valid
    final_fallback = ~final_valid.any(axis=0)
    if bool((fallback_only & independent_union).any()):
        raise RuntimeError(f"fallback-only overlaps formal success: {task_hash}")

    best_ce = np.asarray([v[0] for v in best_values if v is not None], dtype=float)
    best_margin = np.asarray([v[1] for v in best_values if v is not None], dtype=float)
    success_ce = np.asarray([v[0] for v in success_values if v is not None], dtype=float)
    success_margin = np.asarray([v[1] for v in success_values if v is not None], dtype=float)
    if loss_name == "margin":
        best_loss = -best_margin
        success_loss = -success_margin
    elif loss_name == "cw":
        best_loss = np.maximum(-best_margin + CW_KAPPA, 0.0)
        success_loss = np.maximum(-success_margin + CW_KAPPA, 0.0)
    else:
        raise RuntimeError(f"unexpected P3 loss during independent inspection: {loss_name}")
    source_success = source_valid & independent_union
    denominator = int(source_valid.sum())
    feasible_asr = float(source_success.sum() / denominator) if physical and denominator else float("nan")
    task_row = {
        "unit_id": unit_id(summary["seed"], summary["model"], summary["attack"], steps),
        "loss": loss_name,
        "loss_id": LOSSES[loss_name],
        "seed": int(summary["seed"]), "split": int(summary["seed"]), "model": summary["model"],
        "attack": summary["attack"], "K": steps, "R": R,
        "task_hash": task_hash, "attack_config_hash": summary["attack_config_hash"],
        "threshold": threshold_value, "attacked_N": len(sample_ids),
        "source_valid_N": denominator, "actual_candidate_support": int(any_actual.sum()),
        "budget_valid_support": int(any_budget.sum()),
        "kinematic_valid_support": int(any_kinematic.sum()),
        "valid_or_feasible_support": int(any_valid.sum()), "formal_success": int(independent_union.sum()),
        "asr": float(independent_union.mean()), "feasible_success": int(source_success.sum()) if physical else "",
        "feasible_asr": feasible_asr if physical else "",
        "best_target_ce": float(best_ce.mean()) if len(best_ce) else float("nan"),
        "best_target_margin": float(best_margin.mean()) if len(best_margin) else float("nan"),
        "best_target_loss": float(best_loss.mean()) if len(best_loss) else float("nan"),
        "best_target_count": len(best_ce),
        "success_preserving_target_ce": float(success_ce.mean()) if len(success_ce) else float("nan"),
        "success_preserving_target_margin": float(success_margin.mean()) if len(success_margin) else float("nan"),
        "success_preserving_target_loss": float(success_loss.mean()) if len(success_loss) else float("nan"),
        "success_preserving_count": len(success_ce),
        "fallback_event": int(fallback_event.sum()), "fallback_ever": int(fallback_ever.sum()),
        "fallback_only": int(fallback_only.sum()), "final_fallback": int(final_fallback.sum()),
        "fallback_only_success": int((fallback_only & independent_union).sum()),
        "projection_failure": int(fallback_projection.sum()), "initialization_infeasible": int((~init_success.any(axis=0)).sum()),
        "restart_complete": restart_complete, "metric_identity": metric_identity,
        "candidate_preservation": candidate_preservation,
        "normal_byte_invariance": bool(summary["identity_checks"]["normal_samples_bitwise_unchanged"]),
        "far_unchanged": bool(summary["identity_checks"]["best_far_equals_clean_far"]),
        "candidate_hash_pass": sha256_file(npz_path) == summary["candidate_artifact"]["sha256"],
        "step_member_rows": row_count,
        "clean_tp_to_attack_fn": int(summary["transitions"]["best_clean_tp_to_attack_fn"]),
        "clean_fn_to_attack_tp": int(summary["transitions"]["best_clean_fn_to_attack_tp"]),
        "clean_tp": int(summary["clean_metrics"]["tp"]), "clean_fn": int(summary["clean_metrics"]["fn"]),
        "clean_fp": int(summary["clean_metrics"]["fp"]), "clean_tn": int(summary["clean_metrics"]["tn"]),
    }
    memberships = pd.DataFrame({
        "unit_id": task_row["unit_id"], "loss": loss_name, "loss_id": LOSSES[loss_name],
        "seed": task_row["seed"], "model": task_row["model"], "attack": task_row["attack"],
        "K": steps, "sample_id": sample_ids, "formal_success": independent_union,
        "success_restart_incidence": independent_restart.sum(axis=0), "source_valid_V0": source_valid,
    })
    candidates = pd.DataFrame({
        "unit_id": task_row["unit_id"], "loss": loss_name, "seed": task_row["seed"],
        "model": task_row["model"], "attack": task_row["attack"], "K": steps,
        "sample_id": sample_ids,
        "best_target_ce": [v[0] if v else np.nan for v in best_values],
        "best_target_margin": [v[1] if v else np.nan for v in best_values],
        "success_preserving_target_ce": [v[0] if v else np.nan for v in success_values],
        "success_preserving_target_margin": [v[1] if v else np.nan for v in success_values],
        "formal_success": independent_union,
    })
    return {"aggregate": task_row, "memberships": memberships, "candidates": candidates}


def ce_reaggregation(project_root: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Rebuild CE R5 memberships and physical-support diagnostics from frozen evidence."""
    p = paths(project_root)
    pieces: list[pd.DataFrame] = []
    inventory = pd.read_csv(p["p2b"] / "p2b_task_inventory.csv", dtype=str)
    norm_rows = inventory[(inventory.restarts == "5") & (inventory.execution_status == "completed") & (inventory.attack == "norm_pgd")]
    if len(norm_rows) != 20:
        raise RuntimeError(f"CE norm R5 task count != 20: {len(norm_rows)}")
    for _, row in norm_rows.iterrows():
        task_hash = row.executed_task_hash
        summary = load_json(p["p2b"] / "tasks" / task_hash / "summary.json")
        npz_path = p["p2b"] / summary["candidate_artifact"]["path"]
        if sha256_file(npz_path) != summary["candidate_artifact"]["sha256"]:
            raise RuntimeError(f"CE NPZ hash mismatch: {task_hash}")
        with np.load(npz_path, allow_pickle=False) as arrays:
            sample_ids = arrays["sample_id"].astype(str)
            success = arrays["per_restart_success"][:R].astype(bool)
            source = arrays["source_valid"].astype(bool)
        pieces.append(pd.DataFrame({
            "unit_id": unit_id(int(row.seed), row.model, row.attack, int(row.K)), "loss": "ce", "loss_id": "targeted_ce",
            "seed": int(row.seed), "model": row.model, "attack": row.attack, "K": int(row.K),
            "sample_id": sample_ids, "formal_success": success.any(axis=0),
            "success_restart_incidence": success.sum(axis=0), "source_valid_V0": source,
        }))

    matrix_path = p["p2c"] / "integrity_forensic" / "physical_support" / "sample_restart_state_matrix.csv.gz"
    columns = [
        "seed", "model", "attack", "K", "sample_id", "restart_id", "attacked",
        "source_valid", "initialization_success", "active", "final_valid",
        "projection_failed", "budget_valid", "kinematic_valid", "fallback_used",
        "success_event_is_actual_candidate",
    ]
    physical_parts: list[pd.DataFrame] = []
    for chunk in pd.read_csv(matrix_path, usecols=columns, chunksize=750_000):
        chunk = chunk[chunk.restart_id < R]
        if chunk.empty:
            continue
        for column in (
            "attacked", "source_valid", "initialization_success", "active", "final_valid",
            "projection_failed", "budget_valid", "kinematic_valid", "fallback_used",
            "success_event_is_actual_candidate",
        ):
            chunk[column] = chunk[column].map(as_bool)
        chunk["budget_valid_candidate"] = chunk.active & chunk.budget_valid
        chunk["kinematic_valid_candidate"] = chunk.active & chunk.kinematic_valid
        chunk["valid_candidate"] = chunk.active & chunk.budget_valid & chunk.kinematic_valid
        grouped = chunk.groupby(["seed", "model", "attack", "K", "sample_id"], as_index=False).agg(
            formal_success=("success_event_is_actual_candidate", "max"),
            success_restart_incidence=("success_event_is_actual_candidate", "sum"),
            source_valid_V0=("source_valid", "max"),
            attacked=("attacked", "max"),
            active=("active", "max"),
            budget_valid_candidate=("budget_valid_candidate", "max"),
            kinematic_valid_candidate=("kinematic_valid_candidate", "max"),
            valid_candidate=("valid_candidate", "max"),
            final_valid=("final_valid", "max"),
            fallback_event=("fallback_used", "sum"),
            projection_failure=("projection_failed", "max"),
            initialization_success=("initialization_success", "max"),
            restart_rows=("restart_id", "size"),
        )
        physical_parts.append(grouped)
    physical_samples = pd.concat(physical_parts, ignore_index=True).groupby(
        ["seed", "model", "attack", "K", "sample_id"], as_index=False,
    ).agg(
        formal_success=("formal_success", "max"),
        success_restart_incidence=("success_restart_incidence", "sum"),
        source_valid_V0=("source_valid_V0", "max"),
        attacked=("attacked", "max"),
        active=("active", "max"),
        budget_valid_candidate=("budget_valid_candidate", "max"),
        kinematic_valid_candidate=("kinematic_valid_candidate", "max"),
        valid_candidate=("valid_candidate", "max"),
        final_valid=("final_valid", "max"),
        fallback_event=("fallback_event", "sum"),
        projection_failure=("projection_failure", "max"),
        initialization_success=("initialization_success", "max"),
        restart_rows=("restart_rows", "sum"),
    )
    if not bool((physical_samples.restart_rows == R).all()):
        raise RuntimeError("CE physical R5 restart rows are incomplete or duplicated")
    physical_samples["unit_id"] = [
        unit_id(s, m, a, k)
        for s, m, a, k in zip(physical_samples.seed, physical_samples.model, physical_samples.attack, physical_samples.K)
    ]
    physical_samples["loss"] = "ce"
    physical_samples["loss_id"] = "targeted_ce"
    pieces.append(physical_samples[[
        "unit_id", "loss", "loss_id", "seed", "model", "attack", "K", "sample_id",
        "formal_success", "success_restart_incidence", "source_valid_V0",
    ]])
    output = pd.concat(pieces, ignore_index=True)
    if output.groupby(["seed", "model", "attack", "K"]).ngroups != 80:
        raise RuntimeError("CE membership reconstruction did not yield 80 units")

    physical_samples["feasible_success"] = physical_samples.source_valid_V0 & physical_samples.formal_success
    physical_samples["fallback_ever"] = physical_samples.fallback_event > 0
    physical_samples["fallback_only"] = ~physical_samples.valid_candidate
    physical_samples["final_fallback"] = ~physical_samples.final_valid
    physical_samples["initialization_infeasible"] = ~physical_samples.initialization_success
    physical_samples["fallback_only_success"] = physical_samples.fallback_only & physical_samples.formal_success
    physical_rows: list[dict[str, Any]] = []
    for (seed, model, attack, steps), group in physical_samples.groupby(["seed", "model", "attack", "K"], sort=False):
        attacked_n = int(group.attacked.sum())
        source_valid_n = int(group.source_valid_V0.sum())
        feasible_success = int(group.feasible_success.sum())
        physical_rows.append({
            "unit_id": unit_id(int(seed), model, attack, int(steps)),
            "loss": "ce", "loss_id": "targeted_ce", "seed": int(seed), "split": int(seed),
            "model": model, "attack": attack, "K": int(steps), "R": R,
            "task_hash": "FROZEN_P2C_R5_REAGGREGATION", "attack_config_hash": "FROZEN_CE_REFERENCE",
            "threshold": np.nan, "attacked_N": attacked_n, "source_valid_N": source_valid_n,
            "actual_candidate_support": int(group.active.sum()),
            "budget_valid_support": int(group.budget_valid_candidate.sum()),
            "kinematic_valid_support": int(group.kinematic_valid_candidate.sum()),
            "valid_or_feasible_support": int(group.valid_candidate.sum()),
            "formal_success": int(group.formal_success.sum()),
            "asr": float(group.formal_success.mean()),
            "feasible_success": feasible_success,
            "feasible_asr": float(feasible_success / source_valid_n) if source_valid_n else np.nan,
            "best_target_ce": np.nan, "best_target_margin": np.nan, "best_target_count": 0,
            "best_target_loss": np.nan,
            "success_preserving_target_ce": np.nan, "success_preserving_target_margin": np.nan,
            "success_preserving_target_loss": np.nan,
            "success_preserving_count": int(group.formal_success.sum()),
            "fallback_event": int(group.fallback_event.sum()),
            "fallback_ever": int(group.fallback_ever.sum()),
            "fallback_only": int(group.fallback_only.sum()),
            "final_fallback": int(group.final_fallback.sum()),
            "projection_failure": int(group.projection_failure.sum()),
            "initialization_infeasible": int(group.initialization_infeasible.sum()),
            "fallback_only_success": int(group.fallback_only_success.sum()),
            "restart_complete": True,
        })
    return output, pd.DataFrame(physical_rows)


def ce_transitions(project_root: Path) -> pd.DataFrame:
    """Read CE R5 prediction transitions from the frozen P2-B task summaries."""
    p = paths(project_root)
    inventory = pd.read_csv(p["p2b"] / "p2b_task_inventory.csv", dtype=str)
    rows = inventory[(inventory.restarts == "5") & (inventory.execution_status == "completed")]
    if len(rows) != 80:
        raise RuntimeError(f"CE transition source must contain 80 R5 tasks, found {len(rows)}")
    output: list[dict[str, Any]] = []
    for _, row in rows.iterrows():
        summary = load_json(p["p2b"] / "tasks" / row.executed_task_hash / "summary.json")
        output.append({
            "unit_id": unit_id(int(row.seed), row.model, row.attack, int(row.K)),
            "loss": "ce", "seed": int(row.seed), "model": row.model,
            "attack": row.attack, "K": int(row.K),
            "clean_tp": int(summary["clean_metrics"]["tp"]),
            "clean_fn": int(summary["clean_metrics"]["fn"]),
            "clean_tp_to_attack_fn": int(summary["transitions"]["best_clean_tp_to_attack_fn"]),
            "clean_fn_to_attack_tp": int(summary["transitions"]["best_clean_fn_to_attack_tp"]),
        })
    return pd.DataFrame(output)


def ce_aggregate(project_root: Path, memberships: pd.DataFrame) -> pd.DataFrame:
    p = paths(project_root)
    frame = pd.read_csv(p["source"] / "ce_r5_reference.csv")
    frame = frame[frame.R == R].copy()
    frame["unit_id"] = [unit_id(s, m, a, k) for s, m, a, k in zip(frame.seed, frame.model, frame.attack, frame.K)]
    frame = frame.rename(columns={"cumulative_ASR": "asr", "target_CE": "best_target_ce", "target_margin": "best_target_margin"})
    frame["best_target_loss"] = frame.best_target_ce
    frame["success_preserving_target_loss"] = frame.best_target_ce
    independent = memberships.groupby("unit_id").agg(formal_success=("formal_success", "sum"), incidence=("success_restart_incidence", "sum"), attacked_N=("sample_id", "size"), source_valid_recomputed=("source_valid_V0", "sum")).reset_index()
    frame = frame.merge(independent, on="unit_id", validate="one_to_one")
    frame["metric_identity"] = frame.formal_success.astype(int) == frame.cumulative_unique_success.astype(int)
    frame["loss"] = "ce"
    frame["loss_id"] = "targeted_ce"
    return frame


def group_stats(frame: pd.DataFrame, groups: list[str]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for key, group in frame.groupby(groups, dropna=False):
        if not isinstance(key, tuple):
            key = (key,)
        row = dict(zip(groups, key))
        row.update({"unit_count": len(group)})
        for column in (
            "ce_asr", "margin_asr", "cw_asr", "delta_margin_ce", "delta_cw_ce",
            "ce_feasible_asr", "margin_feasible_asr", "cw_feasible_asr",
            "delta_margin_ce_feasible", "delta_cw_ce_feasible",
        ):
            values = pd.to_numeric(group[column], errors="coerce").dropna()
            row[f"{column}_mean"] = float(values.mean()) if len(values) else np.nan
            row[f"{column}_median"] = float(values.median()) if len(values) else np.nan
            row[f"{column}_min"] = float(values.min()) if len(values) else np.nan
            row[f"{column}_max"] = float(values.max()) if len(values) else np.nan
        material_margin = group.delta_margin_ce >= MATERIAL
        material_cw = group.delta_cw_ce >= MATERIAL
        negative_margin = group.delta_margin_ce <= -MATERIAL
        negative_cw = group.delta_cw_ce <= -MATERIAL
        if (material_margin.any() or material_cw.any()) and (negative_margin.any() or negative_cw.any()):
            verdict = "MIXED"
        elif material_margin.all() and material_cw.all():
            verdict = "BOTH_STRONGER"
        elif material_margin.any() and material_cw.any():
            verdict = "BOTH_STRONGER"
        elif material_margin.any():
            verdict = "MARGIN_STRONGER"
        elif material_cw.any():
            verdict = "CW_STRONGER"
        else:
            verdict = "CE_NOT_WEAKER_AT_R5"
        row["diagnostic_verdict"] = verdict
        rows.append(row)
    return pd.DataFrame(rows)


def compact_number(value: Any) -> str:
    numeric = as_float(value)
    return "NA" if not math.isfinite(numeric) else f"{numeric:.6f}"


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in row) + " |")
    return "\n".join(lines)


def hash_tree(root: Path, relative_paths: Iterable[Path]) -> dict[str, Any]:
    relative_list = [Path(path) for path in relative_paths]
    canonical = [path.as_posix() for path in relative_list]
    duplicate_count = len(canonical) - len(set(canonical))
    artifacts = []
    missing = []
    malformed = []
    for relative in sorted(set(relative_list), key=lambda x: x.as_posix()):
        path = root / relative
        if not path.is_file():
            missing.append(relative.as_posix())
            continue
        if path.suffix == ".json":
            try:
                load_json(path)
            except Exception as exc:
                malformed.append({"path": relative.as_posix(), "error": str(exc)})
        artifacts.append({"path": relative.as_posix(), "sha256": sha256_file(path), "size_bytes": path.stat().st_size})
    return {
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "verification": {"missing_artifact_count": len(missing), "missing_artifacts": missing, "hash_mismatch_count": 0, "malformed_json_count": len(malformed), "malformed_json": malformed, "duplicate_canonical_artifact_count": duplicate_count},
        "status": "PASS" if not missing and not malformed and duplicate_count == 0 else "FAIL",
    }


def verify_hash_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Reread a written manifest and independently verify every listed file."""
    manifest = load_json(manifest_path)
    missing: list[str] = []
    mismatches: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    paths_seen: list[str] = []
    for artifact in manifest.get("artifacts", []):
        relative = str(artifact["path"])
        paths_seen.append(relative)
        path = root / Path(relative)
        if not path.is_file():
            missing.append(relative)
            continue
        observed_hash = sha256_file(path)
        observed_size = path.stat().st_size
        if observed_hash != artifact.get("sha256") or observed_size != int(artifact.get("size_bytes", -1)):
            mismatches.append({
                "path": relative, "expected_sha256": artifact.get("sha256"),
                "observed_sha256": observed_hash, "expected_size_bytes": artifact.get("size_bytes"),
                "observed_size_bytes": observed_size,
            })
        if path.suffix == ".json":
            try:
                load_json(path)
            except Exception as exc:
                malformed.append({"path": relative, "error": str(exc)})
    duplicate_count = len(paths_seen) - len(set(paths_seen))
    result = {
        "missing_artifact_count": len(missing), "missing_artifacts": missing,
        "hash_mismatch_count": len(mismatches), "hash_mismatches": mismatches,
        "malformed_json_count": len(malformed), "malformed_json": malformed,
        "duplicate_canonical_artifact_count": duplicate_count,
    }
    result["status"] = "PASS" if not missing and not mismatches and not malformed and duplicate_count == 0 else "FAIL"
    return result


def verify_source_snapshot(p: dict[str, Path]) -> dict[str, Any]:
    """Independently reread every external source frozen before execution."""
    frozen = load_json(p["source"] / "source_hashes.json")
    missing: list[str] = []
    mismatches: list[dict[str, Any]] = []
    duplicate_names: list[str] = []
    duplicate_paths: list[str] = []
    names = [item["name"] for item in frozen["artifacts"]]
    source_paths = [str(Path(item["path"]).resolve()).casefold() for item in frozen["artifacts"]]
    duplicate_names = sorted({name for name in names if names.count(name) > 1})
    duplicate_paths = sorted({path for path in source_paths if source_paths.count(path) > 1})
    for item in frozen["artifacts"]:
        path = Path(item["path"])
        if not path.is_file():
            missing.append(item["path"])
            continue
        observed_size = path.stat().st_size
        observed_hash = sha256_file(path)
        if observed_size != int(item["size_bytes"]) or observed_hash != item["sha256"]:
            mismatches.append({
                "name": item["name"], "path": item["path"],
                "expected_size_bytes": item["size_bytes"], "observed_size_bytes": observed_size,
                "expected_sha256": item["sha256"], "observed_sha256": observed_hash,
            })
    inventory = pd.read_csv(p["source"] / "source_inventory.csv", dtype=str).fillna("")
    expected = pd.DataFrame(frozen["artifacts"], dtype=str).fillna("")
    inventory_identity = (
        list(inventory.columns) == list(expected.columns)
        and len(inventory) == len(expected)
        and inventory.to_dict("records") == expected.to_dict("records")
    )
    result = {
        "missing_count": len(missing), "missing": missing,
        "mismatch_count": len(mismatches), "mismatches": mismatches,
        "duplicate_name_count": len(duplicate_names), "duplicate_names": duplicate_names,
        "duplicate_path_count": len(duplicate_paths), "duplicate_paths": duplicate_paths,
        "inventory_identity": inventory_identity,
    }
    result["status"] = "PASS" if not missing and not mismatches and not duplicate_names and not duplicate_paths and inventory_identity else "FAIL"
    return result


def loss_hash_manifest(p: dict[str, Path], loss_name: str) -> dict[str, Any]:
    loss_root = p["p3"] / loss_name
    relatives = [Path("execution_manifest.json"), Path("task_inventory.csv"), Path("ledger.jsonl"), Path("failed_attempts.jsonl"), Path("raw_results/aggregation_ledger.json"), Path("raw_results/per_step_restart_records.csv.gz"), Path("raw_results/per_sample_attack_records.csv.gz")]
    inventory = read_inventory(loss_root / "task_inventory.csv")
    for row in inventory:
        if row["execution_status"] == "completed":
            task = row["executed_task_hash"]
            relatives.extend([Path("raw_results") / "tasks" / task / "summary.json", Path("raw_results") / "tasks" / task / "candidate_iterates.npz"])
    payload = {"schema_version": "adsb.c001-p3d-loss-artifacts.v1", "loss": loss_name, "generated_at_utc": now(), **hash_tree(loss_root, relatives)}
    atomic_json(loss_root / "artifact_hashes.json", payload)
    verification = verify_hash_manifest(loss_root, loss_root / "artifact_hashes.json")
    if payload["status"] != "PASS" or verification["status"] != "PASS":
        raise RuntimeError(f"{loss_name} artifact hashes failed")
    return payload


def training_attack_identity(project_root: Path) -> dict[str, Any]:
    p = paths(project_root)
    manifest = load_json(source_files(p)["train_attack_manifest"])
    p1_root = p["p1"]
    return {
        "schema_version": "adsb.c001-p3d-training-attack.v1",
        "source": str(source_files(p)["train_attack_manifest"]),
        "source_sha256": sha256_file(source_files(p)["train_attack_manifest"]),
        "matched_baseline_source": "P1 frozen phys_hybrid_pgd/K5 summaries and per-sample artifacts",
        "p1_integrity_gate": str(p1_root / "p1_integrity_gate.json"),
        "p1_integrity_gate_sha256": sha256_file(p1_root / "p1_integrity_gate.json"),
        "p1_artifact_manifest": str(p1_root / "artifact_hashes.json"),
        "p1_artifact_manifest_sha256": sha256_file(p1_root / "artifact_hashes.json"),
        **manifest["attack"],
    }


def p1_matched_baseline(project_root: Path, training: dict[str, Any]) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Load and independently verify the exact frozen training-matched P1 baseline."""
    p = paths(project_root)
    p1_root = p["p1"]
    gate_path = p1_root / "p1_integrity_gate.json"
    manifest_path = p1_root / "artifact_hashes.json"
    gate = load_json(gate_path)
    manifest = load_json(manifest_path)
    manifest_items = {item["path"].replace("\\", "/"): item for item in manifest["artifacts"]}
    gate_item = manifest_items.get("p1_integrity_gate.json")
    gate_manifest_identity = (
        gate_item is not None
        and sha256_file(gate_path) == gate_item["sha256"]
        and gate_path.stat().st_size == int(gate_item["size_bytes"])
    )
    model_dirs = {"BiLSTM-ERM": "erm", "CAT-AD": "catad"}
    training_model_dirs = {"BiLSTM-ERM": "bilstm_erm", "CAT-AD": "cat_ad"}
    dimensions = [
        "steps", "alpha_rule", "initialization", "restart_count", "loss",
        "attack_semantics", "projection_schedule",
    ]
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    mismatches: list[str] = []
    identity_failures: list[dict[str, Any]] = []
    for seed in SEEDS:
        for model in MODELS:
            relative_dir = Path("attack_runs") / f"seed_{seed}" / model_dirs[model] / "phys_hybrid_pgd" / "k5"
            summary_relative = (relative_dir / "summary.json").as_posix()
            sample_relative = (relative_dir / "per_sample.csv.gz").as_posix()
            checkpoint_relative = (Path("training") / f"seed_{seed}" / training_model_dirs[model] / "checkpoint.pt.manifest.json").as_posix()
            summary_path = p1_root / Path(summary_relative)
            sample_path = p1_root / Path(sample_relative)
            checkpoint_path = p1_root / Path(checkpoint_relative)
            for relative, artifact_path in (
                (summary_relative, summary_path), (sample_relative, sample_path),
                (checkpoint_relative, checkpoint_path),
            ):
                item = manifest_items.get(relative)
                if item is None or not artifact_path.is_file():
                    missing.append(relative)
                elif sha256_file(artifact_path) != item["sha256"] or artifact_path.stat().st_size != int(item["size_bytes"]):
                    mismatches.append(relative)
            required_relatives = {summary_relative, sample_relative, checkpoint_relative}
            if required_relatives.intersection(missing) or required_relatives.intersection(mismatches):
                continue
            summary = load_json(summary_path)
            checkpoint_manifest = load_json(checkpoint_path)
            config = summary["attack_config"]
            exact_identity = {
                "steps": int(config["steps"]) == int(training["steps"]),
                "alpha": math.isclose(float(config["alpha"]), float(training["alpha"]), rel_tol=0.0, abs_tol=0.0),
                "initialization": config["initialization"] == training["initialization"],
                "restarts": int(config["restarts"]) == int(training["restarts"]),
                "loss": config["loss"] == training["loss"],
                "attack_id": config["attack_id"] == training["attack_id"],
                "projection_schedule": config["projection_schedule"] == training["projection_schedule"],
                "epsilon": math.isclose(float(config["epsilon"]), float(training["epsilon"]), rel_tol=0.0, abs_tol=0.0),
                "budget_scope": config["budget_scope"] == training["budget_scope"],
                "summary_status": summary.get("status") == "completed",
                "summary_identity": summary.get("identity_pass") is True,
                "model": summary.get("model") == model,
                "seed": int(summary.get("seed")) == int(seed),
                "checkpoint_sha256": checkpoint_manifest.get("checkpoint_sha256") == summary.get("checkpoint_sha256"),
                "checkpoint_training_manifest": checkpoint_manifest.get("identity", {}).get("train_attack_manifest_hash") == training["source_sha256"],
            }
            if not all(exact_identity.values()):
                identity_failures.append({"seed": seed, "model": model, "checks": exact_identity})
                continue
            sample = pd.read_csv(sample_path)
            attacked = sample[sample.original_label.astype(int) == 1].copy()
            if len(attacked) != int(summary["support"]["anomaly"]):
                identity_failures.append({"seed": seed, "model": model, "checks": {"anomaly_denominator": False}})
                continue
            best_success = attacked.best_prediction.astype(int) == 0
            best_feasible = attacked.best_feasible.map(as_bool)
            asr = float(best_success.mean())
            feasible_asr = float((best_success & best_feasible).mean())
            if not math.isclose(asr, float(summary["best_metrics"]["threshold_asr"]), rel_tol=0.0, abs_tol=1e-12):
                identity_failures.append({"seed": seed, "model": model, "checks": {"per_sample_asr_reproduction": False}})
                continue
            config_values = {
                "steps": int(config["steps"]), "alpha_rule": "fixed_0.03",
                "initialization": config["initialization"], "restart_count": int(config["restarts"]),
                "loss": config["loss"], "attack_semantics": config["attack_id"],
                "projection_schedule": config["projection_schedule"],
            }
            changed = [dimension for dimension in dimensions if config_values[dimension] != {
                "steps": int(training["steps"]), "alpha_rule": "fixed_0.03",
                "initialization": training["initialization"], "restart_count": int(training["restarts"]),
                "loss": training["loss"], "attack_semantics": training["attack_id"],
                "projection_schedule": training["projection_schedule"],
            }[dimension]]
            rows.append({
                "unit_id": canonical_hash({"source": "P1", "task_hash": summary["task_hash"]}),
                "seed": seed, "model": model, "attack": config["attack_id"], "K": int(config["steps"]),
                "loss": "ce", "asr": asr, "feasible_asr": feasible_asr,
                "classification": "MATCHED" if not changed else "HOLDOUT",
                "dimensions_changed": "|".join(changed), "dimension_change_count": len(changed),
                "multi_factor_holdout": len(changed) > 1, "steps": int(config["steps"]),
                "alpha": float(config["alpha"]), "alpha_rule": "fixed_0.03",
                "initialization": config["initialization"], "restarts": int(config["restarts"]),
                "restart_count": int(config["restarts"]), "loss_id": config["loss"],
                "attack_id": config["attack_id"], "attack_semantics": config["attack_id"],
                "projection_schedule": config["projection_schedule"], "epsilon": float(config["epsilon"]),
                "budget_scope": config["budget_scope"],
                "training_steps": int(training["steps"]), "training_alpha": float(training["alpha"]),
                "training_alpha_rule": "fixed_0.03", "training_initialization": training["initialization"],
                "training_restarts": int(training["restarts"]), "training_restart_count": int(training["restarts"]),
                "training_loss_id": training["loss"], "training_attack_id": training["attack_id"],
                "training_attack_semantics": training["attack_id"],
                "training_projection_schedule": training["projection_schedule"],
                "training_epsilon": float(training["epsilon"]), "training_budget_scope": training["budget_scope"],
                "source_stage": "P1", "source_path": summary_relative,
                "source_sha256": manifest_items[summary_relative]["sha256"], "source_task_hash": summary["task_hash"],
            })
    checks = {
        "p1_integrity_gate": gate.get("p1_integrity_gate") == "PASS",
        "p1_integrity_gate_hash_manifest_identity": gate_manifest_identity,
        "p1_artifact_manifest_schema": manifest.get("schema_version") == "adsb.c001-p1-results.v1",
        "p1_artifact_manifest_nonempty": len(manifest_items) > 0,
        "matched_artifacts_missing": len(missing) == 0,
        "matched_artifact_hash_mismatches": len(mismatches) == 0,
        "matched_identity_failures": len(identity_failures) == 0,
        "matched_row_count": len(rows) == len(SEEDS) * len(MODELS),
        "all_rows_exactly_matched": len(rows) == len(SEEDS) * len(MODELS) and all(row["classification"] == "MATCHED" for row in rows),
    }
    provenance = {
        "checks": checks, "missing": missing, "mismatches": mismatches,
        "identity_failures": identity_failures, "p1_gate_sha256": sha256_file(gate_path),
        "p1_artifact_manifest_sha256": sha256_file(manifest_path),
    }
    if not all(checks.values()):
        raise RuntimeError(f"P1 matched baseline source identity failure: {provenance}")
    return pd.DataFrame(rows), provenance


def build_holdout(project_root: Path, comparison: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    training = training_attack_identity(project_root)
    rows: list[dict[str, Any]] = []
    dimensions = ["steps", "alpha_rule", "initialization", "restart_count", "loss", "attack_semantics", "projection_schedule"]
    projection = {"norm_pgd": "none", "phys_projection_pgd": "strict_every_step", "phys_penalty_pgd": "none", "phys_hybrid_pgd": "late_plus_final"}
    initialization = {"norm_pgd": "uniform_budget", "phys_projection_pgd": "feasible_random", "phys_penalty_pgd": "uniform_budget", "phys_hybrid_pgd": "feasible_random"}
    training_values = {
        "steps": int(training["steps"]), "alpha_rule": "fixed_0.03",
        "initialization": training["initialization"], "restart_count": int(training["restarts"]),
        "loss": training["loss"], "attack_semantics": training["attack_id"],
        "projection_schedule": training["projection_schedule"],
    }
    for _, row in comparison.iterrows():
        for loss, loss_id in (("ce", "targeted_ce"), ("margin", LOSSES["margin"]), ("cw", LOSSES["cw"])):
            config = {
                "steps": int(row.K), "alpha_rule": "two_eps_over_k", "initialization": initialization[row.attack],
                "restart_count": R, "loss": loss_id, "attack_semantics": row.attack,
                "projection_schedule": projection[row.attack],
            }
            changed = [dimension for dimension in dimensions if config[dimension] != training_values[dimension]]
            rows.append({
                "unit_id": row.unit_id, "seed": row.seed, "model": row.model, "attack": row.attack, "K": row.K,
                "loss": loss, "asr": row[f"{loss}_asr"], "feasible_asr": row[f"{loss}_feasible_asr"],
                "classification": "HOLDOUT" if len(changed) >= 2 else "MATCHED",
                "dimensions_changed": "|".join(changed), "dimension_change_count": len(changed),
                "multi_factor_holdout": len(changed) > 1,
                "steps": config["steps"], "alpha": 0.2 / int(row.K), "alpha_rule": config["alpha_rule"],
                "initialization": config["initialization"], "restarts": config["restart_count"],
                "restart_count": config["restart_count"], "loss_id": config["loss"],
                "attack_id": config["attack_semantics"], "attack_semantics": config["attack_semantics"],
                "projection_schedule": config["projection_schedule"], "epsilon": float(training["epsilon"]),
                "budget_scope": training["budget_scope"],
                "training_steps": training["steps"], "training_alpha": training["alpha"],
                "training_alpha_rule": "fixed_0.03",
                "training_initialization": training["initialization"],
                "training_restarts": training["restarts"], "training_loss_id": training["loss"],
                "training_restart_count": training["restarts"], "training_attack_id": training["attack_id"],
                "training_attack_semantics": training["attack_id"],
                "training_projection_schedule": training["projection_schedule"],
                "training_epsilon": float(training["epsilon"]), "training_budget_scope": training["budget_scope"],
                "source_stage": "P2-B/P3-D", "source_path": "frozen CE R5 / completed fixed-R5 loss matrix",
                "source_sha256": "", "source_task_hash": "",
            })
    matched, provenance = p1_matched_baseline(project_root, training)
    unit = pd.concat([matched, pd.DataFrame(rows)], ignore_index=True, sort=False)
    baseline = matched[["seed", "model", "asr", "feasible_asr"]].rename(columns={"asr": "matched_asr", "feasible_asr": "matched_feasible_asr"})
    unit = unit.merge(baseline, on=["seed", "model"], how="left", validate="many_to_one")
    unit["delta_vs_matched_asr"] = unit.asr - unit.matched_asr
    unit["delta_vs_matched_feasible_asr"] = unit.feasible_asr - unit.matched_feasible_asr
    model = unit.groupby(["model", "loss", "classification"], as_index=False).agg(
        unit_count=("unit_id", "size"), asr_mean=("asr", "mean"), asr_median=("asr", "median"),
        asr_min=("asr", "min"), asr_max=("asr", "max"), feasible_asr_mean=("feasible_asr", "mean"),
        matched_asr_mean=("matched_asr", "mean"), delta_vs_matched_asr_mean=("delta_vs_matched_asr", "mean"),
        delta_vs_matched_asr_median=("delta_vs_matched_asr", "median"),
    )
    holdout = unit[unit.classification == "HOLDOUT"].copy()
    configuration = holdout.groupby(["model", "attack", "K", "loss"], as_index=False).agg(
        repeated_split_count=("seed", "size"), mean_delta=("delta_vs_matched_asr", "mean"),
        median_delta=("delta_vs_matched_asr", "median"), min_delta=("delta_vs_matched_asr", "min"),
        max_delta=("delta_vs_matched_asr", "max"),
    )
    per_model: dict[str, Any] = {}
    for model_name in MODELS:
        current = configuration[configuration.model == model_name]
        higher = int((current.mean_delta >= MATERIAL).sum())
        lower = int((current.mean_delta <= -MATERIAL).sum())
        if higher >= 2 and lower == 0:
            verdict = "YES"
        elif higher == 0:
            verdict = "NO"
        else:
            verdict = "MIXED"
        per_model[model_name] = {
            "attack_specific_sensitivity": verdict,
            "materially_higher_holdout_configurations": higher,
            "materially_lower_holdout_configurations": lower,
            "evaluated_holdout_configurations": int(len(current)),
        }
    model_verdicts = {value["attack_specific_sensitivity"] for value in per_model.values()}
    attack_specificity = next(iter(model_verdicts)) if len(model_verdicts) == 1 else "MIXED"
    diagnostic = {
        "schema_version": "adsb.c001-p3d-holdout.v1", "training_matched_result": "AVAILABLE",
        "matched_source": "frozen P1 exact K5 hybrid targeted-CE evaluation",
        "matched_row_count": int((unit.classification == "MATCHED").sum()),
        "holdout_unit_count": int((unit.classification == "HOLDOUT").sum()), "partial_R80_used": False,
        "attack_specificity": attack_specificity, "per_model": per_model,
        "classification_rule": "YES requires at least two holdout configurations with mean paired ASR delta >=0.01 and no configuration <=-0.01; NO requires zero materially higher configurations; otherwise MIXED.",
        "p1_source_identity": provenance,
        "interpretation_limit": "multi-factor holdout configurations cannot attribute differences to one dimension",
    }
    return unit, model, diagnostic


def holdout_dimension_map(unit: pd.DataFrame) -> pd.DataFrame:
    """Record the exact per-config dimension comparison and required categories."""
    columns = [
        "row_type", "category", "availability", "source", "notes", "unit_id", "seed",
        "model", "attack", "K", "loss", "dimension", "evaluated_value",
        "training_value", "changed", "classification",
    ]
    rows: list[dict[str, Any]] = []
    dimension_columns = {
        "steps": ("steps", "training_steps"),
        "alpha_rule": ("alpha_rule", "training_alpha_rule"),
        "initialization": ("initialization", "training_initialization"),
        "restart_count": ("restart_count", "training_restart_count"),
        "loss": ("loss_id", "training_loss_id"),
        "attack_semantics": ("attack_semantics", "training_attack_semantics"),
        "projection_schedule": ("projection_schedule", "training_projection_schedule"),
    }
    for _, record in unit.iterrows():
        for dimension, (evaluated_column, training_column) in dimension_columns.items():
            evaluated = record[evaluated_column]
            training = record[training_column]
            rows.append({
                "row_type": "dimension_comparison", "category": "", "availability": "AVAILABLE",
                "source": record.source_stage, "notes": record.source_path,
                "unit_id": record.unit_id, "seed": record.seed, "model": record.model,
                "attack": record.attack, "K": record.K, "loss": record.loss,
                "dimension": dimension, "evaluated_value": evaluated, "training_value": training,
                "changed": bool(evaluated != training), "classification": record.classification,
            })
    categories = [
        {"category": "training-matched / closest-matched baseline", "availability": "AVAILABLE", "source": "P1 frozen phys_hybrid_pgd/K5", "notes": "Exact match on all seven frozen major attack-design dimensions; five repeated aircraft splits per model."},
        {"category": "unseen K / alpha", "availability": "AVAILABLE", "source": "P2-B CE plus P3-D Margin/CW", "notes": "K=20/50, alpha=2epsilon/K."},
        {"category": "random-start / restart configuration", "availability": "AVAILABLE", "source": "P2-B CE plus P3-D Margin/CW", "notes": "R=5 random initialization, loss-dependent deterministic seeds."},
        {"category": "margin loss", "availability": "AVAILABLE", "source": "P3-D Margin", "notes": "Fixed R=5 matrix."},
        {"category": "CW loss", "availability": "AVAILABLE", "source": "P3-D CW", "notes": "Fixed R=5, kappa=0.0."},
        {"category": "penalty-only", "availability": "AVAILABLE", "source": "phys_penalty_pgd", "notes": "Fallback success is excluded by corrected formal semantics."},
        {"category": "strict projection", "availability": "AVAILABLE", "source": "phys_projection_pgd", "notes": "strict_every_step."},
        {"category": "hybrid", "availability": "AVAILABLE", "source": "phys_hybrid_pgd", "notes": "late_plus_final."},
    ]
    for category in categories:
        rows.append({"row_type": "required_category", **category})
    return pd.DataFrame(rows, columns=columns)


def finalize(project_root: Path) -> dict[str, Any]:
    p = paths(project_root)
    lock = p["p3"] / "p3d_runner.lock"
    if lock.exists():
        raise RuntimeError(f"cannot finalize while runner lock exists: {load_json(lock)}")
    if code_fingerprint(project_root) != EXPECTED_ATTACK_FINGERPRINT:
        raise RuntimeError("frozen attack fingerprint changed")
    inventories = {name: read_inventory(p["p3"] / name / "task_inventory.csv") for name in ("margin", "cw")}
    for name, rows in inventories.items():
        completed = [row for row in rows if row["execution_status"] == "completed"]
        if len(rows) != 80 or len(completed) != 80 or any(row["execution_status"] != "completed" for row in rows):
            raise RuntimeError(f"{name} is not exactly 80/80 complete")
        if len({row["logical_config_id"] for row in rows}) != 80 or len({row["executed_task_hash"] for row in rows}) != 80:
            raise RuntimeError(f"{name} duplicate task identity")

    for directory in ("reaggregation", "gates", "loss_diagnostic", "holdout_diagnostic", "diagnostics", "final"):
        (p["p3"] / directory).mkdir(parents=True, exist_ok=True)

    aggregates: dict[str, list[dict[str, Any]]] = {"margin": [], "cw": []}
    membership_pieces: list[pd.DataFrame] = []
    candidate_pieces: list[pd.DataFrame] = []
    for loss_name in ("margin", "cw"):
        for row in inventories[loss_name]:
            checked = inspect_task(project_root, loss_name, row["executed_task_hash"])
            aggregates[loss_name].append(checked["aggregate"])
            membership_pieces.append(checked["memberships"])
            candidate_pieces.append(checked["candidates"])
        loss_hash_manifest(p, loss_name)

    ce_members, ce_physical = ce_reaggregation(project_root)
    ce_frame = ce_aggregate(project_root, ce_members)
    margin_frame = pd.DataFrame(aggregates["margin"])
    cw_frame = pd.DataFrame(aggregates["cw"])
    memberships = pd.concat([ce_members, *membership_pieces], ignore_index=True)
    candidates = pd.concat(candidate_pieces, ignore_index=True)
    atomic_dataframe(p["p3"] / "reaggregation" / "ce_r5_corrected.csv", ce_frame)
    atomic_dataframe(p["p3"] / "reaggregation" / "margin_r5_corrected.csv", margin_frame)
    atomic_dataframe(p["p3"] / "reaggregation" / "cw_r5_corrected.csv", cw_frame)
    atomic_dataframe(p["p3"] / "reaggregation" / "success_memberships.csv.gz", memberships, compression="gzip")
    atomic_dataframe(p["p3"] / "reaggregation" / "candidate_summary.csv", candidates)
    physical_support = pd.concat([ce_physical, margin_frame, cw_frame], ignore_index=True, sort=False)
    physical_support = physical_support[physical_support.attack.isin(PHYSICAL)]
    atomic_dataframe(p["p3"] / "reaggregation" / "physical_support.csv", physical_support)
    atomic_dataframe(p["p3"] / "reaggregation" / "fallback_summary.csv", physical_support[["unit_id", "loss", "seed", "model", "attack", "K", "fallback_event", "fallback_ever", "fallback_only", "final_fallback", "projection_failure", "initialization_infeasible"]])

    # Gate the complete frozen matrix before producing any formal loss or
    # holdout interpretation.  G10 is evaluated only after those downstream
    # artifacts have been written and independently reread.
    train = training_attack_identity(project_root)
    _, p1_provenance = p1_matched_baseline(project_root, train)
    frozen_source_verification = verify_source_snapshot(p)
    source_identity_checks = {
        "attack_fingerprint": code_fingerprint(project_root) == EXPECTED_ATTACK_FINGERPRINT,
        "p2c_final_integrity_v2": load_json(source_files(p)["p2c_final_integrity_v2"])["status"] == "PASS",
        "r40_snapshot": load_json(source_files(p)["p2c_r40_snapshot"])["r40_raw_snapshot_hash"] == EXPECTED_R40_SNAPSHOT,
        "p2c_posthoc": load_json(source_files(p)["p2c_posthoc_fingerprint"])["new_reaggregation_fingerprint"] == EXPECTED_P2C_POSTHOC,
        "p2d_termination": verify_p2d_manifest(p)["pass"],
        "p1_integrity": all(p1_provenance["checks"].values()),
        "training_attack_manifest": train["source_sha256"] == sha256_file(source_files(p)["train_attack_manifest"]),
        "frozen_source_snapshot": frozen_source_verification["status"] == "PASS",
        "partial_R80_excluded": True,
    }
    config_hashes = load_json(p["freeze"] / "p3d_configuration_hashes.json")
    config_checks = {name: sha256_file(p["freeze"] / name) == digest for name, digest in config_hashes["artifacts"].items()}
    config_checks["p3d_runner.py"] = sha256_file(project_root / "audit_tools" / "p3d_runner.py") == config_hashes["runner_sha256"]
    task_checks = pd.concat([margin_frame, cw_frame], ignore_index=True)
    inventory_reference = pd.concat([
        pd.DataFrame(inventories[name]).assign(loss=name) for name in ("margin", "cw")
    ], ignore_index=True)
    identity = task_checks.merge(
        inventory_reference[[
            "unit_id", "loss", "loss_id", "restarts", "attack_config_hash",
            "executed_task_hash", "threshold",
        ]],
        on=["unit_id", "loss"], suffixes=("_task", "_inventory"), validate="one_to_one",
    )
    task_configuration_identity = (
        (identity.loss_id_task == identity.loss_id_inventory)
        & (identity.R.astype(int) == identity.restarts.astype(int))
        & (identity.attack_config_hash_task == identity.attack_config_hash_inventory)
        & (identity.task_hash == identity.executed_task_hash)
    )
    task_threshold_identity = np.isclose(
        identity.threshold_task.astype(float), identity.threshold_inventory.astype(float),
        rtol=0.0, atol=0.0,
    )
    gates = {
        "Source Identity": all(source_identity_checks.values()),
        "Configuration": all(config_checks.values()) and bool(task_configuration_identity.all()),
        "Matrix Completeness": len(margin_frame) == 80 and len(cw_frame) == 80,
        "Restart Completeness": bool(task_checks.restart_complete.all()),
        "Candidate Preservation": bool(task_checks.candidate_preservation.all()),
        "Metric Identity": bool(task_checks.metric_identity.all()) and bool(ce_frame.metric_identity.all()),
        "Physical Support": (
            bool((physical_support.formal_success <= physical_support.valid_or_feasible_support).all())
            and int(physical_support.fallback_only_success.sum()) == 0
        ),
        "Threshold Identity": bool(task_threshold_identity.all()),
        "Normal Byte Invariance": bool(task_checks.normal_byte_invariance.all() & task_checks.far_unchanged.all()),
    }
    atomic_json(p["p3"] / "gates" / "source_identity_gate.json", {"gate": "Source Identity", "checks": source_identity_checks, "source_snapshot_verification": frozen_source_verification, "p1_source_verification": p1_provenance, "status": "PASS" if gates["Source Identity"] else "FAIL"})
    atomic_json(p["p3"] / "gates" / "configuration_gate.json", {
        "gate": "Configuration", "checks": config_checks,
        "task_configuration_identity_failures": int((~task_configuration_identity).sum()),
        "threshold_identity_failures": int((~task_threshold_identity).sum()),
        "status": "PASS" if gates["Configuration"] and gates["Threshold Identity"] else "FAIL",
    })
    atomic_json(p["p3"] / "gates" / "completeness_gate.json", {"gate": "Matrix and Restart Completeness", "margin": len(margin_frame), "cw": len(cw_frame), "restart_failures": int((~task_checks.restart_complete).sum()), "status": "PASS" if gates["Matrix Completeness"] and gates["Restart Completeness"] else "FAIL"})
    atomic_json(p["p3"] / "gates" / "metric_identity_gate.json", {"gate": "Candidate Preservation and Metric Identity", "candidate_failures": int((~task_checks.candidate_preservation).sum()), "metric_failures": int((~task_checks.metric_identity).sum()) + int((~ce_frame.metric_identity).sum()), "status": "PASS" if gates["Candidate Preservation"] and gates["Metric Identity"] else "FAIL"})
    atomic_json(p["p3"] / "gates" / "physical_support_gate.json", {
        "gate": "Physical Support", "status": "PASS" if gates["Physical Support"] else "FAIL",
        "fallback_only_success": int(physical_support.fallback_only_success.sum()),
        "formal_success_exceeds_valid_support_units": int((physical_support.formal_success > physical_support.valid_or_feasible_support).sum()),
    })
    if not all(gates.values()):
        failed_gate = {
            "schema_version": "adsb.c001-p3d-final-integrity.v1",
            "gate": "Final P3-Diagnostic Integrity",
            "checks": {**{name: "PASS" if value else "FAIL" for name, value in gates.items()}, "Artifact Hash": "NOT_ASSESSED"},
            "status": "FAIL", "formal_attack_adequacy": "NOT_ESTABLISHED", "formal_P3_clearance": "DENIED",
            "interpretation_performed": False,
        }
        atomic_json(p["p3"] / "gates" / "p3d_final_integrity_gate.json", failed_gate)
        raise RuntimeError("P3-DIAGNOSTIC INTEGRITY FAILURE before loss interpretation")

    ce_select = ce_frame[["unit_id", "seed", "model", "attack", "K", "asr", "feasible_ASR", "best_target_ce", "best_target_margin", "best_target_loss"]].rename(columns={"asr": "ce_asr", "feasible_ASR": "ce_feasible_asr", "best_target_ce": "ce_target_ce", "best_target_margin": "ce_target_margin", "best_target_loss": "ce_best_target_loss"})
    margin_select = margin_frame[["unit_id", "asr", "feasible_asr", "best_target_ce", "best_target_margin", "best_target_loss"]].rename(columns={"asr": "margin_asr", "feasible_asr": "margin_feasible_asr", "best_target_ce": "margin_target_ce", "best_target_margin": "margin_target_margin", "best_target_loss": "margin_best_target_loss"})
    cw_select = cw_frame[["unit_id", "asr", "feasible_asr", "best_target_ce", "best_target_margin", "best_target_loss"]].rename(columns={"asr": "cw_asr", "feasible_asr": "cw_feasible_asr", "best_target_ce": "cw_target_ce", "best_target_margin": "cw_target_margin", "best_target_loss": "cw_best_target_loss"})
    comparison = ce_select.merge(margin_select, on="unit_id", validate="one_to_one").merge(cw_select, on="unit_id", validate="one_to_one")
    for column in (
        "ce_asr", "margin_asr", "cw_asr", "ce_feasible_asr", "margin_feasible_asr",
        "cw_feasible_asr", "ce_target_ce", "margin_target_ce", "cw_target_ce",
        "ce_target_margin", "margin_target_margin", "cw_target_margin",
        "ce_best_target_loss", "margin_best_target_loss", "cw_best_target_loss",
    ):
        comparison[column] = pd.to_numeric(comparison[column], errors="coerce")
    comparison["delta_margin_ce"] = comparison.margin_asr - comparison.ce_asr
    comparison["delta_cw_ce"] = comparison.cw_asr - comparison.ce_asr
    comparison["delta_margin_ce_feasible"] = comparison.margin_feasible_asr - comparison.ce_feasible_asr
    comparison["delta_cw_ce_feasible"] = comparison.cw_feasible_asr - comparison.ce_feasible_asr
    comparison["ceiling_status"] = np.where((1.0 - comparison.ce_asr) < CEILING_HEADROOM, "CEILING-LIMITED COMPARISON", "NOT_CEILING_LIMITED")
    comparison["margin_material"] = comparison.delta_margin_ce.abs() >= MATERIAL
    comparison["cw_material"] = comparison.delta_cw_ce.abs() >= MATERIAL
    comparison["diagnostic_verdict"] = np.select(
        [(comparison.delta_margin_ce >= MATERIAL) & (comparison.delta_cw_ce >= MATERIAL), comparison.delta_margin_ce >= MATERIAL, comparison.delta_cw_ce >= MATERIAL],
        ["BOTH_STRONGER", "MARGIN_STRONGER", "CW_STRONGER"], default="CE_NOT_WEAKER_AT_R5",
    )
    atomic_dataframe(p["p3"] / "loss_diagnostic" / "loss_comparison_by_unit.csv", comparison)
    family = group_stats(comparison, ["attack"])
    model = group_stats(comparison, ["model"])
    atomic_dataframe(p["p3"] / "loss_diagnostic" / "loss_comparison_by_family.csv", family)
    atomic_dataframe(p["p3"] / "loss_diagnostic" / "loss_comparison_by_model.csv", model)

    strongest_rows = []
    for _, row in comparison.iterrows():
        values = {loss: float(row[f"{loss}_asr"]) for loss in ("ce", "margin", "cw")}
        maximum = max(values.values())
        tied = [loss for loss, value in values.items() if value == maximum]
        strongest_rows.append({
            "unit_id": row.unit_id, "seed": row.seed, "model": row.model,
            "attack": row.attack, "K": row.K,
            "strongest_loss_at_R5": "|".join(tied), "asr": maximum,
            "feasible_asr": "|".join(str(row[f"{loss}_feasible_asr"]) for loss in tied),
            "target_margin": "|".join(str(row[f"{loss}_target_margin"]) for loss in tied),
            "best_target_loss": "|".join(str(row[f"{loss}_best_target_loss"]) for loss in tied),
            "tie_count": len(tied),
            "status": "RESOURCE-BOUNDED DIAGNOSTIC STRONGEST LOSS",
        })
    strongest = pd.DataFrame(strongest_rows)
    atomic_dataframe(p["p3"] / "loss_diagnostic" / "strongest_loss_at_r5.csv", strongest)
    material_payload = {
        "schema_version": "adsb.c001-p3d-loss-material.v1", "threshold": MATERIAL,
        "material_margin_units": int((comparison.delta_margin_ce.abs() >= MATERIAL).sum()),
        "material_cw_units": int((comparison.delta_cw_ce.abs() >= MATERIAL).sum()),
        "ceiling_limited_units": int((comparison.ceiling_status == "CEILING-LIMITED COMPARISON").sum()),
        "interpretation": "diagnostic_only", "attack_adequacy": "NOT_ESTABLISHED",
    }
    atomic_json(p["p3"] / "loss_diagnostic" / "loss_material_difference.json", material_payload)

    atomic_json(p["p3"] / "holdout_diagnostic" / "training_attack_identity.json", train)
    holdout_unit, holdout_model, specificity = build_holdout(project_root, comparison)
    atomic_dataframe(p["p3"] / "holdout_diagnostic" / "matched_holdout_dimension_map.csv", holdout_dimension_map(holdout_unit))
    atomic_dataframe(p["p3"] / "holdout_diagnostic" / "holdout_results_by_unit.csv", holdout_unit)
    atomic_dataframe(p["p3"] / "holdout_diagnostic" / "holdout_results_by_model.csv", holdout_model)
    atomic_json(p["p3"] / "holdout_diagnostic" / "attack_specificity_diagnostic.json", specificity)

    atomic_dataframe(p["p3"] / "diagnostics" / "ceiling_effect.csv", comparison[["unit_id", "seed", "model", "attack", "K", "ce_asr", "ceiling_status"]])
    transitions = pd.concat([
        ce_transitions(project_root),
        pd.concat([margin_frame, cw_frame], ignore_index=True)[[
            "unit_id", "loss", "seed", "model", "attack", "K", "clean_tp", "clean_fn",
            "clean_tp_to_attack_fn", "clean_fn_to_attack_tp",
        ]],
    ], ignore_index=True)
    atomic_dataframe(p["p3"] / "diagnostics" / "prediction_transitions.csv", transitions)
    physical_by_loss = physical_support.groupby(["loss", "model", "attack"], as_index=False).agg(
        unit_count=("unit_id", "size"), attacked_N=("attacked_N", "sum"),
        source_valid_N=("source_valid_N", "sum"), budget_valid_support=("budget_valid_support", "sum"),
        kinematic_valid_support=("kinematic_valid_support", "sum"),
        feasible_support=("valid_or_feasible_support", "sum"), formal_success=("formal_success", "sum"),
        feasible_success=("feasible_success", "sum"), asr_mean=("asr", "mean"),
        feasible_asr_mean=("feasible_asr", "mean"),
    )
    atomic_dataframe(p["p3"] / "diagnostics" / "physical_support_by_loss.csv", physical_by_loss)
    fallback_by_loss = physical_support.groupby(["loss", "model", "attack"], as_index=False).agg(fallback_event=("fallback_event", "sum"), fallback_ever=("fallback_ever", "sum"), fallback_only=("fallback_only", "sum"), final_fallback=("final_fallback", "sum"), projection_failure=("projection_failure", "sum"), initialization_infeasible=("initialization_infeasible", "sum"))
    atomic_dataframe(p["p3"] / "diagnostics" / "fallback_by_loss.csv", fallback_by_loss)
    atomic_dataframe(p["p3"] / "diagnostics" / "per_split_results.csv", comparison)

    required_before_hash = [
        Path("configuration_freeze") / name for name in ("p3d_preregistration.json", "p3d_attack_matrix.csv", "p3d_loss_definitions.json", "p3d_cw_parameter_freeze.json", "p3d_resource_budget.json", "p3d_restart_spec.json", "loss_pairing_status.json", "p3d_holdout_definition.json", "p3d_claim_constraints.json", "p3d_configuration_hashes.json")
    ] + [Path("source_snapshot") / name for name in ("p2c_identity.json", "p2d_termination_identity.json", "ce_r5_reference.csv", "source_hashes.json", "source_inventory.csv")]
    for directory, names in {
        "reaggregation": ("ce_r5_corrected.csv", "margin_r5_corrected.csv", "cw_r5_corrected.csv", "success_memberships.csv.gz", "candidate_summary.csv", "physical_support.csv", "fallback_summary.csv"),
        "loss_diagnostic": ("loss_comparison_by_unit.csv", "loss_comparison_by_family.csv", "loss_comparison_by_model.csv", "strongest_loss_at_r5.csv", "loss_material_difference.json"),
        "holdout_diagnostic": ("training_attack_identity.json", "matched_holdout_dimension_map.csv", "holdout_results_by_unit.csv", "holdout_results_by_model.csv", "attack_specificity_diagnostic.json"),
        "diagnostics": ("ceiling_effect.csv", "prediction_transitions.csv", "physical_support_by_loss.csv", "fallback_by_loss.csv", "per_split_results.csv"),
        "gates": ("source_identity_gate.json", "configuration_gate.json", "completeness_gate.json", "metric_identity_gate.json", "physical_support_gate.json"),
    }.items():
        required_before_hash.extend(Path(directory) / name for name in names)
    required_before_hash.extend([Path("margin/artifact_hashes.json"), Path("cw/artifact_hashes.json")])
    artifact_gate = {"schema_version": "adsb.c001-p3d-artifact-gate.v1", "generated_at_utc": now(), **hash_tree(p["p3"], required_before_hash)}
    atomic_json(p["p3"] / "gates" / "artifact_hash_gate.json", artifact_gate)
    artifact_verification = verify_hash_manifest(p["p3"], p["p3"] / "gates" / "artifact_hash_gate.json")
    artifact_gate["independent_reread_verification"] = artifact_verification
    atomic_json(p["p3"] / "gates" / "artifact_hash_gate.json", artifact_gate)
    gates["Artifact Hash"] = artifact_gate["status"] == "PASS" and artifact_verification["status"] == "PASS"
    final_status = "PASS" if all(gates.values()) else "FAIL"
    final_gate = {"schema_version": "adsb.c001-p3d-final-integrity.v1", "gate": "Final P3-Diagnostic Integrity", "checks": {name: "PASS" if value else "FAIL" for name, value in gates.items()}, "status": final_status, "formal_attack_adequacy": "NOT_ESTABLISHED", "formal_P3_clearance": "DENIED"}
    atomic_json(p["p3"] / "gates" / "p3d_final_integrity_gate.json", final_gate)

    interpretation = "INCONCLUSIVE"
    if final_status == "PASS":
        material_positive = (comparison.delta_margin_ce >= MATERIAL) | (comparison.delta_cw_ce >= MATERIAL)
        positive = int(material_positive.sum())
        negative = int(((comparison.delta_margin_ce <= -MATERIAL) | (comparison.delta_cw_ce <= -MATERIAL)).sum())
        if positive and negative:
            interpretation = "LOSS EFFECT HETEROGENEOUS"
        elif positive:
            interpretation = "CE LOSS SENSITIVITY OBSERVED"
        else:
            interpretation = "NO MATERIAL LOSS DIFFERENCE OBSERVED AT R5"
    decision = "READY FOR P4-DIAGNOSTIC PHYSICAL DECOMPOSITION" if final_status == "PASS" else "P3-DIAGNOSTIC INTEGRITY FAILURE"
    atomic_json(p["p3"] / "final" / "next_stage_decision.json", {"decision": decision, "formal_attack_adequacy_clearance": False, "formal_P3_clearance": "DENIED", "interpretation": interpretation})

    gate_rows = [[name, "PASS" if value else "FAIL"] for name, value in gates.items()]
    gate_rows.append(["Final P3-Diagnostic Integrity", final_status])
    family_rows = [[
        record.attack, compact_number(record.ce_asr_mean), compact_number(record.margin_asr_mean),
        compact_number(record.cw_asr_mean), compact_number(record.delta_margin_ce_mean),
        compact_number(record.delta_cw_ce_mean),
        f"{compact_number(record.delta_margin_ce_feasible_mean)} / {compact_number(record.delta_cw_ce_feasible_mean)}",
        record.diagnostic_verdict,
    ] for record in family.itertuples(index=False)]
    model_rows = [[
        record.model, compact_number(record.ce_asr_mean), compact_number(record.margin_asr_mean),
        compact_number(record.cw_asr_mean), compact_number(record.delta_margin_ce_mean),
        compact_number(record.delta_cw_ce_mean), record.diagnostic_verdict,
    ] for record in model.itertuples(index=False)]
    strongest_summary = strongest.groupby(["model", "attack"], as_index=False).agg(
        strongest_losses=("strongest_loss_at_R5", lambda values: ";".join(sorted(set(values)))),
        asr_mean=("asr", "mean"), feasible_asr_values=("feasible_asr", lambda values: ";".join(values)),
        target_margin_values=("target_margin", lambda values: ";".join(values)),
        split_patterns=("strongest_loss_at_R5", lambda values: ";".join(values)),
    )
    strongest_rows_report = [[
        record.model, record.attack, record.strongest_losses, compact_number(record.asr_mean),
        record.feasible_asr_values, record.target_margin_values, record.split_patterns,
    ] for record in strongest_summary.itertuples(index=False)]
    matched_summary = holdout_unit[holdout_unit.classification == "MATCHED"].groupby("model", as_index=False).agg(
        asr_mean=("asr", "mean"), feasible_asr_mean=("feasible_asr", "mean"),
        asr_min=("asr", "min"), asr_max=("asr", "max"), split_count=("seed", "size"),
    )
    holdout_report_rows = []
    for record in matched_summary.itertuples(index=False):
        diagnostic = specificity["per_model"][record.model]
        holdout_report_rows.append([
            record.model, compact_number(record.asr_mean), compact_number(record.feasible_asr_mean),
            f"{compact_number(record.asr_min)}–{compact_number(record.asr_max)}", record.split_count,
            diagnostic["evaluated_holdout_configurations"], diagnostic["materially_higher_holdout_configurations"],
            diagnostic["materially_lower_holdout_configurations"], diagnostic["attack_specific_sensitivity"],
        ])
    report = f"""# C0-01 P3-Diagnostic Report

## 1. Source Identity

- canonical root: `{project_root}`
- P2-C Final Integrity: PASS (v2)
- R40 snapshot: `{EXPECTED_R40_SNAPSHOT}`
- attack fingerprint: `{EXPECTED_ATTACK_FINGERPRINT}`
- P2-D resource termination verified: YES
- partial R80 used: NO
- source identity verdict: PASS

## 2. P3-Diagnostic Freeze

- stage type: DIAGNOSTIC ONLY
- R: 5 (restart IDs 0–4)
- K: 20, 50
- losses: targeted CE (reconstructed, not rerun), targeted logit margin, CW-style margin
- attack families: norm_pgd, phys_projection_pgd, phys_penalty_pgd, phys_hybrid_pgd
- comparison units: 80
- new logical configs: 160
- maximum new restart trajectories: 800
- CW kappa: {CW_KAPPA}
- initialization pairing: UNPAIRED — SAME DISTRIBUTION / SAME RESTART BUDGET
- configuration hash: `{config_hashes['configuration_hash']}`

## 3. Execution

- Margin: expected 80; completed 80; failed 0; missing 0; duplicate 0; restarts 0–4.
- CW: expected 80; completed 80; failed 0; missing 0; duplicate 0; restarts 0–4.
- R10 executed: NO
- R20 executed: NO
- R40 new executed: NO
- R80 resumed: NO

## 4. Integrity

{markdown_table(['Gate', 'Verdict'], gate_rows)}

## 5. Loss Results

The material diagnostic threshold is an absolute ASR difference of {MATERIAL}. Exact per-split values remain in `loss_comparison_by_unit.csv`; the summaries below do not replace them.

### By attack family

{markdown_table(['Family', 'CE R5 ASR', 'Margin R5 ASR', 'CW R5 ASR', 'ΔMargin-CE', 'ΔCW-CE', 'Feasible ΔMargin / ΔCW', 'Diagnostic verdict'], family_rows)}

### By model

{markdown_table(['Model', 'CE R5 ASR', 'Margin R5 ASR', 'CW R5 ASR', 'ΔMargin-CE', 'ΔCW-CE', 'Diagnostic verdict'], model_rows)}

Ceiling status is retained per unit in `diagnostics/ceiling_effect.csv`; {material_payload['ceiling_limited_units']} of 80 units are marked CEILING-LIMITED COMPARISON.

## 6. Strongest Loss

{markdown_table(['Model', 'Family', 'Strongest observed loss at R5', 'Mean ASR', 'Per-split feasible ASR', 'Per-split target margin', 'Consistency across splits'], strongest_rows_report)}

RESOURCE-BOUNDED DIAGNOSTIC ONLY.

## 7. Holdout Results

- training attack identity: phys_hybrid_pgd, targeted CE, K=5, alpha=0.03, clean initialization, R=1, late_plus_final projection, epsilon=0.1, normalized_raw6 budget.
- matched baseline: AVAILABLE from 10 independently hash-verified frozen P1 K5 hybrid evaluations (five repeated aircraft splits per model).
- holdout configurations: P2-B CE and P3-D Margin/CW at K={{20,50}}, R=5, alpha=2epsilon/K, loss-specific deterministic restart seeds, and family-specific initialization/constraint semantics.
- dimensions changed: steps, alpha rule, initialization where applicable, restart count, loss where applicable, attack semantics where applicable, and projection schedule where applicable.

{markdown_table(['Model', 'Matched ASR mean', 'Matched feasible ASR mean', 'Matched ASR min–max', 'Splits', 'Holdout configs', 'Materially higher', 'Materially lower', 'Sensitivity'], holdout_report_rows)}

- attack-specific sensitivity: {specificity['attack_specificity']}
- interpretation limit: all P3 holdouts are multi-factor holdout configurations; differences cannot be assigned to a single changed dimension. Loss-specific attribution uses only equal-K/equal-R/equal-family/equal-model/equal-split CE/Margin/CW comparisons.

## 8. Restart Limitation

Fixed-restart saturation within R≤40 remains NOT ESTABLISHED.

Formal R80 adequacy remains NOT ASSESSED.

P3-Diagnostic does not repair or replace the failed restart-adequacy gate.

## 9. Interpretation

{interpretation}.

Holdout diagnostic classification: {specificity['attack_specificity']}. This evidence is diagnostic and does not establish attack adequacy or prove attack overfitting.

## 10. Formal Research Status

- restart saturation: NOT ESTABLISHED
- attack adequacy: NOT ESTABLISHED
- formal P3 clearance: DENIED
- P3 diagnostic integrity: {final_status}
- robustness claims: SUSPENDED

## 11. Next Stage

{decision}

This is not formal attack-adequacy clearance.

## 12. Stop Confirmation

- Partial R80 data was not used.
- R80 was not resumed.
- R160 was not executed.
- R320 was not executed.
- No new restart above 4 was executed.
- CE was not rerun.
- Margin and CW used the same fixed R=5 computational budget.
- No loss was dropped based on intermediate results.
- No model received a larger attack budget based on outcome.
- No immutable P2-C/P2-D record was modified.
- No failed or unfavorable result was deleted.
- P4–P6 were not executed.
- The manuscript was not modified.
- Restart saturation remains unresolved.
- Formal attack adequacy remains unresolved.
- No CAT-AD robustness or superiority claim was restored.
"""
    (p["p3"] / "final" / "p3d_report.md").write_text(report, encoding="utf-8")
    final_relatives = required_before_hash + [Path("gates/artifact_hash_gate.json"), Path("gates/p3d_final_integrity_gate.json"), Path("final/p3d_report.md"), Path("final/next_stage_decision.json")]
    final_hashes = {"schema_version": "adsb.c001-p3d-final-artifacts.v1", "generated_at_utc": now(), "self_excluded": True, **hash_tree(p["p3"], final_relatives)}
    atomic_json(p["p3"] / "final" / "p3d_artifact_hashes.json", final_hashes)
    final_verification = verify_hash_manifest(p["p3"], p["p3"] / "final" / "p3d_artifact_hashes.json")
    final_hashes["independent_reread_verification"] = final_verification
    atomic_json(p["p3"] / "final" / "p3d_artifact_hashes.json", final_hashes)
    if final_hashes["status"] != "PASS" or final_verification["status"] != "PASS":
        raise RuntimeError("final P3-Diagnostic artifact hash verification failed")
    return {"status": final_status, "decision": decision, "interpretation": interpretation, "artifacts": final_hashes["artifact_count"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check-task", "finalize"))
    parser.add_argument("--project-root", type=Path, default=Path(r"E:\ads-b\ADS-B2 -beifen"))
    parser.add_argument("--loss", choices=("margin", "cw"))
    parser.add_argument("--task-hash")
    args = parser.parse_args()
    if args.command == "check-task":
        if not args.loss or not args.task_hash:
            parser.error("check-task requires --loss and --task-hash")
        result = inspect_task(args.project_root, args.loss, args.task_hash)["aggregate"]
    else:
        result = finalize(args.project_root)
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()

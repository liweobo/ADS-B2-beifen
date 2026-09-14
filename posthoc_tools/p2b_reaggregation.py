"""Independent support-consistent aggregation for C0-01 P2-B.

The attack runner is treated as immutable.  This module reads hash-addressed
gzip members, reconstructs all candidate semantics from native step/restart
records, freezes the preregistered R10 decision, and later produces the final
P2-B tables, figures, and gates.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import os
import traceback
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adsb.checkpoints import sha256_file
from adsb.p2_step_size_restart import ATTACKS, MODELS, RANDOM_INITIALIZATION, SEEDS, STEPS, _attack_config
from audit_tools.p2b_runner import (
    EXPECTED_ATTACK_CODE_FINGERPRINT,
    EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
    EXPECTED_P2B_MANIFEST_SHA256,
    EXPECTED_P2B_TASK_LIST_SHA256,
    TASK_FIELDS,
    atomic_inventory,
    atomic_json,
    key_for,
    load_json,
    now,
    read_inventory,
)
from posthoc_tools.p2a_reaggregation import (
    PHYSICAL_ATTACKS,
    SAMPLE_FIELDS,
    STEP_FIELDS,
    Candidate,
    ConfigAudit,
    SampleState,
    as_bool,
    as_float,
    as_int,
    candidate_rank,
    choose_final,
    choose_success_preserving,
    finite,
    iter_member,
    load_sample_member,
    member_bounds,
    sha256_range,
    success_rank,
    update_state,
)


SCHEMA = "adsb.c001-p2b-reaggregation.v1"


def task_summary(task_root: Path, task_hash: str) -> dict[str, Any]:
    path = task_root / "tasks" / task_hash / "summary.json"
    value = load_json(path)
    if value.get("status") != "completed" or value.get("task_hash") != task_hash:
        raise RuntimeError(f"task summary is not a completed identity match: {path}")
    return value


def candidate_from_row(row: dict[str, str]) -> Candidate:
    return Candidate(
        sample_id=row["sample_id"],
        aircraft_id=row["aircraft_id"],
        restart_id=as_int(row["restart_id"]),
        step=as_int(row["step"]),
        p_anomaly=as_float(row["p_anomaly"]),
        target_ce=as_float(row["target_ce"]),
        target_margin=as_float(row["target_margin"]),
        active=as_bool(row["candidate_active"]),
        source_valid=as_bool(row["source_valid"]),
        budget_valid=as_bool(row["budget_valid"]),
        kinematic_valid=as_bool(row["kinematic_valid"]),
        post_valid=as_bool(row["post_valid"]),
        projection_converged=as_bool(row["projection_converged"]),
        projection_status=str(row["projection_status"]),
    )


def compact_candidate(candidate: Candidate | None) -> dict[str, Any] | None:
    if candidate is None:
        return None
    return {
        "restart_id": candidate.restart_id,
        "step": candidate.step,
        "p_anomaly": candidate.p_anomaly,
        "target_ce": candidate.target_ce,
        "target_margin": candidate.target_margin,
        "active": candidate.active,
        "source_valid": candidate.source_valid,
        "budget_valid": candidate.budget_valid,
        "kinematic_valid": candidate.kinematic_valid,
        "post_valid": candidate.post_valid,
        "projection_converged": candidate.projection_converged,
        "projection_status": candidate.projection_status,
    }


def min_candidate(candidates: list[Candidate]) -> Candidate | None:
    return min(candidates, key=candidate_rank) if candidates else None


def choose_prefix_final(candidates: list[Candidate], physical: bool) -> Candidate | None:
    if not candidates:
        return None
    feasible = [candidate for candidate in candidates if candidate.feasible(physical)]
    return min(feasible if feasible else candidates, key=candidate_rank)


def choose_prefix_success(
    successes: list[Candidate],
    best_loss: Candidate | None,
    physical: bool,
) -> Candidate | None:
    if successes:
        return min(successes, key=lambda candidate: success_rank(candidate, physical))
    return best_loss


def aggregate_state_checks(audit: ConfigAudit, states: dict[str, SampleState], expected_pairs: set[tuple[int, int]]) -> None:
    for state in states.values():
        audit.missing_steps += len(expected_pairs - state.seen)
        audit.duplicate_steps += state.duplicate_steps
        audit.nan_rows += state.nan_rows
        audit.ce_probability_mismatch += state.ce_probability_mismatch
        audit.margin_probability_mismatch += state.margin_probability_mismatch
        audit.margin_probability_gate_mismatch += state.margin_probability_gate_mismatch
        audit.margin_probability_not_reconstructable += state.margin_probability_not_reconstructable
        audit.threshold_flag_mismatch += state.threshold_flag_mismatch
        audit.threshold_flag_gate_mismatch += state.threshold_flag_gate_mismatch
        audit.threshold_flag_boundary_ambiguous += state.threshold_flag_boundary_ambiguous
        audit.argmax_flag_mismatch += state.argmax_flag_mismatch
        audit.probability_pair_mismatch += state.probability_pair_mismatch


def analyze_task(
    task_root: Path,
    summary: dict[str, Any],
    logical_config_id: str,
    cache_dir: Path,
) -> dict[str, Any]:
    cache_path = cache_dir / f"{logical_config_id}.json.gz"
    if cache_path.exists():
        with gzip.open(cache_path, "rt", encoding="utf-8") as stream:
            cached = json.load(stream)
        if (
            cached.get("task_hash") == summary["task_hash"]
            and cached.get("logical_config_id") == logical_config_id
            and cached.get("cache_version") == 2
        ):
            return cached

    ledger = load_json(task_root / "aggregation_ledger.json")
    entry = ledger["tasks"].get(summary["task_hash"])
    if entry is None:
        raise RuntimeError(f"task absent from aggregate ledger: {summary['task_hash']}")
    bounds = member_bounds(ledger)[summary["task_hash"]]
    step_path = task_root / "per_step_restart_records.csv.gz"
    sample_path = task_root / "per_sample_attack_records.csv.gz"
    audit = ConfigAudit(summary=summary)
    samples = load_sample_member(
        sample_path,
        bounds["sample_start"],
        bounds["sample_end"],
        entry["sample_member_sha256"],
        audit,
    )
    if sha256_range(step_path, bounds["step_start"], bounds["step_end"]) != entry["step_member_sha256"]:
        audit.member_hashes_match = False

    physical = summary["attack"] in PHYSICAL_ATTACKS
    threshold = float(summary["threshold"])
    restarts = int(summary["restarts"])
    steps = int(summary["steps"])
    states: dict[str, SampleState] = {}
    by_restart: dict[str, dict[int, dict[str, Any]]] = defaultdict(
        lambda: defaultdict(
            lambda: {
                "best_loss": None,
                "strongest_success": None,
                "best_feasible_success": None,
                "final": None,
                "initialization_success": False,
                "projection_failure": False,
                "projection_converged": False,
                "active": False,
            }
        )
    )
    for row in iter_member(step_path, bounds["step_start"], bounds["step_end"], STEP_FIELDS):
        audit.step_rows += 1
        sample_id = row["sample_id"]
        state = states.get(sample_id)
        if state is None:
            state = SampleState(sample_id=sample_id, aircraft_id=row["aircraft_id"])
            states[sample_id] = state
        update_state(state, row, physical=physical, final_step=steps, threshold=threshold)
        candidate = candidate_from_row(row)
        restart_id = candidate.restart_id
        restart = by_restart[sample_id][restart_id]
        restart["initialization_success"] |= as_bool(row["initialization_success"])
        actual_projection = candidate.projection_status != "not_required"
        restart["projection_failure"] |= actual_projection and not candidate.projection_converged
        restart["projection_converged"] |= actual_projection and candidate.projection_converged
        valid = (
            candidate.active
            and finite(candidate.target_ce)
            and finite(candidate.target_margin)
            and finite(candidate.p_anomaly)
        )
        restart["active"] |= valid
        if not valid:
            continue
        if restart["best_loss"] is None or candidate_rank(candidate) < candidate_rank(restart["best_loss"]):
            restart["best_loss"] = candidate
        if candidate.step == steps:
            if restart["final"] is None or candidate_rank(candidate) < candidate_rank(restart["final"]):
                restart["final"] = candidate
        if candidate.p_anomaly < threshold:
            if (
                restart["strongest_success"] is None
                or success_rank(candidate, physical) < success_rank(restart["strongest_success"], physical)
            ):
                restart["strongest_success"] = candidate
            if candidate.source_valid and candidate.feasible(physical):
                if (
                    restart["best_feasible_success"] is None
                    or candidate_rank(candidate) < candidate_rank(restart["best_feasible_success"])
                ):
                    restart["best_feasible_success"] = candidate

    expected_pairs = {
        (restart_id, step)
        for restart_id in range(restarts)
        for step in range(steps + 1)
    }
    aggregate_state_checks(audit, states, expected_pairs)

    sample_rows: list[dict[str, Any]] = []
    candidate_counts: Counter[str] = Counter()
    candidate_success: Counter[str] = Counter()
    candidate_ce: Counter[str] = Counter()
    candidate_margin: Counter[str] = Counter()
    selected_restart: dict[str, Counter[str]] = defaultdict(Counter)
    cumulative = [
        {
            "restart_count": prefix,
            "support": 0,
            "success_preserving_successes": 0,
            "best_target_loss_successes": 0,
            "best_feasible_successes": 0,
            "best_target_ce_sum": 0.0,
            "best_target_ce_count": 0,
            "initialized": 0,
            "projection_failure": 0,
            "projection_converged": 0,
            "fallback": 0,
        }
        for prefix in range(1, restarts + 1)
    ]
    for sample_id, sample in samples.items():
        state = states.get(sample_id)
        if state is None:
            continue
        restart_map = by_restart[sample_id]
        prefixes: list[dict[str, Any]] = []
        for prefix in range(1, restarts + 1):
            entries = [restart_map[restart_id] for restart_id in range(prefix)]
            best_loss = min_candidate(
                [entry["best_loss"] for entry in entries if entry["best_loss"] is not None]
            )
            success = [
                entry["strongest_success"]
                for entry in entries
                if entry["strongest_success"] is not None
            ]
            success_preserving = choose_prefix_success(success, best_loss, physical)
            feasible_success = min_candidate(
                [
                    entry["best_feasible_success"]
                    for entry in entries
                    if entry["best_feasible_success"] is not None
                ]
            )
            final = choose_prefix_final(
                [entry["final"] for entry in entries if entry["final"] is not None],
                physical,
            )
            prefix_row = {
                "restart_count": prefix,
                "best_target_loss": compact_candidate(best_loss),
                "success_preserving": compact_candidate(success_preserving),
                "best_feasible_success": compact_candidate(feasible_success),
                "final_active": compact_candidate(final),
                "initialized_any": any(entry["initialization_success"] for entry in entries),
                "projection_failure_any": any(entry["projection_failure"] for entry in entries),
                "projection_converged_any": any(entry["projection_converged"] for entry in entries),
                "active_any": any(entry["active"] for entry in entries),
                "fallback": final is None or not final.feasible(physical),
            }
            prefixes.append(prefix_row)
            cumulative_row = cumulative[prefix - 1]
            cumulative_row["support"] += int(success_preserving is not None)
            cumulative_row["success_preserving_successes"] += int(
                success_preserving is not None and success_preserving.p_anomaly < threshold
            )
            cumulative_row["best_target_loss_successes"] += int(
                best_loss is not None and best_loss.p_anomaly < threshold
            )
            cumulative_row["best_feasible_successes"] += int(
                feasible_success is not None and feasible_success.p_anomaly < threshold
            )
            if best_loss is not None:
                cumulative_row["best_target_ce_sum"] += best_loss.target_ce
                cumulative_row["best_target_ce_count"] += 1
            cumulative_row["initialized"] += int(prefix_row["initialized_any"])
            cumulative_row["projection_failure"] += int(prefix_row["projection_failure_any"])
            cumulative_row["projection_converged"] += int(
                prefix_row["projection_converged_any"]
            )
            cumulative_row["fallback"] += int(prefix_row["fallback"])

        final_prefix = prefixes[-1]
        candidates = {
            "final_active": final_prefix["final_active"],
            "best_target_loss": final_prefix["best_target_loss"],
            "success_preserving": final_prefix["success_preserving"],
            "best_feasible_success": final_prefix["best_feasible_success"],
        }
        for kind, candidate in candidates.items():
            if candidate is None:
                continue
            candidate_counts[kind] += 1
            candidate_success[kind] += int(candidate["p_anomaly"] < threshold)
            candidate_ce[kind] += float(candidate["target_ce"])
            candidate_margin[kind] += float(candidate["target_margin"])
            selected_restart[kind][str(candidate["restart_id"])] += 1
        sample_rows.append(
            {
                "sample_id": sample_id,
                "aircraft_id": state.aircraft_id,
                "clean_prediction": as_bool(sample["clean_prediction"]),
                "clean_p_anomaly": as_float(sample["clean_p_anomaly"]),
                "source_valid": state.source_valid,
                "initialization_success": state.initialization_success,
                "projection_not_converged": state.projection_not_converged,
                "projection_converged": state.projection_converged,
                "attack_active": state.attack_active,
                "any_budget_invalid": state.any_budget_invalid,
                "any_kinematic_invalid": state.any_kinematic_invalid,
                "prefixes": prefixes,
            }
        )

    attacked = len(samples)
    v0 = sum(int(row["source_valid"]) for row in sample_rows) if physical else attacked
    for row in cumulative:
        row["success_preserving_asr"] = (
            row["success_preserving_successes"] / row["support"] if row["support"] else None
        )
        row["best_target_loss_asr"] = (
            row["best_target_loss_successes"] / row["support"] if row["support"] else None
        )
        row["best_feasible_success_asr_on_v0"] = (
            row["best_feasible_successes"] / v0 if v0 else None
        )
        row["best_target_ce_mean"] = (
            row["best_target_ce_sum"] / row["best_target_ce_count"]
            if row["best_target_ce_count"]
            else None
        )
        row["initialization_infeasible_rate"] = (
            1.0 - row["initialized"] / attacked if attacked else None
        )
        row["projection_failure_rate"] = (
            row["projection_failure"] / attacked if attacked else None
        )
        row["fallback_rate"] = row["fallback"] / attacked if attacked else None

    gate_checks = {
        "member_hashes_match": audit.member_hashes_match,
        "sample_support_complete": len(samples) == len(states),
        "missing_steps_zero": audit.missing_steps == 0,
        "duplicate_steps_zero": audit.duplicate_steps == 0,
        "nan_rows_zero": audit.nan_rows == 0,
        "ce_probability_consistent": audit.ce_probability_mismatch == 0,
        "margin_probability_gate_consistent": audit.margin_probability_gate_mismatch == 0,
        "threshold_flag_gate_consistent": audit.threshold_flag_gate_mismatch == 0,
        "argmax_flag_consistent": audit.argmax_flag_mismatch == 0,
        "probability_pair_consistent": audit.probability_pair_mismatch == 0,
        "normal_controls_bitwise_unchanged": audit.normal_unchanged,
        "attacked_normal_zero": audit.attacked_normal == 0,
    }
    success_preserving_successes = int(
        candidate_success.get("success_preserving", 0)
    )
    threshold_asr_all_attacked = (
        success_preserving_successes / attacked if attacked else None
    )
    recall_on_attacked = (
        1.0 - threshold_asr_all_attacked
        if threshold_asr_all_attacked is not None
        else None
    )
    clean_far = (
        audit.normal_fp / (audit.normal_fp + audit.normal_tn)
        if audit.normal_fp + audit.normal_tn
        else None
    )
    payload = {
        "schema_version": SCHEMA,
        "cache_version": 2,
        "generation_utc": now(),
        "logical_config_id": logical_config_id,
        "task_hash": summary["task_hash"],
        "seed": int(summary["seed"]),
        "model": summary["model"],
        "attack": summary["attack"],
        "K": steps,
        "alpha_rule": summary["alpha_rule"],
        "alpha": float(summary["alpha"]),
        "initialization": summary["initialization"],
        "restarts": restarts,
        "threshold": threshold,
        "checkpoint_sha256": summary["checkpoint_sha256"],
        "attacked_anomalies": attacked,
        "V0": v0,
        "candidate_counts": dict(candidate_counts),
        "candidate_success": dict(candidate_success),
        "candidate_ce_sum": dict(candidate_ce),
        "candidate_margin_sum": dict(candidate_margin),
        "selected_restart_distribution": {
            key: dict(value) for key, value in selected_restart.items()
        },
        "metric_identity": {
            "threshold_asr_all_attacked": threshold_asr_all_attacked,
            "recall_on_attacked": recall_on_attacked,
            "recall_plus_threshold_asr": (
                recall_on_attacked + threshold_asr_all_attacked
                if recall_on_attacked is not None
                else None
            ),
            "clean_far": clean_far,
            "candidate_far": clean_far if audit.normal_unchanged else None,
            "normal_controls_bitwise_unchanged": audit.normal_unchanged,
        },
        "cumulative": cumulative,
        "gate_checks": gate_checks,
        "gate": "PASS" if all(gate_checks.values()) else "FAIL",
        "samples": sample_rows,
    }
    cache_dir.mkdir(parents=True, exist_ok=True)
    temporary = cache_path.with_name(f".{cache_path.name}.{os.getpid()}.tmp")
    with gzip.open(temporary, "wt", encoding="utf-8", compresslevel=9) as stream:
        json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"))
    os.replace(temporary, cache_path)
    return payload


def candidate_map(audit: dict[str, Any], kind: str) -> dict[str, dict[str, Any]]:
    return {
        row["sample_id"]: row["prefixes"][-1][kind]
        for row in audit["samples"]
        if row["prefixes"][-1][kind] is not None
    }


def success_set(audit: dict[str, Any], kind: str) -> set[str]:
    threshold = float(audit["threshold"])
    return {
        sample_id
        for sample_id, candidate in candidate_map(audit, kind).items()
        if float(candidate["p_anomaly"]) < threshold
    }


def metric(audit: dict[str, Any], kind: str) -> float | None:
    count = int(audit["candidate_counts"].get(kind, 0))
    success = int(audit["candidate_success"].get(kind, 0))
    return success / count if count else None


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fields = sorted({key for row in rows for key in row})
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def run_trigger(project_root: Path, output_dir: Path) -> dict[str, Any]:
    runtime = load_json(output_dir / "p2b_runtime_status.json")
    if runtime.get("phase") != "base_complete":
        raise RuntimeError(f"R10 decision requires base_complete, observed {runtime.get('phase')}")
    rows = read_inventory(output_dir / "p2b_task_inventory.csv")
    if len(rows) != 160 or any(row["execution_status"] not in {"reused", "completed"} for row in rows):
        raise RuntimeError("the 160-task base inventory is not complete")
    p2_root = project_root / "outputs" / "attack_audit_c001" / "p2"
    cache_dir = output_dir / "_analysis_cache"
    row_by_key = {
        (
            int(row["seed"]),
            row["model"],
            row["attack"],
            int(row["K"]),
            int(row["restarts"]),
        ): row
        for row in rows
    }

    def load_row_audit(row: dict[str, Any]) -> dict[str, Any]:
        task_root = p2_root if row["execution_status"] == "reused" else output_dir
        task_hash = (
            row["source_task_hash"]
            if row["execution_status"] == "reused"
            else row["executed_task_hash"]
        )
        audit = analyze_task(
            task_root,
            task_summary(task_root, task_hash),
            row["logical_config_id"],
            cache_dir,
        )
        if audit["gate"] != "PASS":
            raise RuntimeError(
                f"support-consistent task audit failed: {row['logical_config_id']}"
            )
        return audit

    comparisons: list[dict[str, Any]] = []
    nesting_checks: list[dict[str, Any]] = []
    base_audited = 0
    for seed in SEEDS:
        for model in MODELS:
            for attack in ATTACKS:
                for steps in STEPS:
                    print(
                        f"P2-B posthoc base pair seed={seed} model={model} "
                        f"attack={attack} K={steps}",
                        flush=True,
                    )
                    row1 = row_by_key[(seed, model, attack, steps, 1)]
                    row5 = row_by_key[(seed, model, attack, steps, 5)]
                    r1 = load_row_audit(row1)
                    r5 = load_row_audit(row5)
                    base_audited += 2
                    r1_success = success_set(r1, "success_preserving")
                    r5_success = success_set(r5, "success_preserving")
                    r1_best = candidate_map(r1, "best_target_loss")
                    r5_best = candidate_map(r5, "best_target_loss")
                    r5_prefix0 = {
                        row["sample_id"]: row["prefixes"][0]["best_target_loss"]
                        for row in r5["samples"]
                        if row["prefixes"][0]["best_target_loss"] is not None
                    }
                    r1_feasible = success_set(r1, "best_feasible_success")
                    r5_feasible = success_set(r5, "best_feasible_success")
                    r1_ids = {row["sample_id"] for row in r1["samples"]}
                    r5_ids = {row["sample_id"] for row in r5["samples"]}
                    prefix_ce_equal = r1_best.keys() == r5_prefix0.keys() and all(
                        math.isclose(
                            float(r1_best[sample_id]["target_ce"]),
                            float(r5_prefix0[sample_id]["target_ce"]),
                            rel_tol=0.0,
                            abs_tol=1e-7,
                        )
                        for sample_id in r1_best
                    )
                    best_ce_not_higher = all(
                        float(r5_best[sample_id]["target_ce"])
                        <= float(r1_best[sample_id]["target_ce"]) + 1e-7
                        for sample_id in r1_best
                    )
                    checks = {
                        "support_equal": r1_ids == r5_ids,
                        "r1_success_subset_r5": r1_success <= r5_success,
                        "lost_successes_zero": len(r1_success - r5_success) == 0,
                        "r1_feasible_success_subset_r5": r1_feasible <= r5_feasible,
                        "restart_zero_best_ce_equal": prefix_ce_equal,
                        "best_target_ce_not_higher": best_ce_not_higher,
                    }
                    nesting_checks.append(
                        {
                            "seed": seed,
                            "model": model,
                            "attack": attack,
                            "K": steps,
                            "checks": checks,
                            "pass": all(checks.values()),
                        }
                    )
                    intersection = r1_success & r5_success
                    union = r1_success | r5_success
                    comparisons.append(
                        {
                            "Seed": seed,
                            "Model": model,
                            "Attack": attack,
                            "K": steps,
                            "R1 ASR": metric(r1, "success_preserving"),
                            "R5 ASR": metric(r5, "success_preserving"),
                            "Increment": (
                                float(metric(r5, "success_preserving"))
                                - float(metric(r1, "success_preserving"))
                            ),
                            "R1 successes": len(r1_success),
                            "R5 successes": len(r5_success),
                            "R1 support": int(
                                r1["candidate_counts"].get(
                                    "success_preserving", 0
                                )
                            ),
                            "R5 support": int(
                                r5["candidate_counts"].get(
                                    "success_preserving", 0
                                )
                            ),
                            "New successes": len(r5_success - r1_success),
                            "Lost successes": len(r1_success - r5_success),
                            "Intersection": len(intersection),
                            "Jaccard": len(intersection) / len(union) if union else 1.0,
                            "R1 best-target-loss ASR": metric(r1, "best_target_loss"),
                            "R5 best-target-loss ASR": metric(r5, "best_target_loss"),
                            "R1 best-feasible-success ASR | V0": (
                                len(r1_feasible) / int(r1["V0"]) if int(r1["V0"]) else None
                            ),
                            "R5 best-feasible-success ASR | V0": (
                                len(r5_feasible) / int(r5["V0"]) if int(r5["V0"]) else None
                            ),
                        }
                    )
                    del r1, r5, r1_success, r5_success, r1_best, r5_best
    write_csv(output_dir / "r1_r5_comparison.csv", comparisons)

    seed_evidence: dict[str, list[dict[str, Any]]] = {}
    trigger_by_attack: dict[str, bool] = {}
    for attack in ATTACKS:
        evidence: list[dict[str, Any]] = []
        for seed in SEEDS:
            scoped = [
                row
                for row in comparisons
                if row["Attack"] == attack and int(row["Seed"]) == seed
            ]
            r1_successes = sum(int(row["R1 successes"]) for row in scoped)
            r5_successes = sum(int(row["R5 successes"]) for row in scoped)
            r1_support = sum(int(row["R1 support"]) for row in scoped)
            r5_support = sum(int(row["R5 support"]) for row in scoped)
            r1_asr = r1_successes / r1_support if r1_support else None
            r5_asr = r5_successes / r5_support if r5_support else None
            increment = float(r5_asr - r1_asr)
            evidence.append(
                {
                    "seed": seed,
                    "r1_success_preserving_successes": r1_successes,
                    "r1_support": r1_support,
                    "r1_asr": r1_asr,
                    "r5_success_preserving_successes": r5_successes,
                    "r5_support": r5_support,
                    "r5_asr": r5_asr,
                    "increment": increment,
                    "triggers": increment >= 0.005,
                }
            )
        seed_evidence[attack] = evidence
        trigger_by_attack[attack] = any(row["triggers"] for row in evidence)

    decision_core = {
        "schema_version": "adsb.c001-p2b-r10-trigger.v1",
        "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
        "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
        "source_task_list_sha256": EXPECTED_P2B_TASK_LIST_SHA256,
        "rule": "any repeated split pooled across both models and K has R1-to-R5 success-preserving ASR increment >= 0.005",
        "per_attack": {
            attack: {
                "trigger": trigger_by_attack[attack],
                "triggering_splits": [
                    row["seed"] for row in seed_evidence[attack] if row["triggers"]
                ],
                "evidence": seed_evidence[attack],
                "triggered_task_count": 20 if trigger_by_attack[attack] else 0,
            }
            for attack in ATTACKS
        },
        "total_triggered_task_count": 20 * sum(trigger_by_attack.values()),
    }
    decision_core["decision_hash"] = _canonical_decision_hash(decision_core)
    decision = {**decision_core, "generation_utc": now(), "status": "FROZEN"}
    atomic_json(output_dir / "r10_trigger_decision.json", decision)

    freeze = load_json(p2_root / "p2b_configuration_freeze.json")
    templates = {
        (
            int(task["seed"]),
            task["model"],
            task["attack"],
            int(task["K"]),
        ): task
        for task in freeze["conditional_r10_templates"]
    }
    base_r5 = {
        (
            int(row["seed"]),
            row["model"],
            row["attack"],
            int(row["K"]),
        ): row
        for row in rows
        if int(row["restarts"]) == 5
    }
    new_rows: list[dict[str, Any]] = []
    for attack in ATTACKS:
        if not trigger_by_attack[attack]:
            continue
        for seed in SEEDS:
            for model in MODELS:
                for steps in STEPS:
                    template = templates[(seed, model, attack, steps)]
                    source = base_r5[(seed, model, attack, steps)]
                    config = _attack_config(
                        attack=attack,
                        steps=steps,
                        alpha_rule="two_eps_over_k",
                        initialization=RANDOM_INITIALIZATION[attack],
                        restarts=10,
                        seed=seed,
                        projection=freeze["projection_tolerances"],
                    )
                    row = {field: "" for field in TASK_FIELDS}
                    row.update(
                        {
                            "logical_config_id": template["logical_config_id"],
                            "stage": template["stage"],
                            "seed": seed,
                            "model": model,
                            "attack": attack,
                            "K": steps,
                            "alpha_rule": "two_eps_over_k",
                            "alpha": template["alpha"],
                            "initialization": template["initialization"],
                            "restarts": 10,
                            "attack_config_hash": config.config_hash,
                            "checkpoint_sha256": source["checkpoint_sha256"],
                            "dataset_hash": source["dataset_hash"],
                            "split_hash": source["split_hash"],
                            "normalization_hash": source["normalization_hash"],
                            "sample_manifest_hash": source["sample_manifest_hash"],
                            "threshold": source["threshold"],
                            "execution_status": "scheduled",
                            "attempt_count": 0,
                        }
                    )
                    new_rows.append(row)
    existing_ids = {row["logical_config_id"] for row in rows}
    rows.extend(row for row in new_rows if row["logical_config_id"] not in existing_ids)
    atomic_inventory(output_dir / "p2b_task_inventory.csv", rows)
    nesting_gate = {
        "schema_version": "adsb.c001-p2b-gate.v1",
        "generation_utc": now(),
        "gate": "PASS" if all(item["pass"] for item in nesting_checks) else "FAIL",
        "comparisons": len(nesting_checks),
        "checks": nesting_checks,
    }
    atomic_json(output_dir / "p2b_nesting_gate.json", nesting_gate)
    manifest = load_json(output_dir / "p2b_manifest.json")
    manifest.update(
        {
            "updated_at_utc": now(),
            "phase": "r10_decision_frozen",
            "r10_decision_hash": decision["decision_hash"],
            "r10_triggered_families": [
                attack for attack, triggered in trigger_by_attack.items() if triggered
            ],
            "conditional_r10_scheduled": len(new_rows),
        }
    )
    atomic_json(output_dir / "p2b_manifest.json", manifest)
    status = {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "status": "PASS" if nesting_gate["gate"] == "PASS" else "FAIL",
        "base_tasks_audited": base_audited,
        "r1_r5_comparisons": len(comparisons),
        "nesting_gate": nesting_gate["gate"],
        "r10_decision_hash": decision["decision_hash"],
        "r10_tasks_scheduled": len(new_rows),
    }
    atomic_json(output_dir / "p2b_base_analysis_status.json", status)
    if status["status"] != "PASS":
        raise RuntimeError("P2-B base support-consistent aggregation failed")
    return decision


def _canonical_decision_hash(payload: dict[str, Any]) -> str:
    import hashlib

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def prefix_candidate_map(
    audit: dict[str, Any],
    kind: str,
    prefix_index: int,
) -> dict[str, dict[str, Any]]:
    return {
        row["sample_id"]: row["prefixes"][prefix_index][kind]
        for row in audit["samples"]
        if row["prefixes"][prefix_index][kind] is not None
    }


def prefix_success_set(
    audit: dict[str, Any],
    kind: str,
    prefix_index: int,
) -> set[str]:
    threshold = float(audit["threshold"])
    return {
        sample_id
        for sample_id, candidate in prefix_candidate_map(
            audit, kind, prefix_index
        ).items()
        if float(candidate["p_anomaly"]) < threshold
    }


def load_all_audits(
    project_root: Path,
    output_dir: Path,
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    p2_root = project_root / "outputs" / "attack_audit_c001" / "p2"
    cache_dir = output_dir / "_analysis_cache"
    audits: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows, start=1):
        if row["execution_status"] not in {"reused", "completed"}:
            continue
        task_root = p2_root if row["execution_status"] == "reused" else output_dir
        task_hash = (
            row["source_task_hash"]
            if row["execution_status"] == "reused"
            else row["executed_task_hash"]
        )
        print(
            f"P2-B final posthoc {index}/{len(rows)} seed={row['seed']} "
            f"model={row['model']} attack={row['attack']} K={row['K']} "
            f"R={row['restarts']}",
            flush=True,
        )
        audit = analyze_task(
            task_root,
            task_summary(task_root, task_hash),
            row["logical_config_id"],
            cache_dir,
        )
        audits[row["logical_config_id"]] = audit
    return audits


def load_inventory_audit(
    project_root: Path,
    output_dir: Path,
    row: dict[str, Any],
) -> dict[str, Any]:
    p2_root = project_root / "outputs" / "attack_audit_c001" / "p2"
    task_root = p2_root if row["execution_status"] == "reused" else output_dir
    task_hash = (
        row["source_task_hash"]
        if row["execution_status"] == "reused"
        else row["executed_task_hash"]
    )
    audit = analyze_task(
        task_root,
        task_summary(task_root, task_hash),
        row["logical_config_id"],
        output_dir / "_analysis_cache",
    )
    if audit["gate"] != "PASS":
        raise RuntimeError(
            f"support-consistent task audit failed: {row['logical_config_id']}"
        )
    return audit


def gzip_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row})
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with gzip.open(
        temporary, "wt", encoding="utf-8", newline="", compresslevel=9
    ) as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def build_restart_records(
    audits: dict[str, dict[str, Any]],
    rows: list[dict[str, Any]],
    projection: dict[str, Any],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        audit = audits.get(row["logical_config_id"])
        if audit is None:
            continue
        config = _attack_config(
            attack=row["attack"],
            steps=int(row["K"]),
            alpha_rule=row["alpha_rule"],
            initialization=row["initialization"],
            restarts=int(row["restarts"]),
            seed=int(row["seed"]),
            projection=projection,
        )
        for cumulative in audit["cumulative"]:
            restart_id = int(cumulative["restart_count"]) - 1
            deterministic_seed = config.restart_seed(restart_id)
            output.append(
                {
                    "schema_version": SCHEMA,
                    "logical_config_id": row["logical_config_id"],
                    "task_hash": audit["task_hash"],
                    "seed": int(row["seed"]),
                    "model": row["model"],
                    "attack": row["attack"],
                    "K": int(row["K"]),
                    "restarts_configured": int(row["restarts"]),
                    "restart_id": restart_id,
                    "cumulative_restart_count": int(
                        cumulative["restart_count"]
                    ),
                    "runner_seed": int(row["seed"]),
                    "initialization_seed": deterministic_seed,
                    "attack_seed": deterministic_seed,
                    "seed_rule": (
                        "AttackConfig.restart_seed(restart_id); restart count excluded; "
                        "attack path has no additional stochastic draw after initialization"
                    ),
                    "support": cumulative["support"],
                    "success_preserving_successes": cumulative[
                        "success_preserving_successes"
                    ],
                    "success_preserving_asr": cumulative[
                        "success_preserving_asr"
                    ],
                    "best_target_loss_successes": cumulative[
                        "best_target_loss_successes"
                    ],
                    "best_target_loss_asr": cumulative[
                        "best_target_loss_asr"
                    ],
                    "best_feasible_successes": cumulative[
                        "best_feasible_successes"
                    ],
                    "best_feasible_success_asr_on_v0": cumulative[
                        "best_feasible_success_asr_on_v0"
                    ],
                    "best_target_ce_mean": cumulative[
                        "best_target_ce_mean"
                    ],
                    "initialized": cumulative["initialized"],
                    "projection_converged": cumulative[
                        "projection_converged"
                    ],
                    "projection_failure": cumulative["projection_failure"],
                    "fallback": cumulative["fallback"],
                    "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
                    "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
                }
            )
    return output


def restart_records_for_audit(
    audit: dict[str, Any],
    row: dict[str, Any],
    projection: dict[str, Any],
) -> list[dict[str, Any]]:
    return build_restart_records(
        {row["logical_config_id"]: audit},
        [row],
        projection,
    )


def iter_per_sample_candidates_for_audit(
    audit: dict[str, Any],
    row: dict[str, Any],
) -> Any:
    threshold = float(audit["threshold"])
    physical = audit["attack"] in PHYSICAL_ATTACKS
    for sample in audit["samples"]:
        prefix = sample["prefixes"][-1]
        for kind in (
            "final_active",
            "best_target_loss",
            "success_preserving",
            "best_feasible_success",
        ):
            candidate = prefix[kind]
            if candidate is None:
                continue
            projection_ok = (
                candidate["projection_status"] == "not_required"
                or candidate["projection_converged"]
            )
            feasible = (
                candidate["active"]
                and candidate["budget_valid"]
                and (
                    not physical
                    or (
                        candidate["kinematic_valid"]
                        and candidate["post_valid"]
                        and projection_ok
                    )
                )
            )
            yield {
                "schema_version": SCHEMA,
                "logical_config_id": row["logical_config_id"],
                "task_hash": audit["task_hash"],
                "seed": int(row["seed"]),
                "model": row["model"],
                "attack": row["attack"],
                "K": int(row["K"]),
                "restarts": int(row["restarts"]),
                "sample_id": sample["sample_id"],
                "aircraft_id": sample["aircraft_id"],
                "candidate_semantics": kind,
                "restart_id": candidate["restart_id"],
                "step": candidate["step"],
                "target_ce": candidate["target_ce"],
                "target_margin": candidate["target_margin"],
                "p_anomaly": candidate["p_anomaly"],
                "threshold": threshold,
                "threshold_success": candidate["p_anomaly"] < threshold,
                "active": candidate["active"],
                "source_valid": candidate["source_valid"],
                "budget_valid": candidate["budget_valid"],
                "kinematic_valid": candidate["kinematic_valid"],
                "projection_converged": candidate[
                    "projection_converged"
                ],
                "feasible": feasible,
                "clean_fallback": False,
                "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
                "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
            }


def write_per_sample_candidates(
    path: Path,
    rows: list[dict[str, Any]],
    audit_loader: Any,
) -> tuple[int, int]:
    fields = (
        "schema_version",
        "logical_config_id",
        "task_hash",
        "seed",
        "model",
        "attack",
        "K",
        "restarts",
        "sample_id",
        "aircraft_id",
        "candidate_semantics",
        "restart_id",
        "step",
        "target_ce",
        "target_margin",
        "p_anomaly",
        "threshold",
        "threshold_success",
        "active",
        "source_valid",
        "budget_valid",
        "kinematic_valid",
        "projection_converged",
        "feasible",
        "clean_fallback",
        "source_p2a_snapshot_sha256",
        "source_p2b_manifest_sha256",
    )
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    count = 0
    fallback_count = 0
    with gzip.open(
        temporary, "wt", encoding="utf-8", newline="", compresslevel=9
    ) as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        for inventory_row in rows:
            audit = audit_loader(inventory_row)
            for candidate_row in iter_per_sample_candidates_for_audit(
                audit, inventory_row
            ):
                writer.writerow(candidate_row)
                count += 1
                fallback_count += int(bool(candidate_row["clean_fallback"]))
            del audit
    os.replace(temporary, path)
    return count, fallback_count


def make_figures(
    output_dir: Path,
    restart_records: list[dict[str, Any]],
    r1_r5: list[dict[str, Any]],
    r5_r10: list[dict[str, Any]],
    overlap: list[dict[str, Any]],
    strongest: list[dict[str, Any]],
) -> list[Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd

    figures = output_dir / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    def save(fig: Any, name: str) -> None:
        fig.tight_layout()
        for suffix in ("pdf", "svg"):
            path = figures / f"{name}.{suffix}"
            fig.savefig(path, bbox_inches="tight")
            generated.append(path)
        plt.close(fig)

    rr = pd.DataFrame(restart_records)
    base = pd.DataFrame(r1_r5)
    conditional = pd.DataFrame(r5_r10)
    ov = pd.DataFrame(overlap)
    sd = pd.DataFrame(strongest)
    for column in ("Seed", "R5 ASR", "New successes", "Increment"):
        base[column] = pd.to_numeric(base[column], errors="raise")

    fig, axes = plt.subplots(2, 2, figsize=(10, 7), sharex=True, sharey=True)
    for axis, attack in zip(axes.flat, ATTACKS):
        group = rr[rr["attack"] == attack]
        for (seed, model, steps, configured), line in group.groupby(
            ["seed", "model", "K", "restarts_configured"]
        ):
            axis.plot(
                line["cumulative_restart_count"],
                line["success_preserving_asr"],
                alpha=0.35,
                linewidth=0.8,
            )
        axis.set_title(attack)
        axis.set_xlabel("Cumulative restart count")
        axis.set_ylabel("Success-preserving ASR")
    save(fig, "cumulative_asr_vs_restart_count")

    fig, axis = plt.subplots(figsize=(10, 5))
    for index, attack in enumerate(ATTACKS):
        group = base[base["Attack"] == attack]
        axis.scatter(
            group["Seed"] + index * 0.04,
            group["R5 ASR"],
            s=14,
            label=attack,
            alpha=0.65,
        )
    axis.set_xlabel("Repeated split seed")
    axis.set_ylabel("R5 success-preserving ASR")
    axis.legend(fontsize=7, ncol=2)
    save(fig, "r1_r5_r10_asr_by_seed")

    fig, axis = plt.subplots(figsize=(9, 5))
    gain = base.groupby("Attack", as_index=False)["New successes"].sum()
    axis.bar(gain["Attack"], gain["New successes"])
    axis.tick_params(axis="x", rotation=20)
    axis.set_ylabel("R5-only successful samples")
    save(fig, "restart_only_successful_sample_count")

    fig, axis = plt.subplots(figsize=(9, 5))
    axis.bar(ov["Attack"], ov["R1_R5_Jaccard"])
    axis.tick_params(axis="x", rotation=20)
    axis.set_ylabel("Success-set Jaccard")
    save(fig, "success_set_jaccard_overlap")

    fig, axis = plt.subplots(figsize=(9, 5))
    for (attack, restart_id), group in sd.groupby(["Attack", "Restart ID"]):
        axis.scatter(
            [attack],
            [group["Strongest-candidate count"].sum()],
            label=f"r{restart_id}",
            s=25,
        )
    axis.tick_params(axis="x", rotation=20)
    axis.set_ylabel("Strongest-candidate count")
    save(fig, "strongest_restart_id_distribution")

    fig, axes = plt.subplots(2, 2, figsize=(10, 7), sharex=True)
    for axis, attack in zip(axes.flat, ATTACKS):
        group = rr[rr["attack"] == attack]
        aggregate = group.groupby("cumulative_restart_count")[
            "best_target_ce_mean"
        ].mean()
        axis.plot(aggregate.index, aggregate.values, marker="o")
        axis.set_title(attack)
        axis.set_xlabel("Cumulative restart count")
        axis.set_ylabel("Mean target CE")
    save(fig, "target_ce_vs_restart_count")

    fig, axes = plt.subplots(1, 3, figsize=(12, 4), sharex=True)
    for axis, attack in zip(
        axes, ("phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd")
    ):
        group = rr[rr["attack"] == attack]
        aggregate = group.groupby("cumulative_restart_count")[
            "best_feasible_success_asr_on_v0"
        ].mean()
        axis.plot(aggregate.index, aggregate.values, marker="o")
        axis.set_title(attack)
        axis.set_xlabel("Cumulative restart count")
        axis.set_ylabel("Feasible-success ASR | V0")
    save(fig, "feasible_success_asr_vs_restart_count")

    fig, axes = plt.subplots(1, 3, figsize=(12, 4), sharex=True)
    for axis, attack in zip(
        axes, ("phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd")
    ):
        group = rr[rr["attack"] == attack]
        grouped = group.groupby("cumulative_restart_count")
        axis.plot(
            grouped["projection_failure"].sum().index,
            grouped["projection_failure"].sum().values,
            label="projection failure",
        )
        axis.plot(
            grouped["fallback"].sum().index,
            grouped["fallback"].sum().values,
            label="fallback",
        )
        axis.set_title(attack)
        axis.legend(fontsize=7)
    save(fig, "projection_fallback_rate_vs_restart_count")

    fig, axis = plt.subplots(figsize=(9, 5))
    model_gain = base.groupby(["Model", "Attack"], as_index=False)[
        "Increment"
    ].mean()
    for model, group in model_gain.groupby("Model"):
        axis.plot(
            group["Attack"],
            group["Increment"],
            marker="o",
            label=model,
        )
    axis.tick_params(axis="x", rotation=20)
    axis.set_ylabel("Mean R1→R5 ASR increment")
    axis.legend()
    save(fig, "erm_vs_catad_restart_gain")

    fig, axis = plt.subplots(figsize=(9, 5))
    if not conditional.empty:
        for attack, group in conditional.groupby("Attack"):
            axis.scatter(
                group["Seed"],
                group["Increment"],
                label=attack,
                alpha=0.65,
            )
        axis.legend(fontsize=7, ncol=2)
    else:
        axis.text(0.5, 0.5, "No R10 family triggered", ha="center", va="center")
    axis.axhline(0.005, color="red", linestyle="--", linewidth=0.8)
    axis.set_xlabel("Repeated split seed")
    axis.set_ylabel("R5→R10 ASR increment")
    save(fig, "per_seed_r5_r10_increment")
    return generated


def run_finalize(project_root: Path, output_dir: Path) -> dict[str, Any]:
    runtime = load_json(output_dir / "p2b_runtime_status.json")
    if runtime.get("phase") not in {"r10_complete", "r10_not_triggered"}:
        raise RuntimeError(
            f"finalization requires terminal R10 phase, observed {runtime.get('phase')}"
        )
    rows = read_inventory(output_dir / "p2b_task_inventory.csv")
    if any(row["execution_status"] not in {"reused", "completed"} for row in rows):
        raise RuntimeError("non-successful task remains in final inventory")
    decision = load_json(output_dir / "r10_trigger_decision.json")
    row_by_key = {
        (
            int(row["seed"]),
            row["model"],
            row["attack"],
            int(row["K"]),
            int(row["restarts"]),
        ): row
        for row in rows
    }
    audit_loader = lambda row: load_inventory_audit(
        project_root, output_dir, row
    )
    r1_r5 = list(
        csv.DictReader(
            (output_dir / "r1_r5_comparison.csv").open(
                "r", encoding="utf-8", newline=""
            )
        )
    )
    r5_r10: list[dict[str, Any]] = []
    r10_nesting: list[dict[str, Any]] = []
    for attack in ATTACKS:
        if not decision["per_attack"][attack]["trigger"]:
            continue
        for seed in SEEDS:
            for model in MODELS:
                for steps in STEPS:
                    r5 = audit_loader(
                        row_by_key[(seed, model, attack, steps, 5)]
                    )
                    r10 = audit_loader(
                        row_by_key[(seed, model, attack, steps, 10)]
                    )
                    r5_success = success_set(r5, "success_preserving")
                    r10_success = success_set(r10, "success_preserving")
                    r10_prefix5_success = prefix_success_set(
                        r10, "success_preserving", 4
                    )
                    r5_best = candidate_map(r5, "best_target_loss")
                    r10_prefix5_best = prefix_candidate_map(
                        r10, "best_target_loss", 4
                    )
                    r10_best = candidate_map(r10, "best_target_loss")
                    r5_feasible = success_set(r5, "best_feasible_success")
                    r10_feasible = success_set(r10, "best_feasible_success")
                    prefix_ce_equal = r5_best.keys() == r10_prefix5_best.keys() and all(
                        math.isclose(
                            float(r5_best[sample_id]["target_ce"]),
                            float(r10_prefix5_best[sample_id]["target_ce"]),
                            rel_tol=0.0,
                            abs_tol=1e-7,
                        )
                        for sample_id in r5_best
                    )
                    best_ce_not_higher = all(
                        float(r10_best[sample_id]["target_ce"])
                        <= float(r5_best[sample_id]["target_ce"]) + 1e-7
                        for sample_id in r5_best
                    )
                    checks = {
                        "r5_success_set_equals_r10_prefix5": r5_success
                        == r10_prefix5_success,
                        "r5_success_subset_r10": r5_success <= r10_success,
                        "lost_successes_zero": len(r5_success - r10_success)
                        == 0,
                        "feasible_success_subset": r5_feasible <= r10_feasible,
                        "prefix5_best_ce_equal": prefix_ce_equal,
                        "best_target_ce_not_higher": best_ce_not_higher,
                    }
                    r10_nesting.append(
                        {
                            "seed": seed,
                            "model": model,
                            "attack": attack,
                            "K": steps,
                            "checks": checks,
                            "pass": all(checks.values()),
                        }
                    )
                    r5_asr = metric(r5, "success_preserving")
                    r10_asr = metric(r10, "success_preserving")
                    r5_ce = r5["cumulative"][-1]["best_target_ce_mean"]
                    r10_ce = r10["cumulative"][-1]["best_target_ce_mean"]
                    r5_r10.append(
                        {
                            "Seed": seed,
                            "Model": model,
                            "Attack": attack,
                            "K": steps,
                            "R5 ASR": r5_asr,
                            "R10 ASR": r10_asr,
                            "Increment": float(r10_asr - r5_asr),
                            "R5 successes": len(r5_success),
                            "R10 successes": len(r10_success),
                            "New successes": len(r10_success - r5_success),
                            "Lost successes": len(r5_success - r10_success),
                            "R5 best-target CE": r5_ce,
                            "R10 best-target CE": r10_ce,
                            "Target CE improvement": float(r5_ce - r10_ce),
                            "R5 feasible successes": len(r5_feasible),
                            "R10 feasible successes": len(r10_feasible),
                            "Feasible-success increment": (
                                len(r10_feasible) / int(r10["V0"])
                                - len(r5_feasible) / int(r5["V0"])
                                if int(r5["V0"]) and int(r10["V0"])
                                else None
                            ),
                            "Gate": "PASS"
                            if all(checks.values())
                            else "FAIL",
                        }
                    )
                    del r5, r10
    write_csv(output_dir / "r5_r10_comparison.csv", r5_r10)

    overlap_rows: list[dict[str, Any]] = []
    strongest_rows: list[dict[str, Any]] = []
    for model in MODELS:
        for attack in ATTACKS:
            strongest_r = (
                10 if decision["per_attack"][attack]["trigger"] else 5
            )
            for steps in STEPS:
                r1_set: set[str] = set()
                r5_set: set[str] = set()
                r10_set: set[str] = set()
                distribution: Counter[str] = Counter()
                for seed in SEEDS:
                    r1 = audit_loader(
                        row_by_key[(seed, model, attack, steps, 1)]
                    )
                    r5 = audit_loader(
                        row_by_key[(seed, model, attack, steps, 5)]
                    )
                    r1_set |= {
                        f"{seed}:{sample_id}"
                        for sample_id in success_set(
                            r1, "success_preserving"
                        )
                    }
                    r5_set |= {
                        f"{seed}:{sample_id}"
                        for sample_id in success_set(
                            r5, "success_preserving"
                        )
                    }
                    strongest_audit = (
                        r5
                        if strongest_r == 5
                        else audit_loader(
                            row_by_key[
                                (seed, model, attack, steps, strongest_r)
                            ]
                        )
                    )
                    r10_set |= (
                        {
                            f"{seed}:{sample_id}"
                            for sample_id in success_set(
                                strongest_audit, "success_preserving"
                            )
                        }
                        if strongest_r == 10
                        else set()
                    )
                    distribution.update(
                        strongest_audit["selected_restart_distribution"].get(
                            "success_preserving", {}
                        )
                    )
                    if strongest_r == 10:
                        del strongest_audit
                    del r1, r5
                union15 = r1_set | r5_set
                union510 = r5_set | r10_set
                overlap_rows.append(
                    {
                        "Model": model,
                        "Attack": attack,
                        "K": steps,
                        "R1 successes": len(r1_set),
                        "R5 successes": len(r5_set),
                        "R10 successes": len(r10_set)
                        if strongest_r == 10
                        else None,
                        "R1∩R5": len(r1_set & r5_set),
                        "R5-only": len(r5_set - r1_set),
                        "R10-only": len(r10_set - r5_set)
                        if strongest_r == 10
                        else None,
                        "R1_R5_Jaccard": (
                            len(r1_set & r5_set) / len(union15)
                            if union15
                            else 1.0
                        ),
                        "R5_R10_Jaccard": (
                            len(r5_set & r10_set) / len(union510)
                            if strongest_r == 10 and union510
                            else None
                        ),
                    }
                )
                for restart_id in range(strongest_r):
                    strongest_rows.append(
                        {
                            "Model": model,
                            "Attack": attack,
                            "K": steps,
                            "R": strongest_r,
                            "Restart ID": restart_id,
                            "Strongest-candidate count": int(
                                distribution[str(restart_id)]
                            ),
                        }
                    )
    write_csv(output_dir / "success_overlap.csv", overlap_rows)
    write_csv(
        output_dir / "strongest_restart_distribution.csv", strongest_rows
    )

    physical_rows: list[dict[str, Any]] = []
    for attack in (
        "phys_projection_pgd",
        "phys_penalty_pgd",
        "phys_hybrid_pgd",
    ):
        available_restarts = [1, 5] + (
            [10] if decision["per_attack"][attack]["trigger"] else []
        )
        for restarts in available_restarts:
            attacked = v0 = initialized = projection_converged = 0
            projection_failure = fallback = feasible_success = 0
            scoped_rows = [
                row
                for row in rows
                if row["attack"] == attack
                and int(row["restarts"]) == restarts
            ]
            for inventory_row in scoped_rows:
                audit = audit_loader(inventory_row)
                final = audit["cumulative"][-1]
                attacked += int(audit["attacked_anomalies"])
                v0 += int(audit["V0"])
                initialized += int(final["initialized"])
                projection_converged += int(final["projection_converged"])
                projection_failure += int(final["projection_failure"])
                fallback += int(final["fallback"])
                feasible_success += int(
                    final["best_feasible_successes"]
                )
                del audit
            physical_rows.append(
                {
                    "Attack": attack,
                    "R": restarts,
                    "Attacked": attacked,
                    "Initialized": initialized,
                    "Initialization infeasible": attacked - initialized,
                    "Projection converged": projection_converged,
                    "Projection failure": projection_failure,
                    "Valid support V0": v0,
                    "Fallback": fallback,
                    "Feasible success": feasible_success,
                    "PV-ASR | V0": feasible_success / v0 if v0 else None,
                }
            )
    write_csv(
        output_dir / "physical_support_by_restart.csv", physical_rows
    )

    per_seed_gate: list[dict[str, Any]] = []
    family_gate: list[dict[str, Any]] = []
    for attack in ATTACKS:
        triggered = bool(decision["per_attack"][attack]["trigger"])
        attack_rows = [row for row in r5_r10 if row["Attack"] == attack]
        for seed in SEEDS:
            scoped = [row for row in attack_rows if row["Seed"] == seed]
            per_seed_gate.append(
                {
                    "Seed": seed,
                    "Attack": attack,
                    "R10 triggered": triggered,
                    "Max R5→R10 increment": (
                        max(float(row["Increment"]) for row in scoped)
                        if scoped
                        else None
                    ),
                    "Gate": (
                        "PASS"
                        if scoped
                        and all(
                            float(row["Increment"]) < 0.005
                            and row["Gate"] == "PASS"
                            for row in scoped
                        )
                        else (
                            "FAIL"
                            if scoped
                            else "INCONCLUSIVE — R10 NOT EXECUTED"
                        )
                    ),
                }
            )
        if not triggered:
            verdict = "INCONCLUSIVE — R10 NOT EXECUTED"
            max_increment = None
        else:
            max_increment = max(
                float(row["Increment"]) for row in attack_rows
            )
            primary_fail = any(
                float(row["Increment"]) >= 0.005
                or int(row["Lost successes"]) != 0
                or row["Gate"] != "PASS"
                or (
                    row["Feasible-success increment"] is not None
                    and float(row["Feasible-success increment"]) >= 0.005
                )
                for row in attack_rows
            )
            if primary_fail:
                verdict = "FAIL — RESTARTS NOT STABLE"
            else:
                later_selected = sum(
                    int(row["Strongest-candidate count"])
                    for row in strongest_rows
                    if row["Attack"] == attack
                    and int(row["R"]) == 10
                    and int(row["Restart ID"]) >= 5
                )
                any_new = any(
                    int(row["New successes"]) > 0 for row in attack_rows
                )
                any_ce_improvement = any(
                    float(row["Target CE improvement"]) > 1e-7
                    for row in attack_rows
                )
                if not any_new and not any_ce_improvement and later_selected == 0:
                    verdict = "PASS"
                else:
                    verdict = (
                        "INCONCLUSIVE — QUALITATIVE ADEQUACY SUBCRITERIA "
                        "WERE NOT NUMERICALLY FROZEN"
                    )
        family_gate.append(
            {
                "Attack": attack,
                "R10 triggered": triggered,
                "Triggering splits": ",".join(
                    str(value)
                    for value in decision["per_attack"][attack][
                        "triggering_splits"
                    ]
                ),
                "R10 task count": decision["per_attack"][attack][
                    "triggered_task_count"
                ],
                "Max R5→R10 increment": max_increment,
                "Restart Gate": verdict,
            }
        )
    write_csv(output_dir / "per_seed_restart_gate.csv", per_seed_gate)
    write_csv(output_dir / "per_family_restart_gate.csv", family_gate)

    projection = load_json(
        project_root
        / "outputs"
        / "attack_audit_c001"
        / "p2"
        / "p2b_configuration_freeze.json"
    )["projection_tolerances"]
    restart_records: list[dict[str, Any]] = []
    all_task_audits_pass = True
    all_normal_unchanged = True
    all_attacked_normal_zero = True
    all_nan_zero = True
    all_probability_identities = True
    all_recall_asr_identities = True
    all_far_identities = True
    independent_audit_count = 0
    for inventory_row in rows:
        audit = audit_loader(inventory_row)
        independent_audit_count += 1
        restart_records.extend(
            restart_records_for_audit(
                audit, inventory_row, projection
            )
        )
        all_task_audits_pass &= audit["gate"] == "PASS"
        all_normal_unchanged &= audit["gate_checks"][
            "normal_controls_bitwise_unchanged"
        ]
        all_attacked_normal_zero &= audit["gate_checks"][
            "attacked_normal_zero"
        ]
        all_nan_zero &= audit["gate_checks"]["nan_rows_zero"]
        all_probability_identities &= (
            audit["gate_checks"]["ce_probability_consistent"]
            and audit["gate_checks"]["threshold_flag_gate_consistent"]
            and audit["gate_checks"]["probability_pair_consistent"]
        )
        all_recall_asr_identities &= math.isclose(
            float(
                audit["metric_identity"][
                    "recall_plus_threshold_asr"
                ]
            ),
            1.0,
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        all_far_identities &= (
            audit["metric_identity"]["candidate_far"]
            == audit["metric_identity"]["clean_far"]
        )
        del audit
    gzip_csv(output_dir / "restart_records.csv.gz", restart_records)
    per_sample_count, per_sample_fallback_count = write_per_sample_candidates(
        output_dir / "per_sample_restart_candidates.csv.gz",
        rows,
        audit_loader,
    )

    base_nesting = load_json(output_dir / "p2b_nesting_gate.json")
    all_nesting = list(base_nesting.get("checks", [])) + r10_nesting
    nesting_pass = all(item["pass"] for item in all_nesting)
    atomic_json(
        output_dir / "p2b_nesting_gate.json",
        {
            "schema_version": "adsb.c001-p2b-gate.v1",
            "generation_utc": now(),
            "gate": "PASS" if nesting_pass else "FAIL",
            "comparisons": len(all_nesting),
            "checks": all_nesting,
        },
    )

    expected_ids = {row["logical_config_id"] for row in rows}
    duplicate_ids = len(rows) - len(expected_ids)
    executed_rows = [
        row for row in rows if row["execution_status"] == "completed"
    ]
    executed_summaries = [
        load_json(
            output_dir
            / "tasks"
            / row["executed_task_hash"]
            / "summary.json"
        )
        for row in executed_rows
    ]
    observed_ids = {
        summary.get("p2b_logical_config_id") for summary in executed_summaries
    }
    ledger = load_json(output_dir / "aggregation_ledger.json")
    staging = output_dir / ".staging"
    staging_entries = list(staging.iterdir()) if staging.exists() else []
    step_path = output_dir / "per_step_restart_records.csv.gz"
    sample_path = output_dir / "per_sample_attack_records.csv.gz"
    failed_records = [
        json.loads(line)
        for line in (output_dir / "failed_runs.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    completeness_checks = {
        "base_logical_tasks_160": sum(
            int(row["restarts"]) in (1, 5) for row in rows
        )
        == 160,
        "conditional_task_count_matches_decision": sum(
            int(row["restarts"]) == 10 for row in rows
        )
        == int(decision["total_triggered_task_count"]),
        "all_inventory_records_successful": all(
            row["execution_status"] in {"reused", "completed"} for row in rows
        ),
        "duplicate_logical_ids_zero": duplicate_ids == 0,
        "missing_executed_ids_zero": observed_ids
        == {
            row["logical_config_id"] for row in executed_rows
        },
        "ledger_task_count_matches": len(ledger["tasks"])
        == len(executed_rows),
        "aggregate_step_size_matches_ledger": step_path.stat().st_size
        == int(ledger["step_size_bytes"]),
        "aggregate_sample_size_matches_ledger": sample_path.stat().st_size
        == int(ledger["sample_size_bytes"]),
        "staging_empty": not staging_entries,
        "explicit_failed_records_zero": not failed_records,
        "unknown_task_ids_zero": observed_ids <= expected_ids,
        "independent_audit_count_matches": independent_audit_count
        == len(rows),
    }
    configuration_gate = load_json(
        output_dir / "p2b_configuration_gate.json"
    )
    completeness_gate = {
        "schema_version": "adsb.c001-p2b-gate.v1",
        "generation_utc": now(),
        "gate": "PASS"
        if all(completeness_checks.values())
        else "FAIL",
        "checks": completeness_checks,
        "successful": len(rows),
        "explicit_failures": len(failed_records),
        "missing": len(
            expected_ids
            - {
                row["logical_config_id"]
                for row in rows
                if row["execution_status"] in {"reused", "completed"}
            }
        ),
        "duplicates": duplicate_ids,
        "unknown": len(observed_ids - expected_ids),
    }
    atomic_json(
        output_dir / "p2b_completeness_gate.json", completeness_gate
    )

    preservation_checks = {
        "r1_successes_preserved_in_r5": all(
            int(row["Lost successes"]) == 0 for row in r1_r5
        ),
        "r5_successes_preserved_in_r10": all(
            int(row["Lost successes"]) == 0 for row in r5_r10
        ),
        "nesting_gate": nesting_pass,
        "all_task_support_audits_pass": all_task_audits_pass,
    }
    candidate_gate = {
        "schema_version": "adsb.c001-p2b-gate.v1",
        "generation_utc": now(),
        "gate": "PASS" if all(preservation_checks.values()) else "FAIL",
        "checks": preservation_checks,
    }
    atomic_json(
        output_dir / "p2b_candidate_preservation_gate.json",
        candidate_gate,
    )

    metric_checks = {
        "normal_controls_bitwise_unchanged": all_normal_unchanged,
        "attacked_normal_zero": all_attacked_normal_zero,
        "no_nan_target_ce": all_nan_zero,
        "probability_and_threshold_identities": all_probability_identities,
        "recall_plus_threshold_asr_identity": all_recall_asr_identities,
        "far_equals_clean_far": all_far_identities,
    }
    metric_gate = {
        "schema_version": "adsb.c001-p2b-gate.v1",
        "generation_utc": now(),
        "gate": "PASS" if all(metric_checks.values()) else "FAIL",
        "checks": metric_checks,
        "note": (
            "Recall and threshold-ASR are complementary on the identical "
            "original-label-anomaly support; normal controls are bitwise "
            "unchanged, so FAR is identical to clean FAR."
        ),
    }
    atomic_json(
        output_dir / "p2b_metric_identity_gate.json", metric_gate
    )

    physical_checks = {
        "physical_support_rows_present": len(physical_rows) >= 6,
        "v0_reported": all(row["Valid support V0"] is not None for row in physical_rows),
        "initialization_infeasible_reported": all(
            row["Initialization infeasible"] is not None for row in physical_rows
        ),
        "projection_failure_reported": all(
            row["Projection failure"] is not None for row in physical_rows
        ),
        "fallback_reported": all(row["Fallback"] is not None for row in physical_rows),
        "feasible_success_reported": all(
            row["Feasible success"] is not None for row in physical_rows
        ),
        "fallback_not_counted_as_attack_candidate": per_sample_fallback_count
        == 0,
    }
    physical_gate = {
        "schema_version": "adsb.c001-p2b-gate.v1",
        "generation_utc": now(),
        "gate": "PASS" if all(physical_checks.values()) else "FAIL",
        "checks": physical_checks,
    }
    atomic_json(
        output_dir / "p2b_physical_support_gate.json", physical_gate
    )

    figures = make_figures(
        output_dir,
        restart_records,
        r1_r5,
        r5_r10,
        overlap_rows,
        strongest_rows,
    )
    gates = {
        "Configuration Identity": configuration_gate["gate"],
        "Completeness": completeness_gate["gate"],
        "Restart Nesting": "PASS" if nesting_pass else "FAIL",
        "Candidate Preservation": candidate_gate["gate"],
        "Metric Identity": metric_gate["gate"],
        "Physical Support": physical_gate["gate"],
    }
    final_integrity = "PASS" if all(value == "PASS" for value in gates.values()) else "FAIL"
    integrity_gate = {
        "schema_version": "adsb.c001-p2b-gate.v1",
        "generation_utc": now(),
        "gate": final_integrity,
        "formal_gates": gates,
        "restart_adequacy": {
            row["Attack"]: row["Restart Gate"] for row in family_gate
        },
        "restart_adequacy_is_not_integrity": True,
        "p3_to_p6_executed": False,
        "paper_modified": False,
        "robustness_claims_restored": False,
    }
    atomic_json(output_dir / "p2b_integrity_gate.json", integrity_gate)

    report_lines = [
        "# C0-01 P2-B Multiple-Restart Audit",
        "",
        f"Generated: {now()}",
        "",
        f"- Final P2-B Integrity Gate: **{final_integrity}**",
        f"- Base logical tasks: **160/160**",
        f"- Conditional R10 tasks: **{decision['total_triggered_task_count']}**",
        f"- Explicit failed runs: **{len(failed_records)}**",
        "",
        "## Per-family Restart Adequacy",
        "",
        "| Attack | R10 triggered | Max R5→R10 increment | Verdict |",
        "|---|---:|---:|---|",
    ]
    for row in family_gate:
        maximum = (
            "N/A"
            if row["Max R5→R10 increment"] is None
            else f"{float(row['Max R5→R10 increment']):.6f}"
        )
        report_lines.append(
            f"| {row['Attack']} | {row['R10 triggered']} | {maximum} | "
            f"{row['Restart Gate']} |"
        )
    report_lines.extend(
        [
            "",
            "## Interpretation Controls",
            "",
            "- Clean fallback, initialization infeasibility, projection failure, and invalid final candidates are not treated as model robustness.",
            "- ERM and CAT-AD are reported separately in the underlying tables.",
            "- P2-B does not establish final CAT-AD robustness; P3–P5 remain unexecuted.",
            "- [CLAIM TOO STRONG] All legacy strong-robustness claims remain suspended.",
            "- [EXPERIMENT REQUIRED] Any R20 decision requires a separate preregistration.",
            "- [AUTHOR VERIFY] Penalty-only remains subject to a later loss/penalty audit when fallback is substantial.",
        ]
    )
    (output_dir / "p2b_report.md").write_text(
        "\n".join(report_lines) + "\n", encoding="utf-8"
    )

    manifest = load_json(output_dir / "p2b_manifest.json")
    manifest.update(
        {
            "updated_at_utc": now(),
            "phase": "p2b_complete",
            "base_tasks_completed": 160,
            "conditional_r10_completed": int(
                decision["total_triggered_task_count"]
            ),
            "explicit_failures": len(failed_records),
            "formal_gates": gates,
            "final_p2b_integrity_gate": final_integrity,
            "restart_adequacy": {
                row["Attack"]: row["Restart Gate"] for row in family_gate
            },
            "per_sample_restart_candidate_rows": per_sample_count,
            "p3_to_p6_executed": False,
            "paper_modified": False,
            "robustness_claims_restored": False,
        }
    )
    atomic_json(output_dir / "p2b_manifest.json", manifest)
    runtime.update(
        {
            "updated_at_utc": now(),
            "phase": "p2b_complete",
            "final_p2b_integrity_gate": final_integrity,
        }
    )
    atomic_json(output_dir / "p2b_runtime_status.json", runtime)

    required = [
        "p2b_manifest.json",
        "p2b_preflight.json",
        "p2b_task_inventory.csv",
        "p2b_runtime_status.json",
        "restart_records.csv.gz",
        "per_sample_restart_candidates.csv.gz",
        "r1_r5_comparison.csv",
        "r10_trigger_decision.json",
        "r5_r10_comparison.csv",
        "success_overlap.csv",
        "strongest_restart_distribution.csv",
        "physical_support_by_restart.csv",
        "per_seed_restart_gate.csv",
        "per_family_restart_gate.csv",
        "failed_runs.jsonl",
        "p2b_configuration_gate.json",
        "p2b_completeness_gate.json",
        "p2b_nesting_gate.json",
        "p2b_candidate_preservation_gate.json",
        "p2b_metric_identity_gate.json",
        "p2b_physical_support_gate.json",
        "p2b_integrity_gate.json",
        "p2b_report.md",
    ]
    required.extend(
        str(path.relative_to(output_dir)).replace("\\", "/")
        for path in figures
    )
    missing = [name for name in required if not (output_dir / name).is_file()]
    if missing:
        raise RuntimeError(f"required delivery artifacts missing: {missing}")
    generation = now()
    artifacts = []
    for name in sorted(required):
        path = output_dir / name
        artifacts.append(
            {
                "schema_version": SCHEMA,
                "path": name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "generation_utc": generation,
                "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
                "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
            }
        )
    atomic_json(
        output_dir / "artifact_hashes.json",
        {
            "schema_version": SCHEMA,
            "generation_utc": generation,
            "self_excluded": True,
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
            "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
            "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
        },
    )
    return {
        "status": final_integrity,
        "gates": gates,
        "restart_adequacy": integrity_gate["restart_adequacy"],
        "artifact_count": len(artifacts),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("trigger", "finalize"), required=True)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs/attack_audit_c001/p2b"),
    )
    args = parser.parse_args()
    project_root = args.project_root.resolve()
    output_dir = args.output_dir
    if not output_dir.is_absolute():
        output_dir = (project_root / output_dir).resolve()
    try:
        if args.phase == "trigger":
            decision = run_trigger(project_root, output_dir)
            print(json.dumps(decision, ensure_ascii=False, indent=2))
        elif args.phase == "finalize":
            result = run_finalize(project_root, output_dir)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

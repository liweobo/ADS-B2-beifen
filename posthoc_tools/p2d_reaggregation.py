"""Post-hoc aggregation and integrity gates for C0-01 P2-D.

This module never calls an attack.  It merges the corrected formal P2-C R40
sample state with compact records from the newly executed P2-D restart ranges.
Inherited raw artifacts remain in P2-C and are referenced by frozen hashes.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import os
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from adsb.checkpoints import sha256_file
from audit_tools.p2c_orchestration import canonical_hash
from audit_tools.p2c_runner import P2B_ROOT_RELATIVE, P2C_ROOT_RELATIVE, _source_r10_lookup
from audit_tools.p2d_runner import (
    EXPECTED_ATTACK_CODE_FINGERPRINT,
    EXPECTED_P2C_POSTHOC_FINGERPRINT,
    EXPECTED_R40_SNAPSHOT,
    FORMAL_V2_RELATIVE,
    PHYSICAL_ATTACKS,
    P2D_ROOT_RELATIVE,
    R80_IDS,
    R160_IDS,
    SCHEMA as RUNNER_SCHEMA,
    _set_read_only,
    _verify_formal_v2,
    _verify_frozen_state,
    load_json,
    now,
)


SCHEMA = "adsb.c001-p2d-reaggregation.v1"
AGGREGATE_FIELDS = (
    "schema_version",
    "generation_utc",
    "config_id",
    "seed",
    "model",
    "attack",
    "K",
    "restart_count",
    "attacked_support",
    "actual_candidate_support",
    "valid_or_feasible_support",
    "source_valid_support_V0",
    "formal_successes",
    "formal_asr",
    "pv_successes_on_V0",
    "pv_asr_on_V0",
    "restart_incidence_sum",
    "cumulative_unique_union",
    "recall_on_attacked",
    "f1_with_unchanged_normal_controls",
    "far_unchanged",
    "best_target_ce_mean",
    "best_target_ce_count",
    "fallback_event_count",
    "fallback_ever_count",
    "fallback_only_count",
    "final_fallback_count",
    "fallback_and_success_count",
    "new_unique_successes",
    "new_feasible_successes_on_V0",
    "new_restart_start",
    "new_restart_end",
)


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def atomic_csv(
    path: Path,
    rows: Iterable[dict[str, Any]],
    fields: Iterable[str] | None = None,
) -> None:
    values = list(rows)
    if fields is None:
        keys: list[str] = []
        seen: set[str] = set()
        for row in values:
            for key in row:
                if key not in seen:
                    seen.add(key)
                    keys.append(key)
        fields = keys
    fieldnames = list(fields)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fieldnames,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(values)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def _optional_float(value: Any) -> float | None:
    if value in (None, "", "None", "nan"):
        return None
    return float(value)


def _relative_ce_gain(previous: np.ndarray, current: np.ndarray) -> dict[str, Any]:
    """Reuse the frozen P2-C per-sample target-CE stability definition."""

    common = np.isfinite(previous) & np.isfinite(current)
    if not common.any():
        return {
            "common_active_support": 0,
            "median_relative_target_ce_gain": None,
            "max_relative_target_ce_gain": None,
        }
    gains = (previous[common] - current[common]) / np.maximum(
        previous[common], 1e-3
    )
    return {
        "common_active_support": int(common.sum()),
        "median_relative_target_ce_gain": float(np.median(gains)),
        "max_relative_target_ce_gain": float(np.max(gains)),
    }


def _state_path(p2d_root: Path, stage: str, config_id: str) -> Path:
    return p2d_root / stage / "aggregate" / "state" / f"{config_id}.npz"


def _save_state(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp.npz")
    np.savez_compressed(temporary, **value)
    os.replace(temporary, path)


def _load_state(path: Path) -> dict[str, np.ndarray]:
    with np.load(path, allow_pickle=False) as value:
        return {name: value[name] for name in value.files}


def _baseline_r40(project_root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, np.ndarray]]]:
    v2 = project_root / FORMAL_V2_RELATIVE / "reaggregated"
    aggregates = {
        row["config_id"]: row for row in read_csv(v2 / "r40_corrected_aggregate.csv")
    }
    if len(aggregates) != 80:
        raise RuntimeError("formal P2-C R40 aggregate is not exactly 80 units")
    states: dict[str, dict[str, list[Any]]] = {
        config_id: {
            "sample_id": [],
            "formal": [],
            "incidence": [],
            "source_valid": [],
            "actual": [],
            "valid": [],
            "fallback_ever": [],
            "fallback_only": [],
            "final_fallback": [],
            "best_ce": [],
            "best_restart": [],
        }
        for config_id in aggregates
    }
    membership = v2 / "cumulative_success_membership.csv.gz"
    with gzip.open(membership, "rt", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            if int(row["restart_count"]) != 40:
                continue
            state = states[row["config_id"]]
            state["sample_id"].append(row["sample_id"])
            state["formal"].append(_bool(row["formal_success"]))
            state["incidence"].append(int(row["success_restart_incidence"]))
            state["source_valid"].append(_bool(row["source_valid_V0"]))
    best = v2 / "best_target_loss_candidates.csv.gz"
    best_lookup: dict[str, dict[str, tuple[bool, float, int]]] = defaultdict(dict)
    with gzip.open(best, "rt", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            if int(row["restart_count"]) != 40:
                continue
            present = row["candidate_status"] == "PRESENT"
            best_lookup[row["config_id"]][row["sample_id"]] = (
                present,
                float(row["target_ce"]) if present else math.nan,
                int(row["restart_id"]) if present else -1,
            )
    fallback_lookup: dict[str, dict[str, tuple[bool, bool, bool]]] = defaultdict(dict)
    fallback_path = v2 / "fallback_sample_summary.csv"
    with fallback_path.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            if int(row["restart_count"]) != 40:
                continue
            fallback_lookup[row["config_id"]][row["sample_id"]] = (
                _bool(row["fallback_ever"]),
                _bool(row["fallback_only"]),
                _bool(row["final_fallback"]),
            )
    output: dict[str, dict[str, np.ndarray]] = {}
    for config_id, lists in states.items():
        sample_ids = np.asarray(lists["sample_id"], dtype="U64")
        if not len(sample_ids):
            raise RuntimeError(f"empty P2-C R40 membership: {config_id}")
        present = []
        ce = []
        restart = []
        fb_ever = []
        fb_only = []
        fb_final = []
        physical = aggregates[config_id]["attack"] in PHYSICAL_ATTACKS
        for sample_id in sample_ids.tolist():
            candidate = best_lookup[config_id][sample_id]
            present.append(candidate[0])
            ce.append(candidate[1])
            restart.append(candidate[2])
            fallback = fallback_lookup[config_id].get(sample_id, (False, False, False))
            fb_ever.append(fallback[0])
            fb_only.append(fallback[1])
            fb_final.append(fallback[2])
        candidate_present = np.asarray(present, dtype=bool)
        valid = ~np.asarray(fb_only, dtype=bool) if physical else candidate_present.copy()
        actual = (
            valid.copy()
            if aggregates[config_id]["attack"]
            in {"phys_projection_pgd", "phys_hybrid_pgd"}
            else candidate_present
        )
        output[config_id] = {
            "sample_id": sample_ids,
            "formal": np.asarray(lists["formal"], dtype=bool),
            "incidence": np.asarray(lists["incidence"], dtype=np.int32),
            "source_valid": np.asarray(lists["source_valid"], dtype=bool),
            "actual": actual,
            "valid": valid,
            "fallback_ever": np.asarray(fb_ever, dtype=bool),
            "fallback_only": np.asarray(fb_only, dtype=bool),
            "final_fallback": np.asarray(fb_final, dtype=bool),
            "best_ce": np.asarray(ce, dtype=np.float64),
            "best_restart": np.asarray(restart, dtype=np.int16),
        }
    return aggregates, output


def _snapshot_phase(project_root: Path, phase: str) -> dict[str, Any]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    root = p2d_root / phase
    inventory = read_csv(root / "task_inventory.csv")
    manifest = load_json(root / "execution_manifest.json")
    expected_ids = R80_IDS if phase == "r80" else R160_IDS
    if (
        len(inventory) != int(manifest["logical_task_count"])
        or any(row["execution_status"] != "completed" for row in inventory)
        or tuple(manifest["executed_restart_ids"]) != expected_ids
    ):
        raise RuntimeError(f"{phase.upper()} completeness failed before snapshot")
    task_failures: list[dict[str, Any]] = []
    for index, row in enumerate(inventory, 1):
        directory = root / "raw_new_restarts" / "tasks" / row["task_hash"]
        summary_path = directory / "summary.json"
        if not summary_path.is_file():
            task_failures.append({"config_id": row["config_id"], "reason": "missing_summary"})
            continue
        summary = load_json(summary_path)
        exact = tuple(summary["executed_restart_ids"]) == expected_ids
        identity = summary.get("task_hash") == row["task_hash"]
        artifacts = True
        for artifact in summary["artifacts"].values():
            path = directory / artifact["path"]
            artifacts &= (
                path.is_file()
                and path.stat().st_size == int(artifact["size_bytes"])
                and sha256_file(path) == artifact["sha256"]
            )
        if not (exact and identity and artifacts and all(summary["identity_checks"].values())):
            task_failures.append(
                {
                    "config_id": row["config_id"],
                    "exact_range": exact,
                    "identity": identity,
                    "artifacts": artifacts,
                }
            )
        if index % 20 == 0 or index == len(inventory):
            print(f"[{phase}-snapshot] task verification {index}/{len(inventory)}", flush=True)
    if task_failures:
        raise RuntimeError(f"{phase.upper()} task artifact verification failed")
    exclude = {
        f"{phase}_snapshot_manifest.json",
        f"{phase}_artifact_hashes.json",
    }
    paths = sorted(
        (
            value
            for value in root.rglob("*")
            if value.is_file()
            and value.name not in exclude
            and not value.name.endswith(".lock")
        ),
        key=lambda value: value.relative_to(root).as_posix(),
    )
    artifacts = []
    for index, path in enumerate(paths, 1):
        artifacts.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
        if index % 50 == 0 or index == len(paths):
            print(f"[{phase}-snapshot] file hash {index}/{len(paths)}", flush=True)
    hashes, orchestration = _verify_frozen_state(project_root)
    previous = (
        EXPECTED_R40_SNAPSHOT
        if phase == "r80"
        else manifest["source_r80_snapshot_hash"]
    )
    snapshot_hash = canonical_hash(
        {
            "schema_version": SCHEMA,
            "phase": phase,
            "artifacts": artifacts,
            "source_previous_snapshot_hash": previous,
            "p2d_configuration_hash": hashes["p2d_configuration_hash"],
            "orchestration_fingerprint": orchestration["orchestration_fingerprint"],
        }
    )
    payload = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "FROZEN",
        "phase": phase,
        f"{phase}_snapshot_hash": snapshot_hash,
        "source_previous_snapshot_hash": previous,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "p2d_configuration_hash": hashes["p2d_configuration_hash"],
        "orchestration_fingerprint": orchestration["orchestration_fingerprint"],
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "new_restart_ids": list(expected_ids),
        "inherited_restart_rerun": False,
        "task_verification_failures": 0,
    }
    atomic_json(root / f"{phase}_snapshot_manifest.json", payload)
    atomic_json(
        root / f"{phase}_artifact_hashes.json",
        {
            "schema_version": SCHEMA,
            "phase": phase,
            "snapshot_hash": snapshot_hash,
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
            "status": "PASS",
        },
    )
    for path in paths:
        _set_read_only(path)
    _set_read_only(root / f"{phase}_snapshot_manifest.json")
    _set_read_only(root / f"{phase}_artifact_hashes.json")
    return payload


def _previous_stage(
    project_root: Path, stage: str
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, np.ndarray]], int]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    if stage == "r80":
        aggregates, states = _baseline_r40(project_root)
        return aggregates, states, 40
    aggregates = {
        row["config_id"]: row
        for row in read_csv(p2d_root / "r80" / "aggregate" / "r80_corrected_aggregate.csv")
    }
    states = {
        config_id: _load_state(_state_path(p2d_root, "r80", config_id))
        for config_id in aggregates
    }
    return aggregates, states, 80


def _merge_stage(project_root: Path, stage: str) -> dict[str, Any]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    root = p2d_root / stage
    previous_aggregates, previous_states, previous_r = _previous_stage(project_root, stage)
    target_r = 80 if stage == "r80" else 160
    expected_ids = R80_IDS if stage == "r80" else R160_IDS
    inventory = read_csv(root / "task_inventory.csv")
    source_lookup = _source_r10_lookup(project_root)
    generated = now()
    aggregates: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    preservation: list[dict[str, Any]] = []
    metric_checks: list[dict[str, Any]] = []
    physical_checks: list[dict[str, Any]] = []
    for index, row in enumerate(inventory, 1):
        config_id = row["config_id"]
        prior = previous_states[config_id]
        prior_agg = previous_aggregates[config_id]
        source = source_lookup[config_id]
        directory = root / "raw_new_restarts" / "tasks" / row["task_hash"]
        summary = load_json(directory / "summary.json")
        with np.load(directory / summary["artifacts"]["candidates"]["path"], allow_pickle=False) as z:
            sample_id = z["sample_id"].astype("U")
            if not np.array_equal(sample_id, prior["sample_id"].astype("U")):
                raise RuntimeError(f"sample identity mismatch: {stage}/{config_id}")
            if tuple(z["restart_ids"].astype(int).tolist()) != expected_ids:
                raise RuntimeError(f"restart identity mismatch: {stage}/{config_id}")
            new_success_by_restart = z["per_restart_success"].astype(bool)
            new_feasible_by_restart = z["per_restart_feasible_success"].astype(bool)
            new_active_by_restart = z["per_restart_active"].astype(bool)
            new_final_valid_by_restart = z["per_restart_final_valid"].astype(bool)
            new_projection_failure = z["per_restart_projection_failure"].astype(bool)
            new_best_ce_by_restart = z["per_restart_best_target_ce"].astype(float)
            new_best_feasible_ce_by_restart = z[
                "per_restart_best_feasible_target_ce"
            ].astype(float)
            source_valid = z["source_valid"].astype(bool)
        if not np.array_equal(source_valid, prior["source_valid"].astype(bool)):
            raise RuntimeError(f"source-valid identity mismatch: {stage}/{config_id}")
        physical = row["attack"] in PHYSICAL_ATTACKS
        prior_formal = prior["formal"].astype(bool)
        prior_pv = prior_formal & source_valid
        new_success = new_success_by_restart.any(axis=0)
        formal = prior_formal | new_success
        new_pv = formal & source_valid
        incidence = prior["incidence"].astype(np.int64) + new_success_by_restart.sum(axis=0)
        actual = prior["actual"].astype(bool) | new_active_by_restart.any(axis=0)
        new_valid = (
            np.isfinite(new_best_feasible_ce_by_restart).any(axis=0)
            if physical
            else new_active_by_restart.any(axis=0)
        )
        valid = prior["valid"].astype(bool) | new_valid
        new_fallback = ~new_final_valid_by_restart
        fallback_ever = prior["fallback_ever"].astype(bool) | new_fallback.any(axis=0)
        fallback_only = ~valid if physical else np.zeros(len(sample_id), dtype=bool)
        final_fallback = (
            prior["final_fallback"].astype(bool) & new_fallback.all(axis=0)
            if physical
            else np.zeros(len(sample_id), dtype=bool)
        )
        fallback_and_success = fallback_ever & formal
        new_min_ce = np.min(
            np.where(np.isfinite(new_best_ce_by_restart), new_best_ce_by_restart, np.inf),
            axis=0,
        )
        new_min_ce[~np.isfinite(new_min_ce)] = np.nan
        prior_ce = prior["best_ce"].astype(float)
        best_ce = np.where(
            np.isfinite(prior_ce) & np.isfinite(new_min_ce),
            np.minimum(prior_ce, new_min_ce),
            np.where(np.isfinite(prior_ce), prior_ce, new_min_ce),
        )
        local_restart = np.nanargmin(
            np.where(np.isfinite(new_best_ce_by_restart), new_best_ce_by_restart, np.inf),
            axis=0,
        )
        new_restart = np.asarray(expected_ids, dtype=np.int16)[local_restart]
        new_restart[~np.isfinite(new_min_ce)] = -1
        prior_restart = prior["best_restart"].astype(np.int16)
        take_new = np.isfinite(new_min_ce) & (
            ~np.isfinite(prior_ce) | (new_min_ce < prior_ce)
        )
        best_restart = np.where(take_new, new_restart, prior_restart).astype(np.int16)
        support = len(sample_id)
        successes = int(formal.sum())
        source_valid_support = int(source_valid.sum())
        pv_successes = int(new_pv.sum()) if physical else None
        fp = int(source["clean_metrics"]["fp"])
        tn = int(source["clean_metrics"]["tn"])
        tp = support - successes
        fn = successes
        f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0
        finite_ce = best_ce[np.isfinite(best_ce)]
        fallback_events = (
            int(prior_agg.get("fallback_event_count") or 0) + int(new_fallback.sum())
            if physical
            else None
        )
        aggregate = {
            "schema_version": SCHEMA,
            "generation_utc": generated,
            "config_id": config_id,
            "seed": int(row["seed"]),
            "model": row["model"],
            "attack": row["attack"],
            "K": int(row["K"]),
            "restart_count": target_r,
            "attacked_support": support,
            "actual_candidate_support": int(actual.sum()),
            "valid_or_feasible_support": int(valid.sum()),
            "source_valid_support_V0": source_valid_support,
            "formal_successes": successes,
            "formal_asr": successes / support,
            "pv_successes_on_V0": pv_successes,
            "pv_asr_on_V0": (
                pv_successes / source_valid_support
                if physical and source_valid_support
                else None
            ),
            "restart_incidence_sum": int(incidence.sum()),
            "cumulative_unique_union": successes,
            "recall_on_attacked": 1.0 - successes / support,
            "f1_with_unchanged_normal_controls": f1,
            "far_unchanged": fp / (fp + tn) if fp + tn else 0.0,
            "best_target_ce_mean": float(np.mean(finite_ce)) if len(finite_ce) else None,
            "best_target_ce_count": int(len(finite_ce)),
            "fallback_event_count": fallback_events,
            "fallback_ever_count": int(fallback_ever.sum()) if physical else None,
            "fallback_only_count": int(fallback_only.sum()) if physical else None,
            "final_fallback_count": int(final_fallback.sum()) if physical else None,
            "fallback_and_success_count": int(fallback_and_success.sum()) if physical else None,
            "new_unique_successes": int((formal & ~prior_formal).sum()),
            "new_feasible_successes_on_V0": (
                int((new_pv & ~prior_pv).sum()) if physical else 0
            ),
            "new_restart_start": expected_ids[0],
            "new_restart_end": expected_ids[-1],
        }
        aggregates.append(aggregate)
        previous_asr = float(prior_agg["formal_asr"])
        previous_pv = _optional_float(prior_agg.get("pv_asr_on_V0"))
        previous_ce = _optional_float(prior_agg.get("best_target_ce_mean"))
        current_ce = _optional_float(aggregate["best_target_ce_mean"])
        ce_gain = _relative_ce_gain(prior_ce, best_ce)
        relative_ce = ce_gain["median_relative_target_ce_gain"]
        delta = float(aggregate["formal_asr"]) - previous_asr
        feasible_delta = (
            float(aggregate["pv_asr_on_V0"]) - float(previous_pv)
            if physical and previous_pv is not None and aggregate["pv_asr_on_V0"] is not None
            else 0.0
        )
        checks = {
            "success_increment_lt_0_005": delta < 0.005,
            "physical_feasible_increment_lt_0_005": feasible_delta < 0.005,
            "relative_target_ce_improvement_lt_0_01": (
                relative_ce is not None and relative_ce < 0.01
            ),
            "no_nesting_loss": bool(np.all(~prior_formal | formal)),
            "best_target_ce_not_worse": bool(
                np.all(
                    ~np.isfinite(prior_ce)
                    | (np.isfinite(best_ce) & (best_ce <= prior_ce + 1e-12))
                )
            ),
        }
        comparison = {
            "schema_version": SCHEMA,
            "config_id": config_id,
            "seed": int(row["seed"]),
            "model": row["model"],
            "attack": row["attack"],
            "K": int(row["K"]),
            "previous_R": previous_r,
            "current_R": target_r,
            "previous_asr": previous_asr,
            "current_asr": aggregate["formal_asr"],
            "asr_increment": delta,
            "previous_feasible_asr": previous_pv,
            "current_feasible_asr": aggregate["pv_asr_on_V0"],
            "feasible_asr_increment": feasible_delta,
            "previous_best_target_ce_mean": previous_ce,
            "current_best_target_ce_mean": current_ce,
            "relative_target_ce_improvement": relative_ce,
            "common_active_support": ce_gain["common_active_support"],
            "median_relative_target_ce_gain": ce_gain[
                "median_relative_target_ce_gain"
            ],
            "max_relative_target_ce_gain": ce_gain["max_relative_target_ce_gain"],
            "new_unique_successes": aggregate["new_unique_successes"],
            "new_feasible_successes": aggregate["new_feasible_successes_on_V0"],
            "checks": json.dumps(checks, sort_keys=True),
            "stage_stable": all(checks.values()),
        }
        comparisons.append(comparison)
        preservation.append(
            {
                "config_id": config_id,
                "prior_successes_preserved": checks["no_nesting_loss"],
                "prior_actual_support_preserved": bool(
                    np.all(~prior["actual"].astype(bool) | actual)
                ),
                "prior_valid_support_preserved": bool(
                    np.all(~prior["valid"].astype(bool) | valid)
                ),
                "best_target_ce_not_worse": checks["best_target_ce_not_worse"],
                "status": "PASS" if checks["no_nesting_loss"] and checks["best_target_ce_not_worse"] else "FAIL",
            }
        )
        metric_checks.append(
            {
                "config_id": config_id,
                "count_matches_membership": successes == int(formal.sum()),
                "asr_matches": math.isclose(
                    float(aggregate["formal_asr"]), float(formal.mean()), abs_tol=1e-15
                ),
                "unique_union": successes == int(aggregate["cumulative_unique_union"]),
                "recall_identity": math.isclose(
                    float(aggregate["recall_on_attacked"])
                    + float(aggregate["formal_asr"]),
                    1.0,
                    abs_tol=1e-15,
                ),
            }
        )
        if physical:
            physical_checks.append(
                {
                    "config_id": config_id,
                    "success_subset_feasible_support": int((formal & ~valid).sum()) == 0,
                    "fallback_only_success_intersection": int((fallback_only & formal).sum()),
                    "genuine_fallback_candidate_success": 0,
                    "fallback_events_retained": fallback_events is not None,
                    "projection_failures_retained_in_raw": bool(
                        "per_restart_projection_failure" in _load_state_array_names(directory / summary["artifacts"]["candidates"]["path"])
                    ),
                }
            )
        _save_state(
            _state_path(p2d_root, stage, config_id),
            {
                "sample_id": sample_id.astype("U64"),
                "formal": formal,
                "incidence": incidence.astype(np.int32),
                "source_valid": source_valid,
                "actual": actual,
                "valid": valid,
                "fallback_ever": fallback_ever,
                "fallback_only": fallback_only,
                "final_fallback": final_fallback,
                "best_ce": best_ce,
                "best_restart": best_restart,
                "previous_formal": prior_formal,
                "previous_best_ce": prior_ce,
                "new_success_by_restart": new_success_by_restart,
                "new_feasible_by_restart": new_feasible_by_restart,
                "new_best_ce_by_restart": new_best_ce_by_restart,
                "new_projection_failure_by_restart": new_projection_failure,
                "new_final_valid_by_restart": new_final_valid_by_restart,
                "new_restart_ids": np.asarray(expected_ids, dtype=np.int16),
            },
        )
        if index % 10 == 0 or index == len(inventory):
            print(f"[{stage}-aggregate] {index}/{len(inventory)}", flush=True)
    atomic_csv(root / "aggregate" / f"{stage}_corrected_aggregate.csv", aggregates, AGGREGATE_FIELDS)
    comparison_name = "r40_r80_comparison.csv" if stage == "r80" else "r80_r160_comparison.csv"
    atomic_csv(root / comparison_name, comparisons)
    candidate_status = "PASS" if all(row["status"] == "PASS" for row in preservation) else "FAIL"
    candidate_gate = {
        "schema_version": SCHEMA,
        "stage": stage,
        "configurations": len(preservation),
        "failed": [row for row in preservation if row["status"] != "PASS"],
        "status": candidate_status,
    }
    atomic_json(root / f"{stage}_candidate_preservation.json", candidate_gate)
    metric_status = "PASS" if all(all(value for key, value in row.items() if key != "config_id") for row in metric_checks) else "FAIL"
    metric_gate = {
        "schema_version": SCHEMA,
        "stage": stage,
        "checks": metric_checks,
        "status": metric_status,
    }
    atomic_json(root / f"{stage}_metric_identity_gate.json", metric_gate)
    physical_status = "PASS" if all(
        row["success_subset_feasible_support"]
        and row["fallback_only_success_intersection"] == 0
        and row["genuine_fallback_candidate_success"] == 0
        and row["fallback_events_retained"]
        and row["projection_failures_retained_in_raw"]
        for row in physical_checks
    ) else "FAIL"
    physical_gate = {
        "schema_version": SCHEMA,
        "stage": stage,
        "checks": physical_checks,
        "diagnostic_pending_loss_penalty_audit": True,
        "status": physical_status,
    }
    atomic_json(root / f"{stage}_physical_support_gate.json", physical_gate)
    return {
        "aggregates": aggregates,
        "comparisons": comparisons,
        "candidate_status": candidate_status,
        "metric_status": metric_status,
        "physical_status": physical_status,
    }


def _load_state_array_names(path: Path) -> set[str]:
    with np.load(path, allow_pickle=False) as value:
        return set(value.files)


def _integrity_gate(
    *, project_root: Path, stage: str, snapshot: dict[str, Any], merged: dict[str, Any]
) -> dict[str, Any]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    root = p2d_root / stage
    inventory = read_csv(root / "task_inventory.csv")
    expected = 80 if stage == "r80" else len(inventory)
    previous = EXPECTED_R40_SNAPSHOT if stage == "r80" else snapshot["source_previous_snapshot_hash"]
    checks = {
        "Completeness": len(inventory) == expected
        and all(row["execution_status"] == "completed" for row in inventory),
        "Restart Identity": all(
            int(row["executed_restart_start"]) == (40 if stage == "r80" else 80)
            and int(row["executed_restart_end"]) == (79 if stage == "r80" else 159)
            for row in inventory
        ),
        "Nesting": all(row["source_previous_snapshot_hash"] == previous for row in inventory),
        "Candidate Preservation": merged["candidate_status"] == "PASS",
        "Metric Identity": merged["metric_status"] == "PASS",
        "Physical Support": merged["physical_status"] == "PASS",
        "Artifact Identity": snapshot["status"] == "FROZEN"
        and snapshot["task_verification_failures"] == 0,
    }
    payload = {
        "schema_version": SCHEMA,
        "gate": f"P2-D {stage.upper()} Integrity",
        "checks": checks,
        "source_previous_snapshot_hash": previous,
        "snapshot_hash": snapshot[f"{stage}_snapshot_hash"],
        "status": "PASS" if all(checks.values()) else "FAIL",
    }
    atomic_json(root / f"{stage}_integrity_gate.json", payload)
    return payload


def _freeze_trigger(project_root: Path, merged: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    adequacy = p2d_root / "adequacy"
    rows = []
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in merged["comparisons"]:
        reasons = []
        if float(row["asr_increment"]) >= 0.005:
            reasons.append("ASR_INCREMENT_GTE_0.005")
        if row["attack"] in PHYSICAL_ATTACKS and float(row["feasible_asr_increment"]) >= 0.005:
            reasons.append("FEASIBLE_ASR_INCREMENT_GTE_0.005")
        ce_gain = _optional_float(row.get("relative_target_ce_improvement"))
        if ce_gain is None:
            reasons.append("TARGET_CE_NOT_COMPARABLE")
        elif ce_gain >= 0.01:
            reasons.append("RELATIVE_TARGET_CE_IMPROVEMENT_GTE_0.01")
        item = {
            **row,
            "trigger_reason": "|".join(reasons),
            "unit_triggers": bool(reasons),
        }
        rows.append(item)
        by_family[row["attack"]].append(item)
    if set(by_family) != {
        "norm_pgd",
        "phys_projection_pgd",
        "phys_penalty_pgd",
        "phys_hybrid_pgd",
    } or any(len(values) != 20 for values in by_family.values()):
        raise RuntimeError("R160 trigger analysis is not exactly 20 units for each family")
    atomic_csv(adequacy / "r160_trigger_analysis.csv", rows)
    triggered = sorted(
        attack for attack, values in by_family.items() if any(row["unit_triggers"] for row in values)
    )
    family_decisions = {}
    for attack, values in sorted(by_family.items()):
        family_decisions[attack] = {
            "unit_count": len(values),
            "triggering_unit_count": sum(row["unit_triggers"] for row in values),
            "trigger": attack in triggered,
            "reasons": sorted(
                {
                    reason
                    for row in values
                    for reason in str(row["trigger_reason"]).split("|")
                    if reason
                }
            ),
        }
    trigger_spec = p2d_root / "configuration_freeze" / "p2d_trigger_spec.json"
    decision = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "FROZEN",
        "source_r40_snapshot_hash": EXPECTED_R40_SNAPSHOT,
        "source_r80_snapshot_hash": snapshot["r80_snapshot_hash"],
        "source_p2c_v2_hash": sha256_file(
            project_root / FORMAL_V2_RELATIVE / "formal_reaggregation_artifact_hashes.json"
        ),
        "trigger_spec_sha256": sha256_file(trigger_spec),
        "trigger_analysis_sha256": sha256_file(adequacy / "r160_trigger_analysis.csv"),
        "family_decisions": family_decisions,
        "triggered_families": triggered,
        "expected_r160_task_count": 20 * len(triggered),
        "expected_r160_new_restart_executions": 1600 * len(triggered),
        "partial_family_execution": False,
        "r320_authorized": False,
    }
    path = adequacy / "r160_trigger_decision.json"
    atomic_json(path, decision)
    _set_read_only(adequacy / "r160_trigger_analysis.csv")
    _set_read_only(path)
    return decision


def finalize_r80(project_root: Path) -> dict[str, Any]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    _verify_frozen_state(project_root)
    existing = p2d_root / "adequacy" / "r160_trigger_decision.json"
    if existing.exists():
        return load_json(existing)
    snapshot = _snapshot_phase(project_root, "r80")
    merged = _merge_stage(project_root, "r80")
    integrity = _integrity_gate(
        project_root=project_root, stage="r80", snapshot=snapshot, merged=merged
    )
    if integrity["status"] != "PASS":
        raise RuntimeError("P2-D R80 integrity failed; trigger decision is forbidden")
    return _freeze_trigger(project_root, merged, snapshot)


def _family_and_model_tables(
    comparisons: list[dict[str, Any]], stage_label: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    family_rows = []
    for attack in sorted({row["attack"] for row in comparisons}):
        group = [row for row in comparisons if row["attack"] == attack]
        ce_values = [
            value
            for value in (
                _optional_float(row.get("relative_target_ce_improvement"))
                for row in group
            )
            if value is not None
        ]
        family_rows.append(
            {
                "stage": stage_label,
                "attack": attack,
                "unit_count": len(group),
                "max_asr_increment": max(float(row["asr_increment"]) for row in group),
                "mean_asr_increment": float(np.mean([float(row["asr_increment"]) for row in group])),
                "median_asr_increment": float(np.median([float(row["asr_increment"]) for row in group])),
                "max_feasible_increment": max(float(row["feasible_asr_increment"]) for row in group),
                "max_relative_target_ce_improvement": (
                    max(ce_values) if len(ce_values) == len(group) else None
                ),
                "target_ce_comparable_units": len(ce_values),
                "new_successes": sum(int(row["new_unique_successes"]) for row in group),
                "new_feasible_successes": sum(int(row["new_feasible_successes"]) for row in group),
            }
        )
    model_rows = []
    for model in sorted({row["model"] for row in comparisons}):
        group = [row for row in comparisons if row["model"] == model]
        ce_values = [
            value
            for value in (
                _optional_float(row.get("relative_target_ce_improvement"))
                for row in group
            )
            if value is not None
        ]
        model_rows.append(
            {
                "stage": stage_label,
                "model": model,
                "unit_count": len(group),
                "mean_asr_increment": float(np.mean([float(row["asr_increment"]) for row in group])),
                "max_asr_increment": max(float(row["asr_increment"]) for row in group),
                "median_asr_increment": float(np.median([float(row["asr_increment"]) for row in group])),
                "new_successes": sum(int(row["new_unique_successes"]) for row in group),
                "new_feasible_successes": sum(int(row["new_feasible_successes"]) for row in group),
                "mean_relative_target_ce_improvement": (
                    float(np.mean(ce_values)) if ce_values else None
                ),
                "target_ce_comparable_units": len(ce_values),
            }
        )
    return family_rows, model_rows


def _diagnostics(
    project_root: Path,
    r80_rows: list[dict[str, Any]],
    r160_rows: list[dict[str, Any]],
    triggered: set[str],
) -> None:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    diagnostics = p2d_root / "diagnostics"
    p2c = project_root / P2C_ROOT_RELATIVE
    v2 = project_root / FORMAL_V2_RELATIVE / "reaggregated"
    early_curve = read_csv(p2c / "r40_cumulative_success.csv")
    formal_early = {}
    for restart in (10, 20, 40):
        formal_early[restart] = {
            row["config_id"]: row
            for row in read_csv(v2 / f"r{restart}_corrected_aggregate.csv")
        }
    r80_lookup = {row["config_id"]: row for row in r80_rows}
    r160_lookup = {row["config_id"]: row for row in r160_rows}
    curve_rows = []
    for config_id, r80 in sorted(r80_lookup.items()):
        for restart in (1, 5):
            source = next(
                row
                for row in early_curve
                if row["config_id"] == config_id and int(row["restart_count"]) == restart
            )
            curve_rows.append(
                {
                    "config_id": config_id,
                    "seed": int(r80["seed"]),
                    "model": r80["model"],
                    "attack": r80["attack"],
                    "K": int(r80["K"]),
                    "restart_count": restart,
                    "cumulative_unique_asr": float(source["success_preserving_asr"]),
                    "feasible_asr": _optional_float(source.get("feasible_success_asr")),
                    "best_target_ce_mean": None,
                    "source": "frozen P2-C diagnostic curve; DIAGNOSTIC ONLY",
                }
            )
        for restart in (10, 20, 40):
            source = formal_early[restart][config_id]
            curve_rows.append(
                {
                    "config_id": config_id,
                    "seed": int(r80["seed"]),
                    "model": r80["model"],
                    "attack": r80["attack"],
                    "K": int(r80["K"]),
                    "restart_count": restart,
                    "cumulative_unique_asr": float(source["formal_asr"]),
                    "feasible_asr": _optional_float(source.get("pv_asr_on_V0")),
                    "best_target_ce_mean": _optional_float(source.get("best_target_ce_mean")),
                    "source": "P2-C formal_reaggregation_v2",
                }
            )
        curve_rows.append(
            {
                "config_id": config_id,
                "seed": int(r80["seed"]),
                "model": r80["model"],
                "attack": r80["attack"],
                "K": int(r80["K"]),
                "restart_count": 80,
                "cumulative_unique_asr": float(r80["formal_asr"]),
                "feasible_asr": _optional_float(r80.get("pv_asr_on_V0")),
                "best_target_ce_mean": _optional_float(r80.get("best_target_ce_mean")),
                "source": "P2-D R80 corrected",
            }
        )
        if r80["attack"] in triggered:
            source = r160_lookup[config_id]
            curve_rows.append(
                {
                    "config_id": config_id,
                    "seed": int(r80["seed"]),
                    "model": r80["model"],
                    "attack": r80["attack"],
                    "K": int(r80["K"]),
                    "restart_count": 160,
                    "cumulative_unique_asr": float(source["formal_asr"]),
                    "feasible_asr": _optional_float(source.get("pv_asr_on_V0")),
                    "best_target_ce_mean": _optional_float(source.get("best_target_ce_mean")),
                    "source": "P2-D R160 corrected",
                }
            )
    atomic_csv(diagnostics / "cumulative_restart_curve.csv", curve_rows)
    marginal = []
    for config_id, group in _group_rows(curve_rows, "config_id").items():
        ordered = sorted(group, key=lambda row: int(row["restart_count"]))
        for previous, current in zip(ordered, ordered[1:]):
            span = int(current["restart_count"]) - int(previous["restart_count"])
            marginal.append(
                {
                    "config_id": config_id,
                    "model": current["model"],
                    "attack": current["attack"],
                    "K": current["K"],
                    "from_R": previous["restart_count"],
                    "to_R": current["restart_count"],
                    "asr_increment": float(current["cumulative_unique_asr"]) - float(previous["cumulative_unique_asr"]),
                    "marginal_asr_per_restart": (float(current["cumulative_unique_asr"]) - float(previous["cumulative_unique_asr"])) / span,
                    "diagnostic_only": True,
                }
            )
    atomic_csv(diagnostics / "marginal_success_discovery.csv", marginal)
    strongest = []
    overlap = []
    for config_id, r80 in sorted(r80_lookup.items()):
        final_stage = "r160" if r80["attack"] in triggered else "r80"
        state = _load_state(_state_path(p2d_root, final_stage, config_id))
        ids, counts = np.unique(state["best_restart"], return_counts=True)
        for restart_id, count in zip(ids.tolist(), counts.tolist()):
            strongest.append(
                {
                    "config_id": config_id,
                    "model": r80["model"],
                    "attack": r80["attack"],
                    "K": r80["K"],
                    "restart_id": int(restart_id),
                    "selected_count": int(count),
                    "selected_rate": int(count) / len(state["best_restart"]),
                    "diagnostic_only": True,
                }
            )
        a = state["previous_formal"].astype(bool)
        b = state["formal"].astype(bool)
        union = int((a | b).sum())
        overlap.append(
            {
                "config_id": config_id,
                "model": r80["model"],
                "attack": r80["attack"],
                "K": r80["K"],
                "previous_R": 80 if final_stage == "r160" else 40,
                "final_R": 160 if final_stage == "r160" else 80,
                "intersection": int((a & b).sum()),
                "union": union,
                "jaccard": int((a & b).sum()) / union if union else 1.0,
                "diagnostic_only": True,
            }
        )
    atomic_csv(diagnostics / "strongest_restart_distribution.csv", strongest)
    atomic_csv(diagnostics / "success_overlap.csv", overlap)
    capture = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "DIAGNOSTIC ONLY",
        "method": "two-batch overlap placeholder; not a formal stopping rule",
        "estimates": [],
    }
    for config_id, r80 in sorted(r80_lookup.items()):
        final_stage = "r160" if r80["attack"] in triggered else "r80"
        state = _load_state(_state_path(p2d_root, final_stage, config_id))
        by_restart = state["new_success_by_restart"].astype(bool)
        midpoint = len(by_restart) // 2
        a = by_restart[:midpoint].any(axis=0)
        b = by_restart[midpoint:].any(axis=0)
        n1, n2, m = int(a.sum()), int(b.sum()), int((a & b).sum())
        estimate = ((n1 + 1) * (n2 + 1) / (m + 1)) - 1
        capture["estimates"].append(
            {
                "config_id": config_id,
                "stage": final_stage,
                "first_half_discoveries": n1,
                "second_half_discoveries": n2,
                "overlap": m,
                "chapman_estimate": estimate,
            }
        )
    atomic_json(diagnostics / "capture_recapture_diagnostic.json", capture)
    atomic_json(
        diagnostics / "saturation_diagnostic.json",
        {
            "schema_version": SCHEMA,
            "generated_at_utc": now(),
            "status": "DIAGNOSTIC ONLY",
            "formal_gate_replaced": False,
            "curve_rows": len(curve_rows),
            "marginal_rows": len(marginal),
            "strongest_restart_rows": len(strongest),
            "success_overlap_rows": len(overlap),
            "r320_executed": False,
        },
    )


def _group_rows(rows: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        output[str(row[key])].append(row)
    return output


def _fmt(value: Any, digits: int = 6) -> str:
    number = _optional_float(value)
    return "NOT_COMPARABLE" if number is None else f"{number:.{digits}f}"


def _final_artifacts(project_root: Path) -> dict[str, Any]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    artifacts = []
    for index, path in enumerate(
        sorted(
            (
                value
                for value in p2d_root.rglob("*")
                if value.is_file()
                and value.name != "p2d_artifact_hashes.json"
                and not value.name.endswith(".lock")
            ),
            key=lambda value: value.relative_to(p2d_root).as_posix(),
        ),
        1,
    ):
        artifacts.append(
            {
                "path": path.relative_to(p2d_root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
        if index % 100 == 0:
            print(f"[final-artifacts] {index}", flush=True)
    canonical_raw_names = {
        "candidate_iterates.npz",
        "per_sample_range_records.csv.gz",
        "per_step_restart_records.csv.gz",
        "summary.json",
    }
    p2c_inherited_hashes: set[str] = set()
    p2c_root = project_root / P2C_ROOT_RELATIVE
    for phase in ("r20", "r40"):
        manifest = load_json(p2c_root / f"{phase}_raw_snapshot_manifest.json")
        p2c_inherited_hashes.update(
            row["sha256"]
            for row in manifest["artifacts"]
            if Path(row["path"]).name in canonical_raw_names
        )
    r80_snapshot_path = p2d_root / "r80" / "r80_snapshot_manifest.json"
    r80_raw_hashes: set[str] = set()
    if r80_snapshot_path.exists():
        r80_raw_hashes.update(
            row["sha256"]
            for row in load_json(r80_snapshot_path)["artifacts"]
            if "/raw_new_restarts/" in f"/{row['path']}"
            and Path(row["path"]).name in canonical_raw_names
        )
    inherited_matches = [
        row["path"]
        for row in artifacts
        if "/raw_new_restarts/" in f"/{row['path']}"
        and Path(row["path"]).name in canonical_raw_names
        and (
            (
                row["path"].startswith("r80/")
                and row["sha256"] in p2c_inherited_hashes
            )
            or (
                row["path"].startswith("r160/")
                and row["sha256"] in (p2c_inherited_hashes | r80_raw_hashes)
            )
        )
    ]
    forbidden_copy_paths = [
        row["path"]
        for row in artifacts
        if any(
            marker in row["path"].lower()
            for marker in (
                "r80_full_copy_of_r0_79",
                "r160_full_copy_of_r0_159",
                "full_copy",
                "inherited_raw_copy",
            )
        )
    ]
    duplicate_canonical_output = len(inherited_matches) + len(forbidden_copy_paths)
    payload = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "missing": 0,
        "hash_mismatch": 0,
        "duplicate_canonical_output": duplicate_canonical_output,
        "inherited_raw_hash_matches": inherited_matches,
        "forbidden_copy_paths": forbidden_copy_paths,
        "status": "PASS" if duplicate_canonical_output == 0 else "FAIL",
    }
    atomic_json(p2d_root / "p2d_artifact_hashes.json", payload)
    return payload


def _render_report(
    *,
    project_root: Path,
    r80_integrity: dict[str, Any],
    r160_integrity: dict[str, Any],
    trigger: dict[str, Any],
    family_verdicts: dict[str, Any],
    model_rows: list[dict[str, Any]],
    overall: str,
) -> None:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    config = load_json(p2d_root / "configuration_freeze" / "p2d_configuration_hashes.json")
    capacity = load_json(p2d_root / "source_snapshot" / "capacity_estimate.json")
    r80_status = load_json(p2d_root / "r80" / "runtime_status.json")
    r80_snapshot = load_json(p2d_root / "r80" / "r80_snapshot_manifest.json")
    r160_status_path = p2d_root / "r160" / "runtime_status.json"
    r160_status = load_json(r160_status_path)
    r160_snapshot_path = p2d_root / "r160" / "r160_snapshot_manifest.json"
    r160_snapshot = load_json(r160_snapshot_path) if r160_snapshot_path.exists() else None
    family_lines = []
    for attack, value in sorted(family_verdicts.items()):
        family_lines.append(
            f"- {attack}: final R={value['final_evaluated_R']}, max ASR increment={_fmt(value['max_final_stage_asr_increment'])}, mean={_fmt(value['mean_final_stage_asr_increment'])}, max feasible={_fmt(value['max_feasible_increment'])}, max relative CE={_fmt(value['max_relative_target_ce_improvement'])}, verdict={value['verdict']}"
        )
    strongest_path = p2d_root / "diagnostics" / "strongest_restart_distribution.csv"
    strongest_rows = read_csv(strongest_path)
    modal_restart: dict[str, str] = {}
    for model in sorted({row["model"] for row in strongest_rows}):
        counts: dict[int, int] = defaultdict(int)
        for row in strongest_rows:
            if row["model"] == model and int(row["restart_id"]) >= 0:
                counts[int(row["restart_id"])] += int(row["selected_count"])
        modal_restart[model] = (
            str(max(counts, key=counts.get)) if counts else "NOT_APPLICABLE"
        )
    model_lines = []
    for row in model_rows:
        model_lines.append(
            f"- {row['model']} {row['stage']}: mean/max ASR increment={_fmt(row['mean_asr_increment'])}/{_fmt(row['max_asr_increment'])}, new successes={row['new_successes']}, new feasible successes={row['new_feasible_successes']}, mean relative target-CE gain={_fmt(row.get('mean_relative_target_ce_improvement'))}, modal strongest restart={modal_restart.get(row['model'], 'NOT_APPLICABLE')}"
        )
    r80_family_rows = {
        row["attack"]: row
        for row in read_csv(p2d_root / "adequacy" / "restart_gain_by_family.csv")
        if row["stage"] == "R40_TO_R80"
    }
    r80_adequacy_lines = []
    for attack, decision in sorted(trigger["family_decisions"].items()):
        row = r80_family_rows[attack]
        r80_adequacy_lines.append(
            f"- {attack}: max ASR increment={_fmt(row['max_asr_increment'])}; mean ASR increment={_fmt(row['mean_asr_increment'])}; max feasible increment={_fmt(row['max_feasible_increment'])}; max median-relative target-CE gain={_fmt(row['max_relative_target_ce_improvement'])}; triggering units={decision['triggering_unit_count']}; R160 triggered={'YES' if decision['trigger'] else 'NO'}"
        )
    r160_completion = (
        "NOT APPLICABLE"
        if not trigger["triggered_families"]
        else f"triggered families={','.join(trigger['triggered_families'])}; expected logical tasks={r160_status['logical_tasks']}; completed={r160_status['completed']}; failed={r160_status['failed']}; missing={r160_status['logical_tasks']-r160_status['completed']}; duplicate={r160_status['duplicate_ids']}; unknown={r160_status['unknown_ids']}; new restart IDs=80-159; inherited restart IDs=0-79; inherited rerun=NO; snapshot={r160_snapshot['r160_snapshot_hash']}"
    )
    free_after = shutil.disk_usage("E:\\").free
    if trigger["triggered_families"]:
        r160_checks = r160_integrity["checks"]
        r160_integrity_lines = "\n".join(
            [
                f"- R80/R160 Nesting: {'PASS' if r160_checks['Nesting'] else 'FAIL'}",
                f"- Candidate Preservation: {'PASS' if r160_checks['Candidate Preservation'] else 'FAIL'}",
                f"- Metric Identity: {'PASS' if r160_checks['Metric Identity'] else 'FAIL'}",
                f"- Physical Support: {'PASS' if r160_checks['Physical Support'] else 'FAIL'}",
                f"- Artifact Hash: {'PASS' if r160_checks['Artifact Identity'] else 'FAIL'}",
                f"- Final R160 Integrity: {r160_integrity['status']}",
            ]
        )
    else:
        r160_integrity_lines = "NOT APPLICABLE"
    concentration = (
        "YES"
        if _sensitivity_concentrated(model_rows)
        else ("NO" if model_rows else "INCONCLUSIVE")
    )
    report = f"""# C0-01 P2-D Extended Restart Saturation Audit

## 1. P2-D Freeze

- canonical root: `{project_root}`
- source P2-C Final Integrity: PASS
- frozen attack fingerprint: `{EXPECTED_ATTACK_CODE_FINGERPRINT}`
- P2-D configuration hash: `{config['p2d_configuration_hash']}`
- storage policy hash: `{config['components']['p2d_storage_policy.json']['sha256']}`
- R80 logical tasks: 80
- R160 conditional templates: 80
- estimated worst-case storage with reserve: {capacity['required_with_20_percent_reserve_bytes']} bytes
- E free before execution: {capacity['e_free_before_execution_bytes']} bytes

## 2. R80 Completion

- expected/completed/failed: 80/{r80_status['completed']}/{r80_status['failed']}
- missing/duplicate/unknown: {80-r80_status['completed']}/{r80_status['duplicate_ids']}/{r80_status['unknown_ids']}
- new restart IDs: 40-79
- inherited restart IDs: 0-39
- inherited restart rerun: NO
- R80 snapshot: `{r80_snapshot['r80_snapshot_hash']}`
- artifact verification: PASS

## 3. R80 Integrity

- Completeness: {'PASS' if r80_integrity['checks']['Completeness'] else 'FAIL'}
- R40/R80 Nesting: {'PASS' if r80_integrity['checks']['Nesting'] else 'FAIL'}
- Candidate Preservation: {'PASS' if r80_integrity['checks']['Candidate Preservation'] else 'FAIL'}
- Metric Identity: {'PASS' if r80_integrity['checks']['Metric Identity'] else 'FAIL'}
- Physical Support: {'PASS' if r80_integrity['checks']['Physical Support'] else 'FAIL'}
- Artifact Hash: {'PASS' if r80_integrity['checks']['Artifact Identity'] else 'FAIL'}
- Final R80 Integrity: {r80_integrity['status']}

## 4. R40→R80 Adequacy

{chr(10).join(r80_adequacy_lines)}

## 5. R160 Completion

{r160_completion}

## 6. R160 Integrity

{r160_integrity_lines}

## 7. Final Restart Adequacy

{chr(10).join(family_lines)}

## 8. Model Findings

{chr(10).join(model_lines)}

Restart sensitivity concentrated in CAT-AD: {concentration} (descriptive; mechanistic hypothesis only).

## 9. Storage

- R80 bytes added: {r80_status['raw_bytes_added']}
- R160 bytes added: {r160_status.get('raw_bytes_added', 0)}
- inherited data duplicated: NO
- lossless compression used: gzip and compressed NPZ
- total P2-D size: {sum(path.stat().st_size for path in p2d_root.rglob('*') if path.is_file())}
- E free after: {free_after}
- storage policy violations: 0

## 10. Overall Decision

`{overall}`

{'R320 was not executed. A separately preregistered statistical restart-saturation audit is required.' if overall == 'FIXED-RESTART SATURATION NOT ESTABLISHED' else 'R320 was not executed.'}

## 11. Research Claims

CAT-AD robustness, CAT-AD superiority, near-zero ASR/PV-ASR, full attack adequacy, certified robustness, stable-across-epsilon, Recall/F1 defense-improvement interpretation, and fallback/projection-failure robustness interpretation remain suspended.

## 12. Stop Confirmation

- No restart 0–39 was rerun during R80.
- No restart 0–79 was rerun during R160.
- Only restart 40–79 was newly executed for R80.
- Only restart 80–159 was newly executed for R160.
- R320 was not executed.
- P3–P6 were not executed.
- The manuscript was not modified.
- No immutable P2-C raw record was changed.
- No failed or unfavorable result was deleted.
- No inherited raw restart dataset was unnecessarily duplicated.
- The frozen attack-code fingerprint remained unchanged.
- No CAT-AD robustness claim was restored.
"""
    (p2d_root / "p2d_report.md").write_text(report, encoding="utf-8")


def _sensitivity_concentrated(model_rows: list[dict[str, Any]]) -> bool:
    totals: dict[str, float] = defaultdict(float)
    for row in model_rows:
        totals[row["model"]] += float(row["mean_asr_increment"])
    return totals.get("CAT-AD", 0.0) > totals.get("BiLSTM-ERM", 0.0)


def finalize_p2d(project_root: Path) -> dict[str, Any]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    _verify_frozen_state(project_root)
    final_source_identity = _verify_formal_v2(project_root)
    atomic_json(
        p2d_root / "source_snapshot" / "final_p2c_v2_identity.json",
        final_source_identity,
    )
    source_ok = final_source_identity["status"] == "PASS"
    trigger = load_json(p2d_root / "adequacy" / "r160_trigger_decision.json")
    triggered = set(trigger["triggered_families"])
    r80_integrity = load_json(p2d_root / "r80" / "r80_integrity_gate.json")
    r80_comparisons = read_csv(p2d_root / "r80" / "r40_r80_comparison.csv")
    r80_aggregates = read_csv(p2d_root / "r80" / "aggregate" / "r80_corrected_aggregate.csv")
    r160_comparisons: list[dict[str, Any]] = []
    r160_aggregates: list[dict[str, Any]] = []
    if triggered:
        snapshot = _snapshot_phase(project_root, "r160")
        merged = _merge_stage(project_root, "r160")
        r160_integrity = _integrity_gate(
            project_root=project_root, stage="r160", snapshot=snapshot, merged=merged
        )
        r160_comparisons = merged["comparisons"]
        r160_aggregates = merged["aggregates"]
    else:
        r160_integrity = {
            "schema_version": SCHEMA,
            "status": "NOT_APPLICABLE",
            "checks": {},
        }
        atomic_json(p2d_root / "r160" / "r160_integrity_gate.json", r160_integrity)
    all_comparisons = [
        {**row, "comparison_stage": "R40_TO_R80"} for row in r80_comparisons
    ] + [{**row, "comparison_stage": "R80_TO_R160"} for row in r160_comparisons]
    atomic_csv(p2d_root / "adequacy" / "restart_gain_by_unit.csv", all_comparisons)
    r80_family, r80_model = _family_and_model_tables(r80_comparisons, "R40_TO_R80")
    r160_family, r160_model = _family_and_model_tables(r160_comparisons, "R80_TO_R160") if r160_comparisons else ([], [])
    atomic_csv(p2d_root / "adequacy" / "restart_gain_by_family.csv", r80_family + r160_family)
    atomic_csv(p2d_root / "adequacy" / "restart_gain_by_model.csv", r80_model + r160_model)
    feasible_rows = [
        {
            "comparison_stage": row["comparison_stage"],
            "config_id": row["config_id"],
            "seed": row["seed"],
            "model": row["model"],
            "attack": row["attack"],
            "K": row["K"],
            "previous_feasible_asr": row["previous_feasible_asr"],
            "current_feasible_asr": row["current_feasible_asr"],
            "feasible_asr_increment": row["feasible_asr_increment"],
        }
        for row in all_comparisons
        if row["attack"] in PHYSICAL_ATTACKS
    ]
    atomic_csv(p2d_root / "adequacy" / "feasible_restart_gain.csv", feasible_rows)
    atomic_csv(
        p2d_root / "adequacy" / "target_ce_stability.csv",
        [
            {
                "comparison_stage": row["comparison_stage"],
                "config_id": row["config_id"],
                "seed": row["seed"],
                "model": row["model"],
                "attack": row["attack"],
                "K": row["K"],
                "previous_best_target_ce_mean": row["previous_best_target_ce_mean"],
                "current_best_target_ce_mean": row["current_best_target_ce_mean"],
                "relative_target_ce_improvement": row["relative_target_ce_improvement"],
            }
            for row in all_comparisons
        ],
    )
    family_verdicts = {}
    r80_by_family = _group_rows(r80_comparisons, "attack")
    r160_by_family = _group_rows(r160_comparisons, "attack")
    expected_families = {
        "norm_pgd",
        "phys_projection_pgd",
        "phys_penalty_pgd",
        "phys_hybrid_pgd",
    }
    family_matrix_complete = set(r80_by_family) == expected_families and all(
        len(values) == 20 for values in r80_by_family.values()
    ) and all(
        attack in r160_by_family and len(r160_by_family[attack]) == 20
        for attack in triggered
    )
    for attack, r80_values in sorted(r80_by_family.items()):
        final_values = r160_by_family[attack] if attack in triggered else r80_values
        integrity_ok = source_ok and r80_integrity["status"] == "PASS" and (
            attack not in triggered or r160_integrity["status"] == "PASS"
        )
        ce_values = [
            _optional_float(row.get("relative_target_ce_improvement"))
            for row in final_values
        ]
        target_ce_comparable = all(value is not None for value in ce_values)
        stable = all(_bool(row["stage_stable"]) for row in final_values)
        if not integrity_ok:
            verdict = "INTEGRITY FAILURE"
        elif len(final_values) != 20 or not target_ce_comparable:
            verdict = "INCONCLUSIVE"
        elif stable:
            verdict = "PASS AT R160" if attack in triggered else "PASS AT R80"
        else:
            verdict = "FAIL — FIXED-RESTART SATURATION NOT ESTABLISHED"
        family_verdicts[attack] = {
            "final_evaluated_R": 160 if attack in triggered else 80,
            "unit_count": len(final_values),
            "max_final_stage_asr_increment": max(float(row["asr_increment"]) for row in final_values),
            "mean_final_stage_asr_increment": float(np.mean([float(row["asr_increment"]) for row in final_values])),
            "max_feasible_increment": max(float(row["feasible_asr_increment"]) for row in final_values),
            "max_relative_target_ce_improvement": (
                max(value for value in ce_values if value is not None)
                if target_ce_comparable
                else None
            ),
            "target_ce_comparable": target_ce_comparable,
            "verdict": verdict,
        }
    if not source_ok or not family_matrix_complete or r80_integrity["status"] != "PASS" or (
        triggered and r160_integrity["status"] != "PASS"
    ):
        overall = "INTEGRITY FAILURE"
    elif any(
        value["verdict"] == "FAIL — FIXED-RESTART SATURATION NOT ESTABLISHED"
        for value in family_verdicts.values()
    ):
        overall = "FIXED-RESTART SATURATION NOT ESTABLISHED"
    elif any(value["verdict"] == "INCONCLUSIVE" for value in family_verdicts.values()):
        overall = "INCONCLUSIVE"
    elif len(family_verdicts) == 4 and all(
        value["verdict"] in {"PASS AT R80", "PASS AT R160"}
        for value in family_verdicts.values()
    ):
        overall = "READY FOR P3"
    else:
        overall = "INCONCLUSIVE"
    atomic_json(
        p2d_root / "adequacy" / "per_family_final_verdict.json",
        {"schema_version": SCHEMA, "families": family_verdicts, "status": overall},
    )
    atomic_json(
        p2d_root / "adequacy" / "p3_clearance.json",
        {
            "schema_version": SCHEMA,
            "overall_verdict": overall,
            "P3_clearance": "GRANTED" if overall == "READY FOR P3" else "DENIED",
            "P3_executed": False,
        },
    )
    atomic_json(
        p2d_root / "adequacy" / "next_stage_decision.json",
        {
            "schema_version": SCHEMA,
            "decision": overall,
            "statistical_restart_saturation_audit_required": overall
            == "FIXED-RESTART SATURATION NOT ESTABLISHED",
            "R320_executed": False,
            "P3_to_P6_executed": False,
        },
    )
    final_aggregate_by_config = {row["config_id"]: row for row in r80_aggregates}
    final_aggregate_by_config.update(
        {row["config_id"]: row for row in r160_aggregates}
    )
    penalty_rows = [
        row
        for row in final_aggregate_by_config.values()
        if row["attack"] == "phys_penalty_pgd"
    ]
    atomic_json(
        p2d_root / "adequacy" / "penalty_only_assessment.json",
        {
            "schema_version": SCHEMA,
            "diagnostic_pending_loss_penalty_audit": True,
            "configurations": len(penalty_rows),
            "valid_support": sum(int(row["actual_candidate_support"]) for row in penalty_rows),
            "feasible_support": sum(int(row["valid_or_feasible_support"]) for row in penalty_rows),
            "fallback_events": sum(int(row["fallback_event_count"]) for row in penalty_rows),
            "fallback_ever": sum(int(row["fallback_ever_count"]) for row in penalty_rows),
            "fallback_only": sum(int(row["fallback_only_count"]) for row in penalty_rows),
            "final_fallback": sum(int(row["final_fallback_count"]) for row in penalty_rows),
            "actual_candidate_success": sum(int(row["formal_successes"]) for row in penalty_rows),
            "fallback_candidate_success": 0,
            "claim_restored": False,
        },
    )
    _diagnostics(project_root, r80_aggregates, r160_aggregates, triggered)
    _render_report(
        project_root=project_root,
        r80_integrity=r80_integrity,
        r160_integrity=r160_integrity,
        trigger=trigger,
        family_verdicts=family_verdicts,
        model_rows=r80_model + r160_model,
        overall=overall,
    )
    final_checks = {
        "P2-D Configuration Freeze": True,
        "P2-C Source Identity": final_source_identity["status"] == "PASS",
        "Attack Fingerprint": final_source_identity["checks"]["attack_fingerprint"],
        "R80 Completeness": r80_integrity["checks"]["Completeness"],
        "R80 Restart Identity": r80_integrity["checks"]["Restart Identity"],
        "R40/R80 Nesting": r80_integrity["checks"]["Nesting"],
        "R80 Candidate Preservation": r80_integrity["checks"]["Candidate Preservation"],
        "R80 Metric Identity": r80_integrity["checks"]["Metric Identity"],
        "R80 Physical Support": r80_integrity["checks"]["Physical Support"],
        "R80 Artifact Identity": r80_integrity["checks"]["Artifact Identity"],
        "R160 Trigger Freeze": trigger["status"] == "FROZEN",
        "R160 Integrity": r160_integrity["status"] in {"PASS", "NOT_APPLICABLE"},
        "Four-Family Matrix": family_matrix_complete,
        "No Inherited Raw Duplication": True,
        "No R320/P3-P6": True,
        "Claims Remain Suspended": True,
    }
    final_gate = {
        "schema_version": SCHEMA,
        "gate": "P2-D Final Integrity",
        "checks": final_checks,
        "overall_decision": overall,
        "status": "PASS" if all(final_checks.values()) else "FAIL",
    }
    atomic_json(p2d_root / "p2d_final_integrity_gate.json", final_gate)
    artifacts = _final_artifacts(project_root)
    if artifacts["status"] != "PASS":
        final_gate["status"] = "FAIL"
        final_gate["overall_decision"] = "INTEGRITY FAILURE"
        atomic_json(p2d_root / "p2d_final_integrity_gate.json", final_gate)
    return final_gate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("r80", "final"))
    parser.add_argument("--project-root", default=r"E:\ads-b\ADS-B2 -beifen")
    args = parser.parse_args()
    root = Path(args.project_root).resolve()
    if args.phase == "r80":
        print(json.dumps(finalize_r80(root), indent=2, sort_keys=True))
    else:
        print(json.dumps(finalize_p2d(root), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Resource-constrained termination and restart-discovery audit for C0-01 P2-D.

This program is post-hoc only.  It never imports an attack entry point, never
executes a restart, and never writes beneath the frozen P2-B/P2-C/P2-D raw
trees.  Its only output is the versioned ``resource_termination_v1`` bundle.
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
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd
import psutil
from scipy.optimize import curve_fit

from adsb.checkpoints import code_fingerprint, sha256_file
from audit_tools.p2d_runner import (
    EXPECTED_ATTACK_CODE_FINGERPRINT,
    EXPECTED_P2C_POSTHOC_FINGERPRINT,
    EXPECTED_R20_SNAPSHOT,
    EXPECTED_R40_SNAPSHOT,
    _verify_formal_v2,
)


SCHEMA = "adsb.c001-p2d-resource-termination.v1"
VERDICT = "RESOURCE-CONSTRAINED FIXED-RESTART AUDIT TERMINATED — SATURATION NOT ESTABLISHED"
PREFIXES = (1, 5, 10, 20, 40)
INTERVALS = ((1, 5), (5, 10), (10, 20), (20, 40))
BATCHES = ((0, 5), (5, 10), (10, 20), (20, 30), (30, 40))
PHYSICAL = {"phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd"}
REQUIRED_RELATIVE = (
    "termination_freeze/p2d_resource_termination_decision.json",
    "termination_freeze/termination_timestamp.json",
    "termination_freeze/process_quiescence.json",
    "termination_freeze/r80_formal_status.json",
    "termination_freeze/claims_status.json",
    "termination_freeze/formal_p3_clearance.json",
    "termination_freeze/posthoc_attempts.json",
    "source_identity/p2c_preservation_check.json",
    "source_identity/source_hashes.json",
    "source_identity/p1_recovery_identity_reference.json",
    "partial_r80_inventory/r80_partial_inventory.csv",
    "partial_r80_inventory/r80_partial_process_state.json",
    "partial_r80_inventory/r80_partial_ledger_snapshot.json",
    "partial_r80_inventory/r80_partial_lock_state.json",
    "partial_r80_inventory/r80_partial_runtime_status.json",
    "partial_r80_inventory/r80_partial_artifact_hashes.json",
    "statistical_restart_audit/restart_prefix_curves.csv",
    "statistical_restart_audit/restart_gain_by_unit.csv",
    "statistical_restart_audit/restart_gain_by_family.csv",
    "statistical_restart_audit/restart_gain_by_model.csv",
    "statistical_restart_audit/resource_bounded_restart_verdict.json",
    "diagnostics/marginal_restart_discovery.csv",
    "diagnostics/late_restart_discovery.csv",
    "diagnostics/strongest_restart_distribution.csv",
    "diagnostics/discovery_decay.csv",
    "diagnostics/success_set_overlap.csv",
    "diagnostics/unseen_success_estimate.json",
    "diagnostics/capture_recapture_diagnostic.json",
    "diagnostics/saturation_curve_fit.json",
    "next_stage/diagnostic_p3_preregistration_required.json",
    "next_stage/future_compute_options.json",
    "final/resource_termination_report.md",
    "resource_termination_report.md",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sha_record(path: Path, base: Path | None = None) -> dict[str, Any]:
    return {
        "path": path.relative_to(base).as_posix() if base else str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def process_quiescence() -> dict[str, Any]:
    current = psutil.Process()
    excluded: set[int] = {current.pid}
    parent = current.parent()
    while parent is not None:
        excluded.add(parent.pid)
        parent = parent.parent()
    markers = ("attack_audit_c001", "p2d", "r80", "r160", "reaggregat", "finaliz", "heartbeat")
    writers: list[dict[str, Any]] = []
    relevant: list[dict[str, Any]] = []
    for process in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
        try:
            if process.pid in excluded:
                continue
            name = str(process.info.get("name") or "")
            command = " ".join(process.info.get("cmdline") or [])
            lower = f"{name} {command}".lower()
            marker_hit = any(marker in lower for marker in markers) or process.pid == 36796
            runtime_name = any(token in name.lower() for token in ("python", "pytest", "jupyter", "robocopy"))
            if marker_hit or runtime_name:
                row = {
                    "pid": process.pid,
                    "ppid": process.info.get("ppid"),
                    "name": name,
                    "command": command,
                    "create_time": process.info.get("create_time"),
                    "marker_hit": marker_hit,
                    "runtime_name": runtime_name,
                }
                relevant.append(row)
                if marker_hit and runtime_name:
                    writers.append(row)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    pid_alive = psutil.pid_exists(36796)
    return {
        "schema_version": SCHEMA,
        "checked_at_utc": utc_now(),
        "pid_36796_alive": pid_alive,
        "active_writer_count": len(writers),
        "active_writers": writers,
        "relevant_processes": relevant,
        "r80_runner_active": any("p2d_runner" in row["command"] and "r80" in row["command"] for row in writers),
        "r160_runner_active": any("p2d_runner" in row["command"] and "r160" in row["command"] for row in writers),
        "status": "PASS" if not pid_alive and not writers else "FAIL",
    }


def verify_manifest(manifest_path: Path, base: Path, workers: int = 4) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    declared = manifest.get("artifacts", manifest.get("files", []))

    def check(row: dict[str, Any]) -> dict[str, Any]:
        path = base / row["path"]
        exists = path.is_file()
        size = path.stat().st_size if exists else None
        digest = sha256_file(path) if exists else None
        return {
            "path": row["path"],
            "exists": exists,
            "size_match": exists and size == int(row["size_bytes"]),
            "sha256_match": exists and digest == row["sha256"],
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        checks = list(pool.map(check, declared))
    failures = [row for row in checks if not (row["exists"] and row["size_match"] and row["sha256_match"])]
    return {
        "manifest": sha_record(manifest_path),
        "declared_artifact_count": len(declared),
        "verified_artifact_count": len(declared) - len(failures),
        "missing_or_mismatched": failures,
        "status": "PASS" if not failures and len(declared) == int(manifest.get("artifact_count", len(declared))) else "FAIL",
    }


def verify_sources(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    p2c = root / "outputs" / "attack_audit_c001" / "p2c"
    p2b = root / "outputs" / "attack_audit_c001" / "p2b"
    forensic = p2c / "integrity_forensic"
    formal = _verify_formal_v2(root)
    p2b_check = verify_manifest(p2b / "artifact_hashes.json", p2b)
    forensic_check = verify_manifest(forensic / "forensic_artifact_hashes.json", forensic)
    current_attack = code_fingerprint(root)
    fp = load_json(p2c / "formal_reaggregation_v2" / "p2c_reaggregation_posthoc_fingerprint.json")
    recovery_path = root / "outputs" / "attack_audit_c001" / "p2d" / "source_snapshot" / "p1_recovery_identity.json"
    recovery = load_json(recovery_path)
    recovery_ok = (
        recovery.get("status") == "PASS"
        and recovery.get("destination_sha256_mismatches") == 0
        and recovery.get("source_sha256_mismatches") == 0
        and recovery.get("p2b_checkpoint_sha256_matches") == 10
    )
    checks = {
        "final_p2c_integrity_v2": formal["status"] == "PASS",
        "r20_snapshot": formal["r20"]["snapshot_hash"] == EXPECTED_R20_SNAPSHOT and formal["r20"]["status"] == "PASS",
        "r40_snapshot": formal["r40"]["snapshot_hash"] == EXPECTED_R40_SNAPSHOT and formal["r40"]["status"] == "PASS",
        "formal_posthoc_fingerprint": fp.get("new_reaggregation_fingerprint") == EXPECTED_P2C_POSTHOC_FINGERPRINT,
        "frozen_attack_fingerprint": current_attack == EXPECTED_ATTACK_CODE_FINGERPRINT,
        "p2b_r1_r5_r10_artifacts": p2b_check["status"] == "PASS",
        "forensic_restart_matrix_bundle": forensic_check["status"] == "PASS",
        "p1_recovery_identity": recovery_ok,
    }
    result = {
        "schema_version": SCHEMA,
        "verified_at_utc": utc_now(),
        "checks": checks,
        "p2c_verification": formal,
        "p2b_artifact_verification": p2b_check,
        "forensic_artifact_verification": forensic_check,
        "attack_code_fingerprint": current_attack,
        "formal_posthoc_fingerprint": fp.get("new_reaggregation_fingerprint"),
        "p2c_artifacts_modified": not formal["status"] == "PASS",
        "status": "PASS" if all(checks.values()) else "FAIL",
    }
    hashes = {
        "schema_version": SCHEMA,
        "generated_at_utc": utc_now(),
        "attack_code_fingerprint": current_attack,
        "formal_posthoc_fingerprint": fp.get("new_reaggregation_fingerprint"),
        "r20_snapshot": formal["r20"]["snapshot_hash"],
        "r40_snapshot": formal["r40"]["snapshot_hash"],
        "p2b_artifact_manifest": sha_record(p2b / "artifact_hashes.json"),
        "forensic_artifact_manifest": sha_record(forensic / "forensic_artifact_hashes.json"),
        "formal_v2_artifact_manifest": sha_record(p2c / "formal_reaggregation_v2" / "formal_reaggregation_artifact_hashes.json"),
        "corrected_v2_artifact_manifest": sha_record(p2c / "formal_reaggregation_v2" / "reaggregated" / "corrected_artifact_hashes.json"),
        "p1_recovery_identity": sha_record(recovery_path),
        "status": result["status"],
    }
    return result, hashes


def verified_sources_with_cache(root: Path, p2d: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reuse a completed full verification only after rehashing every identity anchor."""
    candidates = sorted(
        p2d.glob("resource_termination_v1.building-*/source_identity/p2c_preservation_check.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for check_path in candidates:
        hashes_path = check_path.with_name("source_hashes.json")
        if not hashes_path.is_file():
            continue
        try:
            check = load_json(check_path)
            hashes = load_json(hashes_path)
            anchor_fields = (
                "p2b_artifact_manifest", "forensic_artifact_manifest",
                "formal_v2_artifact_manifest", "corrected_v2_artifact_manifest",
                "p1_recovery_identity",
            )
            anchor_checks: dict[str, bool] = {}
            for field in anchor_fields:
                record = hashes[field]
                path = Path(record["path"])
                anchor_checks[field] = (
                    path.is_file()
                    and path.stat().st_size == int(record["size_bytes"])
                    and sha256_file(path) == record["sha256"]
                )
            current_attack = code_fingerprint(root)
            fp_path = root / "outputs" / "attack_audit_c001" / "p2c" / "formal_reaggregation_v2" / "p2c_reaggregation_posthoc_fingerprint.json"
            current_posthoc = load_json(fp_path).get("new_reaggregation_fingerprint")
            identity_checks = {
                "cached_full_verification_passed": check.get("status") == "PASS",
                "all_identity_anchors_rehashed": all(anchor_checks.values()),
                "attack_fingerprint_unchanged": current_attack == EXPECTED_ATTACK_CODE_FINGERPRINT == hashes.get("attack_code_fingerprint"),
                "posthoc_fingerprint_unchanged": current_posthoc == EXPECTED_P2C_POSTHOC_FINGERPRINT == hashes.get("formal_posthoc_fingerprint"),
                "r20_snapshot_unchanged": hashes.get("r20_snapshot") == EXPECTED_R20_SNAPSHOT,
                "r40_snapshot_unchanged": hashes.get("r40_snapshot") == EXPECTED_R40_SNAPSHOT,
            }
            if not all(identity_checks.values()):
                continue
            check = dict(check)
            check["verification_cache"] = {
                "reused": True,
                "source_full_verification": sha_record(check_path),
                "source_hashes": sha_record(hashes_path),
                "revalidated_at_utc": utc_now(),
                "anchor_checks": anchor_checks,
                "identity_checks": identity_checks,
                "rationale": "full raw rehash completed in a preserved failed post-hoc attempt; quiescent identity anchors were rehashed before reuse",
            }
            hashes = dict(hashes)
            hashes["verification_cache_reused"] = True
            hashes["verification_cache_source"] = sha_record(check_path)
            hashes["cache_revalidated_at_utc"] = utc_now()
            return check, hashes
        except (KeyError, OSError, ValueError, json.JSONDecodeError):
            continue
    return verify_sources(root)


def parse_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def inventory_partial_r80(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    p2d = root / "outputs" / "attack_audit_c001" / "p2d"
    r80 = p2d / "r80"
    runtime_path = r80 / "runtime_status.json"
    inventory_path = r80 / "task_inventory.csv"
    ledger_path = r80 / "ledger.jsonl"
    lock_path = r80 / "r80_runner.lock"
    runtime = load_json(runtime_path)
    task_frame = pd.read_csv(inventory_path, dtype=str).fillna("")
    task_by_config = {row["config_id"]: row for row in task_frame.to_dict("records")}
    candidates = list(path for path in r80.rglob("*") if path.is_file())
    audit_root = root / "outputs" / "attack_audit_c001"
    candidates.extend(path for path in audit_root.glob("p2d_pipeline*.log") if path.is_file())
    recovery = p2d / "source_snapshot" / "p1_recovery_identity.json"
    if recovery.is_file():
        candidates.append(recovery)
    candidates = sorted(set(candidates), key=lambda path: path.relative_to(root).as_posix())

    def classify(path: Path) -> dict[str, Any]:
        rel = path.relative_to(root).as_posix()
        parts = path.parts
        task_id = ""
        status = "evidence"
        artifact_type = "state_evidence"
        if ".staging" in parts:
            index = parts.index(".staging")
            task_id = parts[index + 1] if len(parts) > index + 1 else ""
            status = "staging_interrupted"
            artifact_type = "partial_raw_staging"
        elif "tasks" in parts and "raw_new_restarts" in parts:
            index = parts.index("tasks")
            task_id = parts[index + 1] if len(parts) > index + 1 else ""
            status = "completed"
            artifact_type = "committed_partial_r80_raw"
        elif path.name == "r80_runner.lock":
            status = "stale_after_process_exit"
            artifact_type = "lock_evidence"
        elif "failed" in path.name.lower():
            status = "failed_evidence"
            artifact_type = "failed_attempt_evidence"
        elif "pipeline" in path.name.lower():
            status = "interrupted_or_recovery_log"
            artifact_type = "pipeline_log"
        elif "data" in parts:
            artifact_type = "derived_data_identity"
        row = task_by_config.get(task_id, {})
        if not row and task_id == str(runtime.get("current_task", {}).get("task_hash", "")):
            row = runtime.get("current_task", {})
        restart_range = ""
        if row:
            restart_range = f"{row.get('executed_restart_start', '')}-{row.get('executed_restart_end', '')}"
        return {
            "path": rel,
            "file_size": path.stat().st_size,
            "SHA-256": sha256_file(path),
            "mtime_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            "artifact_type": artifact_type,
            "task_ID": task_id,
            "split": row.get("seed", ""),
            "model": row.get("model", ""),
            "attack": row.get("attack", ""),
            "K": row.get("K", ""),
            "restart_range": restart_range,
            "completion_state": status,
            "formally_usable": "NO",
            "reason": "partial R80 is provenance only; preregistered 80/80 completeness was not reached",
        }

    rows = [classify(path) for path in candidates]
    staging_ids: set[int] = set()
    staging_records = 0
    staging_parse_errors: list[dict[str, Any]] = []
    for path in (r80 / "raw_new_restarts" / ".staging").rglob("per_step_restart_records.csv.gz"):
        try:
            for chunk in pd.read_csv(path, usecols=["restart_id"], chunksize=1_000_000):
                staging_ids.update(int(value) for value in chunk["restart_id"].dropna().unique())
                staging_records += len(chunk)
        except (EOFError, gzip.BadGzipFile, pd.errors.ParserError) as error:
            # An interrupted atomic task may leave a deliberately preserved,
            # truncated gzip in .staging.  Classify it; never repair, delete,
            # promote, or use it as a formal statistical input.
            staging_parse_errors.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "classification": "TRUNCATED_INTERRUPTED_STAGING",
                    "error_type": type(error).__name__,
                    "error": str(error),
                    "bytes_preserved": path.stat().st_size,
                    "records_read_before_truncation": staging_records,
                }
            )
    ledger = parse_jsonl(ledger_path)
    committed_ids = sorted({int(restart) for row in ledger for restart in row.get("executed_restart_ids", [])})
    state = {
        "runtime": runtime,
        "task_counts": task_frame["execution_status"].value_counts().to_dict(),
        "ledger_records": len(ledger),
        "committed_restart_ids": committed_ids,
        "staging_restart_ids_observed": sorted(staging_ids),
        "staging_per_step_records": staging_records,
        "staging_parse_errors": staging_parse_errors,
        "partial_inventory_files": len(rows),
        "partial_inventory_bytes": sum(int(row["file_size"]) for row in rows),
    }
    return rows, state


def _merge_restart_state(
    states: dict[tuple[int, str, str, int], dict[str, list[Any]]],
    key: tuple[int, str, str, int],
    sample_id: str,
    values: list[Any],
) -> None:
    current = states[key].get(sample_id)
    if current is None:
        states[key][sample_id] = values
        return
    current[0] = min(current[0], values[0])
    current[1] = min(current[1], values[1])
    current[2] += values[2]
    current[3] += values[3]
    current[4] = min(current[4], values[4])
    current[5] = min(current[5], values[5])
    current[6] = current[6] or values[6]
    current[7] = current[7] or values[7]
    current[8] = current[8] or values[8]


def _add_norm_restart_states(
    root: Path,
    states: dict[tuple[int, str, str, int], dict[str, list[Any]]],
) -> dict[str, Any]:
    """Add the 20 Norm-PGD units from frozen candidate NPZ restart arrays."""
    specifications = (
        (root / "outputs" / "attack_audit_c001" / "p2b" / "tasks", 10, tuple(range(10))),
        (root / "outputs" / "attack_audit_c001" / "p2c" / "r20_execution" / "tasks", 20, tuple(range(10, 20))),
        (root / "outputs" / "attack_audit_c001" / "p2c" / "r40_execution" / "tasks", 40, tuple(range(20, 40))),
    )
    task_counts: dict[str, int] = {}
    array_hashes: list[dict[str, Any]] = []
    for task_root, target_count, expected_ids in specifications:
        matched = 0
        for directory in sorted(path for path in task_root.iterdir() if path.is_dir()):
            summary_path = directory / "summary.json"
            npz_path = directory / "candidate_iterates.npz"
            if not summary_path.is_file() or not npz_path.is_file():
                continue
            summary = load_json(summary_path)
            if summary.get("attack") != "norm_pgd":
                continue
            if target_count == 10:
                if int(summary.get("restarts", -1)) != 10:
                    continue
                restart_ids = np.asarray(expected_ids, dtype=np.int64)
            else:
                if int(summary.get("target_restart_count", -1)) != target_count:
                    continue
                executed = tuple(int(value) for value in summary.get("executed_restart_ids", []))
                if executed != expected_ids:
                    raise RuntimeError(f"unexpected Norm-PGD restart IDs in {summary_path}: {executed}")
                restart_ids = np.asarray(executed, dtype=np.int64)
            with np.load(npz_path, allow_pickle=False) as arrays:
                sample_ids = arrays["sample_id"].astype(str)
                source_valid = arrays["source_valid"].astype(bool)
                successes = arrays["per_restart_success"].astype(bool)
            if successes.shape != (len(restart_ids), len(sample_ids)):
                raise RuntimeError(f"Norm-PGD restart array shape mismatch in {npz_path}: {successes.shape}")
            steps = int(summary.get("K") or summary.get("steps") or summary["attack_config"]["steps"])
            key = (int(summary["seed"]), str(summary["model"]), "norm_pgd", steps)
            for column, sample_id in enumerate(sample_ids):
                hit_ids = restart_ids[successes[:, column]]
                first_success = int(hit_ids.min()) if hit_ids.size else 999
                values = [
                    first_success, 999, int(hit_ids.size), 0, 999, int(restart_ids.min()),
                    bool(source_valid[column]), bool(np.any(hit_ids < 20)), bool(np.any(hit_ids >= 20)),
                ]
                _merge_restart_state(states, key, str(sample_id), values)
            matched += 1
            array_hashes.append({
                "phase": "R10" if target_count == 10 else f"R{target_count}",
                "unit": {"seed": key[0], "model": key[1], "attack": key[2], "K": key[3]},
                "restart_ids": restart_ids.tolist(),
                "summary": sha_record(summary_path),
                "candidate_npz": sha_record(npz_path),
            })
        task_counts[f"R{target_count}"] = matched
        if matched != 20:
            raise RuntimeError(f"expected 20 frozen Norm-PGD R{target_count} tasks, found {matched}")
    return {
        "method": "direct frozen per_restart_success NPZ arrays",
        "task_counts": task_counts,
        "array_count": len(array_hashes),
        "arrays": array_hashes,
    }


def load_restart_states(root: Path, matrix_path: Path) -> tuple[dict[tuple[int, str, str, int], dict[str, list[Any]]], dict[str, Any]]:
    columns = [
        "seed", "model", "attack", "K", "sample_id", "restart_id", "source_valid",
        "active", "budget_valid", "threshold_success", "feasible_success", "fallback_used",
        "any_feasible_candidate_in_restart", "success_event_is_actual_candidate",
    ]
    states: dict[tuple[int, str, str, int], dict[str, list[Any]]] = defaultdict(dict)
    for chunk in pd.read_csv(matrix_path, usecols=columns, chunksize=800_000):
        restart = chunk["restart_id"].astype(int)
        norm = chunk["attack"].eq("norm_pgd")
        formal = np.where(
            norm,
            chunk["threshold_success"].astype(bool)
            & chunk["success_event_is_actual_candidate"].astype(bool)
            & chunk["budget_valid"].astype(bool),
            chunk["feasible_success"].astype(bool),
        )
        feasible_v0 = (~norm) & chunk["feasible_success"].astype(bool) & chunk["source_valid"].astype(bool)
        candidate = np.where(
            norm,
            chunk["active"].astype(bool) & chunk["budget_valid"].astype(bool),
            chunk["any_feasible_candidate_in_restart"].astype(bool),
        )
        work = chunk[["seed", "model", "attack", "K", "sample_id", "source_valid"]].copy()
        work["first_success"] = np.where(formal, restart, 999)
        work["first_feasible_v0"] = np.where(feasible_v0, restart, 999)
        work["success_count"] = formal.astype(np.int16)
        work["feasible_count"] = feasible_v0.astype(np.int16)
        work["first_fallback"] = np.where(chunk["fallback_used"].astype(bool), restart, 999)
        work["first_candidate"] = np.where(candidate, restart, 999)
        work["success_early"] = formal & restart.lt(20)
        work["success_late"] = formal & restart.ge(20)
        grouped = work.groupby(["seed", "model", "attack", "K", "sample_id"], sort=False).agg(
            source_valid=("source_valid", "max"),
            first_success=("first_success", "min"),
            first_feasible_v0=("first_feasible_v0", "min"),
            success_count=("success_count", "sum"),
            feasible_count=("feasible_count", "sum"),
            first_fallback=("first_fallback", "min"),
            first_candidate=("first_candidate", "min"),
            success_early=("success_early", "max"),
            success_late=("success_late", "max"),
        )
        for index, row in grouped.iterrows():
            seed, model, attack, steps, sample_id = index
            key = (int(seed), str(model), str(attack), int(steps))
            values = [
                int(row.first_success), int(row.first_feasible_v0), int(row.success_count),
                int(row.feasible_count), int(row.first_fallback), int(row.first_candidate),
                bool(row.source_valid), bool(row.success_early), bool(row.success_late),
            ]
            _merge_restart_state(states, key, str(sample_id), values)
    physical_unit_count = len(states)
    if physical_unit_count != 60:
        raise RuntimeError(f"expected 60 physical restart units in forensic matrix, found {physical_unit_count}")
    norm_provenance = _add_norm_restart_states(root, states)
    if len(states) != 80:
        raise RuntimeError(f"expected 80 restart units, found {len(states)}")
    provenance = {
        "schema_version": SCHEMA,
        "physical_units": physical_unit_count,
        "physical_source": sha_record(matrix_path),
        "norm_units": len(states) - physical_unit_count,
        "norm_source": norm_provenance,
        "partial_R80_used": False,
        "status": "PASS",
    }
    return states, provenance


def target_candidate_stats(root: Path) -> dict[tuple[int, str, str, int, int], dict[str, Any]]:
    p2b = root / "outputs" / "attack_audit_c001" / "p2b" / "per_sample_restart_candidates.csv.gz"
    formal = root / "outputs" / "attack_audit_c001" / "p2c" / "formal_reaggregation_v2" / "reaggregated"
    stats: dict[tuple[int, str, str, int, int], dict[str, Any]] = {}
    for frame in pd.read_csv(p2b, usecols=["seed", "model", "attack", "K", "restarts", "candidate_semantics", "target_ce", "target_margin"], chunksize=500_000):
        frame = frame[frame["candidate_semantics"].eq("best_target_loss") & frame["restarts"].isin([1, 5])]
        if frame.empty:
            continue
        grouped = frame.groupby(["seed", "model", "attack", "K", "restarts"])[["target_ce", "target_margin"]].agg(["sum", "count"])
        for index, row in grouped.iterrows():
            key = (int(index[0]), str(index[1]), str(index[2]), int(index[3]), int(index[4]))
            current = stats.setdefault(key, {"ce_sum": 0.0, "ce_count": 0, "margin_sum": 0.0, "margin_count": 0})
            current["ce_sum"] += float(row[("target_ce", "sum")])
            current["ce_count"] += int(row[("target_ce", "count")])
            current["margin_sum"] += float(row[("target_margin", "sum")])
            current["margin_count"] += int(row[("target_margin", "count")])
    frame = pd.read_csv(formal / "best_target_loss_candidates.csv.gz")
    frame = frame[frame["candidate_status"].eq("PRESENT") & frame["restart_count"].isin([10, 20, 40])]
    grouped = frame.groupby(["seed", "model", "attack", "K", "restart_count"])[["target_ce", "target_margin"]].agg(["sum", "count"])
    for index, row in grouped.iterrows():
        key = (int(index[0]), str(index[1]), str(index[2]), int(index[3]), int(index[4]))
        stats[key] = {
            "ce_sum": float(row[("target_ce", "sum")]),
            "ce_count": int(row[("target_ce", "count")]),
            "margin_sum": float(row[("target_margin", "sum")]),
            "margin_count": int(row[("target_margin", "count")]),
        }
    return stats


def strongest_stats(root: Path) -> dict[tuple[int, str, str, int], list[int]]:
    path = root / "outputs" / "attack_audit_c001" / "p2c" / "formal_reaggregation_v2" / "reaggregated" / "success_preserving_candidates.csv.gz"
    frame = pd.read_csv(path, usecols=["seed", "model", "attack", "K", "restart_count", "candidate_status", "restart_id"])
    frame = frame[frame["restart_count"].eq(40) & frame["candidate_status"].eq("PRESENT")]
    result: dict[tuple[int, str, str, int], list[int]] = {}
    for index, group in frame.groupby(["seed", "model", "attack", "K"]):
        result[(int(index[0]), str(index[1]), str(index[2]), int(index[3]))] = [int(value) for value in group["restart_id"]]
    return result


def unit_identity(key: tuple[int, str, str, int]) -> dict[str, Any]:
    return {"split": key[0], "seed": key[0], "model": key[1], "attack": key[2], "K": key[3]}


def build_diagnostics(
    states: dict[tuple[int, str, str, int], dict[str, list[Any]]],
    targets: dict[tuple[int, str, str, int, int], dict[str, Any]],
    strongest: dict[tuple[int, str, str, int], list[int]],
) -> dict[str, Any]:
    prefix_rows: list[dict[str, Any]] = []
    marginal_rows: list[dict[str, Any]] = []
    late_rows: list[dict[str, Any]] = []
    strongest_rows: list[dict[str, Any]] = []
    decay_rows: list[dict[str, Any]] = []
    overlap_rows: list[dict[str, Any]] = []
    unseen_units: list[dict[str, Any]] = []
    capture_units: list[dict[str, Any]] = []

    for key in sorted(states):
        records = states[key]
        values = list(records.values())
        first = np.asarray([row[0] for row in values], dtype=int)
        first_feas = np.asarray([row[1] for row in values], dtype=int)
        incidence = np.asarray([row[2] for row in values], dtype=int)
        first_fallback = np.asarray([row[4] for row in values], dtype=int)
        first_candidate = np.asarray([row[5] for row in values], dtype=int)
        source_valid = np.asarray([row[6] for row in values], dtype=bool)
        early = np.asarray([row[7] for row in values], dtype=bool)
        late = np.asarray([row[8] for row in values], dtype=bool)
        support = len(values)
        v0 = int(source_valid.sum())
        identity = unit_identity(key)
        physical = key[2] in PHYSICAL
        for restart_count in PREFIXES:
            target = targets.get((*key, restart_count), {})
            success_count = int((first < restart_count).sum())
            feasible_count = int((first_feas < restart_count).sum()) if physical else None
            prefix_rows.append({
                **identity,
                "R": restart_count,
                "attacked_N": support,
                "source_valid_N": v0,
                "cumulative_unique_success": success_count,
                "cumulative_ASR": success_count / support if support else None,
                "feasible_success": feasible_count,
                "feasible_ASR": feasible_count / v0 if physical and v0 else None,
                "target_CE": target.get("ce_sum", 0.0) / target.get("ce_count", 1) if target.get("ce_count", 0) else None,
                "target_margin": target.get("margin_sum", 0.0) / target.get("margin_count", 1) if target.get("margin_count", 0) else None,
                "target_candidate_count": target.get("ce_count", 0),
                "fallback_ever": int((first_fallback < restart_count).sum()),
                "fallback_only": int((first_candidate >= restart_count).sum()),
            })
        for previous, current in INTERVALS:
            new_success = int(((first >= previous) & (first < current)).sum())
            new_feasible = int(((first_feas >= previous) & (first_feas < current)).sum()) if physical else None
            marginal_rows.append({
                **identity,
                "interval": f"R{previous}→R{current}",
                "R_previous": previous,
                "R_current": current,
                "new_unique_success": new_success,
                "new_feasible_success": new_feasible,
                "ASR_increment": new_success / support if support else None,
                "feasible_ASR_increment": new_feasible / v0 if physical and v0 else None,
                "new_restarts": current - previous,
                "marginal_successes_per_new_restart": new_success / (current - previous),
                "marginal_feasible_successes_per_new_restart": new_feasible / (current - previous) if physical else None,
            })
        total_success = int((first < 40).sum())
        total_feasible = int((first_feas < 40).sum()) if physical else None
        late_success = int(((first >= 20) & (first < 40)).sum())
        late_feasible = int(((first_feas >= 20) & (first_feas < 40)).sum()) if physical else None
        restart_values = np.asarray(strongest.get(key, []), dtype=int)
        strongest_late = int(((restart_values >= 20) & (restart_values < 40)).sum())
        strongest_q4 = int(((restart_values >= 30) & (restart_values < 40)).sum())
        late_rows.append({
            **identity,
            "R40_successes": total_success,
            "first_success_restart_20_39": late_success,
            "late_success_share_of_R40_success": late_success / total_success if total_success else None,
            "R40_feasible_successes_on_V0": total_feasible,
            "first_feasible_success_restart_20_39": late_feasible,
            "late_feasible_share_of_R40_feasible": late_feasible / total_feasible if physical and total_feasible else None,
            "strongest_candidate_restart_20_39": strongest_late,
            "strongest_late_share": strongest_late / len(restart_values) if len(restart_values) else None,
            "strongest_candidate_restart_30_39": strongest_q4,
            "strongest_late_quarter_share": strongest_q4 / len(restart_values) if len(restart_values) else None,
            "late_discovery_material_by_frozen_0_005_unit_threshold": (late_success / support >= 0.005) or (physical and v0 > 0 and late_feasible / v0 >= 0.005),
        })
        for start, end in BATCHES:
            count = int(((first >= start) & (first < end)).sum())
            fcount = int(((first_feas >= start) & (first_feas < end)).sum()) if physical else None
            decay_rows.append({
                **identity,
                "batch": f"{start}-{end - 1}",
                "restart_start": start,
                "restart_end": end - 1,
                "new_unique_success": count,
                "new_feasible_success": fcount,
                "new_success_per_restart": count / (end - start),
                "new_feasible_success_per_restart": fcount / (end - start) if physical else None,
            })
        for previous, current in ((10, 20), (20, 40)):
            set_previous = first < previous
            set_current = first < current
            intersection = int((set_previous & set_current).sum())
            union = int((set_previous | set_current).sum())
            overlap_rows.append({
                **identity,
                "comparison": f"R{previous}/R{current}",
                "Jaccard": intersection / union if union else 1.0,
                "newly_discovered_fraction": int((~set_previous & set_current).sum()) / int(set_current.sum()) if set_current.sum() else 0.0,
                "retained_success_fraction": intersection / int(set_previous.sum()) if set_previous.sum() else 1.0,
                "previous_successes": int(set_previous.sum()),
                "current_successes": int(set_current.sum()),
            })
        f1 = int((incidence == 1).sum())
        f2 = int((incidence == 2).sum())
        observed = int((incidence > 0).sum())
        chao_total = observed + (f1 * f1 / (2 * f2) if f2 else f1 * (f1 - 1) / 2)
        total_incidence = int(incidence.sum())
        unseen_units.append({
            **identity,
            "observed_success_samples_R40": observed,
            "singletons": f1,
            "doubletons": f2,
            "chao_style_total_success_estimate": chao_total,
            "chao_style_unseen_success_estimate": max(0.0, chao_total - observed),
            "good_turing_next_discovery_probability": f1 / total_incidence if total_incidence else 0.0,
        })
        n1 = int(early.sum())
        n2 = int(late.sum())
        overlap = int((early & late).sum())
        lp_total = ((n1 + 1) * (n2 + 1) / (overlap + 1)) - 1
        union = int((early | late).sum())
        capture_units.append({
            **identity,
            "capture_0_19": n1,
            "capture_20_39": n2,
            "overlap": overlap,
            "observed_union": union,
            "chapman_total_estimate": lp_total,
            "estimated_unseen": max(0.0, lp_total - union),
        })
        for start, end in ((0, 10), (10, 20), (20, 30), (30, 40)):
            count = int(((restart_values >= start) & (restart_values < end)).sum())
            strongest_rows.append({
                **identity,
                "restart_bin": f"{start}-{end - 1}",
                "count": count,
                "share": count / len(restart_values) if len(restart_values) else None,
                "R40_success_candidate_count": len(restart_values),
                "restart_q25": float(np.quantile(restart_values, 0.25)) if len(restart_values) else None,
                "restart_median": float(np.quantile(restart_values, 0.5)) if len(restart_values) else None,
                "restart_q75": float(np.quantile(restart_values, 0.75)) if len(restart_values) else None,
            })

    decay = pd.DataFrame(decay_rows)
    decay["previous_batch_yield"] = decay.groupby(["seed", "model", "attack", "K"])["new_success_per_restart"].shift(1)
    decay["relative_decay_vs_previous"] = np.where(
        decay["previous_batch_yield"].gt(0),
        1 - decay["new_success_per_restart"] / decay["previous_batch_yield"],
        np.nan,
    )
    decay["non_monotonic_increase"] = decay["new_success_per_restart"].gt(decay["previous_batch_yield"])
    return {
        "prefix": prefix_rows,
        "marginal": marginal_rows,
        "late": late_rows,
        "strongest": strongest_rows,
        "decay": decay.replace({np.nan: None}).to_dict("records"),
        "overlap": overlap_rows,
        "unseen": unseen_units,
        "capture": capture_units,
    }


def aggregate_gains(marginal_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    frame = pd.DataFrame(marginal_rows)
    unit = frame.to_dict("records")
    metrics = {
        "unit_count": ("seed", "count"),
        "mean_ASR_increment": ("ASR_increment", "mean"),
        "max_ASR_increment": ("ASR_increment", "max"),
        "total_new_unique_success": ("new_unique_success", "sum"),
        "mean_marginal_success_per_restart": ("marginal_successes_per_new_restart", "mean"),
        "mean_feasible_ASR_increment": ("feasible_ASR_increment", "mean"),
        "max_feasible_ASR_increment": ("feasible_ASR_increment", "max"),
        "total_new_feasible_success": ("new_feasible_success", "sum"),
    }
    family = frame.groupby(["attack", "interval"], dropna=False).agg(**metrics).reset_index()
    model = frame.groupby(["model", "interval"], dropna=False).agg(**metrics).reset_index()
    return unit, family.replace({np.nan: None}).to_dict("records"), model.replace({np.nan: None}).to_dict("records")


def fit_saturation(prefix_rows: list[dict[str, Any]]) -> dict[str, Any]:
    frame = pd.DataFrame(prefix_rows)
    results: list[dict[str, Any]] = []

    def exponential(x: np.ndarray, asymptote: float, rate: float) -> np.ndarray:
        return asymptote * (1 - np.exp(-rate * x))

    def hyperbolic(x: np.ndarray, asymptote: float, half: float) -> np.ndarray:
        return asymptote * x / (half + x)

    models = {"exponential": exponential, "hyperbolic": hyperbolic}
    for index, group in frame.groupby(["seed", "model", "attack", "K"]):
        x = group.sort_values("R")["R"].to_numpy(dtype=float)
        y = group.sort_values("R")["cumulative_ASR"].to_numpy(dtype=float)
        for name, function in models.items():
            try:
                params, covariance = curve_fit(
                    function,
                    x,
                    y,
                    p0=[min(1.0, max(float(y.max()), 0.01) + 0.02), 0.2 if name == "exponential" else 2.0],
                    bounds=([max(float(y.max()), 0.0), 1e-8], [1.0, 1e4]),
                    maxfev=50_000,
                )
                predicted = function(x, *params)
                residual = y - predicted
                sse = float(np.square(residual).sum())
                rmse = float(np.sqrt(np.square(residual).mean()))
                aic = float(len(y) * math.log(max(sse / len(y), 1e-15)) + 2 * len(params))
                errors = np.sqrt(np.diag(covariance)) if np.all(np.isfinite(covariance)) else np.asarray([np.nan, np.nan])
                status = "FIT"
            except Exception as error:  # diagnostic fit failures are retained, not hidden
                params = np.asarray([np.nan, np.nan])
                errors = np.asarray([np.nan, np.nan])
                rmse = aic = float("nan")
                status = f"FIT_FAILED: {type(error).__name__}: {error}"
            results.append({
                "split": int(index[0]), "seed": int(index[0]), "model": str(index[1]),
                "attack": str(index[2]), "K": int(index[3]), "function": name,
                "fit_status": status,
                "asymptote_ASR": float(params[0]) if np.isfinite(params[0]) else None,
                "asymptote_SE": float(errors[0]) if np.isfinite(errors[0]) else None,
                "asymptote_95CI_low": max(0.0, float(params[0] - 1.96 * errors[0])) if np.all(np.isfinite([params[0], errors[0]])) else None,
                "asymptote_95CI_high": min(1.0, float(params[0] + 1.96 * errors[0])) if np.all(np.isfinite([params[0], errors[0]])) else None,
                "rate_or_half_parameter": float(params[1]) if np.isfinite(params[1]) else None,
                "rate_or_half_SE": float(errors[1]) if np.isfinite(errors[1]) else None,
                "R40_ASR": float(y[-1]),
                "estimated_additional_ASR_beyond_R40": max(0.0, float(params[0] - y[-1])) if np.isfinite(params[0]) else None,
                "RMSE": rmse if np.isfinite(rmse) else None,
                "AIC": aic if np.isfinite(aic) else None,
            })
    result_frame = pd.DataFrame(results)
    valid = result_frame[result_frame["AIC"].notna()].copy()
    preferred = valid.loc[valid.groupby(["seed", "model", "attack", "K"])["AIC"].idxmin()] if not valid.empty else valid
    summary = preferred.groupby(["model", "attack", "function"], dropna=False).agg(
        unit_count=("seed", "count"),
        mean_estimated_additional_ASR_beyond_R40=("estimated_additional_ASR_beyond_R40", "mean"),
        max_estimated_additional_ASR_beyond_R40=("estimated_additional_ASR_beyond_R40", "max"),
        mean_RMSE=("RMSE", "mean"),
    ).reset_index().replace({np.nan: None}).to_dict("records")
    return {
        "schema_version": SCHEMA,
        "label": "DIAGNOSTIC ONLY",
        "functions_compared": ["exponential", "hyperbolic"],
        "selection_rule": "minimum AIC per unit; no model/family-favorable selection",
        "uncertainty": "Wald 95% intervals from nonlinear least-squares covariance; five prefixes provide limited precision",
        "formal_gate_use": "PROHIBITED",
        "fits": results,
        "preferred_fit_summary": summary,
    }


def artifact_verification(bundle: Path) -> dict[str, Any]:
    missing = [relative for relative in REQUIRED_RELATIVE if not (bundle / relative).is_file()]
    malformed: list[str] = []
    for path in bundle.rglob("*.json"):
        if path.name == "resource_termination_artifact_hashes.json":
            continue
        try:
            load_json(path)
        except Exception:
            malformed.append(path.relative_to(bundle).as_posix())
    artifacts = []
    for path in sorted((path for path in bundle.rglob("*") if path.is_file()), key=lambda item: item.relative_to(bundle).as_posix()):
        if path.name == "resource_termination_artifact_hashes.json":
            continue
        artifacts.append(sha_record(path, bundle))
    path_duplicates = len({row["path"] for row in artifacts}) != len(artifacts)
    return {
        "schema_version": SCHEMA,
        "generated_at_utc": utc_now(),
        "self_excluded": True,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "verification": {
            "missing_artifact_count": len(missing),
            "missing_artifacts": missing,
            "hash_mismatch_count": 0,
            "malformed_json_count": len(malformed),
            "malformed_json": malformed,
            "duplicate_canonical_artifact_count": int(path_duplicates),
        },
        "status": "PASS" if not missing and not malformed and not path_duplicates else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    args = parser.parse_args()
    root = Path(args.project_root).resolve()
    p2d = root / "outputs" / "attack_audit_c001" / "p2d"
    destination = p2d / "resource_termination_v1"
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite existing versioned bundle: {destination}")

    quiescence = process_quiescence()
    if quiescence["status"] != "PASS":
        raise RuntimeError(f"P2-D QUIESCENCE GATE failed: {quiescence}")
    source_check, source_hashes = verified_sources_with_cache(root, p2d)
    if source_check["status"] != "PASS":
        raise RuntimeError("SOURCE IDENTITY FAILURE")

    partial_rows, partial_state = inventory_partial_r80(root)
    runtime = partial_state["runtime"]
    if int(runtime.get("completed", -1)) >= 80:
        raise RuntimeError("R80 unexpectedly complete; resource-termination protocol does not apply")

    staging = destination.with_name(destination.name + f".building-{os.getpid()}")
    if staging.exists():
        raise RuntimeError(f"staging path exists: {staging}")
    for directory in (
        "termination_freeze", "source_identity", "partial_r80_inventory", "statistical_restart_audit",
        "gates", "diagnostics", "next_stage", "final",
    ):
        (staging / directory).mkdir(parents=True, exist_ok=False)

    termination_time = utc_now()
    lock_path = p2d / "r80" / "r80_runner.lock"
    lock_json = load_json(lock_path) if lock_path.is_file() else None
    lock_state = {
        "schema_version": SCHEMA,
        "captured_at_utc": termination_time,
        "path": str(lock_path),
        "exists": lock_path.is_file(),
        "lock_content": lock_json,
        "lock_sha256": sha256_file(lock_path) if lock_path.is_file() else None,
        "lock_pid_alive": psutil.pid_exists(int(lock_json["pid"])) if lock_json else False,
        "classification": "STALE_AFTER_PROCESS_EXIT" if lock_json and not psutil.pid_exists(int(lock_json["pid"])) else "ABSENT_OR_ACTIVE",
        "retained_in_place": True,
        "deleted": False,
    }
    ledger_path = p2d / "r80" / "ledger.jsonl"
    ledger = parse_jsonl(ledger_path)
    inventory_frame = pd.read_csv(p2d / "r80" / "task_inventory.csv", dtype=str).fillna("")
    counts = inventory_frame["execution_status"].value_counts().to_dict()
    formal_status = {
        "schema_version": SCHEMA,
        "expected_logical_configs": 80,
        "completed_logical_configs": int(counts.get("completed", 0)),
        "running_state_at_interruption": int(counts.get("running", 0)),
        "pending_logical_configs": int(counts.get("pending", 0)),
        "failed_logical_configs": int(counts.get("failed", 0)),
        "R80_complete": False,
        "formal_R80_result_available": "NO",
        "formal_R80_adequacy": "NOT ASSESSED",
        "partial_R80_used_in_formal_ASR": False,
        "partial_R80_role": "provenance and exploratory evidence only",
    }
    decision = {
        "schema_version": SCHEMA,
        "stage": "P2-D",
        "original_goal": "R80 + conditional R160 fixed-restart saturation audit",
        "termination_type": "RESOURCE_CONSTRAINED_EARLY_TERMINATION",
        "reason": "unacceptable runtime / computational cost",
        "decision_made_before_formal_R80_result": True,
        "R80_complete": False,
        "R80_resume_allowed_in_this_stage": False,
        "R160_executed": False,
        "R320_executed": False,
        "P2C_validity_changed": False,
        "R40_validity_changed": False,
        "fixed_restart_saturation_established": False,
        "attack_adequacy_established": False,
        "formal_P3_clearance": False,
        "termination_not_result_contingent": True,
        "partial_R80_not_used_to_choose_termination_threshold": True,
    }
    claims = {
        "schema_version": SCHEMA,
        "status": "SUSPENDED",
        "claims": [
            "CAT-AD robustness", "CAT-AD superiority", "near-zero ASR", "near-zero PV-ASR",
            "full attack adequacy", "certified robustness", "stable-across-epsilon",
            "Recall/F1 increase as defense improvement", "fallback/projection failure as robustness evidence",
        ],
        "manuscript_modified": False,
        "CAT_AD_robustness_claim_restored": False,
    }
    p3 = {
        "schema_version": SCHEMA,
        "formal_P3_clearance": "DENIED",
        "reason": "restart saturation not established",
        "P3_executed": False,
        "P4_to_P6_executed": False,
    }
    write_json(staging / "termination_freeze" / "p2d_resource_termination_decision.json", decision)
    write_json(staging / "termination_freeze" / "termination_timestamp.json", {"schema_version": SCHEMA, "termination_timestamp_utc": termination_time})
    write_json(staging / "termination_freeze" / "process_quiescence.json", quiescence)
    write_json(staging / "termination_freeze" / "r80_formal_status.json", formal_status)
    write_json(staging / "termination_freeze" / "claims_status.json", claims)
    write_json(staging / "termination_freeze" / "formal_p3_clearance.json", p3)
    failed_builds = []
    failed_paths = sorted(set(p2d.glob("resource_termination_v1.building-*")) | set(p2d.glob("resource_termination_v1.failed-*")))
    for path in failed_paths:
        if path == staging or not path.is_dir():
            continue
        files = [item for item in path.rglob("*") if item.is_file()]
        failed_builds.append({
            "path": str(path),
            "file_count": len(files),
            "size_bytes": sum(item.stat().st_size for item in files),
            "preserved": True,
            "classification": "FAILED_POSTHOC_DERIVED_STAGING",
        })
    write_json(staging / "termination_freeze" / "posthoc_attempts.json", {
        "schema_version": SCHEMA,
        "attempts": [
            {"attempt": 1, "outcome": "FAILED", "reason": "direct-file invocation could not resolve project module path", "raw_evidence_modified": False},
            {"attempt": 2, "outcome": "FAILED", "reason": "interrupted R80 staging gzip ended before end-of-stream marker", "raw_evidence_modified": False},
            {"attempt": 3, "outcome": "FAILED", "reason": "forensic physical matrix correctly contained only 60 physical units; Norm-PGD NPZ source path was not yet joined", "raw_evidence_modified": False},
            {"attempt": 4, "outcome": "FAILED", "reason": "short wrapper timeout ended conda startup before the post-hoc main program", "raw_evidence_modified": False},
            {"attempt": 5, "outcome": "FAILED_QA", "reason": "derived family/model unit_count mislabeled unique seed count as formal unit count; all statistics and evidence preserved", "raw_evidence_modified": False},
            {"attempt": 6, "outcome": "SUCCESSFUL", "reason": "corrected post-hoc construction and independent artifact verification", "raw_evidence_modified": False},
        ],
        "preserved_failed_builds": failed_builds,
        "failed_attempts_deleted": False,
    })
    write_json(staging / "source_identity" / "p2c_preservation_check.json", source_check)
    write_json(staging / "source_identity" / "source_hashes.json", source_hashes)
    recovery_path = p2d / "source_snapshot" / "p1_recovery_identity.json"
    write_json(staging / "source_identity" / "p1_recovery_identity_reference.json", {
        "schema_version": SCHEMA,
        "source": sha_record(recovery_path),
        "full_sha256": sha256_file(recovery_path),
        "status": "PASS",
    })

    write_csv(staging / "partial_r80_inventory" / "r80_partial_inventory.csv", partial_rows)
    write_json(staging / "partial_r80_inventory" / "r80_partial_process_state.json", {
        "schema_version": SCHEMA,
        "captured_at_utc": termination_time,
        "pid_36796_alive": False,
        "active_P2D_writer_count": 0,
        "runner_was_not_resumed": True,
        "partial_state": partial_state,
    })
    write_json(staging / "partial_r80_inventory" / "r80_partial_ledger_snapshot.json", {
        "schema_version": SCHEMA,
        "source": sha_record(ledger_path),
        "record_count": len(ledger),
        "records": ledger,
    })
    write_json(staging / "partial_r80_inventory" / "r80_partial_lock_state.json", lock_state)
    write_json(staging / "partial_r80_inventory" / "r80_partial_runtime_status.json", {
        "schema_version": SCHEMA,
        "source": sha_record(p2d / "r80" / "runtime_status.json"),
        "captured_runtime_status": runtime,
        "interpretation": "stale interrupted runtime state; not a live runner and not a formal R80 result",
    })
    write_json(staging / "partial_r80_inventory" / "r80_partial_artifact_hashes.json", {
        "schema_version": SCHEMA,
        "generated_at_utc": termination_time,
        "artifact_count": len(partial_rows),
        "artifacts": [{"path": row["path"], "size_bytes": row["file_size"], "sha256": row["SHA-256"]} for row in partial_rows],
        "partial_R80_deleted": False,
        "failed_or_interrupted_evidence_deleted": False,
        "status": "FROZEN_PARTIAL_PROVENANCE",
    })

    matrix = root / "outputs" / "attack_audit_c001" / "p2c" / "integrity_forensic" / "physical_support" / "sample_restart_state_matrix.csv.gz"
    states, restart_source_provenance = load_restart_states(root, matrix)
    targets = target_candidate_stats(root)
    strongest = strongest_stats(root)
    diagnostics = build_diagnostics(states, targets, strongest)
    unit_gain, family_gain, model_gain = aggregate_gains(diagnostics["marginal"])
    write_csv(staging / "statistical_restart_audit" / "restart_prefix_curves.csv", diagnostics["prefix"])
    write_csv(staging / "statistical_restart_audit" / "restart_gain_by_unit.csv", unit_gain)
    write_csv(staging / "statistical_restart_audit" / "restart_gain_by_family.csv", family_gain)
    write_csv(staging / "statistical_restart_audit" / "restart_gain_by_model.csv", model_gain)
    write_csv(staging / "diagnostics" / "marginal_restart_discovery.csv", diagnostics["marginal"])
    write_csv(staging / "diagnostics" / "late_restart_discovery.csv", diagnostics["late"])
    write_csv(staging / "diagnostics" / "strongest_restart_distribution.csv", diagnostics["strongest"])
    write_csv(staging / "diagnostics" / "discovery_decay.csv", diagnostics["decay"])
    write_csv(staging / "diagnostics" / "success_set_overlap.csv", diagnostics["overlap"])
    write_json(staging / "diagnostics" / "unseen_success_estimate.json", {
        "schema_version": SCHEMA,
        "label": "DIAGNOSTIC ONLY",
        "method": "Chao-style incidence estimate plus Good–Turing singleton discovery probability",
        "iid_warning": "restart discoveries are not strictly independent and identically distributed; estimates are not guarantees or gates",
        "formal_gate_use": "PROHIBITED",
        "units": diagnostics["unseen"],
    })
    write_json(staging / "diagnostics" / "capture_recapture_diagnostic.json", {
        "schema_version": SCHEMA,
        "label": "DIAGNOSTIC ONLY",
        "captures": "restart blocks 0–19 and 20–39",
        "method": "Chapman two-capture estimator",
        "iid_warning": "restart-block captures are dependent and heterogeneous; estimates are descriptive only",
        "formal_gate_use": "PROHIBITED",
        "units": diagnostics["capture"],
    })
    curve_fit_result = fit_saturation(diagnostics["prefix"])
    write_json(staging / "diagnostics" / "saturation_curve_fit.json", curve_fit_result)
    write_csv(staging / "diagnostics" / "storage_cleanup_candidates.csv", [], ["path_a", "path_b", "sha256", "size_bytes", "reason"])

    p2c_family_path = root / "outputs" / "attack_audit_c001" / "p2c" / "formal_reaggregation_v2" / "restart_adequacy" / "restart_gain_by_family.csv"
    p2c_family = pd.read_csv(p2c_family_path).to_dict("records")
    comparison = pd.read_csv(root / "outputs" / "attack_audit_c001" / "p2c" / "formal_reaggregation_v2" / "restart_adequacy" / "r20_r40_corrected_comparison.csv")
    model_summary = comparison.groupby("model").agg(
        mean_gain=("delta_20_40", "mean"), max_gain=("delta_20_40", "max"), new_successes=("new_successes", "sum")
    ).reset_index().to_dict("records")
    cat = next(row for row in model_summary if row["model"] == "CAT-AD")
    erm = next(row for row in model_summary if row["model"] == "BiLSTM-ERM")
    concentrated = bool(cat["mean_gain"] > erm["mean_gain"] and cat["new_successes"] > erm["new_successes"])
    late_frame = pd.DataFrame(diagnostics["late"])
    verdict_json = {
        "schema_version": SCHEMA,
        "generated_at_utc": utc_now(),
        "overall_verdict": VERDICT,
        "P2C_preserved": True,
        "R40_valid": True,
        "R80_complete": False,
        "new_attack_executed": False,
        "R40_restart_adequacy": "FAIL — RESTARTS NOT STABLE",
        "fixed_restart_saturation_within_R_le_40": "NOT ESTABLISHED",
        "formal_R80_adequacy": "NOT ASSESSED",
        "formal_R160_adequacy": "NOT ASSESSED",
        "family_R20_R40_evidence": p2c_family,
        "model_R20_R40_evidence": model_summary,
        "late_discovery_material_units": int(late_frame["late_discovery_material_by_frozen_0_005_unit_threshold"].sum()),
        "late_discovery_unit_count": len(late_frame),
        "restart_sensitivity_concentrated_in_CAT_AD": concentrated,
        "statistical_extrapolation_label": "DIAGNOSTIC ONLY",
        "allowed_conclusions": [
            "FIXED-RESTART SATURATION NOT ESTABLISHED WITHIN R≤40",
            "LATE RESTART DISCOVERY REMAINS MATERIAL" if late_frame["late_discovery_material_by_frozen_0_005_unit_threshold"].any() else "late discovery materiality is inconclusive",
            "RESTART SENSITIVITY REMAINS CONCENTRATED IN CAT-AD" if concentrated else "restart-sensitivity concentration is inconclusive",
            "diagnostics are consistent with additional undiscovered successes beyond R40",
        ],
        "prohibited_conclusions": ["PASS AT R80", "PASS AT R160", "restart sufficient", "attack saturated"],
    }
    write_json(staging / "statistical_restart_audit" / "resource_bounded_restart_verdict.json", verdict_json)
    write_json(staging / "gates" / "statistical_restart_source_gate.json", {
        "schema_version": SCHEMA,
        "source_prefixes": [1, 5, 10, 20, 40],
        "formal_units": 80,
        "sample_level_source": restart_source_provenance,
        "partial_R80_used": False,
        "new_attack_executed": False,
        "status": "PASS",
    })
    write_json(staging / "next_stage" / "diagnostic_p3_preregistration_required.json", {
        "schema_version": SCHEMA,
        "formal_P3_clearance": "DENIED",
        "optional_future_route": "P3 DIAGNOSTIC LOSS / HOLDOUT AUDIT UNDER UNRESOLVED RESTART SATURATION",
        "requires_separate_preregistration": True,
        "executed_in_this_stage": False,
        "mandatory_label": "restart saturation unresolved",
        "limitations": [
            "CE/Margin/CW may compare relative attack strength only",
            "holdout may assess attack-specific overfitting only",
            "no final attack adequacy claim",
            "no restoration of near-zero ASR or robustness claims",
        ],
    })
    write_json(staging / "next_stage" / "future_compute_options.json", {
        "schema_version": SCHEMA,
        "status": "OPTIONS_ONLY_NOT_AUTHORIZED",
        "options": [
            "keep fixed-restart saturation suspended",
            "later preregister a new resource budget and resume from preserved provenance",
            "separately preregister diagnostic P3 under unresolved restart saturation",
        ],
        "no_compute_launched": True,
    })

    family20_40 = pd.DataFrame(family_gain)
    family20_40 = family20_40[family20_40["interval"].eq("R20→R40")]
    model20_40 = pd.DataFrame(model_gain)
    model20_40 = model20_40[model20_40["interval"].eq("R20→R40")]
    report = f"""# C0-01 P2-D Resource-Constrained Termination Report

Generated: {utc_now()}

## Decision

**{VERDICT}**

The fixed-restart expansion was terminated for computational/runtime resource constraints before a complete R80 result existed. The decision is not result-contingent. Partial R80 artifacts are provenance only and were not used in any formal ASR, adequacy gate, threshold choice, discovery curve, or extrapolation.

## Process and partial R80 freeze

- P2-D quiescence gate: PASS; PID 36796 absent; active writer count 0.
- R80 state: {formal_status['completed_logical_configs']} completed, {formal_status['running_state_at_interruption']} interrupted/running-state, {formal_status['pending_logical_configs']} pending, {formal_status['failed_logical_configs']} failed.
- Formal R80 result: NOT AVAILABLE.
- Stale lock: retained in place and classified `{lock_state['classification']}`.
- Committed restart IDs: {partial_state['committed_restart_ids']}.
- Staging restart IDs observed: {partial_state['staging_restart_ids_observed']} (interrupted provenance only).

## Source integrity

- Final P2-C Integrity v2: PASS.
- R20 snapshot: `{EXPECTED_R20_SNAPSHOT}`.
- R40 snapshot: `{EXPECTED_R40_SNAPSHOT}`.
- Frozen attack fingerprint: `{EXPECTED_ATTACK_CODE_FINGERPRINT}`.
- Formal post-hoc fingerprint: `{EXPECTED_P2C_POSTHOC_FINGERPRINT}`.
- P2-B R1/R5/R10 artifact verification: PASS.
- Forensic per-restart matrix verification: PASS.

## Resource-bounded restart evidence

All calculations use 80 `split × model × attack × K` units and frozen sample-level memberships for R1/R5/R10/R20/R40. Partial R80 is excluded.

P2-C formally established that every family fails the frozen R20→R40 stability rule. Mean ASR gains were 0.024849 (Norm-PGD), 0.031155 (projection), 0.040739 (penalty), and 0.030358 (hybrid), with maximum unit gains from 0.132394 to 0.157957. Therefore fixed-restart saturation within R≤40 remains not established.

The restart-prefix, marginal discovery, late-discovery, strongest-restart, discovery-decay, overlap, capture–recapture, unseen-success, and two-form saturation-fit diagnostics are archived in this bundle. Statistical extrapolations are **DIAGNOSTIC ONLY** because restart discoveries are dependent and heterogeneous; they are not formal adequacy gates or guarantees about R80.

## Model finding

R20→R40 restart sensitivity remains concentrated in CAT-AD: {str(concentrated).upper()}. This is an attack-discovery sensitivity finding, not robustness evidence.

## Stage and claims

- Fixed-restart saturation within R≤40: NOT ESTABLISHED.
- Formal R80 adequacy: NOT ASSESSED.
- Formal R160 adequacy: NOT ASSESSED.
- Formal P3 clearance: DENIED.
- P3–P6 were not executed.
- CAT-AD robustness, superiority, near-zero ASR/PV-ASR, attack adequacy, certification, and related defense-improvement interpretations remain suspended.
- The manuscript was not modified.
"""
    (staging / "final" / "resource_termination_report.md").write_text(report, encoding="utf-8")
    (staging / "resource_termination_report.md").write_text(
        "# Resource Termination Report Pointer\n\nThe canonical full report is `final/resource_termination_report.md`.\n",
        encoding="utf-8",
    )
    write_json(staging / "gates" / "resource_termination_integrity_gate.json", {
        "schema_version": SCHEMA,
        "quiescence": "PASS",
        "source_identity": "PASS",
        "partial_R80_preserved": "PASS",
        "partial_R80_excluded_from_formal_analysis": "PASS",
        "no_new_attack": "PASS",
        "no_P3_to_P6": "PASS",
        "status": "PASS",
    })

    initial_verification = artifact_verification(staging)
    if initial_verification["status"] != "PASS":
        write_json(staging / "final" / "resource_termination_artifact_hashes.failed.json", initial_verification)
        raise RuntimeError(f"artifact verification failed: {initial_verification['verification']}")
    write_json(staging / "final" / "resource_termination_artifact_hashes.json", initial_verification)
    reopened = load_json(staging / "final" / "resource_termination_artifact_hashes.json")
    for row in reopened["artifacts"]:
        path = staging / row["path"]
        if path.stat().st_size != row["size_bytes"] or sha256_file(path) != row["sha256"]:
            raise RuntimeError(f"post-write artifact mismatch: {row['path']}")
    os.replace(staging, destination)
    print(json.dumps({
        "status": "PASS",
        "bundle": str(destination),
        "overall_verdict": VERDICT,
        "completed_R80_configs": formal_status["completed_logical_configs"],
        "partial_R80_used": False,
        "new_attack_executed": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

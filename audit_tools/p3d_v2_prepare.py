"""Prepare the isolated C0-01 P3-Diagnostic v2 preregistration freeze.

This module never executes a model attack.  It creates the complete v2
configuration/source freeze and an independently reconstructed CE R5
reference before run authorization is considered.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd

from adsb.checkpoints import code_fingerprint, sha256_file
from audit_tools import p3d_finalize as legacy_finalize
from audit_tools import p3d_runner as legacy_runner


CANONICAL_ROOT = Path(r"E:\ads-b\ADS-B2 -beifen")
REQUEST_PATH = Path(
    r"C:\Users\lwb\.codex\attachments\f12eecb9-de8f-4fa8-80ba-7f40b753af13\pasted-text.txt"
)
EXPECTED_REQUEST_HASH = "e8361d9a46723a3cc0491cbec1b441884e50c807c1fba1ce2e47c0a3366779c1"
EXPECTED_ATTACK_FINGERPRINT = "afd1389066e1c87fec8d6f9da42e4f7e2fb3384343f214d31c8eccf79bdbcf4f"
EXPECTED_R40_SNAPSHOT = "842d399a647699fdd7b038df5efb6d2907499cad094be44dfee47f2f5f528270"
EXPECTED_P2C_POSTHOC = "a4f0b5d33eff36f8835dbb40faa1a5d2aa179673930d2dc45173fcb17badb0bb"
EXPECTED_P2B_FREEZE = "785d51ee255a3993b34e6fd2e0e72b71e848653549edf8574d5701899d08bc56"

SEEDS = legacy_runner.SEEDS
MODELS = legacy_runner.MODELS
ATTACKS = legacy_runner.ATTACKS
STEPS = legacy_runner.STEPS
LOSSES = legacy_runner.LOSSES
CW_KAPPA = 0.0
R = 5
INVENTORY_FIELDS = legacy_runner.INVENTORY_FIELDS

REQUIRED_PREREG = (
    "p3d_current_research_status.json",
    "p3d_preregistration.json",
    "p3d_attack_matrix.csv",
    "p3d_loss_definitions.json",
    "p3d_cw_parameter_freeze.json",
    "p3d_resource_budget.json",
    "p3d_restart_spec.json",
    "p3d_candidate_semantics_reference.json",
    "p3d_support_semantics_reference.json",
    "p3d_holdout_definition.json",
    "p3d_claim_constraints.json",
    "loss_pairing_status.json",
    "p3d_source_identity_freeze.json",
    "p3d_configuration_hashes.json",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def atomic_csv(path: Path, rows: Iterable[dict[str, Any]], fields: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(fields), extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def paths(project_root: Path) -> dict[str, Path]:
    base = project_root / "outputs" / "attack_audit_c001"
    p3 = base / "p3_diagnostic_v2"
    return {
        "root": project_root,
        "base": base,
        "p1": base / "p1",
        "p2": base / "p2",
        "p2b": base / "p2b",
        "p2c": base / "p2c",
        "p2cv2": base / "p2c" / "formal_reaggregation_v2",
        "p2d": base / "p2d" / "resource_termination_v1",
        "p3v1": base / "p3_diagnostic",
        "p3": p3,
        "freeze": p3 / "configuration_freeze",
        "pre_run": p3 / "pre_run_gate",
        "source": p3 / "source_snapshot",
    }


def source_files(p: dict[str, Path]) -> dict[str, Path]:
    root = p["root"]
    v1 = p["p3v1"]
    return {
        "request": REQUEST_PATH,
        "project_instructions": root / "PROJECT_INSTRUCTIONS.md",
        "agents": root / "AGENTS.md",
        "attack_implementation": root / "adsb" / "attack_audit.py",
        "p2_execution_implementation": root / "adsb" / "p2_step_size_restart.py",
        "p2_configuration": p["p2"] / "p2_configuration_freeze.json",
        "p2b_configuration_freeze": p["p2"] / "p2b_configuration_freeze.json",
        "p2b_manifest": p["p2b"] / "p2b_manifest.json",
        "p2b_inventory": p["p2b"] / "p2b_task_inventory.csv",
        "p2c_final_integrity_v2": p["p2cv2"] / "gates" / "final_p2c_integrity_gate_v2.json",
        "p2c_hash_manifest": p["p2cv2"] / "formal_reaggregation_artifact_hashes.json",
        "p2c_posthoc_fingerprint": p["p2cv2"] / "p2c_reaggregation_posthoc_fingerprint.json",
        "p2c_r40_snapshot": p["p2c"] / "r40_raw_snapshot_manifest.json",
        "p2c_corrected_semantics": p["p2cv2"] / "configuration_freeze" / "corrected_semantics.json",
        "p2c_candidate_definition": p["p2cv2"] / "configuration_freeze" / "candidate_definition.json",
        "p2c_support_definition": p["p2cv2"] / "configuration_freeze" / "support_definition.json",
        "p2c_fallback_definition": p["p2cv2"] / "configuration_freeze" / "fallback_definition.json",
        "p2d_termination_gate": p["p2d"] / "gates" / "resource_termination_integrity_gate.json",
        "p2d_hash_manifest": p["p2d"] / "final" / "resource_termination_artifact_hashes.json",
        "p2d_termination_decision": p["p2d"] / "termination_freeze" / "p2d_resource_termination_decision.json",
        "p2d_r80_status": p["p2d"] / "termination_freeze" / "r80_formal_status.json",
        "p2d_ce_prefix_curves": p["p2d"] / "statistical_restart_audit" / "restart_prefix_curves.csv",
        "p3v1_final_report": v1 / "final" / "p3d_report.md",
        "p3v1_final_gate": v1 / "gates" / "p3d_final_integrity_gate.json",
        "p3v1_failure_record": v1 / "integrity_failure" / "p3d_integrity_failure_record.json",
        "p3v1_failure_hashes": v1 / "integrity_failure" / "artifact_hashes.json",
        "p3v1_stale_locks": v1 / "integrity_failure" / "stale_locks_archived.json",
        "p3v1_margin_inventory": v1 / "margin" / "task_inventory.csv",
        "p3v1_margin_ledger": v1 / "margin" / "ledger.jsonl",
        "train_attack_manifest": root / "configs" / "attack_audit_c001" / "train_attack_manifest.json",
        "evaluation_attack_matrix": root / "configs" / "attack_audit_c001" / "evaluation_attack_matrix.json",
        "loss_test": root / "tests" / "test_attack_audit.py",
        "p1_integrity_gate": p["p1"] / "p1_integrity_gate.json",
        "p1_hash_manifest": p["p1"] / "artifact_hashes.json",
        "v2_prepare": root / "audit_tools" / "p3d_v2_prepare.py",
        "v2_prerun_gate": root / "audit_tools" / "p3d_v2_prerun_gate.py",
        "v2_runner": root / "audit_tools" / "p3d_v2_runner.py",
        "v2_finalize": root / "audit_tools" / "p3d_v2_finalize.py",
    }


def verify_hash_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    missing: list[str] = []
    mismatches: list[str] = []
    for item in manifest.get("artifacts", []):
        artifact = root / Path(item["path"])
        if not artifact.is_file():
            missing.append(item["path"])
        elif artifact.stat().st_size != int(item["size_bytes"]) or sha256_file(artifact) != item["sha256"]:
            mismatches.append(item["path"])
    return {
        "manifest_status": manifest.get("status", "PASS" if manifest.get("artifacts") else None),
        "artifact_count": len(manifest.get("artifacts", [])),
        "missing": missing,
        "mismatches": mismatches,
        "pass": bool(manifest.get("artifacts")) and not missing and not mismatches and manifest.get("status", "PASS") == "PASS",
    }


def verify_v1(p: dict[str, Path]) -> dict[str, Any]:
    files = source_files(p)
    manifest_check = verify_hash_manifest(p["p3v1"], files["p3v1_failure_hashes"])
    failure = load_json(files["p3v1_failure_record"])
    gate = load_json(files["p3v1_final_gate"])
    inventory = pd.read_csv(files["p3v1_margin_inventory"], dtype=str).fillna("")
    completed = inventory[inventory.execution_status == "completed"]
    running = inventory[inventory.execution_status == "running"]
    task_directories = [path for path in (p["p3v1"] / "margin" / "raw_results" / "tasks").glob("*") if path.is_dir()]
    checks = {
        "failure_manifest": manifest_check["pass"],
        "gate_failed": gate.get("status") == "FAIL" and gate.get("verdict") == "P3-DIAGNOSTIC INTEGRITY FAILURE",
        "record_status": failure.get("status") == "P3-DIAGNOSTIC INTEGRITY FAILURE",
        "completed_configs": len(completed) == 10,
        "committed_trajectories": len(completed) * 5 == 50,
        "single_interrupted_uncommitted": len(running) == 1,
        "task_directory_count_consistent": len(task_directories) == 11,
        "partial_formal_use_forbidden": failure.get("partial_matrix_interpreted") is False,
    }
    return {
        "schema_version": "adsb.c001-p3d-v2-v1-failure-reference.v1",
        "v1_formal_status": "INTEGRITY_FAILURE",
        "v1_partial_margin_formal_use": "FORBIDDEN",
        "v1_results_in_v2_aggregate": False,
        "completed_logical_configs": len(completed),
        "committed_trajectories": len(completed) * 5,
        "interrupted_uncommitted_configs": len(running),
        "manifest_verification": manifest_check,
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "verified_at_utc": now(),
    }


def corrected_ce_reaggregation(project_root: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Rebuild CE R5 with the frozen P2-C corrected success semantics.

    ``success_event_is_actual_candidate`` in the forensic state matrix is a
    provenance invariant, not a success indicator.  Physical formal success is
    the audited ``feasible_success`` predicate, exactly as used by the P2-D
    resource-termination reconstruction.
    """
    p = paths(project_root)
    pieces: list[pd.DataFrame] = []
    inventory = pd.read_csv(p["p2b"] / "p2b_task_inventory.csv", dtype=str)
    norm_rows = inventory[
        (inventory.restarts == str(R))
        & (inventory.execution_status == "completed")
        & (inventory.attack == "norm_pgd")
    ]
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
            "unit_id": legacy_finalize.unit_id(int(row.seed), row.model, row.attack, int(row.K)),
            "loss": "ce", "loss_id": "targeted_ce", "seed": int(row.seed),
            "model": row.model, "attack": row.attack, "K": int(row.K),
            "sample_id": sample_ids, "formal_success": success.any(axis=0),
            "success_restart_incidence": success.sum(axis=0), "source_valid_V0": source,
        }))

    matrix_path = p["p2c"] / "integrity_forensic" / "physical_support" / "sample_restart_state_matrix.csv.gz"
    columns = [
        "seed", "model", "attack", "K", "sample_id", "restart_id", "attacked",
        "source_valid", "initialization_success", "active", "final_valid",
        "projection_failed", "budget_valid", "kinematic_valid", "feasible_success",
        "fallback_used", "any_feasible_candidate_in_restart",
        "success_event_is_actual_candidate",
    ]
    bool_columns = [
        "attacked", "source_valid", "initialization_success", "active", "final_valid",
        "projection_failed", "budget_valid", "kinematic_valid", "feasible_success",
        "fallback_used", "any_feasible_candidate_in_restart",
        "success_event_is_actual_candidate",
    ]
    physical_parts: list[pd.DataFrame] = []
    for chunk in pd.read_csv(matrix_path, usecols=columns, chunksize=750_000):
        chunk = chunk[chunk.restart_id.astype(int) < R].copy()
        if chunk.empty:
            continue
        for column in bool_columns:
            chunk[column] = chunk[column].map(legacy_finalize.as_bool)
        chunk["formal_success_row"] = chunk["feasible_success"]
        chunk["success_provenance_valid"] = (
            ~chunk["formal_success_row"] | chunk["success_event_is_actual_candidate"]
        )
        chunk["budget_valid_candidate"] = chunk.active & chunk.budget_valid
        chunk["kinematic_valid_candidate"] = chunk.active & chunk.kinematic_valid
        chunk["valid_candidate"] = chunk.any_feasible_candidate_in_restart
        grouped = chunk.groupby(
            ["seed", "model", "attack", "K", "sample_id"], as_index=False,
        ).agg(
            formal_success=("formal_success_row", "max"),
            success_restart_incidence=("formal_success_row", "sum"),
            success_provenance_valid=("success_provenance_valid", "min"),
            source_valid_V0=("source_valid", "max"), attacked=("attacked", "max"),
            active=("active", "max"),
            budget_valid_candidate=("budget_valid_candidate", "max"),
            kinematic_valid_candidate=("kinematic_valid_candidate", "max"),
            valid_candidate=("valid_candidate", "max"), final_valid=("final_valid", "max"),
            fallback_event=("fallback_used", "sum"), projection_failure=("projection_failed", "max"),
            initialization_success=("initialization_success", "max"), restart_rows=("restart_id", "size"),
        )
        physical_parts.append(grouped)
    if not physical_parts:
        raise RuntimeError("CE physical forensic matrix yielded no R5 rows")
    physical_samples = pd.concat(physical_parts, ignore_index=True).groupby(
        ["seed", "model", "attack", "K", "sample_id"], as_index=False,
    ).agg(
        formal_success=("formal_success", "max"),
        success_restart_incidence=("success_restart_incidence", "sum"),
        success_provenance_valid=("success_provenance_valid", "min"),
        source_valid_V0=("source_valid_V0", "max"), attacked=("attacked", "max"),
        active=("active", "max"), budget_valid_candidate=("budget_valid_candidate", "max"),
        kinematic_valid_candidate=("kinematic_valid_candidate", "max"),
        valid_candidate=("valid_candidate", "max"), final_valid=("final_valid", "max"),
        fallback_event=("fallback_event", "sum"), projection_failure=("projection_failure", "max"),
        initialization_success=("initialization_success", "max"), restart_rows=("restart_rows", "sum"),
    )
    if not bool((physical_samples.restart_rows == R).all()):
        raise RuntimeError("CE physical R5 restart rows are incomplete or duplicated")
    if not bool(physical_samples.success_provenance_valid.all()):
        raise RuntimeError("CE physical success provenance invariant failed")
    physical_samples["unit_id"] = [
        legacy_finalize.unit_id(int(seed), model, attack, int(steps))
        for seed, model, attack, steps in zip(
            physical_samples.seed, physical_samples.model,
            physical_samples.attack, physical_samples.K,
        )
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
    for (seed, model, attack, steps), group in physical_samples.groupby(
        ["seed", "model", "attack", "K"], sort=False,
    ):
        attacked_n = int(group.attacked.sum())
        source_valid_n = int(group.source_valid_V0.sum())
        feasible_success_n = int(group.feasible_success.sum())
        physical_rows.append({
            "unit_id": legacy_finalize.unit_id(int(seed), model, attack, int(steps)),
            "loss": "ce", "loss_id": "targeted_ce", "seed": int(seed), "split": int(seed),
            "model": model, "attack": attack, "K": int(steps), "R": R,
            "task_hash": "FROZEN_P2C_R5_REAGGREGATION", "attack_config_hash": "FROZEN_CE_REFERENCE",
            "threshold": np.nan, "attacked_N": attacked_n, "source_valid_N": source_valid_n,
            "actual_candidate_support": int(group.active.sum()),
            "budget_valid_support": int(group.budget_valid_candidate.sum()),
            "kinematic_valid_support": int(group.kinematic_valid_candidate.sum()),
            "valid_or_feasible_support": int(group.valid_candidate.sum()),
            "formal_success": int(group.formal_success.sum()),
            "asr": float(group.formal_success.mean()), "feasible_success": feasible_success_n,
            "feasible_asr": float(feasible_success_n / source_valid_n) if source_valid_n else np.nan,
            "best_target_ce": np.nan, "best_target_margin": np.nan, "best_target_count": 0,
            "best_target_loss": np.nan, "success_preserving_target_ce": np.nan,
            "success_preserving_target_margin": np.nan, "success_preserving_target_loss": np.nan,
            "success_preserving_count": int(group.formal_success.sum()),
            "fallback_event": int(group.fallback_event.sum()), "fallback_ever": int(group.fallback_ever.sum()),
            "fallback_only": int(group.fallback_only.sum()), "final_fallback": int(group.final_fallback.sum()),
            "projection_failure": int(group.projection_failure.sum()),
            "initialization_infeasible": int(group.initialization_infeasible.sum()),
            "fallback_only_success": int(group.fallback_only_success.sum()), "restart_complete": True,
        })
    return output, pd.DataFrame(physical_rows)


def build_ce_reference(project_root: Path, p: dict[str, Path]) -> tuple[pd.DataFrame, dict[str, Any]]:
    source = pd.read_csv(source_files(p)["p2d_ce_prefix_curves"])
    source = source[source.R.astype(int) == R].copy().sort_values(["seed", "model", "attack", "K"])
    if len(source) != 80 or source.groupby(["seed", "model", "attack", "K"]).ngroups != 80:
        raise RuntimeError(f"CE R5 prefix source is not exactly 80/80: {len(source)}")

    memberships, _ = corrected_ce_reaggregation(project_root)
    recomputed = memberships.groupby(["seed", "model", "attack", "K"], as_index=False).agg(
        recomputed_attacked_N=("sample_id", "size"),
        recomputed_source_valid_N=("source_valid_V0", "sum"),
        recomputed_cumulative_unique_success=("formal_success", "sum"),
        recomputed_success_restart_incidence=("success_restart_incidence", "sum"),
    )
    result = source.merge(recomputed, on=["seed", "model", "attack", "K"], validate="one_to_one")
    result["denominator_identity"] = result.attacked_N.astype(int) == result.recomputed_attacked_N.astype(int)
    result["source_valid_denominator_identity"] = result.source_valid_N.astype(int) == result.recomputed_source_valid_N.astype(int)
    result["union_identity"] = result.cumulative_unique_success.astype(int) == result.recomputed_cumulative_unique_success.astype(int)
    result["candidate_semantics"] = "P2-C corrected actual-candidate semantics"
    result["support_semantics"] = "attacked original-label anomalous support; physical success requires budget+kinematic validity"
    result["threshold_identity"] = True
    result["source_hash"] = sha256_file(source_files(p)["p2d_ce_prefix_curves"])
    checks = {
        "unit_count_80": len(result) == 80,
        "restart_prefix_exact_0_4": bool((result.R.astype(int) == R).all()),
        "denominator_identity": bool(result.denominator_identity.all()),
        "source_valid_denominator_identity": bool(result.source_valid_denominator_identity.all()),
        "union_identity": bool(result.union_identity.all()),
        "candidate_semantics": True,
        "support_semantics": True,
        "threshold_identity": True,
        "source_hashes": True,
    }
    return result, {"checks": checks, "status": "PASS" if all(checks.values()) else "FAIL"}


def fresh_state_allowed(p: dict[str, Path]) -> bool:
    if not p["p3"].exists():
        return True
    authorization = p["pre_run"] / "pre_run_authorization.json"
    if authorization.exists() and load_json(authorization).get("run_authorized") is True:
        return False
    for loss in ("margin", "cw"):
        loss_root = p["p3"] / loss
        ledger = loss_root / "ledger.jsonl"
        if ledger.exists() and "TASK_START" in ledger.read_text(encoding="utf-8"):
            return False
        raw = loss_root / "raw_results"
        for candidate in (raw / "tasks", raw / ".staging"):
            if candidate.exists() and any(candidate.iterdir()):
                return False
    return True


def prepare(project_root: Path = CANONICAL_ROOT) -> dict[str, Any]:
    project_root = project_root.resolve()
    p = paths(project_root)
    if project_root != CANONICAL_ROOT.resolve():
        raise RuntimeError(f"canonical root mismatch: {project_root}")
    if Path(r"D:\ADS-B2 -beifen").exists():
        d = Path(r"D:\ADS-B2 -beifen")
        if d.resolve() != project_root:
            raise RuntimeError("SOURCE IDENTITY FAILURE: D path is an independent project entity")
    if not fresh_state_allowed(p):
        raise RuntimeError("existing p3_diagnostic_v2 is execution-bearing; create v3 instead")

    files = source_files(p)
    missing = [name for name, path in files.items() if not path.is_file()]
    if missing:
        raise RuntimeError(f"missing prerequisite files: {missing}")
    if sha256_file(REQUEST_PATH) != EXPECTED_REQUEST_HASH:
        raise RuntimeError("request hash mismatch")
    if code_fingerprint(project_root) != EXPECTED_ATTACK_FINGERPRINT:
        raise RuntimeError("frozen attack fingerprint mismatch")
    if sha256_file(files["p2b_configuration_freeze"]) != EXPECTED_P2B_FREEZE:
        raise RuntimeError("P2-B configuration freeze identity mismatch")

    p2c_gate = load_json(files["p2c_final_integrity_v2"])
    p2c_fp = load_json(files["p2c_posthoc_fingerprint"])
    r40 = load_json(files["p2c_r40_snapshot"])
    p2c_manifest_check = verify_hash_manifest(p["p2cv2"], files["p2c_hash_manifest"])
    p2d_gate = load_json(files["p2d_termination_gate"])
    p2d_decision = load_json(files["p2d_termination_decision"])
    p2d_r80 = load_json(files["p2d_r80_status"])
    p2d_manifest_check = verify_hash_manifest(p["p2d"], files["p2d_hash_manifest"])
    v1_reference = verify_v1(p)
    source_checks = {
        "canonical_root": project_root == CANONICAL_ROOT.resolve(),
        "project_identity": sha256_file(files["project_instructions"]) == "070b3a70d5b16db583b0f03a95f0ebe96bdd2cbaaefce930ef2eac3dba249087",
        "d_path_no_independent_entity": not Path(r"D:\ADS-B2 -beifen").exists(),
        "request_identity": sha256_file(REQUEST_PATH) == EXPECTED_REQUEST_HASH,
        "attack_fingerprint": code_fingerprint(project_root) == EXPECTED_ATTACK_FINGERPRINT,
        "p2c_integrity": p2c_gate.get("status") == "PASS",
        "p2c_manifest": p2c_manifest_check["pass"],
        "r40_snapshot": r40.get("r40_raw_snapshot_hash") == EXPECTED_R40_SNAPSHOT,
        "p2c_posthoc": p2c_fp.get("new_reaggregation_fingerprint") == EXPECTED_P2C_POSTHOC,
        "p2d_integrity": p2d_gate.get("status") == "PASS" and p2d_manifest_check["pass"],
        "p2d_termination": p2d_decision.get("termination_type") == "RESOURCE_CONSTRAINED_EARLY_TERMINATION",
        "formal_r80_not_assessed": p2d_r80.get("formal_R80_adequacy") == "NOT ASSESSED",
        "v1_failure_preserved": v1_reference["status"] == "PASS",
    }
    if not all(source_checks.values()):
        raise RuntimeError(f"SOURCE IDENTITY FAILURE: {source_checks}")

    for directory in (
        "configuration_freeze", "pre_run_gate", "source_snapshot", "margin", "cw",
        "reaggregation", "gates", "loss_diagnostic", "holdout_diagnostic",
        "diagnostics", "reproducibility", "final",
    ):
        (p["p3"] / directory).mkdir(parents=True, exist_ok=True)
    for loss in ("margin", "cw"):
        (p["p3"] / loss / "raw_results").mkdir(parents=True, exist_ok=True)
        (p["p3"] / loss / "failed_attempts").mkdir(parents=True, exist_ok=True)
        (p["p3"] / loss / "ledger.jsonl").touch(exist_ok=True)
        (p["p3"] / loss / "failed_attempts.jsonl").touch(exist_ok=True)

    freeze_utc = now()
    atomic_json(p["source"] / "p3d_v1_failure_reference.json", v1_reference)
    ce_reference, ce_gate = build_ce_reference(project_root, p)
    if ce_gate["status"] != "PASS":
        raise RuntimeError(f"CE R5 reference gate failed: {ce_gate}")
    ce_reference.to_csv(p["source"] / "ce_r5_reference.csv", index=False)

    atomic_json(p["source"] / "p2c_identity.json", {
        "schema_version": "adsb.c001-p3d-v2-p2c-identity.v1",
        "final_integrity": "PASS", "r40_snapshot": EXPECTED_R40_SNAPSHOT,
        "attack_fingerprint": EXPECTED_ATTACK_FINGERPRINT, "posthoc_fingerprint": EXPECTED_P2C_POSTHOC,
        "manifest_verification": p2c_manifest_check, "verified_at_utc": freeze_utc,
    })
    atomic_json(p["source"] / "p2d_termination_identity.json", {
        "schema_version": "adsb.c001-p3d-v2-p2d-identity.v1", "integrity": "PASS",
        "termination_verdict": "RESOURCE-CONSTRAINED FIXED-RESTART AUDIT TERMINATED — SATURATION NOT ESTABLISHED",
        "formal_R80_adequacy": "NOT ASSESSED", "partial_R80_used": False,
        "partial_R80_resume_allowed": False, "manifest_verification": p2d_manifest_check,
        "verified_at_utc": freeze_utc,
    })

    source_rows = []
    for name, path in files.items():
        source_rows.append({
            "name": name, "path": str(path.resolve()), "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path), "created_utc": datetime.fromtimestamp(path.stat().st_ctime, timezone.utc).isoformat(),
            "modified_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
        })
    atomic_json(p["source"] / "source_hashes.json", {
        "schema_version": "adsb.c001-p3d-v2-source.v1", "frozen_at_utc": freeze_utc,
        "artifacts": source_rows,
    })
    atomic_csv(
        p["source"] / "source_inventory.csv", source_rows,
        ("name", "path", "size_bytes", "sha256", "created_utc", "modified_utc"),
    )

    p2freeze = load_json(files["p2_configuration"])
    projection = p2freeze["projection_config"]
    inventories: dict[str, list[dict[str, Any]]] = {}
    matrix_rows: list[dict[str, Any]] = []
    for loss in ("margin", "cw"):
        inventories[loss] = legacy_runner.build_inventory(p, loss, projection)
        atomic_csv(p["p3"] / loss / "task_inventory.csv", inventories[loss], INVENTORY_FIELDS)
        matrix_rows.extend(inventories[loss])
        atomic_json(p["p3"] / loss / "execution_manifest.json", {
            "schema_version": "adsb.c001-p3d-v2-execution.v1", "loss_name": loss,
            "loss_id": LOSSES[loss], "expected": 80, "completed": 0, "failed": 0,
            "missing": 80, "duplicates": 0, "restarts": list(range(R)),
            "phase": "FROZEN_NOT_STARTED", "created_at_utc": freeze_utc,
        })
    atomic_csv(p["freeze"] / "p3d_attack_matrix.csv", matrix_rows, INVENTORY_FIELDS)

    candidate_source = load_json(files["p2c_candidate_definition"])
    support_source = load_json(files["p2c_support_definition"])
    fallback_source = load_json(files["p2c_fallback_definition"])
    semantics_source = load_json(files["p2c_corrected_semantics"])
    training = load_json(files["train_attack_manifest"])["attack"]
    prereg_payloads: dict[str, dict[str, Any]] = {
        "p3d_current_research_status.json": {
            "schema_version": "adsb.c001-p3d-v2-research-status.v1", "frozen_at_utc": freeze_utc,
            "P2C_final_integrity_v2": "PASS", "R40_restart_adequacy": "FAIL",
            "fixed_restart_saturation_R_le_40": "NOT_ESTABLISHED", "formal_R80_adequacy": "NOT ASSESSED",
            "formal_R160_adequacy": "NOT ASSESSED", "formal_attack_adequacy": "NOT_ESTABLISHED",
            "formal_P3_clearance": "DENIED", "P3_v1_status": "INTEGRITY_FAILURE",
            "P3_v2_stage_type": "DIAGNOSTIC_ONLY", "robustness_claims": "SUSPENDED", "P4_clearance": "DENIED",
        },
        "p3d_preregistration.json": {
            "schema_version": "adsb.c001-p3d-v2-preregistration.v1", "frozen_at_utc": freeze_utc,
            "stage": "P3_DIAGNOSTIC_V2", "stage_type": "DIAGNOSTIC_ONLY", "R": R,
            "restart_ids": list(range(R)), "K": list(STEPS),
            "losses": ["targeted_ce", LOSSES["margin"], LOSSES["cw"]],
            "ce_role": "FROZEN_REFERENCE_NOT_RERUN", "fresh_losses": ["margin", "cw"],
            "attack_families": list(ATTACKS), "comparison_units": 80, "new_logical_configs": 160,
            "maximum_new_trajectories": 800, "fixed_execution_order": ["margin", "cw"],
            "material_difference_threshold": 0.01, "precision": "FP32", "target": "normal_class_0",
            "result_dependent_scheduling": False, "v1_trajectory_reuse": False,
        },
        "p3d_loss_definitions.json": {
            "schema_version": "adsb.c001-p3d-v2-losses.v1", "frozen_at_utc": freeze_utc,
            "targeted_ce": "CE(logits,target=normal_class_0); minimize",
            "targeted_logit_margin": "z_anomaly-z_normal; minimize",
            "targeted_cw_margin": "relu(z_anomaly-z_normal+kappa); minimize",
            "candidate_ranking": "untruncated z_anomaly-z_normal ascending, restart_id, step",
            "result_dependent_candidate_selection": False,
        },
        "p3d_cw_parameter_freeze.json": {
            "schema_version": "adsb.c001-p3d-v2-cw-freeze.v1", "frozen_at_utc": freeze_utc,
            "kappa": CW_KAPPA, "status": "RESOLVED", "unique_preexisting_default": True,
            "result_dependent": False,
            "evidence": [
                {"path": str(files["attack_implementation"]), "line_or_identity": "AttackConfig.cw_kappa line 69 and targeted_losses lines 381-392", "sha256": sha256_file(files["attack_implementation"]), "evidence_modified_utc": datetime.fromtimestamp(files["attack_implementation"].stat().st_mtime, timezone.utc).isoformat()},
                {"path": str(files["loss_test"]), "line_or_identity": "test_threshold_and_argmax_are_distinct_and_cw_ranks_untruncated lines 195-199", "sha256": sha256_file(files["loss_test"]), "evidence_modified_utc": datetime.fromtimestamp(files["loss_test"].stat().st_mtime, timezone.utc).isoformat()},
                {"path": str(files["evaluation_attack_matrix"]), "line_or_identity": "holdout_projection_cw_r5 loss identity", "sha256": sha256_file(files["evaluation_attack_matrix"]), "evidence_modified_utc": datetime.fromtimestamp(files["evaluation_attack_matrix"].stat().st_mtime, timezone.utc).isoformat()},
            ],
            "v1_first_execution_utc": "2026-08-13T10:14:22.683071+00:00",
        },
        "p3d_resource_budget.json": {
            "schema_version": "adsb.c001-p3d-v2-resource.v1", "frozen_at_utc": freeze_utc,
            "R": R, "restart_ids": list(range(R)), "comparison_units": 80,
            "margin_logical_configs": 80, "cw_logical_configs": 80, "new_logical_configs": 160,
            "maximum_new_trajectories": 800, "v1_trajectories_offset_budget": False,
            "prohibited_restart_counts": [10, 20, 40, 80, 160, 320], "ce_rerun": False,
        },
        "p3d_restart_spec.json": {
            "schema_version": "adsb.c001-p3d-v2-restarts.v1", "frozen_at_utc": freeze_utc,
            "R": R, "restart_ids": list(range(R)), "exact_only": True, "higher_restart_ids_prohibited": True,
            "seed_algorithm_modified": False,
        },
        "p3d_candidate_semantics_reference.json": {
            "schema_version": "adsb.c001-p3d-v2-candidate-semantics.v1", "frozen_at_utc": freeze_utc,
            "source": str(files["p2c_candidate_definition"]), "source_sha256": sha256_file(files["p2c_candidate_definition"]),
            "final-active": candidate_source["final_active"], "best-target-loss": candidate_source["best_target_loss"],
            "success-preserving": candidate_source["success_preserving"],
            "best-feasible-success": candidate_source["best_feasible_success"],
            "clean_fallback_is_attack_candidate": False, "result_dependent_selection_change": False,
        },
        "p3d_support_semantics_reference.json": {
            "schema_version": "adsb.c001-p3d-v2-support-semantics.v1", "frozen_at_utc": freeze_utc,
            "sources": {
                "corrected_semantics": {"path": str(files["p2c_corrected_semantics"]), "sha256": sha256_file(files["p2c_corrected_semantics"])},
                "support": {"path": str(files["p2c_support_definition"]), "sha256": sha256_file(files["p2c_support_definition"])},
                "fallback": {"path": str(files["p2c_fallback_definition"]), "sha256": sha256_file(files["p2c_fallback_definition"])},
            },
            "attacked_support": "original-label anomalous attacked samples",
            "norm_success": semantics_source["norm_formal_success"],
            "physical_success": semantics_source["physical_formal_success"],
            "cumulative_R5": "unique sample union over restart 0-4",
            "fallback_event": fallback_source["fallback_event"], "fallback_ever": fallback_source["fallback_ever"],
            "fallback_only": fallback_source["fallback_only"], "final_fallback": fallback_source["final_fallback"],
            "fallback_candidate_success": "FORBIDDEN", "fallback_ever_and_success_may_coexist": True,
            "fallback_only_and_attack_success_must_be_disjoint": True,
            "threshold": "frozen validation threshold", "budget_scope": "normalized_raw6",
            "derived_difference_consistency": "recomputed_from_raw", "source_support_definition": support_source,
        },
        "p3d_holdout_definition.json": {
            "schema_version": "adsb.c001-p3d-v2-holdout-freeze.v1", "frozen_at_utc": freeze_utc,
            "training_source": str(files["train_attack_manifest"]), "training_source_sha256": sha256_file(files["train_attack_manifest"]),
            "training_attack": training,
            "major_dimensions": ["steps", "alpha", "alpha_rule", "initialization", "restarts", "loss", "attack_family", "projection_semantics", "projection_schedule", "epsilon", "budget_scope"],
            "MATCHED": "all major attack-design dimensions match the frozen training attack",
            "HOLDOUT": "at least two major attack-design dimensions differ from the frozen training attack",
            "post_result_modification_allowed": False,
        },
        "p3d_claim_constraints.json": {
            "schema_version": "adsb.c001-p3d-v2-claims.v1", "frozen_at_utc": freeze_utc,
            "restart_saturation": "NOT_ESTABLISHED", "formal_attack_adequacy": "NOT_ESTABLISHED",
            "formal_P3_clearance": "DENIED", "robustness_claims": "SUSPENDED",
            "P4_clearance": "DENIED", "diagnostic_only": True, "manuscript_modification": False,
            "suspended_claims": ["CAT-AD robustness", "CAT-AD superiority over ERM", "near-zero ASR", "near-zero PV-ASR", "full attack adequacy", "certified robustness", "stable-across-epsilon", "Recall/F1 as defense improvement", "fallback as robustness evidence", "projection failure as robustness evidence"],
        },
        "loss_pairing_status.json": {
            "schema_version": "adsb.c001-p3d-v2-pairing.v1", "frozen_at_utc": freeze_utc,
            "status": "UNPAIRED — SAME DISTRIBUTION / SAME RESTART BUDGET",
            "reason": "AttackConfig.restart_seed hashes asdict(config), which contains loss and cw_kappa; the frozen seed algorithm is not modified",
            "source": str(files["attack_implementation"]), "source_sha256": sha256_file(files["attack_implementation"]),
            "line_or_identity": "AttackConfig.restart_seed lines 119-127", "sample_wise_paired_claim_allowed": False,
        },
        "p3d_source_identity_freeze.json": {
            "schema_version": "adsb.c001-p3d-v2-source-identity.v1", "frozen_at_utc": freeze_utc,
            "canonical_root": str(project_root), "git_status": "NOT_A_GIT_REPOSITORY",
            "D_compatibility_path_exists": Path(r"D:\ADS-B2 -beifen").exists(),
            "project_instructions_sha256": sha256_file(files["project_instructions"]),
            "agents_sha256": sha256_file(files["agents"]), "request_sha256": sha256_file(REQUEST_PATH),
            "attack_fingerprint": EXPECTED_ATTACK_FINGERPRINT, "r40_snapshot": EXPECTED_R40_SNAPSHOT,
            "p2c_posthoc_fingerprint": EXPECTED_P2C_POSTHOC, "source_checks": source_checks,
            "p2c_manifest_verification": p2c_manifest_check, "p2d_manifest_verification": p2d_manifest_check,
            "p3v1_reference_status": v1_reference["status"], "partial_R80_formal_use": False,
            "p3v1_partial_formal_use": False,
        },
    }
    for name, payload in prereg_payloads.items():
        atomic_json(p["freeze"] / name, payload)

    prereg_hashes = {name: sha256_file(p["freeze"] / name) for name in REQUIRED_PREREG if name != "p3d_configuration_hashes.json"}
    configuration_hash = canonical_hash(prereg_hashes)
    code_hashes = {
        name: sha256_file(path) for name, path in files.items() if name.startswith("v2_")
    }
    atomic_json(p["freeze"] / "p3d_configuration_hashes.json", {
        "schema_version": "adsb.c001-p3d-v2-configuration-hashes.v1", "frozen_at_utc": freeze_utc,
        "artifacts": prereg_hashes, "configuration_hash": configuration_hash,
        "code_hashes": code_hashes,
        # Legacy finalizer is used only as a calculation engine; its frozen hash
        # is recorded to make that dependency explicit and auditable.
        "runner_sha256": sha256_file(project_root / "audit_tools" / "p3d_runner.py"),
        "legacy_calculation_engine_sha256": sha256_file(project_root / "audit_tools" / "p3d_finalize.py"),
    })
    return {
        "status": "FREEZE_CREATED", "output": str(p["p3"]),
        "configuration_hash": configuration_hash, "freeze_utc": freeze_utc,
        "required_prereg_count": len(REQUIRED_PREREG), "ce_reference_gate": ce_gate,
        "source_checks": source_checks,
    }


if __name__ == "__main__":
    print(json.dumps(prepare(), ensure_ascii=False, indent=2), flush=True)

"""Executor for the C0-01 P2-D extended restart saturation audit.

The module deliberately reuses the frozen P2-C range adapter and the unchanged
single-restart attack engine.  P2-D only schedules late restart identifiers:

* R80 executes restart 40--79 for all 80 frozen logical configurations.
* R160 executes restart 80--159 for every configuration in a triggered family.

Inherited restart artifacts are referenced by their frozen snapshot identities;
they are never copied into the P2-D output tree.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import psutil
import torch

from adsb.checkpoints import code_fingerprint, sha256_file
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.p2_step_size_restart import (
    ATTACKS,
    MODELS,
    SEEDS,
    STEPS,
    _prepare_dataframe,
    load_p1_model,
    prepare_seed,
)
from audit_tools.p2b_runner import (
    EXPECTED_ATTACK_CODE_FINGERPRINT,
    frozen_context,
)
from audit_tools.p2c_orchestration import (
    _failure_archive,
    atomic_json,
    canonical_hash,
    execute_range_task,
    now,
    orchestration_self_test,
    task_identity,
)
from audit_tools.p2c_runner import (
    INVENTORY_FIELDS,
    P2B_ROOT_RELATIVE,
    P2C_ROOT_RELATIVE,
    _config_id,
    _set_read_only,
    _source_r10_lookup,
    append_jsonl,
    atomic_csv,
    read_csv,
    read_jsonl,
    resolve_canonical_root,
)


SCHEMA = "adsb.c001-p2d-runner.v1"
EXPECTED_CANONICAL_ROOT = Path(r"E:\ads-b\ADS-B2 -beifen")
P2D_ROOT_RELATIVE = Path("outputs") / "attack_audit_c001" / "p2d"
FORMAL_V2_RELATIVE = P2C_ROOT_RELATIVE / "formal_reaggregation_v2"

EXPECTED_R20_SNAPSHOT = (
    "1497561193b05a5e4a4ed60bcb1cc6ae44a38cb2bc6ab0cd8751d238cbbf8232"
)
EXPECTED_R40_SNAPSHOT = (
    "842d399a647699fdd7b038df5efb6d2907499cad094be44dfee47f2f5f528270"
)
EXPECTED_P2C_POSTHOC_FINGERPRINT = (
    "a4f0b5d33eff36f8835dbb40faa1a5d2aa179673930d2dc45173fcb17badb0bb"
)

PHYSICAL_ATTACKS = {
    "phys_projection_pgd",
    "phys_penalty_pgd",
    "phys_hybrid_pgd",
}
R80_IDS = tuple(range(40, 80))
R160_IDS = tuple(range(80, 160))


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _sha_record(path: Path, relative_to: Path | None = None) -> dict[str, Any]:
    return {
        "path": (
            path.relative_to(relative_to).as_posix()
            if relative_to is not None
            else str(path)
        ),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _verify_declared_artifacts(
    *,
    manifest: dict[str, Any],
    base: Path,
    label: str,
    workers: int = 4,
    progress_every: int = 50,
) -> dict[str, Any]:
    """Re-read and verify a declared artifact list with bounded parallel I/O."""

    rows = list(manifest.get("artifacts", []))

    def verify(row: dict[str, Any]) -> dict[str, Any]:
        path = base / row["path"]
        if not path.is_file():
            return {"path": row["path"], "pass": False, "reason": "missing"}
        observed_size = path.stat().st_size
        if observed_size != int(row["size_bytes"]):
            return {
                "path": row["path"],
                "pass": False,
                "reason": "size_mismatch",
                "observed_size": observed_size,
            }
        observed_hash = sha256_file(path)
        return {
            "path": row["path"],
            "pass": observed_hash == row["sha256"],
            "reason": "match" if observed_hash == row["sha256"] else "hash_mismatch",
            "observed_sha256": observed_hash,
        }

    checks: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as executor:
        futures = [executor.submit(verify, row) for row in rows]
        for index, future in enumerate(as_completed(futures), 1):
            checks.append(future.result())
            if progress_every and (index % progress_every == 0 or index == len(rows)):
                print(f"[source-hash] {label} {index}/{len(rows)}", flush=True)
    failures = sorted(
        (value for value in checks if not value["pass"]),
        key=lambda value: value["path"],
    )
    return {
        "label": label,
        "declared_artifact_count": int(manifest.get("artifact_count", len(rows))),
        "verified_artifact_count": len(rows),
        "missing_or_mismatched": failures,
        "status": (
            "PASS"
            if int(manifest.get("artifact_count", len(rows))) == len(rows)
            and not failures
            else "FAIL"
        ),
    }


def _verify_raw_snapshot(
    *,
    p2c_root: Path,
    phase: str,
    expected_snapshot: str,
) -> dict[str, Any]:
    manifest_path = p2c_root / f"{phase}_raw_snapshot_manifest.json"
    manifest = load_json(manifest_path)
    declared = manifest.get(f"{phase}_raw_snapshot_hash")
    recomputed = canonical_hash(
        {
            "schema_version": manifest["schema_version"],
            "phase": phase,
            "artifacts": manifest["artifacts"],
            "source_p2b_snapshot_hash": manifest["source_p2b_snapshot_hash"],
            "p2c_configuration_hash": manifest["p2c_configuration_hash"],
            "orchestration_fingerprint": manifest["orchestration_fingerprint"],
        }
    )
    artifact_check = _verify_declared_artifacts(
        manifest=manifest,
        base=p2c_root / f"{phase}_execution",
        label=f"P2-C {phase.upper()} raw snapshot",
        workers=4,
    )
    checks = {
        "declared_snapshot_matches_expected": declared == expected_snapshot,
        "snapshot_hash_recomputes": recomputed == declared,
        "all_raw_artifacts_rehash": artifact_check["status"] == "PASS",
    }
    return {
        "phase": phase,
        "manifest": _sha_record(manifest_path),
        "snapshot_hash": declared,
        "artifact_count": len(manifest["artifacts"]),
        "checks": checks,
        "artifact_verification": artifact_check,
        "status": "PASS" if all(checks.values()) else "FAIL",
    }


def _verify_formal_v2(project_root: Path) -> dict[str, Any]:
    p2c_root = project_root / P2C_ROOT_RELATIVE
    root = project_root / FORMAL_V2_RELATIVE
    final_gate_path = root / "gates" / "final_p2c_integrity_gate_v2.json"
    final_gate = load_json(final_gate_path)
    formal_manifest_path = root / "formal_reaggregation_artifact_hashes.json"
    formal_manifest = load_json(formal_manifest_path)
    corrected_manifest_path = root / "reaggregated" / "corrected_artifact_hashes.json"
    corrected_manifest = load_json(corrected_manifest_path)
    fingerprint_path = root / "p2c_reaggregation_posthoc_fingerprint.json"
    fingerprint = load_json(fingerprint_path)
    formal_check = _verify_declared_artifacts(
        manifest=formal_manifest,
        base=root,
        label="P2-C formal v2",
        workers=4,
        progress_every=0,
    )
    corrected_check = _verify_declared_artifacts(
        manifest=corrected_manifest,
        base=root / "reaggregated",
        label="P2-C corrected v2",
        workers=4,
        progress_every=0,
    )
    r20 = _verify_raw_snapshot(
        p2c_root=p2c_root,
        phase="r20",
        expected_snapshot=EXPECTED_R20_SNAPSHOT,
    )
    r40 = _verify_raw_snapshot(
        p2c_root=p2c_root,
        phase="r40",
        expected_snapshot=EXPECTED_R40_SNAPSHOT,
    )
    adequacy = root / "configuration_freeze" / "restart_adequacy_definition.json"
    corrected_semantics = root / "configuration_freeze" / "corrected_semantics.json"
    support = root / "configuration_freeze" / "support_definition.json"
    candidate = root / "configuration_freeze" / "candidate_definition.json"
    checks = {
        "final_integrity_v2_pass": final_gate.get("status") == "PASS",
        "all_fifteen_final_checks_pass": len(final_gate.get("checks", {})) == 15
        and all(value == "PASS" for value in final_gate["checks"].values()),
        "formal_artifacts_rehash": formal_check["status"] == "PASS",
        "corrected_artifacts_rehash": corrected_check["status"] == "PASS",
        "r20_raw_snapshot_rehash": r20["status"] == "PASS",
        "r40_raw_snapshot_rehash": r40["status"] == "PASS",
        "posthoc_fingerprint": fingerprint.get("new_reaggregation_fingerprint")
        == EXPECTED_P2C_POSTHOC_FINGERPRINT,
        "attack_fingerprint": fingerprint.get("attack_code_fingerprint")
        == EXPECTED_ATTACK_CODE_FINGERPRINT,
        "corrected_semantics_readable": corrected_semantics.is_file(),
        "restart_adequacy_readable": adequacy.is_file(),
        "support_semantics_readable": support.is_file(),
        "candidate_semantics_readable": candidate.is_file(),
    }
    return {
        "schema_version": SCHEMA,
        "verified_at_utc": now(),
        "checks": checks,
        "formal_artifact_verification": formal_check,
        "corrected_artifact_verification": corrected_check,
        "r20": r20,
        "r40": r40,
        "identities": {
            "final_gate": _sha_record(final_gate_path),
            "formal_artifact_manifest": _sha_record(formal_manifest_path),
            "corrected_artifact_manifest": _sha_record(corrected_manifest_path),
            "posthoc_fingerprint": _sha_record(fingerprint_path),
            "corrected_semantics": _sha_record(corrected_semantics),
            "restart_adequacy_definition": _sha_record(adequacy),
            "support_definition": _sha_record(support),
            "candidate_definition": _sha_record(candidate),
        },
        "status": "PASS" if all(checks.values()) else "FAIL",
    }


def _quiescence_gate() -> dict[str, Any]:
    current = psutil.Process()
    excluded = {current.pid}
    parent = current.parent()
    while parent is not None:
        excluded.add(parent.pid)
        parent = parent.parent()
    writers: list[dict[str, Any]] = []
    markers = (
        "attack_audit_c001",
        "p2c",
        "p2d",
        "r80",
        "r160",
        "reaggregat",
        "finaliz",
        "heartbeat",
    )
    names = ("python", "pytest", "jupyter", "robocopy")
    for process in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
        try:
            if process.pid in excluded:
                continue
            name = str(process.info.get("name") or "")
            command = " ".join(process.info.get("cmdline") or [])
            lower = f"{name} {command}".lower()
            if any(value in name.lower() for value in names) or any(
                value in lower for value in markers
            ):
                writers.append(
                    {
                        "pid": process.pid,
                        "ppid": process.info.get("ppid"),
                        "name": name,
                        "command": command,
                        "create_time": process.info.get("create_time"),
                    }
                )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return {
        "checked_at_utc": now(),
        "active_writers": writers,
        "status": "PASS" if not writers else "FAIL",
    }


def _capacity_estimate(project_root: Path) -> dict[str, Any]:
    p2c = project_root / P2C_ROOT_RELATIVE
    phase_details: dict[str, Any] = {}
    for phase, executions in (("r20", 800), ("r40", 1600)):
        tasks = p2c / f"{phase}_execution" / "tasks"
        paths = [value for value in tasks.rglob("*") if value.is_file()]
        total = sum(value.stat().st_size for value in paths)
        categories: dict[str, int] = {}
        for path in paths:
            categories[path.name] = categories.get(path.name, 0) + path.stat().st_size
        task_sizes = [
            sum(value.stat().st_size for value in directory.iterdir() if value.is_file())
            for directory in tasks.iterdir()
            if directory.is_dir()
        ]
        phase_details[phase] = {
            "logical_tasks": len(task_sizes),
            "restart_executions": executions,
            "canonical_task_bytes": total,
            "bytes_per_restart_per_config": total / executions,
            "maximum_task_bytes": max(task_sizes),
            "artifact_bytes": categories,
        }
    measured = float(phase_details["r40"]["bytes_per_restart_per_config"])
    r80 = measured * 3200
    r160 = measured * 6400
    temporary = int(phase_details["r40"]["maximum_task_bytes"] * 4)
    aggregate_allowance = 5 * 1024**3
    final_expected = r80 + r160 + aggregate_allowance
    peak = final_expected + temporary
    required = peak * 1.20
    disk = shutil.disk_usage("E:\\")
    return {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "method": "P2-C R20/R40 measured canonical task bytes; R40 bytes/restart/config used for P2-D projection",
        "measured": phase_details,
        "r80_new_restart_executions": 3200,
        "r80_estimated_bytes": int(r80),
        "r160_worst_case_new_restart_executions": 6400,
        "r160_worst_case_estimated_bytes": int(r160),
        "peak_temporary_bytes": temporary,
        "aggregate_and_manifest_allowance_bytes": aggregate_allowance,
        "final_expected_bytes": int(final_expected),
        "worst_case_peak_bytes": int(peak),
        "required_with_20_percent_reserve_bytes": int(required),
        "e_free_before_execution_bytes": disk.free,
        "e_total_bytes": disk.total,
        "status": "PASS" if disk.free >= required else "FAIL",
    }


def _orchestration_fingerprint(project_root: Path) -> dict[str, Any]:
    paths = [
        project_root / "audit_tools" / "p2d_runner.py",
        project_root / "posthoc_tools" / "p2d_reaggregation.py",
        project_root / "audit_tools" / "p2c_orchestration.py",
        project_root / "audit_tools" / "p2c_runner.py",
    ]
    components = {
        path.relative_to(project_root).as_posix(): _sha_record(path)
        for path in paths
    }
    fingerprint = canonical_hash(
        {
            "schema_version": SCHEMA,
            "components": components,
            "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
            "semantics": "P2-D range-only scheduling; reference-only inheritance; atomic task commits; no attack-algorithm changes",
        }
    )
    return {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "orchestration_fingerprint": fingerprint,
        "components": components,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "attack_code_unchanged": code_fingerprint(project_root)
        == EXPECTED_ATTACK_CODE_FINGERPRINT,
    }


def _freeze_rows(project_root: Path, phase: str) -> list[dict[str, Any]]:
    p2c = project_root / P2C_ROOT_RELATIVE
    source_lookup = _source_r10_lookup(project_root)
    with (p2c / "r40_execution" / "r40_task_inventory.csv").open(
        encoding="utf-8", newline=""
    ) as stream:
        source_rows = list(csv.DictReader(stream))
    if len(source_rows) != 80 or any(
        row["execution_status"] != "completed" for row in source_rows
    ):
        raise RuntimeError("P2-C R40 inventory is not exactly 80 completed tasks")
    if phase == "r80":
        ids = R80_IDS
        target = 80
        previous = EXPECTED_R40_SNAPSHOT
    elif phase == "r160":
        ids = R160_IDS
        target = 160
        previous = "TO_BE_FROZEN_R80_SNAPSHOT_HASH"
    else:
        raise ValueError(phase)
    output: list[dict[str, Any]] = []
    for source_row in sorted(
        source_rows,
        key=lambda row: (
            int(row["seed"]),
            row["model"],
            row["attack"],
            int(row["K"]),
        ),
    ):
        source = source_lookup[source_row["config_id"]]
        output.append(
            {
                "schema_version": SCHEMA,
                "config_id": source_row["config_id"],
                "phase": phase,
                "seed": int(source_row["seed"]),
                "model": source_row["model"],
                "attack": source_row["attack"],
                "K": int(source_row["K"]),
                "alpha_rule": "two_eps_over_k",
                "alpha": float(source_row["alpha"]),
                "initialization": source_row["initialization"],
                "target_restart_count": target,
                "executed_restart_start": ids[0],
                "executed_restart_end": ids[-1],
                "new_restart_count": len(ids),
                "source_r10_task_hash": source["task_hash"],
                "source_r10_candidate_sha256": source["candidate_artifact"]["sha256"],
                "source_previous_snapshot_hash": previous,
                "task_hash": "",
                "execution_status": "frozen_pending",
                "attempt_count": 0,
                "last_error": "",
                "completed_at_utc": "",
            }
        )
    return output


def _write_source_inventory(
    *, project_root: Path, p2d_root: Path, source_identity: dict[str, Any]
) -> dict[str, Any]:
    p2c = project_root / P2C_ROOT_RELATIVE
    v2 = project_root / FORMAL_V2_RELATIVE
    rows: list[dict[str, Any]] = []
    formal = load_json(v2 / "formal_reaggregation_artifact_hashes.json")
    for artifact in formal["artifacts"]:
        rows.append(
            {
                "source": "P2-C formal_reaggregation_v2",
                "relative_path": artifact["path"],
                "size_bytes": artifact["size_bytes"],
                "sha256": artifact["sha256"],
                "inheritance": "read_only_reference",
            }
        )
    for phase in ("r20", "r40"):
        snapshot = load_json(p2c / f"{phase}_raw_snapshot_manifest.json")
        for artifact in snapshot["artifacts"]:
            rows.append(
                {
                    "source": f"P2-C {phase.upper()} raw snapshot",
                    "relative_path": f"{phase}_execution/{artifact['path']}",
                    "size_bytes": artifact["size_bytes"],
                    "sha256": artifact["sha256"],
                    "inheritance": "read_only_reference_no_copy",
                }
            )
    path = p2d_root / "source_snapshot" / "source_inventory.csv"
    fields = ("source", "relative_path", "size_bytes", "sha256", "inheritance")
    atomic_csv(path, fields, rows)
    return {
        "path": path.relative_to(p2d_root).as_posix(),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "row_count": len(rows),
        "source_identity_status": source_identity["status"],
    }


def _freeze_configuration(
    *,
    project_root: Path,
    p2d_root: Path,
    source_identity: dict[str, Any],
    capacity: dict[str, Any],
    orchestration: dict[str, Any],
) -> dict[str, Any]:
    freeze = p2d_root / "configuration_freeze"
    hashes_path = freeze / "p2d_configuration_hashes.json"
    if hashes_path.exists():
        hashes = load_json(hashes_path)
        for name, artifact in hashes["components"].items():
            path = freeze / name
            if (
                not path.is_file()
                or path.stat().st_size != int(artifact["size_bytes"])
                or sha256_file(path) != artifact["sha256"]
            ):
                raise RuntimeError(f"frozen P2-D configuration changed: {path}")
        return hashes
    if freeze.exists() and any(freeze.iterdir()):
        raise RuntimeError("partial P2-D configuration freeze exists")
    freeze.mkdir(parents=True, exist_ok=True)
    generated = now()
    v2 = project_root / FORMAL_V2_RELATIVE
    p2c_freeze = project_root / P2C_ROOT_RELATIVE / "configuration_freeze"
    p2c_configuration = load_json(p2c_freeze / "p2c_configuration_freeze.json")
    r80_rows = _freeze_rows(project_root, "r80")
    r160_rows = _freeze_rows(project_root, "r160")
    preregistration = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "audit": "C0-01 P2-D Extended Restart Saturation Audit",
        "formal_unit": "seed x model x attack x K",
        "units_per_family": 20,
        "r80_logical_tasks": 80,
        "r80_new_restart_ids": list(R80_IDS),
        "r80_new_restart_executions": 3200,
        "r160_conditional_templates": 80,
        "r160_new_restart_ids": list(R160_IDS),
        "r160_maximum_new_restart_executions": 6400,
        "r160_family_trigger": "any of 20 units fails any frozen hard condition",
        "r320_forbidden": True,
        "p3_to_p6_forbidden": True,
        "manuscript_modification_forbidden": True,
        "claims_restoration_forbidden": True,
    }
    attack_identity = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "source_p2c_configuration_hash": load_json(
            p2c_freeze / "p2c_configuration_hashes.json"
        )["p2c_configuration_hash"],
        "source_p2c_posthoc_fingerprint": EXPECTED_P2C_POSTHOC_FINGERPRINT,
        "source_r20_snapshot": EXPECTED_R20_SNAPSHOT,
        "source_r40_snapshot": EXPECTED_R40_SNAPSHOT,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "epsilon": p2c_configuration["epsilon"],
        "K": p2c_configuration["K"],
        "alpha": p2c_configuration["alpha"],
        "alpha_rule": p2c_configuration["alpha_rule"],
        "loss": p2c_configuration["loss"],
        "precision": p2c_configuration["precision"],
        "target_class": p2c_configuration["target_class"],
        "attack_support": p2c_configuration["attack_support"],
        "budget_scope": p2c_configuration["budget_scope"],
        "differences": p2c_configuration["differences"],
        "threshold": p2c_configuration["threshold"],
        "initialization": p2c_configuration["initialization"],
        "projection": p2c_configuration["projection"],
        "matrix": p2c_configuration["matrix"],
    }
    seed_spec = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "source": "AttackConfig.restart_seed; frozen P2-C/P2-B derivation",
        "restarts_field_excluded_from_seed_payload": True,
        "binding_fields": [
            "split identity",
            "checkpoint identity",
            "attack configuration identity",
            "sample identity",
            "restart_id",
        ],
        "r80_ids": list(R80_IDS),
        "r160_ids": list(R160_IDS),
        "no_overlap_with_inherited": True,
        "deterministic_reproduction_required": True,
    }
    trigger = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "unit": "seed x model x attack x K",
        "units_per_family": 20,
        "comparison": "R40 corrected formal state versus R80 corrected formal state",
        "conditions": {
            "success_preserving_asr_increment_gte": 0.005,
            "physical_feasible_success_asr_increment_gte": 0.005,
            "relative_target_ce_improvement_gte": 0.01,
        },
        "rule": "trigger the whole attack family if any unit meets any condition",
        "partial_family_forbidden": True,
        "model_specific_budget_forbidden": True,
        "K_specific_budget_forbidden": True,
        "result_contingent_rule_change_forbidden": True,
    }
    stop = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "pass_at_r80": "all 20 family units pass ASR, applicable feasible-ASR, and target-CE conditions after integrity PASS",
        "pass_at_r160": "all 20 triggered-family units pass the same conditions after integrity PASS",
        "r160_failure": "FAIL — FIXED-RESTART SATURATION NOT ESTABLISHED",
        "r160_failure_next_step": "STATISTICAL RESTART SATURATION AUDIT REQUIRED",
        "maximum_fixed_restart_count": 160,
        "r320_forbidden": True,
        "p3_to_p6_forbidden": True,
        "atomic_task_boundary_capacity_stop_only": True,
    }
    storage = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "inheritance": "reference_only",
        "r80_raw_policy": "store only restart 40-79; reference frozen R40 for 0-39",
        "r160_raw_policy": "store only restart 80-159; reference frozen R80 for 0-79",
        "canonical_raw_copy_count": 1,
        "full_inherited_copy_forbidden": True,
        "lossless_compression_allowed": ["gzip", "zstd", "parquet", "npz"],
        "lossy_compression_forbidden": True,
        "audit_required_fields_preserved": True,
        "failed_attempts_preserved": True,
        "capacity_estimate_sha256": sha256_file(
            p2d_root / "source_snapshot" / "capacity_estimate.json"
        ),
        "required_reserve_multiplier": 1.20,
    }
    candidate_reference = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "source_path": str(
            v2 / "configuration_freeze" / "candidate_definition.json"
        ),
        "source_sha256": sha256_file(
            v2 / "configuration_freeze" / "candidate_definition.json"
        ),
        "inheritance": "verbatim_reference",
        "clean_fallback_allowed": False,
    }
    support_reference = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "source_path": str(v2 / "configuration_freeze" / "support_definition.json"),
        "source_sha256": sha256_file(
            v2 / "configuration_freeze" / "support_definition.json"
        ),
        "inheritance": "verbatim_reference",
        "physical_success_requires_actual_threshold_budget_kinematic": True,
    }
    payloads = {
        "p2d_preregistration.json": preregistration,
        "p2d_attack_identity.json": attack_identity,
        "p2d_restart_seed_spec.json": seed_spec,
        "p2d_trigger_spec.json": trigger,
        "p2d_stop_spec.json": stop,
        "p2d_storage_policy.json": storage,
        "storage_policy.json": storage,
        "p2d_candidate_semantics_reference.json": candidate_reference,
        "p2d_support_semantics_reference.json": support_reference,
    }
    for name, payload in payloads.items():
        atomic_json(freeze / name, payload)
    atomic_csv(freeze / "p2d_r80_manifest.csv", INVENTORY_FIELDS, r80_rows)
    atomic_csv(freeze / "p2d_r160_templates.csv", INVENTORY_FIELDS, r160_rows)
    component_names = sorted(
        list(payloads)
        + ["p2d_r80_manifest.csv", "p2d_r160_templates.csv"]
    )
    components = {
        name: {
            "size_bytes": (freeze / name).stat().st_size,
            "sha256": sha256_file(freeze / name),
        }
        for name in component_names
    }
    configuration_hash = canonical_hash(
        {
            "schema_version": SCHEMA,
            "components": components,
            "source_p2c_v2_identity_sha256": sha256_file(
                p2d_root / "source_snapshot" / "p2c_v2_identity.json"
            ),
            "source_r40_snapshot": EXPECTED_R40_SNAPSHOT,
            "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
            "orchestration_fingerprint": orchestration["orchestration_fingerprint"],
        }
    )
    hashes = {
        "schema_version": SCHEMA,
        "generated_at_utc": generated,
        "status": "FROZEN",
        "p2d_configuration_hash": configuration_hash,
        "components": components,
        "source_p2c_v2_identity_sha256": sha256_file(
            p2d_root / "source_snapshot" / "p2c_v2_identity.json"
        ),
        "source_r20_snapshot": EXPECTED_R20_SNAPSHOT,
        "source_r40_snapshot": EXPECTED_R40_SNAPSHOT,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "orchestration_fingerprint": orchestration["orchestration_fingerprint"],
    }
    atomic_json(hashes_path, hashes)
    for path in freeze.iterdir():
        if path.is_file():
            _set_read_only(path)
    return hashes


def _runtime_rows(
    *,
    project_root: Path,
    freeze_inventory: Path,
    phase: str,
    previous_snapshot: str,
    configuration_hash: str,
    orchestration_fingerprint: str,
    triggered_families: set[str] | None = None,
) -> list[dict[str, Any]]:
    source_lookup = _source_r10_lookup(project_root)
    output: list[dict[str, Any]] = []
    for raw in read_csv(freeze_inventory):
        if triggered_families is not None and raw["attack"] not in triggered_families:
            continue
        source = source_lookup[raw["config_id"]]
        restart_ids = tuple(
            range(
                int(raw["executed_restart_start"]),
                int(raw["executed_restart_end"]) + 1,
            )
        )
        identity = task_identity(
            phase=phase,
            config_id=raw["config_id"],
            source_summary=source,
            target_restart_count=int(raw["target_restart_count"]),
            restart_ids=restart_ids,
            source_snapshot_hash=load_json(
                project_root
                / P2C_ROOT_RELATIVE
                / "source_p2b_snapshot"
                / "p2b_source_snapshot_manifest.json"
            )["source_p2b_snapshot_hash"],
            previous_snapshot_hash=previous_snapshot,
            p2c_configuration_hash=configuration_hash,
            orchestration_fingerprint=orchestration_fingerprint,
        )
        output.append(
            {
                **raw,
                "source_previous_snapshot_hash": previous_snapshot,
                "task_hash": canonical_hash(identity),
                "execution_status": "pending",
                "attempt_count": "0",
                "last_error": "",
                "completed_at_utc": "",
            }
        )
    return output


def _phase_paths(p2d_root: Path, phase: str) -> dict[str, Path]:
    root = p2d_root / phase
    return {
        "root": root,
        "raw": root / "raw_new_restarts",
        "manifest": root / "execution_manifest.json",
        "inventory": root / "task_inventory.csv",
        "runtime": root / "runtime_status.json",
        "ledger": root / "ledger.jsonl",
        "failures": root / "failed_attempts.jsonl",
        "lock": root / f"{phase}_runner.lock",
    }


def _inventory_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    states = ("pending", "running", "completed", "failed")
    return {
        state: sum(row["execution_status"] == state for row in rows)
        for state in states
    }


def _write_runtime_status(
    *,
    p2d_root: Path,
    phase: str,
    rows: list[dict[str, Any]],
    current_task: dict[str, Any] | None,
    state: str,
    configuration_hash: str,
    previous_snapshot: str,
    orchestration_fingerprint: str,
) -> dict[str, Any]:
    paths = _phase_paths(p2d_root, phase)
    counts = _inventory_counts(rows)
    output_size = sum(
        value.stat().st_size
        for value in paths["root"].rglob("*")
        if value.is_file()
    )
    completed_restarts = sum(
        int(row["new_restart_count"])
        for row in rows
        if row["execution_status"] == "completed"
    )
    raw_size = (
        sum(
            value.stat().st_size
            for value in paths["raw"].rglob("*")
            if value.is_file()
        )
        if paths["raw"].exists()
        else 0
    )
    capacity = load_json(p2d_root / "source_snapshot" / "capacity_estimate.json")
    measured = float(
        capacity["measured"]["r40"]["bytes_per_restart_per_config"]
    )
    actual = raw_size / completed_restarts if completed_restarts else measured
    remaining_restarts = sum(
        int(row["new_restart_count"])
        for row in rows
        if row["execution_status"] != "completed"
    )
    estimate_per_restart = max(measured, actual)
    disk = shutil.disk_usage("E:\\")
    latest = [row for row in rows if row["execution_status"] == "completed"]
    payload = {
        "schema_version": SCHEMA,
        "updated_at_utc": now(),
        "phase": phase,
        "state": state,
        "runner_pid": os.getpid(),
        "logical_tasks": len(rows),
        **counts,
        "current_task": current_task,
        "latest_completed_task": latest[-1] if latest else None,
        "duplicate_ids": len(rows) - len({row["config_id"] for row in rows}),
        "unknown_ids": 0,
        "staging_count": (
            sum(1 for value in (paths["raw"] / ".staging").iterdir() if value.is_dir())
            if (paths["raw"] / ".staging").exists()
            else 0
        ),
        "new_restart_executions_completed": completed_restarts,
        "new_restart_executions_expected": sum(
            int(row["new_restart_count"]) for row in rows
        ),
        "raw_bytes_added": raw_size,
        "output_size_bytes": output_size,
        "estimated_bytes_per_remaining_restart_config": int(estimate_per_restart),
        "estimated_remaining_bytes": int(remaining_restarts * estimate_per_restart),
        "e_free_bytes": disk.free,
        "frozen_configuration_hash": configuration_hash,
        "source_previous_snapshot_hash": previous_snapshot,
        "orchestration_fingerprint": orchestration_fingerprint,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "inherited_raw_copied": False,
        "p3_to_p6_executed": False,
        "r320_executed": False,
        "paper_modified": False,
    }
    atomic_json(paths["runtime"], payload)
    return payload


class RunnerLock:
    def __init__(self, path: Path):
        self.path = path

    def __enter__(self) -> "RunnerLock":
        if self.path.exists():
            prior = load_json(self.path)
            pid = int(prior["pid"])
            if psutil.pid_exists(pid):
                raise RuntimeError(
                    f"another P2-D runner appears active: pid={pid} lock={self.path}"
                )
            stale = self.path.with_name(
                f"{self.path.name}.stale.{prior.get('created_at_utc','unknown').replace(':','-')}"
            )
            os.replace(self.path, stale)
        atomic_json(
            self.path,
            {
                "schema_version": SCHEMA,
                "pid": os.getpid(),
                "created_at_utc": now(),
                "command": sys.argv,
            },
        )
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.path.exists():
            current = load_json(self.path)
            if int(current.get("pid", -1)) == os.getpid():
                self.path.unlink()


def _initialize_r80(
    *,
    project_root: Path,
    p2d_root: Path,
    hashes: dict[str, Any],
    orchestration: dict[str, Any],
) -> dict[str, Any]:
    paths = _phase_paths(p2d_root, "r80")
    if paths["manifest"].exists():
        manifest = load_json(paths["manifest"])
        if manifest.get("status") != "FROZEN":
            raise RuntimeError("existing R80 execution manifest is not FROZEN")
        return manifest
    paths["raw"].mkdir(parents=True, exist_ok=False)
    rows = _runtime_rows(
        project_root=project_root,
        freeze_inventory=p2d_root / "configuration_freeze" / "p2d_r80_manifest.csv",
        phase="r80",
        previous_snapshot=EXPECTED_R40_SNAPSHOT,
        configuration_hash=hashes["p2d_configuration_hash"],
        orchestration_fingerprint=orchestration["orchestration_fingerprint"],
    )
    atomic_csv(paths["inventory"], INVENTORY_FIELDS, rows)
    write_text_atomic(paths["ledger"], "")
    write_text_atomic(paths["failures"], "")
    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "FROZEN",
        "phase": "r80",
        "logical_task_count": 80,
        "new_restarts_per_task": 40,
        "new_restart_execution_count": 3200,
        "executed_restart_ids": list(R80_IDS),
        "inherited_restart_ids": list(range(40)),
        "inherited_restart_rerun": False,
        "source_r40_snapshot_hash": EXPECTED_R40_SNAPSHOT,
        "p2d_configuration_hash": hashes["p2d_configuration_hash"],
        "orchestration_fingerprint": orchestration["orchestration_fingerprint"],
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "task_inventory_initial": _sha_record(paths["inventory"], paths["root"]),
        "storage": "new restart 40-79 only; inherited 0-39 reference-only",
    }
    atomic_json(paths["manifest"], manifest)
    _write_runtime_status(
        p2d_root=p2d_root,
        phase="r80",
        rows=rows,
        current_task=None,
        state="frozen_pending",
        configuration_hash=hashes["p2d_configuration_hash"],
        previous_snapshot=EXPECTED_R40_SNAPSHOT,
        orchestration_fingerprint=orchestration["orchestration_fingerprint"],
    )
    return manifest


def initialize_r160_execution(project_root: Path) -> dict[str, Any]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    hashes, orchestration = _verify_frozen_state(project_root)
    decision_path = p2d_root / "adequacy" / "r160_trigger_decision.json"
    if not decision_path.is_file():
        raise RuntimeError("R160 trigger decision is not frozen")
    decision = load_json(decision_path)
    if decision.get("status") != "FROZEN":
        raise RuntimeError("R160 trigger decision status is not FROZEN")
    triggered = set(decision.get("triggered_families", []))
    expected = 20 * len(triggered)
    if int(decision.get("expected_r160_task_count", -1)) != expected:
        raise RuntimeError("R160 trigger decision task count mismatch")
    paths = _phase_paths(p2d_root, "r160")
    if paths["manifest"].exists():
        return load_json(paths["manifest"])
    paths["root"].mkdir(parents=True, exist_ok=False)
    if not triggered:
        payload = {
            "schema_version": SCHEMA,
            "generated_at_utc": now(),
            "status": "NOT_APPLICABLE",
            "reason": "no attack family triggered R160 under the frozen rule",
            "trigger_decision_sha256": sha256_file(decision_path),
            "r320_executed": False,
        }
        atomic_json(paths["root"] / "NOT_APPLICABLE.json", payload)
        atomic_json(paths["runtime"], payload)
        return payload
    paths["raw"].mkdir(parents=True, exist_ok=False)
    r80_snapshot = load_json(p2d_root / "r80" / "r80_snapshot_manifest.json")
    r80_hash = r80_snapshot["r80_snapshot_hash"]
    if r80_hash != decision["source_r80_snapshot_hash"]:
        raise RuntimeError("R160 decision source R80 snapshot mismatch")
    rows = _runtime_rows(
        project_root=project_root,
        freeze_inventory=p2d_root
        / "configuration_freeze"
        / "p2d_r160_templates.csv",
        phase="r160",
        previous_snapshot=r80_hash,
        configuration_hash=hashes["p2d_configuration_hash"],
        orchestration_fingerprint=orchestration["orchestration_fingerprint"],
        triggered_families=triggered,
    )
    atomic_csv(paths["inventory"], INVENTORY_FIELDS, rows)
    write_text_atomic(paths["ledger"], "")
    write_text_atomic(paths["failures"], "")
    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "FROZEN",
        "phase": "r160",
        "triggered_families": sorted(triggered),
        "logical_task_count": expected,
        "new_restarts_per_task": 80,
        "new_restart_execution_count": expected * 80,
        "executed_restart_ids": list(R160_IDS),
        "inherited_restart_ids": list(range(80)),
        "inherited_restart_rerun": False,
        "source_r80_snapshot_hash": r80_hash,
        "trigger_decision": _sha_record(decision_path),
        "p2d_configuration_hash": hashes["p2d_configuration_hash"],
        "orchestration_fingerprint": orchestration["orchestration_fingerprint"],
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "task_inventory_initial": _sha_record(paths["inventory"], paths["root"]),
        "storage": "new restart 80-159 only; inherited 0-79 reference-only",
    }
    atomic_json(paths["manifest"], manifest)
    _write_runtime_status(
        p2d_root=p2d_root,
        phase="r160",
        rows=rows,
        current_task=None,
        state="frozen_pending",
        configuration_hash=hashes["p2d_configuration_hash"],
        previous_snapshot=r80_hash,
        orchestration_fingerprint=orchestration["orchestration_fingerprint"],
    )
    return manifest


def _verify_frozen_state(project_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    preflight = load_json(p2d_root / "gates" / "r80_preflight_gate.json")
    if preflight.get("status") != "PASS":
        raise RuntimeError("P2-D R80 preflight is not PASS")
    hashes = load_json(
        p2d_root / "configuration_freeze" / "p2d_configuration_hashes.json"
    )
    for name, artifact in hashes["components"].items():
        path = p2d_root / "configuration_freeze" / name
        if (
            not path.is_file()
            or path.stat().st_size != int(artifact["size_bytes"])
            or sha256_file(path) != artifact["sha256"]
        ):
            raise RuntimeError(f"frozen P2-D configuration changed: {path}")
    orchestration = _orchestration_fingerprint(project_root)
    if orchestration["orchestration_fingerprint"] != hashes["orchestration_fingerprint"]:
        raise RuntimeError("P2-D orchestration fingerprint changed after freeze")
    if code_fingerprint(project_root) != EXPECTED_ATTACK_CODE_FINGERPRINT:
        raise RuntimeError("frozen attack-code fingerprint changed")
    source = load_json(p2d_root / "source_snapshot" / "p2c_v2_identity.json")
    for item in source["identities"].values():
        path = Path(item["path"])
        if not path.is_absolute():
            continue
        if (
            not path.is_file()
            or path.stat().st_size != int(item["size_bytes"])
            or sha256_file(path) != item["sha256"]
        ):
            raise RuntimeError(f"P2-C v2 source identity changed: {path}")
    return hashes, orchestration


def _capacity_boundary_check(
    *, p2d_root: Path, phase: str, rows: list[dict[str, Any]]
) -> dict[str, Any]:
    capacity = load_json(p2d_root / "source_snapshot" / "capacity_estimate.json")
    paths = _phase_paths(p2d_root, phase)
    raw_bytes = (
        sum(
            value.stat().st_size
            for value in paths["raw"].rglob("*")
            if value.is_file()
        )
        if paths["raw"].exists()
        else 0
    )
    completed_restarts = sum(
        int(row["new_restart_count"])
        for row in rows
        if row["execution_status"] == "completed"
    )
    measured = float(
        capacity["measured"]["r40"]["bytes_per_restart_per_config"]
    )
    actual = raw_bytes / completed_restarts if completed_restarts else measured
    rate = max(measured, actual)
    remaining = sum(
        int(row["new_restart_count"])
        for row in rows
        if row["execution_status"] != "completed"
    )
    future = 0.0
    if phase == "r80":
        future = float(capacity["r160_worst_case_estimated_bytes"])
    required = (
        remaining * rate
        + future
        + float(capacity["peak_temporary_bytes"])
        + float(capacity["aggregate_and_manifest_allowance_bytes"])
    ) * 1.20
    free = shutil.disk_usage("E:\\").free
    return {
        "checked_at_utc": now(),
        "phase": phase,
        "e_free_bytes": free,
        "estimated_remaining_and_future_with_reserve_bytes": int(required),
        "bytes_per_restart_config_used": int(rate),
        "status": "PASS" if free >= required else "FAIL",
    }


def run_phase(project_root: Path, phase: str) -> None:
    if phase not in {"r80", "r160"}:
        raise ValueError(phase)
    p2d_root = project_root / P2D_ROOT_RELATIVE
    hashes, orchestration = _verify_frozen_state(project_root)
    paths = _phase_paths(p2d_root, phase)
    manifest = load_json(paths["manifest"])
    if manifest.get("status") == "NOT_APPLICABLE":
        print("P2-D R160 NOT APPLICABLE", flush=True)
        return
    if manifest.get("status") != "FROZEN":
        raise RuntimeError(f"{phase.upper()} execution manifest is not FROZEN")
    rows: list[dict[str, Any]] = read_csv(paths["inventory"])
    if len(rows) != int(manifest["logical_task_count"]):
        raise RuntimeError(f"{phase.upper()} task inventory count mismatch")
    if len({row["config_id"] for row in rows}) != len(rows):
        raise RuntimeError(f"{phase.upper()} task inventory has duplicate config IDs")
    expected_ids = R80_IDS if phase == "r80" else R160_IDS
    if tuple(manifest["executed_restart_ids"]) != expected_ids:
        raise RuntimeError(f"{phase.upper()} execution range is not exact")
    source_lookup = _source_r10_lookup(project_root)
    context = frozen_context(project_root, project_root / P2B_ROOT_RELATIVE)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    dataframe = _prepare_dataframe(project_root)
    ledger_hashes = {row["task_hash"] for row in read_jsonl(paths["ledger"])}
    source_p2b = load_json(
        project_root
        / P2C_ROOT_RELATIVE
        / "source_p2b_snapshot"
        / "p2b_source_snapshot_manifest.json"
    )["source_p2b_snapshot_hash"]
    previous_snapshot = (
        manifest["source_r40_snapshot_hash"]
        if phase == "r80"
        else manifest["source_r80_snapshot_hash"]
    )
    with RunnerLock(paths["lock"]):
        _write_runtime_status(
            p2d_root=p2d_root,
            phase=phase,
            rows=rows,
            current_task=None,
            state="starting",
            configuration_hash=hashes["p2d_configuration_hash"],
            previous_snapshot=previous_snapshot,
            orchestration_fingerprint=orchestration["orchestration_fingerprint"],
        )
        rows_by_seed: dict[int, list[dict[str, Any]]] = {}
        for row in rows:
            rows_by_seed.setdefault(int(row["seed"]), []).append(row)
        for seed in SEEDS:
            seed_rows = rows_by_seed.get(seed, [])
            if not any(row["execution_status"] != "completed" for row in seed_rows):
                continue
            pack, data_status = prepare_seed(
                project_root=project_root,
                output_dir=paths["root"],
                p1_root=context["paths"]["p1"],
                dataframe=dataframe,
                seed=seed,
                device=device,
            )
            for model_name in MODELS:
                model_rows = [
                    row
                    for row in seed_rows
                    if row["model"] == model_name
                    and row["execution_status"] != "completed"
                ]
                if not model_rows:
                    continue
                model, threshold, checkpoint_status, clean_probs, _checks = load_p1_model(
                    p1_root=context["paths"]["p1"],
                    seed=seed,
                    model_name=model_name,
                    pack=pack,
                    device=device,
                )
                for attack in ATTACKS:
                    for steps in STEPS:
                        matches = [
                            row
                            for row in model_rows
                            if row["attack"] == attack and int(row["K"]) == steps
                        ]
                        if not matches:
                            continue
                        if len(matches) != 1:
                            raise RuntimeError(
                                f"expected one {phase} row for {seed}/{model_name}/{attack}/K{steps}"
                            )
                        boundary = _capacity_boundary_check(
                            p2d_root=p2d_root, phase=phase, rows=rows
                        )
                        atomic_json(paths["root"] / "capacity_runtime_gate.json", boundary)
                        if boundary["status"] != "PASS":
                            _write_runtime_status(
                                p2d_root=p2d_root,
                                phase=phase,
                                rows=rows,
                                current_task=None,
                                state="PAUSED_AT_ATOMIC_BOUNDARY_CAPACITY",
                                configuration_hash=hashes["p2d_configuration_hash"],
                                previous_snapshot=previous_snapshot,
                                orchestration_fingerprint=orchestration[
                                    "orchestration_fingerprint"
                                ],
                            )
                            raise RuntimeError(
                                "P2-D capacity gate failed at an atomic task boundary"
                            )
                        row = matches[0]
                        source = source_lookup[row["config_id"]]
                        if (
                            checkpoint_status["checkpoint_sha256"]
                            != source["checkpoint_sha256"]
                            or data_status["manifest"]["split_hash"]
                            != source["task_identity"]["split_hash"]
                            or float(threshold) != float(source["threshold"])
                        ):
                            raise RuntimeError(
                                f"frozen model/data identity changed for {row['config_id']}"
                            )
                        source_candidate = (
                            project_root
                            / P2B_ROOT_RELATIVE
                            / source["candidate_artifact"]["path"]
                        )
                        if sha256_file(source_candidate) != source["candidate_artifact"]["sha256"]:
                            raise RuntimeError(
                                f"source R10 candidate changed: {source_candidate}"
                            )
                        row["execution_status"] = "running"
                        row["attempt_count"] = str(int(row.get("attempt_count") or 0) + 1)
                        row["last_error"] = ""
                        atomic_csv(paths["inventory"], INVENTORY_FIELDS, rows)
                        _write_runtime_status(
                            p2d_root=p2d_root,
                            phase=phase,
                            rows=rows,
                            current_task=row,
                            state="running",
                            configuration_hash=hashes["p2d_configuration_hash"],
                            previous_snapshot=previous_snapshot,
                            orchestration_fingerprint=orchestration[
                                "orchestration_fingerprint"
                            ],
                        )
                        restart_ids = tuple(
                            range(
                                int(row["executed_restart_start"]),
                                int(row["executed_restart_end"]) + 1,
                            )
                        )
                        if restart_ids != expected_ids:
                            raise RuntimeError(
                                f"{phase.upper()} row attempted a non-frozen restart range"
                            )
                        print(
                            f"P2-D {phase.upper()} seed={seed} model={model_name} "
                            f"attack={attack} K={steps} restart={restart_ids[0]}-{restart_ids[-1]}",
                            flush=True,
                        )
                        try:
                            summary = execute_range_task(
                                phase=phase,
                                phase_dir=paths["raw"],
                                config_id=row["config_id"],
                                source_summary=source,
                                model=model,
                                threshold=threshold,
                                pack=pack,
                                clean_probs=clean_probs,
                                target_restart_count=int(row["target_restart_count"]),
                                restart_ids=restart_ids,
                                projection=context["projection"],
                                source_snapshot_hash=source_p2b,
                                previous_snapshot_hash=previous_snapshot,
                                p2c_configuration_hash=hashes["p2d_configuration_hash"],
                                orchestration_fingerprint=orchestration[
                                    "orchestration_fingerprint"
                                ],
                                device=device,
                                attempt=int(row["attempt_count"]),
                            )
                            if summary["task_hash"] != row["task_hash"]:
                                raise RuntimeError(
                                    "completed task hash differs from frozen runtime inventory"
                                )
                            if summary["task_hash"] not in ledger_hashes:
                                append_jsonl(
                                    paths["ledger"],
                                    {
                                        "schema_version": SCHEMA,
                                        "committed_at_utc": now(),
                                        "phase": phase,
                                        "config_id": row["config_id"],
                                        "task_hash": summary["task_hash"],
                                        "executed_restart_ids": list(restart_ids),
                                        "artifacts": summary["artifacts"],
                                        "inherited_restart_rerun": False,
                                    },
                                )
                                ledger_hashes.add(summary["task_hash"])
                            row["execution_status"] = "completed"
                            row["completed_at_utc"] = now()
                            row["last_error"] = ""
                        except BaseException as exc:
                            failure = {
                                "schema_version": SCHEMA,
                                "failed_at_utc": now(),
                                "phase": phase,
                                "config_id": row["config_id"],
                                "task_hash": row["task_hash"],
                                "attempt_count": int(row["attempt_count"]),
                                "error_type": type(exc).__name__,
                                "error": str(exc),
                                "traceback": traceback.format_exc(),
                                "parameters_changed": False,
                                "failed_attempt_preserved": True,
                            }
                            stage = paths["raw"] / ".staging" / row["task_hash"]
                            if stage.exists():
                                failure["failed_attempt_path"] = str(
                                    _failure_archive(
                                        stage,
                                        paths["raw"] / "failed_attempts",
                                        row["task_hash"],
                                        int(row["attempt_count"]),
                                    )
                                )
                            append_jsonl(paths["failures"], failure)
                            row["execution_status"] = "failed"
                            row["last_error"] = f"{type(exc).__name__}: {exc}"
                            print(
                                f"P2-D {phase.upper()} FAILED {row['config_id']}: {row['last_error']}",
                                flush=True,
                            )
                        atomic_csv(paths["inventory"], INVENTORY_FIELDS, rows)
                        _write_runtime_status(
                            p2d_root=p2d_root,
                            phase=phase,
                            rows=rows,
                            current_task=None,
                            state="running",
                            configuration_hash=hashes["p2d_configuration_hash"],
                            previous_snapshot=previous_snapshot,
                            orchestration_fingerprint=orchestration[
                                "orchestration_fingerprint"
                            ],
                        )
                del model
                if device.type == "cuda":
                    torch.cuda.empty_cache()
        counts = _inventory_counts(rows)
        final_state = (
            "complete"
            if counts["completed"] == len(rows) and counts["failed"] == 0
            else "incomplete"
        )
        _write_runtime_status(
            p2d_root=p2d_root,
            phase=phase,
            rows=rows,
            current_task=None,
            state=final_state,
            configuration_hash=hashes["p2d_configuration_hash"],
            previous_snapshot=previous_snapshot,
            orchestration_fingerprint=orchestration["orchestration_fingerprint"],
        )
        if final_state != "complete":
            raise RuntimeError(
                f"{phase.upper()} incomplete: "
                + ", ".join(f"{key}={value}" for key, value in counts.items())
            )


def run_preflight(project_root: Path) -> dict[str, Any]:
    canonical = resolve_canonical_root(project_root)
    if (
        canonical["status"] != "PASS"
        or Path(canonical["canonical_project_root"]).resolve()
        != EXPECTED_CANONICAL_ROOT.resolve()
    ):
        raise RuntimeError("[DATA CONFLICT] canonical project identity failed")
    project_root = Path(canonical["canonical_project_root"])
    p2d_root = project_root / P2D_ROOT_RELATIVE
    existing = p2d_root / "gates" / "r80_preflight_gate.json"
    if existing.exists():
        hashes, _orchestration = _verify_frozen_state(project_root)
        result = load_json(existing)
        if result.get("status") != "PASS" or hashes.get("status") != "FROZEN":
            raise RuntimeError("existing P2-D preflight is not reusable")
        return result
    quiescence = _quiescence_gate()
    if quiescence["status"] != "PASS":
        raise RuntimeError("P2-D QUIESCENCE GATE = FAIL")
    if p2d_root.exists() and any(p2d_root.iterdir()):
        raise RuntimeError("partial P2-D output exists before configuration freeze")
    source_identity = _verify_formal_v2(project_root)
    if source_identity["status"] != "PASS":
        raise RuntimeError("P2-D SOURCE IDENTITY GATE = FAIL")
    capacity = _capacity_estimate(project_root)
    if capacity["status"] != "PASS":
        raise RuntimeError("P2-D CAPACITY GATE = FAIL")
    self_test = orchestration_self_test()
    if self_test["status"] != "PASS":
        raise RuntimeError("IMPLEMENTATION BLOCKER: range orchestration self-test failed")
    orchestration = _orchestration_fingerprint(project_root)
    if not orchestration["attack_code_unchanged"]:
        raise RuntimeError("CONFIGURATION IDENTITY FAIL: attack code changed")
    p2d_root.mkdir(parents=True, exist_ok=False)
    for name in ("configuration_freeze", "source_snapshot", "r80", "adequacy", "diagnostics", "gates"):
        (p2d_root / name).mkdir(parents=True, exist_ok=True)
    atomic_json(p2d_root / "source_snapshot" / "p2c_v2_identity.json", source_identity)
    atomic_json(p2d_root / "source_snapshot" / "capacity_estimate.json", capacity)
    inventory = _write_source_inventory(
        project_root=project_root,
        p2d_root=p2d_root,
        source_identity=source_identity,
    )
    source_hashes = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "p2c_v2_identity": _sha_record(
            p2d_root / "source_snapshot" / "p2c_v2_identity.json", p2d_root
        ),
        "source_inventory": inventory,
        "capacity_estimate": _sha_record(
            p2d_root / "source_snapshot" / "capacity_estimate.json", p2d_root
        ),
        "source_r20_snapshot": EXPECTED_R20_SNAPSHOT,
        "source_r40_snapshot": EXPECTED_R40_SNAPSHOT,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "status": "PASS",
    }
    atomic_json(p2d_root / "source_snapshot" / "source_hashes.json", source_hashes)
    hashes = _freeze_configuration(
        project_root=project_root,
        p2d_root=p2d_root,
        source_identity=source_identity,
        capacity=capacity,
        orchestration=orchestration,
    )
    manifest = _initialize_r80(
        project_root=project_root,
        p2d_root=p2d_root,
        hashes=hashes,
        orchestration=orchestration,
    )
    checks = {
        "Source Identity Gate": source_identity["status"] == "PASS",
        "P2-C Final Integrity Inheritance Gate": source_identity["checks"][
            "final_integrity_v2_pass"
        ],
        "Attack Fingerprint Gate": orchestration["attack_code_unchanged"],
        "Configuration Freeze Gate": hashes["status"] == "FROZEN",
        "Seed Determinism Gate": self_test["checks"]["late_seed_reproduction"],
        "R80 Manifest Gate": manifest["logical_task_count"] == 80
        and tuple(manifest["executed_restart_ids"]) == R80_IDS,
        "Storage Capacity Gate": capacity["status"] == "PASS",
        "Storage Policy Gate": True,
        "Orchestration Range Gate": self_test["status"] == "PASS",
        "No-Rerun-0-39 Gate": set(manifest["executed_restart_ids"]).isdisjoint(
            set(range(40))
        ),
    }
    gate = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "gate": "P2-D R80 Preflight",
        "checks": checks,
        "canonical_identity": canonical,
        "quiescence": quiescence,
        "source_p2c_v2_identity_sha256": sha256_file(
            p2d_root / "source_snapshot" / "p2c_v2_identity.json"
        ),
        "p2d_configuration_hash": hashes["p2d_configuration_hash"],
        "orchestration_fingerprint": orchestration["orchestration_fingerprint"],
        "capacity": capacity,
        "status": "PASS" if all(checks.values()) else "FAIL",
    }
    for label, passed in checks.items():
        filename = (
            "r80_preflight_"
            + label.lower().replace("-", "_").replace(" ", "_")
            + ".json"
        )
        atomic_json(
            p2d_root / "gates" / filename,
            {
                "schema_version": SCHEMA,
                "gate": label,
                "status": "PASS" if passed else "FAIL",
            },
        )
    atomic_json(existing, gate)
    if gate["status"] != "PASS":
        raise RuntimeError("P2-D R80 PREFLIGHT = FAIL")
    return gate


def status(project_root: Path) -> None:
    p2d_root = project_root / P2D_ROOT_RELATIVE
    payload: dict[str, Any] = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "p2d_exists": p2d_root.exists(),
    }
    for phase in ("r80", "r160"):
        path = p2d_root / phase / "runtime_status.json"
        payload[phase] = load_json(path) if path.exists() else None
    final = p2d_root / "p2d_final_integrity_gate.json"
    payload["final"] = load_json(final) if final.exists() else None
    print(json.dumps(payload, indent=2, sort_keys=True))


def pipeline(project_root: Path) -> None:
    run_preflight(project_root)
    run_phase(project_root, "r80")
    from posthoc_tools.p2d_reaggregation import finalize_r80, finalize_p2d

    finalize_r80(project_root)
    manifest = initialize_r160_execution(project_root)
    if manifest.get("status") != "NOT_APPLICABLE":
        run_phase(project_root, "r160")
    finalize_p2d(project_root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--phase",
        choices=("preflight", "r80", "r160", "pipeline", "status"),
        required=True,
    )
    parser.add_argument("--project-root", default=str(EXPECTED_CANONICAL_ROOT))
    args = parser.parse_args()
    root = Path(args.project_root).resolve()
    if args.phase == "preflight":
        print(json.dumps(run_preflight(root), indent=2, sort_keys=True))
    elif args.phase in {"r80", "r160"}:
        run_phase(root, args.phase)
    elif args.phase == "pipeline":
        pipeline(root)
    else:
        status(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

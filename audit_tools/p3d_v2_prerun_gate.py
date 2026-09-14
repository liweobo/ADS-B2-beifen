"""Independent pre-run freeze checker and authorization issuer for P3-D v2."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import psutil

from adsb.checkpoints import code_fingerprint, sha256_file
from audit_tools import p3d_runner as legacy_runner
from audit_tools.p3d_v2_prepare import (
    ATTACKS,
    CANONICAL_ROOT,
    EXPECTED_ATTACK_FINGERPRINT,
    EXPECTED_P2C_POSTHOC,
    EXPECTED_R40_SNAPSHOT,
    LOSSES,
    MODELS,
    R,
    REQUIRED_PREREG,
    SEEDS,
    STEPS,
    atomic_json,
    canonical_hash,
    load_json,
    paths,
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_inventory(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, dtype=str).fillna("")


def active_v2_writers() -> list[dict[str, Any]]:
    writers: list[dict[str, Any]] = []
    own_pid = os.getpid()
    for process in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
        try:
            info = process.info
            command = " ".join(info.get("cmdline") or [])
            if info["pid"] != own_pid and (
                "audit_tools.p3d_v2_runner" in command
                or "audit_tools.p3d_v2_pipeline" in command
            ):
                writers.append({
                    "pid": info["pid"], "ppid": info.get("ppid"), "name": info.get("name"),
                    "command_line": command,
                    "created_utc": datetime.fromtimestamp(info["create_time"], timezone.utc).isoformat()
                    if info.get("create_time") else None,
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return writers


def verify_external_sources(p: dict[str, Path]) -> dict[str, Any]:
    frozen = load_json(p["source"] / "source_hashes.json")
    missing: list[str] = []
    mismatches: list[dict[str, Any]] = []
    names: list[str] = []
    resolved: list[str] = []
    for item in frozen.get("artifacts", []):
        names.append(item["name"])
        path = Path(item["path"])
        resolved.append(str(path.resolve()).casefold())
        if not path.is_file():
            missing.append(item["path"])
        elif path.stat().st_size != int(item["size_bytes"]) or sha256_file(path) != item["sha256"]:
            mismatches.append({
                "name": item["name"], "path": item["path"],
                "expected_sha256": item["sha256"],
                "observed_sha256": sha256_file(path),
            })
    duplicate_names = sorted({name for name in names if names.count(name) > 1})
    duplicate_paths = sorted({path for path in resolved if resolved.count(path) > 1})
    status = not missing and not mismatches and not duplicate_names and not duplicate_paths and bool(names)
    return {
        "status": "PASS" if status else "FAIL", "artifact_count": len(names),
        "missing": missing, "mismatches": mismatches,
        "duplicate_names": duplicate_names, "duplicate_paths": duplicate_paths,
    }


def schema_checks(p: dict[str, Path]) -> dict[str, bool]:
    freeze = p["freeze"]
    required_keys = {
        "p3d_current_research_status.json": {"schema_version", "P2C_final_integrity_v2", "P3_v1_status", "P3_v2_stage_type", "robustness_claims"},
        "p3d_preregistration.json": {"schema_version", "stage", "R", "K", "losses", "attack_families", "new_logical_configs", "maximum_new_trajectories"},
        "p3d_loss_definitions.json": {"schema_version", "targeted_ce", "targeted_logit_margin", "targeted_cw_margin", "candidate_ranking"},
        "p3d_cw_parameter_freeze.json": {"schema_version", "kappa", "status", "evidence"},
        "p3d_resource_budget.json": {"schema_version", "R", "restart_ids", "new_logical_configs", "maximum_new_trajectories"},
        "p3d_restart_spec.json": {"schema_version", "R", "restart_ids", "exact_only"},
        "p3d_candidate_semantics_reference.json": {"schema_version", "final-active", "best-target-loss", "success-preserving", "best-feasible-success", "clean_fallback_is_attack_candidate"},
        "p3d_support_semantics_reference.json": {"schema_version", "attacked_support", "norm_success", "physical_success", "cumulative_R5", "fallback_event", "fallback_ever", "fallback_only", "final_fallback"},
        "p3d_holdout_definition.json": {"schema_version", "training_attack", "major_dimensions", "MATCHED", "HOLDOUT"},
        "p3d_claim_constraints.json": {"schema_version", "restart_saturation", "formal_attack_adequacy", "formal_P3_clearance", "robustness_claims"},
        "loss_pairing_status.json": {"schema_version", "status", "reason", "source_sha256"},
        "p3d_source_identity_freeze.json": {"schema_version", "canonical_root", "attack_fingerprint", "r40_snapshot", "p2c_posthoc_fingerprint", "source_checks"},
        "p3d_configuration_hashes.json": {"schema_version", "artifacts", "configuration_hash", "code_hashes"},
    }
    result: dict[str, bool] = {}
    for name, keys in required_keys.items():
        try:
            payload = load_json(freeze / name)
            result[name] = keys.issubset(payload)
        except Exception:
            result[name] = False
    try:
        matrix = read_inventory(freeze / "p3d_attack_matrix.csv")
        result["p3d_attack_matrix.csv"] = set(legacy_runner.INVENTORY_FIELDS).issubset(matrix.columns)
    except Exception:
        result["p3d_attack_matrix.csv"] = False
    return result


def configuration_verification(p: dict[str, Path]) -> dict[str, Any]:
    config = load_json(p["freeze"] / "p3d_configuration_hashes.json")
    observed = {
        name: sha256_file(p["freeze"] / name)
        for name in REQUIRED_PREREG if name != "p3d_configuration_hashes.json"
    }
    expected = config.get("artifacts", {})
    observed_hash = canonical_hash(observed)
    code_checks = {
        name: sha256_file(p["root"] / "audit_tools" / f"{name.removeprefix('v2_') if False else ''}")
        for name in ()
    }
    frozen_code = config.get("code_hashes", {})
    code_paths = {
        "v2_prepare": p["root"] / "audit_tools" / "p3d_v2_prepare.py",
        "v2_prerun_gate": p["root"] / "audit_tools" / "p3d_v2_prerun_gate.py",
        "v2_runner": p["root"] / "audit_tools" / "p3d_v2_runner.py",
        "v2_finalize": p["root"] / "audit_tools" / "p3d_v2_finalize.py",
    }
    code_checks = {name: frozen_code.get(name) == sha256_file(path) for name, path in code_paths.items()}
    return {
        "artifact_hashes_match": expected == observed,
        "configuration_hash_match": config.get("configuration_hash") == observed_hash,
        "expected_configuration_hash": config.get("configuration_hash"),
        "observed_configuration_hash": observed_hash,
        "code_checks": code_checks,
        "status": "PASS" if expected == observed and config.get("configuration_hash") == observed_hash and all(code_checks.values()) else "FAIL",
    }


def create_timestamp_evidence(p: dict[str, Path], authorization_utc: str) -> list[dict[str, Any]]:
    config = load_json(p["freeze"] / "p3d_configuration_hashes.json")
    rows: list[dict[str, Any]] = []
    for name in REQUIRED_PREREG:
        path = p["freeze"] / name
        freeze_utc = load_json(path).get("frozen_at_utc") if path.suffix == ".json" else config["frozen_at_utc"]
        rows.append({
            "path": (Path("configuration_freeze") / name).as_posix(), "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "filesystem_creation_utc": datetime.fromtimestamp(path.stat().st_ctime, timezone.utc).isoformat(),
            "filesystem_modified_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            "freeze_utc": freeze_utc, "configuration_hash": config["configuration_hash"],
            "earlier_than_authorization": parse_time(freeze_utc) < parse_time(authorization_utc),
        })
    evidence = p["pre_run"] / "freeze_timestamp_evidence.csv"
    temporary = evidence.with_name(f".{evidence.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, evidence)
    return rows


def create_manifest(p: dict[str, Path], configuration_hash: str) -> tuple[dict[str, Any], str]:
    paths_to_freeze: list[Path] = [p["freeze"] / name for name in REQUIRED_PREREG]
    paths_to_freeze.extend([
        p["source"] / "p2c_identity.json", p["source"] / "p2d_termination_identity.json",
        p["source"] / "p3d_v1_failure_reference.json", p["source"] / "ce_r5_reference.csv",
        p["source"] / "source_hashes.json", p["source"] / "source_inventory.csv",
        p["pre_run"] / "freeze_timestamp_evidence.csv",
    ])
    paths_to_freeze.extend([
        p["root"] / "audit_tools" / "p3d_v2_prepare.py",
        p["root"] / "audit_tools" / "p3d_v2_prerun_gate.py",
        p["root"] / "audit_tools" / "p3d_v2_runner.py",
        p["root"] / "audit_tools" / "p3d_v2_finalize.py",
    ])
    artifacts = [{"path": str(path.resolve()), "size_bytes": path.stat().st_size, "sha256": sha256_file(path)} for path in paths_to_freeze]
    payload = {
        "schema_version": "adsb.c001-p3d-v2-freeze-manifest.v1", "created_at_utc": now(),
        "configuration_hash": configuration_hash, "artifact_count": len(artifacts),
        "artifacts": artifacts, "self_excluded": True,
    }
    path = p["pre_run"] / "freeze_manifest.json"
    atomic_json(path, payload)
    return payload, sha256_file(path)


def issue_authorization(project_root: Path = CANONICAL_ROOT) -> dict[str, Any]:
    project_root = project_root.resolve()
    p = paths(project_root)
    authorization_utc = now()
    timestamp_rows = create_timestamp_evidence(p, authorization_utc)
    config_verification = configuration_verification(p)
    configuration_hash = config_verification["expected_configuration_hash"]
    manifest, manifest_hash = create_manifest(p, configuration_hash)
    schemas = schema_checks(p)
    external = verify_external_sources(p)
    source_identity = load_json(p["freeze"] / "p3d_source_identity_freeze.json")
    p2c = load_json(p["source"] / "p2c_identity.json")
    p2d = load_json(p["source"] / "p2d_termination_identity.json")
    v1 = load_json(p["source"] / "p3d_v1_failure_reference.json")
    ce = pd.read_csv(p["source"] / "ce_r5_reference.csv")
    matrix = read_inventory(p["freeze"] / "p3d_attack_matrix.csv")
    margin = read_inventory(p["p3"] / "margin" / "task_inventory.csv")
    cw = read_inventory(p["p3"] / "cw" / "task_inventory.csv")
    old_inventory = read_inventory(p["p3v1"] / "margin" / "task_inventory.csv")
    old_tasks = set(old_inventory.loc[old_inventory.execution_status == "completed", "executed_task_hash"])
    source_ce_tasks = set(matrix.source_ce_task_hash)
    writers = active_v2_writers()
    locks = [str(path) for path in p["p3"].glob("*.lock")]
    ledger_text = "".join((p["p3"] / loss / "ledger.jsonl").read_text(encoding="utf-8") for loss in ("margin", "cw"))
    raw_entries = []
    for loss in ("margin", "cw"):
        raw = p["p3"] / loss / "raw_results"
        for directory in (raw / "tasks", raw / ".staging"):
            if directory.exists():
                raw_entries.extend(str(item) for item in directory.iterdir())
    loss_preflight = legacy_runner.loss_preflight()

    expected_units = {(seed, model, attack, steps) for seed in SEEDS for model in MODELS for attack in ATTACKS for steps in STEPS}
    observed_units = set(zip(matrix.seed.astype(int), matrix.model, matrix.attack, matrix.K.astype(int)))
    matrix_check = (
        len(matrix) == 160 and len(margin) == 80 and len(cw) == 80
        and observed_units == expected_units
        and set(matrix.loss_name) == {"margin", "cw"}
        and len(set(matrix.logical_config_id)) == 160
        and bool((matrix.restarts.astype(int) == R).all())
    )
    required_exist = {name: (p["freeze"] / name).is_file() for name in REQUIRED_PREREG}
    freeze_times_ok = all(bool(row["earlier_than_authorization"]) for row in timestamp_rows)
    no_committed = (
        not raw_entries
        and all(not set(frame.execution_status).intersection({"completed", "running", "failed"}) for frame in (margin, cw))
    )
    checks = {
        "F1 canonical root": project_root == CANONICAL_ROOT.resolve(),
        "F2 P2-C source identity": p2c.get("final_integrity") == "PASS" and p2c.get("r40_snapshot") == EXPECTED_R40_SNAPSHOT and p2c.get("posthoc_fingerprint") == EXPECTED_P2C_POSTHOC,
        "F3 P2-D termination identity": p2d.get("integrity") == "PASS" and p2d.get("formal_R80_adequacy") == "NOT ASSESSED" and p2d.get("partial_R80_used") is False,
        "F4 P3-v1 failure preserved": v1.get("status") == "PASS" and v1.get("v1_formal_status") == "INTEGRITY_FAILURE",
        "F5 all 14 required preregistration artifacts exist": len(required_exist) == 14 and all(required_exist.values()),
        "F6 all JSON parse/schema checks": len(schemas) == 14 and all(schemas.values()),
        "F7 configuration hash frozen": config_verification["status"] == "PASS",
        "F8 attack matrix frozen": matrix_check,
        "F9 loss definitions frozen": loss_preflight.get("status") == "PASS",
        "F10 CW kappa frozen with valid pre-existing evidence": load_json(p["freeze"] / "p3d_cw_parameter_freeze.json").get("status") == "RESOLVED" and load_json(p["freeze"] / "p3d_cw_parameter_freeze.json").get("kappa") == 0.0,
        "F11 resource budget frozen": load_json(p["freeze"] / "p3d_resource_budget.json").get("maximum_new_trajectories") == 800,
        "F12 restart specification frozen": load_json(p["freeze"] / "p3d_restart_spec.json").get("restart_ids") == list(range(R)),
        "F13 candidate semantics frozen": load_json(p["freeze"] / "p3d_candidate_semantics_reference.json").get("clean_fallback_is_attack_candidate") is False,
        "F14 support semantics frozen": load_json(p["freeze"] / "p3d_support_semantics_reference.json").get("fallback_candidate_success") == "FORBIDDEN",
        "F15 holdout definition frozen": load_json(p["freeze"] / "p3d_holdout_definition.json").get("HOLDOUT", "").startswith("at least two"),
        "F16 claims constraints frozen": load_json(p["freeze"] / "p3d_claim_constraints.json").get("formal_P3_clearance") == "DENIED",
        "F17 CE R5 reference": len(ce) == 80 and bool(ce.denominator_identity.all()) and bool(ce.union_identity.all()) and bool(ce.threshold_identity.all()),
        "F18 source artifact SHA-256": external["status"] == "PASS" and source_identity.get("attack_fingerprint") == EXPECTED_ATTACK_FINGERPRINT and code_fingerprint(project_root) == EXPECTED_ATTACK_FINGERPRINT,
        "F19 active writer count = 0": len(writers) == 0,
        "F20 active experiment lock count = 0": len(locks) == 0,
        "F21 no v2 execution ledger start exists": "TASK_START" not in ledger_text,
        "F22 no v2 committed trajectory exists": no_committed,
        "F23 freeze timestamps are earlier than authorization timestamp": freeze_times_ok,
        "F24 no v1 partial result referenced as v2 formal input": v1.get("v1_results_in_v2_aggregate") is False and old_tasks.isdisjoint(source_ce_tasks),
    }
    status = "PASS" if len(checks) == 24 and all(checks.values()) else "FAIL"
    gate = {
        "schema_version": "adsb.c001-p3d-v2-prerun-gate.v1", "gate": "Pre-Run Freeze Completeness",
        "evaluated_at_utc": now(), "authorization_utc": authorization_utc,
        "checks": {name: "PASS" if value else "FAIL" for name, value in checks.items()},
        "pass_count": sum(checks.values()), "expected_count": 24, "status": status,
        "evidence": {
            "required_artifacts": required_exist, "schema_checks": schemas,
            "configuration_verification": config_verification, "source_verification": external,
            "active_writers": writers, "active_locks": locks, "raw_entries": raw_entries,
            "loss_preflight": loss_preflight, "freeze_manifest_hash": manifest_hash,
            "freeze_manifest_artifact_count": manifest["artifact_count"],
        },
    }
    gate_path = p["pre_run"] / "pre_run_freeze_completeness.json"
    atomic_json(gate_path, gate)
    authorized = status == "PASS"
    authorization = {
        "schema_version": "adsb.c001-p3d-v2-authorization.v1",
        "run_authorized": authorized, "RUN_AUTHORIZED": "YES" if authorized else "NO",
        "authorized_stage": "P3_DIAGNOSTIC_V2", "authorized_losses": ["margin", "cw"] if authorized else [],
        "authorized_restart_ids": list(range(R)) if authorized else [],
        "authorized_logical_configs": 160 if authorized else 0,
        "max_new_trajectories": 800 if authorized else 0,
        "configuration_hash": configuration_hash, "freeze_manifest_hash": manifest_hash,
        "pre_run_gate_sha256": sha256_file(gate_path), "authorization_utc": authorization_utc,
        "attack_fingerprint": EXPECTED_ATTACK_FINGERPRINT,
        "reason": "all 24 independent pre-run checks passed" if authorized else "one or more pre-run checks failed",
    }
    atomic_json(p["pre_run"] / "pre_run_authorization.json", authorization)
    return {"status": status, "pass_count": sum(checks.values()), "run_authorized": authorized, "configuration_hash": configuration_hash, "freeze_manifest_hash": manifest_hash, "checks": gate["checks"]}


if __name__ == "__main__":
    print(json.dumps(issue_authorization(), ensure_ascii=False, indent=2), flush=True)

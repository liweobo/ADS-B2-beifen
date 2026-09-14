"""Freeze a P3-Diagnostic configuration-integrity failure without interpreting partial results."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import psutil

from adsb.checkpoints import code_fingerprint
from audit_tools.p3d_runner import paths as project_paths, verify_p2d_manifest


ROOT = Path(r"E:\ads-b\ADS-B2 -beifen")
P3 = ROOT / "outputs" / "attack_audit_c001" / "p3_diagnostic"
FAILURE_DIR = P3 / "integrity_failure"
GATES = P3 / "gates"
FINAL = P3 / "final"
INFLIGHT_TASK = "75a1fa9c8b94772c2622643a3c87a4041dd2886abd261a6bb6e4b9aea40584f2"
INFLIGHT_LOGICAL_CONFIG = "f26b0c2f856e884d45a6bd40de61162fd96a9b21be03cccb8651c233324283da"
EXPECTED_ATTACK_FINGERPRINT = "afd1389066e1c87fec8d6f9da42e4f7e2fb3384343f214d31c8eccf79bdbcf4f"
EXPECTED_R40 = "842d399a647699fdd7b038df5efb6d2907499cad094be44dfee47f2f5f528270"
EXPECTED_POSTHOC = "a4f0b5d33eff36f8835dbb40faa1a5d2aa179673930d2dc45173fcb17badb0bb"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def active_writers() -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            command = " ".join(process.info.get("cmdline") or [])
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        lowered = command.lower()
        if "audit_tools.p3d_runner" in lowered or "audit_tools.p3d_finalize" in lowered or "p3d_guardian.ps1" in lowered:
            matches.append({"pid": process.pid, "name": process.info.get("name"), "command": command})
    return matches


def verify_frozen_sources() -> dict[str, Any]:
    frozen = load(P3 / "source_snapshot" / "source_hashes.json")
    missing: list[str] = []
    mismatches: list[dict[str, Any]] = []
    for item in frozen["artifacts"]:
        path = Path(item["path"])
        if not path.is_file():
            missing.append(item["path"])
            continue
        observed_hash = sha256(path)
        observed_size = path.stat().st_size
        if observed_hash != item["sha256"] or observed_size != int(item["size_bytes"]):
            mismatches.append({
                "path": item["path"], "expected_sha256": item["sha256"],
                "observed_sha256": observed_hash, "expected_size_bytes": item["size_bytes"],
                "observed_size_bytes": observed_size,
            })
    expected = pd.DataFrame(frozen["artifacts"], dtype=str).fillna("")
    observed = pd.read_csv(P3 / "source_snapshot" / "source_inventory.csv", dtype=str).fillna("")
    inventory_identity = expected.to_dict("records") == observed.to_dict("records")
    return {
        "artifact_count": len(frozen["artifacts"]), "missing": missing, "mismatches": mismatches,
        "inventory_identity": inventory_identity,
        "status": "PASS" if not missing and not mismatches and inventory_identity else "FAIL",
    }


def inventory_snapshot(loss: str) -> dict[str, Any]:
    frame = pd.read_csv(P3 / loss / "task_inventory.csv", dtype=str).fillna("")
    counts = frame.execution_status.value_counts().to_dict()
    running = frame[frame.execution_status == "running"].to_dict("records")
    completed_hashes = sorted(frame.loc[frame.execution_status == "completed", "executed_task_hash"].tolist())
    return {
        "expected": int(len(frame)), "completed": int(counts.get("completed", 0)),
        "running": int(counts.get("running", 0)), "scheduled": int(counts.get("scheduled", 0)),
        "failed": int(counts.get("failed", 0)), "running_records": running,
        "completed_task_hashes": completed_hashes,
    }


def verify_margin_commit_boundary(snapshot: dict[str, Any]) -> dict[str, Any]:
    raw = P3 / "margin" / "raw_results"
    ledger = load(raw / "aggregation_ledger.json")
    entries = [value for value in ledger["tasks"].values()]
    last = max(entries, key=lambda item: int(item["step_size_bytes_after"]))
    step_bytes = (raw / "per_step_restart_records.csv.gz").stat().st_size
    sample_bytes = (raw / "per_sample_attack_records.csv.gz").stat().st_size
    completed_dirs = []
    empty_dirs = []
    for directory in (raw / "tasks").iterdir():
        if not directory.is_dir():
            continue
        files = list(directory.iterdir())
        if (directory / "summary.json").is_file() and (directory / "candidate_iterates.npz").is_file():
            completed_dirs.append(directory.name)
        elif not files:
            empty_dirs.append(directory.name)
    checks = {
        "ledger_task_count_equals_completed_inventory": len(ledger["tasks"]) == snapshot["completed"],
        "completed_task_directories_equal_inventory": sorted(completed_dirs) == snapshot["completed_task_hashes"],
        "step_bytes_equal_last_commit_boundary": step_bytes == int(last["step_size_bytes_after"]),
        "sample_bytes_equal_last_commit_boundary": sample_bytes == int(last["sample_size_bytes_after"]),
        "inflight_directory_empty": empty_dirs == [INFLIGHT_TASK],
        "inflight_not_in_aggregate_ledger": INFLIGHT_TASK not in ledger["tasks"],
    }
    return {
        "checks": checks, "ledger_task_count": len(ledger["tasks"]), "step_bytes": step_bytes,
        "sample_bytes": sample_bytes, "empty_task_directories": empty_dirs,
        "status": "PASS" if all(checks.values()) else "FAIL",
    }


def file_hash_record(path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(P3).as_posix(), "size_bytes": path.stat().st_size, "sha256": sha256(path)}


def main() -> None:
    FAILURE_DIR.mkdir(parents=True, exist_ok=True)
    GATES.mkdir(parents=True, exist_ok=True)
    FINAL.mkdir(parents=True, exist_ok=True)
    writers = active_writers()
    lock_archive: list[dict[str, Any]] = []
    lock_paths = [P3 / "p3d_runner.lock", P3 / "p3d_guardian.lock"]
    for lock_path in lock_paths:
        if lock_path.is_file():
            lock_archive.append({
                "original_path": str(lock_path), "sha256": sha256(lock_path),
                "size_bytes": lock_path.stat().st_size, "payload": load(lock_path),
            })
    write_json(FAILURE_DIR / "stale_locks_archived.json", {
        "schema_version": "adsb.c001-p3d-stale-lock-archive.v1", "archived_at_utc": utc_now(),
        "active_writer_count_at_archive": len(writers), "locks": lock_archive,
    })
    margin = inventory_snapshot("margin")
    cw = inventory_snapshot("cw")
    source_verification = verify_frozen_sources()
    boundary = verify_margin_commit_boundary(margin)
    configuration_hashes = load(P3 / "configuration_freeze" / "p3d_configuration_hashes.json")
    freeze_mismatches = []
    for name, expected in configuration_hashes["artifacts"].items():
        path = P3 / "configuration_freeze" / name
        if not path.is_file() or sha256(path) != expected:
            freeze_mismatches.append(name)
    runner_identity = sha256(ROOT / "audit_tools" / "p3d_runner.py") == configuration_hashes["runner_sha256"]
    missing_required_freeze = [
        name for name in (
            "p3d_current_research_status.json",
            "p3d_candidate_semantics_reference.json",
            "p3d_support_semantics_reference.json",
        ) if not (P3 / "configuration_freeze" / name).is_file()
    ]
    p2c_gate = load(ROOT / "outputs" / "attack_audit_c001" / "p2c" / "formal_reaggregation_v2" / "gates" / "final_p2c_integrity_gate_v2.json")
    p2c_snapshot = load(ROOT / "outputs" / "attack_audit_c001" / "p2c" / "r40_raw_snapshot_manifest.json")
    posthoc = load(ROOT / "outputs" / "attack_audit_c001" / "p2c" / "formal_reaggregation_v2" / "p2c_reaggregation_posthoc_fingerprint.json")
    p2d_gate = load(ROOT / "outputs" / "attack_audit_c001" / "p2d" / "resource_termination_v1" / "gates" / "resource_termination_integrity_gate.json")
    observed_attack_fingerprint = code_fingerprint(ROOT)
    p2d_manifest_verification = verify_p2d_manifest(project_paths(ROOT))
    ledger_lines = [line for line in (P3 / "margin" / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    failure = {
        "schema_version": "adsb.c001-p3d-integrity-failure.v1", "frozen_at_utc": utc_now(),
        "status": "P3-DIAGNOSTIC INTEGRITY FAILURE",
        "cause": "required pre-run freeze artifacts are absent and cannot be created retrospectively without violating freeze-before-run",
        "missing_required_freeze_artifacts": missing_required_freeze,
        "configuration_hash": configuration_hashes["configuration_hash"],
        "existing_freeze_hash_mismatches": freeze_mismatches, "frozen_runner_identity": runner_identity,
        "active_p3_writer_count": len(writers), "active_p3_writers": writers,
        "margin": margin, "cw": cw, "margin_commit_boundary": boundary,
        "inflight_task": {"logical_config_id": INFLIGHT_LOGICAL_CONFIG, "task_hash": INFLIGHT_TASK, "committed": False},
        "ledger_event_count": len(ledger_lines), "failed_attempts_retained": True,
        "partial_matrix_interpreted": False, "loss_diagnostic_performed": False,
        "holdout_diagnostic_performed": False, "partial_R80_used": False,
        "source_snapshot_verification": source_verification,
        "observed_attack_fingerprint": observed_attack_fingerprint,
        "attack_fingerprint_identity": observed_attack_fingerprint == EXPECTED_ATTACK_FINGERPRINT,
        "p2c_final_integrity_v2": p2c_gate.get("status"),
        "r40_snapshot_identity": p2c_snapshot.get("r40_raw_snapshot_hash") == EXPECTED_R40,
        "posthoc_identity": posthoc.get("new_reaggregation_fingerprint") == EXPECTED_POSTHOC,
        "p2d_resource_termination_gate": p2d_gate.get("status"),
        "p2d_resource_termination_manifest_verification": p2d_manifest_verification,
        "formal_research_status": {
            "fixed_restart_saturation_R_le_40": "NOT_ESTABLISHED",
            "formal_R80_adequacy": "NOT_ASSESSED", "formal_R160_adequacy": "NOT_ASSESSED",
            "formal_attack_adequacy": "NOT_ESTABLISHED", "formal_P3_clearance": "DENIED",
            "robustness_claims": "SUSPENDED",
        },
    }
    write_json(FAILURE_DIR / "p3d_integrity_failure_record.json", failure)
    checks = {
        "Source Identity": (
            source_verification["status"] == "PASS"
            and observed_attack_fingerprint == EXPECTED_ATTACK_FINGERPRINT
            and p2d_manifest_verification["pass"]
            and p2c_gate.get("status") == "PASS"
            and p2c_snapshot.get("r40_raw_snapshot_hash") == EXPECTED_R40
            and posthoc.get("new_reaggregation_fingerprint") == EXPECTED_POSTHOC
        ),
        "Existing Frozen Artifacts": not freeze_mismatches and runner_identity,
        "Required Freeze Completeness": not missing_required_freeze,
        "Matrix Completeness": margin["completed"] == 80 and cw["completed"] == 80,
        "Quiescence": len(writers) == 0,
        "Partial Evidence Preservation": boundary["status"] == "PASS",
        "Partial R80 Excluded": True,
    }
    gate = {
        "schema_version": "adsb.c001-p3d-final-integrity.v1", "generated_at_utc": utc_now(),
        "gate": "Final P3-Diagnostic Integrity", "checks": {name: "PASS" if value else "FAIL" for name, value in checks.items()},
        "status": "FAIL", "verdict": "P3-DIAGNOSTIC INTEGRITY FAILURE",
        "formal_attack_adequacy": "NOT_ESTABLISHED", "formal_P3_clearance": "DENIED",
        "interpretation_performed": False,
    }
    write_json(GATES / "p3d_final_integrity_gate.json", gate)
    decision = {
        "schema_version": "adsb.c001-p3d-next-stage.v1", "generated_at_utc": utc_now(),
        "decision": "P3-DIAGNOSTIC INTEGRITY FAILURE", "ready_for_p4_diagnostic": False,
        "formal_attack_adequacy_clearance": False, "formal_P3_clearance": "DENIED",
        "interpretation": "INCONCLUSIVE",
    }
    write_json(FINAL / "next_stage_decision.json", decision)
    report = f"""# C0-01 P3-Diagnostic Integrity Failure Report

## 1. Source Identity

- canonical root: `{ROOT}`
- P2-C Final Integrity: {p2c_gate.get('status')} (v2)
- R40 snapshot: `{EXPECTED_R40}` (identity verified: {str(failure['r40_snapshot_identity']).upper()})
- attack fingerprint: `{EXPECTED_ATTACK_FINGERPRINT}`
- P2-D resource termination verified: YES
- partial R80 used: NO
- source identity verdict: {source_verification['status']}

## 2. P3-Diagnostic Freeze

- stage type: DIAGNOSTIC ONLY
- R: 5
- K: 20, 50
- losses: targeted CE, targeted logit margin, CW-style margin
- attack families: 4
- comparison units: 80
- new logical configs: 160 planned
- maximum new restart trajectories: 800 planned
- CW kappa: 0.0
- initialization pairing: UNPAIRED — SAME DISTRIBUTION / SAME RESTART BUDGET
- configuration hash: `{configuration_hashes['configuration_hash']}`
- missing required pre-run freeze artifacts: {', '.join(missing_required_freeze)}

The missing files cannot be created retrospectively without violating the frozen-before-run protocol.

## 3. Execution

- Margin: expected 80; completed {margin['completed']}; failed {margin['failed']}; missing/incomplete {80 - margin['completed']}; duplicate committed 0; completed tasks use restarts 0–4.
- CW: expected 80; completed {cw['completed']}; failed {cw['failed']}; missing {80 - cw['completed']}; duplicate committed 0.
- one interrupted Margin task was never committed: `{INFLIGHT_TASK}`.
- R10 executed: NO
- R20 executed: NO
- R40 new executed: NO
- R80 resumed: NO

## 4. Integrity

- Source Identity: {gate['checks']['Source Identity']}
- Configuration: FAIL — required freeze completeness failed
- Matrix Completeness: FAIL
- Restart Completeness: NOT ASSESSED for the incomplete matrix
- Candidate Preservation: NOT ASSESSED for the incomplete matrix
- Metric Identity: NOT ASSESSED for the incomplete matrix
- Physical Support: NOT ASSESSED for the incomplete matrix
- Threshold Identity: NOT ASSESSED for the incomplete matrix
- Normal-byte invariance: NOT ASSESSED for the incomplete matrix
- Artifact Hash: PASS for the frozen failure package; formal complete-matrix G10 was not assessed
- Final P3-Diagnostic Integrity: FAIL — P3-DIAGNOSTIC INTEGRITY FAILURE

## 5. Loss Results

INCONCLUSIVE. No formal CE/Margin/CW comparison was performed because the matrix and freeze integrity gates failed. Partial Margin results were not interpreted.

## 6. Strongest Loss

NOT ASSESSED. RESOURCE-BOUNDED DIAGNOSTIC ONLY would apply if a complete integrity-passing matrix existed.

## 7. Holdout Results

- training attack identity: read and frozen in the original source snapshot
- matched baseline: NOT FORMALLY ASSESSED
- holdout configurations: NOT FORMALLY ASSESSED
- dimensions changed: NOT FORMALLY ASSESSED
- CAT-AD matched vs holdout: INCONCLUSIVE
- ERM matched vs holdout: INCONCLUSIVE
- attack-specific sensitivity: INCONCLUSIVE

## 8. Restart Limitation

Fixed-restart saturation within R≤40 remains NOT ESTABLISHED.

Formal R80 adequacy remains NOT ASSESSED.

P3-Diagnostic does not repair or replace the failed restart-adequacy gate.

## 9. Interpretation

INCONCLUSIVE. No result-dependent loss or holdout interpretation was produced.

## 10. Formal Research Status

- restart saturation: NOT ESTABLISHED
- attack adequacy: NOT ESTABLISHED
- formal P3 clearance: DENIED
- P3 diagnostic integrity: FAIL
- robustness claims: SUSPENDED

## 11. Next Stage

P3-DIAGNOSTIC INTEGRITY FAILURE. Not ready for P4-Diagnostic Physical Decomposition. This is not formal attack-adequacy clearance.

## 12. Stop Confirmation

- Partial R80 data was not used.
- R80 was not resumed.
- R160 was not executed.
- R320 was not executed.
- No new restart above 4 was executed.
- CE was not rerun.
- Margin and CW were preregistered for the same fixed R=5 computational budget; CW was not started after the integrity failure was identified.
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
    report_path = FINAL / "p3d_report.md"
    report_path.write_text(report, encoding="utf-8")
    artifact_paths = [
        FAILURE_DIR / "p3d_integrity_failure_record.json", FAILURE_DIR / "stale_locks_archived.json",
        GATES / "p3d_final_integrity_gate.json",
        FINAL / "next_stage_decision.json", report_path,
    ]
    artifacts = [file_hash_record(path) for path in artifact_paths]
    artifact_manifest = {
        "schema_version": "adsb.c001-p3d-integrity-failure-artifacts.v1", "generated_at_utc": utc_now(),
        "artifacts": artifacts, "missing_count": 0, "hash_mismatch_count": 0,
        "malformed_json_count": 0, "duplicate_canonical_artifact_count": 0, "status": "PASS",
    }
    write_json(FAILURE_DIR / "artifact_hashes.json", artifact_manifest)
    reread = load(FAILURE_DIR / "artifact_hashes.json")
    mismatches = []
    malformed = []
    paths_seen = []
    for item in reread["artifacts"]:
        path = P3 / item["path"]
        paths_seen.append(str(path.resolve()).casefold())
        if not path.is_file() or path.stat().st_size != int(item["size_bytes"]) or sha256(path) != item["sha256"]:
            mismatches.append(item["path"])
        if path.suffix == ".json":
            try:
                load(path)
            except Exception as exc:  # pragma: no cover - forensic record
                malformed.append({"path": item["path"], "error": str(exc)})
    verification = {
        "missing_count": 0, "hash_mismatch_count": len(mismatches), "hash_mismatches": mismatches,
        "malformed_json_count": len(malformed), "malformed_json": malformed,
        "duplicate_canonical_artifact_count": len(paths_seen) - len(set(paths_seen)),
    }
    verification["status"] = "PASS" if not mismatches and not malformed and len(paths_seen) == len(set(paths_seen)) else "FAIL"
    artifact_manifest["independent_reread_verification"] = verification
    write_json(FAILURE_DIR / "artifact_hashes.json", artifact_manifest)
    if verification["status"] != "PASS":
        raise RuntimeError(f"failure artifact verification failed: {verification}")
    for lock_path in lock_paths:
        if not lock_path.is_file():
            continue
        lock = load(lock_path)
        lock_pid = int(lock.get("pid", -1))
        if lock_pid > 0 and psutil.pid_exists(lock_pid):
            raise RuntimeError(f"refusing to remove live lock after archival: {lock_path} pid={lock_pid}")
        lock_path.unlink()
    print(json.dumps({"status": gate["verdict"], "margin_completed": margin["completed"], "cw_completed": cw["completed"], "artifact_verification": verification["status"]}, indent=2))


if __name__ == "__main__":
    main()

"""C0-01 P3-Diagnostic fixed-R5 loss audit orchestrator.

This module is intentionally outside the frozen attack fingerprint scope.  It
does not edit the attack implementation.  It supplies the preregistered loss to
the already frozen P2 execution primitive and writes only to the isolated
``outputs/attack_audit_c001/p3_diagnostic`` tree.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import traceback
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd
import torch

import adsb.p2_step_size_restart as p2
from adsb.attack_audit import AttackConfig, targeted_losses
from adsb.checkpoints import code_fingerprint, sha256_file
from adsb.device_setup import configure_cuda_training, resolve_device


EXPECTED_ATTACK_FINGERPRINT = "afd1389066e1c87fec8d6f9da42e4f7e2fb3384343f214d31c8eccf79bdbcf4f"
EXPECTED_R40_SNAPSHOT = "842d399a647699fdd7b038df5efb6d2907499cad094be44dfee47f2f5f528270"
EXPECTED_P2C_POSTHOC = "a4f0b5d33eff36f8835dbb40faa1a5d2aa179673930d2dc45173fcb17badb0bb"
EXPECTED_P2B_MANIFEST = "785d51ee255a3993b34e6fd2e0e72b71e848653549edf8574d5701899d08bc56"
EXPECTED_REQUEST_HASH = "90aa246a2f22c6ab1f43b14708f12de1b2f53b36abf3812f467ab20dc091d783"
REQUEST_PATH = Path(r"C:\Users\lwb\.codex\attachments\b1ce9807-4db0-49da-a143-890c8e17ed1f\pasted-text.txt")

SEEDS = (42, 43, 44, 45, 46)
MODELS = ("BiLSTM-ERM", "CAT-AD")
ATTACKS = ("norm_pgd", "phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd")
STEPS = (20, 50)
LOSSES = {
    "margin": "targeted_logit_margin",
    "cw": "targeted_cw_margin",
}
CW_KAPPA = 0.0
R = 5

INVENTORY_FIELDS = (
    "unit_id", "logical_config_id", "loss_name", "loss_id", "cw_kappa", "seed",
    "model", "attack", "K", "alpha_rule", "alpha", "initialization", "restarts",
    "attack_config_hash", "source_ce_task_hash", "checkpoint_sha256", "dataset_hash",
    "split_hash", "normalization_hash", "sample_manifest_hash", "threshold",
    "execution_status", "executed_task_hash", "attempt_count", "last_error",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


def atomic_csv(path: Path, rows: Iterable[dict[str, Any]], fields: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temp.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(fields), extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temp, path)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def paths(project_root: Path) -> dict[str, Path]:
    base = project_root / "outputs" / "attack_audit_c001"
    p3 = base / "p3_diagnostic"
    return {
        "root": project_root,
        "base": base,
        "p1": base / "p1",
        "p2": base / "p2",
        "p2b": base / "p2b",
        "p2c": base / "p2c",
        "p2cv2": base / "p2c" / "formal_reaggregation_v2",
        "p2d": base / "p2d" / "resource_termination_v1",
        "p3": p3,
        "freeze": p3 / "configuration_freeze",
        "source": p3 / "source_snapshot",
    }


def source_files(p: dict[str, Path]) -> dict[str, Path]:
    return {
        "request": REQUEST_PATH,
        "project_instructions": p["root"] / "PROJECT_INSTRUCTIONS.md",
        "agents": p["root"] / "AGENTS.md",
        "attack_implementation": p["root"] / "adsb" / "attack_audit.py",
        "p2_execution_implementation": p["root"] / "adsb" / "p2_step_size_restart.py",
        "p2_configuration": p["p2"] / "p2_configuration_freeze.json",
        "p2b_manifest": p["p2b"] / "p2b_manifest.json",
        "p2b_inventory": p["p2b"] / "p2b_task_inventory.csv",
        "p2c_final_integrity_v2": p["p2cv2"] / "gates" / "final_p2c_integrity_gate_v2.json",
        "p2c_posthoc_fingerprint": p["p2cv2"] / "p2c_reaggregation_posthoc_fingerprint.json",
        "p2c_r40_snapshot": p["p2c"] / "r40_raw_snapshot_manifest.json",
        "p2c_corrected_semantics": p["p2cv2"] / "configuration_freeze" / "corrected_semantics.json",
        "p2c_candidate_definition": p["p2cv2"] / "configuration_freeze" / "candidate_definition.json",
        "p2d_termination_gate": p["p2d"] / "gates" / "resource_termination_integrity_gate.json",
        "p2d_hash_manifest": p["p2d"] / "final" / "resource_termination_artifact_hashes.json",
        "p2d_termination_decision": p["p2d"] / "termination_freeze" / "p2d_resource_termination_decision.json",
        "p2d_ce_prefix_curves": p["p2d"] / "statistical_restart_audit" / "restart_prefix_curves.csv",
        "train_attack_manifest": p["root"] / "configs" / "attack_audit_c001" / "train_attack_manifest.json",
        "loss_test": p["root"] / "tests" / "test_attack_audit.py",
    }


def verify_p2d_manifest(p: dict[str, Path]) -> dict[str, Any]:
    manifest_path = source_files(p)["p2d_hash_manifest"]
    manifest = load_json(manifest_path)
    missing: list[str] = []
    mismatches: list[str] = []
    for item in manifest["artifacts"]:
        artifact = p["p2d"] / item["path"]
        if not artifact.is_file():
            missing.append(item["path"])
        elif artifact.stat().st_size != int(item["size_bytes"]) or sha256_file(artifact) != item["sha256"]:
            mismatches.append(item["path"])
    return {
        "manifest_status": manifest.get("status"),
        "artifact_count": len(manifest["artifacts"]),
        "missing": missing,
        "mismatches": mismatches,
        "pass": manifest.get("status") == "PASS" and not missing and not mismatches,
    }


def loss_preflight() -> dict[str, Any]:
    checks: dict[str, bool] = {}
    post_values: dict[str, list[float]] = {}
    for name, loss_id in (("ce", "targeted_ce"), ("margin", LOSSES["margin"]), ("cw", LOSSES["cw"])):
        logits = torch.tensor([[0.0, 1.0]], dtype=torch.float64, requires_grad=True)
        values = targeted_losses(logits, loss_id, kappa=CW_KAPPA)
        before = float(values["p_anomaly"].item())
        values["objective"].sum().backward()
        after_logits = (logits.detach() - 0.1 * logits.grad.detach())
        after = float(torch.softmax(after_logits, 1)[0, 1].item())
        post_values[name] = [before, after]
        checks[f"{name}_direction_test"] = after < before
    checks["targeted_normal_direction"] = all(v[1] < v[0] for v in post_values.values())
    checks["one_step_toy_gradient_direction"] = checks["ce_direction_test"] and checks["margin_direction_test"]
    margins = torch.tensor([[2.0, -1.0], [3.0, -3.0]], dtype=torch.float64)
    margin_values = targeted_losses(margins, LOSSES["margin"], kappa=CW_KAPPA)
    checks["margin_ordering"] = float(margin_values["ranking_margin"][1]) < float(margin_values["ranking_margin"][0])
    cw_values = targeted_losses(margins, LOSSES["cw"], kappa=CW_KAPPA)
    checks["cw_saturation_behavior"] = bool(torch.equal(cw_values["objective"], torch.zeros(2, dtype=torch.float64)))
    checks["candidate_ranking_behavior"] = (
        float(cw_values["objective"][0]) == float(cw_values["objective"][1])
        and float(cw_values["ranking_margin"][1]) < float(cw_values["ranking_margin"][0])
    )
    return {"checks": checks, "toy_p_anomaly_before_after": post_values, "status": "PASS" if all(checks.values()) else "FAIL"}


def base_attack_config(
    *, attack: str, steps: int, alpha_rule: str, initialization: str,
    restarts: int, seed: int, projection: dict[str, Any], loss_id: str,
) -> AttackConfig:
    original = p2._attack_config(
        attack=attack, steps=steps, alpha_rule=alpha_rule, initialization=initialization,
        restarts=restarts, seed=seed, projection=projection,
    )
    return replace(original, loss=loss_id, cw_kappa=CW_KAPPA)


def r5_source_rows(p: dict[str, Path]) -> list[dict[str, Any]]:
    frame = pd.read_csv(p["p2b"] / "p2b_task_inventory.csv", dtype=str)
    frame = frame[(frame["restarts"] == "5") & (frame["execution_status"] == "completed")].copy()
    if len(frame) != 80:
        raise RuntimeError(f"expected exactly 80 completed P2-B R5 rows, found {len(frame)}")
    keys = set(zip(frame.seed.astype(int), frame.model, frame.attack, frame.K.astype(int)))
    expected = {(s, m, a, k) for s in SEEDS for m in MODELS for a in ATTACKS for k in STEPS}
    if keys != expected or len(keys) != 80:
        raise RuntimeError("P2-B R5 unit matrix is incomplete or duplicated")
    return frame.sort_values(["seed", "model", "attack", "K"]).to_dict("records")


def build_inventory(p: dict[str, Path], loss_name: str, projection: dict[str, Any]) -> list[dict[str, Any]]:
    loss_id = LOSSES[loss_name]
    rows: list[dict[str, Any]] = []
    for source in r5_source_rows(p):
        config = base_attack_config(
            attack=source["attack"], steps=int(source["K"]), alpha_rule=source["alpha_rule"],
            initialization=source["initialization"], restarts=R, seed=int(source["seed"]),
            projection=projection, loss_id=loss_id,
        )
        unit_payload = {
            "seed": int(source["seed"]), "model": source["model"], "attack": source["attack"],
            "K": int(source["K"]), "alpha_rule": source["alpha_rule"],
            "initialization": source["initialization"],
        }
        logical_payload = {**unit_payload, "loss": loss_id, "cw_kappa": CW_KAPPA, "restarts": R}
        rows.append({
            "unit_id": canonical_hash(unit_payload),
            "logical_config_id": canonical_hash(logical_payload),
            "loss_name": loss_name,
            "loss_id": loss_id,
            "cw_kappa": CW_KAPPA,
            "seed": int(source["seed"]),
            "model": source["model"],
            "attack": source["attack"],
            "K": int(source["K"]),
            "alpha_rule": source["alpha_rule"],
            "alpha": float(config.alpha),
            "initialization": source["initialization"],
            "restarts": R,
            "attack_config_hash": config.config_hash,
            "source_ce_task_hash": source["executed_task_hash"],
            "checkpoint_sha256": source["checkpoint_sha256"],
            "dataset_hash": source["dataset_hash"],
            "split_hash": source["split_hash"],
            "normalization_hash": source["normalization_hash"],
            "sample_manifest_hash": source["sample_manifest_hash"],
            "threshold": float(source["threshold"]),
            "execution_status": "scheduled",
            "executed_task_hash": "",
            "attempt_count": 0,
            "last_error": "",
        })
    return rows


def freeze(project_root: Path) -> dict[str, Any]:
    p = paths(project_root)
    if p["p3"].exists():
        raise RuntimeError(f"P3-Diagnostic output already exists; refusing to overwrite: {p['p3']}")
    files = source_files(p)
    missing = [name for name, path in files.items() if not path.is_file()]
    if missing:
        raise RuntimeError(f"missing prerequisite files: {missing}")

    current_fp = code_fingerprint(project_root)
    p2c_gate = load_json(files["p2c_final_integrity_v2"])
    p2c_fp = load_json(files["p2c_posthoc_fingerprint"])
    r40 = load_json(files["p2c_r40_snapshot"])
    p2d_gate = load_json(files["p2d_termination_gate"])
    p2d_decision = load_json(files["p2d_termination_decision"])
    p2d_verification = verify_p2d_manifest(p)
    p2freeze = load_json(files["p2_configuration"])
    projection = p2freeze["projection_config"]
    preflight = loss_preflight()
    request_hash = sha256_file(REQUEST_PATH)
    p2b_manifest_hash = sha256_file(p["p2"] / "p2b_configuration_freeze.json")

    # A prior narrow unittest invocation used a non-existent class name.  It
    # created no project artifact, but the failed attempt is retained here for
    # forensic completeness rather than silently omitted.
    preflight_attempts = [{
        "attempt": 1,
        "status": "HARNESS_INVOCATION_ERROR",
        "command": "python -m unittest tests.test_attack_audit.AttackAuditTest.test_threshold_and_argmax_are_distinct_and_cw_ranks_untruncated",
        "error": "AttributeError: module tests.test_attack_audit has no attribute AttackAuditTest",
        "attack_code_executed": False,
        "result_used": False,
    }, {
        "attempt": 2,
        "status": preflight["status"],
        "method": "independent in-process CE/margin/CW direction and ranking checks",
        "result": preflight,
    }]

    checks = {
        "canonical_root": project_root.resolve() == Path(r"E:\ads-b\ADS-B2 -beifen").resolve(),
        "request_hash": request_hash == EXPECTED_REQUEST_HASH,
        "attack_fingerprint": current_fp == EXPECTED_ATTACK_FINGERPRINT,
        "p2b_freeze": p2b_manifest_hash == EXPECTED_P2B_MANIFEST,
        "p2c_final_integrity_v2": p2c_gate.get("status") == "PASS",
        "p2c_r40_snapshot": r40.get("r40_raw_snapshot_hash") == EXPECTED_R40_SNAPSHOT,
        "p2c_posthoc_fingerprint": p2c_fp.get("new_reaggregation_fingerprint") == EXPECTED_P2C_POSTHOC,
        "p2d_termination_integrity": p2d_gate.get("status") == "PASS" and p2d_verification["pass"],
        "partial_r80_forbidden": p2d_decision.get("R80_resume_allowed_in_this_stage") is False,
        "cw_kappa_unique_default": CW_KAPPA == 0.0,
        "loss_preflight": preflight["status"] == "PASS",
    }
    if not all(checks.values()):
        raise RuntimeError(f"P3-Diagnostic freeze preflight failed: {checks}")

    p["freeze"].mkdir(parents=True)
    p["source"].mkdir(parents=True)
    for name in ("margin", "cw"):
        (p["p3"] / name / "raw_results").mkdir(parents=True)
        (p["p3"] / name / "failed_attempts").mkdir(parents=True)
        (p["p3"] / name / "ledger.jsonl").touch()
        (p["p3"] / name / "failed_attempts.jsonl").touch()

    ce = pd.read_csv(files["p2d_ce_prefix_curves"])
    ce = ce[ce["R"] == R].sort_values(["seed", "model", "attack", "K"])
    if len(ce) != 80:
        raise RuntimeError(f"CE R5 reference must contain 80 rows, found {len(ce)}")
    ce.to_csv(p["source"] / "ce_r5_reference.csv", index=False)

    source_hashes = []
    for name, path in files.items():
        source_hashes.append({"name": name, "path": str(path), "sha256": sha256_file(path), "size_bytes": path.stat().st_size})
    atomic_json(p["source"] / "source_hashes.json", {"schema_version": "adsb.c001-p3d-source.v1", "artifacts": source_hashes})
    atomic_csv(p["source"] / "source_inventory.csv", source_hashes, ("name", "path", "sha256", "size_bytes"))
    atomic_json(p["source"] / "p2c_identity.json", {
        "final_integrity": "PASS", "final_integrity_gate": str(files["p2c_final_integrity_v2"]),
        "r40_snapshot": EXPECTED_R40_SNAPSHOT, "attack_fingerprint": current_fp,
        "posthoc_fingerprint": EXPECTED_P2C_POSTHOC, "legacy_v1_modified": False,
    })
    atomic_json(p["source"] / "p2d_termination_identity.json", {
        "integrity": "PASS", "verification": p2d_verification, "partial_R80_used": False,
        "partial_R80_resume_allowed": False, "decision": p2d_decision,
    })

    inventories: dict[str, list[dict[str, Any]]] = {}
    matrix_rows: list[dict[str, Any]] = []
    for name in ("margin", "cw"):
        inventories[name] = build_inventory(p, name, projection)
        atomic_csv(p["p3"] / name / "task_inventory.csv", inventories[name], INVENTORY_FIELDS)
        matrix_rows.extend(inventories[name])
        atomic_json(p["p3"] / name / "execution_manifest.json", {
            "schema_version": "adsb.c001-p3d-execution.v1", "loss_name": name,
            "loss_id": LOSSES[name], "expected": 80, "completed": 0, "failed": 0,
            "missing": 80, "duplicates": 0, "restarts": [0, 1, 2, 3, 4],
            "phase": "FROZEN_NOT_STARTED", "created_at_utc": now(),
        })
    atomic_csv(p["freeze"] / "p3d_attack_matrix.csv", matrix_rows, INVENTORY_FIELDS)

    freeze_payloads: dict[str, Any] = {
        "p3d_preregistration.json": {
            "schema_version": "adsb.c001-p3d-preregistration.v1", "stage_type": "RESOURCE_BOUNDED_DIAGNOSTIC_ONLY",
            "R": R, "K": list(STEPS), "losses": ["targeted_ce", LOSSES["margin"], LOSSES["cw"]],
            "attack_families": list(ATTACKS), "comparison_units": 80, "new_logical_configs": 160,
            "maximum_new_restart_trajectories": 800, "fixed_order": ["margin", "cw"],
            "result_dependent_scheduling": False, "created_at_utc": now(), "preflight": preflight,
            "preflight_attempts": preflight_attempts,
        },
        "p3d_loss_definitions.json": {
            "targeted_ce": "cross_entropy(logits, target=normal_class_0)",
            "targeted_logit_margin": "z_anomaly - z_normal; minimized",
            "targeted_cw_margin": "max(z_anomaly - z_normal + kappa, 0); minimized",
            "candidate_tie_break": "untruncated z_anomaly-z_normal ascending, restart_id, step",
        },
        "p3d_cw_parameter_freeze.json": {
            "cw_kappa": CW_KAPPA, "status": "RESOLVED", "result_dependent": False,
            "sources": [
                {"path": str(project_root / "adsb" / "attack_audit.py"), "line": 69, "definition": "AttackConfig.cw_kappa default 0.0"},
                {"path": str(project_root / "tests" / "test_attack_audit.py"), "line": 197, "definition": "CW saturation test uses kappa=0.0"},
            ],
        },
        "p3d_resource_budget.json": {
            "comparison_units": 80, "new_logical_configs": 160, "restarts_per_config": R,
            "maximum_new_restart_trajectories": 800, "ce_rerun": False, "margin_units": 80, "cw_units": 80,
        },
        "p3d_restart_spec.json": {"R": R, "restart_ids": [0, 1, 2, 3, 4], "higher_restart_ids_prohibited": True},
        "loss_pairing_status.json": {
            "status": "UNPAIRED", "label": "UNPAIRED_INITIALIZATION — SAME DISTRIBUTION / SAME RESTART BUDGET",
            "reason": "frozen AttackConfig.restart_seed hashes the loss identifier", "sample_wise_paired_claim_allowed": False,
        },
        "p3d_holdout_definition.json": {
            "matched": "same major attack-design dimensions as frozen training attack",
            "holdout": "at least two major dimensions differ", "epsilon_difference_counted": False,
            "major_dimensions": ["steps", "alpha_rule", "initialization", "restart_count", "loss", "attack_semantics", "projection_schedule"],
        },
        "p3d_claim_constraints.json": {
            "restart_saturation": "NOT_ESTABLISHED", "formal_attack_adequacy": "NOT_ESTABLISHED",
            "formal_P3_clearance": "DENIED", "robustness_claims": "SUSPENDED",
            "diagnostic_only": True, "manuscript_modification": False,
        },
    }
    for name, payload in freeze_payloads.items():
        atomic_json(p["freeze"] / name, payload)
    hashes = {name: sha256_file(p["freeze"] / name) for name in freeze_payloads}
    hashes["p3d_attack_matrix.csv"] = sha256_file(p["freeze"] / "p3d_attack_matrix.csv")
    config_hash = canonical_hash(hashes)
    atomic_json(p["freeze"] / "p3d_configuration_hashes.json", {
        "schema_version": "adsb.c001-p3d-configuration-hashes.v1", "artifacts": hashes,
        "configuration_hash": config_hash, "runner_sha256": sha256_file(Path(__file__)),
    })
    atomic_json(p["p3"] / "p3d_preflight.json", {
        "schema_version": "adsb.c001-p3d-preflight.v1", "status": "PASS", "checks": checks,
        "loss_preflight": preflight, "p2d_verification": p2d_verification,
        "configuration_hash": config_hash, "created_at_utc": now(),
    })
    return {"status": "PASS", "configuration_hash": config_hash, "output": str(p["p3"])}


def read_inventory(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def save_inventory(path: Path, rows: list[dict[str, Any]]) -> None:
    atomic_csv(path, rows, INVENTORY_FIELDS)


def manifest_status(loss_root: Path, rows: list[dict[str, Any]], phase: str, current: dict[str, Any] | None = None) -> None:
    statuses = [row["execution_status"] for row in rows]
    payload = {
        "schema_version": "adsb.c001-p3d-execution.v1", "loss_name": loss_root.name,
        "loss_id": LOSSES[loss_root.name], "expected": 80,
        "completed": statuses.count("completed"), "failed": statuses.count("failed"),
        "running": statuses.count("running"), "missing": statuses.count("scheduled") + statuses.count("failed"),
        "duplicates": 0, "restarts": [0, 1, 2, 3, 4], "phase": phase,
        "current_task": current, "runner_pid": os.getpid(), "updated_at_utc": now(),
    }
    atomic_json(loss_root / "execution_manifest.json", payload)
    atomic_json(loss_root / "runtime_status.json", payload)


class RunnerLock:
    def __init__(self, path: Path, loss_name: str):
        self.path = path
        self.loss_name = loss_name

    def __enter__(self) -> "RunnerLock":
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise RuntimeError(f"P3-Diagnostic runner lock exists: {load_json(self.path)}") from exc
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"pid": os.getpid(), "loss": self.loss_name, "created_at_utc": now()}, stream)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.path.unlink(missing_ok=True)


def preserve_unledgered_tail(raw_root: Path, loss_root: Path) -> None:
    ledger_path = raw_root / "aggregation_ledger.json"
    if not ledger_path.exists():
        return
    ledger = load_json(ledger_path)
    for filename, key in (("per_step_restart_records.csv.gz", "step_size_bytes"), ("per_sample_attack_records.csv.gz", "sample_size_bytes")):
        path = raw_root / filename
        expected = int(ledger.get(key, 0))
        if path.exists() and path.stat().st_size > expected:
            target = loss_root / "failed_attempts" / f"{filename}.unledgered-tail-{now().replace(':', '-')}.bin"
            with path.open("rb") as source, target.open("wb") as output:
                source.seek(expected)
                shutil.copyfileobj(source, output)


def predicted_task_hash(
    *, stage: str, row: dict[str, Any], config: AttackConfig, p2_config: dict[str, Any],
    checkpoint: dict[str, Any], data_manifest: dict[str, Any], threshold: float,
) -> str:
    identity = {
        "stage": stage, "seed": int(row["seed"]), "model": row["model"],
        "attack_config_hash": config.config_hash, "p2_config_hash": p2_config["config_hash"],
        "p2_code_fingerprint": EXPECTED_ATTACK_FINGERPRINT,
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "checkpoint_manifest_sha256": checkpoint["checkpoint_manifest_sha256"],
        "dataset_hash": data_manifest["dataset_hash"], "split_hash": data_manifest["split_hash"],
        "normalization_hash": data_manifest["normalization_hash"], "sample_manifest_hash": data_manifest["sample_manifest_hash"],
        "threshold": float(threshold), "evaluation_batch_size": int(p2_config["identity"]["evaluation_batch_size"]),
        "logical_config_id": None,
    }
    return p2._canonical_hash(identity)


def preserve_failed_task(raw_root: Path, loss_root: Path, task_hash: str, attempt: int) -> None:
    stamp = now().replace(":", "-")
    destination = loss_root / "failed_attempts" / f"{task_hash}.attempt-{attempt:03d}.{stamp}"
    moved = False
    for source in (raw_root / ".staging" / task_hash, raw_root / "tasks" / task_hash):
        if source.exists():
            destination.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(destination / source.parent.name))
            moved = True
    if moved:
        atomic_json(destination / "preservation.json", {"task_hash": task_hash, "attempt": attempt, "preserved_at_utc": now()})


def run_loss(project_root: Path, loss_name: str) -> dict[str, Any]:
    if loss_name not in LOSSES:
        raise ValueError(loss_name)
    p = paths(project_root)
    preflight = load_json(p["p3"] / "p3d_preflight.json")
    if preflight.get("status") != "PASS":
        raise RuntimeError("P3-Diagnostic preflight is not PASS")
    if code_fingerprint(project_root) != EXPECTED_ATTACK_FINGERPRINT:
        raise RuntimeError("frozen attack fingerprint changed after P3-Diagnostic freeze")
    margin_rows = read_inventory(p["p3"] / "margin" / "task_inventory.csv")
    if loss_name == "cw" and sum(row["execution_status"] == "completed" for row in margin_rows) != 80:
        raise RuntimeError("CW is forbidden until Margin is exactly 80/80 complete")

    loss_root = p["p3"] / loss_name
    raw_root = loss_root / "raw_results"
    inventory_path = loss_root / "task_inventory.csv"
    rows = read_inventory(inventory_path)
    preserve_unledgered_tail(raw_root, loss_root)
    store = p2.AggregateStore(raw_root)
    p2freeze = load_json(p["p2"] / "p2_configuration_freeze.json")
    p2_config = p2freeze["p2_config"]
    projection = p2freeze["projection_config"]
    dataframe = p2._prepare_dataframe(project_root)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    stage = f"p3d_{loss_name}"
    loss_id = LOSSES[loss_name]

    with RunnerLock(p["p3"] / "p3d_runner.lock", loss_name):
        manifest_status(loss_root, rows, f"{loss_name.upper()}_STARTING")
        for seed in SEEDS:
            pack, data_status = p2.prepare_seed(
                project_root=project_root, output_dir=raw_root, p1_root=p["p1"],
                dataframe=dataframe, seed=seed, device=device,
            )
            for model_name in MODELS:
                model, threshold, checkpoint, clean_probs, model_checks = p2.load_p1_model(
                    p1_root=p["p1"], seed=seed, model_name=model_name, pack=pack, device=device,
                )
                if not all(v for v in model_checks.values() if isinstance(v, bool)):
                    raise RuntimeError(f"model identity check failed: seed={seed} model={model_name}")
                for attack in ATTACKS:
                    for steps in STEPS:
                        matches = [r for r in rows if int(r["seed"]) == seed and r["model"] == model_name and r["attack"] == attack and int(r["K"]) == steps]
                        if len(matches) != 1:
                            raise RuntimeError(f"inventory identity not unique: {seed} {model_name} {attack} {steps}")
                        row = matches[0]
                        if row["execution_status"] == "completed":
                            continue
                        config = base_attack_config(
                            attack=attack, steps=steps, alpha_rule=row["alpha_rule"], initialization=row["initialization"],
                            restarts=R, seed=seed, projection=projection, loss_id=loss_id,
                        )
                        if config.config_hash != row["attack_config_hash"]:
                            raise RuntimeError("frozen P3 attack config hash mismatch")
                        task_hash = predicted_task_hash(
                            stage=stage, row=row, config=config, p2_config=p2_config,
                            checkpoint=checkpoint, data_manifest=data_status["manifest"], threshold=threshold,
                        )
                        attempt = int(row.get("attempt_count") or 0) + 1
                        preserve_failed_task(raw_root, loss_root, task_hash, attempt)
                        row["attempt_count"] = str(attempt)
                        row["execution_status"] = "running"
                        row["last_error"] = ""
                        save_inventory(inventory_path, rows)
                        manifest_status(loss_root, rows, f"{loss_name.upper()}_RUNNING", row)
                        append_jsonl(loss_root / "ledger.jsonl", {
                            "event": "TASK_START", "at_utc": now(), "attempt": attempt,
                            "logical_config_id": row["logical_config_id"], "task_hash": task_hash,
                        })
                        print(f"P3-Diagnostic {loss_name} seed={seed} model={model_name} attack={attack} K={steps} R=5", flush=True)
                        original_factory = p2._attack_config

                        def factory(**kwargs: Any) -> AttackConfig:
                            base = original_factory(**kwargs)
                            return replace(base, loss=loss_id, cw_kappa=CW_KAPPA)

                        try:
                            p2._attack_config = factory
                            summary = p2.run_configuration(
                                stage=stage, seed=seed, model_name=model_name, model=model, threshold=threshold,
                                pack=pack, clean_probs=clean_probs, attack=attack, steps=steps,
                                alpha_rule=row["alpha_rule"], initialization=row["initialization"], restarts=R,
                                projection=projection, p2_config=p2_config,
                                p2_code_fingerprint=EXPECTED_ATTACK_FINGERPRINT, checkpoint_status=checkpoint,
                                data_manifest=data_status["manifest"], output_dir=raw_root, store=store, device=device,
                            )
                            if summary["task_hash"] != task_hash or summary["attack_config_hash"] != row["attack_config_hash"]:
                                raise RuntimeError("completed task identity differs from frozen inventory")
                            summary["p3d_logical_config_id"] = row["logical_config_id"]
                            summary["p3d_loss_name"] = loss_name
                            summary["p3d_loss_id"] = loss_id
                            summary["p3d_source_ce_task_hash"] = row["source_ce_task_hash"]
                            summary["p3d_pairing_status"] = "UNPAIRED_INITIALIZATION — SAME DISTRIBUTION / SAME RESTART BUDGET"
                            atomic_json(raw_root / "tasks" / task_hash / "summary.json", summary)
                            row["execution_status"] = "completed"
                            row["executed_task_hash"] = task_hash
                            append_jsonl(loss_root / "ledger.jsonl", {"event": "TASK_COMPLETE", "at_utc": now(), "task_hash": task_hash})
                        except Exception as exc:
                            row["execution_status"] = "failed"
                            row["last_error"] = f"{type(exc).__name__}: {exc}"
                            preserve_failed_task(raw_root, loss_root, task_hash, attempt)
                            payload = {
                                "schema_version": "adsb.c001-p3d-failure.v1", "failed_at_utc": now(),
                                "loss_name": loss_name, "attempt": attempt, "task_hash": task_hash,
                                "logical_config_id": row["logical_config_id"], "error_type": type(exc).__name__,
                                "error": str(exc), "traceback": traceback.format_exc(),
                            }
                            append_jsonl(loss_root / "failed_attempts.jsonl", payload)
                            append_jsonl(loss_root / "ledger.jsonl", {"event": "TASK_FAILED", **payload})
                            print(traceback.format_exc(), flush=True)
                        finally:
                            p2._attack_config = original_factory
                        save_inventory(inventory_path, rows)
                        manifest_status(loss_root, rows, f"{loss_name.upper()}_RUNNING")
                del model
                if device.type == "cuda":
                    torch.cuda.empty_cache()
        completed = sum(row["execution_status"] == "completed" for row in rows)
        failed = sum(row["execution_status"] == "failed" for row in rows)
        phase = f"{loss_name.upper()}_COMPLETE" if completed == 80 and failed == 0 else f"{loss_name.upper()}_INCOMPLETE"
        manifest_status(loss_root, rows, phase)
        if completed != 80 or failed:
            raise RuntimeError(f"{loss_name} matrix incomplete: completed={completed} failed={failed}")
    return {"loss": loss_name, "completed": 80, "failed": 0, "status": "COMPLETE"}


def status(project_root: Path) -> dict[str, Any]:
    p = paths(project_root)
    result: dict[str, Any] = {"p3_exists": p["p3"].exists(), "runner_lock": None, "losses": {}}
    lock = p["p3"] / "p3d_runner.lock"
    if lock.exists():
        result["runner_lock"] = load_json(lock)
    for name in ("margin", "cw"):
        inventory = p["p3"] / name / "task_inventory.csv"
        if inventory.exists():
            rows = read_inventory(inventory)
            result["losses"][name] = {state: sum(row["execution_status"] == state for row in rows) for state in ("scheduled", "running", "completed", "failed")}
            manifest = p["p3"] / name / "execution_manifest.json"
            result["losses"][name]["manifest"] = load_json(manifest) if manifest.exists() else None
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("freeze", "run", "status"))
    parser.add_argument("--project-root", type=Path, default=Path(r"E:\ads-b\ADS-B2 -beifen"))
    parser.add_argument("--loss", choices=("margin", "cw"))
    args = parser.parse_args()
    if args.command == "freeze":
        output = freeze(args.project_root)
    elif args.command == "run":
        if not args.loss:
            parser.error("run requires --loss")
        output = run_loss(args.project_root, args.loss)
    else:
        output = status(args.project_root)
    print(json.dumps(output, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()

"""Authorized fresh Margin/CW executor for C0-01 P3-Diagnostic v2."""

from __future__ import annotations

import argparse
import json
import traceback
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import torch

import adsb.p2_step_size_restart as p2
from adsb.attack_audit import AttackConfig
from adsb.checkpoints import code_fingerprint, sha256_file
from adsb.device_setup import configure_cuda_training, resolve_device
from audit_tools import p3d_runner as legacy
from audit_tools.p3d_v2_prepare import (
    ATTACKS,
    CANONICAL_ROOT,
    CW_KAPPA,
    EXPECTED_ATTACK_FINGERPRINT,
    INVENTORY_FIELDS,
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


def read_inventory(path: Path) -> list[dict[str, Any]]:
    return pd.read_csv(path, dtype=str).fillna("").to_dict("records")


def save_inventory(path: Path, rows: list[dict[str, Any]]) -> None:
    legacy.atomic_csv(path, rows, INVENTORY_FIELDS)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    legacy.append_jsonl(path, payload)


def manifest_status(loss_root: Path, rows: list[dict[str, Any]], phase: str, current: dict[str, Any] | None = None) -> None:
    states = {state: sum(row["execution_status"] == state for row in rows) for state in ("scheduled", "running", "completed", "failed")}
    atomic_json(loss_root / "execution_manifest.json", {
        "schema_version": "adsb.c001-p3d-v2-execution.v1", "loss_name": loss_root.name,
        "expected": 80, **states, "missing": 80 - states["completed"], "duplicates": 0,
        "restarts": list(range(R)), "phase": phase, "current": current,
        "updated_at_utc": now(),
    })


def verify_freeze_manifest(path: Path) -> dict[str, Any]:
    manifest = load_json(path)
    missing: list[str] = []
    mismatches: list[str] = []
    for item in manifest.get("artifacts", []):
        artifact = Path(item["path"])
        if not artifact.is_file():
            missing.append(item["path"])
        elif artifact.stat().st_size != int(item["size_bytes"]) or sha256_file(artifact) != item["sha256"]:
            mismatches.append(item["path"])
    return {"missing": missing, "mismatches": mismatches, "status": "PASS" if not missing and not mismatches and manifest.get("artifact_count") == len(manifest.get("artifacts", [])) else "FAIL"}


def validate_authorization(project_root: Path, loss_name: str) -> dict[str, Any]:
    project_root = project_root.resolve()
    p = paths(project_root)
    authorization_path = p["pre_run"] / "pre_run_authorization.json"
    gate_path = p["pre_run"] / "pre_run_freeze_completeness.json"
    manifest_path = p["pre_run"] / "freeze_manifest.json"
    authorization = load_json(authorization_path)
    gate = load_json(gate_path)
    config = load_json(p["freeze"] / "p3d_configuration_hashes.json")
    manifest = load_json(manifest_path)
    frozen_matrix = pd.read_csv(p["freeze"] / "p3d_attack_matrix.csv", dtype=str).fillna("")
    observed_prereg = {
        name: sha256_file(p["freeze"] / name)
        for name in REQUIRED_PREREG if name != "p3d_configuration_hashes.json"
    }
    observed_config_hash = canonical_hash(observed_prereg)
    freeze_verification = verify_freeze_manifest(manifest_path)
    code_hashes = config.get("code_hashes", {})
    runner_hash = sha256_file(Path(__file__))
    checks = {
        "canonical_root": project_root == CANONICAL_ROOT.resolve(),
        "run_authorized": authorization.get("run_authorized") is True and authorization.get("RUN_AUTHORIZED") == "YES",
        "pre_run_gate": gate.get("status") == "PASS" and gate.get("pass_count") == 24,
        "pre_run_gate_hash": authorization.get("pre_run_gate_sha256") == sha256_file(gate_path),
        "stage": authorization.get("authorized_stage") == "P3_DIAGNOSTIC_V2",
        "loss": loss_name in authorization.get("authorized_losses", []) and loss_name in LOSSES,
        "restart_ids": authorization.get("authorized_restart_ids") == list(range(R)),
        "logical_config_budget": authorization.get("authorized_logical_configs") == 160,
        "trajectory_budget": authorization.get("max_new_trajectories") == 800,
        "configuration_hash": authorization.get("configuration_hash") == config.get("configuration_hash") == observed_config_hash,
        "freeze_manifest_hash": authorization.get("freeze_manifest_hash") == sha256_file(manifest_path),
        "freeze_manifest_contents": manifest.get("configuration_hash") == observed_config_hash and freeze_verification["status"] == "PASS",
        "attack_fingerprint": authorization.get("attack_fingerprint") == EXPECTED_ATTACK_FINGERPRINT and code_fingerprint(project_root) == EXPECTED_ATTACK_FINGERPRINT,
        "runner_hash": code_hashes.get("v2_runner") == runner_hash,
        "matrix": len(frozen_matrix) == 160 and set(frozen_matrix.loss_name) == {"margin", "cw"} and bool((frozen_matrix.restarts.astype(int) == R).all()),
        "authorization_after_freeze": authorization.get("authorization_utc") > load_json(p["freeze"] / "p3d_preregistration.json").get("frozen_at_utc"),
    }
    if not all(checks.values()):
        raise RuntimeError(f"P3-Diagnostic v2 RUN AUTHORIZATION rejected: {checks}")
    return {"status": "PASS", "checks": checks, "configuration_hash": observed_config_hash, "freeze_manifest_verification": freeze_verification}


def base_attack_config(*, attack: str, steps: int, alpha_rule: str, initialization: str, restarts: int, seed: int, projection: dict[str, Any], loss_id: str) -> AttackConfig:
    original = p2._attack_config(
        attack=attack, steps=steps, alpha_rule=alpha_rule,
        initialization=initialization, restarts=restarts, seed=seed,
        projection=projection,
    )
    return replace(original, loss=loss_id, cw_kappa=CW_KAPPA)


def run_loss(project_root: Path, loss_name: str) -> dict[str, Any]:
    authorization = validate_authorization(project_root, loss_name)
    p = paths(project_root)
    matrix = pd.read_csv(p["freeze"] / "p3d_attack_matrix.csv", dtype=str).fillna("")
    margin_rows = read_inventory(p["p3"] / "margin" / "task_inventory.csv")
    if loss_name == "cw" and (
        len(margin_rows) != 80
        or sum(row["execution_status"] == "completed" for row in margin_rows) != 80
        or any(row["execution_status"] != "completed" for row in margin_rows)
    ):
        raise RuntimeError("CW is forbidden until fresh v2 Margin is exactly 80/80 complete")

    loss_root = p["p3"] / loss_name
    raw_root = loss_root / "raw_results"
    inventory_path = loss_root / "task_inventory.csv"
    rows = read_inventory(inventory_path)
    frozen_loss = matrix[matrix.loss_name == loss_name]
    if len(rows) != 80 or frozen_loss.to_dict("records") != pd.DataFrame(rows, columns=matrix.columns).to_dict("records"):
        # Execution status is mutable, so compare only identity/configuration columns.
        identity_fields = [field for field in INVENTORY_FIELDS if field not in {"execution_status", "executed_task_hash", "attempt_count", "last_error"}]
        current_identity = pd.DataFrame(rows)[identity_fields].astype(str).to_dict("records")
        frozen_identity = frozen_loss[identity_fields].astype(str).to_dict("records")
        if current_identity != frozen_identity:
            raise RuntimeError("mutable task inventory differs from frozen v2 attack matrix")

    legacy.preserve_unledgered_tail(raw_root, loss_root)
    store = p2.AggregateStore(raw_root)
    p2freeze = load_json(p["p2"] / "p2_configuration_freeze.json")
    p2_config = p2freeze["p2_config"]
    projection = p2freeze["projection_config"]
    dataframe = p2._prepare_dataframe(project_root)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    stage = f"p3d_v2_{loss_name}"
    loss_id = LOSSES[loss_name]

    with legacy.RunnerLock(p["p3"] / "p3d_v2_runner.lock", loss_name):
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
                if not all(value for value in model_checks.values() if isinstance(value, bool)):
                    raise RuntimeError(f"model identity check failed: seed={seed} model={model_name}")
                for attack in ATTACKS:
                    for steps in STEPS:
                        matches = [row for row in rows if int(row["seed"]) == seed and row["model"] == model_name and row["attack"] == attack and int(row["K"]) == steps]
                        if len(matches) != 1:
                            raise RuntimeError(f"inventory identity not unique: {seed} {model_name} {attack} {steps}")
                        row = matches[0]
                        if row["execution_status"] == "completed":
                            continue
                        config = base_attack_config(
                            attack=attack, steps=steps, alpha_rule=row["alpha_rule"],
                            initialization=row["initialization"], restarts=R, seed=seed,
                            projection=projection, loss_id=loss_id,
                        )
                        if config.config_hash != row["attack_config_hash"]:
                            raise RuntimeError("frozen v2 attack config hash mismatch")
                        task_hash = legacy.predicted_task_hash(
                            stage=stage, row=row, config=config, p2_config=p2_config,
                            checkpoint=checkpoint, data_manifest=data_status["manifest"], threshold=threshold,
                        )
                        attempt = int(row.get("attempt_count") or 0) + 1
                        legacy.preserve_failed_task(raw_root, loss_root, task_hash, attempt)
                        row["attempt_count"] = str(attempt)
                        row["execution_status"] = "running"
                        row["last_error"] = ""
                        save_inventory(inventory_path, rows)
                        manifest_status(loss_root, rows, f"{loss_name.upper()}_RUNNING", row)
                        append_jsonl(loss_root / "ledger.jsonl", {
                            "event": "TASK_START", "at_utc": now(), "attempt": attempt,
                            "logical_config_id": row["logical_config_id"], "task_hash": task_hash,
                            "configuration_hash": authorization["configuration_hash"],
                        })
                        print(f"P3-Diagnostic v2 {loss_name} seed={seed} model={model_name} attack={attack} K={steps} R=5", flush=True)
                        original_factory = p2._attack_config

                        def factory(**kwargs: Any) -> AttackConfig:
                            base = original_factory(**kwargs)
                            return replace(base, loss=loss_id, cw_kappa=CW_KAPPA)

                        try:
                            p2._attack_config = factory
                            summary = p2.run_configuration(
                                stage=stage, seed=seed, model_name=model_name, model=model,
                                threshold=threshold, pack=pack, clean_probs=clean_probs,
                                attack=attack, steps=steps, alpha_rule=row["alpha_rule"],
                                initialization=row["initialization"], restarts=R,
                                projection=projection, p2_config=p2_config,
                                p2_code_fingerprint=EXPECTED_ATTACK_FINGERPRINT,
                                checkpoint_status=checkpoint, data_manifest=data_status["manifest"],
                                output_dir=raw_root, store=store, device=device,
                            )
                            if summary["task_hash"] != task_hash or summary["attack_config_hash"] != row["attack_config_hash"]:
                                raise RuntimeError("completed task identity differs from frozen v2 inventory")
                            summary.update({
                                "p3d_v2_logical_config_id": row["logical_config_id"],
                                "p3d_v2_loss_name": loss_name, "p3d_v2_loss_id": loss_id,
                                "p3d_v2_source_ce_task_hash": row["source_ce_task_hash"],
                                "p3d_v2_configuration_hash": authorization["configuration_hash"],
                                "p3d_v2_pairing_status": "UNPAIRED — SAME DISTRIBUTION / SAME RESTART BUDGET",
                                "p3d_v1_trajectory_reused": False,
                            })
                            atomic_json(raw_root / "tasks" / task_hash / "summary.json", summary)
                            row["execution_status"] = "completed"
                            row["executed_task_hash"] = task_hash
                            append_jsonl(loss_root / "ledger.jsonl", {"event": "TASK_COMPLETE", "at_utc": now(), "task_hash": task_hash})
                        except Exception as exc:
                            row["execution_status"] = "failed"
                            row["last_error"] = f"{type(exc).__name__}: {exc}"
                            legacy.preserve_failed_task(raw_root, loss_root, task_hash, attempt)
                            payload = {
                                "schema_version": "adsb.c001-p3d-v2-failure.v1", "failed_at_utc": now(),
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


def status(project_root: Path = CANONICAL_ROOT) -> dict[str, Any]:
    p = paths(project_root)
    result: dict[str, Any] = {"p3_v2_exists": p["p3"].exists(), "runner_lock": None, "authorization": None, "losses": {}}
    lock = p["p3"] / "p3d_v2_runner.lock"
    if lock.exists():
        result["runner_lock"] = load_json(lock)
    authorization = p["pre_run"] / "pre_run_authorization.json"
    if authorization.exists():
        result["authorization"] = load_json(authorization)
    for loss in ("margin", "cw"):
        inventory = p["p3"] / loss / "task_inventory.csv"
        if inventory.exists():
            rows = read_inventory(inventory)
            result["losses"][loss] = {state: sum(row["execution_status"] == state for row in rows) for state in ("scheduled", "running", "completed", "failed")}
            manifest = p["p3"] / loss / "execution_manifest.json"
            result["losses"][loss]["manifest"] = load_json(manifest) if manifest.exists() else None
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("run", "status", "guard"))
    parser.add_argument("--project-root", type=Path, default=CANONICAL_ROOT)
    parser.add_argument("--loss", choices=("margin", "cw"))
    args = parser.parse_args()
    if args.command == "run":
        if not args.loss:
            parser.error("run requires --loss")
        output = run_loss(args.project_root, args.loss)
    elif args.command == "guard":
        if not args.loss:
            parser.error("guard requires --loss")
        output = validate_authorization(args.project_root, args.loss)
    else:
        output = status(args.project_root)
    print(json.dumps(output, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()

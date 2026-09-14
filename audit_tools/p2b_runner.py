"""Isolated executor for the frozen C0-01 P2-B multiple-restart audit.

This module deliberately lives outside ``adsb/``, ``configs/``, and ``scripts/``
so it does not alter the frozen attack-code fingerprint.  It only orchestrates
the already frozen ``adsb.p2_step_size_restart.run_configuration`` execution
semantics and writes P2-B artifacts to a separate output root.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import torch

from adsb.checkpoints import code_fingerprint, sha256_file
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.p2_step_size_restart import (
    ATTACKS,
    MODELS,
    RANDOM_INITIALIZATION,
    SEEDS,
    STEPS,
    AggregateStore,
    _all_summaries,
    _attack_config,
    _canonical_hash,
    _find_task,
    _prepare_dataframe,
    _set_restart_inclusion,
    load_p1_model,
    prepare_seed,
    run_configuration,
)
from posthoc_tools.p2a_reaggregation import canonical_hash, verify_raw_snapshot


EXPECTED_P2B_MANIFEST_SHA256 = "785d51ee255a3993b34e6fd2e0e72b71e848653549edf8574d5701899d08bc56"
EXPECTED_P2B_TASK_LIST_SHA256 = "27a395646e54e8241901a1738f5a96d554ba9d758c93a0f64d9f3a08820dbde1"
EXPECTED_P2A_RAW_SNAPSHOT_SHA256 = "8280b26d62f07a955a11dff960c33575d9362c3e3892d1d3f22fd290c7917ef0"
EXPECTED_P2A_POSTHOC_FINGERPRINT = "cc4ea8ad276a1c6862ffe69ad1074eb59b70fc7c734c53d66238dde32416bc9f"
EXPECTED_ATTACK_CODE_FINGERPRINT = "afd1389066e1c87fec8d6f9da42e4f7e2fb3384343f214d31c8eccf79bdbcf4f"

TASK_FIELDS = (
    "logical_config_id",
    "stage",
    "seed",
    "model",
    "attack",
    "K",
    "alpha_rule",
    "alpha",
    "initialization",
    "restarts",
    "attack_config_hash",
    "checkpoint_sha256",
    "dataset_hash",
    "split_hash",
    "normalization_hash",
    "sample_manifest_hash",
    "threshold",
    "execution_status",
    "reused_from",
    "source_task_hash",
    "executed_task_hash",
    "attempt_count",
    "last_error",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def atomic_inventory(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=TASK_FIELDS, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def append_failure(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def key_for(values: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(values["seed"]),
        str(values["model"]),
        str(values["attack"]),
        int(values.get("K", values.get("steps"))),
        str(values["alpha_rule"]),
        str(values["initialization"]),
        int(values["restarts"]),
    )


def project_paths(project_root: Path, output_dir: Path) -> dict[str, Path]:
    p2 = project_root / "outputs" / "attack_audit_c001" / "p2"
    return {
        "root": project_root,
        "p1": project_root / "outputs" / "attack_audit_c001" / "p1",
        "p2": p2,
        "snapshot": p2 / "final_raw_snapshot",
        "reaggregation": p2 / "final_reaggregation",
        "freeze": p2 / "p2b_configuration_freeze.json",
        "output": output_dir,
    }


def frozen_context(project_root: Path, output_dir: Path) -> dict[str, Any]:
    paths = project_paths(project_root, output_dir)
    freeze = load_json(paths["freeze"])
    p2_execution = load_json(paths["p2"] / "p2_configuration_freeze.json")
    return {
        "paths": paths,
        "freeze": freeze,
        "p2_config": p2_execution["p2_config"],
        "projection": p2_execution["projection_config"],
        "p2_execution": p2_execution,
    }


def p2a_summary_lookup(p2: Path) -> dict[tuple[Any, ...], dict[str, Any]]:
    summaries = _all_summaries(p2, status="completed")
    lookup: dict[tuple[Any, ...], dict[str, Any]] = {}
    for summary in summaries:
        if summary.get("stage") != "p2a":
            continue
        key = key_for(summary)
        if key in lookup:
            raise RuntimeError(f"duplicate P2-A summary identity: {key}")
        lookup[key] = summary
    return lookup


def verify_r1_task(task: dict[str, Any], summary: dict[str, Any]) -> dict[str, bool]:
    identity = summary["task_identity"]
    return {
        "stage": summary.get("stage") == "p2a",
        "status": summary.get("status") == "completed",
        "attack_config_hash": summary.get("attack_config_hash") == task["attack_config_hash"],
        "checkpoint_sha256": summary.get("checkpoint_sha256") == task["checkpoint_sha256"],
        "dataset_hash": identity.get("dataset_hash") == task["dataset_hash"],
        "split_hash": identity.get("split_hash") == task["split_hash"],
        "normalization_hash": identity.get("normalization_hash") == task["normalization_hash"],
        "sample_manifest_hash": identity.get("sample_manifest_hash") == task["sample_manifest_hash"],
        "threshold": float(summary.get("threshold")) == float(task["threshold"]),
        "alpha_rule": summary.get("alpha_rule") == task["alpha_rule"],
        "alpha": float(summary.get("alpha")) == float(task["alpha"]),
        "initialization": summary.get("initialization") == task["initialization"],
        "restarts": int(summary.get("restarts")) == 1,
        "candidate_artifact_recorded": (
            bool(summary.get("candidate_artifact", {}).get("path"))
            and len(str(summary.get("candidate_artifact", {}).get("sha256", ""))) == 64
        ),
    }


def initial_inventory(
    freeze: dict[str, Any],
    r1_lookup: dict[tuple[Any, ...], dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    r1_checks: list[dict[str, Any]] = []
    for task in freeze["base_tasks"]:
        row = {field: task.get(field, "") for field in TASK_FIELDS}
        row.update(
            {
                "execution_status": "scheduled",
                "reused_from": "",
                "source_task_hash": "",
                "executed_task_hash": "",
                "attempt_count": 0,
                "last_error": "",
            }
        )
        if int(task["restarts"]) == 1:
            summary = r1_lookup.get(key_for(task))
            if summary is None:
                checks = {"unique_matching_p2a_task": False}
            else:
                checks = {"unique_matching_p2a_task": True, **verify_r1_task(task, summary)}
                row.update(
                    {
                        "execution_status": "reused",
                        "reused_from": "P2-A frozen raw snapshot",
                        "source_task_hash": summary["task_hash"],
                        "attempt_count": 1,
                    }
                )
            r1_checks.append(
                {
                    "logical_config_id": task["logical_config_id"],
                    "checks": checks,
                    "pass": all(checks.values()),
                }
            )
        rows.append(row)
    return rows, r1_checks


def run_preflight(project_root: Path, output_dir: Path) -> dict[str, Any]:
    context = frozen_context(project_root, output_dir)
    paths = context["paths"]
    freeze = context["freeze"]
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_sha = sha256_file(paths["freeze"])
    task_list_sha = canonical_hash(freeze["base_tasks"])
    raw_manifest = load_json(paths["snapshot"] / "raw_snapshot_manifest.json")
    reaggregation_fingerprint = load_json(
        paths["reaggregation"] / "reaggregation_code_fingerprint.json"
    )
    p2a_gate = load_json(paths["reaggregation"] / "p2a_integrity_gate.json")
    current_attack_fingerprint = code_fingerprint(project_root)
    frozen_copy_sha = sha256_file(paths["reaggregation"] / "p2b_configuration_freeze.json")
    raw_verification = verify_raw_snapshot(project_root, paths["snapshot"])

    r1_lookup = p2a_summary_lookup(paths["p2"])
    inventory, r1_checks = initial_inventory(freeze, r1_lookup)
    attack_config_checks: list[dict[str, Any]] = []
    for task in freeze["base_tasks"]:
        config = _attack_config(
            attack=task["attack"],
            steps=int(task["K"]),
            alpha_rule=task["alpha_rule"],
            initialization=task["initialization"],
            restarts=int(task["restarts"]),
            seed=int(task["seed"]),
            projection=context["projection"],
        )
        attack_config_checks.append(
            {
                "logical_config_id": task["logical_config_id"],
                "observed": config.config_hash,
                "expected": task["attack_config_hash"],
                "pass": config.config_hash == task["attack_config_hash"],
            }
        )

    model_rows: list[dict[str, Any]] = []
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    dataframe = _prepare_dataframe(project_root)
    for seed in SEEDS:
        pack, data_status = prepare_seed(
            project_root=project_root,
            output_dir=output_dir,
            p1_root=paths["p1"],
            dataframe=dataframe,
            seed=seed,
            device=device,
        )
        for model_name in MODELS:
            model, threshold, status, _clean, checks = load_p1_model(
                p1_root=paths["p1"],
                seed=seed,
                model_name=model_name,
                pack=pack,
                device=device,
            )
            model_rows.append(
                {
                    "seed": seed,
                    "model": model_name,
                    "threshold": threshold,
                    "checkpoint_sha256": status["checkpoint_sha256"],
                    "data_checks": data_status["identity_checks"],
                    "checkpoint_checks": checks,
                    "pass": (
                        all(data_status["identity_checks"].values())
                        and all(value for value in checks.values() if isinstance(value, bool))
                    ),
                }
            )
            del model
            if device.type == "cuda":
                torch.cuda.empty_cache()

    checks = {
        "frozen_manifest_sha256": manifest_sha == EXPECTED_P2B_MANIFEST_SHA256,
        "frozen_copy_sha256": frozen_copy_sha == EXPECTED_P2B_MANIFEST_SHA256,
        "task_list_sha256": task_list_sha == EXPECTED_P2B_TASK_LIST_SHA256 == freeze["task_list_sha256"],
        "base_task_count_160": len(freeze["base_tasks"]) == freeze["base_task_count"] == 160,
        "base_task_ids_unique": len({task["logical_config_id"] for task in freeze["base_tasks"]}) == 160,
        "base_matrix_complete": {
            key_for(task) for task in freeze["base_tasks"]
        } == {
            (seed, model, attack, steps, "two_eps_over_k", RANDOM_INITIALIZATION[attack], restarts)
            for seed in SEEDS
            for model in MODELS
            for attack in ATTACKS
            for steps in STEPS
            for restarts in (1, 5)
        },
        "selected_alpha_frozen": all(
            value["alpha_rule"] == "two_eps_over_k"
            for value in freeze["selected_alpha_per_attack"].values()
        ),
        "alpha_values_frozen": all(
            float(task["alpha"]) == (0.01 if int(task["K"]) == 20 else 0.004)
            for task in freeze["base_tasks"]
        ),
        "raw_snapshot_identity": (
            raw_manifest["raw_snapshot_hash"]
            == freeze["source_raw_snapshot_sha256"]
            == EXPECTED_P2A_RAW_SNAPSHOT_SHA256
        ),
        "raw_snapshot_artifacts": raw_verification["status"] == "PASS",
        "p2a_posthoc_fingerprint": (
            reaggregation_fingerprint["posthoc_reaggregation_fingerprint"]
            == freeze["posthoc_reaggregation_fingerprint"]
            == EXPECTED_P2A_POSTHOC_FINGERPRINT
        ),
        "p2a_integrity": p2a_gate.get("status") == "PASS",
        "attack_code_fingerprint": (
            current_attack_fingerprint
            == freeze["original_p2a_attack_code_fingerprint"]
            == EXPECTED_ATTACK_CODE_FINGERPRINT
        ),
        "projection_tolerances": freeze["projection_tolerances"] == context["projection"],
        "candidate_semantics_present": set(freeze["candidate_policies"]) == {
            "final",
            "best_target_loss",
            "success_preserving",
            "best_feasible_success",
        },
        "support_definitions_present": (
            paths["p2"] / freeze["support_definitions"]
        ).is_file(),
        "all_r1_sources_verified": len(r1_checks) == 80 and all(item["pass"] for item in r1_checks),
        "all_attack_configs_verified": len(attack_config_checks) == 160
        and all(item["pass"] for item in attack_config_checks),
        "ten_checkpoints_verified": len(model_rows) == 10 and all(item["pass"] for item in model_rows),
        "p2b_was_not_previously_executed": freeze.get("executed") is False,
        "p3_to_p6_not_scheduled": True,
        "single_restart_attack_semantics_unchanged": True,
        "orchestration_isolated_from_fingerprint_scope": True,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    payload = {
        "schema_version": "adsb.c001-p2b-preflight.v1",
        "generation_utc": now(),
        "gate": status,
        "project_root": str(project_root),
        "output_dir": str(output_dir),
        "device": str(device),
        "checks": checks,
        "observed": {
            "frozen_manifest_sha256": manifest_sha,
            "task_list_sha256": task_list_sha,
            "raw_snapshot_sha256": raw_manifest["raw_snapshot_hash"],
            "posthoc_reaggregation_fingerprint": reaggregation_fingerprint[
                "posthoc_reaggregation_fingerprint"
            ],
            "attack_code_fingerprint": current_attack_fingerprint,
            "raw_snapshot_artifact_count": raw_verification["artifact_count"],
            "raw_snapshot_mismatches": raw_verification["mismatches"],
        },
        "r1_source_checks": r1_checks,
        "attack_config_checks": attack_config_checks,
        "checkpoint_and_data_rows": model_rows,
        "orchestration_note": (
            "Only restart orchestration and isolated P2-B output management were added. "
            "The frozen adsb attack implementation and single-restart semantics were not modified."
        ),
        "robustness_claims_restored": False,
        "paper_modified": False,
        "p3_to_p6_executed": False,
    }
    atomic_inventory(output_dir / "p2b_task_inventory.csv", inventory)
    atomic_json(output_dir / "p2b_preflight.json", payload)
    atomic_json(
        output_dir / "p2b_configuration_gate.json",
        {
            "schema_version": "adsb.c001-p2b-gate.v1",
            "generation_utc": now(),
            "gate": status,
            "source": "p2b_preflight.json",
            "checks": checks,
        },
    )
    manifest = {
        "schema_version": "adsb.c001-p2b-manifest.v1",
        "generation_utc": now(),
        "phase": "preflight_complete" if status == "PASS" else "preflight_failed",
        "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
        "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
        "source_p2b_task_list_sha256": EXPECTED_P2B_TASK_LIST_SHA256,
        "frozen_attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "base_logical_tasks": 160,
        "base_r1_reused_from_p2a": 80,
        "base_r5_scheduled_new": 80,
        "conditional_r10_scheduled": 0,
        "p3_to_p6_executed": False,
        "paper_modified": False,
        "robustness_claims_restored": False,
    }
    atomic_json(output_dir / "p2b_manifest.json", manifest)
    (output_dir / "failed_runs.jsonl").touch(exist_ok=True)
    print(json.dumps({"gate": status, "output": str(output_dir / "p2b_preflight.json")}, indent=2))
    return payload


def read_inventory(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def write_runtime_status(
    output_dir: Path,
    rows: list[dict[str, Any]],
    *,
    phase: str,
    current_task: dict[str, Any] | None,
) -> None:
    statuses = [row["execution_status"] for row in rows]
    ledger_path = output_dir / "aggregation_ledger.json"
    ledger_tasks = 0
    if ledger_path.exists():
        ledger_tasks = len(load_json(ledger_path).get("tasks", {}))
    payload = {
        "schema_version": "adsb.c001-p2b-runtime-status.v1",
        "updated_at_utc": now(),
        "phase": phase,
        "runner_pid": os.getpid(),
        "base_logical_tasks": len(rows),
        "reused_r1": statuses.count("reused"),
        "completed_r5": statuses.count("completed"),
        "failed": statuses.count("failed"),
        "scheduled": statuses.count("scheduled"),
        "running": statuses.count("running"),
        "terminal_base_tasks": statuses.count("reused")
        + statuses.count("completed")
        + statuses.count("failed"),
        "ledger_tasks": ledger_tasks,
        "current_task": current_task,
        "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
        "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
        "p3_to_p6_executed": False,
        "paper_modified": False,
    }
    atomic_json(output_dir / "p2b_runtime_status.json", payload)


class RunnerLock:
    def __init__(self, path: Path):
        self.path = path

    def __enter__(self) -> "RunnerLock":
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as error:
            prior = load_json(self.path)
            raise RuntimeError(f"P2-B runner lock already exists: {prior}") from error
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"pid": os.getpid(), "created_at_utc": now()}, stream)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.path.unlink(missing_ok=True)


def run_base(project_root: Path, output_dir: Path) -> None:
    preflight = load_json(output_dir / "p2b_preflight.json")
    if preflight.get("gate") != "PASS":
        raise RuntimeError("P2-B Configuration Identity Gate is not PASS")
    if code_fingerprint(project_root) != EXPECTED_ATTACK_CODE_FINGERPRINT:
        raise RuntimeError("frozen attack code fingerprint changed after preflight")

    context = frozen_context(project_root, output_dir)
    freeze = context["freeze"]
    paths = context["paths"]
    r1_lookup = p2a_summary_lookup(paths["p2"])
    frozen_by_key = {key_for(task): task for task in freeze["base_tasks"]}
    rows = read_inventory(output_dir / "p2b_task_inventory.csv")
    row_by_id = {row["logical_config_id"]: row for row in rows}
    store = AggregateStore(output_dir)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    dataframe = _prepare_dataframe(project_root)

    with RunnerLock(output_dir / "p2b_runner.lock"):
        write_runtime_status(output_dir, rows, phase="base_starting", current_task=None)
        for seed in SEEDS:
            pack, data_status = prepare_seed(
                project_root=project_root,
                output_dir=output_dir,
                p1_root=paths["p1"],
                dataframe=dataframe,
                seed=seed,
                device=device,
            )
            for model_name in MODELS:
                model, threshold, checkpoint_status, clean_probs, _model_checks = load_p1_model(
                    p1_root=paths["p1"],
                    seed=seed,
                    model_name=model_name,
                    pack=pack,
                    device=device,
                )
                for attack in ATTACKS:
                    initialization = RANDOM_INITIALIZATION[attack]
                    for steps in STEPS:
                        task_key = (
                            seed,
                            model_name,
                            attack,
                            steps,
                            "two_eps_over_k",
                            initialization,
                            5,
                        )
                        frozen_task = frozen_by_key[task_key]
                        inventory_row = row_by_id[frozen_task["logical_config_id"]]
                        if inventory_row["execution_status"] == "completed":
                            continue
                        inventory_row["execution_status"] = "running"
                        inventory_row["attempt_count"] = str(
                            int(inventory_row.get("attempt_count") or 0) + 1
                        )
                        atomic_inventory(output_dir / "p2b_task_inventory.csv", rows)
                        write_runtime_status(
                            output_dir,
                            rows,
                            phase="base_r1_r5_running",
                            current_task=frozen_task,
                        )
                        print(
                            f"P2-B base seed={seed} model={model_name} attack={attack} "
                            f"K={steps} alpha=two_eps_over_k R=5",
                            flush=True,
                        )
                        try:
                            summary = run_configuration(
                                stage="p2b",
                                seed=seed,
                                model_name=model_name,
                                model=model,
                                threshold=threshold,
                                pack=pack,
                                clean_probs=clean_probs,
                                attack=attack,
                                steps=steps,
                                alpha_rule="two_eps_over_k",
                                initialization=initialization,
                                restarts=5,
                                projection=context["projection"],
                                p2_config=context["p2_config"],
                                p2_code_fingerprint=EXPECTED_ATTACK_CODE_FINGERPRINT,
                                checkpoint_status=checkpoint_status,
                                data_manifest=data_status["manifest"],
                                output_dir=output_dir,
                                store=store,
                                device=device,
                            )
                            prior = r1_lookup[
                                (
                                    seed,
                                    model_name,
                                    attack,
                                    steps,
                                    "two_eps_over_k",
                                    initialization,
                                    1,
                                )
                            ]
                            summary = _set_restart_inclusion(summary, prior, 1, output_dir)
                            checks = {
                                "attack_config_hash": summary["attack_config_hash"]
                                == frozen_task["attack_config_hash"],
                                "checkpoint_sha256": summary["checkpoint_sha256"]
                                == frozen_task["checkpoint_sha256"],
                                "threshold": float(summary["threshold"])
                                == float(frozen_task["threshold"]),
                                "restart_zero_fingerprint": summary["restart_fingerprints"][0]
                                == prior["restart_fingerprints"][0],
                                "candidate_artifact": (
                                    sha256_file(output_dir / summary["candidate_artifact"]["path"])
                                    == summary["candidate_artifact"]["sha256"]
                                ),
                            }
                            if not all(checks.values()):
                                raise RuntimeError(f"frozen task identity mismatch: {checks}")
                            summary["p2b_logical_config_id"] = frozen_task["logical_config_id"]
                            summary["p2b_frozen_manifest_sha256"] = EXPECTED_P2B_MANIFEST_SHA256
                            summary["p2a_source_task_hash"] = prior["task_hash"]
                            summary["p2b_identity_checks"] = checks
                            atomic_json(
                                output_dir / "tasks" / summary["task_hash"] / "summary.json",
                                summary,
                            )
                            inventory_row["execution_status"] = "completed"
                            inventory_row["executed_task_hash"] = summary["task_hash"]
                            inventory_row["source_task_hash"] = prior["task_hash"]
                            inventory_row["last_error"] = ""
                        except Exception as error:
                            inventory_row["execution_status"] = "failed"
                            inventory_row["last_error"] = f"{type(error).__name__}: {error}"
                            append_failure(
                                output_dir / "failed_runs.jsonl",
                                {
                                    "schema_version": "adsb.c001-p2b-failure.v1",
                                    "failed_at_utc": now(),
                                    "phase": "base_r1_r5",
                                    "logical_config_id": frozen_task["logical_config_id"],
                                    "task": frozen_task,
                                    "error_type": type(error).__name__,
                                    "error": str(error),
                                    "traceback": traceback.format_exc(),
                                },
                            )
                            print(traceback.format_exc(), flush=True)
                        atomic_inventory(output_dir / "p2b_task_inventory.csv", rows)
                        write_runtime_status(
                            output_dir,
                            rows,
                            phase="base_r1_r5_running",
                            current_task=None,
                        )
                del model
                if device.type == "cuda":
                    torch.cuda.empty_cache()

        failed = [row for row in rows if row["execution_status"] == "failed"]
        completed = [row for row in rows if row["execution_status"] in {"reused", "completed"}]
        final_phase = "base_complete" if len(completed) == 160 and not failed else "base_failed"
        write_runtime_status(output_dir, rows, phase=final_phase, current_task=None)
        manifest = load_json(output_dir / "p2b_manifest.json")
        manifest.update(
            {
                "updated_at_utc": now(),
                "phase": final_phase,
                "base_tasks_completed": len(completed),
                "base_r5_executed": sum(row["execution_status"] == "completed" for row in rows),
                "explicit_failures": len(failed),
            }
        )
        atomic_json(output_dir / "p2b_manifest.json", manifest)
        if failed or len(completed) != 160:
            raise RuntimeError(
                f"P2-B base matrix incomplete: completed={len(completed)} failed={len(failed)}"
            )


def write_r10_runtime_status(
    output_dir: Path,
    rows: list[dict[str, Any]],
    *,
    phase: str,
    current_task: dict[str, Any] | None,
) -> None:
    base = [row for row in rows if int(row["restarts"]) in (1, 5)]
    conditional = [row for row in rows if int(row["restarts"]) == 10]
    ledger_path = output_dir / "aggregation_ledger.json"
    ledger_tasks = len(load_json(ledger_path).get("tasks", {})) if ledger_path.exists() else 0
    payload = {
        "schema_version": "adsb.c001-p2b-runtime-status.v1",
        "updated_at_utc": now(),
        "phase": phase,
        "runner_pid": os.getpid(),
        "base_logical_tasks": len(base),
        "base_terminal": sum(
            row["execution_status"] in {"reused", "completed", "failed"} for row in base
        ),
        "base_successful": sum(
            row["execution_status"] in {"reused", "completed"} for row in base
        ),
        "conditional_r10_tasks": len(conditional),
        "conditional_r10_completed": sum(
            row["execution_status"] == "completed" for row in conditional
        ),
        "conditional_r10_failed": sum(
            row["execution_status"] == "failed" for row in conditional
        ),
        "conditional_r10_scheduled": sum(
            row["execution_status"] == "scheduled" for row in conditional
        ),
        "conditional_r10_running": sum(
            row["execution_status"] == "running" for row in conditional
        ),
        "ledger_tasks": ledger_tasks,
        "current_task": current_task,
        "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
        "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
        "p3_to_p6_executed": False,
        "paper_modified": False,
    }
    atomic_json(output_dir / "p2b_runtime_status.json", payload)


def run_r10(project_root: Path, output_dir: Path) -> None:
    if code_fingerprint(project_root) != EXPECTED_ATTACK_CODE_FINGERPRINT:
        raise RuntimeError("frozen attack code fingerprint changed before R10")
    decision = load_json(output_dir / "r10_trigger_decision.json")
    if decision.get("status") != "FROZEN":
        raise RuntimeError("R10 trigger decision is not frozen")
    rows = read_inventory(output_dir / "p2b_task_inventory.csv")
    base = [row for row in rows if int(row["restarts"]) in (1, 5)]
    conditional = [row for row in rows if int(row["restarts"]) == 10]
    expected_r10 = int(decision["total_triggered_task_count"])
    if len(base) != 160 or any(
        row["execution_status"] not in {"reused", "completed"} for row in base
    ):
        raise RuntimeError("R10 execution requires all 160 base logical tasks")
    if len(conditional) != expected_r10:
        raise RuntimeError(
            f"conditional inventory mismatch: expected={expected_r10} observed={len(conditional)}"
        )
    if expected_r10 == 0:
        write_r10_runtime_status(
            output_dir, rows, phase="r10_not_triggered", current_task=None
        )
        manifest = load_json(output_dir / "p2b_manifest.json")
        manifest.update(
            {
                "updated_at_utc": now(),
                "phase": "r10_not_triggered",
                "conditional_r10_completed": 0,
                "conditional_r10_failures": 0,
            }
        )
        atomic_json(output_dir / "p2b_manifest.json", manifest)
        return

    context = frozen_context(project_root, output_dir)
    paths = context["paths"]
    row_by_id = {row["logical_config_id"]: row for row in rows}
    r5_summaries = {
        key_for(summary): summary
        for summary in _all_summaries(output_dir, status="completed")
        if summary.get("restarts") == 5
    }
    store = AggregateStore(output_dir)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    dataframe = _prepare_dataframe(project_root)
    triggered = {
        attack
        for attack, value in decision["per_attack"].items()
        if value["trigger"]
    }

    with RunnerLock(output_dir / "p2b_runner.lock"):
        write_r10_runtime_status(
            output_dir, rows, phase="r10_starting", current_task=None
        )
        for seed in SEEDS:
            pack, data_status = prepare_seed(
                project_root=project_root,
                output_dir=output_dir,
                p1_root=paths["p1"],
                dataframe=dataframe,
                seed=seed,
                device=device,
            )
            for model_name in MODELS:
                model, threshold, checkpoint_status, clean_probs, _model_checks = load_p1_model(
                    p1_root=paths["p1"],
                    seed=seed,
                    model_name=model_name,
                    pack=pack,
                    device=device,
                )
                for attack in ATTACKS:
                    if attack not in triggered:
                        continue
                    initialization = RANDOM_INITIALIZATION[attack]
                    for steps in STEPS:
                        matches = [
                            row
                            for row in conditional
                            if int(row["seed"]) == seed
                            and row["model"] == model_name
                            and row["attack"] == attack
                            and int(row["K"]) == steps
                        ]
                        if len(matches) != 1:
                            raise RuntimeError(
                                f"expected one R10 task, found {len(matches)} for "
                                f"{seed}/{model_name}/{attack}/K{steps}"
                            )
                        inventory_row = matches[0]
                        if inventory_row["execution_status"] == "completed":
                            continue
                        inventory_row["execution_status"] = "running"
                        inventory_row["attempt_count"] = str(
                            int(inventory_row.get("attempt_count") or 0) + 1
                        )
                        atomic_inventory(output_dir / "p2b_task_inventory.csv", rows)
                        write_r10_runtime_status(
                            output_dir,
                            rows,
                            phase="conditional_r10_running",
                            current_task=inventory_row,
                        )
                        print(
                            f"P2-B R10 seed={seed} model={model_name} attack={attack} "
                            f"K={steps} alpha=two_eps_over_k R=10",
                            flush=True,
                        )
                        try:
                            summary = run_configuration(
                                stage="p2b_conditional_r10",
                                seed=seed,
                                model_name=model_name,
                                model=model,
                                threshold=threshold,
                                pack=pack,
                                clean_probs=clean_probs,
                                attack=attack,
                                steps=steps,
                                alpha_rule="two_eps_over_k",
                                initialization=initialization,
                                restarts=10,
                                projection=context["projection"],
                                p2_config=context["p2_config"],
                                p2_code_fingerprint=EXPECTED_ATTACK_CODE_FINGERPRINT,
                                checkpoint_status=checkpoint_status,
                                data_manifest=data_status["manifest"],
                                output_dir=output_dir,
                                store=store,
                                device=device,
                            )
                            prior = r5_summaries[
                                (
                                    seed,
                                    model_name,
                                    attack,
                                    steps,
                                    "two_eps_over_k",
                                    initialization,
                                    5,
                                )
                            ]
                            summary = _set_restart_inclusion(summary, prior, 5, output_dir)
                            checks = {
                                "attack_config_hash": summary["attack_config_hash"]
                                == inventory_row["attack_config_hash"],
                                "checkpoint_sha256": summary["checkpoint_sha256"]
                                == inventory_row["checkpoint_sha256"],
                                "threshold": float(summary["threshold"])
                                == float(inventory_row["threshold"]),
                                "restart_0_to_4_fingerprints": (
                                    summary["restart_fingerprints"][:5]
                                    == prior["restart_fingerprints"][:5]
                                ),
                                "candidate_artifact": (
                                    sha256_file(output_dir / summary["candidate_artifact"]["path"])
                                    == summary["candidate_artifact"]["sha256"]
                                ),
                            }
                            if not all(checks.values()):
                                raise RuntimeError(f"frozen R10 identity mismatch: {checks}")
                            summary["p2b_logical_config_id"] = inventory_row[
                                "logical_config_id"
                            ]
                            summary["p2b_frozen_manifest_sha256"] = (
                                EXPECTED_P2B_MANIFEST_SHA256
                            )
                            summary["p2b_r5_source_task_hash"] = prior["task_hash"]
                            summary["p2b_identity_checks"] = checks
                            atomic_json(
                                output_dir
                                / "tasks"
                                / summary["task_hash"]
                                / "summary.json",
                                summary,
                            )
                            inventory_row["execution_status"] = "completed"
                            inventory_row["executed_task_hash"] = summary["task_hash"]
                            inventory_row["source_task_hash"] = prior["task_hash"]
                            inventory_row["last_error"] = ""
                        except Exception as error:
                            inventory_row["execution_status"] = "failed"
                            inventory_row["last_error"] = (
                                f"{type(error).__name__}: {error}"
                            )
                            append_failure(
                                output_dir / "failed_runs.jsonl",
                                {
                                    "schema_version": "adsb.c001-p2b-failure.v1",
                                    "failed_at_utc": now(),
                                    "phase": "conditional_r10",
                                    "logical_config_id": inventory_row[
                                        "logical_config_id"
                                    ],
                                    "task": inventory_row,
                                    "error_type": type(error).__name__,
                                    "error": str(error),
                                    "traceback": traceback.format_exc(),
                                },
                            )
                            print(traceback.format_exc(), flush=True)
                        atomic_inventory(output_dir / "p2b_task_inventory.csv", rows)
                        write_r10_runtime_status(
                            output_dir,
                            rows,
                            phase="conditional_r10_running",
                            current_task=None,
                        )
                del model
                if device.type == "cuda":
                    torch.cuda.empty_cache()

        failures = [
            row for row in conditional if row["execution_status"] == "failed"
        ]
        completed = [
            row for row in conditional if row["execution_status"] == "completed"
        ]
        phase = (
            "r10_complete"
            if len(completed) == expected_r10 and not failures
            else "r10_failed"
        )
        write_r10_runtime_status(output_dir, rows, phase=phase, current_task=None)
        manifest = load_json(output_dir / "p2b_manifest.json")
        manifest.update(
            {
                "updated_at_utc": now(),
                "phase": phase,
                "conditional_r10_completed": len(completed),
                "conditional_r10_failures": len(failures),
            }
        )
        atomic_json(output_dir / "p2b_manifest.json", manifest)
        if failures or len(completed) != expected_r10:
            raise RuntimeError(
                f"conditional R10 incomplete: completed={len(completed)} "
                f"expected={expected_r10} failed={len(failures)}"
            )


def status(output_dir: Path) -> None:
    runtime = output_dir / "p2b_runtime_status.json"
    if runtime.exists():
        print(runtime.read_text(encoding="utf-8"))
        return
    inventory = output_dir / "p2b_task_inventory.csv"
    if not inventory.exists():
        print(json.dumps({"status": "not_started", "output_dir": str(output_dir)}, indent=2))
        return
    rows = read_inventory(inventory)
    print(
        json.dumps(
            {
                "status": "inventory_only",
                "counts": pd.Series([row["execution_status"] for row in rows])
                .value_counts()
                .to_dict(),
            },
            indent=2,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase", choices=("preflight", "base", "r10", "status"), required=True
    )
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
        if args.phase == "preflight":
            gate = run_preflight(project_root, output_dir)
            return 0 if gate["gate"] == "PASS" else 2
        if args.phase == "base":
            run_base(project_root, output_dir)
            return 0
        if args.phase == "r10":
            run_r10(project_root, output_dir)
            return 0
        status(output_dir)
        return 0
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

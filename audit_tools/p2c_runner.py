"""Frozen executor for C0-01 P2-C extended restart convergence audit.

Phases:

``preflight``
    Resolve the canonical entity, freeze an immutable P2-B source inventory,
    run the isolated orchestration tests, freeze the P2-C configuration, and
    create the R20 execution manifest.

``r20``
    Execute all 80 logical configurations, and only restart IDs 10--19.

``r40``
    Execute the already-frozen conditional inventory, and only restart IDs
    20--39.  The inventory is created by the independent trigger phase.
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import torch

from adsb.checkpoints import code_fingerprint, sha256_file
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.p2_step_size_restart import (
    ATTACKS,
    MODELS,
    RANDOM_INITIALIZATION,
    SEEDS,
    STEPS,
    _all_summaries,
    _attack_config,
    _prepare_dataframe,
    load_p1_model,
    prepare_seed,
)
from audit_tools.p2b_runner import (
    EXPECTED_ATTACK_CODE_FINGERPRINT,
    EXPECTED_P2A_POSTHOC_FINGERPRINT,
    EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
    EXPECTED_P2B_MANIFEST_SHA256,
    EXPECTED_P2B_TASK_LIST_SHA256,
    frozen_context,
)
from audit_tools.p2c_orchestration import (
    SCHEMA as ORCHESTRATION_SCHEMA,
    _failure_archive,
    atomic_json,
    canonical_hash,
    execute_range_task,
    now,
    orchestration_self_test,
    task_identity,
)


SCHEMA = "adsb.c001-p2c-runner.v1"
P2B_ARTIFACT_HASHES_EXPECTED_SHA256 = (
    "0fa657a4acb5fff743485a8ebcd140bef0570517bf3c273c769c8dcf02754903"
)
P2B_ROOT_RELATIVE = Path("outputs") / "attack_audit_c001" / "p2b"
P2C_ROOT_RELATIVE = Path("outputs") / "attack_audit_c001" / "p2c"

INVENTORY_FIELDS = (
    "schema_version",
    "config_id",
    "phase",
    "seed",
    "model",
    "attack",
    "K",
    "alpha_rule",
    "alpha",
    "initialization",
    "target_restart_count",
    "executed_restart_start",
    "executed_restart_end",
    "new_restart_count",
    "source_r10_task_hash",
    "source_r10_candidate_sha256",
    "source_previous_snapshot_hash",
    "task_hash",
    "execution_status",
    "attempt_count",
    "last_error",
    "completed_at_utc",
)

SOURCE_FILE_FIELDS = (
    "relative_path",
    "size_bytes",
    "sha256",
    "kind",
)

RESTART_INVENTORY_FIELDS = (
    "seed",
    "model",
    "attack",
    "K",
    "restart_count",
    "restart_id",
    "restart_fingerprint",
    "task_hash",
    "source_prior_task_hash",
    "inclusion_pass",
)

CANDIDATE_INVENTORY_FIELDS = (
    "seed",
    "model",
    "attack",
    "K",
    "restart_count",
    "task_hash",
    "relative_path",
    "size_bytes",
    "sha256",
    "sample_count",
    "restart_ids_present",
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_csv(path: Path, fieldnames: Iterable[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=list(fieldnames),
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    output: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            output.append(json.loads(line))
    return output


def _set_read_only(path: Path) -> None:
    # Windows honors the read-only file attribute through chmod's write bits.
    path.chmod(0o444)


def _candidate_project_entities(project_root: Path) -> list[Path]:
    candidates = {
        project_root,
        Path(r"D:\ADS-B2 -beifen"),
        Path(r"D:\ADS-B2 -beifen - 副本 - 副本 (2)"),
        Path(r"C:\Users\lwb\Desktop\ADS-B2 -beifen"),
        Path(r"C:\Users\lwb\Desktop\ADS-B2 -beifen - 副本"),
        Path(r"C:\Users\lwb\Desktop\ADS-B2 -beifen - 副本 - 副本"),
        Path.cwd(),
    }
    return sorted(candidates, key=lambda value: str(value).casefold())


def resolve_canonical_root(project_root: Path) -> dict[str, Any]:
    requested = project_root
    if not requested.exists() or not requested.is_dir():
        raise RuntimeError(f"[DATA CONFLICT] requested project root is absent: {requested}")
    resolved = requested.resolve(strict=True)
    entities: list[dict[str, Any]] = []
    completed_entities: list[Path] = []
    for candidate in _candidate_project_entities(resolved):
        if not candidate.exists() or not candidate.is_dir():
            continue
        candidate_resolved = candidate.resolve(strict=True)
        artifact_path = candidate_resolved / P2B_ROOT_RELATIVE / "artifact_hashes.json"
        record = {
            "path": str(candidate),
            "resolved_path": str(candidate_resolved),
            "same_as_canonical": candidate_resolved == resolved,
            "has_p2b_artifact_hashes": artifact_path.is_file(),
            "p2b_artifact_hashes_sha256": (
                sha256_file(artifact_path) if artifact_path.is_file() else None
            ),
            "has_p2c": (candidate_resolved / P2C_ROOT_RELATIVE).exists(),
        }
        entities.append(record)
        if artifact_path.is_file() and candidate_resolved not in completed_entities:
            completed_entities.append(candidate_resolved)
    conflicts = [value for value in completed_entities if value != resolved]
    if conflicts:
        raise RuntimeError(
            "[DATA CONFLICT] multiple project entities contain P2-B output: "
            + ", ".join(str(value) for value in conflicts)
        )
    return {
        "requested_project_root": str(requested),
        "canonical_project_root": str(resolved),
        "resolved_real_path": str(resolved),
        "requested_is_reparse_alias": requested.absolute() != resolved,
        "entities_checked": entities,
        "completed_p2b_entity_count": len(completed_entities),
        "status": "PASS" if completed_entities == [resolved] else "FAIL",
    }


def verify_p2b_artifacts(p2b_root: Path) -> dict[str, Any]:
    artifact_path = p2b_root / "artifact_hashes.json"
    observed_self_hash = sha256_file(artifact_path)
    artifact_manifest = load_json(artifact_path)
    rows: list[dict[str, Any]] = []
    for artifact in artifact_manifest["artifacts"]:
        path = p2b_root / artifact["path"]
        observed_size = path.stat().st_size if path.exists() else None
        observed_hash = sha256_file(path) if path.exists() else None
        rows.append(
            {
                "path": artifact["path"],
                "expected_size": int(artifact["size_bytes"]),
                "observed_size": observed_size,
                "expected_sha256": artifact["sha256"],
                "observed_sha256": observed_hash,
                "pass": (
                    observed_size == int(artifact["size_bytes"])
                    and observed_hash == artifact["sha256"]
                ),
            }
        )
    checks = {
        "artifact_manifest_self_hash": (
            observed_self_hash == P2B_ARTIFACT_HASHES_EXPECTED_SHA256
        ),
        "artifact_count_43": (
            int(artifact_manifest["artifact_count"]) == len(rows) == 43
        ),
        "all_declared_artifacts_match": all(row["pass"] for row in rows),
    }
    return {
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "artifact_hashes_sha256": observed_self_hash,
        "artifact_manifest": artifact_manifest,
        "verification": rows,
    }


def _p2b_summary_key(summary: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(summary["seed"]),
        str(summary["model"]),
        str(summary["attack"]),
        int(summary["steps"]),
    )


def collect_p2b_summaries(p2b_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    summaries = _all_summaries(p2b_root, status="completed")
    r5 = [value for value in summaries if int(value.get("restarts", 0)) == 5]
    r10 = [value for value in summaries if int(value.get("restarts", 0)) == 10]
    if len(r5) != 80 or len(r10) != 80:
        raise RuntimeError(f"P2-B summary counts are not 80/80: {len(r5)}/{len(r10)}")
    if len({_p2b_summary_key(value) for value in r5}) != 80:
        raise RuntimeError("duplicate P2-B R5 summary identities")
    if len({_p2b_summary_key(value) for value in r10}) != 80:
        raise RuntimeError("duplicate P2-B R10 summary identities")
    return r5, r10


def _source_file_kind(relative_path: Path) -> str:
    name = relative_path.name
    if name == "summary.json":
        return "task_summary"
    if name == "candidate_iterates.npz":
        return "task_candidates"
    if name.endswith(".csv.gz"):
        return "raw_or_derived_table"
    if name.endswith(".json") or name.endswith(".jsonl"):
        return "manifest_or_gate"
    if name.endswith(".csv"):
        return "table"
    if name.endswith(".pdf") or name.endswith(".svg"):
        return "figure"
    return "other"


def build_source_snapshot(project_root: Path, p2c_root: Path) -> dict[str, Any]:
    source_dir = p2c_root / "source_p2b_snapshot"
    if source_dir.exists():
        manifest = load_json(source_dir / "p2b_source_snapshot_manifest.json")
        if manifest.get("status") != "PASS":
            raise RuntimeError("existing P2-B source snapshot is not PASS")
        return manifest

    p2b_root = project_root / P2B_ROOT_RELATIVE
    p2b_verify = verify_p2b_artifacts(p2b_root)
    if p2b_verify["status"] != "PASS":
        raise RuntimeError("P2-C SOURCE IDENTITY GATE = FAIL: P2-B artifacts changed")
    r5, r10 = collect_p2b_summaries(p2b_root)
    r5_lookup = {_p2b_summary_key(value): value for value in r5}

    restart_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    nesting_checks: list[dict[str, Any]] = []
    for summary in sorted(
        r5 + r10,
        key=lambda value: (
            int(value["seed"]),
            str(value["model"]),
            str(value["attack"]),
            int(value["steps"]),
            int(value["restarts"]),
        ),
    ):
        fingerprints = list(summary["restart_fingerprints"])
        expected_ids = list(range(int(summary["restarts"])))
        inclusion = summary["restart_inclusion_check"]
        for restart_id, fingerprint in enumerate(fingerprints):
            restart_rows.append(
                {
                    "seed": summary["seed"],
                    "model": summary["model"],
                    "attack": summary["attack"],
                    "K": summary["steps"],
                    "restart_count": summary["restarts"],
                    "restart_id": restart_id,
                    "restart_fingerprint": fingerprint,
                    "task_hash": summary["task_hash"],
                    "source_prior_task_hash": inclusion["prior_task_hash"],
                    "inclusion_pass": inclusion["pass"],
                }
            )
        artifact = summary["candidate_artifact"]
        candidate_path = p2b_root / artifact["path"]
        candidate_rows.append(
            {
                "seed": summary["seed"],
                "model": summary["model"],
                "attack": summary["attack"],
                "K": summary["steps"],
                "restart_count": summary["restarts"],
                "task_hash": summary["task_hash"],
                "relative_path": artifact["path"],
                "size_bytes": artifact["size_bytes"],
                "sha256": artifact["sha256"],
                "sample_count": summary["support"]["anomaly"],
                "restart_ids_present": ",".join(str(value) for value in expected_ids),
            }
        )
        if not candidate_path.exists() or sha256_file(candidate_path) != artifact["sha256"]:
            raise RuntimeError(f"P2-B candidate artifact changed: {candidate_path}")
        if int(summary["restarts"]) == 10:
            prior = r5_lookup[_p2b_summary_key(summary)]
            nesting_checks.append(
                {
                    "key": list(_p2b_summary_key(summary)),
                    "r10_ids": expected_ids == list(range(10)),
                    "r10_contains_r5": fingerprints[:5] == prior["restart_fingerprints"],
                    "r10_inclusion_gate": inclusion["pass"],
                    "r5_contains_r1": prior["restart_inclusion_check"]["pass"],
                }
            )

    p2b_gate = load_json(p2b_root / "p2b_integrity_gate.json")
    p2b_nesting = load_json(p2b_root / "p2b_nesting_gate.json")
    p2b_completeness = load_json(p2b_root / "p2b_completeness_gate.json")
    p2b_runtime = load_json(p2b_root / "p2b_runtime_status.json")
    p2b_manifest = load_json(p2b_root / "p2b_manifest.json")
    checks = {
        "p2b_artifact_verification": p2b_verify["status"] == "PASS",
        "p2b_final_integrity_pass": p2b_gate.get("gate") == "PASS",
        "p2b_nesting_pass": p2b_nesting.get("gate") == "PASS",
        "p2b_completeness_pass": p2b_completeness.get("gate") == "PASS",
        "p2b_runtime_complete": p2b_runtime.get("phase") == "p2b_complete",
        "p2b_manifest_complete": p2b_manifest.get("phase") == "p2b_complete",
        "r5_task_count_80": len(r5) == 80,
        "r10_task_count_80": len(r10) == 80,
        "r5_restart_ids_0_to_4": all(
            len(value["restart_fingerprints"]) == 5 for value in r5
        ),
        "r10_restart_ids_0_to_9": all(
            len(value["restart_fingerprints"]) == 10 for value in r10
        ),
        "all_r10_contains_r5": all(
            value["r10_contains_r5"] for value in nesting_checks
        ),
        "all_r5_contains_r1": all(
            value["r5_contains_r1"] for value in nesting_checks
        ),
        "no_failed_runs": (p2b_root / "failed_runs.jsonl").stat().st_size == 0,
        "staging_empty": not any((p2b_root / ".staging").iterdir()),
        "attack_code_fingerprint": (
            code_fingerprint(project_root) == EXPECTED_ATTACK_CODE_FINGERPRINT
        ),
    }
    if not all(checks.values()):
        raise RuntimeError(
            "P2-C SOURCE IDENTITY GATE = FAIL: "
            + ", ".join(key for key, value in checks.items() if not value)
        )

    source_dir.mkdir(parents=True, exist_ok=False)
    atomic_json(
        source_dir / "p2b_source_artifact_hashes.json",
        p2b_verify["artifact_manifest"],
    )
    atomic_csv(
        source_dir / "p2b_restart_inventory.csv",
        RESTART_INVENTORY_FIELDS,
        restart_rows,
    )
    atomic_csv(
        source_dir / "p2b_candidate_inventory.csv",
        CANDIDATE_INVENTORY_FIELDS,
        candidate_rows,
    )

    # Inventory every P2-B file after the semantic checks.  This is the
    # immutable source baseline used at finalization.
    file_rows: list[dict[str, Any]] = []
    for path in sorted(
        (value for value in p2b_root.rglob("*") if value.is_file()),
        key=lambda value: value.relative_to(p2b_root).as_posix(),
    ):
        relative = path.relative_to(p2b_root)
        file_rows.append(
            {
                "relative_path": relative.as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "kind": _source_file_kind(relative),
            }
        )
    atomic_csv(
        source_dir / "p2b_source_file_inventory.csv",
        SOURCE_FILE_FIELDS,
        file_rows,
    )
    source_identity = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "canonical_project_root": str(project_root),
        "source_p2b_root": str(p2b_root),
        "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
        "source_p2a_posthoc_fingerprint": EXPECTED_P2A_POSTHOC_FINGERPRINT,
        "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
        "source_p2b_task_list_sha256": EXPECTED_P2B_TASK_LIST_SHA256,
        "source_p2b_artifact_hashes_sha256": p2b_verify[
            "artifact_hashes_sha256"
        ],
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "file_count": len(file_rows),
        "candidate_count": len(candidate_rows),
        "restart_record_count": len(restart_rows),
        "checks": checks,
        "nesting_checks": nesting_checks,
        "status": "PASS",
    }
    atomic_json(source_dir / "p2b_source_identity.json", source_identity)

    snapshot_components = {}
    for name in (
        "p2b_source_file_inventory.csv",
        "p2b_source_artifact_hashes.json",
        "p2b_restart_inventory.csv",
        "p2b_candidate_inventory.csv",
        "p2b_source_identity.json",
    ):
        path = source_dir / name
        snapshot_components[name] = {
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    source_snapshot_hash = canonical_hash(
        {
            "schema_version": SCHEMA,
            "components": snapshot_components,
            "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
            "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        }
    )
    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "PASS",
        "gate": "P2-C SOURCE IDENTITY GATE",
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "components": snapshot_components,
        "checks": checks,
    }
    atomic_json(source_dir / "p2b_source_snapshot_manifest.json", manifest)
    for path in source_dir.iterdir():
        if path.is_file():
            _set_read_only(path)
    return manifest


def _config_id(summary: dict[str, Any]) -> str:
    return canonical_hash(
        {
            "seed": int(summary["seed"]),
            "model": summary["model"],
            "attack": summary["attack"],
            "K": int(summary["steps"]),
            "source_r10_task_hash": summary["task_hash"],
            "alpha_rule": "two_eps_over_k",
            "initialization": RANDOM_INITIALIZATION[summary["attack"]],
        }
    )


def _orchestration_fingerprint(project_root: Path) -> dict[str, Any]:
    paths = [
        project_root / "audit_tools" / "p2c_orchestration.py",
        project_root / "audit_tools" / "p2c_runner.py",
    ]
    components = {
        path.relative_to(project_root).as_posix(): {
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in paths
    }
    fingerprint = canonical_hash(
        {
            "schema_version": SCHEMA,
            "components": components,
            "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
            "semantics": "range scheduling, source reuse, atomic commit only",
        }
    )
    return {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "orchestration_fingerprint": fingerprint,
        "components": components,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "attack_code_unchanged": (
            code_fingerprint(project_root) == EXPECTED_ATTACK_CODE_FINGERPRINT
        ),
    }


def build_configuration_freeze(
    project_root: Path,
    p2c_root: Path,
    source_manifest: dict[str, Any],
    orchestration: dict[str, Any],
) -> dict[str, Any]:
    freeze_dir = p2c_root / "configuration_freeze"
    hashes_path = freeze_dir / "p2c_configuration_hashes.json"
    if freeze_dir.exists():
        hashes = load_json(hashes_path)
        for name, artifact in hashes["components"].items():
            path = freeze_dir / name
            if (
                not path.exists()
                or path.stat().st_size != int(artifact["size_bytes"])
                or sha256_file(path) != artifact["sha256"]
            ):
                raise RuntimeError(f"frozen P2-C configuration changed: {path}")
        return hashes

    p2b_root = project_root / P2B_ROOT_RELATIVE
    _r5, r10 = collect_p2b_summaries(p2b_root)
    context = frozen_context(project_root, p2b_root)
    source_snapshot_hash = source_manifest["source_p2b_snapshot_hash"]
    freeze_dir.mkdir(parents=True, exist_ok=False)

    r20_rows: list[dict[str, Any]] = []
    r40_rows: list[dict[str, Any]] = []
    for summary in sorted(
        r10,
        key=lambda value: (
            int(value["seed"]),
            str(value["model"]),
            str(value["attack"]),
            int(value["steps"]),
        ),
    ):
        config_id = _config_id(summary)
        common = {
            "schema_version": SCHEMA,
            "config_id": config_id,
            "seed": int(summary["seed"]),
            "model": summary["model"],
            "attack": summary["attack"],
            "K": int(summary["steps"]),
            "alpha_rule": "two_eps_over_k",
            "alpha": float(summary["alpha"]),
            "initialization": summary["initialization"],
            "source_r10_task_hash": summary["task_hash"],
            "source_r10_candidate_sha256": summary["candidate_artifact"]["sha256"],
            "execution_status": "frozen_pending",
            "attempt_count": 0,
            "last_error": "",
            "completed_at_utc": "",
            "task_hash": "",
        }
        r20_rows.append(
            {
                **common,
                "phase": "r20",
                "target_restart_count": 20,
                "executed_restart_start": 10,
                "executed_restart_end": 19,
                "new_restart_count": 10,
                "source_previous_snapshot_hash": source_snapshot_hash,
            }
        )
        r40_rows.append(
            {
                **common,
                "phase": "r40",
                "target_restart_count": 40,
                "executed_restart_start": 20,
                "executed_restart_end": 39,
                "new_restart_count": 20,
                "source_previous_snapshot_hash": "TO_BE_FROZEN_R20_SNAPSHOT_HASH",
            }
        )

    preregistration = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "audit": "C0-01 P2-C Extended Restart Convergence Audit",
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "r20_logical_tasks": 80,
        "r20_new_restart_ids": list(range(10, 20)),
        "r20_new_restart_trajectories": 800,
        "conditional_r40_templates": 80,
        "r40_new_restart_ids": list(range(20, 40)),
        "maximum_r40_new_restart_trajectories": 1600,
        "formal_unit": "seed x model x attack_family x K",
        "units_per_family": 20,
        "r40_trigger_metric": "success-preserving threshold-ASR",
        "r40_trigger_threshold": 0.005,
        "r40_trigger_rule": "trigger full family if any of 20 units has delta_R10_R20 >= 0.005",
        "restart_adequacy_asr_threshold": 0.005,
        "restart_adequacy_feasible_asr_threshold": 0.005,
        "restart_adequacy_relative_target_ce_threshold": 0.01,
        "r80_forbidden": True,
        "p3_to_p6_forbidden": True,
        "manuscript_modification_forbidden": True,
    }
    configuration = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
        "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
        "source_p2b_task_list_sha256": EXPECTED_P2B_TASK_LIST_SHA256,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "orchestration_fingerprint": orchestration["orchestration_fingerprint"],
        "epsilon": 0.1,
        "K": [20, 50],
        "alpha": {"20": 0.01, "50": 0.004},
        "alpha_rule": "two_eps_over_k",
        "loss": "targeted_ce",
        "precision": "FP32",
        "target_class": "normal",
        "attack_support": "original-label anomalous samples only",
        "budget_scope": "normalized_raw6",
        "differences": "recomputed_from_raw",
        "threshold": "frozen clean-validation threshold",
        "initialization": RANDOM_INITIALIZATION,
        "projection": context["projection"],
        "matrix": {
            "seeds": list(SEEDS),
            "models": list(MODELS),
            "attacks": list(ATTACKS),
            "K": list(STEPS),
        },
    }
    candidate_semantics = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "final_active": "best active final-step candidate; invalid final retained separately",
        "best_target_loss": "minimum target CE among active candidates",
        "success_preserving": "union of threshold-success candidates; clean fallback excluded",
        "best_feasible_success": "minimum target CE among active feasible threshold-success candidates",
        "clean_fallback": "recorded separately and never counted as an attack candidate",
        "merge_rule": "frozen prior candidate set plus candidates from only the newly executed restart range",
    }
    support_definitions = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "attacked_support": "all original-label anomalous test samples",
        "success_preserving_denominator": "same attacked support and frozen threshold at all restart counts",
        "physical_common_support": "same source-valid attacked samples; no-support units are not_applicable",
        "active_support": "samples with at least one active attack candidate",
        "valid_final_support": "samples with an active final candidate, feasible for physical attacks",
        "fallback_exclusion": "clean fallback is excluded from all attack-success numerators",
        "invalid_and_projection_failure": "retained and reported separately",
    }
    stop_rules = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "r40_trigger": preregistration["r40_trigger_rule"],
        "pass_at_r20": "all 20 final unit conditions pass and family did not trigger R40",
        "pass_at_r40": "all 20 final unit conditions pass after complete triggered R40",
        "fail_not_stable": "any final ASR/feasible increment >= threshold or median relative CE gain >= 1%",
        "inconclusive": "support or semantic insufficiency prevents formal comparison",
        "implementation_failure": "identity, nesting, candidate, seed, raw, or hash failure",
        "no_result_contingent_early_stop": True,
        "r80_not_authorized": True,
    }

    atomic_json(freeze_dir / "p2c_preregistration.json", preregistration)
    atomic_json(freeze_dir / "p2c_configuration_freeze.json", configuration)
    atomic_csv(
        freeze_dir / "p2c_r20_task_inventory.csv",
        INVENTORY_FIELDS,
        r20_rows,
    )
    atomic_csv(
        freeze_dir / "p2c_conditional_r40_templates.csv",
        INVENTORY_FIELDS,
        r40_rows,
    )
    atomic_json(
        freeze_dir / "p2c_candidate_semantics.json", candidate_semantics
    )
    atomic_json(
        freeze_dir / "p2c_support_definitions.json", support_definitions
    )
    atomic_json(freeze_dir / "p2c_stop_rules.json", stop_rules)

    component_names = (
        "p2c_preregistration.json",
        "p2c_configuration_freeze.json",
        "p2c_r20_task_inventory.csv",
        "p2c_conditional_r40_templates.csv",
        "p2c_candidate_semantics.json",
        "p2c_support_definitions.json",
        "p2c_stop_rules.json",
    )
    components = {
        name: {
            "size_bytes": (freeze_dir / name).stat().st_size,
            "sha256": sha256_file(freeze_dir / name),
        }
        for name in component_names
    }
    configuration_hash = canonical_hash(
        {
            "schema_version": SCHEMA,
            "components": components,
            "source_p2b_snapshot_hash": source_snapshot_hash,
            "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
            "orchestration_fingerprint": orchestration[
                "orchestration_fingerprint"
            ],
        }
    )
    hashes = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "FROZEN",
        "p2c_configuration_hash": configuration_hash,
        "components": components,
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "orchestration_fingerprint": orchestration[
            "orchestration_fingerprint"
        ],
    }
    atomic_json(hashes_path, hashes)
    for path in freeze_dir.iterdir():
        if path.is_file():
            _set_read_only(path)
    return hashes


def _source_r10_lookup(project_root: Path) -> dict[str, dict[str, Any]]:
    p2b_root = project_root / P2B_ROOT_RELATIVE
    _r5, r10 = collect_p2b_summaries(p2b_root)
    return {_config_id(summary): summary for summary in r10}


def _runtime_rows_from_freeze(
    *,
    freeze_inventory: Path,
    phase: str,
    source_lookup: dict[str, dict[str, Any]],
    source_snapshot_hash: str,
    previous_snapshot_hash: str,
    configuration_hash: str,
    orchestration_fingerprint: str,
) -> list[dict[str, Any]]:
    rows = read_csv(freeze_inventory)
    output: list[dict[str, Any]] = []
    for raw in rows:
        if raw["phase"] != phase:
            continue
        source = source_lookup[raw["config_id"]]
        restart_ids = range(
            int(raw["executed_restart_start"]),
            int(raw["executed_restart_end"]) + 1,
        )
        identity = task_identity(
            phase=phase,
            config_id=raw["config_id"],
            source_summary=source,
            target_restart_count=int(raw["target_restart_count"]),
            restart_ids=tuple(restart_ids),
            source_snapshot_hash=source_snapshot_hash,
            previous_snapshot_hash=previous_snapshot_hash,
            p2c_configuration_hash=configuration_hash,
            orchestration_fingerprint=orchestration_fingerprint,
        )
        output.append(
            {
                **raw,
                "source_previous_snapshot_hash": previous_snapshot_hash,
                "task_hash": canonical_hash(identity),
                "execution_status": "pending",
                "attempt_count": "0",
                "last_error": "",
                "completed_at_utc": "",
            }
        )
    return output


def _inventory_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    states = ("pending", "running", "completed", "failed")
    return {
        state: sum(row["execution_status"] == state for row in rows)
        for state in states
    }


def write_runtime_status(
    *,
    phase_dir: Path,
    phase: str,
    rows: list[dict[str, Any]],
    current_task: dict[str, Any] | None,
    configuration_hash: str,
    source_snapshot_hash: str,
    orchestration_fingerprint: str,
) -> None:
    counts = _inventory_counts(rows)
    staging = phase_dir / ".staging"
    output_size = sum(
        path.stat().st_size
        for path in phase_dir.rglob("*")
        if path.is_file()
    )
    disk = shutil.disk_usage(phase_dir.drive + "\\")
    latest = [
        row for row in rows if row.get("execution_status") == "completed"
    ]
    payload = {
        "schema_version": SCHEMA,
        "updated_at_utc": now(),
        "phase": phase,
        "runner_pid": os.getpid(),
        "logical_tasks": len(rows),
        **counts,
        "current_task": current_task,
        "latest_completed_task": latest[-1] if latest else None,
        "duplicate_ids": len(rows) - len({row["config_id"] for row in rows}),
        "unknown_ids": 0,
        "staging_count": (
            sum(1 for value in staging.iterdir() if value.is_dir())
            if staging.exists()
            else 0
        ),
        "disk_free_bytes": disk.free,
        "output_size_bytes": output_size,
        "frozen_configuration_hash": configuration_hash,
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "orchestration_fingerprint": orchestration_fingerprint,
        "p3_to_p6_executed": False,
        "r80_executed": False,
        "paper_modified": False,
    }
    atomic_json(phase_dir / f"{phase}_runtime_status.json", payload)


class RunnerLock:
    def __init__(self, path: Path):
        self.path = path

    def __enter__(self) -> "RunnerLock":
        if self.path.exists():
            prior = load_json(self.path)
            pid = int(prior["pid"])
            try:
                os.kill(pid, 0)
            except OSError:
                stale = self.path.with_name(
                    f"{self.path.name}.stale.{prior.get('created_at_utc','unknown').replace(':','-')}"
                )
                os.replace(self.path, stale)
            else:
                raise RuntimeError(
                    f"another P2-C runner appears active: pid={pid} lock={self.path}"
                )
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


def initialize_r20_execution(
    project_root: Path,
    p2c_root: Path,
    source_manifest: dict[str, Any],
    hashes: dict[str, Any],
    orchestration: dict[str, Any],
) -> dict[str, Any]:
    phase_dir = p2c_root / "r20_execution"
    manifest_path = phase_dir / "r20_execution_manifest.json"
    if phase_dir.exists():
        manifest = load_json(manifest_path)
        if manifest.get("status") != "FROZEN":
            raise RuntimeError("existing R20 execution manifest is not frozen")
        return manifest
    phase_dir.mkdir(parents=True, exist_ok=False)
    source_lookup = _source_r10_lookup(project_root)
    rows = _runtime_rows_from_freeze(
        freeze_inventory=p2c_root
        / "configuration_freeze"
        / "p2c_r20_task_inventory.csv",
        phase="r20",
        source_lookup=source_lookup,
        source_snapshot_hash=source_manifest["source_p2b_snapshot_hash"],
        previous_snapshot_hash=source_manifest["source_p2b_snapshot_hash"],
        configuration_hash=hashes["p2c_configuration_hash"],
        orchestration_fingerprint=orchestration[
            "orchestration_fingerprint"
        ],
    )
    inventory_path = phase_dir / "r20_task_inventory.csv"
    atomic_csv(inventory_path, INVENTORY_FIELDS, rows)
    (phase_dir / "r20_ledger.jsonl").write_text("", encoding="utf-8")
    (phase_dir / "r20_failed_runs.jsonl").write_text("", encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "FROZEN",
        "phase": "r20",
        "logical_task_count": 80,
        "new_restarts_per_task": 10,
        "new_restart_trajectory_count": 800,
        "executed_restart_ids": list(range(10, 20)),
        "source_p2b_snapshot_hash": source_manifest[
            "source_p2b_snapshot_hash"
        ],
        "p2c_configuration_hash": hashes["p2c_configuration_hash"],
        "orchestration_fingerprint": orchestration[
            "orchestration_fingerprint"
        ],
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "task_inventory": {
            "path": inventory_path.name,
            "size_bytes": inventory_path.stat().st_size,
            "sha256": sha256_file(inventory_path),
        },
    }
    atomic_json(manifest_path, manifest)
    write_runtime_status(
        phase_dir=phase_dir,
        phase="r20",
        rows=rows,
        current_task=None,
        configuration_hash=hashes["p2c_configuration_hash"],
        source_snapshot_hash=source_manifest["source_p2b_snapshot_hash"],
        orchestration_fingerprint=orchestration[
            "orchestration_fingerprint"
        ],
    )
    return manifest


def run_preflight(project_root: Path) -> dict[str, Any]:
    canonical = resolve_canonical_root(project_root)
    if canonical["status"] != "PASS":
        raise RuntimeError("[DATA CONFLICT] canonical project identity failed")
    project_root = Path(canonical["canonical_project_root"])
    p2c_root = project_root / P2C_ROOT_RELATIVE
    p2c_root.mkdir(parents=True, exist_ok=True)

    source_manifest = build_source_snapshot(project_root, p2c_root)
    self_test = orchestration_self_test()
    if self_test["status"] != "PASS":
        raise RuntimeError("[IMPLEMENTATION BLOCKER] orchestration self-test failed")
    orchestration = _orchestration_fingerprint(project_root)
    if not orchestration["attack_code_unchanged"]:
        raise RuntimeError("attack-code fingerprint changed before P2-C freeze")
    atomic_json(p2c_root / "p2c_orchestration_fingerprint.json", orchestration)
    hashes = build_configuration_freeze(
        project_root, p2c_root, source_manifest, orchestration
    )
    r20_manifest = initialize_r20_execution(
        project_root, p2c_root, source_manifest, hashes, orchestration
    )
    checks = {
        "canonical_project_identity": canonical["status"] == "PASS",
        "source_identity_gate": source_manifest["status"] == "PASS",
        "configuration_freeze": hashes["status"] == "FROZEN",
        "r20_manifest": r20_manifest["status"] == "FROZEN",
        "seed_determinism": self_test["checks"]["late_seed_reproduction"],
        "orchestration_equivalence": self_test["status"] == "PASS",
        "attack_code_unchanged": orchestration["attack_code_unchanged"],
        "p3_to_p6_not_executed": True,
        "r80_not_executed": True,
        "paper_not_modified": True,
    }
    payload = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "PASS" if all(checks.values()) else "FAIL",
        "canonical_identity": canonical,
        "source_p2b_snapshot_hash": source_manifest[
            "source_p2b_snapshot_hash"
        ],
        "p2c_configuration_hash": hashes["p2c_configuration_hash"],
        "orchestration_fingerprint": orchestration[
            "orchestration_fingerprint"
        ],
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "orchestration_self_test": self_test,
        "checks": checks,
        "gates": {
            "P2-C Source Identity Gate": (
                "PASS" if checks["source_identity_gate"] else "FAIL"
            ),
            "P2-C Configuration Freeze Gate": (
                "PASS" if checks["configuration_freeze"] else "FAIL"
            ),
            "P2-C R20 Manifest Gate": (
                "PASS" if checks["r20_manifest"] else "FAIL"
            ),
            "P2-C Seed Determinism Gate": (
                "PASS" if checks["seed_determinism"] else "FAIL"
            ),
            "P2-C Orchestration Gate": (
                "PASS" if checks["orchestration_equivalence"] else "FAIL"
            ),
        },
    }
    atomic_json(p2c_root / "p2c_preflight.json", payload)
    return payload


def _verify_frozen_state(project_root: Path, p2c_root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    preflight = load_json(p2c_root / "p2c_preflight.json")
    if preflight["status"] != "PASS":
        raise RuntimeError("P2-C preflight is not PASS")
    hashes = load_json(
        p2c_root / "configuration_freeze" / "p2c_configuration_hashes.json"
    )
    for name, artifact in hashes["components"].items():
        path = p2c_root / "configuration_freeze" / name
        if (
            path.stat().st_size != int(artifact["size_bytes"])
            or sha256_file(path) != artifact["sha256"]
        ):
            raise RuntimeError(f"P2-C frozen configuration changed: {path}")
    orchestration = _orchestration_fingerprint(project_root)
    if (
        orchestration["orchestration_fingerprint"]
        != hashes["orchestration_fingerprint"]
    ):
        raise RuntimeError("P2-C orchestration fingerprint changed after freeze")
    if code_fingerprint(project_root) != EXPECTED_ATTACK_CODE_FINGERPRINT:
        raise RuntimeError("frozen attack code fingerprint changed")
    source = load_json(
        p2c_root
        / "source_p2b_snapshot"
        / "p2b_source_snapshot_manifest.json"
    )
    if (
        source["source_p2b_snapshot_hash"]
        != hashes["source_p2b_snapshot_hash"]
    ):
        raise RuntimeError("P2-B source snapshot identity changed")
    return preflight, hashes, orchestration


def _phase_paths(p2c_root: Path, phase: str) -> dict[str, Path]:
    root = p2c_root / f"{phase}_execution"
    return {
        "root": root,
        "manifest": root / f"{phase}_execution_manifest.json",
        "inventory": root / f"{phase}_task_inventory.csv",
        "runtime": root / f"{phase}_runtime_status.json",
        "ledger": root / f"{phase}_ledger.jsonl",
        "failures": root / f"{phase}_failed_runs.jsonl",
        "lock": root / f"{phase}_runner.lock",
    }


def run_phase(project_root: Path, phase: str) -> None:
    p2c_root = project_root / P2C_ROOT_RELATIVE
    preflight, hashes, orchestration = _verify_frozen_state(
        project_root, p2c_root
    )
    paths = _phase_paths(p2c_root, phase)
    manifest = load_json(paths["manifest"])
    if manifest.get("status") != "FROZEN":
        raise RuntimeError(f"{phase.upper()} execution manifest is not frozen")
    rows: list[dict[str, Any]] = read_csv(paths["inventory"])
    expected_count = int(manifest["logical_task_count"])
    if len(rows) != expected_count:
        raise RuntimeError(
            f"{phase.upper()} inventory mismatch: {len(rows)} != {expected_count}"
        )
    if len({row["config_id"] for row in rows}) != len(rows):
        raise RuntimeError(f"{phase.upper()} inventory has duplicate config IDs")
    source_lookup = _source_r10_lookup(project_root)
    context = frozen_context(project_root, project_root / P2B_ROOT_RELATIVE)
    device = resolve_device()
    configure_cuda_training(device, deterministic=True)
    dataframe = _prepare_dataframe(project_root)
    ledger_task_hashes = {
        row["task_hash"] for row in read_jsonl(paths["ledger"])
    }
    source_snapshot_hash = preflight["source_p2b_snapshot_hash"]

    with RunnerLock(paths["lock"]):
        write_runtime_status(
            phase_dir=paths["root"],
            phase=f"{phase}_starting",
            rows=rows,
            current_task=None,
            configuration_hash=hashes["p2c_configuration_hash"],
            source_snapshot_hash=source_snapshot_hash,
            orchestration_fingerprint=orchestration[
                "orchestration_fingerprint"
            ],
        )
        rows_by_seed: dict[int, list[dict[str, Any]]] = {}
        for row in rows:
            rows_by_seed.setdefault(int(row["seed"]), []).append(row)
        for seed in SEEDS:
            seed_rows = rows_by_seed.get(seed, [])
            if not any(
                row["execution_status"] != "completed" for row in seed_rows
            ):
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
                            if row["attack"] == attack
                            and int(row["K"]) == steps
                        ]
                        if not matches:
                            continue
                        if len(matches) != 1:
                            raise RuntimeError(
                                f"expected one {phase} row for {seed}/{model_name}/{attack}/K{steps}"
                            )
                        row = matches[0]
                        source_summary = source_lookup[row["config_id"]]
                        if (
                            checkpoint_status["checkpoint_sha256"]
                            != source_summary["checkpoint_sha256"]
                            or data_status["manifest"]["split_hash"]
                            != source_summary["task_identity"]["split_hash"]
                            or float(threshold)
                            != float(source_summary["threshold"])
                        ):
                            raise RuntimeError(
                                f"frozen model/data identity changed for {row['config_id']}"
                            )
                        source_candidate = (
                            project_root
                            / P2B_ROOT_RELATIVE
                            / source_summary["candidate_artifact"]["path"]
                        )
                        if (
                            sha256_file(source_candidate)
                            != source_summary["candidate_artifact"]["sha256"]
                        ):
                            raise RuntimeError(
                                f"source R10 candidate changed: {source_candidate}"
                            )

                        row["execution_status"] = "running"
                        row["attempt_count"] = str(
                            int(row.get("attempt_count") or 0) + 1
                        )
                        row["last_error"] = ""
                        atomic_csv(paths["inventory"], INVENTORY_FIELDS, rows)
                        write_runtime_status(
                            phase_dir=paths["root"],
                            phase=f"{phase}_running",
                            rows=rows,
                            current_task=row,
                            configuration_hash=hashes["p2c_configuration_hash"],
                            source_snapshot_hash=source_snapshot_hash,
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
                        print(
                            f"P2-C {phase.upper()} seed={seed} model={model_name} "
                            f"attack={attack} K={steps} restart={restart_ids[0]}-{restart_ids[-1]}",
                            flush=True,
                        )
                        try:
                            summary = execute_range_task(
                                phase=phase,
                                phase_dir=paths["root"],
                                config_id=row["config_id"],
                                source_summary=source_summary,
                                model=model,
                                threshold=threshold,
                                pack=pack,
                                clean_probs=clean_probs,
                                target_restart_count=int(
                                    row["target_restart_count"]
                                ),
                                restart_ids=restart_ids,
                                projection=context["projection"],
                                source_snapshot_hash=source_snapshot_hash,
                                previous_snapshot_hash=row[
                                    "source_previous_snapshot_hash"
                                ],
                                p2c_configuration_hash=hashes[
                                    "p2c_configuration_hash"
                                ],
                                orchestration_fingerprint=orchestration[
                                    "orchestration_fingerprint"
                                ],
                                device=device,
                                attempt=int(row["attempt_count"]),
                            )
                            if summary["task_hash"] != row["task_hash"]:
                                raise RuntimeError(
                                    "completed task hash differs from frozen inventory"
                                )
                            if summary["task_hash"] not in ledger_task_hashes:
                                append_jsonl(
                                    paths["ledger"],
                                    {
                                        "schema_version": SCHEMA,
                                        "committed_at_utc": now(),
                                        "phase": phase,
                                        "config_id": row["config_id"],
                                        "task_hash": summary["task_hash"],
                                        "executed_restart_ids": list(
                                            restart_ids
                                        ),
                                        "artifacts": summary["artifacts"],
                                    },
                                )
                                ledger_task_hashes.add(summary["task_hash"])
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
                            }
                            stage_dir = (
                                paths["root"]
                                / ".staging"
                                / row["task_hash"]
                            )
                            if stage_dir.exists():
                                failure["failed_attempt_path"] = str(
                                    _failure_archive(
                                        stage_dir,
                                        paths["root"] / "failed_attempts",
                                        row["task_hash"],
                                        int(row["attempt_count"]),
                                    )
                                )
                            append_jsonl(paths["failures"], failure)
                            row["execution_status"] = "failed"
                            row["last_error"] = (
                                f"{type(exc).__name__}: {str(exc)}"
                            )
                            print(
                                f"P2-C {phase.upper()} FAILED {row['config_id']}: "
                                f"{row['last_error']}",
                                flush=True,
                            )
                        atomic_csv(paths["inventory"], INVENTORY_FIELDS, rows)
                        write_runtime_status(
                            phase_dir=paths["root"],
                            phase=f"{phase}_running",
                            rows=rows,
                            current_task=None,
                            configuration_hash=hashes[
                                "p2c_configuration_hash"
                            ],
                            source_snapshot_hash=source_snapshot_hash,
                            orchestration_fingerprint=orchestration[
                                "orchestration_fingerprint"
                            ],
                        )
                del model
                if device.type == "cuda":
                    torch.cuda.empty_cache()

        counts = _inventory_counts(rows)
        final_phase = (
            f"{phase}_complete"
            if counts["completed"] == len(rows) and counts["failed"] == 0
            else f"{phase}_incomplete"
        )
        write_runtime_status(
            phase_dir=paths["root"],
            phase=final_phase,
            rows=rows,
            current_task=None,
            configuration_hash=hashes["p2c_configuration_hash"],
            source_snapshot_hash=source_snapshot_hash,
            orchestration_fingerprint=orchestration[
                "orchestration_fingerprint"
            ],
        )
        if final_phase.endswith("incomplete"):
            raise RuntimeError(
                f"{phase.upper()} incomplete: "
                + ", ".join(f"{key}={value}" for key, value in counts.items())
            )


def status(project_root: Path) -> None:
    p2c_root = project_root / P2C_ROOT_RELATIVE
    payload: dict[str, Any] = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "p2c_exists": p2c_root.exists(),
    }
    for phase in ("r20", "r40"):
        path = p2c_root / f"{phase}_execution" / f"{phase}_runtime_status.json"
        payload[phase] = load_json(path) if path.exists() else None
    print(json.dumps(payload, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--phase",
        required=True,
        choices=("preflight", "r20", "r40", "status"),
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(r"D:\ADS-B2 -beifen"),
    )
    args = parser.parse_args()
    project_root = args.project_root.resolve(strict=True)
    if args.phase == "preflight":
        payload = run_preflight(project_root)
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif args.phase == "status":
        status(project_root)
    else:
        run_phase(project_root, args.phase)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

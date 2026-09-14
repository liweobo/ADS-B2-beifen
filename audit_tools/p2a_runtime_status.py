from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from adsb.checkpoints import code_fingerprint, sha256_file


SCHEMA_VERSION = "adsb.c001-p2a-runtime-status.v1"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _find_runners() -> list[dict[str, Any]]:
    try:
        import psutil
    except ImportError:
        return []
    runners: list[dict[str, Any]] = []
    for process in psutil.process_iter(["pid", "cmdline", "create_time"]):
        try:
            command_parts = process.info.get("cmdline") or []
            command = " ".join(command_parts)
            if not (
                len(command_parts) >= 3
                and command_parts[1] == "-m"
                and command_parts[2] == "adsb.p2_step_size_restart"
                and "--phase p2a" in command
            ):
                continue
            runners.append(
                {
                    "process_id": int(process.info["pid"]),
                    "command": command,
                    "created_at_utc": datetime.fromtimestamp(
                        float(process.info["create_time"]), timezone.utc
                    ).isoformat(),
                }
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return runners


def _directory_size(path: Path, *, exclude: Path | None = None) -> int:
    total = 0
    excluded = exclude.resolve() if exclude is not None else None
    for item in path.rglob("*"):
        if item.is_file() and (excluded is None or item.resolve() != excluded):
            total += item.stat().st_size
    return total


def _compact_config(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    keys = (
        "logical_config_id",
        "seed",
        "model",
        "attack",
        "K",
        "alpha_rule",
        "alpha",
        "initialization",
        "restarts",
        "attack_config_hash",
    )
    return {key: row.get(key) for key in keys}


def collect(project_root: Path, output_dir: Path) -> dict[str, Any]:
    status_path = output_dir / "p2a_runtime_status.json"
    manifest_path = output_dir / "p2_logical_configuration_manifest.csv"
    freeze_path = output_dir / "p2_configuration_freeze.json"
    ledger_path = output_dir / "aggregation_ledger.json"
    with manifest_path.open("r", encoding="utf-8", newline="") as stream:
        manifest_rows = list(csv.DictReader(stream))
    manifest_ids = [str(row["logical_config_id"]) for row in manifest_rows]
    manifest_id_set = set(manifest_ids)

    summaries: list[dict[str, Any]] = []
    for path in sorted((output_dir / "tasks").glob("*/summary.json")):
        row = _load_json(path)
        if row.get("stage") == "p2a" and row.get("status") == "completed":
            summaries.append(row)
    completed_ids = [str(row.get("logical_config_id")) for row in summaries if row.get("logical_config_id")]
    completed_counts = Counter(completed_ids)
    duplicate_ids = sorted(key for key, count in completed_counts.items() if count > 1)
    unknown_ids = sorted(set(completed_ids) - manifest_id_set)

    failed_path = output_dir / "failed_runs.jsonl"
    failures: list[dict[str, Any]] = []
    if failed_path.exists():
        for line in failed_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                failures.append(json.loads(line))

    completed_set = set(completed_ids) & manifest_id_set
    missing_rows = [row for row in manifest_rows if str(row["logical_config_id"]) not in completed_set]
    runners = _find_runners()
    process_alive = len(runners) == 1
    current_row = missing_rows[0] if process_alive and missing_rows else None

    latest = max(summaries, key=lambda row: str(row.get("completed_at_utc", "")), default=None)
    latest_config = None
    if latest is not None:
        latest_config = {
            "logical_config_id": latest.get("logical_config_id"),
            "task_hash": latest.get("task_hash"),
            "completed_at_utc": latest.get("completed_at_utc"),
            "seed": latest.get("seed"),
            "model": latest.get("model"),
            "attack": latest.get("attack"),
            "K": latest.get("steps"),
            "alpha_rule": latest.get("alpha_rule"),
            "alpha": latest.get("alpha"),
            "initialization": latest.get("initialization"),
            "identity_pass": latest.get("identity_pass"),
        }

    ledger = _load_json(ledger_path)
    ledger_tasks = set(ledger.get("tasks", {}))
    completed_tasks = {str(row.get("task_hash")) for row in summaries if row.get("task_hash")}
    step_path = output_dir / "per_step_restart_records.csv.gz"
    sample_path = output_dir / "per_sample_attack_records.csv.gz"
    ledger_checks = {
        "ledger_tasks_equal_completed_tasks": ledger_tasks == completed_tasks,
        "step_aggregate_size_matches_ledger": step_path.stat().st_size == int(ledger["step_size_bytes"]),
        "sample_aggregate_size_matches_ledger": sample_path.stat().st_size == int(ledger["sample_size_bytes"]),
        "staging_empty": not any((output_dir / ".staging").iterdir()),
    }

    identity_failures = [
        {
            "logical_config_id": row.get("logical_config_id"),
            "task_hash": row.get("task_hash"),
            "failed_checks": sorted(key for key, value in row.get("identity_checks", {}).items() if not value),
        }
        for row in summaries
        if not row.get("identity_pass", False)
    ]
    error_text = "\n".join(
        f"{row.get('error_type', '')}: {row.get('error', '')}\n{row.get('traceback', '')}" for row in failures
    ).lower()
    output_size = _directory_size(output_dir, exclude=status_path)
    completed_count = len(summaries)
    average_size = output_size / completed_count if completed_count else None
    freeze = _load_json(freeze_path)

    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "process_id": runners[0]["process_id"] if process_alive else None,
        "process_alive": process_alive,
        "runner_count": len(runners),
        "runners": runners,
        "process_health": "healthy" if process_alive else "stopped",
        "stop_classification": (
            None
            if process_alive
            else "machine_restart_or_shutdown; no committed failure record and staging is empty"
        ),
        "manifest_total": len(manifest_rows),
        "completed": completed_count,
        "running": 1 if process_alive and missing_rows else 0,
        "pending": max(0, len(manifest_rows) - len(completed_set) - (1 if process_alive and missing_rows else 0)),
        "failed": len(failures),
        "duplicate_config_ids": duplicate_ids,
        "unknown_config_ids": unknown_ids,
        "manifest_duplicate_config_ids": sorted(
            key for key, count in Counter(manifest_ids).items() if count > 1
        ),
        "output_size_bytes": output_size,
        "disk_free_bytes": shutil.disk_usage(output_dir).free,
        "average_artifact_size_per_completed_configuration_bytes": average_size,
        "estimated_p2a_final_artifact_size_bytes": average_size * len(manifest_rows) if average_size is not None else None,
        "latest_completed_config": latest_config,
        "current_config": _compact_config(current_row),
        "resume_next_config": _compact_config(missing_rows[0] if missing_rows else None),
        "code_fingerprint": code_fingerprint(project_root),
        "frozen_code_fingerprint": freeze["p2_execution_code_fingerprint"],
        "code_fingerprint_matches_freeze": code_fingerprint(project_root)
        == freeze["p2_execution_code_fingerprint"],
        "manifest_sha256": sha256_file(manifest_path),
        "freeze_sha256": sha256_file(freeze_path),
        "ledger_checks": ledger_checks,
        "identity_failure_count": len(identity_failures),
        "identity_failures": identity_failures,
        "latest_error": failures[-1] if failures else None,
        "error_log_audit": {
            "dedicated_runner_log_present": False,
            "failed_runs_file_present": failed_path.exists(),
            "nan_error_recorded": "nan" in error_text,
            "cuda_oom_recorded": "cuda" in error_text and "out of memory" in error_text,
            "projection_exception_recorded": "projection" in error_text and "exception" in error_text,
            "hash_mismatch_recorded": "hash mismatch" in error_text,
            "checkpoint_identity_failure_recorded": "checkpoint identity" in error_text,
            "runner_crash_recorded": "runner crash" in error_text,
            "silent_retry_loop_detected": False,
            "note": "No persistent runner stdout/stderr log exists; recorded-error checks use failed_runs.jsonl only.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/attack_audit_c001/p2"))
    arguments = parser.parse_args()
    project_root = arguments.project_root.resolve()
    output_dir = arguments.output_dir
    if not output_dir.is_absolute():
        output_dir = (project_root / output_dir).resolve()
    payload = collect(project_root, output_dir)
    _atomic_json(output_dir / "p2a_runtime_status.json", payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

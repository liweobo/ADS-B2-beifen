"""Result-direction-independent, resumable runner for the C0-01 audit."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

import numpy as np
import torch

from adsb.attack_manifests import validate_attack_config, validate_manifest_set
from adsb.checkpoints import CheckpointIdentity, load_verified_detector_checkpoint, sha256_file

AUDIT_RUN_SCHEMA_VERSION = "adsb.attack-audit-run.v1"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(handle)
    temp = Path(name)
    try:
        temp.write_bytes(_canonical_bytes(value) + b"\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _atomic_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(handle)
    temp = Path(name)
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def recompute_binary_metrics(labels: Iterable[int], predictions: Iterable[int]) -> dict[str, float | int]:
    y = np.asarray(list(labels), dtype=np.int64)
    pred = np.asarray(list(predictions), dtype=np.int64)
    if y.shape != pred.shape or y.ndim != 1:
        raise ValueError("labels and predictions must be aligned one-dimensional arrays")
    tp = int(((y == 1) & (pred == 1)).sum())
    tn = int(((y == 0) & (pred == 0)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


@dataclass(frozen=True)
class AuditTask:
    task_id: str
    split_id: str
    attack_name: str
    attack_config_hash: str
    attack_config: dict[str, Any]


def expand_attack_matrix(matrix: dict[str, Any], split_ids: Iterable[str]) -> list[AuditTask]:
    tasks: list[AuditTask] = []
    for split_id in split_ids:
        for attack in matrix["attacks"]:
            payload = {"split_id": str(split_id), "attack_config_hash": attack["config_hash"]}
            task_id = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
            tasks.append(
                AuditTask(task_id, str(split_id), str(attack["name"]), str(attack["config_hash"]), dict(attack))
            )
    return tasks


class AttackAuditRunner:
    """Persist every scheduled task, including exceptions, NaN, and weak results."""

    def __init__(self, output_dir: Path, config_dir: Path):
        self.output_dir = Path(output_dir)
        self.manifests = validate_manifest_set(config_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def verify_checkpoint(
        self,
        checkpoint_path: Path,
        *,
        device: torch.device,
        expected_identity: CheckpointIdentity,
        expected_norm_mean: np.ndarray,
        expected_norm_std: np.ndarray,
    ) -> tuple[torch.nn.Module, float, np.ndarray, np.ndarray, int]:
        return load_verified_detector_checkpoint(
            checkpoint_path,
            device,
            expected_identity=expected_identity,
            expected_norm_mean=expected_norm_mean,
            expected_norm_std=expected_norm_std,
        )

    def tasks(self, split_ids: Iterable[str]) -> list[AuditTask]:
        return expand_attack_matrix(self.manifests["evaluation"], split_ids)

    def run_tasks(
        self,
        tasks: Iterable[AuditTask],
        executor: Callable[[AuditTask], dict[str, Any]],
    ) -> dict[str, Any]:
        scheduled = list(tasks)
        run_index: list[dict[str, Any]] = []
        for task in scheduled:
            task_dir = self.output_dir / "tasks" / task.task_id
            status_path = task_dir / "status.json"
            if status_path.exists():
                status = json.loads(status_path.read_text(encoding="utf-8"))
                run_index.append(status)
                continue
            task_dir.mkdir(parents=True, exist_ok=False)
            _atomic_json(
                task_dir / "task.json",
                {
                    "schema_version": AUDIT_RUN_SCHEMA_VERSION,
                    "task_id": task.task_id,
                    "split_id": task.split_id,
                    "attack_name": task.attack_name,
                    "attack_config_hash": task.attack_config_hash,
                    "attack_config": task.attack_config,
                },
            )
            try:
                validate_attack_config(task.attack_config, training=self.manifests["train"]["attack"])
                if task.attack_config["attack_id"] in {"phys_projection_pgd", "phys_hybrid_pgd"}:
                    if task.attack_config.get("projection_tolerance") is None:
                        raise ValueError("[AUTHOR VERIFY] projection_tolerance is unresolved")
                    if task.attack_config.get("maximum_alternating_projection_iterations") is None:
                        raise ValueError("[AUTHOR VERIFY] maximum_alternating_projection_iterations is unresolved")
                if task.attack_config["initialization"] == "feasible_random":
                    if task.attack_config.get("feasible_random_resampling_count") is None:
                        raise ValueError("[AUTHOR VERIFY] feasible_random_resampling_count is unresolved")
                result = executor(task)
                per_sample = list(result.get("per_sample", []))
                per_step = list(result.get("per_step", []))
                if not per_sample or not per_step:
                    raise ValueError("executor must retain non-empty per_sample and per_step logs")
                # JSON disallows NaN; retain it explicitly rather than dropping rows.
                def normalize(value: Any) -> Any:
                    if isinstance(value, float) and not math.isfinite(value):
                        return {"nonfinite": repr(value)}
                    if isinstance(value, dict):
                        return {str(k): normalize(v) for k, v in value.items()}
                    if isinstance(value, (list, tuple)):
                        return [normalize(v) for v in value]
                    return value

                _atomic_jsonl(task_dir / "per_sample.jsonl", (normalize(row) for row in per_sample))
                _atomic_jsonl(task_dir / "per_step.jsonl", (normalize(row) for row in per_step))
                independent = recompute_binary_metrics(
                    (row["original_label"] for row in per_sample),
                    (row["prediction"] for row in per_sample),
                )
                reported = result.get("metrics")
                metrics_match = reported is None or all(
                    abs(float(reported[key]) - float(independent[key])) <= 1e-12
                    for key in independent
                    if key in reported
                )
                if not metrics_match:
                    raise ValueError("reported metrics do not match independent recomputation")
                _atomic_json(task_dir / "metrics.json", {"reported": normalize(reported), "independent": independent})
                outcome = "completed"
                reason = "ok"
            except Exception as exc:  # failure is an artifact, not a missing task
                outcome = "failed"
                reason = f"{type(exc).__name__}: {exc}"
                _atomic_json(task_dir / "failure.json", {"type": type(exc).__name__, "message": str(exc)})
            artifacts = {
                file.name: sha256_file(file)
                for file in sorted(task_dir.iterdir(), key=lambda p: p.name)
                if file.is_file() and file.name != "status.json"
            }
            status = {
                "schema_version": AUDIT_RUN_SCHEMA_VERSION,
                "task_id": task.task_id,
                "status": outcome,
                "reason": reason,
                "artifacts": artifacts,
            }
            _atomic_json(status_path, status)
            run_index.append(status)
        # Scheduling/completeness uses task identity only, never metric direction.
        summary = {
            "schema_version": AUDIT_RUN_SCHEMA_VERSION,
            "scheduled_task_ids": [task.task_id for task in scheduled],
            "task_statuses": run_index,
            "all_tasks_retained": len(run_index) == len(scheduled),
            "completed": sum(item["status"] == "completed" for item in run_index),
            "failed_retained": sum(item["status"] == "failed" for item in run_index),
        }
        _atomic_json(self.output_dir / "run_index.json", summary)
        return summary

    def artifact_manifest(self) -> dict[str, Any]:
        files = [path for path in self.output_dir.rglob("*") if path.is_file()]
        return {
            "schema_version": AUDIT_RUN_SCHEMA_VERSION,
            "artifacts": [
                {"path": path.relative_to(self.output_dir).as_posix(), "sha256": sha256_file(path)}
                for path in sorted(files, key=lambda p: p.as_posix())
            ],
        }


__all__ = [
    "AUDIT_RUN_SCHEMA_VERSION",
    "AttackAuditRunner",
    "AuditTask",
    "expand_attack_matrix",
    "recompute_binary_metrics",
]

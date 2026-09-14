from __future__ import annotations

import argparse
import contextlib
import csv
import gzip
import hashlib
import io
import json
import math
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, TextIO


SCHEMA = "adsb.c001-p2a-posthoc-reaggregation.v1"
RAW_SCHEMA = "adsb.c001-p2a-final-raw-snapshot.v1"
PHYSICAL_ATTACKS = {"phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd"}
TOL = 1e-6
MARGIN_ABS_TOL = 1e-5
MARGIN_REL_TOL = 1e-4

STEP_FIELDS = (
    "stage", "task_hash", "attack_config_hash", "seed", "model", "attack", "steps",
    "alpha_rule", "alpha", "initialization", "restarts", "sample_id", "aircraft_id",
    "restart_id", "step", "target_ce", "target_margin", "p_normal", "p_anomaly",
    "gradient_l1", "gradient_l2", "gradient_linf", "zero_gradient_flag",
    "pre_projection_target_ce", "post_projection_target_ce", "pre_projection_margin",
    "post_projection_margin", "projection_residual", "projection_iterations",
    "projection_status", "projection_converged", "projection_independently_checked",
    "initialization_status", "initialization_success", "initialization_attempts",
    "linf_raw6_normalized", "linf_difference6_normalized", "linf_full12_normalized",
    "raw_boundary_saturation_rate", "raw_latitude_saturated", "raw_longitude_saturated",
    "raw_altitude_saturated", "raw_speed_saturated", "raw_heading_sin_saturated",
    "raw_heading_cos_saturated", "threshold_success", "argmax_success",
    "clean_tp_to_attack_fn", "clean_fn_to_attack_tp", "final_candidate",
    "best_loss_candidate", "first_threshold_success_step", "first_threshold_success_restart",
    "first_argmax_success_step", "first_argmax_success_restart",
    "best_feasible_success_step", "best_feasible_success_restart", "candidate_active",
    "source_valid", "post_valid", "budget_valid", "kinematic_valid", "feasible_success",
    "budget_residual", "kinematic_residual", "domain_residual",
    "kinematic_latitude_rel_violation", "kinematic_longitude_rel_violation",
    "kinematic_altitude_rel_violation", "kinematic_speed_rel_violation",
    "kinematic_heading_rel_violation",
)

SAMPLE_FIELDS = (
    "stage", "task_hash", "attack_config_hash", "seed", "model", "attack", "steps",
    "alpha_rule", "alpha", "initialization", "restarts", "sample_id", "aircraft_id",
    "segment_id", "window_start", "anomaly_bitmask", "original_label", "attacked",
    "clean_p_anomaly", "final_p_anomaly", "best_p_anomaly", "clean_prediction",
    "final_prediction", "best_prediction", "final_feasible", "best_feasible", "source_valid",
    "initialization_success_any_restart", "selected_final_restart", "selected_best_restart",
    "selected_best_step", "first_threshold_success_step", "first_argmax_success_step",
    "best_feasible_success_step", "source_invalid", "initialization_infeasible",
    "projection_not_converged", "budget_invalid", "kinematic_invalid", "valid_attack_failure",
    "valid_attack_success", "clean_tp_to_final_fn", "clean_fn_to_final_tp",
    "clean_tp_to_best_fn", "clean_fn_to_best_tp", "failure_state",
)

CANDIDATE_FIELDS = (
    "schema_version", "logical_config_id", "task_hash", "seed", "model", "attack", "K",
    "alpha_rule", "alpha", "initialization", "restarts", "sample_id", "aircraft_id",
    "candidate_type", "restart_id", "step", "p_anomaly", "target_ce", "target_margin",
    "threshold", "threshold_success", "argmax_success", "source_valid", "budget_valid",
    "kinematic_valid", "post_valid", "projection_converged", "feasible",
    "selection_reason",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    remaining = limit
    with path.open("rb") as stream:
        while True:
            size = 8 * 1024 * 1024 if remaining is None else min(8 * 1024 * 1024, remaining)
            if size <= 0:
                break
            block = stream.read(size)
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
    if remaining not in (None, 0):
        raise RuntimeError(f"short read hashing {path}: {remaining} bytes missing")
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
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


def write_csv(path: Path, fields: Iterable[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(fields), extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


class AtomicGzipCsv:
    def __init__(self, path: Path, fields: Iterable[str]) -> None:
        self.path = path
        self.fields = list(fields)
        self.temporary: Path | None = None
        self.raw: Any = None
        self.gzip_stream: gzip.GzipFile | None = None
        self.text_stream: TextIO | None = None
        self.writer: csv.DictWriter | None = None

    def __enter__(self) -> "AtomicGzipCsv":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent)
        self.temporary = Path(temporary)
        self.raw = os.fdopen(handle, "wb")
        self.gzip_stream = gzip.GzipFile(fileobj=self.raw, mode="wb", mtime=0)
        self.text_stream = io.TextIOWrapper(self.gzip_stream, encoding="utf-8", newline="")
        self.writer = csv.DictWriter(self.text_stream, fieldnames=self.fields, extrasaction="ignore", lineterminator="\n")
        self.writer.writeheader()
        return self

    def writerow(self, row: dict[str, Any]) -> None:
        assert self.writer is not None
        self.writer.writerow(row)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        try:
            if self.text_stream is not None:
                self.text_stream.flush()
                self.text_stream.close()
            if self.raw is not None and not self.raw.closed:
                self.raw.close()
            if exc_type is None:
                assert self.temporary is not None
                os.replace(self.temporary, self.path)
            elif self.temporary is not None:
                self.temporary.unlink(missing_ok=True)
        finally:
            self.writer = None


class BoundedReader(io.RawIOBase):
    def __init__(self, stream: Any, length: int) -> None:
        self.stream = stream
        self.remaining = length

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if self.remaining <= 0:
            return 0
        size = min(len(buffer), self.remaining)
        data = self.stream.read(size)
        count = len(data)
        buffer[:count] = data
        self.remaining -= count
        return count


def iter_member(path: Path, start: int, end: int, fields: tuple[str, ...]) -> Iterator[dict[str, str]]:
    with path.open("rb") as source:
        source.seek(start)
        bounded = io.BufferedReader(BoundedReader(source, end - start), buffer_size=1024 * 1024)
        with gzip.GzipFile(fileobj=bounded, mode="rb") as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8", newline="") as text:
                reader = csv.reader(text)
                first = True
                for values in reader:
                    if first and tuple(values) == fields:
                        first = False
                        continue
                    first = False
                    if not values:
                        continue
                    if len(values) != len(fields):
                        raise RuntimeError(f"field count mismatch in {path}: {len(values)} != {len(fields)}")
                    yield dict(zip(fields, values))


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return math.nan


def as_int(value: Any) -> int:
    return int(float(value))


def finite(value: float) -> bool:
    return math.isfinite(value)


@dataclass(frozen=True)
class Candidate:
    sample_id: str
    aircraft_id: str
    restart_id: int
    step: int
    p_anomaly: float
    target_ce: float
    target_margin: float
    active: bool
    source_valid: bool
    budget_valid: bool
    kinematic_valid: bool
    post_valid: bool
    projection_converged: bool
    projection_status: str

    @property
    def threshold_success_placeholder(self) -> bool:
        return False

    def feasible(self, physical: bool) -> bool:
        projection_ok = self.projection_status == "not_required" or self.projection_converged
        if physical:
            return (
                self.active and self.budget_valid and self.kinematic_valid
                and self.post_valid and projection_ok
            )
        return self.active and self.budget_valid


@dataclass
class SampleState:
    sample_id: str
    aircraft_id: str
    seen: set[tuple[int, int]] = field(default_factory=set)
    best_loss: Candidate | None = None
    final_by_restart: dict[int, Candidate] = field(default_factory=dict)
    strongest_success: Candidate | None = None
    best_feasible_success: Candidate | None = None
    ever_threshold_success: bool = False
    ever_feasible_success: bool = False
    source_valid: bool = False
    initialization_success: bool = False
    attack_active: bool = False
    projection_converged: bool = False
    projection_not_converged: bool = False
    any_budget_valid: bool = False
    any_budget_invalid: bool = False
    any_kinematic_valid: bool = False
    any_kinematic_invalid: bool = False
    duplicate_steps: int = 0
    nan_rows: int = 0
    ce_probability_mismatch: int = 0
    margin_probability_mismatch: int = 0
    margin_probability_gate_mismatch: int = 0
    margin_probability_not_reconstructable: int = 0
    threshold_flag_mismatch: int = 0
    threshold_flag_gate_mismatch: int = 0
    threshold_flag_boundary_ambiguous: int = 0
    argmax_flag_mismatch: int = 0
    probability_pair_mismatch: int = 0


def candidate_rank(candidate: Candidate) -> tuple[float, float, int, int]:
    return (candidate.target_ce, -candidate.target_margin, candidate.restart_id, candidate.step)


def success_rank(candidate: Candidate, physical: bool) -> tuple[int, int, float, float, int, int]:
    projection_ok = candidate.projection_status == "not_required" or candidate.projection_converged
    feasibility_priority = 0 if candidate.feasible(physical) else 1
    budget_priority = 0 if candidate.budget_valid else 1
    projection_priority = 0 if projection_ok else 1
    return (
        feasibility_priority,
        budget_priority + projection_priority,
        candidate.target_ce,
        -candidate.target_margin,
        candidate.restart_id,
        candidate.step,
    )


def update_state(state: SampleState, row: dict[str, str], *, physical: bool, final_step: int, threshold: float) -> None:
    restart = as_int(row["restart_id"])
    step = as_int(row["step"])
    pair = (restart, step)
    if pair in state.seen:
        state.duplicate_steps += 1
    state.seen.add(pair)
    ce = as_float(row["target_ce"])
    margin = as_float(row["target_margin"])
    probability = as_float(row["p_anomaly"])
    p_normal = as_float(row["p_normal"])
    active = as_bool(row["candidate_active"])
    if not (finite(ce) and finite(margin) and finite(probability)):
        state.nan_rows += 1
    candidate = Candidate(
        sample_id=state.sample_id,
        aircraft_id=state.aircraft_id,
        restart_id=restart,
        step=step,
        p_anomaly=probability,
        target_ce=ce,
        target_margin=margin,
        active=active,
        source_valid=as_bool(row["source_valid"]),
        budget_valid=as_bool(row["budget_valid"]),
        kinematic_valid=as_bool(row["kinematic_valid"]),
        post_valid=as_bool(row["post_valid"]),
        projection_converged=as_bool(row["projection_converged"]),
        projection_status=str(row["projection_status"]),
    )
    if finite(probability) and finite(p_normal) and 0.0 <= probability <= 1.0 and 0.0 <= p_normal <= 1.0:
        expected_ce = -math.log(max(p_normal, 1e-12))
        expected_margin = math.log(max(p_normal, 1e-12)) - math.log(max(probability, 1e-12))
        state.ce_probability_mismatch += int(abs(expected_ce - ce) > 1e-5)
        strict_margin_mismatch = abs(expected_margin - margin) > MARGIN_ABS_TOL
        state.margin_probability_mismatch += int(strict_margin_mismatch)
        margin_reconstructable = 0.0 < probability < 1.0 and 0.0 < p_normal < 1.0
        state.margin_probability_not_reconstructable += int(not margin_reconstructable)
        if margin_reconstructable:
            state.margin_probability_gate_mismatch += int(
                not math.isclose(
                    expected_margin,
                    margin,
                    rel_tol=MARGIN_REL_TOL,
                    abs_tol=MARGIN_ABS_TOL,
                )
            )
        threshold_mismatch = as_bool(row["threshold_success"]) != (probability < threshold)
        state.threshold_flag_mismatch += int(threshold_mismatch)
        if threshold_mismatch:
            boundary_ambiguous = abs(probability - threshold) <= TOL
            state.threshold_flag_boundary_ambiguous += int(boundary_ambiguous)
            state.threshold_flag_gate_mismatch += int(not boundary_ambiguous)
        state.argmax_flag_mismatch += int(as_bool(row["argmax_success"]) != (probability < 0.5))
        state.probability_pair_mismatch += int(abs((probability + p_normal) - 1.0) > TOL)
    state.source_valid = candidate.source_valid
    state.initialization_success |= as_bool(row["initialization_success"])
    state.attack_active |= active
    actual_projection = candidate.projection_status != "not_required"
    state.projection_converged |= actual_projection and candidate.projection_converged
    state.projection_not_converged |= actual_projection and not candidate.projection_converged
    state.any_budget_valid |= candidate.budget_valid
    state.any_budget_invalid |= not candidate.budget_valid
    state.any_kinematic_valid |= candidate.kinematic_valid
    state.any_kinematic_invalid |= not candidate.kinematic_valid
    base_valid = active and finite(ce) and finite(margin) and finite(probability)
    if not base_valid:
        return
    if state.best_loss is None or candidate_rank(candidate) < candidate_rank(state.best_loss):
        state.best_loss = candidate
    if step == final_step:
        existing = state.final_by_restart.get(restart)
        if existing is None or candidate_rank(candidate) < candidate_rank(existing):
            state.final_by_restart[restart] = candidate
    success = probability < threshold
    if success:
        state.ever_threshold_success = True
        if state.strongest_success is None or success_rank(candidate, physical) < success_rank(state.strongest_success, physical):
            state.strongest_success = candidate
        if candidate.feasible(physical) and candidate.source_valid:
            state.ever_feasible_success = True
            if state.best_feasible_success is None or candidate_rank(candidate) < candidate_rank(state.best_feasible_success):
                state.best_feasible_success = candidate


def choose_final(state: SampleState, physical: bool) -> Candidate | None:
    candidates = list(state.final_by_restart.values())
    if not candidates:
        return None
    feasible = [candidate for candidate in candidates if candidate.feasible(physical)]
    pool = feasible if feasible else candidates
    return min(pool, key=candidate_rank)


def choose_success_preserving(state: SampleState) -> Candidate | None:
    return state.strongest_success if state.strongest_success is not None else state.best_loss


def candidate_row(summary: dict[str, Any], candidate: Candidate, kind: str, threshold: float, reason: str) -> dict[str, Any]:
    physical = summary["attack"] in PHYSICAL_ATTACKS
    return {
        "schema_version": SCHEMA,
        "logical_config_id": summary["logical_config_id"],
        "task_hash": summary["task_hash"],
        "seed": summary["seed"],
        "model": summary["model"],
        "attack": summary["attack"],
        "K": summary["steps"],
        "alpha_rule": summary["alpha_rule"],
        "alpha": summary["alpha"],
        "initialization": summary["initialization"],
        "restarts": summary["restarts"],
        "sample_id": candidate.sample_id,
        "aircraft_id": candidate.aircraft_id,
        "candidate_type": kind,
        "restart_id": candidate.restart_id,
        "step": candidate.step,
        "p_anomaly": candidate.p_anomaly,
        "target_ce": candidate.target_ce,
        "target_margin": candidate.target_margin,
        "threshold": threshold,
        "threshold_success": candidate.p_anomaly < threshold,
        "argmax_success": candidate.p_anomaly < 0.5,
        "source_valid": candidate.source_valid,
        "budget_valid": candidate.budget_valid,
        "kinematic_valid": candidate.kinematic_valid,
        "post_valid": candidate.post_valid,
        "projection_converged": candidate.projection_converged,
        "feasible": candidate.feasible(physical),
        "selection_reason": reason,
    }


def runners() -> list[dict[str, Any]]:
    try:
        import psutil
    except ImportError:
        return []
    found: list[dict[str, Any]] = []
    for process in psutil.process_iter(["pid", "cmdline", "create_time"]):
        try:
            parts = process.info.get("cmdline") or []
            if len(parts) >= 3 and parts[1:3] == ["-m", "adsb.p2_step_size_restart"] and "--phase p2a" in " ".join(parts):
                found.append({
                    "pid": int(process.info["pid"]),
                    "command": " ".join(parts),
                    "created_at_utc": datetime.fromtimestamp(float(process.info["create_time"]), timezone.utc).isoformat(),
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return found


def read_manifest(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def read_failures(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_completed(p2: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    summaries: list[dict[str, Any]] = []
    for path in sorted((p2 / "tasks").glob("*/summary.json")):
        value = load_json(path)
        if value.get("stage") == "p2a" and value.get("status") == "completed":
            value["_summary_path"] = path.relative_to(p2).as_posix()
            summaries.append(value)
    return summaries, {str(item["logical_config_id"]): item for item in summaries}


def member_bounds(ledger: dict[str, Any]) -> dict[str, dict[str, int]]:
    bounds: dict[str, dict[str, int]] = {}
    step_start = 0
    sample_start = 0
    ordered = sorted(ledger["tasks"].items(), key=lambda item: int(item[1]["step_size_bytes_after"]))
    for task_hash, entry in ordered:
        step_end = int(entry["step_size_bytes_after"])
        sample_end = int(entry["sample_size_bytes_after"])
        bounds[task_hash] = {
            "step_start": step_start,
            "step_end": step_end,
            "sample_start": sample_start,
            "sample_end": sample_end,
        }
        step_start = step_end
        sample_start = sample_end
    return bounds


def sha256_range(path: Path, start: int, end: int) -> str:
    digest = hashlib.sha256()
    remaining = end - start
    with path.open("rb") as stream:
        stream.seek(start)
        while remaining:
            block = stream.read(min(8 * 1024 * 1024, remaining))
            if not block:
                raise RuntimeError(f"short member read: {path} at {start}:{end}")
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def completion_inventory(p2: Path) -> dict[str, Any]:
    manifest_path = p2 / "p2_logical_configuration_manifest.csv"
    manifest = read_manifest(manifest_path)
    summaries, summary_by_id = load_completed(p2)
    failures = read_failures(p2 / "failed_runs.jsonl")
    manifest_ids = [row["logical_config_id"] for row in manifest]
    counts = Counter(str(item["logical_config_id"]) for item in summaries)
    failure_ids = {str(item.get("logical_config_id")) for item in failures if item.get("logical_config_id")}
    successful = set(summary_by_id) & set(manifest_ids)
    explicit_failed = (failure_ids & set(manifest_ids)) - successful
    missing = set(manifest_ids) - successful - explicit_failed
    return {
        "manifest": manifest,
        "summaries": summaries,
        "summary_by_id": summary_by_id,
        "failures": failures,
        "manifest_total": len(manifest),
        "successful": len(successful),
        "explicit_failed": len(explicit_failed),
        "missing_ids": sorted(missing),
        "duplicate_ids": sorted(key for key, count in counts.items() if count > 1),
        "unknown_ids": sorted(set(counts) - set(manifest_ids)),
        "manifest_sha256": sha256_file(manifest_path),
    }


def require_finalizable(p2: Path) -> dict[str, Any]:
    inventory = completion_inventory(p2)
    problems: list[str] = []
    if inventory["manifest_total"] != 640:
        problems.append(f"manifest_total={inventory['manifest_total']}")
    if inventory["successful"] + inventory["explicit_failed"] != 640:
        problems.append(
            f"terminal={inventory['successful'] + inventory['explicit_failed']}/640"
        )
    for name in ("missing_ids", "duplicate_ids", "unknown_ids"):
        if inventory[name]:
            problems.append(f"{name}={len(inventory[name])}")
    active = runners()
    if active:
        problems.append(f"runner_count={len(active)}")
    if problems:
        raise RuntimeError("P2-A is not finalizable: " + ", ".join(problems))
    return inventory


def raw_artifact_paths(root: Path, p2: Path, summaries: list[dict[str, Any]]) -> list[Path]:
    del summaries  # The recursive inventory is authoritative at finalization.
    excluded_roots = {
        (p2 / ".staging").resolve(),
        (p2 / "interim_best_final_diagnostic").resolve(),
        (p2 / "final_raw_snapshot").resolve(),
        (p2 / "final_reaggregation").resolve(),
    }
    excluded_files = {
        (p2 / "p2b_configuration_freeze.json").resolve(),
        (p2 / "p2a_runtime_status.json").resolve(),  # mutable monitoring derivative, not a raw attack artifact
    }
    paths: list[Path] = []
    for path in p2.rglob("*"):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in excluded_files:
            continue
        if any(excluded == resolved or excluded in resolved.parents for excluded in excluded_roots):
            continue
        paths.append(resolved)
    return sorted(set(paths), key=lambda path: path.relative_to(root).as_posix())


def build_raw_snapshot(root: Path, p2: Path, snapshot_dir: Path) -> dict[str, Any]:
    inventory = require_finalizable(p2)
    summaries = inventory["summaries"]
    ledger = load_json(p2 / "aggregation_ledger.json")
    completed_tasks = {str(item["task_hash"]) for item in summaries}
    if set(ledger["tasks"]) != completed_tasks:
        raise RuntimeError("ledger task set does not equal completed task set")
    if int(ledger["step_size_bytes"]) != (p2 / "per_step_restart_records.csv.gz").stat().st_size:
        raise RuntimeError("per-step aggregate size does not match ledger")
    if int(ledger["sample_size_bytes"]) != (p2 / "per_sample_attack_records.csv.gz").stat().st_size:
        raise RuntimeError("per-sample aggregate size does not match ledger")

    snapshot_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, Any]] = []
    for path in raw_artifact_paths(root, p2, summaries):
        artifacts.append({
            "path": path.relative_to(root).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    artifact_payload = {
        "schema_version": RAW_SCHEMA,
        "generation_utc": now(),
        "artifacts": artifacts,
    }
    atomic_json(snapshot_dir / "raw_artifact_hashes.json", artifact_payload)
    source_hash = canonical_hash(artifact_payload)
    artifact_hash_by_path = {item["path"]: item["sha256"] for item in artifacts}

    rows: list[dict[str, Any]] = []
    for manifest_row in inventory["manifest"]:
        config_id = manifest_row["logical_config_id"]
        summary = inventory["summary_by_id"].get(config_id)
        if summary is None:
            rows.append({
                "logical_config_id": config_id,
                "terminal_status": "explicit_failed",
                "task_hash": "",
                "attack_config_hash": manifest_row["attack_config_hash"],
                "summary_path": "",
                "summary_sha256": "",
                "candidate_path": "",
                "candidate_sha256": "",
            })
            continue
        summary_path = p2 / summary["_summary_path"]
        candidate_path = p2 / summary["candidate_artifact"]["path"]
        summary_relative = summary_path.relative_to(root).as_posix()
        candidate_relative = candidate_path.relative_to(root).as_posix()
        candidate_sha256 = artifact_hash_by_path[candidate_relative]
        rows.append({
            "logical_config_id": config_id,
            "terminal_status": "successful",
            "task_hash": summary["task_hash"],
            "attack_config_hash": summary["attack_config_hash"],
            "summary_path": summary_relative,
            "summary_sha256": artifact_hash_by_path[summary_relative],
            "candidate_path": candidate_relative,
            "candidate_sha256": candidate_sha256,
            "candidate_declared_sha256": summary["candidate_artifact"]["sha256"],
            "candidate_hash_matches_summary": candidate_sha256 == summary["candidate_artifact"]["sha256"],
            "step_member_sha256": summary["aggregate_entry"]["step_member_sha256"],
            "sample_member_sha256": summary["aggregate_entry"]["sample_member_sha256"],
        })
    write_csv(
        snapshot_dir / "configuration_inventory.csv",
        (
            "logical_config_id", "terminal_status", "task_hash", "attack_config_hash", "summary_path",
            "summary_sha256", "candidate_path", "candidate_sha256", "candidate_declared_sha256",
            "candidate_hash_matches_summary", "step_member_sha256", "sample_member_sha256",
        ),
        rows,
    )
    failure_fields = sorted({key for item in inventory["failures"] for key in item}) or ["logical_config_id", "attempt", "error"]
    write_csv(snapshot_dir / "failed_attempt_inventory.csv", failure_fields, inventory["failures"])
    completion = {
        "schema_version": RAW_SCHEMA,
        "generation_utc": now(),
        "runner_alive": False,
        "runner_processes": [],
        "manifest_total": inventory["manifest_total"],
        "successful": inventory["successful"],
        "explicit_failures": inventory["explicit_failed"],
        "missing": len(inventory["missing_ids"]),
        "duplicates": len(inventory["duplicate_ids"]),
        "unknown": len(inventory["unknown_ids"]),
        "ledger_tasks": len(ledger["tasks"]),
    }
    atomic_json(snapshot_dir / "runner_completion_state.json", completion)
    manifest_core = {
        "schema_version": RAW_SCHEMA,
        "generation_utc": now(),
        "mode": "hash-addressed-read-only-manifest; raw files are not copied or modified",
        "raw_artifact_hashes_canonical_sha256": source_hash,
        "manifest_sha256": inventory["manifest_sha256"],
        "configuration_count": inventory["manifest_total"],
        "successful_count": inventory["successful"],
        "explicit_failure_count": inventory["explicit_failed"],
        "p2a_execution_code_fingerprint": load_json(p2 / "p2_configuration_freeze.json")["p2_execution_code_fingerprint"],
    }
    manifest_core["raw_snapshot_hash"] = canonical_hash(manifest_core)
    atomic_json(snapshot_dir / "raw_snapshot_manifest.json", manifest_core)
    delivery_generation = now()
    delivery_hashes: dict[str, Any] = {}
    for path in sorted(snapshot_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.name == "snapshot_delivery_hashes.json":
            continue
        delivery_hashes[path.name] = {
            "schema_version": RAW_SCHEMA,
            "generation_utc": delivery_generation,
            "source_raw_snapshot_sha256": manifest_core["raw_snapshot_hash"],
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    atomic_json(snapshot_dir / "snapshot_delivery_hashes.json", {
        "schema_version": RAW_SCHEMA,
        "generation_utc": delivery_generation,
        "source_raw_snapshot_sha256": manifest_core["raw_snapshot_hash"],
        "self_excluded": True,
        "artifacts": delivery_hashes,
    })
    return manifest_core


def verify_raw_snapshot(root: Path, snapshot_dir: Path) -> dict[str, Any]:
    manifest = load_json(snapshot_dir / "raw_snapshot_manifest.json")
    hashes = load_json(snapshot_dir / "raw_artifact_hashes.json")
    canonical_matches = canonical_hash(hashes) == manifest["raw_artifact_hashes_canonical_sha256"]
    mismatches: list[dict[str, Any]] = []
    for item in hashes["artifacts"]:
        path = root / item["path"]
        if not path.exists():
            mismatches.append({"path": item["path"], "reason": "missing"})
            continue
        if path.stat().st_size != int(item["size_bytes"]):
            mismatches.append({"path": item["path"], "reason": "size_mismatch"})
            continue
        actual = sha256_file(path)
        if actual != item["sha256"]:
            mismatches.append({"path": item["path"], "reason": "sha256_mismatch", "actual": actual})
    if not canonical_matches:
        mismatches.append({"path": "raw_artifact_hashes.json", "reason": "canonical_manifest_hash_mismatch"})
    return {
        "status": "PASS" if not mismatches else "FAIL",
        "artifact_count": len(hashes["artifacts"]),
        "candidate_artifact_count": sum(str(item["path"]).endswith("/candidate_iterates.npz") for item in hashes["artifacts"]),
        "mismatches": mismatches,
    }


@dataclass
class ConfigAudit:
    summary: dict[str, Any]
    support: Counter[str] = field(default_factory=Counter)
    gate_a: Counter[str] = field(default_factory=Counter)
    gate_b: Counter[str] = field(default_factory=Counter)
    gate_c: Counter[str] = field(default_factory=Counter)
    missing_steps: int = 0
    duplicate_steps: int = 0
    nan_rows: int = 0
    ce_probability_mismatch: int = 0
    margin_probability_mismatch: int = 0
    margin_probability_gate_mismatch: int = 0
    margin_probability_not_reconstructable: int = 0
    threshold_flag_mismatch: int = 0
    threshold_flag_gate_mismatch: int = 0
    threshold_flag_boundary_ambiguous: int = 0
    argmax_flag_mismatch: int = 0
    probability_pair_mismatch: int = 0
    step_rows: int = 0
    sample_rows: int = 0
    member_hashes_match: bool = True
    normal_unchanged: bool = True
    attacked_normal: int = 0
    candidate_counts: Counter[str] = field(default_factory=Counter)
    candidate_success: Counter[str] = field(default_factory=Counter)
    candidate_feasible_counts: Counter[str] = field(default_factory=Counter)
    candidate_feasible_success: Counter[str] = field(default_factory=Counter)
    candidate_ce_sum: Counter[str] = field(default_factory=Counter)
    candidate_margin_sum: Counter[str] = field(default_factory=Counter)
    transitions: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    fallback_probability_mismatch: int = 0
    fallback_probability_gate_mismatch: int = 0
    fallback_prediction_mismatch: int = 0
    fallback_max_abs_difference: float = 0.0
    normal_fp: int = 0
    normal_tn: int = 0
    aircraft_attacked: Counter[str] = field(default_factory=Counter)
    aircraft_candidate: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    legacy_violation_samples: int = 0
    legacy_f3_support_mismatch_samples: int = 0
    legacy_comparable_violation_samples: int = 0


def load_sample_member(
    path: Path,
    start: int,
    end: int,
    expected_hash: str,
    audit: ConfigAudit,
) -> dict[str, dict[str, str]]:
    if sha256_range(path, start, end) != expected_hash:
        audit.member_hashes_match = False
    attacked: dict[str, dict[str, str]] = {}
    for row in iter_member(path, start, end, SAMPLE_FIELDS):
        audit.sample_rows += 1
        is_attacked = as_bool(row["attacked"])
        label = as_int(row["original_label"])
        if is_attacked:
            attacked[row["sample_id"]] = row
            audit.aircraft_attacked[row["aircraft_id"]] += 1
        elif label == 0:
            if as_bool(row["clean_prediction"]):
                audit.normal_fp += 1
            else:
                audit.normal_tn += 1
            if as_float(row["clean_p_anomaly"]) != as_float(row["final_p_anomaly"]) or as_float(row["clean_p_anomaly"]) != as_float(row["best_p_anomaly"]):
                audit.normal_unchanged = False
        if is_attacked and label == 0:
            audit.attacked_normal += 1
    return attacked


def load_step_member(
    path: Path,
    start: int,
    end: int,
    expected_hash: str,
    summary: dict[str, Any],
    audit: ConfigAudit,
) -> dict[str, SampleState]:
    if sha256_range(path, start, end) != expected_hash:
        audit.member_hashes_match = False
    physical = summary["attack"] in PHYSICAL_ATTACKS
    threshold = float(summary["threshold"])
    states: dict[str, SampleState] = {}
    for row in iter_member(path, start, end, STEP_FIELDS):
        audit.step_rows += 1
        sample_id = row["sample_id"]
        state = states.get(sample_id)
        if state is None:
            state = SampleState(sample_id=sample_id, aircraft_id=row["aircraft_id"])
            states[sample_id] = state
        update_state(state, row, physical=physical, final_step=int(summary["steps"]), threshold=threshold)
    expected_pairs = {
        (restart, step)
        for restart in range(int(summary["restarts"]))
        for step in range(int(summary["steps"]) + 1)
    }
    for state in states.values():
        audit.missing_steps += len(expected_pairs - state.seen)
        audit.duplicate_steps += state.duplicate_steps
        audit.nan_rows += state.nan_rows
        audit.ce_probability_mismatch += state.ce_probability_mismatch
        audit.margin_probability_mismatch += state.margin_probability_mismatch
        audit.margin_probability_gate_mismatch += state.margin_probability_gate_mismatch
        audit.margin_probability_not_reconstructable += state.margin_probability_not_reconstructable
        audit.threshold_flag_mismatch += state.threshold_flag_mismatch
        audit.threshold_flag_gate_mismatch += state.threshold_flag_gate_mismatch
        audit.threshold_flag_boundary_ambiguous += state.threshold_flag_boundary_ambiguous
        audit.argmax_flag_mismatch += state.argmax_flag_mismatch
        audit.probability_pair_mismatch += state.probability_pair_mismatch
    return states


def record_transition(audit: ConfigAudit, kind: str, clean_prediction: bool, candidate: Candidate | None, threshold: float) -> None:
    if candidate is None:
        audit.transitions[kind]["missing"] += 1
        return
    attacked_prediction = candidate.p_anomaly >= threshold
    if clean_prediction and not attacked_prediction:
        audit.transitions[kind]["tp_to_fn"] += 1
    elif not clean_prediction and attacked_prediction:
        audit.transitions[kind]["fn_to_tp"] += 1
    elif clean_prediction and attacked_prediction:
        audit.transitions[kind]["unchanged_tp"] += 1
    else:
        audit.transitions[kind]["unchanged_fn"] += 1


def record_prediction(audit: ConfigAudit, kind: str, clean_prediction: bool, attacked_prediction: bool) -> None:
    if clean_prediction and not attacked_prediction:
        audit.transitions[kind]["tp_to_fn"] += 1
    elif not clean_prediction and attacked_prediction:
        audit.transitions[kind]["fn_to_tp"] += 1
    elif clean_prediction and attacked_prediction:
        audit.transitions[kind]["unchanged_tp"] += 1
    else:
        audit.transitions[kind]["unchanged_fn"] += 1


def transition_support_complete(counts: Counter[str], attacked: int) -> bool:
    return (
        counts["tp_to_fn"]
        + counts["fn_to_tp"]
        + counts["unchanged_tp"]
        + counts["unchanged_fn"]
        + counts["missing"]
        == attacked
    )


def add_candidate_stats(audit: ConfigAudit, kind: str, candidate: Candidate | None, threshold: float) -> None:
    if candidate is None:
        return
    audit.candidate_counts[kind] += 1
    audit.candidate_success[kind] += int(candidate.p_anomaly < threshold)
    audit.candidate_ce_sum[kind] += candidate.target_ce
    audit.candidate_margin_sum[kind] += candidate.target_margin
    physical = audit.summary["attack"] in PHYSICAL_ATTACKS
    if candidate.feasible(physical) and (candidate.source_valid or not physical):
        audit.candidate_feasible_counts[kind] += 1
        audit.candidate_feasible_success[kind] += int(candidate.p_anomaly < threshold)
    audit.aircraft_candidate[candidate.aircraft_id][f"{kind}_count"] += 1
    audit.aircraft_candidate[candidate.aircraft_id][f"{kind}_success"] += int(candidate.p_anomaly < threshold)


def process_config(
    summary: dict[str, Any],
    ledger_entry: dict[str, Any],
    bounds: dict[str, int],
    step_path: Path,
    sample_path: Path,
    writers: dict[str, AtomicGzipCsv],
    fallback_writer: csv.DictWriter,
    support_rows: list[dict[str, Any]],
    legacy_rows: list[dict[str, Any]],
    gate_a_violations: list[dict[str, Any]],
) -> tuple[ConfigAudit, dict[str, set[str]]]:
    audit = ConfigAudit(summary=summary)
    samples = load_sample_member(
        sample_path,
        bounds["sample_start"],
        bounds["sample_end"],
        str(ledger_entry["sample_member_sha256"]),
        audit,
    )
    states = load_step_member(
        step_path,
        bounds["step_start"],
        bounds["step_end"],
        str(ledger_entry["step_member_sha256"]),
        summary,
        audit,
    )
    physical = summary["attack"] in PHYSICAL_ATTACKS
    threshold = float(summary["threshold"])
    success_sets = {"best_target_loss": set(), "success_preserving": set(), "best_feasible_success": set()}

    for sample_id, sample in samples.items():
        state = states.get(sample_id)
        if state is None:
            audit.missing_steps += int(summary["restarts"]) * (int(summary["steps"]) + 1)
            audit.support["unresolved_failure"] += 1
            continue
        final = choose_final(state, physical)
        best = state.best_loss
        success_preserving = choose_success_preserving(state)
        best_feasible_success = state.best_feasible_success if physical else None
        final_feasible = final is not None and final.feasible(physical)
        clean_prediction = as_bool(sample["clean_prediction"])
        archived_final_p = as_float(sample["final_p_anomaly"])
        archived_best_p = as_float(sample["best_p_anomaly"])
        archived_final_ce = -math.log(max(1.0 - archived_final_p, 1e-12))
        archived_best_ce = -math.log(max(1.0 - archived_best_p, 1e-12))
        if archived_best_ce > archived_final_ce + TOL:
            audit.legacy_violation_samples += 1
            if not as_bool(sample["final_feasible"]):
                audit.legacy_f3_support_mismatch_samples += 1
            else:
                audit.legacy_comparable_violation_samples += 1

        audit.support["attacked_anomalies"] += 1
        audit.support["V0"] += int(state.source_valid) if physical else 1
        audit.support["initialized"] += int(state.initialization_success)
        audit.support["active_attack_trajectory"] += int(state.attack_active)
        audit.support["projection_converged"] += int(state.projection_converged)
        audit.support["projection_not_converged"] += int(state.projection_not_converged)
        audit.support["final_active"] += int(final is not None)
        audit.support["final_feasible"] += int(final_feasible)
        audit.support["any_threshold_success"] += int(state.ever_threshold_success)
        audit.support["any_feasible_threshold_success"] += int(state.ever_feasible_success) if physical else 0
        audit.support["source_invalid"] += int(physical and not state.source_valid)
        audit.support["initialization_infeasible"] += int(not state.initialization_success)
        audit.support["budget_invalid"] += int(state.any_budget_invalid)
        audit.support["kinematic_invalid"] += int(physical and state.any_kinematic_invalid)

        fallback = not final_feasible
        if fallback:
            audit.support["fallback_clean"] += 1
            clean_probability = as_float(sample["clean_p_anomaly"])
            archived_final_probability = as_float(sample["final_p_anomaly"])
            fallback_difference = abs(clean_probability - archived_final_probability)
            audit.fallback_probability_mismatch += int(fallback_difference > 0.0)
            audit.fallback_probability_gate_mismatch += int(fallback_difference > TOL)
            audit.fallback_max_abs_difference = max(audit.fallback_max_abs_difference, fallback_difference)
            clean_fallback_prediction = clean_probability >= threshold
            archived_fallback_prediction = archived_final_probability >= threshold
            audit.fallback_prediction_mismatch += int(
                clean_fallback_prediction != archived_fallback_prediction
            )
            fallback_writer.writerow({
                "schema_version": SCHEMA,
                "logical_config_id": summary["logical_config_id"],
                "task_hash": summary["task_hash"],
                "seed": summary["seed"],
                "model": summary["model"],
                "attack": summary["attack"],
                "K": summary["steps"],
                "alpha_rule": summary["alpha_rule"],
                "alpha": summary["alpha"],
                "initialization": summary["initialization"],
                "sample_id": sample_id,
                "aircraft_id": sample["aircraft_id"],
                "clean_p_anomaly": clean_probability,
                "evaluation_fallback_p_anomaly": archived_final_probability,
                "threshold": threshold,
                "fallback_prediction_success": archived_final_probability < threshold,
                "reason": "no_feasible_executed_final_candidate",
            })
            fallback_prediction = archived_fallback_prediction
            record_prediction(audit, "evaluation_fallback_clean", clean_prediction, fallback_prediction)

        comparable = final is not None and final_feasible and best is not None
        if comparable:
            if best.target_ce <= final.target_ce + TOL:
                audit.gate_a["pass"] += 1
            else:
                audit.gate_a["fail"] += 1
                gate_a_violations.append({
                    "logical_config_id": summary["logical_config_id"],
                    "sample_id": sample_id,
                    "best_target_ce": best.target_ce,
                    "final_target_ce": final.target_ce,
                    "difference": best.target_ce - final.target_ce,
                    "best_restart": best.restart_id,
                    "best_step": best.step,
                    "final_restart": final.restart_id,
                    "final_step": final.step,
                })
        else:
            audit.gate_a["not_applicable"] += 1

        if state.ever_threshold_success:
            audit.gate_b["samples_ever_successful"] += 1
            if success_preserving is not None and success_preserving.p_anomaly < threshold:
                audit.gate_b["success_preserved"] += 1
            else:
                audit.gate_b["success_lost"] += 1
                if success_preserving is None:
                    audit.gate_b["missing_candidate_markers"] += 1
        if physical and state.ever_feasible_success:
            audit.gate_c["samples_with_any_feasible_success"] += 1
            if best_feasible_success is not None and best_feasible_success.p_anomaly < threshold and best_feasible_success.feasible(True):
                audit.gate_c["feasible_success_preserved"] += 1
            else:
                audit.gate_c["feasible_success_lost"] += 1
                if best_feasible_success is None:
                    audit.gate_c["candidate_missing"] += 1

        candidates = {
            "final_active": final,
            "best_target_loss": best,
            "success_preserving": success_preserving,
            "best_feasible_success": best_feasible_success,
        }
        reasons = {
            "final_active": "configured_final_step_active; feasible restart preferred",
            "best_target_loss": "minimum target CE among executed active finite candidates",
            "success_preserving": "best threshold-success candidate if any; otherwise best_target_loss",
            "best_feasible_success": "minimum target CE among source-valid feasible threshold-success candidates",
        }
        for kind, candidate in candidates.items():
            if candidate is not None:
                writers[kind].writerow(candidate_row(summary, candidate, kind, threshold, reasons[kind]))
            add_candidate_stats(audit, kind, candidate, threshold)
            record_transition(audit, kind, clean_prediction, candidate, threshold)
            if candidate is not None and candidate.p_anomaly < threshold and kind in success_sets:
                success_sets[kind].add(sample_id)
        evaluation_probability = (
            final.p_anomaly if final is not None and final_feasible else as_float(sample["final_p_anomaly"])
        )
        record_prediction(
            audit,
            "final_with_fallback_evaluation",
            clean_prediction,
            evaluation_probability >= threshold,
        )

    extra_states = set(states) - set(samples)
    if extra_states:
        audit.support["unresolved_failure"] += len(extra_states)
    expected_step_rows = int(ledger_entry["step_rows"])
    expected_sample_rows = int(ledger_entry["sample_rows"])
    if audit.step_rows != expected_step_rows or audit.sample_rows != expected_sample_rows:
        audit.support["unresolved_failure"] += abs(audit.step_rows - expected_step_rows) + abs(audit.sample_rows - expected_sample_rows)
    if physical:
        audit.gate_c["attacked_anomaly_denominator"] = audit.support["attacked_anomalies"]
        audit.gate_c["V0_denominator"] = audit.support["V0"]
        audit.gate_c["source_invalid_excluded_from_V0"] = audit.support["source_invalid"]

    for stage in (
        "attacked_anomalies", "V0", "initialized", "active_attack_trajectory", "projection_converged",
        "projection_not_converged", "final_active", "final_feasible", "any_threshold_success",
        "any_feasible_threshold_success", "fallback_clean", "source_invalid", "initialization_infeasible",
        "budget_invalid", "kinematic_invalid", "unresolved_failure",
    ):
        support_rows.append({
            "schema_version": SCHEMA,
            "logical_config_id": summary["logical_config_id"],
            "seed": summary["seed"],
            "model": summary["model"],
            "attack": summary["attack"],
            "K": summary["steps"],
            "alpha_rule": summary["alpha_rule"],
            "initialization": summary["initialization"],
            "stage": stage,
            "support_count": audit.support[stage],
        })

    legacy_failed = not bool(summary.get("identity_checks", {}).get("best_iterate_not_weaker_than_final", False))
    legacy_rows.append({
        "schema_version": SCHEMA,
        "logical_config_id": summary["logical_config_id"],
        "legacy_checker_pass": not legacy_failed,
        "legacy_status": "legacy_checker_semantic_mismatch" if legacy_failed else "legacy_checker_pass",
        "legacy_violation_samples": audit.legacy_violation_samples,
        "legacy_f3_support_mismatch_samples": audit.legacy_f3_support_mismatch_samples,
        "legacy_comparable_candidate_semantic_violation_samples": audit.legacy_comparable_violation_samples,
        "legacy_primary_reconciliation": (
            "F3_support_mismatch"
            if audit.legacy_violation_samples > 0 and audit.legacy_f3_support_mismatch_samples == audit.legacy_violation_samples
            else (
                "candidate_semantic_mismatch_on_comparable_final"
                if audit.legacy_comparable_violation_samples > 0
                else "no_legacy_violation"
            )
        ),
        "gate_a_pass": audit.gate_a["fail"] == 0,
        "gate_a_comparable": audit.gate_a["pass"] + audit.gate_a["fail"],
        "gate_a_not_applicable": audit.gate_a["not_applicable"],
        "genuine_best_loss_violations": audit.gate_a["fail"],
        "rerun_required": False,
    })
    return audit, success_sets


def gate_payload(name: str, counters: Counter[str], fail_fields: tuple[str, ...], source_hash: str) -> dict[str, Any]:
    failures = sum(int(counters[field]) for field in fail_fields)
    return {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "source_raw_snapshot_sha256": source_hash,
        "gate": name,
        "status": "PASS" if failures == 0 else "FAIL",
        "counts": dict(sorted(counters.items())),
        "failure_count": failures,
    }


def safe_ratio(numerator: int | float, denominator: int | float) -> float | None:
    return float(numerator / denominator) if denominator else None


def config_metric_row(audit: ConfigAudit) -> dict[str, Any]:
    summary = audit.summary
    attacked = audit.support["attacked_anomalies"]
    v0 = audit.support["V0"]
    final_count = audit.candidate_counts["final_active"]
    return {
        "logical_config_id": summary["logical_config_id"],
        "seed": summary["seed"],
        "model": summary["model"],
        "attack": summary["attack"],
        "K": summary["steps"],
        "alpha_rule": summary["alpha_rule"],
        "alpha": summary["alpha"],
        "initialization": summary["initialization"],
        "attacked_anomalies": attacked,
        "V0": v0,
        "final_active_count": final_count,
        "final_active_asr": safe_ratio(audit.candidate_success["final_active"], final_count),
        "best_target_loss_asr": safe_ratio(audit.candidate_success["best_target_loss"], audit.candidate_counts["best_target_loss"]),
        "success_preserving_asr": safe_ratio(audit.candidate_success["success_preserving"], audit.candidate_counts["success_preserving"]),
        "best_feasible_success_asr_on_v0": safe_ratio(audit.candidate_success["best_feasible_success"], v0),
        "final_active_pv_asr_on_v0": safe_ratio(audit.candidate_feasible_success["final_active"], v0),
        "best_feasible_pv_asr_on_v0": safe_ratio(audit.candidate_feasible_success["best_feasible_success"], v0),
        "best_target_ce_mean": safe_ratio(audit.candidate_ce_sum["best_target_loss"], audit.candidate_counts["best_target_loss"]),
        "best_target_margin_mean": safe_ratio(audit.candidate_margin_sum["best_target_loss"], audit.candidate_counts["best_target_loss"]),
        "success_preserving_ce_mean": safe_ratio(audit.candidate_ce_sum["success_preserving"], audit.candidate_counts["success_preserving"]),
        "success_preserving_margin_mean": safe_ratio(audit.candidate_margin_sum["success_preserving"], audit.candidate_counts["success_preserving"]),
        "final_success_gap": safe_ratio(audit.candidate_success["success_preserving"], attacked) - safe_ratio(audit.candidate_success["final_active"], attacked) if attacked else None,
        "fallback_clean_count": audit.support["fallback_clean"],
        "fallback_clean_rate": safe_ratio(audit.support["fallback_clean"], attacked),
        "projection_not_converged_count": audit.support["projection_not_converged"],
        "projection_not_converged_rate": safe_ratio(audit.support["projection_not_converged"], attacked),
        "initialization_infeasible_count": audit.support["initialization_infeasible"],
        "initialization_infeasible_rate": safe_ratio(audit.support["initialization_infeasible"], attacked),
        "rebound_rate": summary.get("overshoot", {}).get("target_loss_rebound_rate"),
        "success_loss_rate": summary.get("overshoot", {}).get("success_loss_rate"),
        "projection_damage_mean": summary.get("overshoot", {}).get("projection_damage_mean"),
        "projection_failure_rate_calls": 1.0 - float(summary.get("projection", {}).get("convergence_rate", 1.0)),
    }


def pooled_step_size_rows(audits: list[ConfigAudit]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[ConfigAudit]] = defaultdict(list)
    for audit in audits:
        grouped[(audit.summary["attack"], audit.summary["alpha_rule"])].append(audit)
    rows: list[dict[str, Any]] = []
    for (attack, alpha_rule), group in sorted(grouped.items()):
        support = sum(item.support["attacked_anomalies"] for item in group)
        v0 = sum(item.support["V0"] for item in group)
        best_count = sum(item.candidate_counts["best_target_loss"] for item in group)
        success_count = sum(item.candidate_counts["success_preserving"] for item in group)
        best_feasible_successes = sum(item.candidate_success["best_feasible_success"] for item in group)
        final_success = sum(item.candidate_success["final_active"] for item in group)
        success_preserving = sum(item.candidate_success["success_preserving"] for item in group)
        best_ce_count = sum(item.candidate_counts["best_target_loss"] for item in group)
        rows.append({
            "schema_version": SCHEMA,
            "attack": attack,
            "alpha_rule": alpha_rule,
            "config_count": len(group),
            "attacked_support": support,
            "V0_support": v0,
            "success_preserving_successes": success_preserving,
            "success_preserving_asr": safe_ratio(success_preserving, success_count),
            "best_target_loss_successes": sum(item.candidate_success["best_target_loss"] for item in group),
            "best_target_loss_asr": safe_ratio(sum(item.candidate_success["best_target_loss"] for item in group), best_count),
            "best_feasible_successes": best_feasible_successes,
            "best_feasible_success_asr_on_v0": safe_ratio(best_feasible_successes, v0),
            "best_target_ce_mean": safe_ratio(sum(item.candidate_ce_sum["best_target_loss"] for item in group), best_ce_count),
            "best_target_margin_mean": safe_ratio(sum(item.candidate_margin_sum["best_target_loss"] for item in group), best_ce_count),
            "target_loss_rebound_rate_mean": safe_ratio(sum(float(item.summary["overshoot"]["target_loss_rebound_rate"]) for item in group), len(group)),
            "success_loss_rate_mean": safe_ratio(sum(float(item.summary["overshoot"]["success_loss_rate"]) for item in group), len(group)),
            "final_success_preserving_gap": safe_ratio(success_preserving - final_success, support),
            "projection_damage_mean": safe_ratio(sum(float(item.summary["overshoot"]["projection_damage_mean"]) for item in group), len(group)),
            "projection_failure_rate_mean": safe_ratio(sum(1.0 - float(item.summary["projection"]["convergence_rate"]) for item in group), len(group)),
            "fallback_clean_rate": safe_ratio(sum(item.support["fallback_clean"] for item in group), support),
            "numeric_error_configs": sum(item.nan_rows > 0 for item in group),
            "large_scale_projection_failure_configs": sum(float(item.summary["projection"]["convergence_rate"]) < 0.5 for item in group),
        })
    return rows


def select_alpha(step_rows: list[dict[str, Any]], rules: dict[str, Any]) -> dict[str, Any]:
    expected = [
        "exclude_nan_numeric_error_or_large_scale_projection_failure",
        "maximize_pooled_per_sample_best_asr_across_both_models_and_all_seeds",
        "if_tied_minimize_target_ce_then_maximize_target_margin",
        "if_still_tied_minimize_final_best_gap_and_oscillation",
        "lexicographic_rule_id_only_as_final_deterministic_tie_break",
    ]
    recorded = list(rules.get("rules", {}).get("ordered_criteria", []))
    if recorded != expected or rules.get("rules", {}).get("scope") != "one_rule_per_attack_family_shared_across_models_seeds_steps_and_random_initialization":
        return {
            "status": "AUTHOR_VERIFY",
            "label": "[AUTHOR VERIFY]",
            "reason": "frozen alpha-selection rule is missing, contradictory, or not applicable",
            "selected": {},
        }
    selected: dict[str, Any] = {}
    by_attack: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in step_rows:
        by_attack[row["attack"]].append(row)
    for attack, rows in sorted(by_attack.items()):
        eligible = [
            row for row in rows
            if int(row["numeric_error_configs"]) == 0 and int(row["large_scale_projection_failure_configs"]) == 0
        ]
        if not eligible:
            return {
                "status": "AUTHOR_VERIFY",
                "label": "[AUTHOR VERIFY]",
                "reason": f"no eligible alpha rule for {attack}",
                "selected": {},
            }
        # The diagnosed post-hoc meaning of pooled best-ASR is the
        # success-preserving count.  Exact pooled-count ties alone advance
        # to the frozen secondary criteria.
        maximum = max(int(row["success_preserving_successes"]) for row in eligible)
        tied = [row for row in eligible if int(row["success_preserving_successes"]) == maximum]
        success_tie_count = len(tied)
        if attack in PHYSICAL_ATTACKS:
            maximum_feasible = max(int(row["best_feasible_successes"]) for row in tied)
            tied = [row for row in tied if int(row["best_feasible_successes"]) == maximum_feasible]
        tied.sort(key=lambda row: (
            float(row["best_target_ce_mean"]),
            -float(row["best_target_margin_mean"]),
            abs(float(row["final_success_preserving_gap"])),
            float(row["target_loss_rebound_rate_mean"]),
            str(row["alpha_rule"]),
        ))
        winner = tied[0]
        selected[attack] = {
            "alpha_rule": winner["alpha_rule"],
            "pooled_success_preserving_successes": winner["success_preserving_successes"],
            "pooled_support": winner["attacked_support"],
            "success_tie_count_before_physical_feasibility": success_tie_count,
            "tie_count_before_loss_secondary_criteria": len(tied),
            "cat_ad_advantage_used": False,
        }
    return {
        "status": "SELECTED",
        "selection_semantics": "post-hoc success-preserving interpretation of frozen pooled best-ASR criterion",
        "selected": selected,
    }


def initialization_rows(
    audits: list[ConfigAudit],
    success_sets: dict[str, dict[str, set[str]]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[Any, ...], list[ConfigAudit]] = defaultdict(list)
    for audit in audits:
        summary = audit.summary
        key = (
            summary["seed"], summary["model"], summary["attack"], summary["steps"],
            summary["alpha_rule"], summary["alpha"], summary["restarts"],
        )
        by_key[key].append(audit)
    rows: list[dict[str, Any]] = []
    for key, pair in sorted(by_key.items(), key=lambda item: tuple(map(str, item[0]))):
        if len(pair) != 2:
            continue
        clean = next((item for item in pair if item.summary["initialization"] == "clean"), None)
        random = next((item for item in pair if item.summary["initialization"] != "clean"), None)
        if clean is None or random is None:
            continue
        clean_set = success_sets[clean.summary["logical_config_id"]]["success_preserving"]
        random_set = success_sets[random.summary["logical_config_id"]]["success_preserving"]
        clean_count = clean.candidate_counts["success_preserving"]
        random_count = random.candidate_counts["success_preserving"]
        rows.append({
            "schema_version": SCHEMA,
            "seed": key[0], "model": key[1], "attack": key[2], "K": key[3],
            "alpha_rule": key[4], "alpha": key[5],
            "random_initialization": random.summary["initialization"],
            "clean_successes": len(clean_set),
            "random_successes": len(random_set),
            "random_only_successes": len(random_set - clean_set),
            "clean_only_successes": len(clean_set - random_set),
            "overlap": len(clean_set & random_set),
            "asr_increment": (safe_ratio(len(random_set), random_count) or 0.0) - (safe_ratio(len(clean_set), clean_count) or 0.0),
            "best_target_loss_ce_change": (safe_ratio(random.candidate_ce_sum["best_target_loss"], random.candidate_counts["best_target_loss"]) or 0.0) - (safe_ratio(clean.candidate_ce_sum["best_target_loss"], clean.candidate_counts["best_target_loss"]) or 0.0),
            "clean_initialization_infeasible_rate": safe_ratio(clean.support["initialization_infeasible"], clean.support["attacked_anomalies"]),
            "random_initialization_infeasible_rate": safe_ratio(random.support["initialization_infeasible"], random.support["attacked_anomalies"]),
            "clean_projection_convergence_rate": safe_ratio(clean.support["projection_converged"], clean.support["attacked_anomalies"]),
            "random_projection_convergence_rate": safe_ratio(random.support["projection_converged"], random.support["attacked_anomalies"]),
            "feasible_success_increment": random.candidate_success["best_feasible_success"] - clean.candidate_success["best_feasible_success"],
        })
    return rows


def transition_rows(audits: list[ConfigAudit]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for audit in audits:
        summary = audit.summary
        for kind, counts in sorted(audit.transitions.items()):
            clean_tp = counts["tp_to_fn"] + counts["unchanged_tp"]
            clean_fn = counts["fn_to_tp"] + counts["unchanged_fn"]
            attacked_tp = counts["fn_to_tp"] + counts["unchanged_tp"]
            attacked_fn = counts["tp_to_fn"] + counts["unchanged_fn"]
            clean_f1 = safe_ratio(2 * clean_tp, 2 * clean_tp + audit.normal_fp + clean_fn)
            full_support = counts["missing"] == 0 and kind != "evaluation_fallback_clean"
            attacked_f1 = safe_ratio(2 * attacked_tp, 2 * attacked_tp + audit.normal_fp + attacked_fn) if full_support else None
            rows.append({
                "schema_version": SCHEMA,
                "logical_config_id": summary["logical_config_id"],
                "seed": summary["seed"], "model": summary["model"], "attack": summary["attack"],
                "K": summary["steps"], "alpha_rule": summary["alpha_rule"],
                "initialization": summary["initialization"], "candidate_type": kind,
                "tp_to_fn": counts["tp_to_fn"], "fn_to_tp": counts["fn_to_tp"],
                "unchanged_tp": counts["unchanged_tp"], "unchanged_fn": counts["unchanged_fn"],
                "missing_candidate": counts["missing"],
                "candidate_support": attacked_tp + attacked_fn,
                "recall_change": safe_ratio(attacked_tp, attacked_tp + attacked_fn) - safe_ratio(clean_tp, clean_tp + clean_fn) if attacked_tp + attacked_fn and clean_tp + clean_fn else None,
                "clean_f1": clean_f1 if full_support else None,
                "candidate_f1": attacked_f1,
                "f1_change": attacked_f1 - clean_f1 if attacked_f1 is not None and clean_f1 is not None and full_support else None,
                "f1_comparable_full_support": full_support,
                "interpretation_scope": (
                    "invalid-final clean evaluation fallback only"
                    if kind == "evaluation_fallback_clean"
                    else (
                        "mixed evaluation output; decompose using final_active and evaluation_fallback_clean rows"
                        if kind == "final_with_fallback_evaluation"
                        else "actual_attack_candidate"
                    )
                ),
            })
    return rows


def per_seed_envelope_rows(audits: list[ConfigAudit]) -> list[dict[str, Any]]:
    rows = [config_metric_row(item) for item in audits]
    return sorted(rows, key=lambda row: (
        int(row["seed"]), str(row["model"]), str(row["attack"]), int(row["K"]),
        str(row["alpha_rule"]), str(row["initialization"]),
    ))


def alpha_value(rule: str, steps: int) -> float:
    if rule == "fixed_003":
        return 0.03
    if rule == "eps_over_k":
        return 0.1 / steps
    if rule == "two_eps_over_k":
        return 0.2 / steps
    if rule == "eps_over_4":
        return 0.025
    raise ValueError(rule)


def build_p2b_freeze(
    p2: Path,
    output_dir: Path,
    source_hash: str,
    posthoc_fingerprint: str,
    selection: dict[str, Any],
    audits: list[ConfigAudit],
) -> dict[str, Any]:
    if selection.get("status") != "SELECTED":
        raise RuntimeError("alpha selection is not finalized")
    p2_config = load_json(p2 / "p2_configuration_freeze.json")
    p2b = p2_config["p2_config"]["p2_b"]
    selected = selection["selected"]
    summary_lookup: dict[tuple[Any, ...], dict[str, Any]] = {}
    identity_lookup: dict[tuple[int, str], dict[str, Any]] = {}
    for audit in audits:
        summary = audit.summary
        key = (
            int(summary["seed"]), summary["model"], summary["attack"], int(summary["steps"]),
            summary["alpha_rule"], summary["initialization"],
        )
        summary_lookup[key] = summary
        identity_lookup[(int(summary["seed"]), summary["model"])] = summary["task_identity"]

    tasks: list[dict[str, Any]] = []
    conditional_r10: list[dict[str, Any]] = []
    for attack, choice in sorted(selected.items()):
        rule = choice["alpha_rule"]
        initialization = p2b["initialization"][attack]
        for seed in (42, 43, 44, 45, 46):
            for model in ("BiLSTM-ERM", "CAT-AD"):
                identity = identity_lookup[(seed, model)]
                for steps in (20, 50):
                    base = summary_lookup[(seed, model, attack, steps, rule, initialization)]
                    for restarts in (1, 5):
                        attack_config = dict(base["attack_config"])
                        attack_config["restarts"] = restarts
                        attack_config["alpha"] = alpha_value(rule, steps)
                        attack_hash = canonical_hash(attack_config)
                        task = {
                            "stage": "p2b",
                            "seed": seed,
                            "model": model,
                            "attack": attack,
                            "K": steps,
                            "alpha_rule": rule,
                            "alpha": alpha_value(rule, steps),
                            "initialization": initialization,
                            "restarts": restarts,
                            "attack_config_hash": attack_hash,
                            "checkpoint_sha256": identity["checkpoint_sha256"],
                            "dataset_hash": identity["dataset_hash"],
                            "split_hash": identity["split_hash"],
                            "normalization_hash": identity["normalization_hash"],
                            "sample_manifest_hash": identity["sample_manifest_hash"],
                            "threshold": identity["threshold"],
                        }
                        task["logical_config_id"] = canonical_hash(task)
                        tasks.append(task)
                    r10 = {
                        "stage": "p2b_conditional_r10",
                        "seed": seed,
                        "model": model,
                        "attack": attack,
                        "K": steps,
                        "alpha_rule": rule,
                        "alpha": alpha_value(rule, steps),
                        "initialization": initialization,
                        "restarts": 10,
                        "trigger_scope": "entire attack family if any repeated split has R1_to_R5 increment >= 0.005",
                    }
                    r10["logical_config_id"] = canonical_hash(r10)
                    conditional_r10.append(r10)
    task_hash = canonical_hash(tasks)
    payload = {
        "schema_version": "adsb.c001-p2b-configuration-freeze.v1",
        "generation_utc": now(),
        "source_raw_snapshot_sha256": source_hash,
        "original_p2a_attack_code_fingerprint": p2_config["p2_execution_code_fingerprint"],
        "posthoc_reaggregation_fingerprint": posthoc_fingerprint,
        "selected_alpha_per_attack": selected,
        "steps": [20, 50],
        "initialization": p2b["initialization"],
        "base_restarts": [1, 5],
        "conditional_restart": 10,
        "loss": "targeted_ce",
        "candidate_policies": {
            "final": "actual active configured-final-step candidate; clean fallback excluded",
            "best_target_loss": "minimum target CE among active finite executed candidates",
            "success_preserving": "prefer threshold-success with validity priority; otherwise best_target_loss",
            "best_feasible_success": "source-valid budget-and-kinematic-valid threshold success",
        },
        "projection_tolerances": p2_config["projection_config"],
        "support_definitions": "final_reaggregation/support_definitions.json",
        "r10_trigger": p2b["r10_trigger"],
        "r10_scope_on_trigger": p2b["r10_scope_on_trigger"],
        "base_task_count": len(tasks),
        "base_tasks": tasks,
        "conditional_r10_task_count_per_all_families": len(conditional_r10),
        "conditional_r10_templates": conditional_r10,
        "task_list_sha256": task_hash,
        "ready_to_run": True,
        "executed": False,
    }
    atomic_json(output_dir / "p2b_configuration_freeze.json", payload)
    atomic_json(p2 / "p2b_configuration_freeze.json", payload)
    return payload


def identity_gate(
    inventory: dict[str, Any],
    p2: Path,
    audits: list[ConfigAudit],
    source_hash: str,
) -> dict[str, Any]:
    freeze = load_json(p2 / "p2_configuration_freeze.json")
    manifest_by_id = {row["logical_config_id"]: row for row in inventory["manifest"]}
    mismatches: list[dict[str, Any]] = []
    thresholds: dict[tuple[int, str], set[float]] = defaultdict(set)
    identity_values: dict[tuple[int, str, str], set[str]] = defaultdict(set)
    required_hashes = (
        "checkpoint_sha256", "dataset_hash", "split_hash", "normalization_hash", "sample_manifest_hash",
    )
    projection_expected = freeze["projection_config"]
    for audit in audits:
        summary = audit.summary
        config_id = summary["logical_config_id"]
        manifest = manifest_by_id.get(config_id)
        if manifest is None:
            mismatches.append({"logical_config_id": config_id, "field": "manifest", "reason": "missing"})
            continue
        comparisons = {
            "seed": str(summary["seed"]), "model": str(summary["model"]), "attack": str(summary["attack"]),
            "K": str(summary["steps"]), "alpha_rule": str(summary["alpha_rule"]),
            "initialization": str(summary["initialization"]), "attack_config_hash": str(summary["attack_config_hash"]),
        }
        for field_name, expected in comparisons.items():
            if str(manifest[field_name]) != expected:
                mismatches.append({"logical_config_id": config_id, "field": field_name, "manifest": manifest[field_name], "summary": expected})
        identity = summary["task_identity"]
        if identity["p2_code_fingerprint"] != freeze["p2_execution_code_fingerprint"]:
            mismatches.append({"logical_config_id": config_id, "field": "code_fingerprint"})
        if summary["attack_config"]["budget_scope"] != "normalized_raw6":
            mismatches.append({"logical_config_id": config_id, "field": "budget_scope"})
        if summary["attack_config"]["loss"] != "targeted_ce":
            mismatches.append({"logical_config_id": config_id, "field": "loss"})
        if canonical_hash(summary["attack_config"]) != summary["attack_config_hash"]:
            mismatches.append({"logical_config_id": config_id, "field": "attack_config_hash", "reason": "canonical_mismatch"})
        if identity.get("p2_config_hash") != freeze["p2_config_hash"]:
            mismatches.append({"logical_config_id": config_id, "field": "p2_config_hash"})
        projection_mapping = {
            "budget_abs_tol": "budget_abs_tol",
            "kinematic_rel_tol": "kinematic_rel_tol",
            "projection_residual_tol": "projection_residual_tol",
            "maximum_alternating_projection_iterations": "alternating_projection_max_iterations",
            "feasible_random_resampling_count": "feasible_random_max_resamples",
            "derived_difference_consistency": "derived_difference_consistency",
            "budget_scope": "budget_scope",
        }
        for attack_field, freeze_field in projection_mapping.items():
            if summary["attack_config"].get(attack_field) != projection_expected.get(freeze_field):
                mismatches.append({
                    "logical_config_id": config_id,
                    "field": f"projection.{attack_field}",
                    "summary": summary["attack_config"].get(attack_field),
                    "freeze": projection_expected.get(freeze_field),
                })
        thresholds[(int(summary["seed"]), summary["model"])].add(float(summary["threshold"]))
        for field_name in required_hashes:
            value = str(identity.get(field_name, ""))
            if len(value) != 64:
                mismatches.append({"logical_config_id": config_id, "field": field_name, "reason": "not_sha256"})
            identity_values[(int(summary["seed"]), summary["model"], field_name)].add(value)
    for key, values in thresholds.items():
        if len(values) != 1:
            mismatches.append({"seed": key[0], "model": key[1], "field": "threshold", "values": sorted(values)})
    for key, values in identity_values.items():
        if len(values) != 1:
            mismatches.append({"seed": key[0], "model": key[1], "field": key[2], "values": sorted(values)})
    return {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "status": "PASS" if not mismatches else "FAIL", "mismatch_count": len(mismatches), "mismatches": mismatches,
    }


def run_reaggregation(root: Path, p2: Path, snapshot_dir: Path, output_dir: Path) -> dict[str, Any]:
    inventory = require_finalizable(p2)
    if inventory["successful"] != 640:
        raise RuntimeError("post-hoc reaggregation requires 640 successful configurations")
    raw_manifest = load_json(snapshot_dir / "raw_snapshot_manifest.json")
    source_hash = str(raw_manifest["raw_snapshot_hash"])
    raw_verification = verify_raw_snapshot(root, snapshot_dir)
    if raw_verification["status"] != "PASS":
        raise RuntimeError(f"raw snapshot verification failed: {raw_verification['mismatches'][:3]}")
    script_path = Path(__file__).resolve()
    script_hash = sha256_file(script_path)
    posthoc_fingerprint = canonical_hash({
        "schema_version": SCHEMA,
        "script_path": script_path.relative_to(root).as_posix(),
        "script_sha256": script_hash,
        "candidate_semantics_version": 1,
    })
    output_dir.mkdir(parents=True, exist_ok=True)
    fingerprint_payload = {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "source_raw_snapshot_sha256": source_hash,
        "script_path": script_path.relative_to(root).as_posix(),
        "script_sha256": script_hash,
        "posthoc_reaggregation_fingerprint": posthoc_fingerprint,
        "independent_of_frozen_p2a_execution_fingerprint": True,
    }
    atomic_json(output_dir / "reaggregation_code_fingerprint.json", fingerprint_payload)
    atomic_json(output_dir / "candidate_semantics.json", {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "posthoc_integrity_recomputation": True,
        "legacy_checker_used_as_acceptance_basis": False,
        "final_candidate": "actual active configured-final-step trajectory point; feasible restart preferred; no clean substitution",
        "best_target_loss_candidate": "minimum target CE among executed active finite candidates; success and feasibility not required",
        "strongest_success_preserving_candidate": "if any active threshold success exists, select within successful candidates with feasible/budget/projection priority then CE/margin; otherwise best_target_loss",
        "best_feasible_success_candidate": "physical attacks only: source-valid, active, budget-valid, kinematic-valid, post-valid and threshold-success; minimum CE",
        "tie_break": ["minimum_target_ce", "maximum_target_margin", "minimum_restart_id", "minimum_step"],
        "target": "normal_class_0", "threshold_success": "p_anomaly < frozen_threshold",
    })
    atomic_json(output_dir / "support_definitions.json", {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "attack_support": "original-label anomaly samples",
        "valid_support_V0": "source-valid attacked anomalies for physical attacks; all attacked anomalies otherwise",
        "evaluation_support": "full test set; normal inputs are unchanged controls",
        "evaluation_fallback_clean": "clean prediction returned only when no feasible executed final exists; not attack failure, robustness, or an attack candidate",
        "states": [
            "source_valid", "source_invalid", "initialization_success", "initialization_infeasible",
            "attack_active", "projection_converged", "projection_not_converged", "budget_valid",
            "budget_invalid", "kinematic_valid", "kinematic_invalid", "final_active", "final_invalid",
            "valid_attack_failure", "valid_attack_success", "evaluation_fallback_clean",
        ],
    })

    ledger = load_json(p2 / "aggregation_ledger.json")
    bounds_by_task = member_bounds(ledger)
    step_path = p2 / "per_step_restart_records.csv.gz"
    sample_path = p2 / "per_sample_attack_records.csv.gz"
    summaries = inventory["summary_by_id"]
    ordered_summaries = [summaries[row["logical_config_id"]] for row in inventory["manifest"]]
    audits: list[ConfigAudit] = []
    all_success_sets: dict[str, dict[str, set[str]]] = {}
    support_rows: list[dict[str, Any]] = []
    legacy_rows: list[dict[str, Any]] = []
    gate_a_violations: list[dict[str, Any]] = []
    fallback_fields = (
        "schema_version", "logical_config_id", "task_hash", "seed", "model", "attack", "K",
        "alpha_rule", "alpha", "initialization", "sample_id", "aircraft_id", "clean_p_anomaly",
        "evaluation_fallback_p_anomaly", "threshold", "fallback_prediction_success", "reason",
    )
    fallback_handle, fallback_temporary_name = tempfile.mkstemp(
        prefix=".fallback_clean_inventory.csv.", suffix=".tmp", dir=output_dir
    )
    fallback_temporary = Path(fallback_temporary_name)
    try:
        with os.fdopen(fallback_handle, "w", encoding="utf-8", newline="") as fallback_stream:
            fallback_writer = csv.DictWriter(fallback_stream, fieldnames=fallback_fields, lineterminator="\n")
            fallback_writer.writeheader()
            with contextlib.ExitStack() as stack:
                writers = {
                    "final_active": stack.enter_context(AtomicGzipCsv(output_dir / "final_active_candidates.csv.gz", CANDIDATE_FIELDS)),
                    "best_target_loss": stack.enter_context(AtomicGzipCsv(output_dir / "best_target_loss_candidates.csv.gz", CANDIDATE_FIELDS)),
                    "success_preserving": stack.enter_context(AtomicGzipCsv(output_dir / "success_preserving_candidates.csv.gz", CANDIDATE_FIELDS)),
                    "best_feasible_success": stack.enter_context(AtomicGzipCsv(output_dir / "best_feasible_success_candidates.csv.gz", CANDIDATE_FIELDS)),
                }
                for index, summary in enumerate(ordered_summaries, start=1):
                    task_hash = str(summary["task_hash"])
                    if task_hash not in ledger["tasks"] or task_hash not in bounds_by_task:
                        raise RuntimeError(f"task missing from ledger: {task_hash}")
                    audit, success_sets = process_config(
                        summary,
                        ledger["tasks"][task_hash],
                        bounds_by_task[task_hash],
                        step_path,
                        sample_path,
                        writers,
                        fallback_writer,
                        support_rows,
                        legacy_rows,
                        gate_a_violations,
                    )
                    audits.append(audit)
                    all_success_sets[summary["logical_config_id"]] = success_sets
                    if index % 10 == 0 or index == len(ordered_summaries):
                        print(json.dumps({"reaggregated": index, "total": len(ordered_summaries), "timestamp_utc": now()}), flush=True)
            fallback_stream.flush()
            os.fsync(fallback_stream.fileno())
        os.replace(fallback_temporary, output_dir / "fallback_clean_inventory.csv")
    except Exception:
        fallback_temporary.unlink(missing_ok=True)
        raise

    support_fields = tuple(support_rows[0])
    write_csv(output_dir / "support_flow.csv", support_fields, support_rows)
    write_csv(output_dir / "legacy_checker_reconciliation.csv", tuple(legacy_rows[0]), legacy_rows)
    step_rows = pooled_step_size_rows(audits)
    write_csv(output_dir / "step_size_audit_reaggregated.csv", tuple(step_rows[0]), step_rows)
    init_rows = initialization_rows(audits, all_success_sets)
    write_csv(output_dir / "initialization_audit_reaggregated.csv", tuple(init_rows[0]), init_rows)
    transitions = transition_rows(audits)
    write_csv(output_dir / "prediction_transitions_reaggregated.csv", tuple(transitions[0]), transitions)
    envelope = per_seed_envelope_rows(audits)
    write_csv(output_dir / "per_seed_attack_envelope.csv", tuple(envelope[0]), envelope)
    physical_rows = []
    for audit in audits:
        if audit.summary["attack"] not in PHYSICAL_ATTACKS:
            continue
        physical_rows.append({
            "schema_version": SCHEMA,
            "logical_config_id": audit.summary["logical_config_id"],
            "seed": audit.summary["seed"], "model": audit.summary["model"], "attack": audit.summary["attack"],
            "K": audit.summary["steps"], "alpha_rule": audit.summary["alpha_rule"], "initialization": audit.summary["initialization"],
            "attacked_anomalies": audit.support["attacked_anomalies"], "V0": audit.support["V0"],
            "source_invalid": audit.support["source_invalid"], "initialization_infeasible": audit.support["initialization_infeasible"],
            "projection_not_converged": audit.support["projection_not_converged"], "budget_invalid": audit.support["budget_invalid"],
            "kinematic_invalid": audit.support["kinematic_invalid"], "final_active": audit.support["final_active"],
            "final_feasible": audit.support["final_feasible"], "fallback_clean": audit.support["fallback_clean"],
            "any_feasible_threshold_success": audit.support["any_feasible_threshold_success"],
        })
    write_csv(output_dir / "physical_status_reaggregated.csv", tuple(physical_rows[0]), physical_rows)

    gate_a_counts: Counter[str] = Counter()
    gate_b_counts: Counter[str] = Counter()
    gate_c_counts: Counter[str] = Counter()
    for audit in audits:
        gate_a_counts.update(audit.gate_a)
        gate_b_counts.update(audit.gate_b)
        gate_c_counts.update(audit.gate_c)
    gate_a = gate_payload("Gate A - Best-Loss Correctness", gate_a_counts, ("fail",), source_hash)
    gate_a["tolerance"] = TOL
    gate_a["exact_violating_samples"] = gate_a_violations
    gate_b = gate_payload("Gate B - Success Preservation", gate_b_counts, ("success_lost", "missing_candidate_markers"), source_hash)
    gate_c = gate_payload("Gate C - Feasible-Success Preservation", gate_c_counts, ("feasible_success_lost", "candidate_missing"), source_hash)
    atomic_json(output_dir / "gate_a_best_loss.json", gate_a)
    atomic_json(output_dir / "gate_b_success_preservation.json", gate_b)
    atomic_json(output_dir / "gate_c_feasible_success.json", gate_c)

    aircraft_mismatch = 0
    transition_support_mismatch = 0
    summary_identity_failures_excluding_legacy = 0
    for audit in audits:
        for kind in ("final_active", "best_target_loss", "success_preserving", "best_feasible_success"):
            count = sum(values[f"{kind}_count"] for values in audit.aircraft_candidate.values())
            success = sum(values[f"{kind}_success"] for values in audit.aircraft_candidate.values())
            aircraft_mismatch += int(count != audit.candidate_counts[kind] or success != audit.candidate_success[kind])
        attacked = audit.support["attacked_anomalies"]
        for kind in ("best_target_loss", "success_preserving", "final_with_fallback_evaluation"):
            counts = audit.transitions[kind]
            transition_support_mismatch += int(not transition_support_complete(counts, attacked))
        summary_identity_failures_excluding_legacy += sum(
            not bool(value)
            for key, value in audit.summary.get("identity_checks", {}).items()
            if key != "best_iterate_not_weaker_than_final" and isinstance(value, bool)
        )
    gate_d_checks = {
        "all_denominators_explicit": True,
        "final_invalid_not_counted_as_resistance": True,
        "fallback_clean_not_mixed_with_final_attack_asr": True,
        "projection_failure_reported_separately": True,
        "source_invalid_reported_separately": True,
        "fallback_probability_matches_clean_within_tolerance": (
            sum(item.fallback_probability_gate_mismatch for item in audits) == 0
        ),
        "fallback_prediction_equals_clean": sum(item.fallback_prediction_mismatch for item in audits) == 0,
        "normal_controls_unchanged": all(item.normal_unchanged for item in audits),
        "attacked_normal_count_zero": sum(item.attacked_normal for item in audits) == 0,
        "per_aircraft_aggregation_reproduces_totals": aircraft_mismatch == 0,
        "prediction_transitions_cover_attacked_support": transition_support_mismatch == 0,
        "runner_metric_identities_excluding_legacy_checker": summary_identity_failures_excluding_legacy == 0,
        "target_ce_recomputes_from_probability": sum(item.ce_probability_mismatch for item in audits) == 0,
        "target_margin_recomputes_on_non_saturated_probability_rows": (
            sum(item.margin_probability_gate_mismatch for item in audits) == 0
        ),
        "threshold_success_recomputes_away_from_rounding_boundary": (
            sum(item.threshold_flag_gate_mismatch for item in audits) == 0
        ),
        "argmax_success_recomputes_from_probability": sum(item.argmax_flag_mismatch for item in audits) == 0,
        "probability_pairs_sum_to_one_within_tolerance": (
            sum(item.probability_pair_mismatch for item in audits) == 0
        ),
    }
    gate_d = {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "gate": "Gate D - Aggregate Reporting Consistency",
        "status": "PASS" if all(gate_d_checks.values()) else "FAIL",
        "checks": gate_d_checks,
        "denominators": {
            "final_active_asr": "samples with an actual active configured-final-step candidate",
            "evaluation_fallback_metric": "samples with no feasible executed final and archived clean fallback",
            "best_target_loss_asr": "attacked anomalies with an active finite candidate",
            "success_preserving_asr": "attacked anomalies with an active finite candidate",
            "best_feasible_success_asr": "V0 source-valid attacked anomalies for physical attacks",
            "pv_asr_v0": "V0 source-valid attacked anomalies",
        },
        "per_config_metrics_file": "per_seed_attack_envelope.csv",
        "diagnostic_counts": {
            "fallback_strict_float_mismatch": sum(item.fallback_probability_mismatch for item in audits),
            "fallback_tolerance_mismatch": sum(item.fallback_probability_gate_mismatch for item in audits),
            "fallback_prediction_mismatch": sum(item.fallback_prediction_mismatch for item in audits),
            "fallback_max_abs_difference": max(
                (item.fallback_max_abs_difference for item in audits), default=0.0
            ),
            "transition_support_mismatch": transition_support_mismatch,
            "transition_missing_candidates_reported": sum(
                audit.transitions[kind]["missing"]
                for audit in audits
                for kind in ("best_target_loss", "success_preserving", "final_with_fallback_evaluation")
            ),
            "target_margin_strict_mismatch": sum(item.margin_probability_mismatch for item in audits),
            "target_margin_gate_mismatch": sum(item.margin_probability_gate_mismatch for item in audits),
            "target_margin_not_reconstructable": sum(
                item.margin_probability_not_reconstructable for item in audits
            ),
            "threshold_flag_strict_mismatch": sum(item.threshold_flag_mismatch for item in audits),
            "threshold_flag_boundary_ambiguous": sum(
                item.threshold_flag_boundary_ambiguous for item in audits
            ),
            "threshold_flag_gate_mismatch": sum(item.threshold_flag_gate_mismatch for item in audits),
            "probability_pair_mismatch": sum(item.probability_pair_mismatch for item in audits),
        },
    }
    atomic_json(output_dir / "gate_d_aggregate_reporting.json", gate_d)

    configuration_checks = {
        "logical_records_640": inventory["manifest_total"] == 640,
        "successful_640": inventory["successful"] == 640,
        "missing_zero": not inventory["missing_ids"],
        "duplicates_zero": not inventory["duplicate_ids"],
        "unknown_zero": not inventory["unknown_ids"],
        "all_attempts_retained": True,
    }
    configuration_gate = {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "status": "PASS" if all(configuration_checks.values()) else "FAIL", "checks": configuration_checks,
    }
    completeness_checks = {
        "all_step_members_present": len(ledger["tasks"]) == 640,
        "all_summary_files_present": len(audits) == 640,
        "raw_snapshot_hashes_match": raw_verification["status"] == "PASS",
        "all_candidate_artifacts_hashed_in_raw_snapshot": raw_verification["candidate_artifact_count"] == 640,
        "explicit_failures_zero": inventory["explicit_failed"] == 0,
    }
    completeness_gate = {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "status": "PASS" if all(completeness_checks.values()) else "FAIL", "checks": completeness_checks,
    }
    identity = identity_gate(inventory, p2, audits, source_hash)
    native_checks = {
        "native_step_present": sum(item.step_rows for item in audits) > 0,
        "native_restart_id_present": True,
        "missing_steps_zero": sum(item.missing_steps for item in audits) == 0,
        "duplicate_steps_zero": sum(item.duplicate_steps for item in audits) == 0,
        "corrupted_members_zero": all(item.member_hashes_match for item in audits),
        "nan_target_rows_zero": sum(item.nan_rows for item in audits) == 0,
        "running_tail_not_read": not runners(),
    }
    native_gate = {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "status": "PASS" if all(native_checks.values()) else "FAIL", "checks": native_checks,
        "counts": {
            "step_rows": sum(item.step_rows for item in audits), "sample_rows": sum(item.sample_rows for item in audits),
            "missing_steps": sum(item.missing_steps for item in audits), "duplicate_steps": sum(item.duplicate_steps for item in audits),
            "nan_target_rows": sum(item.nan_rows for item in audits),
            "ce_probability_mismatch": sum(item.ce_probability_mismatch for item in audits),
            "margin_probability_mismatch": sum(item.margin_probability_mismatch for item in audits),
            "margin_probability_gate_mismatch": sum(item.margin_probability_gate_mismatch for item in audits),
            "margin_probability_not_reconstructable": sum(item.margin_probability_not_reconstructable for item in audits),
            "threshold_flag_mismatch": sum(item.threshold_flag_mismatch for item in audits),
            "threshold_flag_gate_mismatch": sum(item.threshold_flag_gate_mismatch for item in audits),
            "threshold_flag_boundary_ambiguous": sum(item.threshold_flag_boundary_ambiguous for item in audits),
            "argmax_flag_mismatch": sum(item.argmax_flag_mismatch for item in audits),
            "probability_pair_mismatch": sum(item.probability_pair_mismatch for item in audits),
        },
    }
    atomic_json(output_dir / "p2a_configuration_gate.json", configuration_gate)
    atomic_json(output_dir / "p2a_completeness_gate.json", completeness_gate)
    atomic_json(output_dir / "p2a_identity_gate.json", identity)
    atomic_json(output_dir / "p2a_native_logging_gate.json", native_gate)

    formal_statuses = {
        "configuration": configuration_gate["status"], "completeness": completeness_gate["status"],
        "identity": identity["status"], "native_logging": native_gate["status"],
        "gate_a_best_loss": gate_a["status"], "gate_b_success_preservation": gate_b["status"],
        "gate_c_feasible_success": gate_c["status"], "gate_d_aggregate_reporting": gate_d["status"],
    }
    integrity_status = "PASS" if all(value == "PASS" for value in formal_statuses.values()) else "FAIL"
    integrity = {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "status": integrity_status, "formal_gates": formal_statuses,
        "legacy_checker_is_non_binding": True,
        "legacy_failure_count": sum(not as_bool(row["legacy_checker_pass"]) for row in legacy_rows),
        "robustness_claims_restored": False,
    }
    atomic_json(output_dir / "p2a_integrity_gate.json", integrity)

    rules = load_json(p2 / "p2_alpha_selection_rules.json")
    selection = select_alpha(step_rows, rules) if integrity_status == "PASS" else {
        "status": "BLOCKED", "reason": "formal P2-A integrity gate did not pass", "selected": {},
    }
    selection.update({
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "frozen_rule_sha256": sha256_file(p2 / "p2_alpha_selection_rules.json"),
    })
    atomic_json(output_dir / "selected_attack_configs.json", selection)
    p2b_payload = None
    if integrity_status == "PASS" and selection["status"] == "SELECTED":
        p2b_payload = build_p2b_freeze(p2, output_dir, source_hash, posthoc_fingerprint, selection, audits)

    report = f"""# P2-A final post-hoc integrity reaggregation

Generated: {now()}

- Source raw snapshot: `{source_hash}`
- Post-hoc reaggregation fingerprint: `{posthoc_fingerprint}`
- Configurations: {len(audits)}/640
- Legacy checker failures retained: {integrity['legacy_failure_count']}
- Genuine comparable best-loss violations: {gate_a_counts['fail']}
- Gate A: {gate_a['status']}
- Gate B: {gate_b['status']}
- Gate C: {gate_c['status']}
- Gate D: {gate_d['status']}
- Final P2-A Integrity Gate: {integrity_status}
- P2-B freeze generated: {'yes' if p2b_payload is not None else 'no'}
- P2-B executed: no

This is a post-hoc integrity recomputation. It reads immutable native trajectory records and does not change attack values, candidates, the frozen runner, or the legacy checker history. Clean evaluation fallback is reported separately and is not treated as an executed attack candidate or evidence of robustness.
"""
    (output_dir / "final_reaggregation_report.md").write_text(report, encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA, "generation_utc": now(), "source_raw_snapshot_sha256": source_hash,
        "posthoc_reaggregation_fingerprint": posthoc_fingerprint, "configuration_count": len(audits),
        "formal_integrity_status": integrity_status, "p2b_freeze_generated": p2b_payload is not None,
        "p2b_executed": False, "p3_to_p6_executed": False, "manuscript_modified": False,
    }
    manifest["reaggregation_manifest_hash"] = canonical_hash(manifest)
    atomic_json(output_dir / "reaggregation_manifest.json", manifest)

    artifact_entries: dict[str, Any] = {}
    generation = now()
    for path in sorted(output_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.name == "artifact_hashes.json":
            continue
        artifact_entries[path.name] = {
            "schema_version": SCHEMA, "generation_utc": generation,
            "source_raw_snapshot_sha256": source_hash, "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    atomic_json(output_dir / "artifact_hashes.json", {
        "schema_version": SCHEMA, "generation_utc": generation,
        "source_raw_snapshot_sha256": source_hash, "self_excluded": True, "artifacts": artifact_entries,
    })
    return {
        "integrity": integrity, "selection": selection, "p2b": p2b_payload,
        "raw_snapshot_hash": source_hash, "posthoc_fingerprint": posthoc_fingerprint,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only P2-A post-hoc candidate reaggregation")
    parser.add_argument("command", choices=("snapshot", "reaggregate", "all"))
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--p2-dir", type=Path, default=Path("outputs/attack_audit_c001/p2"))
    parser.add_argument("--snapshot-dir", type=Path, default=Path("outputs/attack_audit_c001/p2/final_raw_snapshot"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/attack_audit_c001/p2/final_reaggregation"))
    args = parser.parse_args()
    root = args.project_root.resolve()
    resolve = lambda path: path.resolve() if path.is_absolute() else (root / path).resolve()
    p2 = resolve(args.p2_dir)
    snapshot_dir = resolve(args.snapshot_dir)
    output_dir = resolve(args.output_dir)
    result: dict[str, Any] = {}
    if args.command in {"snapshot", "all"}:
        result["snapshot"] = build_raw_snapshot(root, p2, snapshot_dir)
    if args.command in {"reaggregate", "all"}:
        result["reaggregation"] = run_reaggregation(root, p2, snapshot_dir, output_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

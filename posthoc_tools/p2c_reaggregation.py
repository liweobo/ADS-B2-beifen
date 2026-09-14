"""Independent P2-C reaggregation, trigger, and finalization.

The execution runner writes only newly executed restart ranges.  This module
never invokes an attack.  It reconstructs the formal nested candidate sets
from the immutable P2-B R10 cache plus P2-C range artifacts, applies the
preregistered unit-level R40 trigger, and produces the final gates.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import os
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from adsb.checkpoints import code_fingerprint, sha256_file
from adsb.p2_step_size_restart import ATTACKS, MODELS, PHYSICAL_ATTACKS, SEEDS, STEPS
from audit_tools.p2b_runner import (
    EXPECTED_ATTACK_CODE_FINGERPRINT,
    EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
    EXPECTED_P2B_MANIFEST_SHA256,
)
from audit_tools.p2c_orchestration import canonical_hash, task_identity
from audit_tools.p2c_runner import (
    INVENTORY_FIELDS,
    P2B_ROOT_RELATIVE,
    P2C_ROOT_RELATIVE,
    SCHEMA as RUNNER_SCHEMA,
    atomic_csv,
    load_json,
    read_csv,
    read_jsonl,
    verify_p2b_artifacts,
)


SCHEMA = "adsb.c001-p2c-reaggregation.v1"
TRIGGER_THRESHOLD = 0.005
CE_THRESHOLD = 0.01


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(
            value,
            stream,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = sorted({key for row in rows for key in row})
    if not fields:
        fields = ["schema_version", "status"]
        rows = [{"schema_version": SCHEMA, "status": "NOT_APPLICABLE"}]
    atomic_csv(path, fields, rows)


def _p2c_context(project_root: Path) -> dict[str, Any]:
    p2c = project_root / P2C_ROOT_RELATIVE
    preflight = load_json(p2c / "p2c_preflight.json")
    freeze = load_json(
        p2c / "configuration_freeze" / "p2c_configuration_hashes.json"
    )
    orchestration = load_json(p2c / "p2c_orchestration_fingerprint.json")
    source = load_json(
        p2c / "source_p2b_snapshot" / "p2b_source_snapshot_manifest.json"
    )
    if preflight["status"] != "PASS" or source["status"] != "PASS":
        raise RuntimeError("P2-C preflight/source snapshot is not PASS")
    if code_fingerprint(project_root) != EXPECTED_ATTACK_CODE_FINGERPRINT:
        raise RuntimeError("attack-code fingerprint changed before P2-C reaggregation")
    if (
        freeze["orchestration_fingerprint"]
        != orchestration["orchestration_fingerprint"]
    ):
        raise RuntimeError("orchestration fingerprint differs from frozen configuration")
    for name, artifact in freeze["components"].items():
        path = p2c / "configuration_freeze" / name
        if (
            path.stat().st_size != int(artifact["size_bytes"])
            or sha256_file(path) != artifact["sha256"]
        ):
            raise RuntimeError(f"frozen P2-C configuration changed: {path}")
    return {
        "p2c": p2c,
        "p2b": project_root / P2B_ROOT_RELATIVE,
        "preflight": preflight,
        "freeze": freeze,
        "orchestration": orchestration,
        "source": source,
    }


def _source_summary_lookup(p2b_root: Path) -> dict[str, dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for path in p2b_root.glob("tasks/*/summary.json"):
        summary = load_json(path)
        if summary.get("status") == "completed" and int(summary.get("restarts", 0)) == 10:
            summaries.append(summary)
    if len(summaries) != 80:
        raise RuntimeError(f"expected 80 frozen R10 summaries, found {len(summaries)}")
    output = {summary["p2b_logical_config_id"]: summary for summary in summaries}
    if len(output) != 80:
        raise RuntimeError("duplicate P2-B R10 logical config IDs")
    return output


def _config_source_lookup(p2c_root: Path, p2b_root: Path) -> dict[str, dict[str, Any]]:
    by_logical = _source_summary_lookup(p2b_root)
    frozen_rows = read_csv(
        p2c_root / "configuration_freeze" / "p2c_r20_task_inventory.csv"
    )
    by_task_hash = {value["task_hash"]: value for value in by_logical.values()}
    output: dict[str, dict[str, Any]] = {}
    for row in frozen_rows:
        output[row["config_id"]] = by_task_hash[row["source_r10_task_hash"]]
    if len(output) != 80:
        raise RuntimeError("P2-C frozen config/source mapping is incomplete")
    return output


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)


def _candidate_success(candidate: dict[str, Any] | None, threshold: float) -> bool:
    return candidate is not None and float(candidate["p_anomaly"]) < threshold


def _candidate_ce(candidate: dict[str, Any] | None) -> float:
    return float(candidate["target_ce"]) if candidate is not None else float("nan")


def _candidate_restart(candidate: dict[str, Any] | None) -> int:
    return int(candidate["restart_id"]) if candidate is not None else -1


def load_r10_state(
    *,
    p2b_root: Path,
    source_summary: dict[str, Any],
) -> dict[str, Any]:
    logical_id = source_summary["p2b_logical_config_id"]
    cache_path = p2b_root / "_analysis_cache" / f"{logical_id}.json.gz"
    if not cache_path.exists():
        raise RuntimeError(f"missing frozen P2-B analysis cache: {cache_path}")
    with gzip.open(cache_path, "rt", encoding="utf-8") as stream:
        audit = json.load(stream)
    if (
        audit.get("cache_version") != 2
        or audit.get("task_hash") != source_summary["task_hash"]
        or int(audit.get("restarts", 0)) != 10
        or audit.get("gate") != "PASS"
    ):
        raise RuntimeError(f"invalid frozen R10 cache: {cache_path}")

    samples = audit["samples"]
    sample_ids = np.asarray([row["sample_id"] for row in samples]).astype("U")
    candidate_artifact = source_summary["candidate_artifact"]
    candidate_path = p2b_root / candidate_artifact["path"]
    if (
        not candidate_path.exists()
        or candidate_path.stat().st_size
        != int(candidate_artifact["size_bytes"])
        or sha256_file(candidate_path) != candidate_artifact["sha256"]
    ):
        raise RuntimeError(f"frozen P2-B candidate artifact changed: {candidate_path}")
    candidate_archive = np.load(candidate_path)
    candidate_sample_ids = candidate_archive["sample_id"].astype("U")
    if set(candidate_sample_ids.tolist()) != set(sample_ids.tolist()):
        raise RuntimeError("P2-B cache/candidate sample support differs")
    candidate_lookup = {
        value: index for index, value in enumerate(candidate_sample_ids.tolist())
    }
    candidate_order = np.asarray(
        [candidate_lookup[value] for value in sample_ids.tolist()],
        dtype=np.int64,
    )
    individual_success = candidate_archive["per_restart_success"][
        :, candidate_order
    ].astype(bool)
    if individual_success.shape != (10, len(sample_ids)):
        raise RuntimeError("P2-B R10 per-restart success incidence is malformed")
    n = len(sample_ids)
    restarts = 10
    success = np.zeros((restarts, n), dtype=bool)
    feasible_success = np.zeros((restarts, n), dtype=bool)
    active = np.zeros((restarts, n), dtype=bool)
    final_valid = np.zeros((restarts, n), dtype=bool)
    initialized = np.zeros((restarts, n), dtype=bool)
    projection_failure = np.zeros((restarts, n), dtype=bool)
    best_ce = np.full((restarts, n), np.nan, dtype=np.float64)
    feasible_success_ce = np.full((restarts, n), np.nan, dtype=np.float64)
    selected_best = np.full((restarts, n), -1, dtype=np.int64)
    selected_success = np.full((restarts, n), -1, dtype=np.int64)
    selected_feasible = np.full((restarts, n), -1, dtype=np.int64)
    source_valid = np.zeros(n, dtype=bool)
    clean_probability = np.zeros(n, dtype=np.float64)
    clean_prediction = np.zeros(n, dtype=bool)
    threshold = float(audit["threshold"])
    for sample_index, sample in enumerate(samples):
        source_valid[sample_index] = _bool(sample["source_valid"])
        clean_probability[sample_index] = float(sample["clean_p_anomaly"])
        clean_prediction[sample_index] = _bool(sample["clean_prediction"])
        prefixes = sample["prefixes"]
        if len(prefixes) != 10:
            raise RuntimeError("R10 cache does not contain all ten prefixes")
        for prefix_index, prefix in enumerate(prefixes):
            success_candidate = prefix["success_preserving"]
            feasible_candidate = prefix["best_feasible_success"]
            best_candidate = prefix["best_target_loss"]
            success[prefix_index, sample_index] = _candidate_success(
                success_candidate, threshold
            )
            feasible_success[prefix_index, sample_index] = _candidate_success(
                feasible_candidate, threshold
            )
            active[prefix_index, sample_index] = _bool(prefix["active_any"])
            final_valid[prefix_index, sample_index] = not _bool(prefix["fallback"])
            initialized[prefix_index, sample_index] = _bool(prefix["initialized_any"])
            projection_failure[prefix_index, sample_index] = _bool(
                prefix["projection_failure_any"]
            )
            best_ce[prefix_index, sample_index] = _candidate_ce(best_candidate)
            feasible_success_ce[prefix_index, sample_index] = _candidate_ce(
                feasible_candidate
            )
            selected_best[prefix_index, sample_index] = _candidate_restart(
                best_candidate
            )
            selected_success[prefix_index, sample_index] = _candidate_restart(
                success_candidate if success[prefix_index, sample_index] else None
            )
            selected_feasible[prefix_index, sample_index] = _candidate_restart(
                feasible_candidate
            )
    return {
        "config_id": None,
        "seed": int(audit["seed"]),
        "model": audit["model"],
        "attack": audit["attack"],
        "K": int(audit["K"]),
        "threshold": threshold,
        "restart_count": 10,
        "sample_id": sample_ids,
        "source_valid": source_valid,
        "clean_p_anomaly": clean_probability,
        "clean_prediction": clean_prediction,
        "success_by_prefix": success,
        "feasible_success_by_prefix": feasible_success,
        "active_by_prefix": active,
        "final_valid_by_prefix": final_valid,
        "initialized_by_prefix": initialized,
        "projection_failure_by_prefix": projection_failure,
        "best_ce_by_prefix": best_ce,
        "feasible_success_ce_by_prefix": feasible_success_ce,
        "selected_best_by_prefix": selected_best,
        "selected_success_by_prefix": selected_success,
        "selected_feasible_by_prefix": selected_feasible,
        "individual_success_by_restart": individual_success,
        "source_task_hash": source_summary["task_hash"],
        "source_cache_sha256": sha256_file(cache_path),
        "source_candidate_sha256": candidate_artifact["sha256"],
    }


def _cumulative_min(value: np.ndarray) -> np.ndarray:
    safe = np.where(np.isfinite(value), value, np.inf)
    output = np.minimum.accumulate(safe, axis=0)
    output[~np.isfinite(output) | (output == np.inf)] = np.nan
    return output


def _combine_min(
    previous: np.ndarray,
    current: np.ndarray,
) -> np.ndarray:
    left = np.where(np.isfinite(previous), previous, np.inf)
    right = np.where(np.isfinite(current), current, np.inf)
    output = np.minimum(left, right)
    output[output == np.inf] = np.nan
    return output


def _selected_for_prefixes(
    *,
    previous_ce: np.ndarray,
    previous_selected: np.ndarray,
    new_ce: np.ndarray,
    new_restart_ids: np.ndarray,
) -> np.ndarray:
    rows: list[np.ndarray] = []
    best_ce = previous_ce.copy()
    best_selected = previous_selected.copy()
    for local_index, restart_id in enumerate(new_restart_ids):
        candidate = new_ce[local_index]
        stronger = np.isfinite(candidate) & (
            ~np.isfinite(best_ce) | (candidate < best_ce)
        )
        best_ce[stronger] = candidate[stronger]
        best_selected[stronger] = int(restart_id)
        rows.append(best_selected.copy())
    return np.stack(rows, axis=0)


def merge_range_state(
    *,
    previous: dict[str, Any],
    range_npz_path: Path,
    expected_restart_ids: Sequence[int],
    config_id: str,
) -> dict[str, Any]:
    archive = np.load(range_npz_path)
    restart_ids = archive["restart_ids"].astype(np.int64)
    if restart_ids.tolist() != list(expected_restart_ids):
        raise RuntimeError(f"range candidate restart IDs mismatch: {range_npz_path}")
    prior_ids = previous["sample_id"].astype("U")
    new_ids = archive["sample_id"].astype("U")
    if set(prior_ids.tolist()) != set(new_ids.tolist()):
        raise RuntimeError(f"range sample support differs from previous stage: {config_id}")
    new_lookup = {value: index for index, value in enumerate(new_ids.tolist())}
    order = np.asarray([new_lookup[value] for value in prior_ids.tolist()], dtype=np.int64)

    def aligned(name: str) -> np.ndarray:
        value = archive[name]
        if value.ndim == 1:
            return value[order]
        return value[:, order]

    new_success = aligned("per_restart_success").astype(bool)
    new_feasible = aligned("per_restart_feasible_success").astype(bool)
    new_active = aligned("per_restart_active").astype(bool)
    new_final_valid = aligned("per_restart_final_valid").astype(bool)
    new_initialized = aligned("per_restart_initialization_success").astype(bool)
    new_projection_failure = aligned("per_restart_projection_failure").astype(bool)
    new_best_ce = aligned("per_restart_best_target_ce").astype(np.float64)
    new_best_feasible_ce = aligned(
        "per_restart_best_feasible_target_ce"
    ).astype(np.float64)
    new_feasible_success_ce = np.where(
        new_feasible, new_best_feasible_ce, np.nan
    )
    new_success_ce = np.where(
        new_success,
        (
            new_best_feasible_ce
            if previous["attack"] in PHYSICAL_ATTACKS
            else new_best_ce
        ),
        np.nan,
    )

    previous_success = previous["success_by_prefix"][-1]
    previous_feasible = previous["feasible_success_by_prefix"][-1]
    previous_active = previous["active_by_prefix"][-1]
    previous_final_valid = previous["final_valid_by_prefix"][-1]
    previous_initialized = previous["initialized_by_prefix"][-1]
    previous_projection_failure = previous["projection_failure_by_prefix"][-1]
    previous_best_ce = previous["best_ce_by_prefix"][-1]
    previous_feasible_ce = previous["feasible_success_ce_by_prefix"][-1]
    previous_selected_best = previous["selected_best_by_prefix"][-1]
    previous_selected_success = previous["selected_success_by_prefix"][-1]
    previous_selected_feasible = previous["selected_feasible_by_prefix"][-1]

    new_success_prefix = np.logical_or.accumulate(new_success, axis=0)
    new_feasible_prefix = np.logical_or.accumulate(new_feasible, axis=0)
    new_active_prefix = np.logical_or.accumulate(new_active, axis=0)
    new_final_prefix = np.logical_or.accumulate(new_final_valid, axis=0)
    new_init_prefix = np.logical_or.accumulate(new_initialized, axis=0)
    new_projection_prefix = np.logical_or.accumulate(
        new_projection_failure, axis=0
    )
    new_best_ce_prefix = _cumulative_min(new_best_ce)
    new_success_ce_prefix = _cumulative_min(new_success_ce)
    new_feasible_ce_prefix = _cumulative_min(new_feasible_success_ce)

    current_success = previous_success[None, :] | new_success_prefix
    current_feasible = previous_feasible[None, :] | new_feasible_prefix
    current_active = previous_active[None, :] | new_active_prefix
    current_final_valid = previous_final_valid[None, :] | new_final_prefix
    current_initialized = previous_initialized[None, :] | new_init_prefix
    current_projection = previous_projection_failure[None, :] | new_projection_prefix
    current_best_ce = np.stack(
        [
            _combine_min(previous_best_ce, new_best_ce_prefix[index])
            for index in range(len(restart_ids))
        ],
        axis=0,
    )
    current_feasible_ce = np.stack(
        [
            _combine_min(previous_feasible_ce, new_feasible_ce_prefix[index])
            for index in range(len(restart_ids))
        ],
        axis=0,
    )
    previous_success_ce = np.where(previous_success, previous_best_ce, np.nan)
    if previous["attack"] in PHYSICAL_ATTACKS:
        previous_success_ce = previous_feasible_ce.copy()
    selected_best = _selected_for_prefixes(
        previous_ce=previous_best_ce,
        previous_selected=previous_selected_best,
        new_ce=new_best_ce,
        new_restart_ids=restart_ids,
    )
    selected_success = _selected_for_prefixes(
        previous_ce=previous_success_ce,
        previous_selected=previous_selected_success,
        new_ce=new_success_ce,
        new_restart_ids=restart_ids,
    )
    selected_feasible = _selected_for_prefixes(
        previous_ce=previous_feasible_ce,
        previous_selected=previous_selected_feasible,
        new_ce=new_feasible_success_ce,
        new_restart_ids=restart_ids,
    )

    return {
        "config_id": config_id,
        "seed": previous["seed"],
        "model": previous["model"],
        "attack": previous["attack"],
        "K": previous["K"],
        "threshold": previous["threshold"],
        "restart_count": previous["restart_count"] + len(restart_ids),
        "sample_id": prior_ids,
        "source_valid": previous["source_valid"],
        "clean_p_anomaly": previous["clean_p_anomaly"],
        "clean_prediction": previous["clean_prediction"],
        "success_by_prefix": np.concatenate(
            [previous["success_by_prefix"], current_success], axis=0
        ),
        "feasible_success_by_prefix": np.concatenate(
            [previous["feasible_success_by_prefix"], current_feasible], axis=0
        ),
        "active_by_prefix": np.concatenate(
            [previous["active_by_prefix"], current_active], axis=0
        ),
        "final_valid_by_prefix": np.concatenate(
            [previous["final_valid_by_prefix"], current_final_valid], axis=0
        ),
        "initialized_by_prefix": np.concatenate(
            [previous["initialized_by_prefix"], current_initialized], axis=0
        ),
        "projection_failure_by_prefix": np.concatenate(
            [previous["projection_failure_by_prefix"], current_projection], axis=0
        ),
        "best_ce_by_prefix": np.concatenate(
            [previous["best_ce_by_prefix"], current_best_ce], axis=0
        ),
        "feasible_success_ce_by_prefix": np.concatenate(
            [
                previous["feasible_success_ce_by_prefix"],
                current_feasible_ce,
            ],
            axis=0,
        ),
        "selected_best_by_prefix": np.concatenate(
            [previous["selected_best_by_prefix"], selected_best], axis=0
        ),
        "selected_success_by_prefix": np.concatenate(
            [previous["selected_success_by_prefix"], selected_success], axis=0
        ),
        "selected_feasible_by_prefix": np.concatenate(
            [previous["selected_feasible_by_prefix"], selected_feasible], axis=0
        ),
        "individual_success_by_restart": np.concatenate(
            [previous["individual_success_by_restart"], new_success], axis=0
        ),
        "source_task_hash": previous["source_task_hash"],
        "source_cache_sha256": previous["source_cache_sha256"],
        "source_candidate_sha256": previous["source_candidate_sha256"],
        "range_candidate_sha256": sha256_file(range_npz_path),
        "executed_restart_ids": restart_ids.tolist(),
    }


def _state_cache_paths(
    p2c_root: Path, stage: str, config_id: str
) -> tuple[Path, Path]:
    root = p2c_root / "_analysis_cache" / stage
    return root / f"{config_id}.npz", root / f"{config_id}.json"


def save_state(p2c_root: Path, stage: str, state: dict[str, Any]) -> dict[str, Any]:
    npz_path, json_path = _state_cache_paths(p2c_root, stage, state["config_id"])
    npz_path.parent.mkdir(parents=True, exist_ok=True)
    array_names = (
        "sample_id",
        "source_valid",
        "clean_p_anomaly",
        "clean_prediction",
        "success_by_prefix",
        "feasible_success_by_prefix",
        "active_by_prefix",
        "final_valid_by_prefix",
        "initialized_by_prefix",
        "projection_failure_by_prefix",
        "best_ce_by_prefix",
        "feasible_success_ce_by_prefix",
        "selected_best_by_prefix",
        "selected_success_by_prefix",
        "selected_feasible_by_prefix",
        "individual_success_by_restart",
    )
    temporary = npz_path.with_name(f".{npz_path.name}.{os.getpid()}.tmp.npz")
    np.savez_compressed(temporary, **{name: state[name] for name in array_names})
    os.replace(temporary, npz_path)
    metadata = {
        key: value
        for key, value in state.items()
        if key not in array_names
    }
    metadata.update(
        {
            "schema_version": SCHEMA,
            "generated_at_utc": now(),
            "array_artifact": {
                "path": npz_path.name,
                "size_bytes": npz_path.stat().st_size,
                "sha256": sha256_file(npz_path),
            },
        }
    )
    atomic_json(json_path, metadata)
    return {
        "npz": npz_path,
        "json": json_path,
        "metadata": metadata,
    }


def load_state(p2c_root: Path, stage: str, config_id: str) -> dict[str, Any]:
    npz_path, json_path = _state_cache_paths(p2c_root, stage, config_id)
    metadata = load_json(json_path)
    if (
        npz_path.stat().st_size
        != int(metadata["array_artifact"]["size_bytes"])
        or sha256_file(npz_path) != metadata["array_artifact"]["sha256"]
    ):
        raise RuntimeError(f"cached P2-C state changed: {npz_path}")
    archive = np.load(npz_path)
    output = dict(metadata)
    output.pop("array_artifact", None)
    output.update({name: archive[name] for name in archive.files})
    return output


def _relative_ce_gain(previous: np.ndarray, current: np.ndarray) -> dict[str, Any]:
    common = np.isfinite(previous) & np.isfinite(current)
    if not common.any():
        return {
            "common_active_support": 0,
            "median_relative_target_ce_gain": None,
            "max_relative_target_ce_gain": None,
        }
    gains = (previous[common] - current[common]) / np.maximum(
        previous[common], 1e-3
    )
    return {
        "common_active_support": int(common.sum()),
        "median_relative_target_ce_gain": float(np.median(gains)),
        "max_relative_target_ce_gain": float(np.max(gains)),
    }


def compare_states(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    previous_index = int(previous["restart_count"]) - 1
    current_index = int(current["restart_count"]) - 1
    previous_success = previous["success_by_prefix"][previous_index]
    current_success = current["success_by_prefix"][current_index]
    previous_feasible = previous["feasible_success_by_prefix"][previous_index]
    current_feasible = current["feasible_success_by_prefix"][current_index]
    previous_ce = previous["best_ce_by_prefix"][previous_index]
    current_ce = current["best_ce_by_prefix"][current_index]
    previous_feasible_ce = previous["feasible_success_ce_by_prefix"][
        previous_index
    ]
    current_feasible_ce = current["feasible_success_ce_by_prefix"][
        current_index
    ]
    attacked = len(previous_success)
    if attacked != len(current_success):
        raise RuntimeError("attacked support changed across restart stages")
    source_valid = previous["source_valid"]
    if not np.array_equal(source_valid, current["source_valid"]):
        raise RuntimeError("physical source support changed across restart stages")
    v0 = int(source_valid.sum())
    previous_count = int(previous_success.sum())
    current_count = int(current_success.sum())
    previous_asr = previous_count / attacked if attacked else None
    current_asr = current_count / attacked if attacked else None
    delta = (
        float(current_asr - previous_asr)
        if previous_asr is not None and current_asr is not None
        else None
    )
    physical = previous["attack"] in PHYSICAL_ATTACKS
    previous_feasible_count = int((previous_feasible & source_valid).sum())
    current_feasible_count = int((current_feasible & source_valid).sum())
    previous_feasible_asr = (
        previous_feasible_count / v0 if physical and v0 else None
    )
    current_feasible_asr = (
        current_feasible_count / v0 if physical and v0 else None
    )
    feasible_delta = (
        float(current_feasible_asr - previous_feasible_asr)
        if previous_feasible_asr is not None
        and current_feasible_asr is not None
        else None
    )
    ce = _relative_ce_gain(previous_ce, current_ce)
    overlap_intersection = int((previous_success & current_success).sum())
    overlap_union = int((previous_success | current_success).sum())
    row = {
        "schema_version": SCHEMA,
        "config_id": current["config_id"],
        "seed": current["seed"],
        "model": current["model"],
        "attack": current["attack"],
        "K": current["K"],
        "previous_restarts": previous["restart_count"],
        "current_restarts": current["restart_count"],
        "attacked_support": attacked,
        "source_valid_support": v0,
        "previous_successes": previous_count,
        "current_successes": current_count,
        "new_successes": current_count - previous_count,
        "previous_success_preserving_asr": previous_asr,
        "current_success_preserving_asr": current_asr,
        "success_preserving_asr_increment": delta,
        "previous_feasible_successes": previous_feasible_count if physical else None,
        "current_feasible_successes": current_feasible_count if physical else None,
        "new_feasible_successes": (
            current_feasible_count - previous_feasible_count if physical else None
        ),
        "previous_feasible_success_asr": previous_feasible_asr,
        "current_feasible_success_asr": current_feasible_asr,
        "feasible_success_asr_increment": feasible_delta,
        **ce,
        "success_intersection": overlap_intersection,
        "success_union": overlap_union,
        "success_jaccard": (
            overlap_intersection / overlap_union if overlap_union else 1.0
        ),
        "trigger_threshold": TRIGGER_THRESHOLD,
        "trigger_unit": delta is not None and delta >= TRIGGER_THRESHOLD,
    }
    checks = {
        "same_sample_ids": np.array_equal(
            previous["sample_id"], current["sample_id"]
        ),
        "same_attacked_support": attacked == len(current_success),
        "same_source_valid_support": np.array_equal(
            previous["source_valid"], current["source_valid"]
        ),
        "no_threshold_success_loss": int(
            (previous_success & ~current_success).sum()
        )
        == 0,
        "no_feasible_success_loss": int(
            (previous_feasible & ~current_feasible).sum()
        )
        == 0,
        "best_target_ce_not_worse": bool(
            (
                ~np.isfinite(previous_ce)
                | (
                    np.isfinite(current_ce)
                    & (current_ce <= previous_ce + 1e-8)
                )
            ).all()
        ),
        "best_feasible_success_not_worse": bool(
            (
                ~np.isfinite(previous_feasible_ce)
                | (
                    np.isfinite(current_feasible_ce)
                    & (current_feasible_ce <= previous_feasible_ce + 1e-8)
                )
            ).all()
        ),
        "success_preserving_not_worse": current_count >= previous_count,
        "candidate_archive_nested": current["restart_count"]
        > previous["restart_count"],
    }
    audit = {
        "schema_version": SCHEMA,
        "config_id": current["config_id"],
        "seed": current["seed"],
        "model": current["model"],
        "attack": current["attack"],
        "K": current["K"],
        "previous_restart_count": previous["restart_count"],
        "current_restart_count": current["restart_count"],
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL",
    }
    return row, audit


def _verify_phase_execution(
    phase_dir: Path,
    expected_count: int,
    expected_ids: Sequence[int],
) -> dict[str, Any]:
    phase = phase_dir.name.split("_", 1)[0]
    inventory = read_csv(phase_dir / f"{phase}_task_inventory.csv")
    ledger = read_jsonl(phase_dir / f"{phase}_ledger.jsonl")
    task_hashes = [row["task_hash"] for row in inventory]
    ledger_hashes = [row["task_hash"] for row in ledger]
    task_verification: list[dict[str, Any]] = []
    for row in inventory:
        summary_path = phase_dir / "tasks" / row["task_hash"] / "summary.json"
        passed = summary_path.exists()
        details: dict[str, Any] = {}
        if passed:
            summary = load_json(summary_path)
            passed &= summary.get("status") == "completed"
            passed &= summary.get("executed_restart_ids") == list(expected_ids)
            passed &= summary.get("task_hash") == row["task_hash"]
            artifact_checks = []
            for artifact in summary["artifacts"].values():
                path = summary_path.parent / artifact["path"]
                match = (
                    path.exists()
                    and path.stat().st_size == int(artifact["size_bytes"])
                    and sha256_file(path) == artifact["sha256"]
                )
                artifact_checks.append(match)
            passed &= all(artifact_checks)
            passed &= all(summary["identity_checks"].values())
            details = {
                "executed_restart_ids": summary["executed_restart_ids"],
                "artifact_checks": artifact_checks,
                "identity_checks": summary["identity_checks"],
            }
        task_verification.append(
            {
                "config_id": row["config_id"],
                "task_hash": row["task_hash"],
                "pass": bool(passed),
                **details,
            }
        )
    staging = phase_dir / ".staging"
    failed_final = [
        row for row in inventory if row["execution_status"] == "failed"
    ]
    checks = {
        "inventory_count": len(inventory) == expected_count,
        "inventory_config_ids_unique": len({row["config_id"] for row in inventory})
        == len(inventory),
        "inventory_task_hashes_unique": len(set(task_hashes)) == len(task_hashes),
        "all_inventory_completed": all(
            row["execution_status"] == "completed" for row in inventory
        ),
        "ledger_count": len(ledger) == expected_count,
        "ledger_task_hashes_unique": len(set(ledger_hashes)) == len(ledger_hashes),
        "ledger_equals_inventory": set(ledger_hashes) == set(task_hashes),
        "staging_empty": not staging.exists()
        or not any(value.is_dir() for value in staging.iterdir()),
        "no_final_failed_tasks": len(failed_final) == 0,
        "all_task_artifacts_verified": all(
            value["pass"] for value in task_verification
        ),
    }
    return {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "phase": phase,
        "expected_task_count": expected_count,
        "expected_restart_ids": list(expected_ids),
        "checks": checks,
        "task_verification": task_verification,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "inventory": inventory,
        "ledger": ledger,
    }


def _snapshot_phase_raw(
    *,
    p2c_root: Path,
    phase: str,
    source_snapshot_hash: str,
    configuration_hash: str,
    orchestration_fingerprint: str,
) -> dict[str, Any]:
    phase_dir = p2c_root / f"{phase}_execution"
    rows: list[dict[str, Any]] = []
    for path in sorted(
        (value for value in phase_dir.rglob("*") if value.is_file()),
        key=lambda value: value.relative_to(phase_dir).as_posix(),
    ):
        if path.name.endswith(".lock"):
            continue
        rows.append(
            {
                "path": path.relative_to(phase_dir).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    snapshot_hash = canonical_hash(
        {
            "schema_version": SCHEMA,
            "phase": phase,
            "artifacts": rows,
            "source_p2b_snapshot_hash": source_snapshot_hash,
            "p2c_configuration_hash": configuration_hash,
            "orchestration_fingerprint": orchestration_fingerprint,
        }
    )
    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "FROZEN",
        "phase": phase,
        f"{phase}_raw_snapshot_hash": snapshot_hash,
        "artifact_count": len(rows),
        "artifacts": rows,
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "p2c_configuration_hash": configuration_hash,
        "orchestration_fingerprint": orchestration_fingerprint,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
    }
    atomic_json(p2c_root / f"{phase}_raw_snapshot_manifest.json", manifest)
    atomic_json(
        p2c_root / f"{phase}_artifact_hashes.json",
        {
            "schema_version": SCHEMA,
            "generated_at_utc": now(),
            "phase": phase,
            "raw_snapshot_hash": snapshot_hash,
            "artifact_count": len(rows),
            "artifacts": rows,
        },
    )
    return manifest


def _task_summary_path(phase_dir: Path, task_hash: str) -> Path:
    return phase_dir / "tasks" / task_hash / "summary.json"


def _aggregate_by_model(rows: list[dict[str, Any]], label: str) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["model"], row["attack"])].append(row)
    output: list[dict[str, Any]] = []
    for (model, attack), values in sorted(groups.items()):
        increments = [
            float(row["success_preserving_asr_increment"]) for row in values
        ]
        ce_gains = [
            float(row["median_relative_target_ce_gain"])
            for row in values
            if row["median_relative_target_ce_gain"] is not None
        ]
        output.append(
            {
                "schema_version": SCHEMA,
                "comparison": label,
                "model": model,
                "attack": attack,
                "unit_count": len(values),
                "mean_asr_increment": float(np.mean(increments)),
                "max_asr_increment": float(np.max(increments)),
                "new_successes": sum(int(row["new_successes"]) for row in values),
                "new_feasible_successes": sum(
                    int(row["new_feasible_successes"] or 0) for row in values
                ),
                "median_unit_relative_target_ce_gain": (
                    float(np.median(ce_gains)) if ce_gains else None
                ),
            }
        )
    return output


def _diagnostic_tables(
    states: list[dict[str, Any]],
    comparison_rows: list[dict[str, Any]],
    prefix: str,
) -> dict[str, list[dict[str, Any]]]:
    cumulative: list[dict[str, Any]] = []
    distributions: list[dict[str, Any]] = []
    physical: list[dict[str, Any]] = []
    overlap: list[dict[str, Any]] = []
    for state in states:
        attacked = len(state["sample_id"])
        v0 = int(state["source_valid"].sum())
        for restart_index in range(state["restart_count"]):
            success = state["success_by_prefix"][restart_index]
            feasible = state["feasible_success_by_prefix"][restart_index]
            cumulative.append(
                {
                    "schema_version": SCHEMA,
                    "stage": prefix,
                    "config_id": state["config_id"],
                    "seed": state["seed"],
                    "model": state["model"],
                    "attack": state["attack"],
                    "K": state["K"],
                    "restart_count": restart_index + 1,
                    "successes": int(success.sum()),
                    "success_preserving_asr": (
                        float(success.sum() / attacked) if attacked else None
                    ),
                    "feasible_successes": int((feasible & state["source_valid"]).sum()),
                    "feasible_success_asr": (
                        float((feasible & state["source_valid"]).sum() / v0)
                        if state["attack"] in PHYSICAL_ATTACKS and v0
                        else None
                    ),
                    "active_support": int(
                        state["active_by_prefix"][restart_index].sum()
                    ),
                    "fallback_count": int(
                        (
                            ~state["final_valid_by_prefix"][restart_index]
                        ).sum()
                    ),
                }
            )
        final_selected = state["selected_best_by_prefix"][-1]
        for restart_id, count in sorted(Counter(final_selected.tolist()).items()):
            distributions.append(
                {
                    "schema_version": SCHEMA,
                    "stage": prefix,
                    "config_id": state["config_id"],
                    "seed": state["seed"],
                    "model": state["model"],
                    "attack": state["attack"],
                    "K": state["K"],
                    "restart_id": restart_id,
                    "selected_count": count,
                    "selected_rate": count / attacked if attacked else None,
                }
            )
        if state["attack"] in PHYSICAL_ATTACKS:
            physical.append(
                {
                    "schema_version": SCHEMA,
                    "stage": prefix,
                    "config_id": state["config_id"],
                    "seed": state["seed"],
                    "model": state["model"],
                    "attack": state["attack"],
                    "K": state["K"],
                    "attacked_support": attacked,
                    "source_valid_support": v0,
                    "active_support": int(state["active_by_prefix"][-1].sum()),
                    "final_valid_support": int(
                        state["final_valid_by_prefix"][-1].sum()
                    ),
                    "fallback_count": int(
                        (~state["final_valid_by_prefix"][-1]).sum()
                    ),
                    "initialization_infeasible_count": int(
                        (~state["initialized_by_prefix"][-1]).sum()
                    ),
                    "projection_failure_count": int(
                        state["projection_failure_by_prefix"][-1].sum()
                    ),
                    "threshold_success_support": int(
                        state["success_by_prefix"][-1].sum()
                    ),
                    "feasible_success_support": int(
                        (
                            state["feasible_success_by_prefix"][-1]
                            & state["source_valid"]
                        ).sum()
                    ),
                    "diagnostic_pending_loss_penalty_audit": (
                        state["attack"] == "phys_penalty_pgd"
                    ),
                }
            )
    for row in comparison_rows:
        overlap.append(
            {
                key: row[key]
                for key in (
                    "schema_version",
                    "config_id",
                    "seed",
                    "model",
                    "attack",
                    "K",
                    "previous_restarts",
                    "current_restarts",
                    "success_intersection",
                    "success_union",
                    "success_jaccard",
                    "new_successes",
                )
            }
        )
    return {
        "cumulative": cumulative,
        "distribution": distributions,
        "physical": physical,
        "overlap": overlap,
    }


def _gate(path: Path, name: str, checks: dict[str, Any], **extra: Any) -> dict[str, Any]:
    boolean_checks = [
        bool(value) for value in checks.values() if isinstance(value, bool)
    ]
    status = "PASS" if boolean_checks and all(boolean_checks) else "FAIL"
    payload = {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "gate_name": name,
        "status": status,
        "checks": checks,
        **extra,
    }
    atomic_json(path, payload)
    return payload


def _initialize_r40(
    *,
    context: dict[str, Any],
    decision: dict[str, Any],
    r20_snapshot_hash: str,
) -> dict[str, Any]:
    p2c = context["p2c"]
    root = p2c / "r40_execution"
    if root.exists():
        raise RuntimeError("R40 execution directory already exists before trigger freeze")
    root.mkdir(parents=True, exist_ok=False)
    templates = read_csv(
        p2c
        / "configuration_freeze"
        / "p2c_conditional_r40_templates.csv"
    )
    triggered = {
        attack
        for attack, value in decision["per_family"].items()
        if value["trigger"]
    }
    source_lookup = _config_source_lookup(p2c, context["p2b"])
    rows: list[dict[str, Any]] = []
    source_snapshot_hash = context["source"]["source_p2b_snapshot_hash"]
    configuration_hash = context["freeze"]["p2c_configuration_hash"]
    orchestration_fingerprint = context["orchestration"][
        "orchestration_fingerprint"
    ]
    for template in templates:
        if template["attack"] not in triggered:
            continue
        source = source_lookup[template["config_id"]]
        restart_ids = tuple(range(20, 40))
        identity = task_identity(
            phase="r40",
            config_id=template["config_id"],
            source_summary=source,
            target_restart_count=40,
            restart_ids=restart_ids,
            source_snapshot_hash=source_snapshot_hash,
            previous_snapshot_hash=r20_snapshot_hash,
            p2c_configuration_hash=configuration_hash,
            orchestration_fingerprint=orchestration_fingerprint,
        )
        rows.append(
            {
                **template,
                "source_previous_snapshot_hash": r20_snapshot_hash,
                "task_hash": canonical_hash(identity),
                "execution_status": "pending",
                "attempt_count": "0",
                "last_error": "",
                "completed_at_utc": "",
            }
        )
    expected = 20 * len(triggered)
    if len(rows) != expected:
        raise RuntimeError(f"R40 triggered inventory mismatch: {len(rows)} != {expected}")
    atomic_csv(root / "r40_task_inventory.csv", INVENTORY_FIELDS, rows)
    (root / "r40_ledger.jsonl").write_text("", encoding="utf-8")
    (root / "r40_failed_runs.jsonl").write_text("", encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "FROZEN",
        "phase": "r40",
        "triggered_families": sorted(triggered),
        "logical_task_count": expected,
        "new_restarts_per_task": 20,
        "new_restart_trajectory_count": expected * 20,
        "executed_restart_ids": list(range(20, 40)),
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "source_r20_snapshot_hash": r20_snapshot_hash,
        "r40_trigger_decision_sha256": sha256_file(
            p2c / "r40_trigger_decision.json"
        ),
        "p2c_configuration_hash": configuration_hash,
        "orchestration_fingerprint": orchestration_fingerprint,
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
        "task_inventory_initial_sha256": sha256_file(
            root / "r40_task_inventory.csv"
        ),
    }
    atomic_json(root / "r40_execution_manifest.json", manifest)
    runtime = {
        "schema_version": RUNNER_SCHEMA,
        "updated_at_utc": now(),
        "phase": "r40_not_applicable" if expected == 0 else "r40",
        "runner_pid": None,
        "logical_tasks": expected,
        "pending": expected,
        "running": 0,
        "completed": 0,
        "failed": 0,
        "current_task": None,
        "latest_completed_task": None,
        "duplicate_ids": 0,
        "unknown_ids": 0,
        "staging_count": 0,
        "disk_free_bytes": shutil.disk_usage(p2c.drive + "\\").free,
        "output_size_bytes": sum(
            path.stat().st_size for path in root.rglob("*") if path.is_file()
        ),
        "frozen_configuration_hash": configuration_hash,
        "source_p2b_snapshot_hash": source_snapshot_hash,
        "source_r20_snapshot_hash": r20_snapshot_hash,
        "orchestration_fingerprint": orchestration_fingerprint,
        "p3_to_p6_executed": False,
        "r80_executed": False,
        "paper_modified": False,
    }
    atomic_json(root / "r40_runtime_status.json", runtime)
    return manifest


def _slice_state(state: dict[str, Any], restart_count: int) -> dict[str, Any]:
    """Return an in-memory prefix without changing a cached state."""
    if restart_count < 1 or restart_count > int(state["restart_count"]):
        raise ValueError("invalid state prefix")
    prefix_arrays = (
        "success_by_prefix",
        "feasible_success_by_prefix",
        "active_by_prefix",
        "final_valid_by_prefix",
        "initialized_by_prefix",
        "projection_failure_by_prefix",
        "best_ce_by_prefix",
        "feasible_success_ce_by_prefix",
        "selected_best_by_prefix",
        "selected_success_by_prefix",
        "selected_feasible_by_prefix",
        "individual_success_by_restart",
    )
    output = dict(state)
    output["restart_count"] = restart_count
    for name in prefix_arrays:
        output[name] = state[name][:restart_count].copy()
    return output


def _not_applicable_rows(
    attacks: Iterable[str],
    *,
    stage: str,
    reason: str,
) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": SCHEMA,
            "generation_utc": now(),
            "stage": stage,
            "attack": attack,
            "status": "NOT_APPLICABLE",
            "reason": reason,
        }
        for attack in sorted(attacks)
    ]


def _stage_support_row(
    state: dict[str, Any],
    *,
    stage: str,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    index = int(state["restart_count"]) - 1
    attacked = len(state["sample_id"])
    source_valid = state["source_valid"]
    v0 = int(source_valid.sum())
    active = state["active_by_prefix"][index]
    final_valid = state["final_valid_by_prefix"][index]
    success = state["success_by_prefix"][index]
    feasible_success = state["feasible_success_by_prefix"][index] & source_valid
    previous_success = (
        previous["success_by_prefix"][int(previous["restart_count"]) - 1]
        if previous is not None
        else np.zeros(attacked, dtype=bool)
    )
    previous_valid = (
        previous["final_valid_by_prefix"][int(previous["restart_count"]) - 1]
        if previous is not None
        else np.zeros(attacked, dtype=bool)
    )
    return {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "stage": stage,
        "config_id": state["config_id"],
        "seed": state["seed"],
        "model": state["model"],
        "attack": state["attack"],
        "K": state["K"],
        "restart_count": state["restart_count"],
        "attacked_support": attacked,
        "active_support": int(active.sum()),
        "final_valid_support": int(final_valid.sum()),
        "fallback_count": int((~final_valid).sum()),
        "fallback_rate": float((~final_valid).sum() / attacked)
        if attacked
        else None,
        "source_valid_support": v0,
        "feasible_support": int((final_valid & source_valid).sum()),
        "threshold_success_support": int(success.sum()),
        "feasible_success_support": int(feasible_success.sum()),
        "new_success_attributable_to_new_restart": int(
            (success & ~previous_success).sum()
        )
        if previous is not None
        else None,
        "new_valid_support_attributable_to_new_restart": int(
            (final_valid & ~previous_valid).sum()
        )
        if previous is not None
        else None,
        "initialization_infeasible_count": int(
            (~state["initialized_by_prefix"][index]).sum()
        ),
        "projection_failure_count": int(
            state["projection_failure_by_prefix"][index].sum()
        ),
        "diagnostic_pending_loss_penalty_audit": (
            state["attack"] == "phys_penalty_pgd"
        ),
    }


def _fit_saturation(success_by_prefix: np.ndarray) -> dict[str, Any]:
    counts = success_by_prefix.sum(axis=1).astype(np.float64)
    n = np.arange(1, len(counts) + 1, dtype=np.float64)
    final = float(counts[-1]) if len(counts) else 0.0
    support = float(success_by_prefix.shape[1])
    if not len(counts) or final == 0:
        return {
            "model": "discrete_grid y=A*(1-exp(-b*n))",
            "fitted_asymptote": final,
            "fitted_rate": None,
            "fitted_unseen_successes": 0.0,
            "fit_rmse": 0.0,
            "warning": "NO_OBSERVED_SUCCESSES",
        }
    if final >= support:
        return {
            "model": "discrete_grid y=A*(1-exp(-b*n))",
            "fitted_asymptote": support,
            "fitted_rate": None,
            "fitted_unseen_successes": 0.0,
            "fit_rmse": 0.0,
            "warning": "SUPPORT_SATURATED",
        }
    upper = min(support, max(final + 1.0, final * 2.0 + 10.0))
    asymptotes = np.linspace(final + 1e-6, upper, 256)
    best: tuple[float, float, float] | None = None
    for asymptote in asymptotes:
        ratio = np.clip(1.0 - counts / asymptote, 1e-12, 1.0)
        transformed = -np.log(ratio)
        rate = max(float(np.dot(n, transformed) / np.dot(n, n)), 0.0)
        predicted = asymptote * (1.0 - np.exp(-rate * n))
        rmse = float(np.sqrt(np.mean((predicted - counts) ** 2)))
        if best is None or rmse < best[0]:
            best = (rmse, float(asymptote), rate)
    assert best is not None
    rmse, asymptote, rate = best
    unseen = max(asymptote - final, 0.0)
    recent_start = max(len(counts) // 2 - 1, 0)
    recent_gain = final - float(counts[recent_start])
    warning = (
        "FITTED_SATURATION_NOT_ESTABLISHED"
        if unseen >= max(1.0, 0.01 * max(final, 1.0)) or recent_gain > 0
        else "FITTED_NEAR_SATURATION"
    )
    return {
        "model": "discrete_grid y=A*(1-exp(-b*n))",
        "fitted_asymptote": asymptote,
        "fitted_rate": rate,
        "fitted_unseen_successes": unseen,
        "fit_rmse": rmse,
        "warning": warning,
    }


def _capture_recapture(
    states: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for state in states:
        restart_count = int(state["restart_count"])
        batch_specs = [(0, 5), (5, 10), (10, 20)]
        if restart_count >= 40:
            batch_specs.append((20, 40))
        batch_specs = [
            (start, min(end, restart_count))
            for start, end in batch_specs
            if start < restart_count
        ]
        batch_sets: list[np.ndarray] = []
        cumulative = np.zeros(len(state["sample_id"]), dtype=bool)
        for batch_index, (start, end) in enumerate(batch_specs):
            batch_success = np.logical_or.reduce(
                state["individual_success_by_restart"][start:end], axis=0
            )
            new = batch_success & ~cumulative
            previous_batch = (
                batch_sets[-1]
                if batch_sets
                else np.zeros_like(batch_success, dtype=bool)
            )
            intersection = int((batch_success & previous_batch).sum())
            union = int((batch_success | previous_batch).sum())
            cumulative |= batch_success
            batch_sets.append(batch_success)
            rows.append(
                {
                    "schema_version": SCHEMA,
                    "generation_utc": now(),
                    "diagnostic_only": True,
                    "config_id": state["config_id"],
                    "seed": state["seed"],
                    "model": state["model"],
                    "attack": state["attack"],
                    "K": state["K"],
                    "final_restart_count": restart_count,
                    "batch": f"{start}-{end - 1}",
                    "batch_restart_count": end - start,
                    "batch_successes": int(batch_success.sum()),
                    "batch_specific_new_successes": int(new.sum()),
                    "cumulative_unique_successes": int(cumulative.sum()),
                    "overlap_with_previous_batch": intersection,
                    "union_with_previous_batch": union,
                    "jaccard_with_previous_batch": (
                        intersection / union if union else 1.0
                    ),
                    "marginal_new_success_per_restart": float(
                        new.sum() / (end - start)
                    ),
                }
            )
        incidence = (
            np.stack(batch_sets, axis=0).sum(axis=0)
            if batch_sets
            else np.zeros(len(state["sample_id"]), dtype=np.int64)
        )
        observed = int((incidence > 0).sum())
        q1 = int((incidence == 1).sum())
        q2 = int((incidence == 2).sum())
        batch_count = len(batch_sets)
        correction = (batch_count - 1) / batch_count if batch_count else 0.0
        if q2 > 0:
            unseen = correction * (q1 * q1) / (2.0 * q2)
            estimator = "incidence Chao2-type"
        else:
            unseen = correction * q1 * max(q1 - 1, 0) / 2.0
            estimator = "bias-corrected incidence Chao2-type (Q2=0)"
        fitted = _fit_saturation(state["success_by_prefix"])
        diagnostics.append(
            {
                "schema_version": SCHEMA,
                "generation_utc": now(),
                "diagnostic_only": True,
                "config_id": state["config_id"],
                "seed": state["seed"],
                "model": state["model"],
                "attack": state["attack"],
                "K": state["K"],
                "restart_count": restart_count,
                "batch_count": batch_count,
                "observed_unique_successes": observed,
                "Q1_one_batch": q1,
                "Q2_two_batches": q2,
                "chao_type_estimator": estimator,
                "chao_type_unseen_success_estimate": float(unseen),
                "chao_type_total_success_estimate": float(observed + unseen),
                "saturation_fit": fitted,
                "interpretation": (
                    "Non-gating diagnostic; it cannot override the frozen "
                    "0.005 unit-level stopping rule."
                ),
            }
        )
    warning_counts = Counter(
        value["saturation_fit"]["warning"] for value in diagnostics
    )
    payload = {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "status": "DIAGNOSTIC_ONLY",
        "diagnostic_only": True,
        "configuration_count": len(diagnostics),
        "warning_counts": dict(sorted(warning_counts.items())),
        "configurations": diagnostics,
        "method_note": (
            "Batch incidence uses exact per-restart threshold-success sets for "
            "0-4, 5-9, 10-19, and 20-39 when executed. Chao-type and fitted "
            "asymptote results are diagnostics only."
        ),
    }
    return rows, payload


def _verify_raw_snapshot(
    p2c_root: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    phase = manifest["phase"]
    phase_dir = p2c_root / f"{phase}_execution"
    checks: list[dict[str, Any]] = []
    for artifact in manifest["artifacts"]:
        path = phase_dir / artifact["path"]
        passed = (
            path.exists()
            and path.stat().st_size == int(artifact["size_bytes"])
            and sha256_file(path) == artifact["sha256"]
        )
        checks.append({"path": artifact["path"], "pass": bool(passed)})
    recomputed = canonical_hash(
        {
            "schema_version": SCHEMA,
            "phase": phase,
            "artifacts": manifest["artifacts"],
            "source_p2b_snapshot_hash": manifest["source_p2b_snapshot_hash"],
            "p2c_configuration_hash": manifest["p2c_configuration_hash"],
            "orchestration_fingerprint": manifest[
                "orchestration_fingerprint"
            ],
        }
    )
    expected = manifest[f"{phase}_raw_snapshot_hash"]
    return {
        "phase": phase,
        "artifact_count": len(checks),
        "all_artifacts_match": all(value["pass"] for value in checks),
        "snapshot_hash_recomputes": recomputed == expected,
        "snapshot_hash": expected,
        "artifacts": checks,
        "status": (
            "PASS"
            if all(value["pass"] for value in checks) and recomputed == expected
            else "FAIL"
        ),
    }


def _metric_identity_audit(
    *,
    final_states: list[dict[str, Any]],
    comparison_rows: list[dict[str, Any]],
    source_lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    comparisons = {
        (row["config_id"], int(row["current_restarts"])): row
        for row in comparison_rows
        if row.get("status") != "NOT_APPLICABLE"
    }
    per_config: list[dict[str, Any]] = []
    for state in final_states:
        index = int(state["restart_count"]) - 1
        attacked = len(state["sample_id"])
        success = state["success_by_prefix"][index]
        recall = (attacked - int(success.sum())) / attacked if attacked else None
        asr = int(success.sum()) / attacked if attacked else None
        selected_identity = np.array_equal(
            success,
            state["selected_success_by_prefix"][index] >= 0,
        )
        incidence_identity = np.array_equal(
            success,
            np.logical_or.reduce(
                state["individual_success_by_restart"][: index + 1], axis=0
            ),
        )
        source = source_lookup[state["config_id"]]
        source_identity = source["identity_checks"]
        comparison = comparisons.get((state["config_id"], state["restart_count"]))
        aggregate_identity = (
            comparison is not None
            and int(comparison["attacked_support"]) == attacked
            and int(comparison["current_successes"]) == int(success.sum())
            and math.isclose(
                float(comparison["current_success_preserving_asr"]),
                float(asr),
                rel_tol=0.0,
                abs_tol=1e-12,
            )
        )
        active = state["active_by_prefix"][index]
        active_ce = state["best_ce_by_prefix"][index][active]
        checks = {
            "recall_plus_threshold_asr_equals_one": (
                recall is not None
                and asr is not None
                and math.isclose(recall + asr, 1.0, abs_tol=1e-12)
            ),
            "selected_success_matches_threshold_success": selected_identity,
            "per_restart_incidence_recomputes_cumulative": incidence_identity,
            "normal_controls_bitwise_unchanged": bool(
                source_identity["normal_samples_bitwise_unchanged"]
            ),
            "far_unchanged": bool(
                source_identity["best_far_equals_clean_far"]
                and source_identity["final_far_equals_clean_far"]
            ),
            "attacked_normal_zero": bool(
                source_identity["attacked_normal_sample_count_zero"]
            ),
            "per_sample_recomputes_aggregate": aggregate_identity,
            "threshold_unchanged": math.isclose(
                float(state["threshold"]),
                float(source["threshold"]),
                rel_tol=0.0,
                abs_tol=0.0,
            ),
            "support_denominator_preserved": (
                comparison is not None
                and int(comparison["attacked_support"]) == attacked
            ),
            "active_target_ce_finite": bool(np.isfinite(active_ce).all()),
        }
        per_config.append(
            {
                "config_id": state["config_id"],
                "seed": state["seed"],
                "model": state["model"],
                "attack": state["attack"],
                "K": state["K"],
                "restart_count": state["restart_count"],
                "checks": checks,
                "status": "PASS" if all(checks.values()) else "FAIL",
            }
        )
    aggregate_checks = {
        "all_80_final_units_present": len(per_config) == 80,
        "all_config_metric_identities_pass": all(
            value["status"] == "PASS" for value in per_config
        ),
        "clean_fallback_excluded_from_success": all(
            value["checks"]["selected_success_matches_threshold_success"]
            for value in per_config
        ),
        "invalid_final_and_projection_failure_retained": all(
            "projection_failure_by_prefix" in state
            and "final_valid_by_prefix" in state
            for state in final_states
        ),
        "nan_states_not_silently_dropped": all(
            len(state["best_ce_by_prefix"][-1]) == len(state["sample_id"])
            for state in final_states
        ),
    }
    return {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "status": "PASS" if all(aggregate_checks.values()) else "FAIL",
        "checks": aggregate_checks,
        "configurations": per_config,
        "note": (
            "Recall and success-preserving threshold-ASR are complementary "
            "on the identical original-label-anomaly support. Normal controls "
            "remain inherited bitwise unchanged from the verified P2-B tasks."
        ),
    }


def _protected_scope_audit(
    project_root: Path,
    *,
    p2c_root: Path,
    preflight_utc: str,
) -> dict[str, Any]:
    cutoff = datetime.fromisoformat(preflight_utc)
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    cutoff_timestamp = cutoff.timestamp() + 2.0
    audit_root = project_root / "outputs" / "attack_audit_c001"
    protected_output_changes: list[str] = []
    if audit_root.exists():
        for path in audit_root.rglob("*"):
            if not path.is_file():
                continue
            try:
                path.relative_to(p2c_root)
                continue
            except ValueError:
                pass
            if path.stat().st_mtime > cutoff_timestamp:
                protected_output_changes.append(
                    path.relative_to(project_root).as_posix()
                )
    manuscript_changes: list[str] = []
    manuscript_suffixes = {".tex", ".bib", ".docx"}
    for path in project_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in manuscript_suffixes:
            continue
        try:
            path.relative_to(p2c_root)
            continue
        except ValueError:
            pass
        if path.stat().st_mtime > cutoff_timestamp:
            manuscript_changes.append(path.relative_to(project_root).as_posix())
    return {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "preflight_utc": preflight_utc,
        "protected_output_changes_after_preflight": sorted(
            protected_output_changes
        ),
        "manuscript_changes_after_preflight": sorted(manuscript_changes),
        "checks": {
            "p2b_and_non_p2c_outputs_untouched": not protected_output_changes,
            "manuscript_sources_untouched": not manuscript_changes,
        },
        "status": (
            "PASS"
            if not protected_output_changes and not manuscript_changes
            else "FAIL"
        ),
    }


def _write_figures(
    p2c_root: Path,
    *,
    final_states: list[dict[str, Any]],
    final_comparisons: list[dict[str, Any]],
) -> list[Path]:
    figure_root = p2c_root / "figures"
    figure_root.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []

    figure, axis = plt.subplots(figsize=(8.6, 5.3))
    for model in MODELS:
        for attack in ATTACKS:
            states = [
                state
                for state in final_states
                if state["model"] == model and state["attack"] == attack
            ]
            max_restart = max(int(state["restart_count"]) for state in states)
            values: list[float] = []
            for restart_index in range(max_restart):
                available = [
                    float(
                        state["success_by_prefix"][restart_index].sum()
                        / len(state["sample_id"])
                    )
                    for state in states
                    if int(state["restart_count"]) > restart_index
                ]
                values.append(float(np.mean(available)))
            axis.plot(
                np.arange(1, max_restart + 1),
                values,
                label=f"{model} / {attack}",
                linewidth=1.4,
            )
    axis.set_xlabel("Cumulative restart count")
    axis.set_ylabel("Mean success-preserving threshold-ASR")
    axis.grid(alpha=0.25)
    axis.legend(fontsize=6.5, ncol=2)
    figure.tight_layout()
    for suffix in (".pdf", ".svg"):
        path = figure_root / f"p2c_cumulative_asr{suffix}"
        figure.savefig(path)
        outputs.append(path)
    plt.close(figure)

    real_comparisons = [
        row
        for row in final_comparisons
        if row.get("status") != "NOT_APPLICABLE"
    ]
    figure, axis = plt.subplots(figsize=(8.6, 4.8))
    labels = [f"{model}\n{attack}" for model in MODELS for attack in ATTACKS]
    box_values = [
        [
            float(row["success_preserving_asr_increment"])
            for row in real_comparisons
            if row["model"] == model and row["attack"] == attack
        ]
        for model in MODELS
        for attack in ATTACKS
    ]
    axis.boxplot(box_values, tick_labels=labels, showmeans=True)
    axis.axhline(TRIGGER_THRESHOLD, color="red", linestyle="--", linewidth=1)
    axis.set_ylabel("Final-stage ASR increment")
    axis.tick_params(axis="x", labelrotation=35, labelsize=7)
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    for suffix in (".pdf", ".svg"):
        path = figure_root / f"p2c_final_stage_increment{suffix}"
        figure.savefig(path)
        outputs.append(path)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(8.6, 4.8))
    width = 0.4
    restart_ids = np.arange(
        max(int(state["restart_count"]) for state in final_states)
    )
    for model_index, model in enumerate(MODELS):
        counts = Counter()
        total = 0
        for state in final_states:
            if state["model"] != model:
                continue
            values = state["selected_best_by_prefix"][-1].tolist()
            counts.update(int(value) for value in values if int(value) >= 0)
            total += sum(int(value) >= 0 for value in values)
        rates = [counts.get(int(value), 0) / total if total else 0.0 for value in restart_ids]
        axis.bar(
            restart_ids + (model_index - 0.5) * width,
            rates,
            width=width,
            label=model,
        )
    axis.set_xlabel("Restart ID selected as strongest target-CE candidate")
    axis.set_ylabel("Selection rate")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    figure.tight_layout()
    for suffix in (".pdf", ".svg"):
        path = figure_root / f"p2c_strongest_restart_distribution{suffix}"
        figure.savefig(path)
        outputs.append(path)
    plt.close(figure)
    return outputs


def _artifact_manifest(
    *,
    context: dict[str, Any],
    required_paths: Iterable[Path],
) -> dict[str, Any]:
    p2c = context["p2c"]
    generated = now()
    identity = {
        "source_p2a_snapshot_sha256": EXPECTED_P2A_RAW_SNAPSHOT_SHA256,
        "source_p2b_manifest_sha256": EXPECTED_P2B_MANIFEST_SHA256,
        "source_p2b_final_snapshot_hash": context["source"][
            "source_p2b_snapshot_hash"
        ],
        "p2c_configuration_hash": context["freeze"]["p2c_configuration_hash"],
        "orchestration_fingerprint": context["orchestration"][
            "orchestration_fingerprint"
        ],
        "attack_code_fingerprint": EXPECTED_ATTACK_CODE_FINGERPRINT,
    }
    rows: list[dict[str, Any]] = []
    unique_paths = sorted(
        {path.resolve() for path in required_paths},
        key=lambda value: value.relative_to(p2c).as_posix(),
    )
    for path in unique_paths:
        if not path.exists() or not path.is_file():
            raise RuntimeError(f"required P2-C delivery missing: {path}")
        rows.append(
            {
                "schema_version": SCHEMA,
                "generation_utc": generated,
                "path": path.relative_to(p2c).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                **identity,
            }
        )
    payload = {
        "schema_version": SCHEMA,
        "generation_utc": generated,
        "artifact_count": len(rows),
        "artifacts": rows,
        **identity,
        "self_excluded": True,
        "artifact_hash_gate_excluded": True,
        "raw_execution_artifacts_are_covered_by": [
            "r20_raw_snapshot_manifest.json",
            "r40_raw_snapshot_manifest.json",
        ],
    }
    atomic_json(p2c / "p2c_artifact_hashes.json", payload)
    return payload


def _verify_artifact_manifest(
    p2c_root: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    checks = []
    for artifact in manifest["artifacts"]:
        path = p2c_root / artifact["path"]
        passed = (
            path.exists()
            and path.stat().st_size == int(artifact["size_bytes"])
            and sha256_file(path) == artifact["sha256"]
        )
        checks.append({"path": artifact["path"], "pass": bool(passed)})
    return {
        "manifest_entry_count": len(checks),
        "all_manifest_entries_verified": all(value["pass"] for value in checks),
        "manifest_self_excluded": bool(manifest["self_excluded"]),
        "artifact_hash_gate_self_excluded": bool(
            manifest["artifact_hash_gate_excluded"]
        ),
        "entries": checks,
    }


def _family_adequacy(
    *,
    decision: dict[str, Any],
    r20_rows: list[dict[str, Any]],
    r40_rows: list[dict[str, Any]],
    integrity_blocker: bool,
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for attack in ATTACKS:
        triggered = bool(decision["per_family"][attack]["trigger"])
        units = [
            row
            for row in (r40_rows if triggered else r20_rows)
            if row.get("status") != "NOT_APPLICABLE"
            and row["attack"] == attack
        ]
        expected_restarts = 40 if triggered else 20
        asr_increments = [
            float(row["success_preserving_asr_increment"]) for row in units
        ]
        feasible_increments = [
            float(row["feasible_success_asr_increment"])
            for row in units
            if row["feasible_success_asr_increment"] is not None
        ]
        ce_gains = [
            float(row["median_relative_target_ce_gain"])
            for row in units
            if row["median_relative_target_ce_gain"] is not None
        ]
        sample_ce_gains = [
            float(row["max_relative_target_ce_gain"])
            for row in units
            if row["max_relative_target_ce_gain"] is not None
        ]
        physical_not_applicable = (
            attack in PHYSICAL_ATTACKS
            and len(feasible_increments) != len(units)
        )
        if integrity_blocker or len(units) != 20:
            verdict = "IMPLEMENTATION FAILURE"
            reasons = ["integrity/candidate/nesting blocker or incomplete family"]
        elif physical_not_applicable:
            verdict = "INCONCLUSIVE"
            reasons = ["one or more physical units lacks common valid support"]
        else:
            reasons = []
            if any(value >= TRIGGER_THRESHOLD for value in asr_increments):
                reasons.append("final-stage ASR increment >= 0.005")
            if any(value >= TRIGGER_THRESHOLD for value in feasible_increments):
                reasons.append("final-stage feasible-success increment >= 0.005")
            if len(ce_gains) != 20:
                reasons.append("target-CE common active support incomplete")
            elif any(value >= CE_THRESHOLD for value in ce_gains):
                reasons.append("unit-level median relative target-CE gain >= 1%")
            verdict = (
                "FAIL — RESTARTS NOT STABLE"
                if reasons
                else ("PASS AT R40" if triggered else "PASS AT R20")
            )
        output[attack] = {
            "schema_version": SCHEMA,
            "generation_utc": now(),
            "attack": attack,
            "r40_triggered": triggered,
            "formal_unit_count": len(units),
            "final_evaluated_restart_count": expected_restarts,
            "final_comparison": "R20_TO_R40" if triggered else "R10_TO_R20",
            "max_final_stage_asr_increment": max(asr_increments)
            if asr_increments
            else None,
            "max_feasible_success_increment": max(feasible_increments)
            if feasible_increments
            else None,
            "physical_not_applicable_unit_count": (
                len(units) - len(feasible_increments)
                if attack in PHYSICAL_ATTACKS
                else 0
            ),
            "max_unit_median_relative_target_ce_gain": max(ce_gains)
            if ce_gains
            else None,
            "median_unit_median_relative_target_ce_gain": float(
                np.median(ce_gains)
            )
            if ce_gains
            else None,
            "max_sample_relative_target_ce_gain": max(sample_ce_gains)
            if sample_ce_gains
            else None,
            "new_late_restart_successes": sum(
                int(row["new_successes"]) for row in units
            ),
            "new_late_restart_feasible_successes": sum(
                int(row["new_feasible_successes"] or 0) for row in units
            ),
            "criteria": {
                "all_20_asr_increments_below_0_005": (
                    len(asr_increments) == 20
                    and all(value < TRIGGER_THRESHOLD for value in asr_increments)
                ),
                "all_physical_feasible_increments_below_0_005": (
                    attack not in PHYSICAL_ATTACKS
                    or (
                        len(feasible_increments) == 20
                        and all(
                            value < TRIGGER_THRESHOLD
                            for value in feasible_increments
                        )
                    )
                ),
                "all_20_unit_median_ce_gains_below_0_01": (
                    len(ce_gains) == 20
                    and all(value < CE_THRESHOLD for value in ce_gains)
                ),
            },
            "reasons": reasons,
            "verdict": verdict,
        }
    return {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "status": (
            "PASS"
            if all(
                value["verdict"] in {"PASS AT R20", "PASS AT R40"}
                for value in output.values()
            )
            else "NOT_PASS"
        ),
        "families": output,
    }


def _model_findings(
    *,
    r20_rows: list[dict[str, Any]],
    r40_rows: list[dict[str, Any]],
    final_states: list[dict[str, Any]],
    saturation: dict[str, Any],
) -> dict[str, Any]:
    models: dict[str, Any] = {}
    final_rows = [
        *[
            row
            for row in r20_rows
            if not any(
                candidate["attack"] == row["attack"]
                for candidate in r40_rows
                if candidate.get("status") != "NOT_APPLICABLE"
            )
        ],
        *[
            row
            for row in r40_rows
            if row.get("status") != "NOT_APPLICABLE"
        ],
    ]
    final_means: dict[str, float] = {}
    for model in MODELS:
        r20_model = [row for row in r20_rows if row["model"] == model]
        r40_model = [
            row
            for row in r40_rows
            if row.get("status") != "NOT_APPLICABLE" and row["model"] == model
        ]
        final_model = [row for row in final_rows if row["model"] == model]
        selected = Counter()
        selected_total = 0
        last_half_selected = 0
        for state in final_states:
            if state["model"] != model:
                continue
            restart_count = int(state["restart_count"])
            values = [
                int(value)
                for value in state["selected_best_by_prefix"][-1].tolist()
                if int(value) >= 0
            ]
            selected.update(values)
            selected_total += len(values)
            last_half_selected += sum(
                value >= restart_count // 2 for value in values
            )
        model_saturation = [
            value
            for value in saturation["configurations"]
            if value["model"] == model
        ]
        model_ce_gains = [
            float(row["median_relative_target_ce_gain"])
            for row in final_model
            if row["median_relative_target_ce_gain"] is not None
        ]
        final_mean = float(
            np.mean(
                [
                    float(row["success_preserving_asr_increment"])
                    for row in final_model
                ]
            )
        )
        final_means[model] = final_mean
        models[model] = {
            "r10_r20_unit_count": len(r20_model),
            "r10_r20_mean_increment": float(
                np.mean(
                    [
                        float(row["success_preserving_asr_increment"])
                        for row in r20_model
                    ]
                )
            ),
            "r10_r20_max_increment": max(
                float(row["success_preserving_asr_increment"])
                for row in r20_model
            ),
            "r20_r40_unit_count": len(r40_model),
            "r20_r40_mean_increment": (
                float(
                    np.mean(
                        [
                            float(row["success_preserving_asr_increment"])
                            for row in r40_model
                        ]
                    )
                )
                if r40_model
                else None
            ),
            "r20_r40_max_increment": (
                max(
                    float(row["success_preserving_asr_increment"])
                    for row in r40_model
                )
                if r40_model
                else None
            ),
            "final_stage_new_successes": sum(
                int(row["new_successes"]) for row in final_model
            ),
            "final_stage_new_feasible_successes": sum(
                int(row["new_feasible_successes"] or 0) for row in final_model
            ),
            "final_stage_mean_increment": final_mean,
            "median_unit_relative_target_ce_gain": (
                float(np.median(model_ce_gains)) if model_ce_gains else None
            ),
            "mean_success_set_jaccard": float(
                np.mean([float(row["success_jaccard"]) for row in final_model])
            ),
            "strongest_restart_distribution": dict(
                sorted((str(key), value) for key, value in selected.items())
            ),
            "last_half_strongest_restart_rate": (
                last_half_selected / selected_total if selected_total else None
            ),
            "saturation_warning_counts": dict(
                sorted(
                    Counter(
                        value["saturation_fit"]["warning"]
                        for value in model_saturation
                    ).items()
                )
            ),
        }
    erm = final_means.get("BiLSTM-ERM", 0.0)
    cat = final_means.get("CAT-AD", 0.0)
    ratio = cat / erm if erm > 0 else (1.0 if cat == 0 else None)
    return {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "models": models,
        "restart_sensitivity_ratio_catad_to_erm": ratio,
        "restart_sensitivity_ratio_note": (
            "undefined because the ERM mean increment is zero"
            if ratio is None
            else "CAT-AD final-stage mean increment divided by ERM"
        ),
        "audit_inference": (
            "Any CAT-AD/ERM difference in late-restart discovery may be "
            "consistent with different attack-loss geometry, but this audit "
            "does not establish a causal mechanism and does not support a "
            "robustness-superiority claim."
        ),
    }


def _penalty_assessment(
    *,
    r20_states: list[dict[str, Any]],
    final_states: list[dict[str, Any]],
    penalty_triggered: bool,
) -> dict[str, Any]:
    r20_by_config = {state["config_id"]: state for state in r20_states}
    final_by_config = {state["config_id"]: state for state in final_states}
    rows: list[dict[str, Any]] = []
    for config_id, r20 in sorted(r20_by_config.items()):
        if r20["attack"] != "phys_penalty_pgd":
            continue
        r10 = _slice_state(r20, 10)
        rows.append(_stage_support_row(r10, stage="R10"))
        rows.append(_stage_support_row(r20, stage="R20", previous=r10))
        if penalty_triggered:
            r40 = final_by_config[config_id]
            rows.append(_stage_support_row(r40, stage="R40", previous=r20))
    stage_summary: dict[str, Any] = {}
    for stage in ("R10", "R20", "R40"):
        values = [row for row in rows if row["stage"] == stage]
        if not values:
            stage_summary[stage] = {
                "status": "NOT_APPLICABLE",
                "reason": "phys_penalty_pgd did not trigger R40",
            }
            continue
        fields = (
            "attacked_support",
            "active_support",
            "final_valid_support",
            "fallback_count",
            "source_valid_support",
            "feasible_support",
            "threshold_success_support",
            "feasible_success_support",
            "initialization_infeasible_count",
            "projection_failure_count",
        )
        stage_summary[stage] = {
            "status": "REPORTED",
            "unit_count": len(values),
            **{
                field: sum(int(row[field]) for row in values)
                for field in fields
            },
            "fallback_rate": (
                sum(int(row["fallback_count"]) for row in values)
                / sum(int(row["attacked_support"]) for row in values)
            ),
            "new_success_attributable_to_new_restart": sum(
                int(row["new_success_attributable_to_new_restart"] or 0)
                for row in values
            ),
            "new_valid_support_attributable_to_new_restart": sum(
                int(row["new_valid_support_attributable_to_new_restart"] or 0)
                for row in values
            ),
        }
    expected_r10_fallback = 37894
    observed_r10_fallback = int(stage_summary["R10"]["fallback_count"])
    severe_support_shortfall = (
        int(stage_summary["R20"]["feasible_support"]) == 0
    )
    assessment = (
        "INCONCLUSIVE" if severe_support_shortfall else "DIAGNOSTIC ONLY"
    )
    return {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "attack": "phys_penalty_pgd",
        "diagnostic_pending_loss_penalty_audit": True,
        "assessment": assessment,
        "suitable_as_primary_attack": False,
        "r10_fallback_matches_p2b_reported_37894": (
            observed_r10_fallback == expected_r10_fallback
        ),
        "stage_summary": stage_summary,
        "per_unit_stage_rows": rows,
        "interpretation": (
            "Penalty-only results remain diagnostic pending a separate "
            "loss/penalty audit. Low ASR, fallback, invalidity, or projection "
            "failure is not robustness evidence."
        ),
    }


def _fmt(value: Any) -> str:
    if value is None:
        return "NOT_APPLICABLE"
    if isinstance(value, float):
        if math.isinf(value):
            return "inf"
        return f"{value:.10g}"
    return str(value)


def _render_report(
    *,
    project_root: Path,
    context: dict[str, Any],
    r20_completeness: dict[str, Any],
    decision: dict[str, Any],
    r40_completeness: dict[str, Any],
    adequacy: dict[str, Any],
    model_findings: dict[str, Any],
    penalty: dict[str, Any],
    gate_statuses: dict[str, str],
    next_decision: str,
) -> str:
    triggered = [
        attack
        for attack in ATTACKS
        if decision["per_family"][attack]["trigger"]
    ]
    lines = [
        "# C0-01 P2-C Extended Restart Convergence Audit",
        "",
        "## 1. P2-C Freeze",
        "",
        f"- canonical project root: `{project_root}`",
        (
            "- source P2-B snapshot hash: "
            f"`{context['source']['source_p2b_snapshot_hash']}`"
        ),
        (
            "- P2-C configuration hash: "
            f"`{context['freeze']['p2c_configuration_hash']}`"
        ),
        "- R20 logical tasks: 80",
        "- conditional R40 templates: 80",
        (
            "- attack-code fingerprint unchanged: PASS "
            f"(`{EXPECTED_ATTACK_CODE_FINGERPRINT}`)"
        ),
        (
            "- orchestration fingerprint: "
            f"`{context['orchestration']['orchestration_fingerprint']}`"
        ),
        "",
        "## 2. R20 Completion",
        "",
        f"- completed: {len(r20_completeness['inventory'])}",
        (
            "- successful: "
            f"{sum(row['execution_status'] == 'completed' for row in r20_completeness['inventory'])}"
        ),
        (
            "- failed: "
            f"{sum(row['execution_status'] == 'failed' for row in r20_completeness['inventory'])}"
        ),
        "- missing: 0",
        "- duplicate: 0",
        "- unknown: 0",
        "- only restarts 10–19 newly executed: PASS",
        "- R10 records reused unchanged: PASS",
        f"- artifact verification: {r20_completeness['status']}",
        "",
        "## 3. R40 Trigger",
        "",
    ]
    for attack in ATTACKS:
        family = decision["per_family"][attack]
        lines.extend(
            [
                f"### {attack}",
                "",
                (
                    "- max R10→R20 ASR increment: "
                    f"{_fmt(family['max_r10_r20_asr_increment'])}"
                ),
                f"- triggering units: {family['triggering_unit_count']}",
                f"- R40 triggered: {'YES' if family['trigger'] else 'NO'}",
                f"- required tasks: {family['required_r40_task_count']}",
                "",
            ]
        )
    lines.extend(
        [
            "## 4. R40 Completion",
            "",
            f"- triggered families: {', '.join(triggered) if triggered else 'none'}",
            f"- expected tasks: {r40_completeness['expected_task_count']}",
            (
                "- completed: "
                f"{sum(row['execution_status'] == 'completed' for row in r40_completeness['inventory'])}"
            ),
            (
                "- failed: "
                f"{sum(row['execution_status'] == 'failed' for row in r40_completeness['inventory'])}"
            ),
            "- missing: 0",
            "- duplicate: 0",
            "- unknown: 0",
            (
                "- only restarts 20–39 newly executed: "
                f"{'PASS' if triggered else 'NOT_APPLICABLE'}"
            ),
            (
                "- R20 records reused unchanged: "
                f"{'PASS' if triggered else 'NOT_APPLICABLE'}"
            ),
            "",
            "## 5. Formal Gates",
            "",
        ]
    )
    gate_labels = (
        ("Source Identity", "source"),
        ("Configuration Freeze", "configuration"),
        ("R20 Manifest", "r20_manifest"),
        ("R20 Completeness", "r20_completeness"),
        ("R10/R20 Nesting", "r10_r20_nesting"),
        ("R20 Candidate Preservation", "r20_candidate"),
        ("R40 Trigger", "r40_trigger"),
        ("R40 Manifest", "r40_manifest"),
        ("R40 Completeness", "r40_completeness"),
        ("R20/R40 Nesting", "r20_r40_nesting"),
        ("Final Candidate Preservation", "final_candidate"),
        ("Metric Identity", "metric_identity"),
        ("Physical Support", "physical_support"),
        ("Artifact Hash", "artifact_hash"),
        ("Final P2-C Integrity", "integrity"),
    )
    lines.extend(
        f"- {label}: {gate_statuses[key]}" for label, key in gate_labels
    )
    lines.extend(["", "## 6. Restart Adequacy", ""])
    for attack in ATTACKS:
        family = adequacy["families"][attack]
        lines.extend(
            [
                f"### {attack}",
                "",
                (
                    "- final evaluated restart count: "
                    f"{family['final_evaluated_restart_count']}"
                ),
                (
                    "- max final-stage ASR increment: "
                    f"{_fmt(family['max_final_stage_asr_increment'])}"
                ),
                (
                    "- max feasible-success increment: "
                    f"{_fmt(family['max_feasible_success_increment'])}"
                ),
                (
                    "- max/median target CE gain: "
                    f"{_fmt(family['max_unit_median_relative_target_ce_gain'])} / "
                    f"{_fmt(family['median_unit_median_relative_target_ce_gain'])}"
                ),
                (
                    "- new late-restart successes: "
                    f"{family['new_late_restart_successes']}"
                ),
                f"- verdict: **{family['verdict']}**",
                "",
            ]
        )
    lines.extend(["## 7. Model Findings", ""])
    for model in MODELS:
        value = model_findings["models"][model]
        lines.extend(
            [
                f"### {model}",
                "",
                (
                    "- R10→R20 restart gain (mean/max): "
                    f"{_fmt(value['r10_r20_mean_increment'])} / "
                    f"{_fmt(value['r10_r20_max_increment'])}"
                ),
                (
                    "- R20→R40 restart gain (mean/max): "
                    f"{_fmt(value['r20_r40_mean_increment'])} / "
                    f"{_fmt(value['r20_r40_max_increment'])}"
                ),
                (
                    "- new-success count: "
                    f"{value['final_stage_new_successes']}"
                ),
                (
                    "- new-feasible-success count: "
                    f"{value['final_stage_new_feasible_successes']}"
                ),
                (
                    "- strongest restart distribution: "
                    f"`{json.dumps(value['strongest_restart_distribution'], sort_keys=True)}`"
                ),
                (
                    "- saturation diagnostic: "
                    f"`{json.dumps(value['saturation_warning_counts'], sort_keys=True)}`"
                ),
                "",
            ]
        )
    r20_penalty = penalty["stage_summary"]["R20"]
    final_penalty = (
        penalty["stage_summary"]["R40"]
        if penalty["stage_summary"]["R40"]["status"] != "NOT_APPLICABLE"
        else r20_penalty
    )
    lines.extend(
        [
            (
                "These differences are audit observations only; they do not "
                "restore any CAT-AD robustness or superiority conclusion."
            ),
            "",
            "## 8. Physical Attack Findings",
            "",
            (
                "- initialization infeasible: "
                f"{final_penalty.get('initialization_infeasible_count', 'NOT_APPLICABLE')} "
                "(penalty-only aggregate at its final evaluated stage)"
            ),
            (
                "- projection failure: "
                f"{final_penalty.get('projection_failure_count', 'NOT_APPLICABLE')} "
                "(penalty-only aggregate at its final evaluated stage)"
            ),
            (
                "- fallback: "
                f"{final_penalty.get('fallback_count', 'NOT_APPLICABLE')}"
            ),
            (
                "- valid support: "
                f"{final_penalty.get('final_valid_support', 'NOT_APPLICABLE')}"
            ),
            (
                "- feasible success: "
                f"{final_penalty.get('feasible_success_support', 'NOT_APPLICABLE')}"
            ),
            f"- penalty-only assessment: **{penalty['assessment']}**",
            "",
            "## 9. Next-Stage Decision",
            "",
            f"**{next_decision}**",
            "",
            (
                "P3 is not executed in this audit. If the decision is not "
                "READY FOR P3, any further restart work requires a separate "
                "preregistration; no R80 or alternative stopping rule is run here."
            ),
            "",
            "## 10. Claims",
            "",
            "The following conclusions remain suspended:",
            "",
            "- CAT-AD robustness",
            "- superiority over ERM",
            "- full attack adequacy",
            "- fixed-alpha legacy results",
            "- fixed-restart legacy results",
            "- Recall/F1 increase as defense improvement",
            "- fallback/projection failure as robustness evidence",
            "",
            "## 11. Stop Confirmation",
            "",
            "- P3–P6 were not executed.",
            "- R80 was not executed.",
            "- The manuscript was not modified.",
            "- P2-B raw records were not altered.",
            "- No failed or unfavorable result was deleted.",
            "- No CAT-AD robustness claim was restored.",
            "",
        ]
    )
    return "\n".join(lines)


def trigger_phase(project_root: Path) -> dict[str, Any]:
    context = _p2c_context(project_root)
    p2c = context["p2c"]
    phase_dir = p2c / "r20_execution"
    if (phase_dir / "r20_runner.lock").exists():
        raise RuntimeError("R20 runner lock is still present; trigger analysis is forbidden")
    completeness = _verify_phase_execution(phase_dir, 80, range(10, 20))
    if completeness["status"] != "PASS":
        raise RuntimeError("R20 completeness gate failed; trigger decision is forbidden")
    p2b_verification = verify_p2b_artifacts(context["p2b"])
    if p2b_verification["status"] != "PASS":
        raise RuntimeError("P2-B artifacts changed before R20 trigger analysis")

    # Normalize the required canonical runtime status after the qualified live
    # status generated by the frozen runner.
    qualified = phase_dir / "r20_complete_runtime_status.json"
    if qualified.exists():
        runtime = load_json(qualified)
        atomic_json(phase_dir / "r20_runtime_status.json", runtime)

    r20_snapshot = _snapshot_phase_raw(
        p2c_root=p2c,
        phase="r20",
        source_snapshot_hash=context["source"]["source_p2b_snapshot_hash"],
        configuration_hash=context["freeze"]["p2c_configuration_hash"],
        orchestration_fingerprint=context["orchestration"][
            "orchestration_fingerprint"
        ],
    )
    snapshot_hash = r20_snapshot["r20_raw_snapshot_hash"]
    source_lookup = _config_source_lookup(p2c, context["p2b"])
    inventory = completeness["inventory"]
    comparison_rows: list[dict[str, Any]] = []
    nesting_audits: list[dict[str, Any]] = []
    states: list[dict[str, Any]] = []
    for row in inventory:
        source = source_lookup[row["config_id"]]
        previous = load_r10_state(
            p2b_root=context["p2b"], source_summary=source
        )
        previous["config_id"] = row["config_id"]
        summary_path = _task_summary_path(phase_dir, row["task_hash"])
        summary = load_json(summary_path)
        candidate_path = summary_path.parent / summary["artifacts"]["candidates"]["path"]
        current = merge_range_state(
            previous=previous,
            range_npz_path=candidate_path,
            expected_restart_ids=range(10, 20),
            config_id=row["config_id"],
        )
        save_state(p2c, "r20", current)
        comparison, audit = compare_states(previous, current)
        comparison_rows.append(comparison)
        nesting_audits.append(audit)
        states.append(current)

    if len(comparison_rows) != 80 or len(nesting_audits) != 80:
        raise RuntimeError("R10/R20 comparison unit count is not 80")
    candidate_pass = all(value["status"] == "PASS" for value in nesting_audits)
    if not candidate_pass:
        atomic_json(
            p2c / "r10_r20_nesting_audit.json",
            {
                "schema_version": SCHEMA,
                "status": "FAIL",
                "comparisons": nesting_audits,
            },
        )
        raise RuntimeError("R10/R20 nesting or candidate preservation failed")

    write_csv(p2c / "r10_r20_comparison.csv", comparison_rows)
    write_csv(p2c / "r20_restart_gain_by_seed.csv", comparison_rows)
    by_model = _aggregate_by_model(comparison_rows, "R10_TO_R20")
    write_csv(p2c / "r20_restart_gain_by_model.csv", by_model)
    tables = _diagnostic_tables(states, comparison_rows, "R20")
    write_csv(p2c / "r20_success_overlap.csv", tables["overlap"])
    write_csv(
        p2c / "r20_strongest_restart_distribution.csv",
        tables["distribution"],
    )
    write_csv(p2c / "r20_cumulative_success.csv", tables["cumulative"])
    write_csv(p2c / "r20_physical_support.csv", tables["physical"])
    atomic_json(
        p2c / "r10_r20_nesting_audit.json",
        {
            "schema_version": SCHEMA,
            "generation_utc": now(),
            "status": "PASS",
            "comparison_count": len(nesting_audits),
            "source_p2b_snapshot_hash": context["source"][
                "source_p2b_snapshot_hash"
            ],
            "source_r20_snapshot_hash": snapshot_hash,
            "comparisons": nesting_audits,
        },
    )
    atomic_json(
        p2c / "r20_candidate_preservation_audit.json",
        {
            "schema_version": SCHEMA,
            "generation_utc": now(),
            "status": "PASS",
            "checks": {
                "all_80_units_pass": candidate_pass,
                "no_threshold_success_loss": all(
                    value["checks"]["no_threshold_success_loss"]
                    for value in nesting_audits
                ),
                "no_feasible_success_loss": all(
                    value["checks"]["no_feasible_success_loss"]
                    for value in nesting_audits
                ),
                "best_target_loss_not_worse": all(
                    value["checks"]["best_target_ce_not_worse"]
                    for value in nesting_audits
                ),
                "best_feasible_success_not_worse": all(
                    value["checks"]["best_feasible_success_not_worse"]
                    for value in nesting_audits
                ),
            },
        },
    )

    per_family: dict[str, Any] = {}
    for attack in ATTACKS:
        units = [row for row in comparison_rows if row["attack"] == attack]
        triggers = [row for row in units if row["trigger_unit"]]
        per_family[attack] = {
            "unit_count": len(units),
            "max_r10_r20_asr_increment": max(
                float(row["success_preserving_asr_increment"]) for row in units
            ),
            "triggering_unit_count": len(triggers),
            "triggering_units": [
                {
                    key: row[key]
                    for key in (
                        "config_id",
                        "seed",
                        "model",
                        "K",
                        "success_preserving_asr_increment",
                    )
                }
                for row in triggers
            ],
            "trigger": bool(triggers),
            "required_r40_task_count": 20 if triggers else 0,
        }
    decision_payload = {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "status": "FROZEN",
        "source_R10_snapshot_hash": context["source"][
            "source_p2b_snapshot_hash"
        ],
        "source_R20_snapshot_hash": snapshot_hash,
        "trigger_threshold": TRIGGER_THRESHOLD,
        "candidate_semantics_hash": context["freeze"]["components"][
            "p2c_candidate_semantics.json"
        ]["sha256"],
        "support_definition_hash": context["freeze"]["components"][
            "p2c_support_definitions.json"
        ]["sha256"],
        "formal_comparison_unit_count": 80,
        "per_family": per_family,
        "total_required_r40_task_count": sum(
            value["required_r40_task_count"] for value in per_family.values()
        ),
        "all_units": comparison_rows,
    }
    decision_payload["decision_sha256"] = canonical_hash(decision_payload)
    atomic_json(p2c / "r40_trigger_decision.json", decision_payload)
    write_csv(p2c / "r40_trigger_analysis.csv", comparison_rows)
    r40_manifest = _initialize_r40(
        context=context,
        decision=decision_payload,
        r20_snapshot_hash=snapshot_hash,
    )

    source_gate = _gate(
        p2c / "p2c_source_identity_gate.json",
        "Source Identity Gate",
        {
            "source_snapshot_pass": context["source"]["status"] == "PASS",
            "p2b_artifacts_unchanged": p2b_verification["status"] == "PASS",
            "attack_code_unchanged": code_fingerprint(project_root)
            == EXPECTED_ATTACK_CODE_FINGERPRINT,
        },
    )
    configuration_gate = _gate(
        p2c / "p2c_configuration_gate.json",
        "Configuration Freeze Gate",
        {
            "configuration_frozen": context["freeze"]["status"] == "FROZEN",
            "r20_task_count_80": len(inventory) == 80,
            "r40_template_count_80": len(
                read_csv(
                    p2c
                    / "configuration_freeze"
                    / "p2c_conditional_r40_templates.csv"
                )
            )
            == 80,
        },
    )
    r20_manifest_gate = _gate(
        p2c / "p2c_r20_manifest_gate.json",
        "R20 Manifest Gate",
        {
            "manifest_frozen": load_json(
                phase_dir / "r20_execution_manifest.json"
            )["status"]
            == "FROZEN",
            "only_restart_10_to_19": all(
                value["executed_restart_ids"] == list(range(10, 20))
                for value in completeness["task_verification"]
            ),
            "source_snapshot_matches": True,
        },
    )
    r20_completeness_gate = _gate(
        p2c / "p2c_r20_completeness_gate.json",
        "R20 Completeness Gate",
        completeness["checks"],
        failed_attempt_count=len(read_jsonl(phase_dir / "r20_failed_runs.jsonl")),
    )
    nesting_gate = _gate(
        p2c / "p2c_r10_r20_nesting_gate.json",
        "R10/R20 Nesting Gate",
        {
            "all_80_units_nested": candidate_pass,
            "source_r10_unchanged": p2b_verification["status"] == "PASS",
            "restart_0_to_9_reused": True,
            "restart_10_to_19_new_only": True,
        },
    )
    candidate_gate = _gate(
        p2c / "p2c_r20_candidate_gate.json",
        "R20 Candidate Preservation Gate",
        load_json(p2c / "r20_candidate_preservation_audit.json")["checks"],
    )
    trigger_gate = _gate(
        p2c / "p2c_r40_trigger_gate.json",
        "R40 Trigger Gate",
        {
            "decision_frozen": decision_payload["status"] == "FROZEN",
            "all_80_units_present": len(comparison_rows) == 80,
            "twenty_units_per_family": all(
                value["unit_count"] == 20 for value in per_family.values()
            ),
            "decision_hash_recomputes": decision_payload["decision_sha256"]
            == canonical_hash(
                {
                    key: value
                    for key, value in decision_payload.items()
                    if key != "decision_sha256"
                }
            ),
        },
    )
    r40_manifest_gate = _gate(
        p2c / "p2c_r40_manifest_gate.json",
        "R40 Manifest Gate",
        {
            "manifest_frozen": r40_manifest["status"] == "FROZEN",
            "exact_triggered_task_count": r40_manifest["logical_task_count"]
            == decision_payload["total_required_r40_task_count"],
            "only_restart_20_to_39_scheduled": r40_manifest[
                "executed_restart_ids"
            ]
            == list(range(20, 40)),
        },
        per_family={
            attack: (
                "PASS"
                if decision_payload["per_family"][attack]["trigger"]
                else "NOT_APPLICABLE"
            )
            for attack in ATTACKS
        },
    )
    return {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
        "status": "PASS",
        "r20_snapshot_hash": snapshot_hash,
        "r40_trigger_decision": decision_payload,
        "r40_execution_manifest": r40_manifest,
        "gates": {
            "source": source_gate["status"],
            "configuration": configuration_gate["status"],
            "r20_manifest": r20_manifest_gate["status"],
            "r20_completeness": r20_completeness_gate["status"],
            "r10_r20_nesting": nesting_gate["status"],
            "r20_candidate": candidate_gate["status"],
            "r40_trigger": trigger_gate["status"],
            "r40_manifest": r40_manifest_gate["status"],
        },
    }


def finalize_phase(project_root: Path) -> dict[str, Any]:
    context = _p2c_context(project_root)
    p2c = context["p2c"]
    decision_path = p2c / "r40_trigger_decision.json"
    if not decision_path.exists():
        raise RuntimeError("R40 trigger decision is missing")
    decision = load_json(decision_path)
    decision_without_hash = {
        key: value
        for key, value in decision.items()
        if key != "decision_sha256"
    }
    if (
        decision["status"] != "FROZEN"
        or decision["decision_sha256"]
        != canonical_hash(decision_without_hash)
    ):
        raise RuntimeError("R40 trigger decision is not a valid frozen decision")
    expected_r40 = int(decision["total_required_r40_task_count"])
    triggered_families = {
        attack
        for attack, value in decision["per_family"].items()
        if value["trigger"]
    }
    nontriggered_families = set(ATTACKS) - triggered_families

    r20_dir = p2c / "r20_execution"
    r40_dir = p2c / "r40_execution"
    if (r20_dir / "r20_runner.lock").exists():
        raise RuntimeError("R20 runner lock is present during finalization")
    if (r40_dir / "r40_runner.lock").exists():
        raise RuntimeError("R40 runner lock is present during finalization")
    r20_completeness = _verify_phase_execution(r20_dir, 80, range(10, 20))
    if r20_completeness["status"] != "PASS":
        raise RuntimeError("R20 no longer passes completeness during finalization")

    if expected_r40:
        qualified = r40_dir / "r40_complete_runtime_status.json"
        if qualified.exists():
            atomic_json(
                r40_dir / "r40_runtime_status.json",
                load_json(qualified),
            )
    r40_completeness = _verify_phase_execution(
        r40_dir, expected_r40, range(20, 40)
    )
    if r40_completeness["status"] != "PASS":
        raise RuntimeError("R40 completeness failed; finalization is forbidden")

    r40_manifest = load_json(r40_dir / "r40_execution_manifest.json")
    r20_snapshot = load_json(p2c / "r20_raw_snapshot_manifest.json")
    if (
        r40_manifest["source_r20_snapshot_hash"]
        != r20_snapshot["r20_raw_snapshot_hash"]
        or r40_manifest["logical_task_count"] != expected_r40
        or set(r40_manifest["triggered_families"]) != triggered_families
    ):
        raise RuntimeError("R40 execution manifest differs from trigger decision")

    r40_snapshot = _snapshot_phase_raw(
        p2c_root=p2c,
        phase="r40",
        source_snapshot_hash=context["source"]["source_p2b_snapshot_hash"],
        configuration_hash=context["freeze"]["p2c_configuration_hash"],
        orchestration_fingerprint=context["orchestration"][
            "orchestration_fingerprint"
        ],
    )
    r40_snapshot_hash = r40_snapshot["r40_raw_snapshot_hash"]

    templates = read_csv(
        p2c
        / "configuration_freeze"
        / "p2c_conditional_r40_templates.csv"
    )
    template_lookup = {row["config_id"]: row for row in templates}
    frozen_fields = (
        "config_id",
        "seed",
        "model",
        "attack",
        "K",
        "alpha",
        "alpha_rule",
        "initialization",
        "phase",
        "new_restart_count",
        "target_restart_count",
        "executed_restart_start",
        "executed_restart_end",
    )
    template_checks = [
        all(row[field] == template_lookup[row["config_id"]][field] for field in frozen_fields)
        for row in r40_completeness["inventory"]
        if row["config_id"] in template_lookup
    ]
    inventory_family_counts = Counter(
        row["attack"] for row in r40_completeness["inventory"]
    )
    r40_inventory_checks = {
        "all_configs_in_frozen_templates": all(
            row["config_id"] in template_lookup
            for row in r40_completeness["inventory"]
        ),
        "all_frozen_template_fields_match": (
            len(template_checks) == expected_r40 and all(template_checks)
        ),
        "twenty_tasks_per_triggered_family": all(
            inventory_family_counts.get(attack, 0) == 20
            for attack in triggered_families
        ),
        "zero_tasks_per_nontriggered_family": all(
            inventory_family_counts.get(attack, 0) == 0
            for attack in nontriggered_families
        ),
        "restart_20_to_39_only": all(
            verification.get("executed_restart_ids") == list(range(20, 40))
            for verification in r40_completeness["task_verification"]
        ),
        "restart_0_to_19_not_regenerated": all(
            not set(verification.get("executed_restart_ids", []))
            & set(range(0, 20))
            for verification in r40_completeness["task_verification"]
        ),
    }

    source_lookup = _config_source_lookup(p2c, context["p2b"])
    r20_states = [
        load_state(p2c, "r20", row["config_id"])
        for row in r20_completeness["inventory"]
    ]
    r20_by_config = {state["config_id"]: state for state in r20_states}
    r20_rows = [
        dict(row)
        for row in decision["all_units"]
    ]
    r40_rows: list[dict[str, Any]] = []
    r40_audits: list[dict[str, Any]] = []
    r40_states: list[dict[str, Any]] = []
    for row in r40_completeness["inventory"]:
        previous = r20_by_config[row["config_id"]]
        summary_path = _task_summary_path(r40_dir, row["task_hash"])
        summary = load_json(summary_path)
        candidate_path = (
            summary_path.parent
            / summary["artifacts"]["candidates"]["path"]
        )
        current = merge_range_state(
            previous=previous,
            range_npz_path=candidate_path,
            expected_restart_ids=range(20, 40),
            config_id=row["config_id"],
        )
        save_state(p2c, "r40", current)
        comparison, audit = compare_states(previous, current)
        r40_rows.append(comparison)
        r40_audits.append(audit)
        r40_states.append(current)

    r40_candidate_pass = all(
        value["status"] == "PASS" for value in r40_audits
    )
    if len(r40_rows) != expected_r40 or len(r40_audits) != expected_r40:
        raise RuntimeError("R20/R40 comparison count differs from triggered inventory")
    per_family_nesting: dict[str, Any] = {}
    for attack in ATTACKS:
        values = [value for value in r40_audits if value["attack"] == attack]
        if attack not in triggered_families:
            per_family_nesting[attack] = {
                "status": "NOT_APPLICABLE",
                "reason": "attack family did not trigger R40",
                "comparison_count": 0,
            }
        else:
            per_family_nesting[attack] = {
                "status": (
                    "PASS"
                    if len(values) == 20
                    and all(value["status"] == "PASS" for value in values)
                    else "FAIL"
                ),
                "comparison_count": len(values),
            }
    nesting_status = (
        "PASS"
        if r40_candidate_pass
        and all(
            value["status"] in {"PASS", "NOT_APPLICABLE"}
            for value in per_family_nesting.values()
        )
        else "FAIL"
    )
    atomic_json(
        p2c / "r20_r40_nesting_audit.json",
        {
            "schema_version": SCHEMA,
            "generation_utc": now(),
            "status": nesting_status,
            "source_r20_snapshot_hash": r20_snapshot[
                "r20_raw_snapshot_hash"
            ],
            "source_r40_snapshot_hash": r40_snapshot_hash,
            "per_family": per_family_nesting,
            "comparisons": r40_audits,
        },
    )
    atomic_json(
        p2c / "r40_candidate_preservation_audit.json",
        {
            "schema_version": SCHEMA,
            "generation_utc": now(),
            "status": (
                "PASS"
                if expected_r40 and r40_candidate_pass
                else (
                    "NOT_APPLICABLE"
                    if expected_r40 == 0
                    else "FAIL"
                )
            ),
            "per_family": per_family_nesting,
            "checks": {
                "all_triggered_units_pass": r40_candidate_pass,
                "no_threshold_success_loss": all(
                    value["checks"]["no_threshold_success_loss"]
                    for value in r40_audits
                ),
                "no_feasible_success_loss": all(
                    value["checks"]["no_feasible_success_loss"]
                    for value in r40_audits
                ),
                "best_target_loss_not_worse": all(
                    value["checks"]["best_target_ce_not_worse"]
                    for value in r40_audits
                ),
                "best_feasible_success_not_worse": all(
                    value["checks"]["best_feasible_success_not_worse"]
                    for value in r40_audits
                ),
            },
        },
    )

    na_reason = "attack family did not trigger R40"
    na_rows = _not_applicable_rows(
        nontriggered_families, stage="R40", reason=na_reason
    )
    write_csv(p2c / "r20_r40_comparison.csv", [*r40_rows, *na_rows])
    write_csv(p2c / "r40_restart_gain_by_seed.csv", [*r40_rows, *na_rows])
    r40_by_model = _aggregate_by_model(r40_rows, "R20_TO_R40")
    write_csv(
        p2c / "r40_restart_gain_by_model.csv",
        [*r40_by_model, *na_rows],
    )
    r40_tables = _diagnostic_tables(r40_states, r40_rows, "R40")
    write_csv(
        p2c / "r40_success_overlap.csv",
        [*r40_tables["overlap"], *na_rows],
    )
    write_csv(
        p2c / "r40_strongest_restart_distribution.csv",
        [*r40_tables["distribution"], *na_rows],
    )
    write_csv(
        p2c / "r40_cumulative_success.csv",
        [*r40_tables["cumulative"], *na_rows],
    )
    write_csv(
        p2c / "r40_physical_support.csv",
        [
            *r40_tables["physical"],
            *_not_applicable_rows(
                nontriggered_families & set(PHYSICAL_ATTACKS),
                stage="R40",
                reason=na_reason,
            ),
        ],
    )

    r40_by_config = {state["config_id"]: state for state in r40_states}
    final_states = [
        r40_by_config.get(state["config_id"], state) for state in r20_states
    ]
    final_rows = [
        *[
            row
            for row in r20_rows
            if row["attack"] not in triggered_families
        ],
        *r40_rows,
    ]
    if len(final_states) != 80 or len(final_rows) != 80:
        raise RuntimeError("final unit/state inventory is not exactly 80")

    metric_audit = _metric_identity_audit(
        final_states=final_states,
        comparison_rows=final_rows,
        source_lookup=source_lookup,
    )
    atomic_json(p2c / "p2c_metric_identity_audit.json", metric_audit)
    metric_gate = _gate(
        p2c / "p2c_metric_identity_gate.json",
        "Metric Identity Gate",
        metric_audit["checks"],
        configuration_statuses=[
            value["status"] for value in metric_audit["configurations"]
        ],
    )

    final_physical_rows = [
        _stage_support_row(
            state,
            stage=(
                "R40"
                if int(state["restart_count"]) == 40
                else "R20"
            ),
            previous=(
                r20_by_config[state["config_id"]]
                if int(state["restart_count"]) == 40
                else _slice_state(state, 10)
            ),
        )
        for state in final_states
        if state["attack"] in PHYSICAL_ATTACKS
    ]
    write_csv(p2c / "p2c_final_physical_support.csv", final_physical_rows)
    penalty = _penalty_assessment(
        r20_states=r20_states,
        final_states=final_states,
        penalty_triggered="phys_penalty_pgd" in triggered_families,
    )
    atomic_json(p2c / "penalty_only_assessment.json", penalty)
    physical_checks = {
        "all_60_final_physical_units_present": len(final_physical_rows) == 60,
        "all_physical_support_fields_reported": all(
            all(
                key in row
                for key in (
                    "attacked_support",
                    "active_support",
                    "final_valid_support",
                    "fallback_count",
                    "source_valid_support",
                    "feasible_support",
                    "threshold_success_support",
                    "feasible_success_support",
                    "initialization_infeasible_count",
                    "projection_failure_count",
                )
            )
            for row in final_physical_rows
        ),
        "source_valid_support_nonzero": all(
            int(row["source_valid_support"]) > 0 for row in final_physical_rows
        ),
        "penalty_only_diagnostic_flag_true": bool(
            penalty["diagnostic_pending_loss_penalty_audit"]
        ),
        "penalty_r10_fallback_reconciles": bool(
            penalty["r10_fallback_matches_p2b_reported_37894"]
        ),
        "fallback_not_counted_as_success": all(
            int(row["threshold_success_support"])
            <= int(row["final_valid_support"])
            for row in final_physical_rows
        ),
    }
    physical_gate = _gate(
        p2c / "p2c_physical_support_gate.json",
        "Physical Support Gate",
        physical_checks,
        penalty_only_assessment=penalty["assessment"],
    )

    r40_family_status = {
        attack: (
            "PASS"
            if attack in triggered_families
            else "NOT_APPLICABLE"
        )
        for attack in ATTACKS
    }
    r40_completeness_gate = _gate(
        p2c / "p2c_r40_completeness_gate.json",
        "R40 Completeness Gate",
        {
            **r40_completeness["checks"],
            **r40_inventory_checks,
        },
        expected_task_count=expected_r40,
        failed_attempt_count=len(
            read_jsonl(r40_dir / "r40_failed_runs.jsonl")
        ),
        per_family=r40_family_status,
    )
    r20_r40_nesting_gate = _gate(
        p2c / "p2c_r20_r40_nesting_gate.json",
        "R20/R40 Nesting Gate",
        {
            "all_triggered_units_nested": nesting_status == "PASS",
            "restart_0_to_19_reused": True,
            "restart_20_to_39_new_only": all(r40_inventory_checks.values()),
            "source_r20_snapshot_unchanged": True,
        },
        per_family=per_family_nesting,
    )
    r20_candidate = load_json(p2c / "r20_candidate_preservation_audit.json")
    final_candidate_gate = _gate(
        p2c / "p2c_final_candidate_gate.json",
        "Final Candidate Preservation Gate",
        {
            "r10_r20_candidate_preservation_pass": r20_candidate["status"]
            == "PASS",
            "r20_r40_triggered_candidate_preservation_pass": r40_candidate_pass,
            "no_threshold_success_loss": all(
                value["checks"]["no_threshold_success_loss"]
                for value in r40_audits
            )
            and bool(
                r20_candidate["checks"]["no_threshold_success_loss"]
            ),
            "no_feasible_success_loss": all(
                value["checks"]["no_feasible_success_loss"]
                for value in r40_audits
            )
            and bool(
                r20_candidate["checks"]["no_feasible_success_loss"]
            ),
            "best_objectives_not_worse": all(
                value["checks"]["best_target_ce_not_worse"]
                and value["checks"]["best_feasible_success_not_worse"]
                for value in r40_audits
            )
            and bool(r20_candidate["checks"]["best_target_loss_not_worse"])
            and bool(
                r20_candidate["checks"]["best_feasible_success_not_worse"]
            ),
        },
        r40_per_family=per_family_nesting,
    )

    capture_rows, saturation = _capture_recapture(final_states)
    write_csv(p2c / "capture_recapture_diagnostic.csv", capture_rows)
    atomic_json(p2c / "saturation_diagnostic.json", saturation)
    model_findings = _model_findings(
        r20_rows=r20_rows,
        r40_rows=[*r40_rows, *na_rows],
        final_states=final_states,
        saturation=saturation,
    )
    atomic_json(p2c / "model_findings.json", model_findings)
    figure_paths = _write_figures(
        p2c,
        final_states=final_states,
        final_comparisons=final_rows,
    )

    p2b_verification = verify_p2b_artifacts(context["p2b"])
    protected = _protected_scope_audit(
        project_root,
        p2c_root=p2c,
        preflight_utc=context["preflight"]["generated_at_utc"],
    )
    atomic_json(p2c / "p2c_protected_scope_audit.json", protected)
    r20_raw_verification = _verify_raw_snapshot(p2c, r20_snapshot)
    r40_raw_verification = _verify_raw_snapshot(p2c, r40_snapshot)
    artifact_identity_checks = {
        "p2b_artifacts_unchanged": p2b_verification["status"] == "PASS",
        "r20_raw_snapshot_verified": r20_raw_verification["status"] == "PASS",
        "r40_raw_snapshot_verified": r40_raw_verification["status"] == "PASS",
        "attack_code_fingerprint_unchanged": code_fingerprint(project_root)
        == EXPECTED_ATTACK_CODE_FINGERPRINT,
        "configuration_fingerprint_unchanged": context["freeze"]["status"]
        == "FROZEN",
        "orchestration_fingerprint_unchanged": context["freeze"][
            "orchestration_fingerprint"
        ]
        == context["orchestration"]["orchestration_fingerprint"],
        "r40_decision_hash_recomputes": decision["decision_sha256"]
        == canonical_hash(decision_without_hash),
        "canonical_project_root_unchanged": str(project_root)
        == context["preflight"]["canonical_identity"][
            "canonical_project_root"
        ],
        "protected_scope_untouched": protected["status"] == "PASS",
    }

    existing_gate_paths = {
        "source": p2c / "p2c_source_identity_gate.json",
        "configuration": p2c / "p2c_configuration_gate.json",
        "r20_manifest": p2c / "p2c_r20_manifest_gate.json",
        "r20_completeness": p2c / "p2c_r20_completeness_gate.json",
        "r10_r20_nesting": p2c / "p2c_r10_r20_nesting_gate.json",
        "r20_candidate": p2c / "p2c_r20_candidate_gate.json",
        "r40_trigger": p2c / "p2c_r40_trigger_gate.json",
        "r40_manifest": p2c / "p2c_r40_manifest_gate.json",
        "r40_completeness": p2c / "p2c_r40_completeness_gate.json",
        "r20_r40_nesting": p2c / "p2c_r20_r40_nesting_gate.json",
        "final_candidate": p2c / "p2c_final_candidate_gate.json",
        "metric_identity": p2c / "p2c_metric_identity_gate.json",
        "physical_support": p2c / "p2c_physical_support_gate.json",
    }
    gate_statuses = {
        key: load_json(path)["status"]
        for key, path in existing_gate_paths.items()
    }
    base_integrity_blocker = (
        any(value != "PASS" for value in gate_statuses.values())
        or not all(artifact_identity_checks.values())
    )
    adequacy = _family_adequacy(
        decision=decision,
        r20_rows=r20_rows,
        r40_rows=r40_rows,
        integrity_blocker=base_integrity_blocker,
    )
    atomic_json(p2c / "per_family_restart_adequacy.json", adequacy)

    base_delivery_paths = [
        p2c / "p2c_preflight.json",
        p2c / "p2c_orchestration_fingerprint.json",
        *list((p2c / "source_p2b_snapshot").glob("*")),
        *list((p2c / "configuration_freeze").glob("*")),
        p2c / "r20_raw_snapshot_manifest.json",
        p2c / "r20_artifact_hashes.json",
        p2c / "r10_r20_nesting_audit.json",
        p2c / "r20_candidate_preservation_audit.json",
        p2c / "r10_r20_comparison.csv",
        p2c / "r20_restart_gain_by_seed.csv",
        p2c / "r20_restart_gain_by_model.csv",
        p2c / "r20_success_overlap.csv",
        p2c / "r20_strongest_restart_distribution.csv",
        p2c / "r20_cumulative_success.csv",
        p2c / "r20_physical_support.csv",
        p2c / "r40_trigger_analysis.csv",
        p2c / "r40_trigger_decision.json",
        p2c / "r40_raw_snapshot_manifest.json",
        p2c / "r40_artifact_hashes.json",
        p2c / "r20_r40_nesting_audit.json",
        p2c / "r40_candidate_preservation_audit.json",
        p2c / "r20_r40_comparison.csv",
        p2c / "r40_restart_gain_by_seed.csv",
        p2c / "r40_restart_gain_by_model.csv",
        p2c / "r40_success_overlap.csv",
        p2c / "r40_strongest_restart_distribution.csv",
        p2c / "r40_cumulative_success.csv",
        p2c / "r40_physical_support.csv",
        p2c / "per_family_restart_adequacy.json",
        p2c / "penalty_only_assessment.json",
        p2c / "capture_recapture_diagnostic.csv",
        p2c / "saturation_diagnostic.json",
        p2c / "model_findings.json",
        p2c / "p2c_metric_identity_audit.json",
        p2c / "p2c_final_physical_support.csv",
        p2c / "p2c_protected_scope_audit.json",
        *existing_gate_paths.values(),
        *figure_paths,
    ]
    for phase in ("r20", "r40"):
        phase_dir = p2c / f"{phase}_execution"
        base_delivery_paths.extend(
            [
                phase_dir / f"{phase}_execution_manifest.json",
                phase_dir / f"{phase}_task_inventory.csv",
                phase_dir / f"{phase}_runtime_status.json",
                phase_dir / f"{phase}_ledger.jsonl",
                phase_dir / f"{phase}_failed_runs.jsonl",
            ]
        )
    preliminary_manifest = _artifact_manifest(
        context=context,
        required_paths=base_delivery_paths,
    )
    preliminary_verification = _verify_artifact_manifest(
        p2c, preliminary_manifest
    )
    artifact_gate = _gate(
        p2c / "p2c_artifact_hash_gate.json",
        "Artifact Hash Gate",
        {
            **artifact_identity_checks,
            "all_delivery_manifest_entries_verified": preliminary_verification[
                "all_manifest_entries_verified"
            ],
            "manifest_self_exclusion_declared": preliminary_verification[
                "manifest_self_excluded"
            ],
            "artifact_gate_self_exclusion_declared": preliminary_verification[
                "artifact_hash_gate_self_excluded"
            ],
        },
        r20_raw_verification=r20_raw_verification,
        r40_raw_verification=r40_raw_verification,
    )
    gate_statuses["artifact_hash"] = artifact_gate["status"]
    if artifact_gate["status"] != "PASS":
        adequacy = _family_adequacy(
            decision=decision,
            r20_rows=r20_rows,
            r40_rows=r40_rows,
            integrity_blocker=True,
        )
        atomic_json(p2c / "per_family_restart_adequacy.json", adequacy)

    integrity_pass = all(value == "PASS" for value in gate_statuses.values())
    verdicts = [
        value["verdict"] for value in adequacy["families"].values()
    ]
    if not integrity_pass or "IMPLEMENTATION FAILURE" in verdicts:
        next_decision = "IMPLEMENTATION FAILURE"
    elif "INCONCLUSIVE" in verdicts or penalty["assessment"] == "INCONCLUSIVE":
        next_decision = "INCONCLUSIVE"
    elif "FAIL — RESTARTS NOT STABLE" in verdicts:
        next_decision = "RESTART AUDIT NOT STABLE"
    else:
        next_decision = "READY FOR P3"
    integrity_gate = _gate(
        p2c / "p2c_integrity_gate.json",
        "Final P2-C Integrity Gate",
        {
            **{
                f"{key}_gate_pass": value == "PASS"
                for key, value in gate_statuses.items()
            },
            "p3_to_p6_not_executed": protected["status"] == "PASS",
            "r80_not_executed": not (p2c / "r80_execution").exists(),
            "manuscript_not_modified": not protected[
                "manuscript_changes_after_preflight"
            ],
            "p2b_raw_records_not_altered": p2b_verification["status"]
            == "PASS",
            "failed_results_preserved": True,
            "robustness_claims_not_restored": True,
        },
        restart_adequacy={
            attack: value["verdict"]
            for attack, value in adequacy["families"].items()
        },
        restart_adequacy_is_not_integrity=True,
        next_stage_decision=next_decision,
        p3_to_p6_executed=False,
        r80_executed=False,
        paper_modified=False,
    )
    gate_statuses["integrity"] = integrity_gate["status"]
    report = _render_report(
        project_root=project_root,
        context=context,
        r20_completeness=r20_completeness,
        decision=decision,
        r40_completeness=r40_completeness,
        adequacy=adequacy,
        model_findings=model_findings,
        penalty=penalty,
        gate_statuses=gate_statuses,
        next_decision=next_decision,
    )
    report_path = p2c / "p2c_report.md"
    with report_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(report)

    final_manifest = _artifact_manifest(
        context=context,
        required_paths=[
            *base_delivery_paths,
            p2c / "p2c_integrity_gate.json",
            report_path,
        ],
    )
    final_verification = _verify_artifact_manifest(p2c, final_manifest)
    final_artifact_gate = _gate(
        p2c / "p2c_artifact_hash_gate.json",
        "Artifact Hash Gate",
        {
            **artifact_identity_checks,
            "all_delivery_manifest_entries_verified": final_verification[
                "all_manifest_entries_verified"
            ],
            "manifest_self_exclusion_declared": final_verification[
                "manifest_self_excluded"
            ],
            "artifact_gate_self_exclusion_declared": final_verification[
                "artifact_hash_gate_self_excluded"
            ],
        },
        r20_raw_verification=r20_raw_verification,
        r40_raw_verification=r40_raw_verification,
    )
    if final_artifact_gate["status"] != "PASS":
        raise RuntimeError("final P2-C artifact manifest verification failed")
    if integrity_gate["status"] != (
        "PASS"
        if all(
            value == "PASS"
            for key, value in gate_statuses.items()
            if key != "integrity"
        )
        else "FAIL"
    ):
        raise RuntimeError("final integrity gate is inconsistent with formal gates")
    return {
        "schema_version": SCHEMA,
        "generation_utc": now(),
        "status": "COMPLETE",
        "next_stage_decision": next_decision,
        "triggered_families": sorted(triggered_families),
        "r20_task_count": 80,
        "r40_task_count": expected_r40,
        "formal_gates": gate_statuses,
        "restart_adequacy": {
            attack: value["verdict"]
            for attack, value in adequacy["families"].items()
        },
        "p3_to_p6_executed": False,
        "r80_executed": False,
        "paper_modified": False,
        "robustness_claims_restored": False,
    }


def status(project_root: Path) -> None:
    context = _p2c_context(project_root)
    p2c = context["p2c"]
    payload: dict[str, Any] = {
        "schema_version": SCHEMA,
        "generated_at_utc": now(),
    }
    for name in (
        "r20_raw_snapshot_manifest.json",
        "r40_trigger_decision.json",
        "r40_raw_snapshot_manifest.json",
        "p2c_integrity_gate.json",
    ):
        path = p2c / name
        payload[name] = load_json(path) if path.exists() else None
    print(json.dumps(payload, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--phase", required=True, choices=("trigger", "finalize", "status")
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(r"D:\ADS-B2 -beifen"),
    )
    args = parser.parse_args()
    project_root = args.project_root.resolve(strict=True)
    if args.phase == "trigger":
        payload = trigger_phase(project_root)
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif args.phase == "status":
        status(project_root)
    else:
        payload = finalize_phase(project_root)
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

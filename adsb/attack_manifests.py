"""Validation and hashing for the frozen C0-01 attack manifests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ATTACK_MANIFEST_SCHEMA_VERSION = "adsb.attack-manifest.v1"


def canonical_config_hash(config: dict[str, Any]) -> str:
    payload = {key: value for key, value in config.items() if key != "config_hash"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_json_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"manifest must be an object: {path}")
    return value


def validate_attack_config(config: dict[str, Any], *, training: dict[str, Any] | None = None) -> None:
    required = {
        "seen_during_training",
        "differing_dimensions",
        "attack_id",
        "loss",
        "steps",
        "alpha",
        "epsilon",
        "initialization",
        "restarts",
        "projection_schedule",
        "budget_scope",
        "config_hash",
    }
    missing = sorted(required.difference(config))
    if missing:
        raise ValueError(f"attack config missing fields: {', '.join(missing)}")
    if config["budget_scope"] != "normalized_raw6":
        raise ValueError("budget_scope must be normalized_raw6")
    if config["config_hash"] != canonical_config_hash(config):
        raise ValueError(f"attack config hash mismatch: {config.get('name', config['attack_id'])}")
    if not bool(config["seen_during_training"]):
        dimensions = set(str(value) for value in config["differing_dimensions"])
        if len(dimensions) < 2:
            raise ValueError("holdout attack must differ in at least two dimensions")
        if training is not None:
            actually_different = {
                key
                for key in ("attack_id", "loss", "steps", "alpha", "epsilon", "initialization", "restarts", "projection_schedule")
                if config.get(key) != training.get(key)
            }
            if not dimensions.issubset(actually_different):
                raise ValueError("declared differing_dimensions are not actually different")


def validate_manifest_set(config_dir: Path) -> dict[str, dict[str, Any]]:
    root = Path(config_dir)
    train = load_json_manifest(root / "train_attack_manifest.json")
    evaluation = load_json_manifest(root / "evaluation_attack_matrix.json")
    threat = load_json_manifest(root / "threat_model.json")
    for name, manifest in (("train", train), ("evaluation", evaluation), ("threat", threat)):
        if manifest.get("schema_version") != ATTACK_MANIFEST_SCHEMA_VERSION:
            raise ValueError(f"{name} manifest schema mismatch")
    train_config = train["attack"]
    validate_attack_config(train_config)
    for config in evaluation["attacks"]:
        validate_attack_config(config, training=train_config)
    frozen = threat["frozen_decisions"]
    required_frozen = {
        "budget_scope": "normalized_raw6",
        "derived_difference_consistency": "recomputed_from_raw",
        "normal_class": 0,
        "anomaly_class": 1,
        "attack_target": "normal",
        "evaluation_threshold": "frozen_clean_validation_threshold_per_model",
        "numeric_precision": "float32",
        "result_retention": "all_directions",
    }
    if any(frozen.get(key) != expected for key, expected in required_frozen.items()):
        raise ValueError("threat-model frozen decision mismatch")
    return {"train": train, "evaluation": evaluation, "threat": threat}


__all__ = ["canonical_config_hash", "load_json_manifest", "validate_attack_config", "validate_manifest_set"]

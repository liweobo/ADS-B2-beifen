"""Detector checkpoint I/O with verifiable experiment identity."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import torch

from adsb.model import LSTMDetector

CHECKPOINT_SCHEMA_VERSION = "adsb.detector-checkpoint.v2"
CHECKPOINT_MANIFEST_SCHEMA_VERSION = "adsb.detector-checkpoint-manifest.v1"


class CheckpointIdentityError(RuntimeError):
    """Raised when a checkpoint cannot be tied to the requested experiment."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def code_fingerprint(project_root: Path) -> str:
    """Hash source/config files deterministically for checkpoint identity."""
    root = Path(project_root).resolve()
    files: list[Path] = []
    for directory in ("adsb", "configs", "scripts"):
        base = root / directory
        if base.exists():
            files.extend(path for path in base.rglob("*") if path.is_file() and path.suffix in {".py", ".json"})
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(path.stat().st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def sha256_array(value: np.ndarray) -> str:
    array = np.ascontiguousarray(np.asarray(value, dtype=np.float32))
    digest = hashlib.sha256()
    digest.update(str(array.shape).encode("ascii"))
    digest.update(str(array.dtype).encode("ascii"))
    digest.update(array.tobytes(order="C"))
    return digest.hexdigest()


def normalization_hash(mean: np.ndarray, std: np.ndarray) -> str:
    return hashlib.sha256(_canonical_json({"mean": sha256_array(mean), "std": sha256_array(std)})).hexdigest()


@dataclass(frozen=True)
class CheckpointIdentity:
    split_hash: str
    dataset_hash: str
    config_hash: str
    code_fingerprint: str
    train_attack_manifest_hash: str | None = None

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if name == "train_attack_manifest_hash" and value is None:
                continue
            if not isinstance(value, str) or len(value.strip()) != 64:
                raise ValueError(f"{name} must be a 64-character SHA-256 hex digest")
            try:
                int(value, 16)
            except ValueError as exc:
                raise ValueError(f"{name} is not hexadecimal") from exc


def unwrap_compiled_module(module: torch.nn.Module) -> torch.nn.Module:
    """Return the underlying model for DataParallel/compile-style wrappers."""
    current = module
    seen: set[int] = set()
    while id(current) not in seen:
        seen.add(id(current))
        child = getattr(current, "_orig_mod", None)
        if child is None and hasattr(current, "module"):
            child = getattr(current, "module")
        if not isinstance(child, torch.nn.Module):
            return current
        current = child
    return current


def detector_model_spec(model: torch.nn.Module, *, input_dim: int) -> dict[str, Any]:
    base = unwrap_compiled_module(model)
    if not isinstance(base, LSTMDetector):
        raise TypeError("verified detector checkpoints require an LSTMDetector")
    head_dropout = next((float(m.p) for m in base.head if isinstance(m, torch.nn.Dropout)), 0.0)
    return {
        "class": "adsb.model.LSTMDetector",
        "input_dim": int(input_dim),
        "hidden_dim": int(base.hidden_dim),
        "num_layers": int(base.lstm.num_layers),
        "dropout": head_dropout,
        "bidirectional": bool(base.bidirectional),
        "num_classes": 2,
        "class_mapping": {"normal": 0, "anomaly": 1},
    }


def _atomic_torch_save(payload: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(handle)
    temp_path = Path(temp_name)
    try:
        torch.save(dict(payload), temp_path)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _atomic_json_save(payload: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(handle)
    temp_path = Path(temp_name)
    try:
        temp_path.write_bytes(_canonical_json(payload) + b"\n")
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def checkpoint_manifest_path(path: Path) -> Path:
    path = Path(path)
    return path.with_name(path.name + ".manifest.json")


def save_detector_checkpoint(
    path: Path,
    model: torch.nn.Module,
    *,
    input_dim: int,
    threshold: float,
    norm_mean: np.ndarray,
    norm_std: np.ndarray,
    identity: CheckpointIdentity | None = None,
) -> Path:
    """Atomically save a checkpoint.

    Passing ``identity`` creates the v2 verified format and a SHA-256 sidecar.
    Omitting it preserves legacy callers, but the result is explicitly marked
    unverified and is rejected by :func:`load_verified_detector_checkpoint`.
    """
    path = Path(path)
    mean = np.asarray(norm_mean, dtype=np.float32)
    std = np.asarray(norm_std, dtype=np.float32)
    if identity is None:
        payload: dict[str, Any] = {
            "schema_version": "adsb.detector-checkpoint.legacy-unverified",
            "state_dict": unwrap_compiled_module(model).state_dict(),
            "input_dim": int(input_dim),
            "threshold": float(threshold),
            "norm_mean": mean,
            "norm_std": std,
        }
    else:
        identity.validate()
        payload = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "state_dict": unwrap_compiled_module(model).state_dict(),
            "model_spec": detector_model_spec(model, input_dim=input_dim),
            "clean_validation_threshold": float(threshold),
            "normalization": {
                "mean": mean,
                "std": std,
                "sha256": normalization_hash(mean, std),
            },
            "identity": asdict(identity),
        }
    _atomic_torch_save(payload, path)
    if identity is not None:
        _atomic_json_save(
            {
                "schema_version": CHECKPOINT_MANIFEST_SCHEMA_VERSION,
                "checkpoint_file": path.name,
                "checkpoint_sha256": sha256_file(path),
                "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
                "identity": asdict(identity),
                "normalization_sha256": normalization_hash(mean, std),
            },
            checkpoint_manifest_path(path),
        )
    return path


def _torch_load(path: Path, device: torch.device) -> dict[str, Any]:
    try:
        value = torch.load(path, map_location=device, weights_only=False)
    except TypeError:
        value = torch.load(path, map_location=device)
    if not isinstance(value, dict):
        raise CheckpointIdentityError("checkpoint payload is not a mapping")
    return value


def _model_from_spec(spec: Mapping[str, Any], device: torch.device) -> LSTMDetector:
    if spec.get("class") != "adsb.model.LSTMDetector":
        raise CheckpointIdentityError("unsupported model specification")
    return LSTMDetector(
        input_dim=int(spec["input_dim"]),
        hidden_dim=int(spec["hidden_dim"]),
        num_layers=int(spec["num_layers"]),
        dropout=float(spec["dropout"]),
        bidirectional=bool(spec["bidirectional"]),
    ).to(device)


def load_verified_detector_checkpoint(
    path: Path,
    device: torch.device,
    *,
    expected_identity: CheckpointIdentity,
    expected_norm_mean: np.ndarray | None = None,
    expected_norm_std: np.ndarray | None = None,
) -> tuple[LSTMDetector, float, np.ndarray, np.ndarray, int]:
    """Load only if every recorded and expected identity component matches."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"checkpoint does not exist: {path.resolve()}")
    expected_identity.validate()
    sidecar_path = checkpoint_manifest_path(path)
    if not sidecar_path.is_file():
        raise CheckpointIdentityError("verified checkpoint manifest is missing")
    try:
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckpointIdentityError("checkpoint manifest is unreadable") from exc
    if sidecar.get("schema_version") != CHECKPOINT_MANIFEST_SCHEMA_VERSION:
        raise CheckpointIdentityError("checkpoint manifest schema mismatch")
    if sidecar.get("checkpoint_sha256") != sha256_file(path):
        raise CheckpointIdentityError("checkpoint SHA-256 mismatch (file may be tampered)")
    ckpt = _torch_load(path, device)
    if ckpt.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise CheckpointIdentityError("checkpoint is not a verified v2 checkpoint")
    expected = asdict(expected_identity)
    if ckpt.get("identity") != expected or sidecar.get("identity") != expected:
        actual = ckpt.get("identity", {})
        mismatches = [key for key, value in expected.items() if actual.get(key) != value]
        raise CheckpointIdentityError(f"checkpoint identity mismatch: {', '.join(mismatches) or 'sidecar'}")
    normalization = ckpt.get("normalization")
    if not isinstance(normalization, dict):
        raise CheckpointIdentityError("normalization payload missing")
    mean = np.asarray(normalization.get("mean"), dtype=np.float32)
    std = np.asarray(normalization.get("std"), dtype=np.float32)
    actual_norm_hash = normalization_hash(mean, std)
    if normalization.get("sha256") != actual_norm_hash or sidecar.get("normalization_sha256") != actual_norm_hash:
        raise CheckpointIdentityError("normalization hash mismatch")
    if expected_norm_mean is not None and expected_norm_std is not None:
        if actual_norm_hash != normalization_hash(expected_norm_mean, expected_norm_std):
            raise CheckpointIdentityError("normalization does not match evaluation data")
    spec = ckpt.get("model_spec")
    if not isinstance(spec, dict):
        raise CheckpointIdentityError("model specification missing")
    model = _model_from_spec(spec, device)
    try:
        model.load_state_dict(ckpt["state_dict"], strict=True)
    except (KeyError, RuntimeError) as exc:
        raise CheckpointIdentityError("state_dict does not match model specification") from exc
    model.eval()
    return model, float(ckpt["clean_validation_threshold"]), mean, std, int(spec["input_dim"])


def load_detector_checkpoint(path: Path, device: torch.device) -> tuple[LSTMDetector, float, np.ndarray, np.ndarray, int]:
    """Compatibility loader for inference; audit evaluation must use verified load."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"checkpoint does not exist: {path.resolve()}")
    ckpt = _torch_load(path, device)
    if ckpt.get("schema_version") == CHECKPOINT_SCHEMA_VERSION:
        spec = ckpt["model_spec"]
        model = _model_from_spec(spec, device)
        model.load_state_dict(ckpt["state_dict"], strict=True)
        model.eval()
        norm = ckpt["normalization"]
        return (
            model,
            float(ckpt["clean_validation_threshold"]),
            np.asarray(norm["mean"], dtype=np.float32),
            np.asarray(norm["std"], dtype=np.float32),
            int(spec["input_dim"]),
        )
    input_dim = int(ckpt["input_dim"])
    model = LSTMDetector(input_dim=input_dim).to(device)
    model.load_state_dict(ckpt["state_dict"], strict=True)
    model.eval()
    return (
        model,
        float(ckpt["threshold"]),
        np.asarray(ckpt["norm_mean"], dtype=np.float32),
        np.asarray(ckpt["norm_std"], dtype=np.float32),
        input_dim,
    )

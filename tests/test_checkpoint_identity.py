from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import torch

from adsb.checkpoints import (
    CheckpointIdentity,
    CheckpointIdentityError,
    checkpoint_manifest_path,
    load_verified_detector_checkpoint,
    save_detector_checkpoint,
    sha256_file,
    unwrap_compiled_module,
)
from adsb.model import LSTMDetector


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _Wrapped(torch.nn.Module):
    def __init__(self, module):
        super().__init__()
        self._orig_mod = module

    def forward(self, x):
        return self._orig_mod(x)


class CheckpointIdentityTests(unittest.TestCase):
    def setUp(self):
        torch.manual_seed(7)
        self.model = LSTMDetector(input_dim=12, hidden_dim=8, num_layers=1, dropout=0.0, bidirectional=False)
        self.mean = np.zeros((1, 1, 12), dtype=np.float32)
        self.std = np.ones((1, 1, 12), dtype=np.float32)
        self.identity = CheckpointIdentity(_digest("split"), _digest("data"), _digest("config"), _digest("code"))

    def _save(self, root: Path, model=None) -> Path:
        path = root / "detector.pt"
        save_detector_checkpoint(
            path,
            model or self.model,
            input_dim=12,
            threshold=0.37,
            norm_mean=self.mean,
            norm_std=self.std,
            identity=self.identity,
        )
        return path

    def test_round_trip_logits_and_wrapped_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._save(Path(tmp), _Wrapped(self.model))
            loaded, threshold, _, _, _ = load_verified_detector_checkpoint(
                path,
                torch.device("cpu"),
                expected_identity=self.identity,
                expected_norm_mean=self.mean,
                expected_norm_std=self.std,
            )
            x = torch.randn(3, 5, 12)
            self.model.eval()
            self.assertTrue(torch.equal(self.model(x), loaded(x)))
            self.assertEqual(threshold, 0.37)
            self.assertIs(unwrap_compiled_module(_Wrapped(self.model)), self.model)

    def test_checkpoint_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._save(Path(tmp))
            with path.open("ab") as stream:
                stream.write(b"tamper")
            with self.assertRaisesRegex(CheckpointIdentityError, "SHA-256"):
                load_verified_detector_checkpoint(path, torch.device("cpu"), expected_identity=self.identity)

    def test_split_config_and_code_mismatch_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._save(Path(tmp))
            for field in ("split_hash", "config_hash", "code_fingerprint"):
                values = self.identity.__dict__.copy()
                values[field] = _digest("wrong-" + field)
                with self.subTest(field=field), self.assertRaisesRegex(CheckpointIdentityError, field):
                    load_verified_detector_checkpoint(
                        path, torch.device("cpu"), expected_identity=CheckpointIdentity(**values)
                    )

    def test_normalization_mismatch_and_internal_tamper_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._save(Path(tmp))
            with self.assertRaisesRegex(CheckpointIdentityError, "normalization"):
                load_verified_detector_checkpoint(
                    path,
                    torch.device("cpu"),
                    expected_identity=self.identity,
                    expected_norm_mean=self.mean + 1,
                    expected_norm_std=self.std,
                )
            payload = torch.load(path, map_location="cpu", weights_only=False)
            payload["normalization"]["mean"] = self.mean + 2
            torch.save(payload, path)
            sidecar_path = checkpoint_manifest_path(path)
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            sidecar["checkpoint_sha256"] = sha256_file(path)
            sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
            with self.assertRaisesRegex(CheckpointIdentityError, "normalization hash"):
                load_verified_detector_checkpoint(path, torch.device("cpu"), expected_identity=self.identity)


if __name__ == "__main__":
    unittest.main()

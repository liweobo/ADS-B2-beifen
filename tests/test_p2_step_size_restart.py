from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from adsb.p2_step_size_restart import (
    ALPHA_RULES,
    ATTACKS,
    MODELS,
    SAMPLE_FIELDS,
    SEEDS,
    STEP_FIELDS,
    STEPS,
    AggregateStore,
    _alpha,
    _canonical_hash,
    _contains_null,
    _write_rows,
)


ROOT = Path(__file__).resolve().parents[1]


class P2StepSizeRestartTests(unittest.TestCase):
    def test_frozen_manifest_hash_grid_and_no_nulls(self):
        path = ROOT / "configs" / "attack_audit_c001" / "p2_audit_manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        expected = _canonical_hash({key: value for key, value in manifest.items() if key != "config_hash"})
        self.assertEqual(manifest["config_hash"], expected)
        self.assertFalse(_contains_null(manifest))
        configurations = len(SEEDS) * len(MODELS) * len(ATTACKS) * len(STEPS) * len(ALPHA_RULES) * 2
        self.assertEqual(configurations, 640)
        self.assertEqual(manifest["p2_a"]["logical_configurations"], configurations)

    def test_alpha_rules_are_exact(self):
        self.assertEqual(_alpha("fixed_003", 20), 0.03)
        self.assertEqual(_alpha("eps_over_k", 20), 0.005)
        self.assertEqual(_alpha("eps_over_k", 50), 0.002)
        self.assertEqual(_alpha("two_eps_over_k", 20), 0.01)
        self.assertEqual(_alpha("two_eps_over_k", 50), 0.004)
        self.assertEqual(_alpha("eps_over_4", 20), 0.025)

    def test_native_log_contract_contains_p2_fields(self):
        required = {
            "restart_id",
            "step",
            "pre_projection_margin",
            "post_projection_margin",
            "raw_boundary_saturation_rate",
            "initialization_status",
            "final_candidate",
            "best_loss_candidate",
            "best_feasible_success_step",
        }
        self.assertTrue(required.issubset(STEP_FIELDS))

    def test_aggregate_store_recovers_unledgered_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = AggregateStore(root)
            step_fragment = root / "step.gz"
            sample_fragment = root / "sample.gz"
            step_rows, step_hash = _write_rows(
                step_fragment,
                STEP_FIELDS,
                [{"task_hash": "a" * 64, "restart_id": 0, "step": 0}],
                header=True,
            )
            sample_rows, sample_hash = _write_rows(
                sample_fragment,
                SAMPLE_FIELDS,
                [{"task_hash": "a" * 64, "sample_id": "s0"}],
                header=True,
            )
            store.commit(
                task_hash="a" * 64,
                step_fragment=step_fragment,
                sample_fragment=sample_fragment,
                step_rows=step_rows,
                sample_rows=sample_rows,
                step_sha256=step_hash,
                sample_sha256=sample_hash,
            )
            ledger_size = store.step_path.stat().st_size
            with store.step_path.open("ab") as stream:
                stream.write(b"unledgered tail")
            self.assertGreater(store.step_path.stat().st_size, ledger_size)
            recovered = AggregateStore(root)
            self.assertEqual(recovered.step_path.stat().st_size, ledger_size)
            self.assertTrue(recovered.has_task("a" * 64))


if __name__ == "__main__":
    unittest.main()

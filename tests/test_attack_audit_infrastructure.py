from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np

from adsb.anomalies import inject
from adsb.attack_audit_runner import AttackAuditRunner, AuditTask
from adsb.attack_manifests import validate_manifest_set
from adsb.dataset import DS


ROOT = Path(__file__).resolve().parents[1]


class AttackAuditInfrastructureTests(unittest.TestCase):
    def test_manifests_hash_and_holdout_dimensions(self):
        manifests = validate_manifest_set(ROOT / "configs" / "attack_audit_c001")
        holdouts = [row for row in manifests["evaluation"]["attacks"] if not row["seen_during_training"]]
        self.assertTrue(holdouts)
        self.assertTrue(all(len(set(row["differing_dimensions"])) >= 2 for row in holdouts))

    def test_overlapping_anomalies_use_bitmask_and_dataset_order_is_stable(self):
        raw = np.zeros((2, 6, 6), dtype=np.float32)
        raw[..., 3] = 100.0
        raw[..., 5] = 1.0
        _, labels, metadata = inject(
            raw,
            ratio=1.0,
            anomaly_types=("d", "s"),
            poison_len_min=6,
            poison_len_max=6,
            seq_len=1,
            random_state=5,
            return_metadata=True,
        )
        self.assertTrue(np.all(labels == 1))
        self.assertTrue(np.all(metadata["anomaly_bitmask"] > 0))
        sample_metadata = {
            "sample_id": np.asarray(["a", "b"]),
            "aircraft_id": np.asarray(["x", "y"]),
            "segment_id": np.asarray(["x_1", "y_1"]),
            "window_start": np.asarray([0, 1]),
            "anomaly_bitmask": metadata["anomaly_bitmask"],
            "seed": np.asarray([5, 5]),
            "split": np.asarray(["test", "test"]),
            "original_label": labels,
        }
        dataset = DS(np.zeros((2, 3, 12)), labels, metadata=sample_metadata, return_metadata=True)
        self.assertEqual([dataset[i][2]["sample_id"] for i in range(2)], ["a", "b"])

    def test_runner_retains_negative_and_failed_tasks_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = AttackAuditRunner(Path(tmp), ROOT / "configs" / "attack_audit_c001")
            ready_config = next(
                row for row in runner.manifests["evaluation"]["attacks"] if row["name"] == "holdout_norm_margin_r5"
            )
            tasks = [
                AuditTask("a" * 64, "split-1", "negative", ready_config["config_hash"], ready_config),
                AuditTask("c" * 64, "split-1", "failure", ready_config["config_hash"], ready_config),
            ]

            def executor(task):
                if task.attack_name == "failure":
                    raise RuntimeError("synthetic failure")
                return {
                    "per_sample": [
                        {"sample_id": "s0", "original_label": 1, "prediction": 0, "metric": float("nan")},
                        {"sample_id": "s1", "original_label": 0, "prediction": 1, "metric": -1.0},
                    ],
                    "per_step": [{"step": 0, "loss": float("nan")}],
                    "metrics": {"tp": 0, "tn": 0, "fp": 1, "fn": 1, "precision": 0, "recall": 0, "f1": 0},
                }

            summary = runner.run_tasks(tasks, executor)
            self.assertTrue(summary["all_tasks_retained"])
            self.assertEqual(summary["completed"], 1)
            self.assertEqual(summary["failed_retained"], 1)
            second = runner.run_tasks(tasks, lambda task: self.fail("completed task was overwritten"))
            self.assertEqual(second["task_statuses"], summary["task_statuses"])
            artifact_paths = {item["path"] for item in runner.artifact_manifest()["artifacts"]}
            self.assertIn("tasks/" + "c" * 64 + "/failure.json", artifact_paths)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import torch

from audit_tools.p2c_orchestration import (
    _TinyDetector,
    execute_range_task,
    orchestration_self_test,
)


def test_restart_range_matches_unchanged_engine() -> None:
    result = orchestration_self_test()
    assert result["status"] == "PASS"
    assert all(result["checks"].values())


def test_atomic_range_task_smoke(tmp_path) -> None:
    model = _TinyDetector().eval()
    generator = torch.Generator().manual_seed(711)
    X = torch.randn((5, 4, 12), generator=generator) * 0.05
    y = torch.tensor([1, 0, 1, 0, 1], dtype=torch.long)
    with torch.no_grad():
        clean_probs = torch.softmax(model(X), dim=1)[:, 1].numpy()
    dataset = SimpleNamespace(X=X, y=y)
    pack = SimpleNamespace(
        test_loader=SimpleNamespace(dataset=dataset),
        norm_mean=np.zeros(12, dtype=np.float32),
        norm_std=np.ones(12, dtype=np.float32),
        audit_metadata={
            "test": {
                "sample_id": np.asarray([f"sample-{value}" for value in range(5)]),
                "aircraft_id": np.asarray(["A", "A", "B", "B", "C"]),
                "segment_id": np.asarray(["0", "0", "1", "1", "2"]),
                "window_start": np.arange(5),
                "anomaly_bitmask": np.asarray([1, 0, 2, 0, 4]),
            }
        },
    )
    source_summary = {
        "seed": 42,
        "model": "BiLSTM-ERM",
        "attack": "norm_pgd",
        "steps": 2,
        "initialization": "uniform_budget",
        "alpha": 0.1,
        "task_hash": "1" * 64,
        "candidate_artifact": {"sha256": "2" * 64},
        "checkpoint_sha256": "3" * 64,
        "threshold": 0.5,
        "task_identity": {
            "split_hash": "4" * 64,
            "normalization_hash": "5" * 64,
            "sample_manifest_hash": "6" * 64,
        },
    }
    summary = execute_range_task(
        phase="smoke",
        phase_dir=tmp_path,
        config_id="7" * 64,
        source_summary=source_summary,
        model=model,
        threshold=0.5,
        pack=pack,
        clean_probs=clean_probs,
        target_restart_count=12,
        restart_ids=(10, 11),
        projection={
            "budget_abs_tol": 1e-5,
            "kinematic_rel_tol": 1e-5,
            "projection_residual_tol": 1e-6,
            "alternating_projection_max_iterations": 5,
            "feasible_random_max_resamples": 2,
        },
        source_snapshot_hash="8" * 64,
        previous_snapshot_hash="8" * 64,
        p2c_configuration_hash="9" * 64,
        orchestration_fingerprint="a" * 64,
        device=torch.device("cpu"),
        attempt=1,
    )
    assert summary["status"] == "completed"
    assert summary["executed_restart_ids"] == [10, 11]
    assert all(summary["identity_checks"].values())
    assert summary["artifacts"]["per_step"]["rows"] == 3 * 2 * 3
    assert summary["artifacts"]["per_sample"]["rows"] == 3


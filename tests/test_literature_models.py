from __future__ import annotations

import unittest

import numpy as np
import torch

from adsb.literature_models import (
    ContextualAutoencoder,
    FriedDifferencingLSTMAE,
    VAESVDD,
    fit_rbf_svdd,
)


class LiteratureModelTest(unittest.TestCase):
    def test_fried_lstm_ae_exposes_finite_differentiable_logits(self) -> None:
        model = FriedDifferencingLSTMAE()
        x = torch.randn(4, 15, 12, requires_grad=True)
        logits = model(x)
        self.assertEqual(logits.shape, (4, 2))
        logits[:, 1].sum().backward()
        self.assertIsNotNone(x.grad)
        self.assertTrue(torch.isfinite(x.grad).all())
        self.assertGreater(torch.count_nonzero(x.grad[..., 6:12]).item(), 0)

    def test_contextual_autoencoder_routes_physical_climb_cruise_descent(self) -> None:
        model = ContextualAutoencoder(
            sequence_length=15,
            norm_mean=np.zeros((1, 1, 12), dtype=np.float32),
            norm_std=np.ones((1, 1, 12), dtype=np.float32),
            phase_deadband=5.0,
        )
        x = torch.zeros(3, 15, 12)
        x[0, :, 8] = 10.0
        x[1, :, 8] = 0.0
        x[2, :, 8] = -10.0
        self.assertEqual(model.phase_labels(x).tolist(), [0, 1, 2])
        loss = model.reconstruction_loss(x)
        self.assertTrue(torch.isfinite(loss))
        loss.backward()
        for decoder in model.decoders:
            self.assertTrue(any(parameter.grad is not None for parameter in decoder.parameters()))

    def test_vae_svdd_rbf_boundary_is_differentiable_after_fit(self) -> None:
        torch.manual_seed(7)
        model = VAESVDD(sequence_length=15)
        residuals = np.abs(np.random.default_rng(7).normal(size=(48, 12))).astype(np.float32)
        metadata = fit_rbf_svdd(model, residuals, nu=0.1)
        self.assertGreater(int(metadata["support_vectors"]), 0)
        x = torch.randn(3, 15, 12, requires_grad=True)
        logits = model(x)
        self.assertEqual(logits.shape, (3, 2))
        logits[:, 0].sum().backward()
        self.assertIsNotNone(x.grad)
        self.assertTrue(torch.isfinite(x.grad).all())
        self.assertGreater(torch.count_nonzero(x.grad).item(), 0)


if __name__ == "__main__":
    unittest.main()

"""Protocol-aligned reimplementations of published ADS-B anomaly detectors.

The original papers use different feature sets, sequence lengths, and software
frameworks.  The classes below preserve each paper's defining architecture and
one-class training rule while accepting CAT-AD's common ``(B, T, 12)`` input.
Consequently, results produced by this module are same-protocol
reimplementations, not copied numbers from the source papers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.svm import OneClassSVM


@dataclass(frozen=True)
class LiteratureModelSpec:
    key: str
    display_name: str
    publication_year: int
    citation_key: str
    doi: str
    implementation_basis: str


LITERATURE_MODEL_SPECS: tuple[LiteratureModelSpec, ...] = (
    LiteratureModelSpec(
        key="fried_lstm_ae",
        display_name="Fried--Last Differenced LSTM-AE",
        publication_year=2021,
        citation_key="fried2021autoencoders",
        doi="10.1016/j.cose.2021.102405",
        implementation_basis=(
            "paper and official GPL-3.0 notebook; recurrent autoencoder trained "
            "on benign differenced ADS-B trajectories"
        ),
    ),
    LiteratureModelSpec(
        key="vae_svdd",
        display_name="VAE--SVDD",
        publication_year=2021,
        citation_key="luo2021vaesvdd",
        doi="10.1016/j.cose.2021.102213",
        implementation_basis=(
            "paper method; recurrent VAE reconstruction residuals followed by "
            "an RBF support-vector data description"
        ),
    ),
    LiteratureModelSpec(
        key="contextual_ae",
        display_name="Contextual AE",
        publication_year=2022,
        citation_key="chevrot2022cae",
        doi="10.1016/j.cose.2022.102652",
        implementation_basis=(
            "paper and official scifly implementation; shared recurrent encoder "
            "with climb, cruise, and descent decoders"
        ),
    ),
)


class CalibratedAnomalyDetector(nn.Module):
    """Expose a differentiable anomaly score through two-class logits.

    CAT-AD's evaluation code expects class 0=normal and class 1=malicious.
    One-class detectors instead emit an anomaly score.  Robust location/scale
    calibration maps that score to logits without changing its ordering; the
    final decision threshold is still selected only on the validation split.
    """

    def __init__(self) -> None:
        super().__init__()
        self.register_buffer("score_center", torch.tensor(0.0, dtype=torch.float32))
        self.register_buffer("score_scale", torch.tensor(1.0, dtype=torch.float32))

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        raise NotImplementedError

    def reconstruction_loss(self, x: torch.Tensor) -> torch.Tensor:
        raise NotImplementedError

    @torch.no_grad()
    def set_score_calibration(self, scores: torch.Tensor | np.ndarray) -> dict[str, float]:
        values = torch.as_tensor(scores, dtype=torch.float32, device=self.score_center.device).reshape(-1)
        values = values[torch.isfinite(values)]
        if values.numel() == 0:
            raise ValueError("Cannot calibrate an anomaly detector from empty/non-finite scores.")
        center = values.median()
        q25 = torch.quantile(values, 0.25)
        q75 = torch.quantile(values, 0.75)
        robust_scale = (q75 - q25) / 1.349
        fallback = values.std(unbiased=False)
        scale = torch.where(robust_scale > 1e-8, robust_scale, fallback).clamp_min(1e-6)
        self.score_center.copy_(center)
        self.score_scale.copy_(scale)
        return {"score_center": float(center.item()), "score_scale": float(scale.item())}

    def forward(self, x: torch.Tensor, return_features: bool = False):
        score = self.anomaly_score(x)
        z = (score - self.score_center) / self.score_scale
        logits = torch.stack((-0.5 * z, 0.5 * z), dim=-1)
        if return_features:
            return logits, score.unsqueeze(-1)
        return logits


class FriedDifferencingLSTMAE(CalibratedAnomalyDetector):
    """Fried and Last (2021) recurrent AE on differenced ADS-B features."""

    def __init__(self, *, hidden_dim: int = 32, latent_dim: int = 20) -> None:
        super().__init__()
        self.input_dim = 6
        self.encoder = nn.LSTM(self.input_dim, hidden_dim, batch_first=True)
        self.to_latent = nn.Linear(hidden_dim, latent_dim)
        self.decoder = nn.LSTM(latent_dim, hidden_dim, batch_first=True)
        self.output = nn.Linear(hidden_dim, self.input_dim)

    @staticmethod
    def _paper_features(x: torch.Tensor) -> torch.Tensor:
        if x.ndim != 3 or x.shape[-1] != 12:
            raise ValueError("FriedDifferencingLSTMAE expects (B, T, 12) input.")
        return x[..., 6:12]

    def reconstruct(self, x: torch.Tensor) -> torch.Tensor:
        features = self._paper_features(x)
        _, (h_n, _) = self.encoder(features)
        latent = self.to_latent(h_n[-1])
        repeated = latent.unsqueeze(1).expand(-1, features.shape[1], -1)
        decoded, _ = self.decoder(repeated)
        return self.output(decoded)

    def reconstruction_error_features(self, x: torch.Tensor) -> torch.Tensor:
        features = self._paper_features(x)
        return (self.reconstruct(x) - features).pow(2).mean(dim=1)

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        return self.reconstruction_error_features(x).mean(dim=-1)

    def reconstruction_loss(self, x: torch.Tensor) -> torch.Tensor:
        return self.anomaly_score(x).mean()


class _ContextDecoder(nn.Module):
    def __init__(self, latent_dim: int, hidden_dim: int, output_dim: int) -> None:
        super().__init__()
        self.rnn = nn.LSTM(latent_dim, hidden_dim, batch_first=True)
        self.output = nn.Linear(hidden_dim, output_dim)

    def forward(self, latent: torch.Tensor, timesteps: int) -> torch.Tensor:
        repeated = latent.unsqueeze(1).expand(-1, timesteps, -1)
        decoded, _ = self.rnn(repeated)
        return self.output(decoded)


class ContextualAutoencoder(CalibratedAnomalyDetector):
    """Chevrot et al. (2022) shared encoder with phase-specific decoders.

    The source implementation receives an explicit phase label.  Under the
    common CAT-AD input contract, phase is deterministically derived from the
    physical mean altitude increment in each window.  The three phase labels
    are climb, cruise, and descent.
    """

    def __init__(
        self,
        *,
        sequence_length: int,
        input_dim: int = 12,
        hidden_dim: int = 32,
        latent_dim: int = 10,
        norm_mean: np.ndarray | torch.Tensor,
        norm_std: np.ndarray | torch.Tensor,
        phase_deadband: float = 5.0,
    ) -> None:
        super().__init__()
        self.sequence_length = int(sequence_length)
        self.input_dim = int(input_dim)
        self.phase_deadband = float(phase_deadband)
        self.encoder = nn.LSTM(
            self.input_dim,
            hidden_dim,
            batch_first=True,
            bidirectional=True,
        )
        self.to_latent = nn.Linear(self.sequence_length * hidden_dim * 2, latent_dim)
        self.decoders = nn.ModuleList(
            [_ContextDecoder(latent_dim, hidden_dim, self.input_dim) for _ in range(3)]
        )
        mean = torch.as_tensor(norm_mean, dtype=torch.float32).reshape(1, 1, -1)
        std = torch.as_tensor(norm_std, dtype=torch.float32).reshape(1, 1, -1)
        self.register_buffer("norm_mean", mean)
        self.register_buffer("norm_std", std)

    def phase_labels(self, x: torch.Tensor) -> torch.Tensor:
        # Differential altitude is channel 8: raw order is
        # lat/lon/alt/spd/sin/cos followed by the corresponding differences.
        dalt = x[..., 8] * self.norm_std[..., 8] + self.norm_mean[..., 8]
        mean_dalt = dalt.mean(dim=1)
        phase = torch.ones_like(mean_dalt, dtype=torch.long)  # cruise
        phase = torch.where(mean_dalt > self.phase_deadband, torch.zeros_like(phase), phase)
        phase = torch.where(mean_dalt < -self.phase_deadband, torch.full_like(phase, 2), phase)
        return phase

    def reconstruct(self, x: torch.Tensor) -> torch.Tensor:
        if x.ndim != 3 or x.shape[-1] != self.input_dim:
            raise ValueError(f"ContextualAutoencoder expects (B, T, {self.input_dim}) input.")
        if x.shape[1] != self.sequence_length:
            raise ValueError(
                f"ContextualAutoencoder was built for T={self.sequence_length}, got T={x.shape[1]}."
            )
        encoded, _ = self.encoder(x)
        latent = self.to_latent(encoded.flatten(start_dim=1))
        candidates = torch.stack(
            [decoder(latent, x.shape[1]) for decoder in self.decoders],
            dim=1,
        )
        phase = self.phase_labels(x)
        batch_index = torch.arange(x.shape[0], device=x.device)
        return candidates[batch_index, phase]

    def reconstruction_error_features(self, x: torch.Tensor) -> torch.Tensor:
        return (self.reconstruct(x) - x).pow(2).mean(dim=1)

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        return self.reconstruction_error_features(x).mean(dim=-1)

    def reconstruction_loss(self, x: torch.Tensor) -> torch.Tensor:
        return self.anomaly_score(x).mean()


class VAESVDD(CalibratedAnomalyDetector):
    """Luo et al. (2021) recurrent VAE followed by an RBF SVDD boundary."""

    def __init__(
        self,
        *,
        sequence_length: int,
        input_dim: int = 12,
        hidden_dim: int = 20,
        latent_dim: int = 10,
        beta: float = 0.1,
    ) -> None:
        super().__init__()
        self.sequence_length = int(sequence_length)
        self.input_dim = int(input_dim)
        self.beta = float(beta)
        self.encoder = nn.GRU(
            self.input_dim,
            hidden_dim,
            batch_first=True,
            bidirectional=True,
        )
        encoded_dim = self.sequence_length * hidden_dim * 2
        self.to_mean = nn.Linear(encoded_dim, latent_dim)
        self.to_log_var = nn.Linear(encoded_dim, latent_dim)
        self.decoder = nn.LSTM(
            latent_dim,
            hidden_dim,
            batch_first=True,
            bidirectional=True,
        )
        self.output = nn.Linear(hidden_dim * 2, self.input_dim)

        self.register_buffer("residual_mean", torch.zeros(self.input_dim))
        self.register_buffer("residual_scale", torch.ones(self.input_dim))
        self.register_buffer("support_vectors", torch.empty(0, self.input_dim))
        self.register_buffer("dual_coef", torch.empty(0))
        self.register_buffer("svdd_intercept", torch.tensor(0.0))
        self.register_buffer("svdd_gamma", torch.tensor(1.0))

    def encode(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        encoded, _ = self.encoder(x)
        flat = encoded.flatten(start_dim=1)
        return self.to_mean(flat), self.to_log_var(flat)

    def reconstruct(
        self,
        x: torch.Tensor,
        *,
        sample: bool = False,
        return_latent_stats: bool = False,
    ):
        if x.ndim != 3 or x.shape[-1] != self.input_dim:
            raise ValueError(f"VAESVDD expects (B, T, {self.input_dim}) input.")
        if x.shape[1] != self.sequence_length:
            raise ValueError(f"VAESVDD was built for T={self.sequence_length}, got T={x.shape[1]}.")
        mean, log_var = self.encode(x)
        if sample:
            latent = mean + torch.randn_like(mean) * torch.exp(0.5 * log_var)
        else:
            latent = mean
        repeated = latent.unsqueeze(1).expand(-1, x.shape[1], -1)
        decoded, _ = self.decoder(repeated)
        reconstruction = self.output(decoded)
        if return_latent_stats:
            return reconstruction, mean, log_var
        return reconstruction

    def reconstruction_error_features(self, x: torch.Tensor) -> torch.Tensor:
        return (self.reconstruct(x, sample=False) - x).pow(2).mean(dim=1)

    def reconstruction_loss(self, x: torch.Tensor) -> torch.Tensor:
        reconstruction, mean, log_var = self.reconstruct(
            x,
            sample=True,
            return_latent_stats=True,
        )
        recon = F.mse_loss(reconstruction, x)
        kl = -0.5 * (1.0 + log_var - mean.pow(2) - log_var.exp()).sum(dim=1).mean()
        return recon + self.beta * kl

    @torch.no_grad()
    def set_svdd(
        self,
        *,
        residual_mean: np.ndarray,
        residual_scale: np.ndarray,
        support_vectors: np.ndarray,
        dual_coef: np.ndarray,
        intercept: float,
        gamma: float,
    ) -> None:
        device = self.score_center.device
        self.residual_mean = torch.as_tensor(residual_mean, dtype=torch.float32, device=device)
        self.residual_scale = torch.as_tensor(residual_scale, dtype=torch.float32, device=device)
        self.support_vectors = torch.as_tensor(support_vectors, dtype=torch.float32, device=device)
        self.dual_coef = torch.as_tensor(dual_coef, dtype=torch.float32, device=device).reshape(-1)
        self.svdd_intercept.copy_(torch.tensor(float(intercept), device=device))
        self.svdd_gamma.copy_(torch.tensor(float(gamma), device=device))

    def svdd_decision(self, residual_features: torch.Tensor) -> torch.Tensor:
        if self.support_vectors.numel() == 0:
            raise RuntimeError("SVDD boundary has not been fitted.")
        normalized = (residual_features - self.residual_mean) / self.residual_scale
        # Squared Euclidean distances without materializing (B, S, D).
        x2 = normalized.pow(2).sum(dim=1, keepdim=True)
        s2 = self.support_vectors.pow(2).sum(dim=1).unsqueeze(0)
        distance2 = (x2 + s2 - 2.0 * normalized @ self.support_vectors.T).clamp_min(0.0)
        kernel = torch.exp(-self.svdd_gamma * distance2)
        return kernel @ self.dual_coef + self.svdd_intercept

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        return -self.svdd_decision(self.reconstruction_error_features(x))


def build_literature_model(
    key: str,
    *,
    sequence_length: int,
    norm_mean: np.ndarray,
    norm_std: np.ndarray,
    device: torch.device,
) -> CalibratedAnomalyDetector:
    normalized = str(key).strip().lower()
    if normalized == "fried_lstm_ae":
        model: CalibratedAnomalyDetector = FriedDifferencingLSTMAE()
    elif normalized == "vae_svdd":
        model = VAESVDD(sequence_length=sequence_length)
    elif normalized == "contextual_ae":
        model = ContextualAutoencoder(
            sequence_length=sequence_length,
            norm_mean=norm_mean,
            norm_std=norm_std,
        )
    else:
        known = ", ".join(spec.key for spec in LITERATURE_MODEL_SPECS)
        raise ValueError(f"Unknown literature model {key!r}; expected one of: {known}")
    return model.to(device)


@torch.no_grad()
def collect_reconstruction_features(
    model: CalibratedAnomalyDetector,
    loader: Iterable,
    device: torch.device,
) -> np.ndarray:
    model.eval()
    rows: list[np.ndarray] = []
    for x, _ in loader:
        x = x.to(device, non_blocking=True)
        features = model.reconstruction_error_features(x)
        rows.append(features.detach().cpu().numpy())
    if not rows:
        raise ValueError("Cannot fit a literature detector from an empty loader.")
    return np.concatenate(rows, axis=0).astype(np.float32, copy=False)


@torch.no_grad()
def collect_anomaly_scores(
    model: CalibratedAnomalyDetector,
    loader: Iterable,
    device: torch.device,
) -> torch.Tensor:
    model.eval()
    rows: list[torch.Tensor] = []
    for x, _ in loader:
        x = x.to(device, non_blocking=True)
        rows.append(model.anomaly_score(x).detach().cpu())
    if not rows:
        raise ValueError("Cannot calibrate a literature detector from an empty loader.")
    return torch.cat(rows, dim=0)


def fit_rbf_svdd(
    model: VAESVDD,
    residual_features: np.ndarray,
    *,
    nu: float = 0.05,
) -> dict[str, float | int | str]:
    """Fit an RBF one-class SVM, the translation-invariant SVDD equivalent.

    For RBF kernels, one-class SVM and SVDD produce equivalent boundaries up
    to parameterization.  The fitted support-vector decision function is moved
    into torch buffers so CAT-AD's white-box attacks remain differentiable.
    """

    residuals = np.asarray(residual_features, dtype=np.float64)
    mean = residuals.mean(axis=0)
    scale = residuals.std(axis=0)
    scale = np.where(scale > 1e-8, scale, 1.0)
    normalized = (residuals - mean) / scale
    estimator = OneClassSVM(kernel="rbf", gamma="scale", nu=float(nu))
    estimator.fit(normalized)
    model.set_svdd(
        residual_mean=mean,
        residual_scale=scale,
        support_vectors=estimator.support_vectors_,
        dual_coef=estimator.dual_coef_,
        intercept=float(estimator.intercept_[0]),
        gamma=float(estimator._gamma),
    )
    normal_scores = -estimator.decision_function(normalized).reshape(-1)
    calibration = model.set_score_calibration(normal_scores)
    return {
        "kernel": "rbf",
        "nu": float(nu),
        "gamma": float(estimator._gamma),
        "support_vectors": int(estimator.support_vectors_.shape[0]),
        **calibration,
    }

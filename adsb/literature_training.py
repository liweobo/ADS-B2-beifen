"""Training utilities for protocol-aligned published ADS-B baselines."""

from __future__ import annotations

import copy
import time
from contextlib import nullcontext
from typing import Iterable

import torch

from adsb.literature_models import (
    CalibratedAnomalyDetector,
    VAESVDD,
    collect_anomaly_scores,
    collect_reconstruction_features,
    fit_rbf_svdd,
)
from adsb.train_constants import EARLY_STOP_PATIENCE, EPOCHS, GRAD_CLIP_MAX_NORM, USE_AMP


def _mean_reconstruction_loss(
    model: CalibratedAnomalyDetector,
    loader: Iterable,
    device: torch.device,
) -> float:
    model.eval()
    total = 0.0
    count = 0
    with torch.no_grad():
        for x, _ in loader:
            x = x.to(device, non_blocking=True)
            loss = model.reconstruction_loss(x)
            batch_size = int(x.shape[0])
            total += float(loss.item()) * batch_size
            count += batch_size
    if count == 0:
        raise ValueError("Validation loader is empty.")
    return total / count


def _default_learning_rate(model: CalibratedAnomalyDetector) -> float:
    # CAE's public implementation uses 3e-4; the other recurrent baselines use
    # Adam at the common experiment learning rate.
    return 3e-4 if model.__class__.__name__ == "ContextualAutoencoder" else 1e-3


def train_literature_detector(
    model: CalibratedAnomalyDetector,
    train_loader: Iterable,
    val_loader: Iterable,
    *,
    device: torch.device,
    epochs: int = EPOCHS,
    learning_rate: float | None = None,
    early_stop_patience: int = EARLY_STOP_PATIENCE,
    use_amp: bool = USE_AMP,
    svdd_nu: float = 0.05,
) -> tuple[CalibratedAnomalyDetector, dict[str, object]]:
    """Train on clean windows only, then fit/calibrate the one-class score."""

    if int(epochs) < 1:
        raise ValueError("Literature baselines require at least one training epoch.")
    lr = float(learning_rate if learning_rate is not None else _default_learning_rate(model))
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=max(int(epochs), 1))
    amp_enabled = bool(use_amp) and device.type == "cuda"
    scaler = torch.amp.GradScaler("cuda", enabled=amp_enabled)
    autocast_ctx = (
        (lambda: torch.amp.autocast(device_type="cuda", enabled=True))
        if amp_enabled
        else (lambda: nullcontext())
    )

    best_state = copy.deepcopy(model.state_dict())
    best_val = float("inf")
    wait = 0
    history: list[dict[str, float | int]] = []
    started = time.perf_counter()
    for epoch in range(int(epochs)):
        model.train()
        running = 0.0
        sample_count = 0
        for x, _ in train_loader:
            x = x.to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)
            with autocast_ctx():
                loss = model.reconstruction_loss(x)
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP_MAX_NORM)
            scaler.step(optimizer)
            scaler.update()
            batch_size = int(x.shape[0])
            running += float(loss.detach().item()) * batch_size
            sample_count += batch_size
        scheduler.step()
        train_loss = running / max(sample_count, 1)
        val_loss = _mean_reconstruction_loss(model, val_loader, device)
        history.append(
            {
                "epoch": epoch + 1,
                "train_reconstruction_objective": train_loss,
                "val_reconstruction_objective": val_loss,
                "learning_rate": float(optimizer.param_groups[0]["lr"]),
            }
        )
        print(
            f"Literature {model.__class__.__name__} epoch {epoch + 1:02d} | "
            f"train={train_loss:.6f} | val={val_loss:.6f} | "
            f"lr={optimizer.param_groups[0]['lr']:.6g}"
        )
        if val_loss < best_val - 1e-7:
            best_val = val_loss
            best_state = copy.deepcopy(model.state_dict())
            wait = 0
        else:
            wait += 1
            if wait >= int(early_stop_patience):
                print(
                    f"Literature {model.__class__.__name__} early stopping at epoch "
                    f"{epoch + 1}; best_val={best_val:.6f}"
                )
                break

    model.load_state_dict(best_state)
    model.eval()
    fit_metadata: dict[str, object]
    if isinstance(model, VAESVDD):
        residuals = collect_reconstruction_features(model, train_loader, device)
        fit_metadata = {"svdd": fit_rbf_svdd(model, residuals, nu=svdd_nu)}
    else:
        calibration = model.set_score_calibration(collect_anomaly_scores(model, train_loader, device))
        fit_metadata = {"score_calibration": calibration}

    elapsed = time.perf_counter() - started
    metadata: dict[str, object] = {
        "epochs_requested": int(epochs),
        "epochs_completed": len(history),
        "learning_rate": lr,
        "early_stop_patience": int(early_stop_patience),
        "amp_enabled": amp_enabled,
        "best_validation_reconstruction_objective": float(best_val),
        "parameter_count": int(sum(parameter.numel() for parameter in model.parameters())),
        "training_seconds": float(elapsed),
        "history": history,
        **fit_metadata,
    }
    return model, metadata

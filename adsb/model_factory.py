"""模型构建与训练超参默认值（与具体实验脚本解耦）。"""

from __future__ import annotations

import torch

from adsb.model import LSTMDetector
from adsb.train_constants import (
    EARLY_STOP_PATIENCE,
    EPOCHS,
    LR,
    USE_AMP,
)


def make_detector(device: torch.device, input_dim: int = 12) -> LSTMDetector:
    m = LSTMDetector(input_dim=input_dim).to(device)
    if device.type == "cuda" and hasattr(torch, "compile"):
        m = torch.compile(m)
    return m


def train_common_kwargs(device: torch.device) -> dict:
    return {
        "device": device,
        "epochs": EPOCHS,
        "lr": LR,
        "use_amp": USE_AMP,
        "early_stop_patience": EARLY_STOP_PATIENCE,
    }

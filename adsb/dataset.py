"""``Dataset`` 封装。标签 ``y`` 与 ``adsb.anomalies.inject`` 一致：0=正常，1=恶意（窗口内投毒≥5 步，含重叠滑窗）。"""

from __future__ import annotations

from typing import Any

import numpy as np
import torch
from torch.utils.data import Dataset


class DS(Dataset):
    """``y[i]``：0 正常，1 恶意（``long``）。"""

    def __init__(self, X, y, *, metadata: dict[str, Any] | None = None, return_metadata: bool = False):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)
        self.metadata = metadata
        self.return_metadata = bool(return_metadata)
        if metadata is not None:
            for key, values in metadata.items():
                if len(values) != len(self.X):
                    raise ValueError(f"metadata field {key!r} length does not match X")

    def __len__(self):
        return len(self.X)

    def __getitem__(self, i):
        if self.return_metadata:
            if self.metadata is None:
                raise RuntimeError("return_metadata=True but no metadata was supplied")
            item: dict[str, Any] = {}
            for key, values in self.metadata.items():
                value = values[i]
                if isinstance(value, np.generic):
                    value = value.item()
                item[key] = value
            return self.X[i], self.y[i], item
        return self.X[i], self.y[i]

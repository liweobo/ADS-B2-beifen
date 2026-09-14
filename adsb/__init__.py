"""ADS-B 轨迹异常检测实验代码包。

监督标签约定（全流水线一致）：``y=0`` 正常，``y=1`` 恶意（窗口内投毒时间步数≥5，含滑窗重叠传播）；``LSTMDetector`` 输出两维 logits，
下标 0 对应正常类、下标 1 对应恶意类（与 ``nn.CrossEntropyLoss`` 一致）。
"""

import os

# Must be set before torch initializes CuBLAS for deterministic CUDA GEMMs.
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

from adsb.data import (
    add_differential_to_windows,
    build_raw_windows,
    build_sequences,
    denormalize,
    filter_data,
    heading_to_sincos,
    load_data,
    normalize,
)

__all__ = [
    "add_differential_to_windows",
    "build_raw_windows",
    "build_sequences",
    "denormalize",
    "filter_data",
    "heading_to_sincos",
    "load_data",
    "normalize",
]

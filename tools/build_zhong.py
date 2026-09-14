"""从 adsb/ 生成整合版 zhong.py（勿手改 zhong.py，改 adsb 后重新运行本脚本）。"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADSB = ROOT / "adsb"
OUT = ROOT / "zhong.py"

HEADER = '''\
"""
ADS-B 轨迹异常检测 — 单体脚本（由 adsb 包整合生成，与 ``adsb/`` 逻辑一致）。

监督标签：``y=0`` 正常，``y=1`` 恶意（窗口内投毒时间步数达到阈值，含滑窗重叠传播）。

用法::

    conda run -n testtorch python zhong.py
    conda run -n testtorch python zhong.py --csv states_2022-06-27-23.csv
    conda run -n testtorch python zhong.py --test-checkpoint checkpoints/baseline.pt --csv your.csv

重新生成本文件（修改 adsb 后）::

    conda run -n testtorch python tools/build_zhong.py

默认输出：与本文件同目录 ``figures/``、``checkpoints/``。
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import csv
import json
import random
import sys
from collections import defaultdict
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset


def _script_dir() -> Path:
    return Path(__file__).resolve().parent


def default_project_root() -> Path:
    return _script_dir()


'''

SECTIONS = [
    ("Constants", "train_constants.py"),
    ("Data", "data.py"),
    ("Anomalies (inject)", "anomalies.py"),
    ("Dataset", "dataset.py"),
    ("Model", "model.py"),
    ("Attacks", "attacks.py"),
    ("Training", "training.py"),
    ("Fig5 epsilon sensitivity", "fig5_epsilon_sensitivity.py"),
    ("Device", "device_setup.py"),
    ("Checkpoints", "checkpoints.py"),
    ("Model factory", "model_factory.py"),
    ("DataLoaders", "dataloading.py"),
    ("Plots", "plots.py"),
    ("Trajectory compare", "trajectory_compare.py"),
    ("Paper tables", "paper_tables.py"),
    ("Fig4 ASR-PVR tradeoff", "fig4_asr_pvr_tradeoff.py"),
    ("Eval report", "eval_report.py"),
    ("Ablation", "ablation.py"),
    ("Table V ablation", "ablation_table5.py"),
    ("Inference", "inference.py"),
    ("Experiment", "experiment.py"),
    ("CLI", "cli.py"),
]

SKIP_PATTERNS = [
    r"^from adsb\.",
    r"^import adsb",
    r"^from __future__ import annotations\s*$",
    r"^if __name__ == .__main__.:",
]


def _drop_adsb_import_blocks(lines: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if re.match(r"^from adsb\.", line) or re.match(r"^import adsb\b", line):
            if "(" in line and ")" not in line:
                i += 1
                while i < n and ")" not in lines[i]:
                    i += 1
            i += 1
            continue
        out.append(line)
        i += 1
    return out


def _strip_module(text: str, fname: str) -> str:
    lines = _drop_adsb_import_blocks(text.splitlines())
    if fname == "paths.py":
        return ""
    cleaned: list[str] = []
    for line in lines:
        if fname == "dataset.py" and line.strip().startswith('"""') and "Dataset" in line:
            continue
        skip = False
        for pat in SKIP_PATTERNS:
            if re.match(pat, line):
                skip = True
                break
        if skip:
            continue
        if "from adsb.training import evaluate_with_threshold" in line:
            continue
        if "from adsb.trajectory_compare import" in line:
            continue
        cleaned.append(line)
    lines = cleaned
    # 去掉文件顶部 module docstring
    while lines and (lines[0].strip() == "" or lines[0].strip().startswith('"""') or lines[0].strip().startswith("'''")):
        if lines[0].strip().endswith('"""') and lines[0].strip().startswith('"""'):
            lines.pop(0)
            break
        if lines and lines[0].strip().startswith('"""'):
            lines.pop(0)
            while lines and not lines[0].strip().endswith('"""'):
                lines.pop(0)
            if lines:
                lines.pop(0)
            break
        lines.pop(0)
    return "\n".join(lines).strip()


def _strip_leading_imports(body: str) -> str:
    """去掉模块内开头的 import（全局 HEADER 已包含）。"""
    lines = body.splitlines()
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if s == "" or s.startswith("#"):
            i += 1
            continue
        if s.startswith("import ") or s.startswith("from "):
            i += 1
            while i < len(lines):
                t = lines[i].strip()
                if t == "" or t.startswith("#"):
                    i += 1
                    continue
                if t.startswith("import ") or t.startswith("from "):
                    i += 1
                    continue
                break
            continue
        break
    return "\n".join(lines[i:]).strip()


def _patch_body(body: str, fname: str) -> str:
    body = _strip_leading_imports(body)
    body = body.replace("Path(__file__).resolve().parent.parent", "_script_dir()")
    body = body.replace("experiment import main", "experiment import run_experiment")
    if fname == "experiment.py":
        body = re.sub(r"^def main\(", "def run_experiment(", body, count=1, flags=re.M)
    if fname == "cli.py":
        body = body.replace('default="sample_adsb_decoded.csv"', 'default="states_2022-06-27-23.csv"')
    if fname == "eval_report.py":
        body = body.replace(
            "#b_no_inj = evaluate(m1, test_loader_no_inject",
            "b_no_inj = evaluate(m1, test_loader_no_inject",
        )
        body = body.replace(
            "#print(\"Baseline (未投毒数据, y=0 正常, clean 推理):\", b_no_inj)",
            'print("Baseline (未投毒数据, y=0 正常, clean 推理):", b_no_inj)',
        )
        body = body.replace(
            "#a_no_inj = evaluate(m2, test_loader_no_inject",
            "a_no_inj = evaluate(m2, test_loader_no_inject",
        )
        body = body.replace(
            "#print(\"Adv (未投毒数据, y=0 正常, clean 推理):\", a_no_inj)",
            'print("Adv (未投毒数据, y=0 正常, clean 推理):", a_no_inj)',
        )
    if fname == "trajectory_compare.py":
        body = re.sub(r"\nif __name__ == .__main__.:[\s\S]*$", "", body)
        body = re.sub(r"\ndef _cli\(\):[\s\S]*$", "", body)
    return body


def main() -> None:
    parts = [HEADER]
    for title, fname in SECTIONS:
        path = (ADSB / fname).resolve()
        raw = path.read_text(encoding="utf-8")
        body = _strip_module(raw, fname)
        body = _patch_body(body, fname)
        parts.append(f"\n\n# {'=' * 72}\n# {title}\n# {'=' * 72}\n\n")
        parts.append(body)
        parts.append("\n")

    parts.append(
        "\n\n# ========================================================================\n"
        "# Entry\n"
        "# ========================================================================\n\n"
        "if __name__ == '__main__':\n"
        "    main_entry()\n"
    )
    OUT.write_text("".join(parts), encoding="utf-8")
    print(f"Wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()

"""工程路径：集中管理，避免各模块重复解析 ``__file__``。"""

from __future__ import annotations

from pathlib import Path


def adsb_package_dir() -> Path:
    return Path(__file__).resolve().parent


def default_project_root() -> Path:
    """含 ``adsb/``、``figures/``、``checkpoints/`` 的项目根目录。"""
    return adsb_package_dir().parent

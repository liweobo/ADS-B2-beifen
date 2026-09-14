"""Trajectory figures: PGD three-panel (lat/lon) and six-panel anomaly-type (Drift / Shift / Physical).

经纬度等用于 **绘图** 的量一律为 **反归一化后的物理量**（度、m/s 等），不使用 z-score 归一化后的数值。
``save_adv_trajectory_compare`` 在取 lat/lon 前对模型输入做 ``denormalize``；``plot_anomaly_types_six_panel``
使用未标准化的 raw 窗口 ``(T,6)``。"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import torch

from adsb.anomalies import anomaly_drift, anomaly_physical, anomaly_shift
from adsb.attacks import pgd, pgd_phys
from adsb.data import denormalize


def lat_lon_from_seq(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """X: (T, D) **反归一化后** 的特征序列；前 2 维为度制的纬度、经度（不得传入归一化后的 z-score）。"""
    return X[:, 0].astype(np.float64), X[:, 1].astype(np.float64)


def _setup_style():
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": [
                "Microsoft YaHei",
                "SimHei",
                "DejaVu Sans",
                "Arial",
                "Helvetica",
                "sans-serif",
            ],
            "axes.unicode_minus": False,
            "figure.dpi": 120,
            "savefig.dpi": 160,
        }
    )


def _denorm_batch(x: torch.Tensor, m: np.ndarray, s: np.ndarray) -> np.ndarray:
    """x: (1, T, D) float tensor -> (T, D) numpy 反归一化。"""
    xn = x.detach().float().cpu().numpy()
    return denormalize(xn, m, s)[0]


def plot_trajectory_three_panel(
    lat_lon_list: list[tuple[np.ndarray, np.ndarray, str, str]],
    out_path: Path | str,
    suptitle: str,
    share_lim: bool = True,
) -> Path:
    """
    lat_lon_list: 每项为 (lat, lon, panel_title, line_label)，须 **恰好 3 项** 对应三个子图。
    lat / lon 须为度等 **物理量**（来自反归一化序列或 raw），勿传入归一化空间坐标。
    """
    if len(lat_lon_list) != 3:
        raise ValueError(f"lat_lon_list 须含 3 项，当前为 {len(lat_lon_list)} 项")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _setup_style()

    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))
    all_lon: list[float] = []
    all_lat: list[float] = []

    for ax, (lat, lon, ptitle, _) in zip(axes, lat_lon_list):
        ax.plot(lon, lat, "b-o", markersize=3, linewidth=1.5, alpha=0.9)
        ax.set_xlabel("Longitude (deg)")
        ax.set_ylabel("Latitude (deg)")
        ax.set_title(ptitle)
        ax.grid(True, alpha=0.35)
        try:
            ax.set_aspect("equal", adjustable="datalim")
        except Exception:
            pass
        all_lon.extend(lon.tolist())
        all_lat.extend(lat.tolist())

    if share_lim and all_lon and all_lat:
        pad_lon = (max(all_lon) - min(all_lon)) * 0.08 + 1e-9
        pad_lat = (max(all_lat) - min(all_lat)) * 0.08 + 1e-9
        lo = min(all_lon) - pad_lon
        hi = max(all_lon) + pad_lon
        la = min(all_lat) - pad_lat
        hb = max(all_lat) + pad_lat
        for ax in axes:
            ax.set_xlim(lo, hi)
            ax.set_ylim(la, hb)

    fig.suptitle(suptitle, fontsize=12, y=1.02)
    fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.96))
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    return out_path


def save_adv_trajectory_compare(
    model: torch.nn.Module,
    X_norm: np.ndarray,
    y_labels: np.ndarray,
    m: np.ndarray,
    s: np.ndarray,
    device: torch.device,
    out_path: Path | str,
    sample_index: int = 0,
    adv_eps: float = 0.01,
    model_name: str = "Baseline",
) -> Path:
    """
    取一条归一化序列，用同一标签生成 PGD / 物理 PGD 扰动，反归一化后画三栏经纬度轨迹。

    ``X_norm`` / ``y_labels`` 为测试集（与评估时相同的归一化与标签）。
    ``X_norm`` 形状须为 ``(N, T, D)``（通常为 ``D=12`` 的 raw+差分特征）；``y_labels`` 形状 ``(N,)``。
    ``y_labels``：0=正常，1=恶意（与 ``inject`` / ``DS`` 一致）。

    画图与写 CSV 的经纬度均取自 **反归一化** 后的 ``(T,12)``（``_denorm_batch``），不使用归一化张量直接绘图。

    同时将上述 ``lat_c/lon_c``、``lat_f/lon_f``、``lat_p/lon_p``（物理度）写入与 ``out_path`` 同主文件名、扩展名为 ``.csv`` 的文件。
    """
    import csv

    X_norm = np.asarray(X_norm)
    y_labels = np.asarray(y_labels)
    if X_norm.ndim != 3:
        raise ValueError(f"X_norm 须为 (N, T, D) 三维数组，当前 ndim={X_norm.ndim}")
    if y_labels.ndim != 1:
        raise ValueError(f"y_labels 须为一维 (N,)，当前 shape={y_labels.shape}")
    n = int(X_norm.shape[0])
    if n != len(y_labels):
        raise ValueError(f"X_norm 与 y_labels 样本数不一致: N={n}, len(y)={len(y_labels)}")
    if n == 0:
        raise ValueError("无样本可绘制")
    idx = int(sample_index) % n

    X0 = torch.tensor(X_norm[idx : idx + 1], dtype=torch.float32, device=device)
    y0 = torch.tensor(y_labels[idx : idx + 1], dtype=torch.long, device=device)

    x_clean = _denorm_batch(X0, m, s)
    x_pgd_t = pgd(model, X0, y0, eps=float(adv_eps), m=m, s=s)
    x_pgd = _denorm_batch(x_pgd_t, m, s)
    x_phys_t = pgd_phys(model, X0, y0, m, s, eps=float(adv_eps))
    x_phys = _denorm_batch(x_phys_t, m, s)
    # 以下 lat/lon 均来自反归一化序列，非 z-score
    lat_c, lon_c = lat_lon_from_seq(x_clean)
    lat_f, lon_f = lat_lon_from_seq(x_pgd)
    lat_p, lon_p = lat_lon_from_seq(x_phys)

    triples = [
        (lat_c, lon_c, "Clean trajectory", "clean"),
        (lat_f, lon_f, "PGD perturbation", "pgd"),
        (lat_p, lon_p, "Phys-constrained PGD", "phys-pgd"),
    ]
    suptitle = (
        f"Trajectory comparison ({model_name}) | sample index {idx} | "
        f"y={int(y_labels[idx])} (0=normal,1=malicious) | ε={adv_eps}"
    )
    data_path = Path(out_path).with_suffix(".csv")
    data_path.parent.mkdir(parents=True, exist_ok=True)
    T = int(lat_c.shape[0])
    header = (
        "time_step",
        "lat_clean",
        "lon_clean",
        "lat_pgd",
        "lon_pgd",
        "lat_phys",
        "lon_phys",
    )
    with data_path.open("w", newline="", encoding="utf-8-sig") as fp:
        w = csv.writer(fp)
        w.writerow(header)
        for t in range(T):
            w.writerow(
                [
                    t,
                    float(lat_c[t]),
                    float(lon_c[t]),
                    float(lat_f[t]),
                    float(lon_f[t]),
                    float(lat_p[t]),
                    float(lon_p[t]),
                ]
            )

    fig_path = plot_trajectory_three_panel(triples, out_path, suptitle=suptitle)
    print(f"Saved trajectory lat/lon CSV: {data_path.resolve()}")
    return fig_path


def plot_anomaly_types_six_panel(
    raw_normal: np.ndarray,
    out_path: Path | str,
    *,
    attack_seed: int = 42,
    suptitle: str | None = None,
) -> Path:
    """
    2×3 图：上行未修改的 raw 窗口；下行在 **拷贝** 上分别施加 Drift / Shift / Physical（与 ``anomalies`` 一致）。

    ``raw_normal`` 形状 ``(T, 6)``：lat, lon, alt, spd, sin(hdg), cos(hdg)，物理量。
    """
    raw_normal = np.asarray(raw_normal, dtype=np.float32)
    if raw_normal.ndim != 2 or int(raw_normal.shape[1]) != 6:
        raise ValueError("raw_normal 须为 (T, 6) 的 raw 窗口")

    rng_state = np.random.get_state()
    try:
        np.random.seed(int(attack_seed))
        drift = raw_normal.copy()
        anomaly_drift(drift)
        np.random.seed(int(attack_seed) + 1000)
        shift = raw_normal.copy()
        anomaly_shift(shift)
        np.random.seed(int(attack_seed) + 2000)
        phys = raw_normal.copy()
        anomaly_physical(phys)
    finally:
        np.random.set_state(rng_state)

    T = int(raw_normal.shape[0])
    if T < 1:
        raise ValueError("raw_normal 时间长度 T 须 >= 1")
    t = np.arange(T, dtype=np.float64)
    lat = raw_normal[:, 0]
    lon = raw_normal[:, 1]
    vel = raw_normal[:, 3]
    c_h = raw_normal[:, 5]

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _setup_style()

    fig, axes = plt.subplots(2, 3, figsize=(16, 9))

    axes[0, 0].plot(t, vel, "b-o", markersize=3, linewidth=1.2, alpha=0.9)
    axes[0, 0].set_xlabel("时间步")
    axes[0, 0].set_ylabel("速度 (m/s)")
    axes[0, 0].set_title("正常数据：速度–时间步")
    axes[0, 0].grid(True, alpha=0.35)

    axes[0, 1].plot(t, c_h, "b-o", markersize=3, linewidth=1.2, alpha=0.9)
    axes[0, 1].set_xlabel("时间步")
    axes[0, 1].set_ylabel("cos(航向)")
    axes[0, 1].set_title("正常数据：航向 cos–时间步")
    axes[0, 1].grid(True, alpha=0.35)

    axes[0, 2].plot(lon, lat, "b-o", markersize=3, linewidth=1.2, alpha=0.9)
    axes[0, 2].set_xlabel("经度 (°)")
    axes[0, 2].set_ylabel("纬度 (°)")
    axes[0, 2].set_title("正常数据：纬度–经度")
    axes[0, 2].grid(True, alpha=0.35)
    try:
        axes[0, 2].set_aspect("equal", adjustable="datalim")
    except Exception:
        pass

    axes[1, 0].plot(t, drift[:, 3], "r-o", markersize=3, linewidth=1.2, alpha=0.9)
    axes[1, 0].set_xlabel("时间步")
    axes[1, 0].set_ylabel("速度 (m/s)")
    axes[1, 0].set_title("Drift 攻击：修改后速度–时间步")
    axes[1, 0].grid(True, alpha=0.35)

    axes[1, 1].plot(shift[:, 1], shift[:, 0], "r-o", markersize=3, linewidth=1.2, alpha=0.9)
    axes[1, 1].set_xlabel("经度 (°)")
    axes[1, 1].set_ylabel("纬度 (°)")
    axes[1, 1].set_title("Shift 攻击：纬度–经度")
    axes[1, 1].grid(True, alpha=0.35)
    try:
        axes[1, 1].set_aspect("equal", adjustable="datalim")
    except Exception:
        pass

    axes[1, 2].plot(t, phys[:, 3], "r-o", markersize=3, linewidth=1.2, alpha=0.9)
    axes[1, 2].set_xlabel("时间步")
    axes[1, 2].set_ylabel("速度 (m/s)")
    axes[1, 2].set_title("Physical 攻击：攻击后速度–时间步")
    axes[1, 2].grid(True, alpha=0.35)

    st = (
        suptitle
        if suptitle is not None
        else "异常类型轨迹对比（上行：正常；下行：在拷贝上施加 Drift / Shift / Physical）"
    )
    fig.suptitle(st, fontsize=12, y=1.01)
    fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.96))
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    return out_path


def _cli():
    print(
        "Trajectory figures (PGD 3-panel + anomaly-type 6-panel) are generated by default when running:\n"
        "  conda run -n testtorch python test.py\n"
        "Use --skip-trajectory to omit. Options: --trajectory-sample-index N --trajectory-adv-eps 0.01\n"
    )
    sys.exit(0)


if __name__ == "__main__":
    _cli()

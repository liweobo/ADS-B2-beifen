"""在独立 CSV 上加载 checkpoint 并跑与训练一致的评估。"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader

from adsb.anomalies import inject
from adsb.checkpoints import load_detector_checkpoint
from adsb.data import (
    add_differential_to_windows,
    build_raw_windows,
    filter_data,
    load_data,
    subset_df_by_aircraft,
)
from adsb.dataset import DS
from adsb.paths import default_project_root
from adsb.train_constants import (
    EVAL_ATTACK_EPS,
    EVAL_BATCH_SIZE,
    INJECT_RATIO,
    SEED,
    TRAJECTORY_ADV_EPS_DEFAULT,
    WINDOW_SIZE,
)
from adsb.training import evaluate


def _write_trajectory_figures(
    model: torch.nn.Module,
    X_norm: np.ndarray,
    y: np.ndarray,
    X_raw_clean: np.ndarray,
    m: np.ndarray,
    s: np.ndarray,
    device: torch.device,
    fig_root: Path,
    *,
    trajectory_sample_index: int,
    trajectory_adv_eps: float,
    tag: str,
) -> None:
    """写出 ``trajectory_compare.png`` 与 ``anomaly_types_six_panel.png``（与训练流程同名）。"""
    from adsb.trajectory_compare import plot_anomaly_types_six_panel, save_adv_trajectory_compare

    fig_root = Path(fig_root)
    fig_root.mkdir(parents=True, exist_ok=True)
    print(f"\n=== Trajectory figures ({tag}) ===")
    if len(X_norm) > 0:
        p_tc = save_adv_trajectory_compare(
            model,
            X_norm,
            y,
            m,
            s,
            device,
            fig_root / "trajectory_compare.png",
            sample_index=trajectory_sample_index,
            adv_eps=float(trajectory_adv_eps),
            model_name="Inference",
        )
        print(f"Saved trajectory comparison: {p_tc.resolve()}")
    else:
        print("Skipped trajectory_compare.png: no windows.")

    nr = len(X_raw_clean)
    if nr > 0:
        ix = int(trajectory_sample_index) % nr
        p6 = plot_anomaly_types_six_panel(
            X_raw_clean[ix],
            fig_root / "anomaly_types_six_panel.png",
            attack_seed=SEED,
            suptitle=(
                f"异常类型六子图（{tag}）| CSV 干净窗口索引 {ix} "
                f"（上行：正常；下行：Drift / Shift / Physical 作用于拷贝，随机种子={SEED}）"
            ),
        )
        print(f"Saved anomaly-type six-panel: {p6.resolve()}")
    else:
        print("Skipped anomaly_types_six_panel.png: no raw windows.")


def run_checkpoint_on_new_csv(
    checkpoint_path: Path,
    csv_path: str,
    *,
    device: torch.device,
    num_aircraft: int | None = None,
    inject_ratio: float = INJECT_RATIO,
    anomaly_types: tuple[str, ...] = ("d", "s", "p"),
    eval_eps: float = EVAL_ATTACK_EPS,
    batch_size: int = EVAL_BATCH_SIZE,
    inject_for_metrics: bool = True,
    figures_dir: Path | None = None,
    trajectory_compare: bool = True,
    trajectory_sample_index: int = 0,
    trajectory_adv_eps: float = TRAJECTORY_ADV_EPS_DEFAULT,
    window_size: int = WINDOW_SIZE,
) -> None:
    model, thr, m, s, input_dim = load_detector_checkpoint(checkpoint_path, device)  # 加载本地模型文件
    print(f"Loaded checkpoint: {Path(checkpoint_path).resolve()}")
    print(f"  input_dim={input_dim}, threshold={thr:.6f}, device={device}")

    fig_root = figures_dir if figures_dir is not None else default_project_root() / "figures"

    df = filter_data(load_data(csv_path))  # 加载新的csv文件
    n_before = df["icao"].nunique()  # 计算飞机数量
    df = subset_df_by_aircraft(df, max_aircraft=num_aircraft, random_state=SEED)
    n_after = df["icao"].nunique()  # 计算飞机数量
    if num_aircraft is not None:
        print(f"新数据飞机子集: {n_after} / 可选 {n_before} (目标 N={num_aircraft})")
    else:
        print(f"新数据飞机数: {n_after}")

    print(f"Sliding window size: {window_size}")
    X_raw, raw_prev, ids, win_starts = build_raw_windows(df, seq_len=window_size)
    if X_raw.size == 0:
        print("无可用滑窗（轨迹可能过短），退出。")
        return

    def _features_from_raw(raw_6d: np.ndarray) -> np.ndarray:
        if input_dim == 12:
            return add_differential_to_windows(raw_6d, raw_prev)
        if input_dim == 6:
            return raw_6d
        raise ValueError(f"不支持的 checkpoint input_dim={input_dim}")

    pin = device.type == "cuda"

    if not inject_for_metrics:
        X_u = _features_from_raw(X_raw.copy())
        feat_dim = int(X_u.shape[-1])
        if feat_dim != input_dim or m.shape[-1] != feat_dim:
            raise ValueError("特征维或 checkpoint 归一化与 input_dim 不匹配。")
        Xn_u = (X_u - m) / s
        y_u = np.zeros(len(Xn_u), dtype=np.int64)
        loader_u = DataLoader(
            DS(Xn_u, y_u), batch_size=batch_size, shuffle=False, pin_memory=pin, num_workers=0
        )
        model.eval()
        n_pos = 0
        n_tot = 0
        with torch.no_grad():
            for Xb, _ in loader_u:
                Xb = Xb.to(device, non_blocking=True)
                logits = model(Xb)
                prob_mal = torch.softmax(logits, dim=1)[:, 1]
                pred = (prob_mal >= thr).long()
                n_pos += int(pred.sum().item())
                n_tot += int(pred.numel())
        rate = n_pos / max(n_tot, 1)
        print(f"\n（未注入）按 checkpoint 阈值 {thr:.4f} 的预测异常占比: {rate:.4f} (n={n_tot})")

        if trajectory_compare:
            _write_trajectory_figures(
                model,
                Xn_u,
                y_u,
                X_raw,
                m,
                s,
                device,
                fig_root,
                trajectory_sample_index=trajectory_sample_index,
                trajectory_adv_eps=trajectory_adv_eps,
                tag="推理·无注入",
            )
        return

    # --- 有监督四类评估：未投毒 / 仅投毒(Clean) / 投毒+PGD / 投毒+Phys-PGD ---
    X_nop = _features_from_raw(X_raw.copy())
    feat_dim = int(X_nop.shape[-1])
    if feat_dim != input_dim:
        raise ValueError(
            f"特征维 {feat_dim} 与 checkpoint 的 input_dim={input_dim} 不一致；"
            "请确认是否使用了带差分(12)或无差分(6)的权重文件。"
        )
    if m.shape[-1] != feat_dim or s.shape[-1] != feat_dim:
        raise ValueError(
            f"checkpoint 中归一化形状 {m.shape}/{s.shape[-1]} 与特征维 {feat_dim} 不匹配。"
        )

    y_nop = np.zeros(len(X_nop), dtype=np.int64)
    Xn_nop = (X_nop - m) / s
    loader_no_inject = DataLoader(
        DS(Xn_nop, y_nop),
        batch_size=batch_size,
        shuffle=False,
        pin_memory=pin,
        num_workers=0,
    )

    X_poison, y_poison = inject(
        X_raw.copy(),
        ratio=inject_ratio,
        anomaly_types=anomaly_types,
        track_ids=ids,
        window_starts=win_starts,
    )
    X_p = _features_from_raw(X_poison)
    Xn_p = (X_p - m) / s
    loader_poison = DataLoader(
        DS(Xn_p, y_poison),
        batch_size=batch_size,
        shuffle=False,
        pin_memory=pin,
        num_workers=0,
    )

    print(f"\n=== 新数据评估（仅测试 / 推理，ε={eval_eps}）===")
    print(f"投毒对照集参数: ratio={inject_ratio}, types={anomaly_types}")

    print("\n【1】未投毒 — Clean 推理（无 inject，标签均为 y=0 正常）")
    r_no = evaluate(
        model,
        loader_no_inject,
        device=device,
        threshold=thr,
        adv_eps=eval_eps,
        physical_m=m,
        physical_s=s,
    )
    print(r_no)

    print("\n【2】仅投毒 — Clean 推理（数据已 inject，评估时不对输入加 PGD/Phys）")
    r_poison_clean = evaluate(
        model,
        loader_poison,
        device=device,
        threshold=thr,
        adv_eps=eval_eps,
        physical_m=m,
        physical_s=s,
    )
    print(r_poison_clean)

    print("\n【3】投毒 + PGD（评估阶段仅对恶意样本 y=1 做 PGD）")
    r_poison_pgd = evaluate(
        model,
        loader_poison,
        device=device,
        threshold=thr,
        mode="pgd",
        m=m,
        s=s,
        adv_eps=eval_eps,
        physical_m=m,
        physical_s=s,
    )
    print(r_poison_pgd)

    print("\n【4】投毒 + Phys-PGD（评估阶段仅对恶意样本 y=1 做 Phys-PGD）")
    r_poison_phys = evaluate(
        model,
        loader_poison,
        device=device,
        threshold=thr,
        mode="phys",
        m=m,
        s=s,
        adv_eps=eval_eps,
        physical_m=m,
        physical_s=s,
    )
    print(r_poison_phys)

    if trajectory_compare:
        _write_trajectory_figures(
            model,
            Xn_p,
            y_poison,
            X_raw,
            m,
            s,
            device,
            fig_root,
            trajectory_sample_index=trajectory_sample_index,
            trajectory_adv_eps=trajectory_adv_eps,
            tag="推理·有注入",
        )

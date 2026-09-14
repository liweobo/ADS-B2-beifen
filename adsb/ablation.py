"""消融：无差分输入与 Vanilla PGD 变体训练及结果表。"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader

from adsb.anomalies import inject
from adsb.checkpoints import save_detector_checkpoint
from adsb.data import normalize
from adsb.dataset import DS
from adsb.model_factory import make_detector
from adsb.paths import default_project_root
from adsb.train_constants import (
    ADV_CE_CLASS_WEIGHTS,
    ADV_PROJECT_PHYSICAL,
    ADV_TRAIN_EPS_ABLATION,
    ADV_TRAIN_LAMBDA,
    ADV_WARMUP_EPOCHS,
    EVAL_BATCH_SIZE,
    INJECT_RATIO,
    PGD_ALPHA,
    PGD_STEPS,
    TRAIN_BATCH_SIZE,
)
from adsb.training import evaluate, pick_best_threshold, train_adv_with_val


def run_ablation_study(
    *,
    m1,
    m2,
    device: torch.device,
    pin_memory: bool,
    train_loader: DataLoader,
    val_loader: DataLoader,
    test_loader: DataLoader,
    test_loader_no_inject: DataLoader,
    seq_no_diff: np.ndarray,
    mtr: np.ndarray,
    mva: np.ndarray,
    mte: np.ndarray,
    track_ids: np.ndarray,
    window_starts: np.ndarray,
    m: np.ndarray,
    s: np.ndarray,
    kw: dict,
    b_thr: float,
    a_thr: float,
    b_val_f1: float,
    a_val_f1: float,
    b_eval_eps: float,
    save_models: bool,
    checkpoint_dir: Path | None,
) -> None:
    print("\n=== Ablation training (vanilla PGD) ===")

    Xtr_nd, Xva_nd, Xte_nd = seq_no_diff[mtr], seq_no_diff[mva], seq_no_diff[mte]
    Xte_nd_clean = Xte_nd.copy()
    Xtr_nd, ytr_nd = inject(
        Xtr_nd,
        ratio=INJECT_RATIO,
        anomaly_types=("d", "s", "p"),
        track_ids=track_ids[mtr],
        window_starts=window_starts[mtr],
    )
    Xva_nd, yva_nd = inject(
        Xva_nd,
        ratio=INJECT_RATIO,
        anomaly_types=("d", "s", "p"),
        track_ids=track_ids[mva],
        window_starts=window_starts[mva],
    )
    Xte_nd, yte_nd = inject(
        Xte_nd,
        ratio=INJECT_RATIO,
        anomaly_types=("d", "s", "p"),
        track_ids=track_ids[mte],
        window_starts=window_starts[mte],
    )
    Xtr_nd, Xva_nd, m_nd, s_nd = normalize(Xtr_nd, Xva_nd)
    Xte_nd = (Xte_nd - m_nd) / s_nd
    Xte_nd_nop = (Xte_nd_clean - m_nd) / s_nd
    yte_nd_nop = np.zeros(len(Xte_nd_nop), dtype=np.int64)
    test_loader_nd_no_inject = DataLoader(
        DS(Xte_nd_nop, yte_nd_nop), batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0
    )
    train_loader_nd = DataLoader(
        DS(Xtr_nd, ytr_nd), batch_size=TRAIN_BATCH_SIZE, shuffle=True, pin_memory=pin_memory, num_workers=0
    )
    val_loader_nd = DataLoader(
        DS(Xva_nd, yva_nd), batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0
    )
    test_loader_nd = DataLoader(
        DS(Xte_nd, yte_nd), batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0
    )

    m5 = make_detector(device, input_dim=6)
    m5 = train_adv_with_val(
        m5,
        train_loader_nd,
        val_loader_nd,
        m_nd,
        s_nd,
        adv_eps=ADV_TRAIN_EPS_ABLATION,
        adv_lambda=ADV_TRAIN_LAMBDA,
        warmup_epochs=ADV_WARMUP_EPOCHS,
        pgd_steps=PGD_STEPS,
        pgd_alpha=PGD_ALPHA,
        project_physical=ADV_PROJECT_PHYSICAL,
        use_penalty_phys_pgd_train=False,
        class_weights=ADV_CE_CLASS_WEIGHTS,
        **kw,
    )
    print("\n=== Ablation training (differential features) ===")
    m6 = make_detector(device)
    m6 = train_adv_with_val(
        m6,
        train_loader,
        val_loader,
        m,
        s,
        project_physical=False,
        adv_eps=ADV_TRAIN_EPS_ABLATION,
        adv_lambda=ADV_TRAIN_LAMBDA,
        warmup_epochs=ADV_WARMUP_EPOCHS,
        pgd_steps=PGD_STEPS,
        pgd_alpha=PGD_ALPHA,
        use_penalty_phys_pgd_train=False,
        class_weights=ADV_CE_CLASS_WEIGHTS,
        **kw,
    )

    thr5, val_f5 = pick_best_threshold(m5, val_loader_nd, device=device)
    thr6, val_f6 = pick_best_threshold(m6, val_loader, device=device)

    ckpt_root = checkpoint_dir if checkpoint_dir is not None else default_project_root() / "checkpoints"
    if save_models:
        p5 = save_detector_checkpoint(
            ckpt_root / "ablation_no_diff.pt",
            m5,
            input_dim=6,
            threshold=thr5,
            norm_mean=m_nd,
            norm_std=s_nd,
        )
        p6 = save_detector_checkpoint(
            ckpt_root / "ablation_vanilla_pgd.pt",
            m6,
            input_dim=12,
            threshold=thr6,
            norm_mean=m,
            norm_std=s,
        )
        print(f"Saved ablation checkpoints: {p5.resolve()}, {p6.resolve()}")

    ablation_configs: list[tuple[str, object, float, float, object, object, object, object]] = [
        ("Standard training", m1, b_thr, b_val_f1, test_loader, m, s, test_loader_no_inject),
        ("Adversarial training (full)", m2, a_thr, a_val_f1, test_loader, m, s, test_loader_no_inject),
        (
            "w/o differential features (raw input)",
            m5,
            thr5,
            val_f5,
            test_loader_nd,
            m_nd,
            s_nd,
            test_loader_nd_no_inject,
        ),
        ("Vanilla PGD (no physical projection)", m6, thr6, val_f6, test_loader, m, s, test_loader_no_inject),
    ]

    ablation_metrics: list[dict[str, object]] = []
    for name, model, thr, val_f1, loader, mu, sigma, loader_nop in ablation_configs:
        cl = evaluate(
            model,
            loader,
            device=device,
            threshold=thr,
            adv_eps=b_eval_eps,
            physical_m=mu,
            physical_s=sigma,
        )
        pgd_r = evaluate(
            model,
            loader,
            device=device,
            threshold=thr,
            mode="pgd",
            m=mu,
            s=sigma,
            adv_eps=b_eval_eps,
            physical_m=mu,
            physical_s=sigma,
        )
        ph = evaluate(
            model,
            loader,
            device=device,
            threshold=thr,
            mode="phys",
            m=mu,
            s=sigma,
            adv_eps=b_eval_eps,
            physical_m=mu,
            physical_s=sigma,
        )
        ni = evaluate(
            model,
            loader_nop,
            device=device,
            threshold=thr,
            adv_eps=b_eval_eps,
            physical_m=mu,
            physical_s=sigma,
        )
        ablation_metrics.append(
            {
                "variant": name,
                "threshold": thr,
                "val_f1": val_f1,
                "clean": cl,
                "pgd": pgd_r,
                "phys": ph,
                "no_inject": ni,
            }
        )

    print("\n=== Ablation results ===")
    for row in ablation_metrics:
        name = str(row["variant"])
        thr = float(row["threshold"])
        val_f1 = float(row["val_f1"])
        cl, pgd_r, ph, ni = row["clean"], row["pgd"], row["phys"], row["no_inject"]
        print(f"\n{name} best threshold on val: {thr:.3f}, val_f1={val_f1:.4f}")
        print(f"{name} clean:", cl)
        print(f"{name} PGD:", pgd_r)
        print(f"{name} phys PGD:", ph)
        print(f"{name} (未投毒数据, y=0 正常, clean 推理):", ni)

"""主实验在测试集上的指标计算与控制台输出（与训练 / 数据模块解耦）。"""

from __future__ import annotations

import torch
from torch.utils.data import DataLoader

from adsb.training import evaluate


def report_trained_models_test_metrics(
    m1,
    m2,
    test_loader: DataLoader,
    test_loader_no_inject: DataLoader,
    *,
    b_thr: float,
    a_thr: float,
    b_val_f1: float,
    a_val_f1: float,
    b_eval_eps: float,
    device: torch.device,
    m,
    s,
    phys_penalty_lambda_max: float,
    phys_penalty_lambda_gamma: float,
    phys_penalty_use_lambda_schedule: bool,
    phys_penalty_w_speed: float,
    phys_penalty_w_altitude: float,
    phys_penalty_w_latlon: float,
    phys_penalty_w_heading: float,
    phys_penalty_use_soft_projection: bool,
    phys_penalty_projection_start_ratio: float,
    phys_penalty_final_projection: bool,
) -> dict[tuple[str, str], dict[str, float]]:
    def _eval(model, loader, *, threshold, mode=None, attack_m=None, attack_s=None):
        return evaluate(
            model,
            loader,
            device=device,
            threshold=threshold,
            mode=mode,
            m=attack_m,
            s=attack_s,
            adv_eps=b_eval_eps,
            phys_penalty_lambda_max=phys_penalty_lambda_max,
            phys_penalty_lambda_gamma=phys_penalty_lambda_gamma,
            phys_penalty_use_lambda_schedule=phys_penalty_use_lambda_schedule,
            phys_penalty_w_speed=phys_penalty_w_speed,
            phys_penalty_w_altitude=phys_penalty_w_altitude,
            phys_penalty_w_latlon=phys_penalty_w_latlon,
            phys_penalty_w_heading=phys_penalty_w_heading,
            phys_penalty_use_soft_projection=phys_penalty_use_soft_projection,
            phys_penalty_projection_start_ratio=phys_penalty_projection_start_ratio,
            phys_penalty_final_projection=phys_penalty_final_projection,
            physical_m=m,
            physical_s=s,
        )

    print("\n=== Results ===")
    print(f"Baseline best threshold on val: {b_thr:.3f}, val_f1={b_val_f1:.4f}")
    print(f"Adv best threshold on val: {a_thr:.3f}, val_f1={a_val_f1:.4f}")

    b_clean = _eval(m1, test_loader, threshold=b_thr)
    b_pgd = _eval(m1, test_loader, threshold=b_thr, mode="pgd", attack_m=m, attack_s=s)
    b_phys = _eval(m1, test_loader, threshold=b_thr, mode="phys", attack_m=m, attack_s=s)
    b_phys_penalty = _eval(m1, test_loader, threshold=b_thr, mode="phys_penalty", attack_m=m, attack_s=s)
    # 论文表格直接复用主流程评估结果，避免表格脚本重复跑模型或重新定义指标。
    table_results: dict[tuple[str, str], dict[str, float]] = {
        ("Baseline", "Clean"): b_clean,
        ("Baseline", "Standard PGD"): b_pgd,
        ("Baseline", "Projection-based phys-PGD"): b_phys,
        ("Baseline", "Penalty-based phys-PGD"): b_phys_penalty,
    }
    print("Baseline clean:", b_clean)
    print("Baseline PGD:", b_pgd)
    print("Baseline phys PGD:", b_phys)
    print("Baseline phys PGD penalty:", b_phys_penalty)
    b_no_inj = _eval(m1, test_loader_no_inject, threshold=b_thr)
    print("Baseline (未投毒数据, y=0 正常, clean 推理):", b_no_inj)

    a_clean = _eval(m2, test_loader, threshold=a_thr)
    a_pgd = _eval(m2, test_loader, threshold=a_thr, mode="pgd", attack_m=m, attack_s=s)
    a_phys = _eval(m2, test_loader, threshold=a_thr, mode="phys", attack_m=m, attack_s=s)
    a_phys_penalty = _eval(m2, test_loader, threshold=a_thr, mode="phys_penalty", attack_m=m, attack_s=s)
    table_results.update(
        {
            ("Proposed", "Clean"): a_clean,
            ("Proposed", "Standard PGD"): a_pgd,
            ("Proposed", "Projection-based phys-PGD"): a_phys,
            ("Proposed", "Penalty-based phys-PGD"): a_phys_penalty,
        }
    )
    print("Adv clean:", a_clean)
    print("Adv PGD:", a_pgd)
    print("Adv phys PGD:", a_phys)
    print("Adv phys PGD penalty:", a_phys_penalty)
    a_no_inj = _eval(m2, test_loader_no_inject, threshold=a_thr)
    print("Adv (未投毒数据, y=0 正常, clean 推理):", a_no_inj)
    return table_results

    # print(f"\n=== Per-injection-attack test (ε={b_eval_eps}; threshold 仍来自混合注入验证集) ===")
    # print("每种测试集仅注入一种异常（漂移 / 位置偏移 / 物理），与混合注入 test_loader 并列对照。")
    # print("\n--- 未投毒（标签均为 y=0 正常）---")
    # b_ni_pgd = _eval(m1, test_loader_no_inject, threshold=b_thr, mode="pgd", attack_m=m, attack_s=s)
    # b_ni_ph = _eval(m1, test_loader_no_inject, threshold=b_thr, mode="phys", attack_m=m, attack_s=s)
    # a_ni_pgd = _eval(m2, test_loader_no_inject, threshold=a_thr, mode="pgd", attack_m=m, attack_s=s)
    # a_ni_ph = _eval(m2, test_loader_no_inject, threshold=a_thr, mode="phys", attack_m=m, attack_s=s)
    # print("  Baseline clean / PGD / Phys-PGD:", b_no_inj, b_ni_pgd, b_ni_ph)
    # print("  Adv      clean / PGD / Phys-PGD:", a_no_inj, a_ni_pgd, a_ni_ph)
    # print(
    #     "  F1 summary | Baseline: "
    #     f"clean={b_no_inj['f1']:.4f} PGD={b_ni_pgd['f1']:.4f} phys={b_ni_ph['f1']:.4f} | "
    #     f"Adv: clean={a_no_inj['f1']:.4f} PGD={a_ni_pgd['f1']:.4f} phys={a_ni_ph['f1']:.4f}"
    # )
    # for attack_title, loader_pa in per_attack_test_loaders:
    #     print(f"\n--- {attack_title} ---")
    #     b_cl = _eval(m1, loader_pa, threshold=b_thr)
    #     b_pgd = _eval(m1, loader_pa, threshold=b_thr, mode="pgd", attack_m=m, attack_s=s)
    #     b_ph = _eval(m1, loader_pa, threshold=b_thr, mode="phys", attack_m=m, attack_s=s)
    #     a_cl = _eval(m2, loader_pa, threshold=a_thr)
    #     a_pgd = _eval(m2, loader_pa, threshold=a_thr, mode="pgd", attack_m=m, attack_s=s)
    #     a_ph = _eval(m2, loader_pa, threshold=a_thr, mode="phys", attack_m=m, attack_s=s)
    #     print("  Baseline clean / PGD / Phys-PGD:", b_cl, b_pgd, b_ph)
    #     print("  Adv      clean / PGD / Phys-PGD:", a_cl, a_pgd, a_ph)
    #     print(
    #         "  F1 summary | Baseline: "
    #         f"clean={b_cl['f1']:.4f} PGD={b_pgd['f1']:.4f} phys={b_ph['f1']:.4f} | "
    #         f"Adv: clean={a_cl['f1']:.4f} PGD={a_pgd['f1']:.4f} phys={a_ph['f1']:.4f}"
    #     )

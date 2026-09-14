"""端到端训练与评估主流程（编排数据、模型、检查点与图表）。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import torch

from adsb.ablation_table5 import run_table5_ablation_study
from adsb.checkpoints import (
    CheckpointIdentity,
    code_fingerprint,
    save_detector_checkpoint,
    sha256_file,
    sha256_json,
)
from adsb.data import filter_data, load_data, subset_df_by_aircraft
from adsb.dataloading import prepare_train_val_test_loaders
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.eval_report import report_trained_models_test_metrics
from adsb.fig4_asr_pvr_tradeoff import (
    collect_fig4_data_from_tables,
    plot_fig_physical_valid_asr,
    write_fig4_data_csv,
)
from adsb.fig5_epsilon_sensitivity import FIG5_EPS_LIST, generate_fig5_from_models
from adsb.model_factory import make_detector, train_common_kwargs
from adsb.paper_tables import (
    write_experimental_setup_table,
    write_table_clean_performance,
    write_table4_physical_feasibility,
    write_table_robustness_summary,
    write_test_set_results_csv,
)
from adsb.paths import default_project_root
from adsb.plots import plot_fig_main_robustness
from adsb.train_constants import (
    ADV_CE_CLASS_WEIGHTS,
    ADV_PROJECT_PHYSICAL,
    ADV_TRAIN_EPS,
    ADV_TRAIN_LAMBDA,
    ADV_WARMUP_EPOCHS,
    BASELINE_CE_CLASS_WEIGHTS,
    EVAL_ATTACK_EPS,
    PGD_ALPHA,
    PGD_STEPS,
    PHYS_FEAT_LAMBDA,
    PHYS_OUT_LAMBDA,
    PHYS_PENALTY_FINAL_PROJECTION,
    PHYS_PENALTY_LAMBDA_GAMMA,
    PHYS_PENALTY_LAMBDA_MAX,
    PHYS_PENALTY_PROJECTION_START_RATIO,
    PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
    PHYS_PENALTY_USE_SOFT_PROJECTION,
    PHYS_PENALTY_W_ALTITUDE,
    PHYS_PENALTY_W_HEADING,
    PHYS_PENALTY_W_LATLON,
    PHYS_PENALTY_W_SPEED,
    PHYS_TEMPERATURE,
    SEED,
    USE_PENALTY_PHYS_PGD_TRAIN,
    WINDOW_SIZE,
)
from adsb.training import pick_best_threshold, train_adv_with_val, train_with_val
from adsb.utils import set_seed


def main(
    run_ablation_plots: bool = True,
    csv_path: str = "sample_adsb_decoded.csv",
    figures_dir: Path | None = None,
    num_aircraft: int | None = None,
    save_models: bool = True,
    checkpoint_dir: Path | None = None,
    window_size: int = WINDOW_SIZE,
    phys_penalty_lambda_max: float = PHYS_PENALTY_LAMBDA_MAX,
    phys_penalty_lambda_gamma: float = PHYS_PENALTY_LAMBDA_GAMMA,
    phys_penalty_use_lambda_schedule: bool = PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
    phys_penalty_w_speed: float = PHYS_PENALTY_W_SPEED,
    phys_penalty_w_altitude: float = PHYS_PENALTY_W_ALTITUDE,
    phys_penalty_w_latlon: float = PHYS_PENALTY_W_LATLON,
    phys_penalty_w_heading: float = PHYS_PENALTY_W_HEADING,
    phys_penalty_use_soft_projection: bool = PHYS_PENALTY_USE_SOFT_PROJECTION,
    phys_penalty_projection_start_ratio: float = PHYS_PENALTY_PROJECTION_START_RATIO,
    phys_penalty_final_projection: bool = PHYS_PENALTY_FINAL_PROJECTION,
    use_penalty_phys_pgd_train: bool = USE_PENALTY_PHYS_PGD_TRAIN,
    seed: int = SEED,
    deterministic: bool = False,
    max_epochs: int | None = None,
    output_root: Path | None = None,
    make_paper_exports: bool = True,
) -> dict[str, Any]:
    set_seed(seed)
    device = resolve_device()
    print("Using device:", device)
    configure_cuda_training(device, deterministic=deterministic)

    project_root = default_project_root()
    out_root = output_root if output_root is not None else project_root / "outputs"
    result_root = out_root / "results" if output_root is not None else project_root / "results"
    fig_root = figures_dir if figures_dir is not None else (
        out_root / "figures" if output_root is not None else project_root / "figures"
    )
    ckpt_default_root = out_root / "checkpoints" if output_root is not None else project_root / "checkpoints"
    fig_root.mkdir(parents=True, exist_ok=True)
    out_root.mkdir(parents=True, exist_ok=True)
    result_root.mkdir(parents=True, exist_ok=True)

    loaded_df = load_data(csv_path)
    filtered_df = filter_data(loaded_df)      #加载并过滤数据
    n_loaded_rows = int(len(loaded_df))
    n_filtered_rows = int(len(filtered_df))
    n_loaded_aircraft = int(loaded_df["icao"].nunique())
    n_before = int(filtered_df["icao"].nunique())      #过滤后数据集中的飞机数量
    df = subset_df_by_aircraft(filtered_df, max_aircraft=num_aircraft, random_state=seed)      #子集数据集
    n_after = int(df["icao"].nunique())      #子集数据集中的飞机数量
    data_summary = {
        "csv_path": str(csv_path),
        "rows_loaded": n_loaded_rows,
        "rows_after_filter": n_filtered_rows,
        "rows_after_subset": int(len(df)),
        "aircraft_loaded": n_loaded_aircraft,
        "aircraft_after_filter": n_before,
        "aircraft_after_subset": n_after,
    }
    if num_aircraft is not None:
        print(f"Aircraft subset: {n_after} aircraft kept of {n_before} available (target N={num_aircraft})")
    else:
        print(f"Aircraft subset: using all {n_after} aircraft")

    pin = device.type == "cuda"
    print(f"Sliding window size: {window_size}")
    pack = prepare_train_val_test_loaders(df, pin_memory=pin, random_state=seed, window_size=window_size)
    m, s = pack.norm_mean, pack.norm_std      #训练集和验证集的均值和标准差

    kw = train_common_kwargs(device)
    if max_epochs is not None:
        kw["epochs"] = int(max_epochs)      #训练超参数

    m1 = make_detector(device)      #创建模型
    m1 = train_with_val(
        m1, pack.train_loader, pack.val_loader, class_weights=BASELINE_CE_CLASS_WEIGHTS, **kw
    )       #正常训练模型开始函数

    m2 = make_detector(device)      #创建模型
    m2 = train_adv_with_val(
        m2,     #对抗训练模型开始函数
        pack.train_loader,    #训练数据集
        pack.val_loader,    #验证数据集
        m,    #训练集和验证集的均值
        s,    #训练集和验证集的标准差
        adv_eps=ADV_TRAIN_EPS,    #对抗训练的epsilon
        adv_lambda=ADV_TRAIN_LAMBDA,    #对抗训练的lambda
        warmup_epochs=ADV_WARMUP_EPOCHS,    #对抗训练的warmup epoch
        pgd_steps=PGD_STEPS,
        pgd_alpha=PGD_ALPHA,    #对抗训练的pgd alpha
        project_physical=ADV_PROJECT_PHYSICAL,
        use_penalty_phys_pgd_train=use_penalty_phys_pgd_train,
        lambda_phys_max=phys_penalty_lambda_max,
        lambda_phys_gamma=phys_penalty_lambda_gamma,
        use_lambda_schedule=phys_penalty_use_lambda_schedule,
        use_soft_projection=phys_penalty_use_soft_projection,
        projection_start_ratio=phys_penalty_projection_start_ratio,
        final_projection=phys_penalty_final_projection,
        phys_out_lambda=PHYS_OUT_LAMBDA,
        phys_feat_lambda=PHYS_FEAT_LAMBDA,
        phys_temperature=PHYS_TEMPERATURE,
        class_weights=ADV_CE_CLASS_WEIGHTS,
        early_stop_metric="clean_f1",
        **kw,
    )

    b_eval_eps = EVAL_ATTACK_EPS
    b_thr, b_val_f1 = pick_best_threshold(m1, pack.val_loader, device=device)   #确定正常训练最好的阈值和F1分数
    a_thr, a_val_f1 = pick_best_threshold(m2, pack.val_loader, device=device)   #确定对抗训练最好的阈值和F1分数

    table_metrics = report_trained_models_test_metrics(
        m1,
        m2,
        pack.test_loader,
        pack.test_loader_no_inject,       #未投毒的测试数据集
        b_thr=b_thr,       #正常训练最好的阈值
        a_thr=a_thr,       #对抗训练最好的阈值
        b_val_f1=b_val_f1, #正常训练最好的F1分数
        a_val_f1=a_val_f1, #对抗训练最好的F1分数
        b_eval_eps=b_eval_eps,
        device=device,
        m=m,       #训练集和验证集的均值
        s=s,       #训练集和验证集的标准差
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
    )
    if not make_paper_exports:
        return {
            "seed": int(seed),
            "csv_path": str(csv_path),
            "num_aircraft": num_aircraft,
            "window_size": int(window_size),
            "device": str(device),
            "deterministic": bool(deterministic),
            "epochs": int(kw["epochs"]),
            "data_summary": data_summary,
            "split_summary": pack.split_summary,
            "metrics": table_metrics,
            "thresholds": {
                "baseline": float(b_thr),
                "proposed": float(a_thr),
            },
            "validation_f1": {
                "baseline": float(b_val_f1),
                "proposed": float(a_val_f1),
            },
            "artifacts": {
                "tables": [],
                "figures": [],
                "data": [],
                "table5_summary": None,
            },
        }
    # 主流程评估完成后立即导出论文表格与主图，保证数值与控制台评估完全一致。
    table_root = out_root / "tables"
    table_root = out_root / "tables"
    generated_tables: list[Path] = []
    generated_figures: list[Path] = []
    table5_summary: Path | None = None

    for _csv, tex in (
        write_experimental_setup_table(table_root),
        write_table_clean_performance(table_metrics, table_root),
        write_table_robustness_summary(table_metrics, table_root),
        write_table4_physical_feasibility(table_metrics, table_root),
    ):
        generated_tables.append(tex)
    write_test_set_results_csv(table_metrics, out_root)

    if run_ablation_plots:
        # Table V 消融实验纳入主流程；每次重新训练变体，不保存/复用中间 checkpoint 或 metrics。
        table5_summary = run_table5_ablation_study(
            csv_path=csv_path,
            output_root=out_root / "ablation_table5",
            table_dir=table_root,
            device=device,
            num_aircraft=num_aircraft,
            window_size=window_size,
            adv_eps=ADV_TRAIN_EPS,
            eval_eps=EVAL_ATTACK_EPS,
            pgd_alpha=PGD_ALPHA,
            pgd_steps=PGD_STEPS,
        )
        print(f"Saved Table V ablation summary: {table5_summary.resolve()}")

    main_robustness_paths = plot_fig_main_robustness(table3_results=table_metrics, figures_dir=fig_root)
    generated_figures.extend(main_robustness_paths.values())

    fig_phys_rows = collect_fig4_data_from_tables(table_metrics, table_metrics)
    fig_phys_csv = write_fig4_data_csv(
        fig_phys_rows,
        result_root / "fig_physical_valid_asr_data.csv",
    )
    fig_phys_paths = plot_fig_physical_valid_asr(fig_phys_rows, figures_dir=fig_root)
    generated_figures.extend(fig_phys_paths.values())

    print("\n=== Paper exports ===")
    for path in generated_tables:
        print(f"Table: {path.resolve()}")
    print(f"Figure data: {fig_phys_csv.resolve()}")
    for path in generated_figures:
        print(f"Figure: {path.resolve()}")

    # if trajectory_compare:
    #     from adsb.trajectory_compare import plot_anomaly_types_six_panel, save_adv_trajectory_compare

    #     print("\n=== Test phase: trajectory figures (test split) ===")
    #     Xte_np = pack.test_loader.dataset.X.cpu().numpy()
    #     yte_np = pack.test_loader.dataset.y.cpu().numpy()
    #     p_tc = save_adv_trajectory_compare(
    #         m1,
    #         Xte_np,
    #         yte_np,
    #         m,
    #         s,
    #         device,
    #         fig_root / "trajectory_compare.png",
    #         sample_index=trajectory_sample_index,
    #         adv_eps=trajectory_adv_eps,
    #         model_name="Baseline",
    #     )
    #     print(f"Saved trajectory comparison (clean / PGD / Phys-PGD): {p_tc.resolve()}")
    #     n_raw = len(pack.test_raw_windows_clean)
    #     if n_raw > 0:
    #         ix = int(trajectory_sample_index) % n_raw
    #         p6 = plot_anomaly_types_six_panel(
    #             pack.test_raw_windows_clean[ix],
    #             fig_root / "anomaly_types_six_panel.png",
    #             attack_seed=SEED,
    #             suptitle=(
    #                 f"异常类型六子图（测试阶段）| 测试集干净窗口索引 {ix} "
    #                 f"（上行：正常；下行：Drift / Shift / Physical 作用于拷贝，随机种子={SEED}）"
    #             ),
    #         )
    #         print(f"Saved anomaly-type six-panel trajectory: {p6.resolve()}")
    #     else:
    #         print("Skipped anomaly-type six-panel: no clean test raw windows.")

    if save_models:
        ckpt_root = checkpoint_dir if checkpoint_dir is not None else ckpt_default_root
        checkpoint_config = {
            "schema": "adsb.training-config.v1",
            "seed": int(seed),
            "window_size": int(window_size),
            "max_epochs": None if max_epochs is None else int(max_epochs),
            "adv_train_epsilon": float(ADV_TRAIN_EPS),
            "pgd_alpha": float(PGD_ALPHA),
            "pgd_steps": int(PGD_STEPS),
            "use_penalty_phys_pgd_train": bool(use_penalty_phys_pgd_train),
            "phys_penalty_lambda_max": float(phys_penalty_lambda_max),
            "phys_penalty_projection_start_ratio": float(phys_penalty_projection_start_ratio),
            "phys_penalty_final_projection": bool(phys_penalty_final_projection),
        }
        shared_identity = {
            "split_hash": sha256_json(pack.split_summary),
            "dataset_hash": sha256_file(Path(csv_path)),
            "code_fingerprint": code_fingerprint(project_root),
        }
        baseline_identity = CheckpointIdentity(
            config_hash=sha256_json({**checkpoint_config, "training_regime": "erm"}),
            **shared_identity,
        )
        adversarial_identity = CheckpointIdentity(
            config_hash=sha256_json({**checkpoint_config, "training_regime": "adversarial"}),
            **shared_identity,
        )
        p_b = save_detector_checkpoint(
            ckpt_root / "baseline.pt",
            m1,
            input_dim=12,
            threshold=b_thr,
            norm_mean=m,
            norm_std=s,
            identity=baseline_identity,
        )
        p_a = save_detector_checkpoint(
            ckpt_root / "adv_full.pt",
            m2,
            input_dim=12,
            threshold=a_thr,
            norm_mean=m,
            norm_std=s,
            identity=adversarial_identity,
        )
        print(f"\nSaved checkpoints: {p_b.resolve()}, {p_a.resolve()}")
    else:
        p_b = Path("current_run_baseline")
        p_a = Path("current_run_proposed")

    fig5_paths = generate_fig5_from_models(
        baseline_model=m1,
        proposed_model=m2,
        test_loader=pack.test_loader,
        device=device,
        m=m,
        s=s,
        baseline_threshold=b_thr,
        proposed_threshold=a_thr,
        figures_dir=fig_root,
        results_dir=result_root,
        eps_list=FIG5_EPS_LIST,
        attacks=("projection_phys_pgd", "penalty_phys_pgd"),
        baseline_checkpoint_path=p_b,
        proposed_checkpoint_path=p_a,
        pgd_alpha=PGD_ALPHA,
        pgd_steps=PGD_STEPS,
    )
    print(
        "Saved epsilon sensitivity figure: "
        f"{fig5_paths['pdf'].resolve()}, {fig5_paths['png'].resolve()}, {fig5_paths['svg'].resolve()}"
    )
    generated_figures.extend(fig5_paths.values())

    return {
        "seed": int(seed),
        "csv_path": str(csv_path),
        "num_aircraft": num_aircraft,
        "window_size": int(window_size),
        "device": str(device),
        "deterministic": bool(deterministic),
        "epochs": int(kw["epochs"]),
        "data_summary": data_summary,
        "split_summary": pack.split_summary,
        "metrics": table_metrics,
        "thresholds": {
            "baseline": float(b_thr),
            "proposed": float(a_thr),
        },
        "validation_f1": {
            "baseline": float(b_val_f1),
            "proposed": float(a_val_f1),
        },
        "artifacts": {
            "tables": [str(path.resolve()) for path in generated_tables],
            "figures": [str(path.resolve()) for path in generated_figures],
            "data": [str(fig_phys_csv.resolve())],
            "table5_summary": str(table5_summary.resolve()) if table5_summary is not None else None,
        },
    }

    # if run_ablation_plots:
    #     run_ablation_study(
    #         m1=m1,
    #         m2=m2,
    #         device=device,
    #         pin_memory=pin,
    #         train_loader=pack.train_loader,
    #         val_loader=pack.val_loader,
    #         test_loader=pack.test_loader,
    #         test_loader_no_inject=pack.test_loader_no_inject,
    #         seq_no_diff=pack.seq_no_diff,
    #         mtr=pack.mtr,
    #         mva=pack.mva,
    #         mte=pack.mte,
    #         track_ids=pack.track_ids,
    #         window_starts=pack.window_starts,
    #         m=m,
    #         s=s,
    #         kw=kw,
    #         b_thr=b_thr,
    #         a_thr=a_thr,
    #         b_eval_eps=b_eval_eps,
    #         save_models=save_models,
    #         checkpoint_dir=checkpoint_dir,
    #         b_val_f1=b_val_f1,
    #         a_val_f1=a_val_f1,
    #     )

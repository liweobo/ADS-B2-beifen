"""Table V 消融实验：主流程内置实现。"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch.utils.data import DataLoader

from adsb.anomalies import inject
from adsb.data import filter_data, load_data, normalize, subset_df_by_aircraft
from adsb.dataloading import prepare_train_val_test_loaders
from adsb.dataset import DS
from adsb.device_setup import configure_cuda_training, resolve_device
from adsb.model_factory import make_detector, train_common_kwargs
from adsb.paper_naming import ablation_display_name
from adsb.train_constants import (
    ADV_CE_CLASS_WEIGHTS,
    ADV_TRAIN_EPS,
    ADV_TRAIN_LAMBDA,
    ADV_WARMUP_EPOCHS,
    BASELINE_CE_CLASS_WEIGHTS,
    EVAL_ATTACK_EPS,
    EVAL_BATCH_SIZE,
    INJECT_RATIO,
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
    PHYS_TEMPERATURE,
    SEED,
    TRAIN_BATCH_SIZE,
    WINDOW_SIZE,
)
from adsb.training import evaluate, pick_best_threshold, train_adv_with_val, train_with_val
from adsb.utils import set_seed


ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Table5Variant:
    slug: str
    name: str
    train_kind: str
    input_dim: int = 12
    use_seq_no_diff: bool = False
    use_penalty_phys_pgd_train: bool = True
    project_physical: bool = True
    phys_out_lambda: float = PHYS_OUT_LAMBDA
    phys_feat_lambda: float = PHYS_FEAT_LAMBDA


TABLE5_VARIANTS = [
    Table5Variant("standard_training", "Standard training", "standard"),
    Table5Variant(
        "vanilla_pgd_adv_training",
        "Vanilla PGD adversarial training",
        "adv",
        use_penalty_phys_pgd_train=False,
        project_physical=False,
        phys_out_lambda=0.0,
        phys_feat_lambda=0.0,
    ),
    Table5Variant(
        "projection_phys_pgd_adv_training",
        "Projection-based phys-PGD adversarial training",
        "adv",
        use_penalty_phys_pgd_train=False,
        project_physical=True,
        phys_out_lambda=0.0,
        phys_feat_lambda=0.0,
    ),
    Table5Variant(
        "penalty_phys_pgd_wo_consistency",
        "Penalty-based phys-PGD w/o consistency",
        "adv",
        use_penalty_phys_pgd_train=True,
        phys_out_lambda=0.0,
        phys_feat_lambda=0.0,
    ),
    Table5Variant(
        "output_consistency_only",
        "Output consistency only",
        "adv",
        use_penalty_phys_pgd_train=True,
        phys_out_lambda=PHYS_OUT_LAMBDA,
        phys_feat_lambda=0.0,
    ),
    Table5Variant(
        "representation_consistency_only",
        "Representation consistency only",
        "adv",
        use_penalty_phys_pgd_train=True,
        phys_out_lambda=0.0,
        phys_feat_lambda=PHYS_FEAT_LAMBDA,
    ),
    Table5Variant(
        "full_proposed_method",
        "Full proposed method",
        "adv",
        use_penalty_phys_pgd_train=True,
        phys_out_lambda=PHYS_OUT_LAMBDA,
        phys_feat_lambda=PHYS_FEAT_LAMBDA,
    ),
    Table5Variant(
        "full_proposed_wo_differential_features",
        "Full proposed method w/o differential features",
        "adv",
        input_dim=6,
        use_seq_no_diff=True,
        use_penalty_phys_pgd_train=True,
        phys_out_lambda=PHYS_OUT_LAMBDA,
        phys_feat_lambda=PHYS_FEAT_LAMBDA,
    ),
]


def _format_metric(value: Any) -> str:
    if value is None:
        return "--"
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "--"


def _tex_escape(text: str) -> str:
    text = str(text)
    if "$" in text:
        return text
    return text.replace("&", r"\&").replace("%", r"\%").replace("_", r"\_")


def _build_no_diff_loaders(pack, *, pin_memory: bool):
    """构造 raw 6 维输入，保持主流程 train/val/test 划分不变。"""
    xtr = pack.seq_no_diff[pack.mtr].copy()
    xva = pack.seq_no_diff[pack.mva].copy()
    xte = pack.seq_no_diff[pack.mte].copy()
    xtr, ytr = inject(
        xtr,
        ratio=INJECT_RATIO,
        anomaly_types=("d", "s", "p"),
        track_ids=pack.track_ids[pack.mtr],
        window_starts=pack.window_starts[pack.mtr],
    )
    xva, yva = inject(
        xva,
        ratio=INJECT_RATIO,
        anomaly_types=("d", "s", "p"),
        track_ids=pack.track_ids[pack.mva],
        window_starts=pack.window_starts[pack.mva],
    )
    xte, yte = inject(
        xte,
        ratio=INJECT_RATIO,
        anomaly_types=("d", "s", "p"),
        track_ids=pack.track_ids[pack.mte],
        window_starts=pack.window_starts[pack.mte],
    )
    xtr, xva, m, s = normalize(xtr, xva)
    xte = (xte - m) / s
    return (
        DataLoader(DS(xtr, ytr), batch_size=TRAIN_BATCH_SIZE, shuffle=True, pin_memory=pin_memory, num_workers=0),
        DataLoader(DS(xva, yva), batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0),
        DataLoader(DS(xte, yte), batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0),
        m,
        s,
    )


def _variant_loaders(variant: Table5Variant, pack, *, pin_memory: bool):
    if variant.use_seq_no_diff:
        return _build_no_diff_loaders(pack, pin_memory=pin_memory)
    return pack.train_loader, pack.val_loader, pack.test_loader, pack.norm_mean, pack.norm_std


def _train_variant(variant: Table5Variant, *, device, train_loader, val_loader, m, s, cfg):
    set_seed(SEED)
    model = make_detector(device, input_dim=variant.input_dim)
    common = train_common_kwargs(device)
    if cfg["epochs"] is not None:
        common["epochs"] = int(cfg["epochs"])
    if variant.train_kind == "standard":
        return train_with_val(
            model,
            train_loader,
            val_loader,
            class_weights=BASELINE_CE_CLASS_WEIGHTS,
            **common,
        )
    return train_adv_with_val(
        model,
        train_loader,
        val_loader,
        m,
        s,
        adv_eps=cfg["adv_eps"],
        adv_lambda=ADV_TRAIN_LAMBDA,
        warmup_epochs=ADV_WARMUP_EPOCHS,
        pgd_steps=cfg["pgd_steps"],
        pgd_alpha=cfg["pgd_alpha"],
        project_physical=variant.project_physical,
        use_penalty_phys_pgd_train=variant.use_penalty_phys_pgd_train,
        lambda_phys_max=PHYS_PENALTY_LAMBDA_MAX,
        lambda_phys_gamma=PHYS_PENALTY_LAMBDA_GAMMA,
        use_lambda_schedule=PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
        use_soft_projection=PHYS_PENALTY_USE_SOFT_PROJECTION,
        projection_start_ratio=PHYS_PENALTY_PROJECTION_START_RATIO,
        final_projection=PHYS_PENALTY_FINAL_PROJECTION,
        phys_out_lambda=variant.phys_out_lambda,
        phys_feat_lambda=variant.phys_feat_lambda,
        phys_temperature=PHYS_TEMPERATURE,
        class_weights=ADV_CE_CLASS_WEIGHTS,
        early_stop_metric="clean_f1",
        **common,
    )


def _evaluate_variant(model, *, test_loader, val_loader, device, m, s, cfg):
    threshold, val_f1 = pick_best_threshold(model, val_loader, device=device)
    common = dict(device=device, threshold=threshold, adv_eps=cfg["eval_eps"], physical_m=m, physical_s=s)
    clean = evaluate(model, test_loader, **common)
    phys = evaluate(model, test_loader, mode="phys", m=m, s=s, **common)
    penalty = evaluate(
        model,
        test_loader,
        mode="phys_penalty",
        m=m,
        s=s,
        pgd_alpha=cfg["pgd_alpha"],
        pgd_steps=cfg["pgd_steps"],
        **common,
    )
    return {
        "threshold": float(threshold),
        "val_f1": float(val_f1),
        "clean": clean,
        "phys": phys,
        "phys_penalty": penalty,
    }


def _row_from_result(variant_name: str, result: dict[str, Any] | None) -> dict[str, str]:
    if not result:
        return {
            "Variant": variant_name,
            "Unperturbed F1": "--",
            "Projection F1": "--",
            "Penalty F1": "--",
            "Penalty ASR": "--",
            "Penalty PV-ASR": "--",
            "FAR": "--",
        }
    clean = result.get("clean", {})
    phys = result.get("phys", {})
    penalty = result.get("phys_penalty", {})
    return {
        "Variant": variant_name,
        "Unperturbed F1": _format_metric(clean.get("f1")),
        "Projection F1": _format_metric(phys.get("f1")),
        "Penalty F1": _format_metric(penalty.get("f1")),
        "Penalty ASR": _format_metric(penalty.get("asr")),
        "Penalty PV-ASR": _format_metric(penalty.get("pv_asr")),
        "FAR": _format_metric(penalty.get("far", clean.get("far"))),
    }


def _write_table5(rows: list[dict[str, str]], table_dir: Path) -> tuple[Path, Path]:
    table_dir.mkdir(parents=True, exist_ok=True)
    headers = ["Variant", "Unperturbed F1", "Projection F1", "Penalty F1", "Penalty ASR", "Penalty PV-ASR", "FAR"]
    csv_path = table_dir / "table5_ablation_study.csv"
    tex_path = table_dir / "table5_ablation_study.tex"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        r"\begin{table*}[!ht]",
        r"\centering",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{3pt}",
        r"\renewcommand{\arraystretch}{1.10}",
        r"\caption{Ablation study of CAT-AD}",
        r"\label{tab:ablation}",
        r"\begin{tabular}{lcccccc}",
        r"\toprule",
        r"Variant & Unpert. F1 & Proj. F1 & \multicolumn{3}{c}{Penalty Phys-PGD} & FAR \\",
        r"\cmidrule(lr){4-6}",
        r" & & & F1 & ASR & PV-ASR & \\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(" & ".join(_tex_escape(row[h]) for h in headers) + r" \\")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\vspace{1mm}",
            r"\begin{minipage}{0.98\textwidth}",
            r"\footnotesize ERM denotes empirical risk minimization. PGD-AT denotes adversarial training "
            r"with norm-bounded PGD without physical constraints. Projection Phys-PGD-AT and Penalty Phys-PGD-AT denote adversarial "
            r"training with projection-based and penalty-based physically constrained PGD, respectively. "
            r"Prediction Consistency and Feature Consistency denote consistency regularization at the "
            r"prediction and feature levels. Unpert., Proj., and Pen. denote unperturbed evaluation, "
            r"Projection-based Phys-PGD, and Penalty-based Phys-PGD, respectively; $\Delta X$ denotes "
            r"temporal-difference features. Lower ASR, PV-ASR, and FAR are better.",
            r"\end{minipage}",
            r"\end{table*}",
            "",
        ]
    )
    tex_path.write_text("\n".join(lines), encoding="utf-8")
    return csv_path, tex_path


def _missing_metrics(rows: list[dict[str, str]]) -> list[str]:
    missing = []
    for row in rows:
        for key, value in row.items():
            if key != "Variant" and value == "--":
                missing.append(f"{row['Variant']} | {key}")
    return missing


def run_table5_ablation_study(
    *,
    csv_path: str | Path = ROOT / "sample_adsb_decoded.csv",
    output_root: str | Path = ROOT / "outputs" / "ablation_table5",
    table_dir: str | Path = ROOT / "outputs" / "tables",
    device: str | torch.device | None = None,
    num_aircraft: int | None = None,
    window_size: int = WINDOW_SIZE,
    epochs: int | None = None,
    adv_eps: float = ADV_TRAIN_EPS,
    eval_eps: float = EVAL_ATTACK_EPS,
    pgd_alpha: float = PGD_ALPHA,
    pgd_steps: int = PGD_STEPS,
) -> Path:
    """生成 Table V 消融结果；每次调用均重新训练，不保存或复用变体缓存。"""
    set_seed(SEED)
    device = torch.device(device) if device is not None else resolve_device()
    configure_cuda_training(device)
    pin_memory = device.type == "cuda"
    output_root = Path(output_root)
    table_dir = Path(table_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    df = filter_data(load_data(str(csv_path)))
    df = subset_df_by_aircraft(df, max_aircraft=num_aircraft, random_state=SEED)
    pack = prepare_train_val_test_loaders(df, pin_memory=pin_memory, random_state=SEED, window_size=window_size)

    cfg_base = {
        "epochs": epochs,
        "adv_eps": adv_eps,
        "eval_eps": eval_eps,
        "pgd_alpha": pgd_alpha,
        "pgd_steps": pgd_steps,
    }
    summary: dict[str, Any] = {
        "paper_model_name": "BiLSTM-based trajectory anomaly detector",
        "seed": SEED,
        "variants": {},
        "warnings": [],
    }
    rows: list[dict[str, str]] = []

    for variant in TABLE5_VARIANTS:
        print(f"\n=== Table V variant: {variant.name} ===")
        train_loader, val_loader, test_loader, m, s = _variant_loaders(variant, pack, pin_memory=pin_memory)
        variant_cfg = {
            **cfg_base,
            "name": variant.name,
            "paper_name": ablation_display_name(variant.name),
            "slug": variant.slug,
            "train_kind": variant.train_kind,
            "input_dim": variant.input_dim,
            "use_seq_no_diff": variant.use_seq_no_diff,
            "use_penalty_phys_pgd_train": variant.use_penalty_phys_pgd_train,
            "project_physical": variant.project_physical,
            "phys_out_lambda": variant.phys_out_lambda,
            "phys_feat_lambda": variant.phys_feat_lambda,
        }
        print(json.dumps({"variant_config": variant_cfg}, ensure_ascii=False, indent=2))
        model = _train_variant(
            variant,
            device=device,
            train_loader=train_loader,
            val_loader=val_loader,
            m=m,
            s=s,
            cfg=cfg_base,
        )
        result = _evaluate_variant(
            model,
            test_loader=test_loader,
            val_loader=val_loader,
            device=device,
            m=m,
            s=s,
            cfg=cfg_base,
        )
        print(json.dumps({"variant_result": result}, ensure_ascii=False, indent=2))

        row = _row_from_result(ablation_display_name(variant.name), result)
        rows.append(row)
        summary["variants"][variant.slug] = {
            "name": variant.name,
            "paper_name": ablation_display_name(variant.name),
            "config": variant_cfg,
            "threshold": result.get("threshold"),
            "val_f1": result.get("val_f1"),
            "row": row,
        }
        print(
            f"{variant.name}: threshold={_format_metric(result.get('threshold'))} "
            f"val_f1={_format_metric(result.get('val_f1'))} "
            f"Penalty F1={row['Penalty F1']} Penalty ASR={row['Penalty ASR']} "
            f"Penalty PV-ASR={row['Penalty PV-ASR']}"
        )

    missing = _missing_metrics(rows)
    for item in missing:
        warning = f"missing metric: {item}"
        print(f"WARNING: {warning}")
        summary["warnings"].append(warning)

    csv_out, tex_out = _write_table5(rows, table_dir)
    summary["table5_csv"] = str(csv_out.resolve())
    summary["table5_tex"] = str(tex_out.resolve())
    summary["missing_metrics"] = missing
    summary_path = output_root / "ablation_table5_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n=== Table V summary ===")
    for row in rows:
        print(
            f"{row['Variant']}: Unperturbed F1={row['Unperturbed F1']} Projection F1={row['Projection F1']} "
            f"Penalty F1={row['Penalty F1']} Penalty ASR={row['Penalty ASR']} "
            f"Penalty PV-ASR={row['Penalty PV-ASR']} FAR={row['FAR']}"
        )
    print(f"Saved Table V CSV: {csv_out.resolve()}")
    print(f"Saved Table V LaTeX: {tex_out.resolve()}")
    print(f"Saved summary JSON: {summary_path.resolve()}")
    return summary_path


__all__ = ["run_table5_ablation_study", "TABLE5_VARIANTS", "Table5Variant"]

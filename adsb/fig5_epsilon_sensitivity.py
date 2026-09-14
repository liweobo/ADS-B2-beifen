"""Fig. 5: F1-score sensitivity under different perturbation budgets."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable

import matplotlib.pyplot as plt
import numpy as np
import torch

from adsb.paper_style import MODEL_COLORS, MODEL_MARKERS, save_figure, setup_paper_style
from adsb.paper_naming import attack_display_name, model_display_name
from adsb.train_constants import (
    PGD_ALPHA,
    PGD_STEPS,
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
)
from adsb.training import evaluate


FIG5_EPS_LIST = [0.05, 0.10, 0.20, 0.30, 0.40, 0.50]
FIG5_RENDER_FONT_SIZE = 10.0

FIG5_CAPTION = (
    "F1-score sensitivity under different perturbation budgets. The F1-score is reported "
    "for BiLSTM-ERM and CAT-AD under Projection-based Phys-PGD and "
    "Penalty-based Phys-PGD."
)

ATTACK_MODES = {
    "projection_phys_pgd": "phys",
    "penalty_phys_pgd": "phys_penalty",
}


def _setup_ieee_style() -> None:
    setup_paper_style()


def collect_fig5_epsilon_sensitivity(
    *,
    baseline_model,
    proposed_model,
    test_loader,
    device: torch.device,
    m,
    s,
    baseline_threshold: float,
    proposed_threshold: float,
    eps_list: Iterable[float] = FIG5_EPS_LIST,
    attacks: Iterable[str] = ("projection_phys_pgd", "penalty_phys_pgd"),
    baseline_checkpoint_path: str | Path = "current_run_baseline",
    proposed_checkpoint_path: str | Path = "current_run_proposed",
    pgd_alpha: float = PGD_ALPHA,
    pgd_steps: int = PGD_STEPS,
) -> list[dict[str, Any]]:
    """Collect Fig. 5 F1-scores using fixed validation thresholds."""
    rows: list[dict[str, Any]] = []
    specs = [
        (model_display_name("Baseline"), baseline_model, float(baseline_threshold), str(baseline_checkpoint_path)),
        ("CAT-AD", proposed_model, float(proposed_threshold), str(proposed_checkpoint_path)),
    ]
    for attack in attacks:
        if attack not in ATTACK_MODES:
            raise ValueError(f"Unknown Fig. 5 attack setting: {attack}")
        mode = ATTACK_MODES[attack]
        for eps in eps_list:
            eps = float(eps)
            for model_name, model, threshold, ckpt in specs:
                metrics = evaluate(
                    model,
                    test_loader,
                    device=device,
                    threshold=threshold,
                    mode=mode,
                    m=m,
                    s=s,
                    adv_eps=eps,
                    pgd_alpha=pgd_alpha,
                    pgd_steps=pgd_steps,
                    phys_penalty_lambda_max=PHYS_PENALTY_LAMBDA_MAX,
                    phys_penalty_lambda_gamma=PHYS_PENALTY_LAMBDA_GAMMA,
                    phys_penalty_use_lambda_schedule=PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
                    phys_penalty_w_speed=PHYS_PENALTY_W_SPEED,
                    phys_penalty_w_altitude=PHYS_PENALTY_W_ALTITUDE,
                    phys_penalty_w_latlon=PHYS_PENALTY_W_LATLON,
                    phys_penalty_w_heading=PHYS_PENALTY_W_HEADING,
                    phys_penalty_use_soft_projection=PHYS_PENALTY_USE_SOFT_PROJECTION,
                    phys_penalty_projection_start_ratio=PHYS_PENALTY_PROJECTION_START_RATIO,
                    phys_penalty_final_projection=PHYS_PENALTY_FINAL_PROJECTION,
                    physical_m=m,
                    physical_s=s,
                )
                row = {
                    "attack_setting": attack,
                    "epsilon": eps,
                    "model": model_name,
                    "f1_score": float(metrics["f1"]),
                    "threshold": threshold,
                    "checkpoint_path": ckpt,
                }
                rows.append(row)
                print(
                    f"Fig. 5 | {attack} | epsilon={eps:.2f} | "
                    f"{model_name} F1={row['f1_score']:.4f} | threshold={threshold:.4f}"
                )
    return rows


def write_fig5_csv(rows: list[dict[str, Any]], path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    attack_name_map = {
        "projection_phys_pgd": "Projection-based Phys-PGD",
        "penalty_phys_pgd": "Penalty-based Phys-PGD",
    }
    headers = ["attack_setting", "attack", "epsilon", "model", "f1_score", "threshold", "checkpoint_path"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            attack_key = str(row["attack_setting"])
            writer.writerow(
                {
                    "attack_setting": attack_key,
                    "attack": attack_display_name(attack_name_map.get(attack_key, attack_key)),
                    "epsilon": f"{float(row['epsilon']):.4f}",
                    "model": model_display_name(row["model"]),
                    "f1_score": f"{float(row['f1_score']):.4f}",
                    "threshold": f"{float(row['threshold']):.4f}",
                    "checkpoint_path": "",
                }
            )
    return path


def plot_fig5_epsilon_sensitivity(
    rows: list[dict[str, Any]],
    *,
    figures_dir: Path | str,
) -> dict[str, Path]:
    """Plot the two-panel Fig. 5 F1-score sensitivity analysis."""
    setup_paper_style()
    figures_dir = Path(figures_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)

    titles = {
        "projection_phys_pgd": "(b) Projection-based Phys-PGD",
        "penalty_phys_pgd": "(c) Penalty-based Phys-PGD",
    }
    attacks = [a for a in ("projection_phys_pgd", "penalty_phys_pgd") if any(r["attack_setting"] == a for r in rows)]

    fig, axes = plt.subplots(1, len(attacks), figsize=(7.15, 2.65), constrained_layout=False)
    if len(attacks) == 1:
        axes = [axes]
    fig.subplots_adjust(left=0.075, right=0.985, top=0.80, bottom=0.25, wspace=0.18)

    for ax_idx, (ax, attack) in enumerate(zip(axes, attacks)):
        ax.set_facecolor("white")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(True, axis="y", color="#D9DEE5", linewidth=0.5, alpha=0.75)
        ax.set_axisbelow(True)
        ax.set_xlim(0.035, 0.515)
        ax.set_ylim(0.0, 1.02)
        ax.set_yticks(np.linspace(0.0, 1.0, 6))
        ax.set_xticks(sorted({float(r["epsilon"]) for r in rows if r["attack_setting"] == attack}))
        ax.tick_params(axis="both", labelsize=FIG5_RENDER_FONT_SIZE)
        ax.set_xlabel("Perturbation budget $\\epsilon$", fontsize=FIG5_RENDER_FONT_SIZE)
        ax.set_ylabel("F1-score" if ax_idx == 0 else "", fontsize=FIG5_RENDER_FONT_SIZE)
        ax.set_title(titles.get(attack, attack), pad=6, fontsize=FIG5_RENDER_FONT_SIZE)
        for model_name in ("BiLSTM-ERM", "CAT-AD"):
            aliases = {model_name}
            if model_name == "BiLSTM-ERM":
                aliases.update({"Baseline", "Standard BiLSTM"})
            if model_name == "CAT-AD":
                aliases.add("Proposed")
            sub = [r for r in rows if r["attack_setting"] == attack and str(r["model"]) in aliases]
            sub = sorted(sub, key=lambda r: float(r["epsilon"]))
            eps = [float(r["epsilon"]) for r in sub]
            f1 = [float(r["f1_score"]) for r in sub]
            ax.plot(
                eps,
                f1,
                label=model_name,
                color=MODEL_COLORS[model_name],
                marker=MODEL_MARKERS[model_name],
                linestyle="-" if model_name == "BiLSTM-ERM" else "--",
                linewidth=1.25,
                markerfacecolor="white" if model_name == "CAT-AD" else MODEL_COLORS[model_name],
                markeredgecolor="#30343B",
                markeredgewidth=0.6,
            )

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        ncol=2,
        frameon=False,
        bbox_to_anchor=(0.5, 1.02),
        columnspacing=1.6,
        handlelength=1.8,
        fontsize=FIG5_RENDER_FONT_SIZE,
    )

    paths = save_figure(fig, figures_dir / "fig_epsilon_sensitivity")
    plt.close(fig)
    return paths


def generate_fig5_from_models(
    *,
    baseline_model,
    proposed_model,
    test_loader,
    device: torch.device,
    m,
    s,
    baseline_threshold: float,
    proposed_threshold: float,
    figures_dir: Path | str,
    results_dir: Path | str,
    eps_list: Iterable[float] = FIG5_EPS_LIST,
    attacks: Iterable[str] = ("projection_phys_pgd", "penalty_phys_pgd"),
    baseline_checkpoint_path: str | Path = "current_run_baseline",
    proposed_checkpoint_path: str | Path = "current_run_proposed",
    pgd_alpha: float = PGD_ALPHA,
    pgd_steps: int = PGD_STEPS,
) -> dict[str, Path]:
    rows = collect_fig5_epsilon_sensitivity(
        baseline_model=baseline_model,
        proposed_model=proposed_model,
        test_loader=test_loader,
        device=device,
        m=m,
        s=s,
        baseline_threshold=baseline_threshold,
        proposed_threshold=proposed_threshold,
        eps_list=eps_list,
        attacks=attacks,
        baseline_checkpoint_path=baseline_checkpoint_path,
        proposed_checkpoint_path=proposed_checkpoint_path,
        pgd_alpha=pgd_alpha,
        pgd_steps=pgd_steps,
    )
    csv_path = write_fig5_csv(rows, Path(results_dir) / "fig_epsilon_sensitivity_data.csv")
    fig_paths = plot_fig5_epsilon_sensitivity(rows, figures_dir=figures_dir)
    fig_paths["csv"] = csv_path
    return fig_paths

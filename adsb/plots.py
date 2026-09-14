"""Plotting: robustness vs. ε, paper figures, baseline vs. adversarial training."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable, Sequence

import matplotlib.pyplot as plt
import numpy as np

from adsb.paper_style import MODEL_COLORS, save_figure, setup_paper_style
from adsb.paper_tables import TABLE3_ALIASES, TABLE3_ROWS, _metric
from adsb.paper_naming import canonical_model_key, canonical_setting_key, model_display_name, setting_display_name


def _figure_dir(base: Path | None = None) -> Path:
    root = base if base is not None else Path(__file__).resolve().parent.parent
    d = root / "figures"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _setup_matplotlib():
    setup_paper_style()


FIG3_CAPTION = (
    "Robustness comparison between BiLSTM-ERM and CAT-AD under "
    "unperturbed and adversarial evaluation settings."
)


FIG3_F1_SETTINGS = [
    "Clean",
    "Standard PGD",
    "Projection-based phys-PGD",
    "Penalty-based phys-PGD",
]

FIG3_ASR_SETTINGS = [
    "Standard PGD",
    "Projection-based phys-PGD",
    "Penalty-based phys-PGD",
]

MODEL_HATCHES = {"BiLSTM-ERM": "///", "CAT-AD": "..."}
FIG_MAIN_RENDER_FONT_SIZE = 9.0


def _read_table3_csv(path: Path | str) -> dict[tuple[str, str], dict[str, Any]]:
    """读取已生成的 Table III CSV，供单独补画 Fig. 3 时复用。"""
    table3: dict[tuple[str, str], dict[str, Any]] = {}
    with Path(path).open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            model = str(row.get("Model", "")).strip()
            setting = str(row.get("Setting", "")).strip()
            model = canonical_model_key(model)
            setting = canonical_setting_key(setting)
            if model and setting:
                table3[(model, setting)] = dict(row)
    return table3


def _table3_metric_value(
    table3_results: dict[tuple[str, str], dict[str, Any]],
    model: str,
    setting: str,
    metric_name: str,
) -> float:
    value = _metric(table3_results.get((model, setting), {}), TABLE3_ALIASES[metric_name])
    if value is None:
        raise ValueError(f"Fig. 3 缺少 Table III 指标：{model} | {setting} | {metric_name}")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Fig. 3 的 Table III 指标不是数值：{model} | {setting} | {metric_name}={value!r}"
        ) from exc


def _fig3_series_from_table3(
    table3_results: dict[tuple[str, str], dict[str, Any]]
) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, float]]]:
    """从 Table III 的检测指标中提取 Fig. 3 所需的 F1 和 ASR，不单独维护硬编码数值。"""
    missing_rows = [row for row in TABLE3_ROWS if row not in table3_results]
    if missing_rows:
        missing = ", ".join(f"{model} | {setting}" for model, setting in missing_rows)
        raise ValueError(f"Fig. 3 无法生成：Table III 缺少行 {missing}")

    f1_data = {
        model: {
            setting: _table3_metric_value(table3_results, model, setting, "F1-score")
            for setting in FIG3_F1_SETTINGS
        }
        for model in ("Baseline", "Proposed")
    }
    asr_data = {
        model: {
            setting: _table3_metric_value(table3_results, model, setting, "ASR")
            for setting in FIG3_ASR_SETTINGS
        }
        for model in ("Baseline", "Proposed")
    }
    return f1_data, asr_data


def _read_aggregate_csv(path: Path | str) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _aggregate_fig3_series(
    aggregate_rows: Sequence[dict[str, Any]],
) -> dict[str, dict[str, dict[str, tuple[float, float, float, int]]]]:
    """Return mean/CI/n values for the 14 bars in the main robustness figure."""
    lookup = {
        (
            canonical_model_key(str(row["model"])),
            canonical_setting_key(str(row["setting"])),
            str(row["metric"]),
        ): row
        for row in aggregate_rows
    }
    series: dict[str, dict[str, dict[str, tuple[float, float, float, int]]]] = {
        "f1": {"Baseline": {}, "Proposed": {}},
        "asr": {"Baseline": {}, "Proposed": {}},
    }
    for metric, settings in (("f1", FIG3_F1_SETTINGS), ("asr", FIG3_ASR_SETTINGS)):
        for model in ("Baseline", "Proposed"):
            for setting in settings:
                row = lookup.get((model, setting, metric))
                if row is None:
                    raise ValueError(f"Aggregate figure source is missing {model} | {setting} | {metric}")
                series[metric][model][setting] = (
                    float(row["mean"]),
                    float(row["ci95_low"]),
                    float(row["ci95_high"]),
                    int(row["n"]),
                )
    return series


def write_fig_main_robustness_data(
    aggregate_rows: Sequence[dict[str, Any]], path: Path | str
) -> Path:
    """Write the exact aggregate rows used by the main robustness figure."""
    series = _aggregate_fig3_series(aggregate_rows)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = ["model", "setting", "metric", "n", "mean", "ci95_low", "ci95_high"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for metric, settings in (("f1", FIG3_F1_SETTINGS), ("asr", FIG3_ASR_SETTINGS)):
            for model in ("Baseline", "Proposed"):
                for setting in settings:
                    mean, low, high, n = series[metric][model][setting]
                    writer.writerow(
                        {
                            "model": model_display_name(model),
                            "setting": setting_display_name(setting),
                            "metric": metric,
                            "n": n,
                            "mean": f"{mean:.10f}",
                            "ci95_low": f"{low:.10f}",
                            "ci95_high": f"{high:.10f}",
                        }
                    )
    return path


def plot_fig_main_robustness(
    *,
    aggregate_rows: Sequence[dict[str, Any]] | None = None,
    aggregate_csv_path: Path | str | None = None,
    figure_source_csv_path: Path | str | None = None,
    table3_results: dict[tuple[str, str], dict[str, Any]] | None = None,
    table3_csv_path: Path | str | None = None,
    figures_dir: Path | str | None = None,
) -> dict[str, Path]:
    """Generate the main robustness figure, preferring five-run aggregate data."""
    setup_paper_style()
    if figures_dir is None:
        figures_dir = Path(__file__).resolve().parent.parent / "figures"
    figures_dir = Path(figures_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)

    if aggregate_rows is None and aggregate_csv_path is not None:
        aggregate_rows = _read_aggregate_csv(aggregate_csv_path)
    aggregate_series = None
    if aggregate_rows is not None:
        aggregate_series = _aggregate_fig3_series(aggregate_rows)
        if figure_source_csv_path is not None:
            write_fig_main_robustness_data(aggregate_rows, figure_source_csv_path)

    if aggregate_series is None and table3_results is None:
        if table3_csv_path is None:
            table3_csv_path = (
                Path(__file__).resolve().parent.parent
                / "outputs"
                / "tables"
                / "table3_main_results_updated.csv"
            )
        table3_results = _read_table3_csv(table3_csv_path)

    if aggregate_series is None:
        f1_data, asr_data = _fig3_series_from_table3(table3_results)

    f1_settings = FIG3_F1_SETTINGS
    asr_settings = FIG3_ASR_SETTINGS
    f1_labels = [setting_display_name(s, short=True) for s in f1_settings]
    asr_labels = [setting_display_name(s, short=True) for s in asr_settings]

    baseline_color = MODEL_COLORS["BiLSTM-ERM"]
    proposed_color = MODEL_COLORS["CAT-AD"]
    width = 0.30

    fig, axes = plt.subplots(1, 2, figsize=(7.15, 2.75), constrained_layout=False)
    fig.subplots_adjust(left=0.075, right=0.985, top=0.82, bottom=0.24, wspace=0.20)
    for ax in axes:
        ax.set_facecolor("white")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(True, axis="y", color="#D9DEE5", linewidth=0.5, alpha=0.75)
        ax.set_axisbelow(True)
        ax.set_ylim(-0.06, 1.08)
        ax.set_yticks(np.linspace(0, 1, 6))
        ax.tick_params(axis="both", labelsize=FIG_MAIN_RENDER_FONT_SIZE)

    x = np.arange(len(f1_settings))
    if aggregate_series is not None:
        b_stats = [aggregate_series["f1"]["Baseline"][s] for s in f1_settings]
        p_stats = [aggregate_series["f1"]["Proposed"][s] for s in f1_settings]
        b_vals, p_vals = [v[0] for v in b_stats], [v[0] for v in p_stats]
        b_err = np.array([[v[0] - v[1] for v in b_stats], [v[2] - v[0] for v in b_stats]])
        p_err = np.array([[v[0] - v[1] for v in p_stats], [v[2] - v[0] for v in p_stats]])
    else:
        b_vals = [f1_data["Baseline"][s] for s in f1_settings]
        p_vals = [f1_data["Proposed"][s] for s in f1_settings]
        b_err = p_err = None
    error_kw = {"elinewidth": 0.7, "capsize": 2.0, "capthick": 0.7, "ecolor": "#20242A"}
    axes[0].bar(x - width / 2, b_vals, width, yerr=b_err, error_kw=error_kw, label=model_display_name("Baseline"), color=baseline_color, edgecolor="#30343B", hatch=MODEL_HATCHES["BiLSTM-ERM"], linewidth=0.5)
    axes[0].bar(x + width / 2, p_vals, width, yerr=p_err, error_kw=error_kw, label="CAT-AD", color=proposed_color, edgecolor="#30343B", hatch=MODEL_HATCHES["CAT-AD"], linewidth=0.5)
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(f1_labels, rotation=15, ha="right", fontsize=FIG_MAIN_RENDER_FONT_SIZE)
    axes[0].set_ylabel("F1-score", fontsize=FIG_MAIN_RENDER_FONT_SIZE)
    axes[0].set_title("(a) F1-score", pad=6, fontsize=FIG_MAIN_RENDER_FONT_SIZE)

    x = np.arange(len(asr_settings))
    if aggregate_series is not None:
        b_stats = [aggregate_series["asr"]["Baseline"][s] for s in asr_settings]
        p_stats = [aggregate_series["asr"]["Proposed"][s] for s in asr_settings]
        b_vals, p_vals = [v[0] for v in b_stats], [v[0] for v in p_stats]
        b_err = np.array([[v[0] - v[1] for v in b_stats], [v[2] - v[0] for v in b_stats]])
        p_err = np.array([[v[0] - v[1] for v in p_stats], [v[2] - v[0] for v in p_stats]])
    else:
        b_vals = [asr_data["Baseline"][s] for s in asr_settings]
        p_vals = [asr_data["Proposed"][s] for s in asr_settings]
        b_err = p_err = None
    axes[1].bar(x - width / 2, b_vals, width, yerr=b_err, error_kw=error_kw, label=model_display_name("Baseline"), color=baseline_color, edgecolor="#30343B", hatch=MODEL_HATCHES["BiLSTM-ERM"], linewidth=0.5)
    axes[1].bar(x + width / 2, p_vals, width, yerr=p_err, error_kw=error_kw, label="CAT-AD", color=proposed_color, edgecolor="#30343B", hatch=MODEL_HATCHES["CAT-AD"], linewidth=0.5)
    for xpos, value in zip(x + width / 2, p_vals):
        axes[1].text(xpos, 0.035, f"{value:.4f}", ha="center", va="bottom", fontsize=FIG_MAIN_RENDER_FONT_SIZE)
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(asr_labels, rotation=15, ha="right", fontsize=FIG_MAIN_RENDER_FONT_SIZE)
    axes[1].set_ylabel("ASR", fontsize=FIG_MAIN_RENDER_FONT_SIZE)
    axes[1].set_title("(b) ASR", pad=6, fontsize=FIG_MAIN_RENDER_FONT_SIZE)

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
        fontsize=FIG_MAIN_RENDER_FONT_SIZE,
    )

    paths = save_figure(fig, figures_dir / "fig_main_robustness")
    plt.close(fig)
    return paths


def plot_fig3_robustness_comparison(
    *,
    table3_results: dict[tuple[str, str], dict[str, Any]] | None = None,
    table3_csv_path: Path | str | None = None,
    figures_dir: Path | str | None = None,
) -> dict[str, Path]:
    """Legacy wrapper. Prefer ``plot_fig_main_robustness`` for main-paper output."""
    return plot_fig_main_robustness(
        table3_results=table3_results,
        table3_csv_path=table3_csv_path,
        figures_dir=figures_dir,
    )


def sweep_f1_vs_epsilon(
    model,
    loader,
    device,
    threshold: float,
    eps_list: Sequence[float],
    modes: Sequence[tuple[str, str | None]],
    m=None,
    s=None,
) -> dict[str, list[float]]:
    """
    modes: list of (label, mode) where mode is None (clean), 'pgd', or 'phys'.
    Returns dict label -> [f1 at each epsilon]; clean mode repeats same F1 (eps ignored).
    """
    from adsb.training import evaluate_with_threshold

    out: dict[str, list[float]] = {}
    for label, mode in modes:
        fs = []
        for eps in eps_list:
            if mode is None:
                r = evaluate_with_threshold(
                    model, loader, device, threshold=threshold, mode=None, adv_eps=float(eps)
                )
            else:
                r = evaluate_with_threshold(
                    model,
                    loader,
                    device,
                    threshold=threshold,
                    mode=mode,
                    m=m,
                    s=s,
                    adv_eps=float(eps),
                )
            fs.append(float(r["f1"]))
        out[label] = fs
    return out


def plot_robustness_vs_epsilon(
    eps_list: Sequence[float],
    series: dict[str, Sequence[float]],
    out_path: Path | str | None = None,
    title: str = "Robustness under Different Attack Strengths",
    ylabel: str = "F1 score",
):
    """Robustness curve: F1 vs. perturbation budget ε."""
    _setup_matplotlib()
    fig, ax = plt.subplots()
    eps_arr = np.asarray(eps_list, dtype=float)
    for name, ys in series.items():
        ax.plot(eps_arr, np.asarray(ys, dtype=float), marker="o", markersize=3, linewidth=1.8, label=name)
    ax.set_xlabel("Epsilon")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, alpha=0.35)
    ax.legend(loc="best", fontsize=9)
    fig.tight_layout()
    path = Path(out_path) if out_path else _figure_dir() / "robustness_vs_epsilon.png"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def plot_baseline_vs_adv_attacks(
    attack_names: Sequence[str],
    baseline_scores: Sequence[float],
    adv_scores: Sequence[float],
    metric: str = "F1 score",
    out_path: Path | str | None = None,
    title: str = "Model Performance under Different Conditions",
):
    """Legacy grouped bar chart: BiLSTM-ERM vs. an adversarially trained detector."""
    _setup_matplotlib()
    x = np.arange(len(attack_names))
    w = 0.36
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w / 2, baseline_scores, width=w, label="BiLSTM-ERM")
    ax.bar(x + w / 2, adv_scores, width=w, label="Adversarial training (PGD + physical projection)")
    ax.set_xticks(x)
    ax.set_xticklabels(list(attack_names))
    ax.set_ylabel(metric)
    ax.set_title(title)
    ax.legend()
    ax.grid(True, axis="y", alpha=0.35)
    fig.tight_layout()
    path = Path(out_path) if out_path else _figure_dir() / "baseline_vs_adv_attacks.png"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def plot_ablation_modules(
    variant_names: Sequence[str],
    f1_clean: Sequence[float],
    f1_pgd: Sequence[float],
    out_path: Path | str | None = None,
    title: str = "Ablation Study of Model Components",
    eval_eps_note: str = "",
):
    """Legacy ablation bar chart: unperturbed vs. PGD F1 per configuration."""
    _setup_matplotlib()
    x = np.arange(len(variant_names))
    w = 0.36
    fig_w = float(min(12.0, max(8.0, 4.8 + 1.75 * len(variant_names))))
    fig, ax = plt.subplots(figsize=(fig_w, 5))
    ax.bar(x - w / 2, f1_clean, width=w, label="Unperturbed (F1)")
    lab = "PGD attack (F1)"
    if eval_eps_note:
        lab = f"{lab}, {eval_eps_note}"
    ax.bar(x + w / 2, f1_pgd, width=w, label=lab)
    ax.set_xticks(x)
    ax.set_xticklabels(list(variant_names), rotation=15, ha="right")
    ax.set_ylabel("F1 score")
    ax.set_title(title)
    ax.legend()
    ax.grid(True, axis="y", alpha=0.35)
    fig.tight_layout()
    path = Path(out_path) if out_path else _figure_dir() / "ablation_modules.png"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def collect_robustness_curves(
    baseline_model,
    adv_model,
    b_thr: float,
    a_thr: float,
    test_loader,
    device,
    m,
    s,
    eps_list: Iterable[float],
) -> dict[str, list[float]]:
    """Collect legacy F1-vs-epsilon curves for BiLSTM-ERM and CAT-AD."""
    eps_list = list(eps_list)
    sb = sweep_f1_vs_epsilon(
        baseline_model,
        test_loader,
        device,
        b_thr,
        eps_list,
        modes=[
            ("BiLSTM-ERM (PGD)", "pgd"),
            ("BiLSTM-ERM (Phys-PGD)", "phys"),
        ],
        m=m,
        s=s,
    )
    sa = sweep_f1_vs_epsilon(
        adv_model,
        test_loader,
        device,
        a_thr,
        eps_list,
        modes=[
            ("CAT-AD (PGD)", "pgd"),
            ("CAT-AD (Phys-PGD)", "phys"),
        ],
        m=m,
        s=s,
    )
    sb.update(sa)
    return sb

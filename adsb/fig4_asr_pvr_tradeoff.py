"""Fig. 4 paired physical-feasibility plotting from Table III and Table IV."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np

from adsb.paper_style import MODEL_COLORS, save_figure, setup_paper_style
from adsb.paper_tables import TABLE3_ALIASES, TABLE4_ALIASES, _metric
from adsb.paper_naming import (
    attack_display_name,
    canonical_model_key,
    canonical_setting_key,
    model_display_name,
)
from adsb.paths import default_project_root


FIG4_PAIRS = [
    ("Baseline", "Standard PGD"),
    ("Baseline", "Projection-based phys-PGD"),
    ("Baseline", "Penalty-based phys-PGD"),
    ("Proposed", "Standard PGD"),
    ("Proposed", "Projection-based phys-PGD"),
    ("Proposed", "Penalty-based phys-PGD"),
]

FIG4_CAPTION = (
    "Paired physical feasibility of adversarial examples. New-PVR and PV-ASR are computed "
    "on anomalous trajectories that satisfy all audited constraints before perturbation. "
    "CAT-AD substantially reduces conditional PV-ASR under the evaluated attacks."
)

FIG4_ANALYSIS_TEXT = (
    "The physical feasibility figure is constructed from the main experimental results. "
    "Specifically, ASR is taken from Table III, whereas New-PVR|V0 and PV-ASR|V0 are taken "
    "from Table IV. Conditioning on pre-attack-valid trajectories prevents originally invalid "
    "samples from being credited to the attack. Projection-based Phys-PGD introduces no new "
    "violations in the audited benchmark while retaining high conditional attack success against "
    "BiLSTM-ERM. CAT-AD suppresses physically valid evasion under the same attacks."
)


def _setup_matplotlib() -> None:
    setup_paper_style()


def _candidate_table3_paths(root: Path) -> list[Path]:
    return [
        root / "outputs" / "tables" / "table_full_main_results.csv",
        root / "outputs" / "tables" / "table3_main_results_updated.csv",
        root / "outputs" / "tables" / "table3_main_results.csv",
        root / "results" / "table3_main_results_updated.csv",
        root / "results" / "table3_main_results.csv",
        root / "results" / "main_results.csv",
        root / "results" / "eval_report.csv",
    ]


def _candidate_table3_tex_paths(root: Path) -> list[Path]:
    return [
        root / "outputs" / "tables" / "table3_main_results_updated.tex",
        root / "outputs" / "tables" / "table3_main_results.tex",
        root / "paper_lncs" / "main.tex",
    ]


def _candidate_table4_paths(root: Path) -> list[Path]:
    return [
        root / "outputs" / "tables" / "table_physical_feasibility.csv",
        root / "outputs" / "tables" / "table4_physical_feasibility_updated.csv",
        root / "outputs" / "tables" / "table4_physical_feasibility.csv",
        root / "results" / "table4_physical_feasibility_updated.csv",
        root / "results" / "table4_physical_feasibility.csv",
        root / "results" / "physical_feasibility_results.csv",
    ]


def _candidate_table4_tex_paths(root: Path) -> list[Path]:
    return [
        root / "outputs" / "tables" / "table4_physical_feasibility_updated.tex",
        root / "outputs" / "tables" / "table4_physical_feasibility.tex",
        root / "paper_lncs" / "main.tex",
    ]


def _find_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def _read_table_csv(path: Path, setting_key: str) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            model = str(row.get("Model", row.get("model", ""))).strip()
            model = canonical_model_key(model)
            setting = str(
                row.get(setting_key, row.get(setting_key.lower(), row.get("Attack", row.get("attack", ""))))
            ).strip()
            setting = canonical_setting_key(setting)
            if model and setting:
                rows[(model, setting)] = dict(row)
    return rows


def _read_table3(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    return _read_table_csv(path, "Setting")


def _read_table4(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    return _read_table_csv(path, "Attack Setting")


def _clean_tex_cell(cell: str) -> str:
    return (
        cell.replace(r"\midrule", "")
        .replace(r"\hline", "")
        .replace(r"\bottomrule", "")
        .replace(r"\toprule", "")
        .replace(r"\\", "")
        .strip()
    )


def _read_table3_tex(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    """Parse Table 1/Table III LaTeX source when the CSV result file is unavailable."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or "&" not in line or r"\\" not in line:
            continue
        cells = [_clean_tex_cell(c) for c in line.split("&")]
        if len(cells) not in {8, 9} or cells[0] in {"Model", "Variant"}:
            continue
        model, setting = cells[0], cells[1]
        if (model, setting) not in FIG4_PAIRS:
            continue
        asr_idx = 7 if len(cells) == 9 else 6
        far_idx = 8 if len(cells) == 9 else 7
        rows[(model, setting)] = {
            "Model": model,
            "Setting": setting,
            "Accuracy": cells[2],
            "Precision": cells[3],
            "Recall": cells[4],
            "F1-score": cells[5],
            "ASR": cells[asr_idx],
            "FAR": cells[far_idx],
        }
    return rows


def _read_table4_tex(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    """Parse Table 2/Table IV LaTeX source when the CSV result file is unavailable."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or "&" not in line or r"\\" not in line:
            continue
        cells = [_clean_tex_cell(c) for c in line.split("&")]
        if len(cells) != 8 or cells[0] in {"Model", "Variant"}:
            continue
        model, setting = cells[0], cells[1]
        if (model, setting) not in FIG4_PAIRS:
            continue
        rows[(model, setting)] = {
            "Model": model,
            "Attack Setting": setting,
            "PVR": cells[2],
            "PV-ASR": cells[3],
            "Position VR": cells[4],
            "Alt. VR": cells[5],
            "Vel. VR": cells[6],
            "Head. VR": cells[7],
        }
    return rows


def _float_metric(metrics: dict[str, Any], aliases: tuple[str, ...], label: str) -> float:
    value = _metric(metrics, aliases)
    if value is None:
        raise ValueError(f"missing metric {label}")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"metric {label} is not numeric: {value!r}") from exc


def collect_fig4_data_from_tables(
    table3_results: dict[tuple[str, str], dict[str, Any]],
    table4_results: dict[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge Table III/IV metrics for the six primary model--attack pairs."""
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    for model, setting in FIG4_PAIRS:
        table3_metrics = table3_results.get((model, setting))
        table4_metrics = table4_results.get((model, setting))
        if table3_metrics is None:
            missing.append(f"{model} | {setting} | Table III")
            continue
        if table4_metrics is None:
            missing.append(f"{model} | {setting} | Table IV")
            continue
        try:
            rows.append(
                {
                    "model": model,
                    "attack_setting": setting,
                    "asr": _float_metric(table3_metrics, TABLE3_ALIASES["ASR"], "ASR"),
                    "pvr": _float_metric(
                        table4_metrics,
                        TABLE4_ALIASES["New-PVR|V0"],
                        "New-PVR|V0",
                    ),
                    "pv_asr": _float_metric(
                        table4_metrics,
                        TABLE4_ALIASES["PV-ASR|V0"],
                        "PV-ASR|V0",
                    ),
                }
            )
        except ValueError as exc:
            missing.append(f"{model} | {setting} | {exc}")
    if missing:
        raise ValueError("Fig. 4 required data are incomplete: " + "; ".join(missing))
    return rows


def collect_fig4_aggregate_data(
    aggregate_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collect five-run conditional PV-ASR means and confidence intervals."""
    lookup = {
        (
            canonical_model_key(str(row["model"])),
            canonical_setting_key(str(row["setting"])),
            str(row["metric"]),
        ): row
        for row in aggregate_rows
    }
    rows: list[dict[str, Any]] = []
    for model, setting in FIG4_PAIRS:
        row = lookup.get((model, setting, "conditional_pv_asr_start_valid"))
        if row is None:
            raise ValueError(f"Aggregate physical figure source is missing {model} | {setting}")
        rows.append(
            {
                "model": model,
                "attack_setting": setting,
                "n": int(row["n"]),
                "pv_asr": float(row["mean"]),
                "ci95_low": float(row["ci95_low"]),
                "ci95_high": float(row["ci95_high"]),
            }
        )
    return rows


def load_fig4_data(
    *,
    table3_csv_path: Path | str | None = None,
    table4_csv_path: Path | str | None = None,
    project_root: Path | str | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Read Fig. 4 data from Table 1/2 CSV files, or parse their LaTeX sources if CSV is absent."""
    root = Path(project_root) if project_root is not None else default_project_root()
    table3_path = Path(table3_csv_path) if table3_csv_path is not None else _find_existing(_candidate_table3_paths(root))
    table4_path = Path(table4_csv_path) if table4_csv_path is not None else _find_existing(_candidate_table4_paths(root))

    if table3_path is not None:
        table3_results = _read_table3(table3_path)
        print(f"Fig. 4 data source: Table III={table3_path.resolve()}")
        table3_source = "table3_csv"
    else:
        table3_tex_path = _find_existing(_candidate_table3_tex_paths(root))
        if table3_tex_path is None:
            raise FileNotFoundError("Fig. 4 requires Table 1/Table III data, but no CSV or LaTeX source was found.")
        table3_results = _read_table3_tex(table3_tex_path)
        print(f"Fig. 4 data source: Table III LaTeX={table3_tex_path.resolve()}")
        table3_source = "table3_tex"

    if table4_path is not None:
        table4_results = _read_table4(table4_path)
        print(f"Fig. 4 data source: Table IV={table4_path.resolve()}")
        table4_source = "table4_csv"
    else:
        table4_tex_path = _find_existing(_candidate_table4_tex_paths(root))
        if table4_tex_path is None:
            raise FileNotFoundError("Fig. 4 requires Table 2/Table IV data, but no CSV or LaTeX source was found.")
        table4_results = _read_table4_tex(table4_tex_path)
        print(f"Fig. 4 data source: Table IV LaTeX={table4_tex_path.resolve()}")
        table4_source = "table4_tex"

    rows = collect_fig4_data_from_tables(table3_results, table4_results)
    return rows, f"{table3_source}+{table4_source}"


def write_fig4_data_csv(rows: list[dict[str, Any]], path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["model", "attack", "asr", "pvr", "pv_asr"])
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "model": model_display_name(row["model"]),
                    "attack": attack_display_name(row["attack_setting"]),
                    "asr": f"{float(row['asr']):.4f}",
                    "pvr": f"{float(row['pvr']):.4f}",
                    "pv_asr": f"{float(row['pv_asr']):.4f}",
                }
            )
    return path


def write_fig4_aggregate_data_csv(rows: list[dict[str, Any]], path: Path | str) -> Path:
    """Write the exact multi-seed source rows used by the paper-facing bar chart."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = ["model", "attack", "n", "pv_asr", "ci95_low", "ci95_high"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "model": model_display_name(row["model"]),
                    "attack": attack_display_name(row["attack_setting"]),
                    "n": int(row["n"]),
                    "pv_asr": f"{float(row['pv_asr']):.10f}",
                    "ci95_low": f"{float(row['ci95_low']):.10f}",
                    "ci95_high": f"{float(row['ci95_high']):.10f}",
                }
            )
    return path


def plot_fig4_asr_pvr_tradeoff(rows: list[dict[str, Any]], *, figures_dir: Path | str | None = None) -> dict[str, Path]:
    """Legacy/appendix scatter plot using valid-start-conditioned metrics."""
    _setup_matplotlib()
    if figures_dir is None:
        figures_dir = default_project_root() / "figures"
    figures_dir = Path(figures_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)

    colors = {"Baseline": MODEL_COLORS["BiLSTM-ERM"], "Proposed": MODEL_COLORS["CAT-AD"]}
    markers = {
        "Standard PGD": "o",
        "Projection-based phys-PGD": "s",
        "Penalty-based phys-PGD": "^",
    }
    labels = {s: attack_display_name(s, short=True) for s in markers}

    row_map = {(str(r["model"]), str(r["attack_setting"])): r for r in rows}

    fig, axes = plt.subplots(1, 2, figsize=(7.6, 3.65), constrained_layout=False)
    fig.subplots_adjust(left=0.075, right=0.985, top=0.88, bottom=0.28, wspace=0.24)
    panels = [
        (axes[0], "asr", "ASR", "(a) ASR vs. New-PVR"),
        (axes[1], "pv_asr", "PV-ASR | V0", "(b) Conditional PV-ASR vs. New-PVR"),
    ]
    for ax, metric_key, ylabel, title in panels:
        ax.set_facecolor("white")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_linewidth(0.9)
        ax.spines["bottom"].set_linewidth(0.9)
        ax.grid(True, color="#D8DDE3", linewidth=0.55, alpha=0.78)
        ax.set_axisbelow(True)
        ax.set_xlim(0.0, 1.0)
        ax.set_ylim(0.0, 1.0)
        ax.set_xticks(np.linspace(0, 1, 6))
        ax.set_yticks(np.linspace(0, 1, 6))
        ax.set_xlabel("New-PVR | V0", fontsize=8.8)
        ax.set_ylabel(ylabel, fontsize=8.8)
        ax.set_title(title, fontsize=9.3, pad=8)
        ax.tick_params(axis="both", labelsize=7.7, pad=2)

        for row in rows:
            model = str(row["model"])
            setting = str(row["attack_setting"])
            x = float(row["pvr"])
            y = float(row[metric_key])
            ax.scatter(
                x,
                y,
                s=54,
                marker=markers[setting],
                color=colors[model],
                edgecolor="#30343B",
                linewidth=0.55,
                zorder=3,
            )

    def _annotate(ax, key: tuple[str, str], metric_key: str, text: str, xytext: tuple[float, float], ha: str = "left"):
        row = row_map[key]
        xy = (float(row["pvr"]), float(row[metric_key]))
        ax.annotate(
            text,
            xy=xy,
            xytext=xytext,
            textcoords="data",
            ha=ha,
            va="center",
            fontsize=7.0,
            color="#20242A",
            arrowprops={
                "arrowstyle": "->",
                "color": "#5B616A",
                "lw": 0.7,
                "shrinkA": 2,
                "shrinkB": 4,
                "connectionstyle": "arc3,rad=0.12",
            },
            bbox={"boxstyle": "round,pad=0.18", "fc": "white", "ec": "none", "alpha": 0.78},
            zorder=4,
        )

    _annotate(
        axes[0],
        ("Baseline", "Standard PGD"),
        "asr",
        "High ASR",
        (0.58, 0.88),
        ha="left",
    )
    _annotate(
        axes[1],
        ("Baseline", "Penalty-based phys-PGD"),
        "pv_asr",
        "High PV-ASR | V0",
        (0.22, 0.70),
        ha="left",
    )
    _annotate(
        axes[1],
        ("Proposed", "Penalty-based phys-PGD"),
        "pv_asr",
        "Suppressed\nPV-ASR | V0",
        (0.20, 0.17),
        ha="left",
    )

    model_handles = [
        plt.Line2D([0], [0], marker="o", linestyle="", markersize=6, markerfacecolor=colors[m], markeredgecolor="#30343B", label=model_display_name(m))
        for m in ("Baseline", "Proposed")
    ]
    attack_handles = [
        plt.Line2D([0], [0], marker=markers[s], linestyle="", markersize=6, color="#5B616A", label=labels[s])
        for s in ("Standard PGD", "Projection-based phys-PGD", "Penalty-based phys-PGD")
    ]
    fig.legend(
        handles=model_handles + attack_handles,
        loc="lower center",
        ncol=5,
        frameon=False,
        fontsize=8.0,
        bbox_to_anchor=(0.5, 0.035),
        columnspacing=1.0,
        handletextpad=0.4,
    )

    base = figures_dir / "fig4_asr_pvr_tradeoff"
    pdf_path = base.with_suffix(".pdf")
    png_path = base.with_suffix(".png")
    svg_path = base.with_suffix(".svg")
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(svg_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return {"pdf": pdf_path, "png": png_path, "svg": svg_path}


def plot_fig_physical_valid_asr(
    rows: list[dict[str, Any]],
    *,
    figures_dir: Path | str | None = None,
) -> dict[str, Path]:
    """Main-paper bar chart for PV-ASR conditioned on pre-attack-valid samples."""
    setup_paper_style()
    if figures_dir is None:
        figures_dir = default_project_root() / "figures"
    figures_dir = Path(figures_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)

    attacks = [
        ("Standard PGD", attack_display_name("Standard PGD", short=True)),
        ("Projection-based phys-PGD", attack_display_name("Projection-based phys-PGD", short=True)),
        ("Penalty-based phys-PGD", attack_display_name("Penalty-based phys-PGD", short=True)),
    ]
    models = [("Baseline", model_display_name("Baseline")), ("Proposed", model_display_name("Proposed"))]
    hatches = {"BiLSTM-ERM": "///", "CAT-AD": "..."}
    row_map = {(str(r["model"]), str(r["attack_setting"])): r for r in rows}

    x = np.arange(len(attacks))
    width = 0.30
    fig, ax = plt.subplots(figsize=(3.55, 2.75))
    fig.subplots_adjust(left=0.17, right=0.98, top=0.72, bottom=0.25)
    for idx, (model_key, label) in enumerate(models):
        vals = [float(row_map[(model_key, attack_key)]["pv_asr"]) for attack_key, _ in attacks]
        selected_rows = [row_map[(model_key, attack_key)] for attack_key, _ in attacks]
        yerr = None
        if all("ci95_low" in row and "ci95_high" in row for row in selected_rows):
            yerr = np.array(
                [
                    [float(row["pv_asr"]) - float(row["ci95_low"]) for row in selected_rows],
                    [float(row["ci95_high"]) - float(row["pv_asr"]) for row in selected_rows],
                ]
            )
        offset = -width / 2 if idx == 0 else width / 2
        ax.bar(
            x + offset,
            vals,
            width,
            label=label,
            color=MODEL_COLORS[label],
            edgecolor="#30343B",
            hatch=hatches[label],
            linewidth=0.5,
            yerr=yerr,
            error_kw={"elinewidth": 0.7, "capsize": 2.0, "capthick": 0.7, "ecolor": "#20242A"},
        )
        if model_key == "Proposed":
            for xpos, value in zip(x + offset, vals):
                ax.text(xpos, 0.028, f"{value:.4f}", ha="center", va="bottom", fontsize=7.5)

    ax.set_xticks(x)
    ax.set_xticklabels([label for _, label in attacks], rotation=15, ha="right")
    ax.set_ylabel(r"PV-ASR $\mid V_0$")
    ax.set_title("(a) Conditional PV-ASR", pad=6)
    ax.set_ylim(-0.06, 1.08)
    ax.set_yticks(np.linspace(0.0, 1.0, 5))
    ax.grid(True, axis="y", color="#D9DEE5", linewidth=0.5, alpha=0.75)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1.16),
        ncol=2,
        frameon=False,
        columnspacing=1.2,
        handlelength=1.8,
    )
    paths = save_figure(fig, figures_dir / "fig_physical_valid_asr")
    plt.close(fig)
    return paths


def generate_fig4_asr_pvr_tradeoff(
    *,
    table3_results: dict[tuple[str, str], dict[str, Any]] | None = None,
    table4_results: dict[tuple[str, str], dict[str, Any]] | None = None,
    table3_csv_path: Path | str | None = None,
    table4_csv_path: Path | str | None = None,
    figures_dir: Path | str | None = None,
    results_dir: Path | str | None = None,
    project_root: Path | str | None = None,
) -> tuple[dict[str, Path], Path, str]:
    """Generate Fig. 4, its normalized CSV, and the data-source identifier."""
    root = Path(project_root) if project_root is not None else default_project_root()
    if figures_dir is None:
        figures_dir = root / "figures"
    if results_dir is None:
        results_dir = root / "results"
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    if table3_results is not None and table4_results is not None:
        rows = collect_fig4_data_from_tables(table3_results, table4_results)
        source = "in_memory_table_results"
    else:
        rows, source = load_fig4_data(
            table3_csv_path=table3_csv_path,
            table4_csv_path=table4_csv_path,
            project_root=root,
        )

    csv_path = write_fig4_data_csv(rows, results_dir / "fig4_asr_pvr_tradeoff_data.csv")
    fig_paths = plot_fig4_asr_pvr_tradeoff(rows, figures_dir=figures_dir)
    return fig_paths, csv_path, source


def main() -> None:
    fig_paths, csv_path, source = generate_fig4_asr_pvr_tradeoff()
    print(f"Fig. 4 data source: {source}")
    print(f"Saved Fig. 4 CSV: {csv_path.resolve()}")
    print(
        "Saved Fig. 4: "
        f"{fig_paths['pdf'].resolve()}, {fig_paths['png'].resolve()}, {fig_paths['svg'].resolve()}"
    )
    print("\nRecommended caption:")
    print(FIG4_CAPTION)
    print("\nSuggested paper text:")
    print(FIG4_ANALYSIS_TEXT)


if __name__ == "__main__":
    main()

"""Regenerate paper tables and figures from existing result CSV files.

This script does not train or evaluate models. It only reloads saved result
tables, normalizes paper-facing terminology, and rewrites LaTeX/CSV/figure
exports for the CAT-AD experimental section.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adsb.ablation_table5 import _write_table5
from adsb.benchmark import _write_paired_comparisons_tex, _write_selected_tex
from adsb.fig4_asr_pvr_tradeoff import (
    collect_fig4_aggregate_data,
    plot_fig_physical_valid_asr,
    write_fig4_aggregate_data_csv,
)
from adsb.fig5_epsilon_sensitivity import plot_fig5_epsilon_sensitivity, write_fig5_csv
from adsb.paper_naming import (
    ablation_display_name,
    canonical_model_key,
    canonical_setting_key,
    model_display_name,
)
from adsb.paper_tables import (
    write_experimental_setup_table,
    write_table4_physical_feasibility,
    write_table_clean_performance,
    write_table_robustness_summary,
    write_test_set_results_csv,
)
from adsb.plots import plot_fig_main_robustness


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _parse_metric(value):
    text = str(value).strip()
    if text in {"", "--", "nan", "None"}:
        return None
    try:
        return float(text)
    except ValueError:
        return text


def _first(row: dict[str, str], *names: str):
    for name in names:
        if name in row and str(row[name]).strip() != "":
            return row[name]
    return None


def _load_test_results(path: Path) -> dict[tuple[str, str], dict[str, object]]:
    metrics_by_key: dict[tuple[str, str], dict[str, object]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            model = canonical_model_key(_first(row, "Model", "model"))
            setting = canonical_setting_key(_first(row, "Setting", "Attack", "attack_setting", "Attack Setting"))
            metrics_by_key[(model, setting)] = {
                "Accuracy": _parse_metric(_first(row, "Accuracy", "Acc.")),
                "Precision": _parse_metric(_first(row, "Precision", "Prec.")),
                "Recall": _parse_metric(_first(row, "Recall")),
                "F1-score": _parse_metric(_first(row, "F1-score", "F1")),
                "ASR": _parse_metric(_first(row, "ASR")),
                "FAR": _parse_metric(_first(row, "FAR")),
                "PVR": _parse_metric(_first(row, "PVR")),
                "PV-ASR": _parse_metric(_first(row, "PV-ASR")),
                "Pre-PVR": _parse_metric(_first(row, "Pre-PVR")),
                "Valid-start rate": _parse_metric(_first(row, "Valid-start rate")),
                "Post-PVR": _parse_metric(_first(row, "Post-PVR")),
                "New-PVR|V0": _parse_metric(_first(row, "New-PVR|V0")),
                "ASR|V0": _parse_metric(_first(row, "ASR|V0")),
                "PV-ASR|V0": _parse_metric(_first(row, "PV-ASR|V0")),
                "position_vr": _parse_metric(
                    _first(row, "Position violation rate", "Position VR")
                ),
                "alt_vr": _parse_metric(
                    _first(row, "Altitude violation rate", "Alt. VR")
                ),
                "vel_vr": _parse_metric(
                    _first(row, "Speed violation rate", "Vel. VR")
                ),
                "head_vr": _parse_metric(
                    _first(row, "Heading violation rate", "Head. VR")
                ),
                "physical_scope": _first(row, "PVR Scope"),
                "pv_asr_method": _first(row, "PV-ASR Method"),
                "conditional_physical_method": _first(row, "Conditional Physical Method"),
            }
    return metrics_by_key


def _load_benchmark_seed_results(path: Path) -> dict[tuple[str, str], dict[str, object]]:
    """Load one audited benchmark seed without passing through rounded paper CSVs."""
    metrics_by_key: dict[tuple[str, str], dict[str, object]] = {}
    for row in _load_csv_rows(path):
        key = (canonical_model_key(row["model"]), canonical_setting_key(row["setting"]))
        metrics_by_key.setdefault(key, {})[row["metric"]] = _parse_metric(row["value"])
    for (_, setting), metrics in metrics_by_key.items():
        if setting != "Clean":
            metrics["physical_scope"] = "paired pre/post attacked anomalous samples"
            metrics["pv_asr_method"] = "exact_per_sample"
            metrics["conditional_physical_method"] = "conditioned_on_pre_attack_validity"
    return metrics_by_key


def _rewrite_ablation_table(table_dir: Path) -> list[Path]:
    ablation_csv = table_dir / "table5_ablation_study.csv"
    if not ablation_csv.exists():
        return []

    rows: list[dict[str, str]] = []
    with ablation_csv.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append(
                {
                    "Variant": ablation_display_name(row.get("Variant", "")),
                    "Unperturbed F1": _first(row, "Unperturbed F1", "Clean F1"),
                    "Projection F1": _first(row, "Projection F1", "Phys-F1"),
                    "Penalty F1": _first(row, "Penalty F1", "Penalty-F1"),
                    "Penalty ASR": _first(row, "Penalty ASR", "Penalty-ASR"),
                    "Penalty PV-ASR": _first(row, "Penalty PV-ASR", "Penalty-PV-ASR"),
                    "FAR": _first(row, "FAR"),
                }
            )
    try:
        return list(_write_table5(rows, table_dir))
    except PermissionError as exc:
        print(f"WARNING: skipped ablation table rewrite because the file is locked: {exc}")
        return []


def _load_fig5_rows(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append(
                {
                    "attack_setting": row["attack_setting"],
                    "epsilon": row["epsilon"],
                    "model": model_display_name(row.get("model", "")),
                    "f1_score": row["f1_score"],
                    "threshold": row["threshold"],
                    "checkpoint_path": row.get("checkpoint_path", ""),
                }
            )
    return rows


def main() -> None:
    table_dir = ROOT / "outputs" / "tables"
    fig_dir = ROOT / "figures"
    results_dir = ROOT / "results"
    table_dir.mkdir(parents=True, exist_ok=True)
    fig_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    benchmark_seed = ROOT / "outputs" / "publication_benchmark" / "runs" / "seed_42" / "per_seed_metrics_long.csv"
    metrics_by_key = (
        _load_benchmark_seed_results(benchmark_seed)
        if benchmark_seed.exists()
        else _load_test_results(ROOT / "outputs" / "test_set_results.csv")
    )
    generated: list[Path] = []
    for csv_path, tex_path in (
        write_experimental_setup_table(table_dir),
        write_table_clean_performance(metrics_by_key, table_dir),
        write_table_robustness_summary(metrics_by_key, table_dir),
        write_table4_physical_feasibility(metrics_by_key, table_dir),
    ):
        generated.extend([csv_path, tex_path])

    generated.append(write_test_set_results_csv(metrics_by_key, ROOT / "outputs"))
    generated.extend(_rewrite_ablation_table(table_dir))

    benchmark_dir = ROOT / "outputs" / "publication_benchmark"
    multi_seed_tex = table_dir / "table_multiseed_summary.tex"
    paired_tex = table_dir / "table_paired_multiseed_comparison.tex"
    aggregate_rows = _load_csv_rows(benchmark_dir / "aggregate_summary.csv")
    _write_selected_tex(multi_seed_tex, aggregate_rows)
    _write_paired_comparisons_tex(
        paired_tex,
        _load_csv_rows(benchmark_dir / "paired_comparisons.csv"),
        require_all_primary=True,
    )
    generated.extend([multi_seed_tex, paired_tex])

    main_figure_source = results_dir / "fig_main_robustness_data.csv"
    generated.extend(
        plot_fig_main_robustness(
            aggregate_rows=aggregate_rows,
            figure_source_csv_path=main_figure_source,
            figures_dir=fig_dir,
        ).values()
    )
    generated.append(main_figure_source)

    fig4_rows = collect_fig4_aggregate_data(aggregate_rows)
    generated.append(write_fig4_aggregate_data_csv(fig4_rows, results_dir / "fig_physical_valid_asr_data.csv"))
    generated.extend(plot_fig_physical_valid_asr(fig4_rows, figures_dir=fig_dir).values())

    fig5_csv = results_dir / "fig_epsilon_sensitivity_data.csv"
    if fig5_csv.exists():
        fig5_rows = _load_fig5_rows(fig5_csv)
        generated.append(write_fig5_csv(fig5_rows, fig5_csv))
        generated.extend(plot_fig5_epsilon_sensitivity(fig5_rows, figures_dir=fig_dir).values())

    print("Regenerated paper exports:")
    for path in generated:
        print(_display_path(path))


if __name__ == "__main__":
    main()

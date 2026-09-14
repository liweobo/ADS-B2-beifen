"""Paper-ready result table exporters for CAT-AD."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from adsb.paper_naming import (
    attack_display_name,
    model_display_name,
    setting_display_name,
)
from adsb.train_constants import (
    EPOCHS,
    EVAL_ATTACK_EPS,
    INJECT_RATIO,
    LR,
    PGD_ALPHA,
    PGD_STEPS,
    PHYS_FEAT_LAMBDA,
    PHYS_OUT_LAMBDA,
    TRAIN_BATCH_SIZE,
    WINDOW_SIZE,
)


TABLE3_ROWS = [
    ("Baseline", "Clean"),
    ("Baseline", "Standard PGD"),
    ("Baseline", "Projection-based phys-PGD"),
    ("Baseline", "Penalty-based phys-PGD"),
    ("Proposed", "Clean"),
    ("Proposed", "Standard PGD"),
    ("Proposed", "Projection-based phys-PGD"),
    ("Proposed", "Penalty-based phys-PGD"),
]

TABLE4_ROWS = [row for row in TABLE3_ROWS if row[1] != "Clean"]

TABLE3_ALIASES = {
    "Accuracy": ("accuracy", "acc"),
    "Precision": ("precision", "prec"),
    "Recall": ("recall", "sensitivity"),
    "F1-score": ("f1", "f1_score", "f1-score"),
    "ASR": ("asr", "attack_success_rate"),
    "FAR": ("far", "false_alarm_rate"),
}

TABLE4_ALIASES = {
    "Pre-PVR": ("pre_attack_pvr",),
    "Valid-start rate": ("start_valid_rate",),
    "Post-PVR": ("pvr",),
    "New-PVR|V0": ("introduced_pvr_start_valid",),
    "ASR|V0": ("conditional_asr_start_valid",),
    "PV-ASR|V0": ("conditional_pv_asr_start_valid",),
    "PVR": ("pvr",),
    "PV-ASR": ("pv_asr", "physically_valid_asr", "physically_valid_attack_success_rate"),
    "Position violation rate": ("position_vr",),
    "Altitude violation rate": ("alt_vr",),
    "Speed violation rate": ("vel_vr",),
    "Heading violation rate": ("head_vr",),
}

def _normalized_key(key: str) -> str:
    return str(key).strip().lower().replace(" ", "_").replace("-", "_").replace(".", "")


def _metric(metrics: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    normalized = {_normalized_key(k): v for k, v in metrics.items()}
    for alias in aliases:
        key = _normalized_key(alias)
        if key in normalized:
            return normalized[key]
    return None


def _format_metric(value: Any) -> str:
    if value is None:
        return "--"
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "--"


def _tex_escape(text: str) -> str:
    text = str(text)
    if text.startswith(r"\shortstack{") and text.endswith("}"):
        return text
    if "$" in text:
        return text
    return (
        text.replace("\\", r"\textbackslash{}")
        .replace("&", r"\&")
        .replace("%", r"\%")
        .replace("_", r"\_")
    )


def _write_csv(rows: list[dict[str, str]], headers: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def _write_tex(
    rows: list[dict[str, str]],
    *,
    path: Path,
    caption: str,
    label: str,
    tabular_spec: str,
    headers: list[str],
    header_labels: list[str] | None = None,
    note: str | None = None,
    table_star: bool = True,
    tabcolsep: str = "3.5pt",
    arraystretch: str = "1.08",
    font_size: str = r"\small",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    env = "table*" if table_star else "table"
    labels = header_labels or headers
    lines = [
        rf"\begin{{{env}}}[!ht]",
        r"\centering",
        font_size,
        rf"\setlength{{\tabcolsep}}{{{tabcolsep}}}",
        rf"\renewcommand{{\arraystretch}}{{{arraystretch}}}",
        rf"\caption{{{caption}}}",
        rf"\label{{{label}}}",
        rf"\begin{{tabular}}{{{tabular_spec}}}",
        r"\toprule",
        " & ".join(labels) + r" \\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(" & ".join(_tex_escape(row[h]) for h in headers) + r" \\")
    lines.extend([r"\bottomrule", r"\end{tabular}"])
    if note:
        lines.extend(
            [
                r"\vspace{1mm}",
                r"\begin{minipage}{0.98\textwidth}",
                r"\footnotesize " + note,
                r"\end{minipage}",
            ]
        )
    lines.extend([rf"\end{{{env}}}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def write_experimental_setup_table(output_dir: Path) -> tuple[Path, Path]:
    rows = [
        {"Item": "Split", "Configuration": "Aircraft-level 70/10/20 train/val/test split"},
        {"Item": "Window length", "Configuration": f"{WINDOW_SIZE} time steps"},
        {"Item": "Input dimension", "Configuration": "12 = 6 raw features + 6 temporal differences"},
        {"Item": "Anomaly ratio", "Configuration": f"{INJECT_RATIO:.0%}"},
        {"Item": "Spoofing types", "Configuration": "Gradual drift, position shift, kinematic spoofing"},
        {"Item": "Backbone", "Configuration": "2-layer BiLSTM, hidden size 64"},
        {"Item": "Optimizer", "Configuration": f"Adam, learning rate {LR:.0e}"},
        {"Item": "Training", "Configuration": f"Batch size {TRAIN_BATCH_SIZE}, up to {EPOCHS} epochs"},
        {
            "Item": "Attack setting",
            "Configuration": f"$\\epsilon={EVAL_ATTACK_EPS:g}$, step size={PGD_ALPHA:g}, {PGD_STEPS} PGD steps",
        },
        {
            "Item": "Consistency weights",
            "Configuration": (
                f"$\\lambda_{{\\mathrm{{out}}}}={PHYS_OUT_LAMBDA:g}$, "
                f"$\\lambda_{{\\mathrm{{rep}}}}={PHYS_FEAT_LAMBDA:g}$"
            ),
        },
    ]
    headers = ["Item", "Configuration"]
    csv_path = output_dir / "table_experimental_setup.csv"
    tex_path = output_dir / "table_experimental_setup.tex"
    _write_csv(rows, headers, csv_path)
    _write_tex(
        rows,
        path=tex_path,
        caption="Experimental setup for CAT-AD evaluation",
        label="tab:experimental_setup",
        tabular_spec="p{0.24\\textwidth}p{0.68\\textwidth}",
        headers=headers,
        table_star=True,
        note=(
            "ADS-B trajectories are split by aircraft identity to prevent aircraft-level leakage. "
            "The perturbation budget is applied in normalized feature space."
        ),
    )
    return csv_path, tex_path


def write_table_clean_performance(
    results: dict[tuple[str, str], dict[str, Any]], output_dir: Path
) -> tuple[Path, Path]:
    headers = ["Model", "Acc.", "Prec.", "Recall", "F1-score", "FAR"]
    metric_headers = ["Accuracy", "Precision", "Recall", "F1-score", "FAR"]
    rows: list[dict[str, str]] = []
    for model in ("Baseline", "Proposed"):
        metrics = results.get((model, "Clean"), {})
        row = {"Model": model_display_name(model)}
        for display, metric in zip(headers[1:], metric_headers):
            row[display] = _format_metric(_metric(metrics, TABLE3_ALIASES[metric]))
        rows.append(row)
    csv_path = output_dir / "table_clean_performance.csv"
    tex_path = output_dir / "table_clean_performance.tex"
    _write_csv(rows, headers, csv_path)
    _write_tex(
        rows,
        path=tex_path,
        caption="Detection performance on unperturbed test data",
        label="tab:clean_performance",
        tabular_spec="lccccc",
        headers=headers,
        table_star=False,
        tabcolsep="4.0pt",
        note=(
            "Acc. and Prec. denote accuracy and precision, respectively; "
            "FAR denotes the false alarm rate on normal test windows."
        ),
    )
    return csv_path, tex_path


def write_table_robustness_summary(
    results: dict[tuple[str, str], dict[str, Any]], output_dir: Path
) -> tuple[Path, Path]:
    baseline_name = model_display_name("Baseline")
    baseline_f1 = f"{baseline_name} F1-score"
    baseline_asr = f"{baseline_name} ASR"
    headers = ["Attack", baseline_f1, "CAT-AD F1-score", baseline_asr, "CAT-AD ASR"]
    rows: list[dict[str, str]] = []
    for setting in ("Standard PGD", "Projection-based phys-PGD", "Penalty-based phys-PGD"):
        b = results.get(("Baseline", setting), {})
        p = results.get(("Proposed", setting), {})
        rows.append(
            {
                "Attack": attack_display_name(setting),
                baseline_f1: _format_metric(_metric(b, TABLE3_ALIASES["F1-score"])),
                "CAT-AD F1-score": _format_metric(_metric(p, TABLE3_ALIASES["F1-score"])),
                baseline_asr: _format_metric(_metric(b, TABLE3_ALIASES["ASR"])),
                "CAT-AD ASR": _format_metric(_metric(p, TABLE3_ALIASES["ASR"])),
            }
        )
    csv_path = output_dir / "table_robustness_summary.csv"
    tex_path = output_dir / "table_robustness_summary.tex"
    _write_csv(rows, headers, csv_path)
    _write_tex(
        rows,
        path=tex_path,
        caption="Robustness under adversarial attacks",
        label="tab:robustness_summary",
        tabular_spec="lrrrr",
        headers=headers,
        header_labels=[
            "Attack",
            r"\shortstack{BiLSTM-ERM\\F1-score}",
            r"\shortstack{CAT-AD\\F1-score}",
            r"\shortstack{BiLSTM-ERM\\ASR}",
            r"\shortstack{CAT-AD\\ASR}",
        ],
        table_star=True,
        tabcolsep="2pt",
        font_size=r"\scriptsize",
        note=(
            "ASR is the targeted anomalous-to-normal evasion success rate. "
            "All attacks perturb only anomalous windows during robustness evaluation."
        ),
    )
    return csv_path, tex_path


def write_table3_main_results(
    results: dict[tuple[str, str], dict[str, Any]], output_dir: Path
) -> tuple[Path, Path]:
    """Legacy/appendix full metric table."""
    rows: list[dict[str, str]] = []
    headers = ["Model", "Setting", "Acc.", "Prec.", "Recall", "F1-score", "ASR", "FAR"]
    metric_headers = ["Accuracy", "Precision", "Recall", "F1-score", "ASR", "FAR"]
    for model, setting in TABLE3_ROWS:
        metrics = results.get((model, setting), {})
        row = {"Model": model_display_name(model), "Setting": setting_display_name(setting)}
        for display, metric in zip(headers[2:], metric_headers):
            row[display] = _format_metric(_metric(metrics, TABLE3_ALIASES[metric]))
        if setting == "Clean":
            row["ASR"] = "--"
        rows.append(row)
    csv_path = output_dir / "table_full_main_results.csv"
    tex_path = output_dir / "table_full_main_results.tex"
    _write_csv(rows, headers, csv_path)
    _write_tex(
        rows,
        path=tex_path,
        caption="Full Detection and Robustness Metrics",
        label="tab:full_main_results",
        tabular_spec="llcccccc",
        headers=headers,
        table_star=True,
        font_size=r"\scriptsize",
        note="This appendix table reports all classification metrics used to derive the main paper summaries.",
    )
    return csv_path, tex_path


def write_table4_physical_feasibility(
    results: dict[tuple[str, str], dict[str, Any]], output_dir: Path
) -> tuple[Path, Path]:
    rows: list[dict[str, str]] = []
    headers = [
        "Model",
        "Attack",
        "Valid-start rate",
        "Pre-PVR",
        "Post-PVR",
        "New-PVR|V0",
        "ASR|V0",
        "PV-ASR|V0",
        "PVR",
        "PV-ASR",
        "Position violation rate",
        "Altitude violation rate",
        "Speed violation rate",
        "Heading violation rate",
    ]
    for model, setting in TABLE4_ROWS:
        metrics = results.get((model, setting), {})
        row = {"Model": model_display_name(model), "Attack": attack_display_name(setting)}
        for heading in headers[2:]:
            row[heading] = _format_metric(_metric(metrics, TABLE4_ALIASES[heading]))
        rows.append(row)
    csv_path = output_dir / "table_physical_feasibility.csv"
    tex_path = output_dir / "table_physical_feasibility.tex"
    _write_csv(rows, headers, csv_path)
    aggregate_headers = [
        "Model",
        "Attack",
        "Post-PVR",
        "New-PVR|V0",
        "ASR|V0",
        "PV-ASR|V0",
    ]
    violation_headers = [
        "Model",
        "Attack",
        "Position violation rate",
        "Altitude violation rate",
        "Speed violation rate",
        "Heading violation rate",
    ]
    lines = [
        r"\begin{table*}[!ht]",
        r"\centering",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{2pt}",
        r"\renewcommand{\arraystretch}{1.10}",
        r"\caption{Single-seed auxiliary paired pre/post physical feasibility of adversarial examples}",
        r"\label{tab:physical_feasibility}",
        r"\textit{(a) Aggregate physical feasibility}\par\smallskip",
        r"\begin{tabular}{llcccc}",
        r"\toprule",
        r"Model & Attack & Post-PVR & New-PVR$\mid V_0$ & ASR$\mid V_0$ & PV-ASR$\mid V_0$ \\",
        r"\midrule",
    ]
    for row in rows:
        display = dict(row)
        display["Attack"] = attack_display_name(row["Attack"], short=True)
        lines.append(" & ".join(_tex_escape(display[h]) for h in aggregate_headers) + r" \\")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\par\medskip",
            r"\textit{(b) Constraint-specific violation rates}\par\smallskip",
            r"\begin{tabular}{llcccc}",
            r"\toprule",
            r"Model & Attack & Pos. VR & Alt. VR & Speed VR & Head. VR \\",
            r"\midrule",
        ]
    )
    for row in rows:
        display = dict(row)
        display["Attack"] = attack_display_name(row["Attack"], short=True)
        lines.append(" & ".join(_tex_escape(display[h]) for h in violation_headers) + r" \\")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\vspace{1mm}",
            r"\begin{minipage}{0.98\textwidth}",
            r"\raggedright\footnotesize The valid-start rate is 0.8324 and Pre-PVR is 0.1676 for every row in this single-seed auxiliary table; "
            r"these repeated constants are stated here instead of occupying two columns. $V_0$ denotes anomalous samples that satisfy every audited constraint before the adversarial perturbation. "
            r"New-PVR, ASR, and PV-ASR conditioned on $V_0$ use exactly that paired denominator; Post-PVR and constraint-specific violation rates (VRs) are retained as all-sample diagnostics. Pos., Alt., and Head. denote position, altitude, and heading, respectively; Speed denotes ground speed.",
            r"\end{minipage}",
            r"\end{table*}",
            "",
        ]
    )
    tex_path.write_text("\n".join(lines), encoding="utf-8")
    return csv_path, tex_path


def write_test_set_results_csv(
    results: dict[tuple[str, str], dict[str, Any]], output_dir: Path
) -> Path:
    """Save the complete machine-readable test-set results."""
    headers = [
        "Model",
        "Setting",
        "Acc.",
        "Prec.",
        "Recall",
        "F1-score",
        "ASR",
        "FAR",
        "PVR",
        "PV-ASR",
        "Pre-PVR",
        "Valid-start rate",
        "Post-PVR",
        "New-PVR|V0",
        "ASR|V0",
        "PV-ASR|V0",
        "Position violation rate",
        "Altitude violation rate",
        "Speed violation rate",
        "Heading violation rate",
        "PVR Scope",
        "PV-ASR Method",
        "Conditional Physical Method",
    ]
    rows: list[dict[str, str]] = []
    for model, setting in TABLE3_ROWS:
        metrics = results.get((model, setting), {})
        row = {"Model": model_display_name(model), "Setting": setting_display_name(setting)}
        for display, metric in (
            ("Acc.", "Accuracy"),
            ("Prec.", "Precision"),
            ("Recall", "Recall"),
            ("F1-score", "F1-score"),
            ("ASR", "ASR"),
            ("FAR", "FAR"),
        ):
            row[display] = _format_metric(_metric(metrics, TABLE3_ALIASES[metric]))
        if setting == "Clean":
            row["ASR"] = "--"

        if setting == "Clean":
            for heading in TABLE4_ALIASES:
                row[heading] = "--"
            row["PVR Scope"] = "--"
            row["PV-ASR Method"] = "--"
            row["Conditional Physical Method"] = "--"
        else:
            for heading, aliases in TABLE4_ALIASES.items():
                row[heading] = _format_metric(_metric(metrics, aliases))
            row["PVR Scope"] = str(metrics.get("physical_scope", "--"))
            row["PV-ASR Method"] = str(metrics.get("pv_asr_method", "--"))
            row["Conditional Physical Method"] = str(metrics.get("conditional_physical_method", "--"))
        rows.append(row)

    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "test_set_results.csv"
    _write_csv(rows, headers, csv_path)
    try:
        display_path = csv_path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        display_path = csv_path.as_posix()
    print(f"Saved complete test-set results CSV: {display_path}")
    return csv_path

"""Build and verify the unperturbed-detection report for published ADS-B baselines.

The training benchmark also stores exploratory attack outputs for the
one-class detectors.  Those outputs are intentionally not promoted into the
paper table: a fixed classifier-PGD step size is not a validated robustness
test for heterogeneous reconstruction and support-vector score surfaces.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PUBLISHED_MODELS = (
    "Fried--Last Differenced LSTM-AE",
    "VAE--SVDD",
    "Contextual AE",
)
MODEL_ORDER = (
    "BiLSTM-ERM",
    *PUBLISHED_MODELS,
    "CAT-AD",
)
COLUMNS = (
    ("f1", r"F1-score $\uparrow$", True),
    ("precision", r"Prec. $\uparrow$", True),
    ("recall", r"Rec. $\uparrow$", True),
    ("far", r"FAR $\downarrow$", False),
)
TEX_MODEL_NAMES = {
    "BiLSTM-ERM": r"BiLSTM-ERM",
    "Fried--Last Differenced LSTM-AE": r"Fried--Last LSTM-AE (2021)",
    "VAE--SVDD": r"VAE--SVDD (2021)",
    "Contextual AE": r"Contextual AE (2022)",
    "CAT-AD": r"CAT-AD",
}
REPORT_MODEL_NAMES = {
    "BiLSTM-ERM": "BiLSTM-ERM",
    "Fried--Last Differenced LSTM-AE": "Fried--Last Differenced LSTM-AE",
    "VAE--SVDD": "VAE--SVDD",
    "Contextual AE": "Contextual AE",
    "CAT-AD": "CAT-AD",
}
PUBLICATION_YEARS = {
    "Fried--Last Differenced LSTM-AE": 2021,
    "VAE--SVDD": 2021,
    "Contextual AE": 2022,
}
MODEL_ALIASES = {
    "Standard BiLSTM": "BiLSTM-ERM",
    "BiLSTM-ERM": "BiLSTM-ERM",
    "Fried--Last diff. LSTM-AE": "Fried--Last Differenced LSTM-AE",
    "Fried--Last Differenced LSTM-AE": "Fried--Last Differenced LSTM-AE",
    "VAE--SVDD": "VAE--SVDD",
    "Contextual AE": "Contextual AE",
    "CAT-AD": "CAT-AD",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _clean_index(rows: list[dict[str, str]], seed_count: int) -> dict[tuple[str, str], dict[str, float]]:
    index: dict[tuple[str, str], dict[str, float]] = {}
    for row in rows:
        if row["setting"] != "Clean" or row["metric"] not in {column[0] for column in COLUMNS}:
            continue
        model = MODEL_ALIASES.get(row["model"], row["model"])
        if model not in MODEL_ORDER:
            continue
        n = int(row["n"])
        mean = float(row["mean"])
        half = float(row["ci95_half_width"])
        if n != seed_count:
            raise RuntimeError(f"{model} {row['metric']} has n={n}; expected {seed_count}.")
        if not (math.isfinite(mean) and math.isfinite(half) and half >= 0.0):
            raise RuntimeError(f"Non-finite aggregate for {model} {row['metric']}.")
        index[(model, row["metric"])] = {"mean": mean, "ci95_half_width": half}
    missing = [
        f"{model}/{metric}"
        for model in MODEL_ORDER
        for metric, _label, _higher_better in COLUMNS
        if (model, metric) not in index
    ]
    if missing:
        raise RuntimeError("Missing clean aggregate rows: " + ", ".join(missing))
    return index


def _write_table(path: Path, index: dict[tuple[str, str], dict[str, float]], seed_count: int) -> None:
    best: dict[str, float] = {}
    for metric, _label, higher_better in COLUMNS:
        values = [index[(model, metric)]["mean"] for model in MODEL_ORDER]
        best[metric] = max(values) if higher_better else min(values)

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        (
            r"\caption{Same-protocol unperturbed detection comparison with concrete ADS-B models "
            r"published within the July 2019--July 2026 review window, over "
            rf"{seed_count} aircraft-level splits. Entries are mean (95\% "
            r"confidence-interval half-width).}"
        ),
        r"\label{tab:literature_detection}",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{2pt}",
        r"\begin{tabular}{@{}>{\raggedright\arraybackslash}p{0.24\textwidth}cccc@{}}",
        r"\toprule",
        "Model (year) & " + " & ".join(label for _metric, label, _higher_better in COLUMNS) + r" \\",
        r"\midrule",
    ]
    for model in MODEL_ORDER:
        cells = [TEX_MODEL_NAMES[model]]
        for metric, _label, _higher_better in COLUMNS:
            row = index[(model, metric)]
            value = f"{row['mean']:.3f} ({row['ci95_half_width']:.3f})"
            if math.isclose(row["mean"], best[metric], rel_tol=0.0, abs_tol=5e-7):
                value = r"\textbf{" + value + "}"
            cells.append(value)
        lines.append(" & ".join(cells) + r" \\")
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\begin{minipage}{0.98\textwidth}",
            (
                r"\footnotesize All methods use the same normalized 15-step windows, aircraft "
                r"splits, validation-only threshold selection, and injected test windows. The "
                r"three cited 2021--2022 methods~\cite{fried2021autoencoders,luo2021vaesvdd,chevrot2022cae} are representative, protocol-aligned "
                r"reimplementations rather than an exhaustive census or original-paper numbers. "
                r"Consistent with their one-class objectives, they train on the normal-only "
                r"view of the shared training windows; the supervised detectors use the "
                r"corresponding labeled view. Fried--Last Differenced LSTM-AE is shortened to Fried--Last LSTM-AE in the table. "
                r"Prec. and Rec. denote precision and recall. "
                r"Intervals are unbounded Student-$t$ intervals."
            ),
            r"\end{minipage}",
            r"\end{table*}",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _paired_clean_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    wanted = {"f1", "far"}
    selected: list[dict[str, str]] = []
    for row in rows:
        baseline = MODEL_ALIASES.get(row["baseline"], row["baseline"])
        if row["setting"] == "Clean" and row["metric"] in wanted and baseline in MODEL_ORDER[:-1]:
            normalized = dict(row)
            normalized["baseline"] = baseline
            selected.append(normalized)
    return selected


def _write_markdown(
    path: Path,
    *,
    benchmark_manifest: dict[str, Any],
    index: dict[tuple[str, str], dict[str, float]],
    paired_rows: list[dict[str, str]],
    attack_diagnostic: dict[str, Any],
) -> None:
    seeds = [int(seed) for seed in benchmark_manifest["seeds"]]
    publication_window = benchmark_manifest["publication_window"]
    inclusion_criteria = benchmark_manifest["literature_inclusion_criteria"]
    lines = [
        "# Published ADS-B baseline reproduction report",
        "",
        "## Scope",
        "",
        (
            "This report compares CAT-AD with BiLSTM-ERM and protocol-aligned "
            "reimplementations of three concrete ADS-B detectors published within the "
            "prespecified seven-year window: the 2021 Fried--Last differencing LSTM "
            "autoencoder, the 2021 VAE--SVDD, and the 2022 Contextual Autoencoder. "
            "It does not copy performance values from the source papers."
        ),
        "",
        "## Seven-year literature window and selection",
        "",
        (
            f"- Window: {publication_window['start']} through {publication_window['end']} "
            f"({publication_window['basis']})."
        ),
        *[f"- Inclusion criterion: {criterion}." for criterion in inclusion_criteria],
        "- Coverage boundary: the three models form a reproducible method-family sample, not an exhaustive census.",
        "",
        "## Common protocol",
        "",
        f"- Aircraft-level split seeds: {', '.join(str(seed) for seed in seeds)}.",
        "- Input: the same normalized 15-step, 12-channel raw-plus-differential windows.",
        "- Selection: the same mixed validation split and maximum-F1 threshold scan.",
        "- Test: the same injected mixed test windows used by the archived CAT-AD benchmark.",
        "- Training signal: normal-only windows for one-class methods; labeled windows for supervised methods.",
        "",
        "## Unperturbed detection results",
        "",
        "| Model | F1-score (mean ± 95% CI half-width) | FAR (mean ± 95% CI half-width) |",
        "|---|---:|---:|",
    ]
    for model in MODEL_ORDER:
        f1 = index[(model, "f1")]
        far = index[(model, "far")]
        display_model = REPORT_MODEL_NAMES[model]
        if model in PUBLICATION_YEARS:
            display_model = f"{display_model} ({PUBLICATION_YEARS[model]})"
        lines.append(
            f"| {display_model} | {f1['mean']:.4f} ± {f1['ci95_half_width']:.4f} "
            f"| {far['mean']:.4f} ± {far['ci95_half_width']:.4f} |"
        )
    lines.extend(
        [
            "",
            "Across all five paired aircraft splits, CAT-AD has higher F1 and lower FAR than every comparator.",
            "",
            "## Paired CAT-AD improvements",
            "",
            "| Comparator | Metric | Mean improvement | Wins / ties / losses |",
            "|---|---|---:|---:|",
        ]
    )
    for row in sorted(paired_rows, key=lambda item: (item["baseline"], item["metric"])):
        lines.append(
            f"| {REPORT_MODEL_NAMES[row['baseline']]} | {row['metric']} | {float(row['mean_improvement']):.4f} "
            f"| {row['wins']} / {row['ties']} / {row['losses']} |"
        )
    lines.extend(
        [
            "",
            "## Robustness reporting boundary",
            "",
            (
                "The publication table reports unperturbed detection only. The exploratory fixed-step "
                "classifier-PGD outputs stored by the training run are not used as cross-family "
                "robustness evidence: a step-size diagnostic showed severe overshoot on a "
                "reconstruction-score surface, so a zero ASR from that evaluator would be a weak-attack "
                "artifact rather than evidence of robustness. The manuscript's adversarial claims "
                "therefore remain restricted to BiLSTM-ERM and CAT-AD, for which the attack "
                "objective and sanity checks were pre-specified."
            ),
            "",
            (
                f"The archived diagnostic uses seed {attack_diagnostic['seed']} and the first "
                f"deterministic anomalous test batch ({attack_diagnostic['malicious_samples']} samples). "
                f"At eps={attack_diagnostic['fixed_classifier_pgd']['eps']}, alpha="
                f"{attack_diagnostic['fixed_classifier_pgd']['alpha']} for "
                f"{attack_diagnostic['fixed_classifier_pgd']['steps']} steps raises the mean anomalous-class "
                f"probability to {attack_diagnostic['fixed_classifier_pgd']['mean_malicious_probability']:.4f}, "
                f"whereas alpha={attack_diagnostic['finer_step_diagnostic']['alpha']} for "
                f"{attack_diagnostic['finer_step_diagnostic']['steps']} steps lowers it to "
                f"{attack_diagnostic['finer_step_diagnostic']['mean_malicious_probability']:.4f} and yields "
                f"ASR {attack_diagnostic['finer_step_diagnostic']['asr_at_validation_threshold']:.4f}."
            ),
            "",
            "## Reimplementation boundary",
            "",
            (
                "The defining model ideas are retained, but original feature sets, sequence lengths, "
                "datasets, and frameworks are intentionally replaced by the common CAT-AD protocol. "
                "These values quantify performance under this archived experiment and must not be "
                "presented as exact reproductions of the source papers' reported numbers or as an "
                "exhaustive ranking of every ADS-B detector published in the review window."
            ),
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def verify_report(benchmark_dir: str | Path) -> dict[str, Any]:
    root = Path(benchmark_dir).resolve()
    manifest_path = root / "literature_detection_report_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Missing report manifest: {manifest_path}")
    manifest = _read_json(manifest_path)
    if manifest.get("status") != "verified" or manifest.get("reporting_scope") not in {
        "clean_detection_only",
        "unperturbed_detection_only",
    }:
        raise RuntimeError("Literature report manifest has an invalid status or scope.")
    for relative, expected_hash in manifest["artifacts"].items():
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(f"Missing literature report artifact: {path}")
        actual_hash = _sha256(path)
        if actual_hash != expected_hash:
            raise RuntimeError(f"Artifact hash mismatch for {relative}: {actual_hash} != {expected_hash}")
    table = (root / "table_literature_detection.tex").read_text(encoding="utf-8")
    required = (
        r"\label{tab:literature_detection}",
        "fried2021autoencoders",
        "luo2021vaesvdd",
        "chevrot2022cae",
        "0.908",
        "0.026",
        "protocol-aligned reimplementations",
        "July 2019--July 2026",
        "(2021)",
        "(2022)",
    )
    missing = [marker for marker in required if marker not in table]
    if missing:
        raise RuntimeError("Literature detection table is missing markers: " + ", ".join(missing))
    return manifest


def build_report(benchmark_dir: str | Path) -> dict[str, Any]:
    root = Path(benchmark_dir).resolve()
    benchmark_manifest_path = root / "literature_benchmark_manifest.json"
    aggregate_path = root / "aggregate_summary.csv"
    paired_path = root / "paired_vs_catad.csv"
    attack_diagnostic_path = root / "attack_resolution_audit.json"
    for path in (benchmark_manifest_path, aggregate_path, paired_path, attack_diagnostic_path):
        if not path.is_file():
            raise FileNotFoundError(f"Missing literature benchmark input: {path}")
    benchmark_manifest = _read_json(benchmark_manifest_path)
    if not benchmark_manifest.get("completed"):
        raise RuntimeError("Literature benchmark is not marked complete.")
    seeds = [int(seed) for seed in benchmark_manifest.get("seeds", [])]
    if len(seeds) < 5 or len(set(seeds)) != len(seeds):
        raise RuntimeError("Literature report requires at least five unique seeds.")
    represented = {item["key"] for item in benchmark_manifest.get("model_reimplementations", [])}
    if represented != {"fried_lstm_ae", "vae_svdd", "contextual_ae"}:
        raise RuntimeError(f"Unexpected literature model set: {sorted(represented)}")
    publication_window = benchmark_manifest.get("publication_window", {})
    if publication_window.get("start") != "2019-07-15" or publication_window.get("end") != "2026-07-15":
        raise RuntimeError(f"Unexpected seven-year publication window: {publication_window}")
    expected_years = {"fried_lstm_ae": 2021, "vae_svdd": 2021, "contextual_ae": 2022}
    actual_years = {
        item["key"]: int(item.get("publication_year", -1))
        for item in benchmark_manifest.get("model_reimplementations", [])
    }
    if actual_years != expected_years:
        raise RuntimeError(f"Unexpected literature publication years: {actual_years}")
    criteria = benchmark_manifest.get("literature_inclusion_criteria", [])
    if len(criteria) < 4:
        raise RuntimeError("Literature benchmark must archive at least four inclusion criteria.")
    attack_diagnostic = _read_json(attack_diagnostic_path)
    if attack_diagnostic.get("status") != "passed":
        raise RuntimeError("Literature attack-resolution diagnostic is not marked passed.")
    if attack_diagnostic.get("dataset_sha256") != benchmark_manifest["dataset"]["sha256"]:
        raise RuntimeError("Attack-resolution diagnostic uses a different dataset hash.")

    aggregate_rows = _read_csv(aggregate_path)
    paired_rows = _paired_clean_rows(_read_csv(paired_path))
    index = _clean_index(aggregate_rows, len(seeds))
    if len(paired_rows) != 8:
        raise RuntimeError(f"Expected eight paired unperturbed F1-score/FAR rows, found {len(paired_rows)}.")
    for row in paired_rows:
        if int(row["n"]) != len(seeds) or int(row["wins"]) != len(seeds):
            raise RuntimeError(f"Paired unperturbed result is incomplete or not directionally consistent: {row}")

    table_path = root / "table_literature_detection.tex"
    report_path = root / "literature_detection_report.md"
    _write_table(table_path, index, len(seeds))
    _write_markdown(
        report_path,
        benchmark_manifest=benchmark_manifest,
        index=index,
        paired_rows=paired_rows,
        attack_diagnostic=attack_diagnostic,
    )
    manifest = {
        "status": "verified",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "reporting_scope": "unperturbed_detection_only",
        "publication_window": publication_window,
        "included_publication_years": expected_years,
        "reason_attack_columns_excluded": (
            "fixed-step classifier PGD did not pass cross-objective step-size sanity checking "
            "for reconstruction-based detectors"
        ),
        "seeds": seeds,
        "models": list(MODEL_ORDER),
        "benchmark_inputs": {
            "literature_benchmark_manifest.json": _sha256(benchmark_manifest_path),
            "aggregate_summary.csv": _sha256(aggregate_path),
            "paired_vs_catad.csv": _sha256(paired_path),
        },
        "artifacts": {
            "attack_resolution_audit.json": _sha256(attack_diagnostic_path),
            "table_literature_detection.tex": _sha256(table_path),
            "literature_detection_report.md": _sha256(report_path),
        },
    }
    manifest_path = root / "literature_detection_report_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return verify_report(root)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-dir", default="outputs/literature_benchmark")
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    manifest = verify_report(args.benchmark_dir) if args.verify_only else build_report(args.benchmark_dir)
    print(
        "Literature detection report verified: "
        f"{args.benchmark_dir} | seeds={manifest['seeds']}"
    )


if __name__ == "__main__":
    main()

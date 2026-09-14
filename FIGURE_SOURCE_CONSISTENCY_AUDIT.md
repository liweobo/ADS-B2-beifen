# CAT-AD Figure Source Consistency Audit

This audit verifies that the figures shown in the manuscript are tied to the
current machine-readable result sources rather than stale plotting data. It is
separate from the broader paper-artifact provenance audit: provenance checks
that files exist and are cited, while this audit checks that the current figure
source values agree with the tables and benchmark exports used by the paper.

## Regeneration Command

Use the no-capture Conda form on Windows so Conda does not re-encode captured
stdout through a legacy console code page:

```powershell
conda run --no-capture-output -n testtorch python tools\regenerate_paper_exports.py
```

The command reloads archived result CSV files and rewrites paper-facing tables,
figure source CSV files, and figure PDF/PNG/SVG artifacts. It does not train
models or evaluate new attacks.

## Source Mapping

| Manuscript figure | Figure artifacts | Machine-readable sources |
| --- | --- | --- |
| `fig:robustness_comparison` | `figures/fig_main_robustness.{pdf,png,svg}` | `outputs/publication_benchmark/aggregate_summary.csv`, `results/fig_main_robustness_data.csv` |
| `fig:physical_valid_asr` | `figures/fig_physical_valid_asr.{pdf,png,svg}` | `outputs/publication_benchmark/aggregate_summary.csv`, `results/fig_physical_valid_asr_data.csv` |
| `fig:epsilon_sensitivity` | `figures/fig_epsilon_sensitivity.{pdf,png,svg}` | `results/fig_epsilon_sensitivity_data.csv` |

## Consistency Checks

`tools/verify_figure_source_consistency.ps1` checks:

- the 14 main-robustness bars and their 95% confidence intervals match the
  five-run aggregate summary;
- the six conditional PV-ASR bars and their 95% confidence intervals match the
  five-run aggregate summary;
- retained single-seed auxiliary table exports still match
  `outputs/test_set_results.csv`;
- epsilon-sensitivity figure data contain the complete two-attack, two-model,
  six-budget grid;
- the three official manuscript figures each have PDF, PNG, and SVG variants;
- the manuscript does not reference `figures/legacy`;
- the generated submission bundle excludes legacy figures so reviewers see only
  the official figure set.

## Current Boundary

This audit does not inspect the plotted pixels directly. It verifies the data
closure and packaging boundary that make the figures reproducible from the
current archived result artifacts.

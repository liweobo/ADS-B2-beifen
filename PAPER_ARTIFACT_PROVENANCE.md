# CAT-AD Paper Artifact Provenance

This note maps every manuscript table and figure to the local artifact that
backs it. The goal is to make the paper auditable: a reviewer or artifact
evaluator should be able to locate the source artifact for each displayed
result without guessing.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_paper_artifact_provenance.ps1
```

Expected output includes `paper_artifact_provenance=PASSED`.

## Tables Included by the Manuscript

| Manuscript label | Included file | Source artifact | Provenance check |
|---|---|---|---|
| `tab:positioning` | inline in `paper_lncs/main.tex` | `PRIOR_ART_NOVELTY_MATRIX.md`, `INNOVATION_AND_EVIDENCE.md`, `paper_lncs/references.bib` | Related-work boundary and citations are checked by `tools/verify_novelty_evidence.ps1`. |
| `tab:experimental_setup` | `outputs/tables/table_experimental_setup.tex` | `outputs/tables/table_experimental_setup.csv` | CSV and TeX must both contain the evaluated split, window length, attack setting, and consistency weights. |
| `tab:data_split_audit` | `outputs/publication_benchmark/data_split_audit.tex` | `outputs/publication_benchmark/preflight_report.json`, `outputs/publication_benchmark/data_split_audit.csv` | The table is generated from the preflight report and must show seed coverage, full-data use, aircraft split counts, zero aircraft overlap, and nonempty malicious windows. |
| `tab:multiseed_summary` | `outputs/tables/table_multiseed_summary.tex` | `outputs/publication_benchmark/aggregate_summary.csv`, `per_seed_metrics_long.csv`, `per_seed_metrics_wide.csv` | The paper-facing TeX is regenerated from the archived CSV; benchmark row counts must match the strict gate: 152 aggregate rows, 760 long rows, and 40 wide rows. |
| `tab:paired_multiseed_comparison` | `outputs/tables/table_paired_multiseed_comparison.tex` | `outputs/publication_benchmark/paired_comparisons.csv` | The paper-facing two-panel TeX is regenerated from the archived CSV; the paired comparison CSV must contain 14 rows and match the strict verification report. |
| `tab:literature_detection` | `outputs/literature_benchmark/table_literature_detection.tex` | `outputs/literature_benchmark/aggregate_summary.csv`, `paired_vs_catad.csv`, and `literature_detection_report_manifest.json` | The same-protocol table and report manifest are regenerated and hash-verified from five matched aircraft splits. |
| `tab:physical_feasibility` | `outputs/tables/table_physical_feasibility.tex` | `outputs/tables/table_physical_feasibility.csv` | CSV and TeX must contain valid-start coverage, paired pre/post PVR, New-PVR, conditional PV-ASR, and sub-violation columns. |
| `tab:ablation` | `outputs/tables/table5_ablation_study.tex` | `outputs/tables/table5_ablation_study.csv` | CSV and TeX must both contain CAT-AD, adversarial-training variants, and the no-delta-feature ablation. |

## Figures Included by the Manuscript

| Manuscript label | Included file | Local figure artifacts | Provenance check |
|---|---|---|---|
| `fig:robustness_comparison` | `figures/fig_main_robustness.pdf` | `results/fig_main_robustness_data.csv`; `figures/fig_main_robustness.pdf`, `figures/fig_main_robustness.png`, `figures/fig_main_robustness.svg` | The source CSV and figure must match the five-run aggregate means and 95% confidence intervals. |
| `fig:physical_valid_asr` | `figures/fig_physical_valid_asr.pdf` | `results/fig_physical_valid_asr_data.csv`; `figures/fig_physical_valid_asr.pdf`, `figures/fig_physical_valid_asr.png`, `figures/fig_physical_valid_asr.svg` | The source CSV and figure must match the five-run aggregate conditional PV-ASR means and 95% confidence intervals. |
| `fig:epsilon_sensitivity` | `figures/fig_epsilon_sensitivity.pdf` | `results/fig_epsilon_sensitivity_data.csv`; `figures/fig_epsilon_sensitivity.pdf`, `figures/fig_epsilon_sensitivity.png`, `figures/fig_epsilon_sensitivity.svg` | The manuscript must include the PDF, the source CSV must contain the evaluated epsilon grid, and the preview builder must render the corresponding PNG. |

## Benchmark Manifest Link

The publication benchmark manifest at
`outputs/publication_benchmark/benchmark_manifest.json` records the benchmark
configuration, data hash, code fingerprint, package snapshot, per-seed logs,
and artifact-integrity entries. The provenance verifier checks that the
multi-seed tables and CSV files used by the paper are represented in that
artifact-integrity record.

## Figure Freshness Link

`FIGURE_SOURCE_CONSISTENCY_AUDIT.md` and
`tools/verify_figure_source_consistency.ps1` provide the stricter stale-figure
guard: they check that figure source CSV values agree with the current paper
tables and test-set result export, that the epsilon-sensitivity grid is
complete, and that legacy figures are excluded from the submission bundle.

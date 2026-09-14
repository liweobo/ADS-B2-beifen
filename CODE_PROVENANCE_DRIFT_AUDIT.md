# CAT-AD Code Provenance Drift Audit

This audit records the relationship between the code fingerprint stored in the
multi-seed benchmark manifest and the source tree packaged for review.

## Purpose

The benchmark manifest in `outputs/publication_benchmark/benchmark_manifest.json`
records a SHA-256 fingerprint over the experiment source files that were present
when the five-seed publication benchmark was produced. After the benchmark, a
small number of submission-hygiene changes were made to improve reviewer
reproducibility instructions and regression coverage. These changes should be
visible rather than silently mixed into the artifact package.

The corresponding verifier is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_code_provenance_drift.ps1
```

## Current Drift Boundary

The verifier rebuilds the same source-file set used by the benchmark manifest
and compares current file sizes and SHA-256 hashes against the recorded
manifest entries.

Allowed changed files:

| File | Reason |
| --- | --- |
| `adsb/ablation_table5.py` | Only the generated LaTeX table typography was compacted (`\scriptsize`, narrower column spacing, and shorter headers) to fit the formal LNCS page; experiment computation is unchanged. |
| `adsb/benchmark.py` | Only paper-facing LaTeX rendering was changed: percent escaping, compact aggregate typography, an explanatory interval note, and a two-panel paired-comparison table. Archived numerical CSVs remain the claim source and are checked independently by paper-export regeneration and provenance audits. |
| `adsb/run.py` | Entry-point documentation was changed from a bare Python example to the required `conda run -n testtorch python` form. |
| `adsb/trajectory_compare.py` | CLI helper text was changed to show the required conda invocation. |
| `adsb/paper_tables.py` | Publication-facing model, attack, ground-speed, metric, and table-note terminology was standardized; numerical inputs and computations are unchanged. |
| `adsb/paper_naming.py` | Added canonical `BiLSTM-ERM` and `Norm-bounded PGD` display names while retaining explicit aliases for historical archive keys. |
| `adsb/paper_style.py` | Added the canonical `BiLSTM-ERM` style alias; colors and markers are unchanged. |
| `adsb/plots.py` | Replaced ambiguous model labels in publication-facing plot captions and legends; plotted values are unchanged. |
| `adsb/fig4_asr_pvr_tradeoff.py` | The physical figure was rebound to New-PVR and PV-ASR conditioned on valid starts. |
| `adsb/fig5_epsilon_sensitivity.py` | Replaced the ambiguous baseline display name and clarified figure-export docstrings; plotted values are unchanged. |
| `adsb/model.py` | Comment-only edit: the two output classes and bidirectional state selection are now documented in clear English; executable statements are unchanged. |
| `adsb/dataloading.py` | Added benign train/validation loader views for one-class literature models. The legacy labeled loaders, aircraft split, normalization, and window counts are unchanged; all five split hashes and window summaries are checked byte-for-byte against the archived primary run records. |
| `tools/regenerate_paper_exports.py` | Paper table/figure regeneration output was changed to list repository-relative paths and avoid local absolute-path noise. |
| `tools/build_primary_seed_direction_summary.ps1` | Primary physical claims were switched to conditional PV-ASR on valid starts. |
| `tools/verify_numeric_claims.ps1` | Numeric claims and corrected artifact row counts were rebound to the new benchmark. |
| `tools/verify_manuscript_claim_traceability.ps1` | Manuscript physical claims are checked against conditional benchmark metrics. |
| `tools/verify_claim_hierarchy.ps1` | The primary-claim hierarchy now names conditional PV-ASR. |
| `tools/verify_seed_direction_consistency.ps1` | Per-seed direction checks now use conditional PV-ASR. |
| `tools/verify_physical_metric_semantics.ps1` | Added executable paired pre/post identities, bounds, coverage, and hard-projection checks. |
| `tools/verify_attack_evaluation_sanity.ps1` | Added baseline conditional attack-strength and hard-projection tests. |
| `tools/verify_novelty_evidence.ps1` | The novelty criterion now names paired valid-start physical evaluation. |
| `tools/verify_figure_source_consistency.ps1` | Figure provenance now checks New-PVR and conditional PV-ASR columns. |
| `tools/verify_code_provenance_drift.ps1` | This allowlist records the post-benchmark audit-only changes. |
| `tools/build_zhong.py` | Generated single-file script header examples were changed to show the required conda invocation. |
| `tests/test_benchmark_stats.py` | Synthetic manifest fixture was changed to model the required conda invocation. |
| `tests/test_submission_tex_generation.py` | Updated the expected physical-table header from velocity to the implemented ground-speed constraint. |
| `EXPERIMENTS.md` | Added commands and reporting boundaries for the independently manifested published-model comparison. |

Allowed added files:

| File | Reason |
| --- | --- |
| `tests/test_physical_metrics.py` | Post-benchmark regression tests for targeted anomalous-to-normal attacks, anomalous-only attack application, physical diagnostics, and exact PV-ASR computation. |
| `tests/test_submission_tex_generation.py` | Post-benchmark regression tests for valid percent escaping and readable two-panel formal-paper tables. |
| `adsb/literature_models.py` | Protocol-aligned Fried--Last LSTM-AE, VAE--SVDD, and Contextual AE implementations for the independently manifested literature benchmark. |
| `adsb/literature_training.py` | Normal-only training and one-class calibration for the published-model comparison. |
| `adsb/literature_benchmark.py` | Five-seed literature runner that refuses dataset, aircraft-split, or window-count mismatches with the archived primary benchmark. |
| `adsb/literature_report.py` | Unperturbed-detection table/report generator with canonical model names, artifact-hash verification, and explicit exclusion of failed cross-objective attack values. |
| `tools/audit_literature_attack_resolution.py` | Deterministic step-size counterexample showing why fixed classifier-PGD output is not promoted as one-class robustness evidence. |
| `tests/test_literature_models.py` | Architecture, routing, differentiability, and gradient tests for the three literature models. |
| `tests/test_literature_report.py` | Executable `unittest` regression tests that require complete five-seed unperturbed aggregates, normalize legacy archive names, and prohibit attack columns in the paper-facing literature table. |
| `tests/test_paper_naming.py` | Executable `unittest` checks for canonical display names and backward-compatible archive aliases. |

## Guardrail

This audit does not claim that a benchmark can remain valid after arbitrary
source edits. If files that implement the primary model, attacks, training loop,
benchmark runner, publication claims, or artifact verifier drift from the
manifest, the verifier fails: rerun before making updated quantitative claims.
The sole data-loading exception is additive:
it exposes clean views for the independent one-class benchmark while preserving
the legacy loaders, and the new runner verifies all five archived aircraft split
hashes and window/label summaries before accepting a run.

The accepted drift is limited to reviewer-facing command examples, paper-export
formatting and logging hygiene, tests, and the separately manifested literature
benchmark. In particular, the accepted
`adsb/benchmark.py` drift is confined to LaTeX rendering; the archived numerical
CSV files remain immutable evidence and regenerate into the checked paper exports.
The primary numerical claims remain tied to the manifest-recorded benchmark
artifacts and the strict publication gate.

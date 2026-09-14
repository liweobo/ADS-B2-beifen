# CAT-AD Artifact Reproducibility Checklist

This checklist is written for a reviewer or artifact evaluator who receives the
submission bundle and wants to verify the experiment code and paper artifacts
without downloading software.

## Scope

- Task: robust ADS-B trajectory anomaly detection under targeted
  anomalous-to-normal evasion.
- Method under test: CAT-AD.
- Reference classifier: BiLSTM-ERM.
- Main adversarial settings: Norm-bounded PGD, Projection-based Phys-PGD, and
  Penalty-based Phys-PGD.
- Main robustness metrics: F1-score, ASR, PVR, and PV-ASR.
- Seeds in the current benchmark: `42,43,44,45,46`.

## Included Artifacts

- Code: `adsb/`, `tools/`, `tests/`
- Manuscript source: `paper_lncs/main.tex`, `paper_lncs/references.bib`
- Preview PDF: `output/pdf/catad_submission_preview.pdf`
- Data sample: `sample_adsb_decoded.csv`
- Generated benchmark artifacts: `outputs/publication_benchmark/`
  - `preflight_report.json`
  - `data_split_audit.csv`
  - `data_split_audit.tex`
  - `primary_seed_direction_summary.csv`
  - `primary_seed_direction_summary.tex`
- Generated paper tables: `outputs/tables/`
- Figures: `figures/`
- Evidence documents:
  - `REVIEWER_QUICKSTART.md`
  - `INNOVATION_AND_EVIDENCE.md`
  - `PRIOR_ART_NOVELTY_MATRIX.md`
  - `PRIOR_ART_CRITERIA_COVERAGE.tsv`
  - `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md`
  - `REVIEWER_OBJECTION_RESPONSE_AUDIT.md`
  - `DATA_PROVENANCE_AND_ETHICS.md`
  - `DATASET_PROFILE_AUDIT.md`
  - `EXTERNAL_VALIDITY_SCOPE_AUDIT.md`
  - `ENVIRONMENT_REPRODUCIBILITY.md`
  - `CODE_PROVENANCE_DRIFT_AUDIT.md`
  - `ABLATION_AND_SENSITIVITY_AUDIT.md`
  - `THRESHOLD_AND_HYPERPARAMETER_AUDIT.md`
  - `PAPER_ARTIFACT_PROVENANCE.md`
  - `BASELINE_COMPETITIVENESS_AUDIT.md`
  - `DOUBLE_BLIND_REVIEW_CHECKLIST.md`
  - `ATTACK_EVALUATION_SANITY_CHECKLIST.md`
  - `STATISTICAL_INTERPRETATION_CHECKLIST.md`
  - `NUMERIC_CLAIMS_LEDGER.md`
  - `MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md`
  - `CLAIM_HIERARCHY_AUDIT.md`
  - `SEED_DIRECTION_CONSISTENCY_AUDIT.md`
  - `PHYSICAL_METRIC_SEMANTICS_AUDIT.md`
  - `TERMINOLOGY_AND_NAMING_AUDIT.md`
  - `MANUSCRIPT_REVIEWABILITY_AUDIT.md`
  - `TOP_CONFERENCE_READINESS_AUDIT.md`
  - `SUBMISSION_COMPLETION_AUDIT.md`
  - `SUBMISSION_READINESS.md`
  - `ARTIFACT_EVALUATION_GUIDE.md`
  - `WORKSPACE_HYGIENE_AUDIT.md`
  - `TEX_SOURCE_PORTABILITY_AUDIT.md`
  - `FORMAL_PDF_BUILD_AUDIT.md`
  - `FIGURE_SOURCE_CONSISTENCY_AUDIT.md`
  - `PAPER_EXPORT_REGENERATION_AUDIT.md`

## Local Environment Requirement

Python commands must use the project conda environment:

```powershell
conda run -n testtorch python
```

The no-download audit does not install packages and does not call package
managers. It assumes the local machine already has the project environment and
the local preview tools used by the repository.

## Quick Verification

Run this command from the repository or extracted bundle root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload
```

Expected high-level result:

- no-download policy: `OK`
- strict publication gate: `VERIFY PASSED`
- unit tests: `OK`
- README review entry: `PASSED`
- artifact license and citation: `PASSED`
- numeric claims traceability: `PASSED`
- dataset profile: `PASSED`
- external-validity scope: `PASSED`
- environment reproducibility: `PASSED`
- code provenance drift: `PASSED`
- ablation and sensitivity: `PASSED`
- threshold and hyperparameter audit: `PASSED`
- baseline competitiveness: `PASSED`
- artifact evaluation guide: `PASSED`
- workspace hygiene: `PASSED`
- terminology and naming: `PASSED`
- manuscript reviewability: `PASSED`
- TeX source portability: `PASSED`
- formal PDF build readiness: `PASSED`
- figure source consistency: `PASSED`
- paper export regeneration: `PASSED`
- recent prior-art challenge: `PASSED`
- completion audit: `PASSED`
- preview artifact: `PASSED`
- anonymized bundle: `PASSED`
- submission bundle verification: `status=PASSED`
- preview PDF metadata, warning-free Pandoc log, and full-page render check:
  `OK`

For the shortest reviewer-oriented entry point, see
`REVIEWER_QUICKSTART.md`. It lists the one-command audit, expected outputs,
data boundary, and external limits.

## Rebuild Local Review Artifacts

To rebuild the local preview PDF and submission bundle without downloading
software:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload -BuildPreviewPdf -BuildSubmissionBundle
```

Expected generated artifacts:

- `output/pdf/catad_submission_preview.pdf`
- `output/submission/catad_topconf_submission_bundle.zip`
- `output/submission/catad_topconf_submission_bundle.manifest.tsv`
- `output/submission/catad_topconf_submission_bundle.manifest.json`

## Verify Bundle Integrity Offline

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_submission_bundle.ps1
```

Expected output includes:

- `manifest_files_checked=...`
- `extracted_strict_gate=PASSED`
- `status=PASSED`

The verifier extracts the zip to a temporary directory, checks every manifest
file by byte count and SHA-256, checks the strict gate report, reruns the
strict publication gate inside the extracted bundle, and removes the temporary
directory unless `-KeepExtracted` is used.

## Verify Artifact Evaluation Guide

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_artifact_evaluation_guide.ps1
```

Expected output includes `artifact_evaluation_guide=PASSED`,
`guide_markers_checked=64`, and `required_files_checked=61`. This check verifies
the venue-neutral artifact-evaluation guide, badge-readiness boundary, fast
path, deep-check matrix, required evidence files, and explicit external limits.

## Verify Artifact License and Citation

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_artifact_license_citation.ps1
```

Expected output includes `artifact_license_citation=PASSED`,
`license_markers_checked=12`, `citation_markers_checked=8`, and
`forbidden_claims_checked=8`. This check verifies the anonymous review use
statement, citation metadata, public-redistribution boundary, and public-license
external limit.

## Verify README Review Entry

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_readme_review_entry.ps1
```

Expected output includes `readme_review_entry=PASSED`,
`readme_markers_checked=44`, `entry_files_checked=26`, and
`forbidden_claims_checked=8`. This check verifies that the root `README.md`
exposes the no-download audit, rebuild command, main entry points, conda rule,
artifact boundary, and external limits without claiming acceptance.

## Verify Workspace Hygiene

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_workspace_hygiene.ps1
```

Expected output includes `workspace_hygiene=PASSED`,
`non_submission_artifacts_documented=9`, `excluded_manifest_paths_checked=9`,
and `entrypoints_checked=8`. This check verifies that local raw snapshots,
historical scripts, old archives, and scratch files are documented as
non-submission artifacts and are absent from the review bundle manifest and
zip.

## Verify Recent Prior-Art Challenge

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_recent_prior_art_challenge.ps1
```

Expected output includes `recent_prior_art_challenge=PASSED`,
`recent_sources_checked=12`, `criteria_checked=6`, and
`paper_citations_checked=12`. This check verifies that recent 2025/2026 ADS-B
IDS, attack-vector benchmarks, lightweight IDS, physics-consistent robust
trajectory anomaly detection, adversarial-perturbation detection, attack-type
detection, xLSTM/Transformer IDS, data-security, and ADS-B/RID security-survey
challenge references are cited in the manuscript and bounded by the novelty
matrix and evidence snapshot.

## Verify Reviewer-Objection Response Matrix

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_reviewer_objection_response.ps1
```

Expected output includes `reviewer_objection_response=PASSED`,
`objections_checked=12`, `evidence_paths_checked=42`,
`verifier_outputs_checked=48`, `coverage_rows_checked=25`,
`primary_seed_rows_checked=6`, and `full_prior_art_rows=0`. This check maps
likely reviewer objections to concrete evidence paths, verifier commands,
expected outputs, and non-rebuttal boundaries.

## Verify Terminology and Naming

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_terminology_and_naming.ps1
```

Expected output includes `terminology_and_naming=PASSED`,
`publication_surfaces_checked=17`, and `definitions_checked=22`. This check
requires canonical model and attack names, first-use definitions, consistent
class/feature/metric terminology, and explicit aliases for immutable archive
schema keys.

## Verify Manuscript Reviewability

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_manuscript_reviewability.ps1
```

Expected output includes `manuscript_reviewability=PASSED`,
`abstract_words=180`, `contribution_items_checked=3`,
`sections_checked=12`, `citations_checked=24`, and `pdf_pages=11`. This check
verifies anonymous review metadata, bounded abstract length, explicit
contributions, ordered review-critical sections, citation closure, placeholder
absence, and plausible A4 preview-PDF metadata.

## Verify Attack Strength Configuration

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_strength_configuration.ps1
```

Expected output includes `attack_strength_configuration=PASSED`,
`hyperparameters_checked=12`, `paired_attack_rows_checked=3`,
`epsilon_rows_checked=24`, and `epsilon_levels_checked=6`. This check verifies
that the benchmark manifest records fixed PGD/Phys-PGD attack hyperparameters,
the PGD step-size coverage reaches the evaluation budget, the undefended
baseline is vulnerable under all evaluated attack families, and the exported
epsilon-sensitivity rows cover both physical attack families.

## Verify Method Implementation Traceability

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_method_implementation_traceability.ps1
```

Expected output includes `method_implementation_traceability=PASSED`,
`training_markers_checked=23`, `attack_markers_checked=8`,
`seed_logs_checked=5`, and `manifest_hyperparameters_checked=11`. This check
links the manuscript objective to the training code, attack code, model code,
benchmark-manifest hyperparameters, and archived seed logs.

## Verify Baseline Competitiveness

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_baseline_competitiveness.ps1
```

Expected output includes `baseline_competitiveness=PASSED`,
`strong_training_baselines_checked=3`, and `ablation_variants_checked=8`. This
check verifies that the auxiliary ablation table includes strong
adversarial-training baselines beyond ERM and that the manuscript does not
claim CAT-AD dominates every single-run ablation metric.

## Verify Dual-Use Safety

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_dual_use_safety.ps1
```

Expected output includes `dual_use_safety=PASSED`,
`safety_markers_checked=18`, and
`forbidden_operational_markers_checked=13`. This check verifies that the
manuscript and artifact docs frame the work as offline defensive evaluation and
that core code/scripts do not include live ADS-B radio, socket, serial, SDR, or
operational air-traffic integration markers.

## Verify TeX Source Portability

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_tex_source_portability.ps1
```

Expected output includes `tex_source_portability=PASSED`,
`tex_inputs_checked=8`, `figures_checked=3`, and `citations_checked=22`. This
check verifies TeX source closure, official LNCS style hashes, local input and
figure paths, BibTeX citation mapping, forbidden absolute paths and shell-escape
style commands, and bundle inclusion of source inputs plus the formal PDF.

## Verify Formal PDF Build Readiness

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_formal_pdf_build_readiness.ps1
```

Expected output includes `formal_pdf_build_readiness=PASSED` and either
`formal_pdf_build=PASSED` when a supported TeX engine is already installed, or
`formal_pdf_build=SKIPPED_NO_TEX_TOOL` when no supported TeX engine is on
`PATH`. The archived `output/pdf/catad_submission_latex_updated.pdf` is already a
verified 18-page official-LNCS build; the skipped status applies only to a local
rebuild attempt. The check verifies the no-download entry point, supported
engines, TeX-log quality, and formal artifact.

## Regenerate Paper Tables And Figures

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_paper_export_regeneration.ps1
```

Expected output includes `paper_export_regeneration=PASSED`,
`stable_exports_checked=18`, and the command
`conda run --no-capture-output -n testtorch python tools\regenerate_paper_exports.py`.
The verifier runs the regeneration command, checks byte-stable CSV/TeX/PNG
exports, and reruns figure-source consistency.

## Verify Figure Source Consistency

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_figure_source_consistency.ps1
```

Expected output includes `figure_source_consistency=PASSED`,
`physical_figure_rows_checked=6`, `epsilon_rows_checked=24`, and
`legacy_bundle_entries=0`. This check verifies that figure-source CSV values
match current table/test-result sources, official figure PDF/PNG/SVG triads
exist, and legacy figures are excluded from the submission bundle.

## Verify Numeric Claims

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_numeric_claims.ps1
```

Expected output:

- `numeric_claims=PASSED`
- `primary_claims_checked=6`
- `table_rows_checked=8`

This check ties the main claims in `NUMERIC_CLAIMS_LEDGER.md` to
`paired_comparisons.csv`, `aggregate_selected_summary.tex`, and
`verification_report.md`.

## Verify Manuscript Claim Traceability

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_manuscript_claim_traceability.ps1
```

Expected output includes `manuscript_claim_traceability=PASSED`,
`narrative_claims_checked=11`, and `epsilon_settings_checked=2`. This check
maps manuscript result wording to code markers, generated benchmark CSV/TeX
artifacts, physical-feasibility rows, paired comparisons, and
epsilon-sensitivity data.

## Verify Claim Hierarchy

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_claim_hierarchy.ps1
```

Expected output includes `claim_hierarchy=PASSED`,
`primary_claims_checked=6`, `auxiliary_boundaries_checked=4`, and
`forbidden_hierarchy_claims_checked=10`. This check verifies that primary
claims come from the five-seed paired benchmark while ablation, sensitivity,
strong-baseline, and PVR evidence remain auxiliary or diagnostic.

## Verify Seed-Direction Consistency

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_seed_direction_consistency.ps1
```

Expected output includes `seed_direction_consistency=PASSED`,
`primary_claims_checked=6`, `seed_pairs_checked=30`, and
`paired_rows_checked=6`, plus `summary_csv_rows_checked=6` and
`summary_tex_markers_checked=7`. This check recomputes the six primary claim
directions from per-seed metric rows, verifies that all five paired seeds
support each primary direction, and checks that
`primary_seed_direction_summary.csv` and
`primary_seed_direction_summary.tex` match the recomputed values.

## Verify Physical Metric Semantics

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_physical_metric_semantics.ps1
```

Expected output includes `physical_metric_semantics=PASSED`,
`paper_definitions_checked=5`, `code_markers_checked=7`,
`test_markers_checked=4`, and `metric_rows_checked=42`. This check verifies
that ASR, PVR, and PV-ASR are defined and implemented at the attacked
anomalous-sample level and that PV-ASR satisfies the expected per-sample
intersection bounds in generated result rows.

## Verify Attack Evaluation Sanity

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_evaluation_sanity.ps1
```

Expected output includes `attack_evaluation_sanity=PASSED`. This check verifies
attack-code markers, targeted-attack regression tests, and strong baseline ASR
under the evaluated attack families.

## Verify Statistical Interpretation

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_statistical_interpretation.ps1
```

Expected output includes `statistical_interpretation=PASSED`. This check
verifies paired-comparison row counts, effect sizes, confidence intervals,
exact sign-flip p-values, and cautious statistical wording.

## Verify Novelty Evidence

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_novelty_evidence.ps1
```

Expected output includes `novelty_evidence=PASSED`,
`coverage_rows_checked=25`, and `full_prior_art_rows=0`. This check verifies
that the paper, bibliography, innovation note, prior-art matrix, and
machine-readable C1-C6 coverage table all preserve the scoped novelty boundary
and cautious claim wording.

## Verify Paper Artifact Provenance

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_paper_artifact_provenance.ps1
```

Expected output includes `paper_artifact_provenance=PASSED`. This check maps
manuscript tables and figures to local CSV, benchmark, figure, and manifest
records.

## Rebuild Data Split Audit Table

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build_data_split_audit_table.ps1
```

Expected output includes `data_split_audit_rows=12`. The generated
`data_split_audit.tex` is included by the manuscript and is derived from
`outputs/publication_benchmark/preflight_report.json`.

## Verify Data Provenance and Ethics

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_data_provenance_ethics.ps1
```

Expected output includes `data_provenance_ethics=PASSED`,
`preflight_runs_checked=5`, `aircraft_overlap_violations=0`, and
`bundle_manifests_checked=...`. This check verifies the benchmark CSV SHA-256,
manifest data hash, local raw-snapshot hashes when present, preflight split and
leakage evidence, bundled-data boundary, raw upstream snapshot exclusion from
the submission bundle, and offline safety restrictions.

## Verify Dataset Profile

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_dataset_profile.ps1
```

Expected output includes `dataset_profile=PASSED`,
`raw_rows_checked=217148`, `preflight_runs_checked=5`, and
`per_attack_summaries_checked=15`. This check verifies the raw CSV header,
byte size, SHA-256, row count, time range, feature ranges, model-loaded and
filtered counts, aircraft split counts, overlap, and malicious-window coverage.

## Verify External Validity Scope

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_external_validity_scope.ps1
```

Expected output includes `external_validity_scope=PASSED`,
`scope_markers_checked=18`, `preflight_counts_checked=8`, and
`forbidden_generalization_claims_checked=8`. This check verifies that the
manuscript and guardrails scope the benchmark to one UTC day, 20 raw aircraft
identifiers, 19 filtered aircraft, and the archived split/preflight boundary.

## Verify Environment Reproducibility

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_environment_reproducibility.ps1
```

Expected output includes `environment_reproducibility=PASSED`,
`conda_env=testtorch`, `packages_checked=5`, and
`determinism_markers_checked=5`. This check verifies the current conda
environment against the benchmark manifest's key package versions, CUDA
availability, hashes, and deterministic settings.

## Verify Compute Resource Audit

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_compute_resource_audit.ps1
```

Expected output includes `compute_resource_audit=PASSED`,
`seeds_checked=5`, `logs_checked=5`, `metrics_rows_checked=480`, and
`observed_wall_clock_minutes=158.09`. This check verifies the observed
five-seed benchmark runtime boundary, GPU/CUDA metadata, per-seed logs, and
per-seed metric row counts from the archived benchmark artifacts.

## Verify Code Provenance Drift

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_code_provenance_drift.ps1
```

Expected output includes `code_provenance_drift=PASSED`,
`changed_files_checked=4`, and `added_files_checked=1`. This check compares
the current source tree with the benchmark manifest code fingerprint and fails
on unexplained core experiment-code drift.

## Verify Ablation And Sensitivity

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_ablation_sensitivity.ps1
```

Expected output includes `ablation_sensitivity=PASSED`,
`ablation_variants_checked=8`, and `epsilon_rows_checked=24`. This check
verifies component variants, ablation CSV/JSON consistency, epsilon-sensitivity
source rows, and rendered sensitivity figure artifacts.

## Verify Threshold And Hyperparameter Boundary

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_threshold_hyperparameter_audit.ps1
```

Expected output includes `threshold_hyperparameter_audit=PASSED`,
`run_records_checked=5`, and `threshold_records_checked=10`. This check
verifies validation-only threshold selection, fixed test-time thresholds,
per-seed run-record metadata, zero aircraft-split overlap, and manifest
hyperparameters.

## Verify Baseline Fairness

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_baseline_fairness.ps1
```

Expected output includes `baseline_fairness=PASSED`,
`run_records_checked=5`, and `metric_pairs_checked=240`. This check verifies
shared detector construction, shared train/validation/test loaders, common
training kwargs, equal class weights, validation-only thresholds, and paired
Baseline/Proposed metric rows.

## Verify Failure Modes And Negative Results

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_failure_mode_negative_results.ps1
```

Expected output includes `failure_mode_negative_results=PASSED`,
`nonclaimed_pvr_rows_checked=2`, and `paired_rows_checked=12`. This check
verifies the `CAT-AD w/o Delta X` high-FAR failure mode, non-primary PVR
boundary, conservative five-seed significance interpretation, and
no-certificate limitation.

## Verify Double-Blind Submission

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_double_blind_submission.ps1
```

Expected output includes `double_blind_submission=PASSED`. This check verifies
anonymous manuscript metadata, preview author metadata, contact-macro absence,
and bundle-facing identity markers.

## Verify Unit Tests

```powershell
conda run -n testtorch python -m unittest discover -s tests -p "test*.py"
```

Expected output includes:

- `OK`
- targeted-attack, projection-path, penalty-attack diagnostics, PV-ASR, ASR,
  physical-feasibility flag, benchmark-statistics, preflight, and strict-gate
  regression tests are discovered.

## Verify Completion Audit

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_completion_audit.ps1
```

Expected output:

- `completion_audit=PASSED`
- `requirements_checked=50`
- `evidence_files_checked=121`
- `limits_checked=2`

This check ties `SUBMISSION_COMPLETION_AUDIT.md` to the local code, manuscript,
benchmark, bundle, and explicit external-boundary evidence.

## Verify Preview Artifact

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_preview_artifact.ps1
```

Expected output:

- `preview_artifact=PASSED`
- `html_markers_checked=...`
- `pandoc_log_warnings=0`
- `rendered_pages_checked=...`

This check verifies that the generated review HTML contains title, result-table,
figure, PV-ASR, ethics, limitations, and reference markers, and that the preview
PDF has a warning-free Pandoc conversion log, A4 metadata, and every page
renders.

## Verify Rendered PDF Content

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_rendered_pdf_content.ps1
```

Expected output includes `rendered_pdf_content=PASSED`, `pages_checked=11`,
`formal_pages_checked=18`, `html_markers_checked=27`,
`nonblank_pages_checked=11`, and `formal_nonblank_pages_checked=18`. This check renders the review PDF to page
PNGs and verifies page dimensions, nonblank sampled pixels, dark text/line
samples, and nontrivial content bounding boxes.

## Verify Bundle Anonymity and Portability

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_anonymized_bundle.ps1
```

Expected output:

- `anonymized_bundle=PASSED`
- `text_files_checked=...`

This check extracts the submission zip and scans reviewer-facing text artifacts
for local usernames, home-directory paths, and absolute workstation project
paths.

## Full Benchmark Rerun

The full benchmark can be rerun with:

```powershell
conda run -n testtorch python tools\run_publication_gate.py `
  --csv sample_adsb_decoded.csv `
  --seeds "42,43,44,45,46" `
  --output-dir outputs\publication_benchmark
```

This is more expensive than the quick audit because it retrains and reevaluates
models for all seeds. The current bundle includes completed benchmark artifacts
and strict-gate verification output, so reviewers can first use the quick
verification commands above.

## Known Limitation

The current no-download workflow cannot create a formal LNCS PDF on a machine
that does not already have TeX/BibTeX installed. The bundle includes a
Pandoc/Chrome preview PDF for local review, the full LaTeX source, and
`tools/build_submission_pdf.ps1` for formal venue PDF generation on an already
provisioned TeX machine.

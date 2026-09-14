# ADS-B CAT-AD Submission Readiness

This repository contains the code, benchmark artifacts, and manuscript sources
needed to prepare a top-tier-conference-style experimental submission for
CAT-AD. Publication is not guaranteed by the code alone; the final claim must be
supported by a passed strict publication gate and by a complete
venue-compliant manuscript.

## Main Experiment Code

- `adsb/run.py`: main CLI entry point.
- `adsb/benchmark.py`: multi-seed benchmark runner with aggregate statistics,
  paired comparisons, environment metadata, provenance, and artifact integrity.
- `adsb/verify_artifacts.py`: strict publication verification gate.
- `adsb/publication_preflight.py`: data, split, leakage, and malicious-window
  preflight checks before training.
- `tools/run_publication_gate.py`: one-command preflight, benchmark, and strict
  verification wrapper.
- `tools/benchmark_status.py`: inspect a running or completed benchmark.
- `tools/build_data_split_audit_table.ps1`: regenerate the paper's data split
  and leakage audit table from the publication preflight report.
- `tools/verify_data_provenance_ethics.ps1`: verify benchmark CSV hash,
  preflight split/leakage evidence, bundled-data boundary, and offline safety
  restrictions.
- `tools/verify_dual_use_safety.ps1`: verify offline defensive-use wording, no
  live-system interaction, no operational injection guidance, and absence of
  socket/serial/SDR/transmitter integration markers in core code.
- `tools/verify_dataset_profile.ps1`: verify raw CSV profile, model-loaded
  data boundary, filtering counts, and split/window coverage.
- `tools/verify_external_validity_scope.ps1`: verify one-day/aircraft-count
  dataset-scope wording and prevent overbroad external-validity claims.
- `tools/verify_environment_reproducibility.ps1`: verify that the current
  `testtorch` conda environment matches the benchmark manifest's key package
  versions and deterministic settings.
- `tests/test_physical_metrics.py`: regression checks for anomalous-only
  targeted attacks, projection-based Phys-PGD plumbing, penalty-based Phys-PGD
  diagnostics and budget bounds, targeted ASR, trajectory-level physical
  feasibility flags, and exact per-sample PV-ASR.
- `tests/test_benchmark_stats.py`: regression checks for benchmark statistics,
  resume behavior, preflight checks, and strict artifact verification.

## Manuscript Sources

- `paper_lncs/main.tex`: LNCS/Springer-style manuscript source.
- `README.md`: root anonymous reviewer landing page with the no-download audit
  command, rebuild command, main entry points, conda rule, artifact boundary,
  and external limits.
- `LICENSE`: anonymous review artifact use statement.
- `CITATION.cff`: anonymous review citation metadata.
- `README_REVIEW_ENTRY_AUDIT.md`: root README review-entry audit.
- `ARTIFACT_LICENSE_AND_CITATION_AUDIT.md`: anonymous review license/citation
  boundary audit.
- `REVIEWER_QUICKSTART.md`: shortest no-download reviewer path with expected
  outputs, data boundary, and external limits.
- `INNOVATION_AND_EVIDENCE.md`: paper-level innovation claims, rationale, and
  code/experiment evidence mapping.
- `PRIOR_ART_NOVELTY_MATRIX.md`: falsifiable prior-art boundary showing which
  representative papers do and do not cover CAT-AD's combined protocol.
- `PRIOR_ART_CRITERIA_COVERAGE.tsv`: machine-readable C1-C6 prior-art coverage
  table used to verify that no non-CAT-AD row is marked as fully subsuming the
  contribution.
- `PRIOR_ART_EVIDENCE_SNAPSHOT.md`: dated external-source, search-query, and
  repository-evidence snapshot for the novelty boundary.
- `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md`: recent 2025/2026 ADS-B IDS,
  attack-vector benchmark, lightweight IDS, adversarial-perturbation detection,
  attack-type detection, xLSTM/Transformer IDS, data-security, ADS-B security
  survey, and ADS-B/RID survey challenge references with a C1-C6
  novelty-boundary check.
- `ARTIFACT_REPRODUCIBILITY_CHECKLIST.md`: artifact-evaluation checklist with
  local verification commands and expected outputs.
- `ARTIFACT_EVALUATION_GUIDE.md`: venue-neutral artifact-evaluation evidence
  matrix, fast path, deep checks, and official-badge boundary.
- `WORKSPACE_HYGIENE_AUDIT.md`: local root scratch/raw-file boundary showing
  which historical scripts, old archives, and raw snapshots are intentionally
  excluded from the review bundle.
- `TEX_SOURCE_PORTABILITY_AUDIT.md`: TeX source-closure, path-portability,
  bibliography, bundle-manifest, and formal-PDF boundary audit.
- `FORMAL_PDF_BUILD_AUDIT.md`: formal LaTeX PDF build-helper, supported-engine,
  and no-TeX boundary audit.
- `ADAPTIVE_ATTACK_AUDIT.md`: weak-attack and gradient-masking risk audit with
  local tests and benchmark attack-strength signals.
- `ATTACK_STRENGTH_CONFIGURATION_AUDIT.md`: fixed attack-budget, PGD-step,
  penalty-Phys-PGD, and epsilon-sensitivity configuration audit.
- `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md`: paper objective,
  training-loss, attack-code, model-feature, manifest, and seed-log
  traceability audit.
- `DATA_PROVENANCE_AND_ETHICS.md`: dataset hash, preflight split evidence,
  bundled-data boundary, and offline safety-use statement.
- `DUAL_USE_SAFETY_AUDIT.md`: offline defensive-use and operational-misuse
  boundary audit.
- `DATASET_PROFILE_AUDIT.md`: raw CSV profile, model-loaded/filtering counts,
  aircraft/time/feature ranges, and split/window coverage boundary.
- `EXTERNAL_VALIDITY_SCOPE_AUDIT.md`: one-day, raw-aircraft, filtered-aircraft,
  and external-validity overclaim boundary.
- `ENVIRONMENT_REPRODUCIBILITY.md`: conda environment, key package, and
  determinism boundary for no-download artifact review.
- `COMPUTE_RESOURCE_AUDIT.md`: observed hardware, GPU/CUDA environment, and
  five-seed benchmark wall-clock runtime boundary.
- `CODE_PROVENANCE_DRIFT_AUDIT.md`: source-code fingerprint drift boundary
  between the benchmark manifest and the review package.
- `ABLATION_AND_SENSITIVITY_AUDIT.md`: ablation-table and
  perturbation-budget sensitivity evidence boundary.
- `FIGURE_SOURCE_CONSISTENCY_AUDIT.md`: figure-source freshness,
  table/test-result consistency, epsilon-grid coverage, and legacy-figure
  packaging boundary.
- `PAPER_EXPORT_REGENERATION_AUDIT.md`: paper-facing table/figure regeneration
  command, byte-stable CSV/TeX/PNG output boundary, and no-capture Conda
  workflow.
- `THRESHOLD_AND_HYPERPARAMETER_AUDIT.md`: validation-only threshold,
  fixed-test-threshold, and hyperparameter snapshot audit.
- `BASELINE_FAIRNESS_AUDIT.md`: shared-architecture, shared-split,
  validation-threshold, and paired-comparison fairness audit.
- `BASELINE_COMPETITIVENESS_AUDIT.md`: strong adversarial-training baseline
  and auxiliary ablation interpretation audit.
- `FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md`: failure-mode, PVR non-claim,
  conservative significance, and no-certificate boundary audit.
- `CLAIM_SCOPE_GUARDRAILS.md`: wording guardrails for allowed claims,
  required limiting language, and disallowed overclaims.
- `NUMERIC_CLAIMS_LEDGER.md`: headline numeric claim ledger mapping paper
  claims to generated CSV, TeX, and verification artifacts.
- `MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md`: narrative claim-to-evidence map
  for threat-model, attack-strength, high-F1/low-ASR, PV-ASR, and sensitivity
  statements.
- `CLAIM_HIERARCHY_AUDIT.md`: primary-vs-auxiliary evidence hierarchy audit
  for five-seed paired claims, ablations, sensitivity, strong baselines, and
  PVR diagnostics.
- `SEED_DIRECTION_CONSISTENCY_AUDIT.md`: per-seed primary-claim direction audit
  verifying that the six primary claim directions hold in all five seeds.
- `PHYSICAL_METRIC_SEMANTICS_AUDIT.md`: sample-level ASR/PVR/PV-ASR semantics
  audit tying paper definitions to code, regression tests, and generated rows.
- `TERMINOLOGY_AND_NAMING_AUDIT.md`: canonical model, attack, class, feature,
  metric, and comparator naming audit with an explicit archive-schema boundary.
- `MANUSCRIPT_REVIEWABILITY_AUDIT.md`: anonymous review-entry,
  contribution-shape, citation-closure, preview HTML, and A4 preview-PDF
  metadata audit.
- `RENDERED_PDF_CONTENT_AUDIT.md`: rendered preview-PDF page count, A4
  dimensions, nonblank pixel samples, and content bounding-box audit.
- `TOP_CONFERENCE_READINESS_AUDIT.md`: reviewer-risk and evidence matrix for
  top-conference-style submission checks.
- `SUBMISSION_COMPLETION_AUDIT.md`: requirement-by-requirement audit separating
  locally proven deliverables from external peer-review and TeX dependencies.
- `tools/build_submission_preview_pdf.ps1`: reproducible Pandoc/Chrome builder
  for the local manuscript preview PDF.
- `tools/build_submission_pdf.ps1`: no-download formal LaTeX PDF builder for
  machines that already expose `latexmk`, `tectonic`, or `pdflatex` plus
  `bibtex`.
- `tools/package_submission_bundle.ps1`: reproducible submission-bundle builder
  for packaging code, tests, manuscript sources, figures, tables, benchmark
  artifacts, preview PDF, and sample data.
- `tools/verify_submission_bundle.ps1`: offline verifier for extracting the
  submission bundle, checking every manifest SHA-256 and byte count, and
  rerunning the strict publication gate inside the extracted bundle.
- `tools/verify_numeric_claims.ps1`: local verifier for primary claim values
  and selected multi-seed table rows.
- `tools/verify_manuscript_claim_traceability.ps1`: local verifier that maps
  manuscript narrative claims to code markers, generated CSV/TeX artifacts,
  physical-feasibility rows, and epsilon-sensitivity data.
- `tools/verify_claim_hierarchy.ps1`: local verifier that primary numeric
  claims come from five-seed paired comparisons while ablation, sensitivity,
  strong-baseline, and PVR evidence remain auxiliary or diagnostic.
- `tools/verify_seed_direction_consistency.ps1`: local verifier that recomputes
  30 seed-level primary-claim differences and requires each to be positive in
  the claim direction.
- `tools/verify_physical_metric_semantics.ps1`: local verifier for sample-level
  ASR/PVR/PV-ASR definitions, exact per-sample PV-ASR, and generated metric-row
  bounds.
- `tools/verify_terminology_and_naming.ps1`: local verifier for first-use
  definitions, canonical publication labels, prohibited ambiguous display names,
  and legacy archive-key mappings.
- `tools/verify_manuscript_reviewability.ps1`: local verifier for anonymous
  manuscript metadata, abstract length, contribution count, section order,
  citation closure, placeholder-free preview HTML, and preview PDF metadata.
- `tools/verify_rendered_pdf_content.ps1`: local verifier for rendered
  preview-PDF page content, dimensions, nonblank pixels, and content boxes.
- `ATTACK_EVALUATION_SANITY_CHECKLIST.md`: attack-strength and
  gradient-masking sanity checklist.
- `tools/verify_attack_evaluation_sanity.ps1`: local verifier for targeted
attack implementation, dropout handling during PGD, anomalous-only attack
  application, attack-unit tests, and high baseline ASR under evaluated attacks.
- `tools/verify_attack_strength_configuration.ps1`: local verifier for
  manifest-recorded attack hyperparameters, PGD step-size coverage, penalty
  schedule/weights, paired ASR rows, and epsilon-sensitivity rows.
- `tools/verify_method_implementation_traceability.ps1`: local verifier that
  the manuscript CAT-AD objective maps to the archived training code, attack
  code, model feature path, manifest hyperparameters, and seed logs.
- `tools/verify_dual_use_safety.ps1`: local verifier for offline defensive-use
  wording, no live-system interaction, no operational injection guidance, and
  absence of socket/serial/SDR/transmitter integration markers in core code.
- `STATISTICAL_INTERPRETATION_CHECKLIST.md`: effect-size-first statistical
  interpretation boundary for five-seed paired comparisons.
- `tools/verify_statistical_interpretation.ps1`: local verifier for paired row
  counts, effect sizes, confidence intervals, exact sign-flip p-values, and
  absence of overstrong significance wording.
- `PAPER_ARTIFACT_PROVENANCE.md`: manuscript table/figure provenance map.
- `tools/verify_paper_artifact_provenance.ps1`: local verifier for manuscript
  table inputs, CSV sources, figure variants, benchmark row counts, and
  manifest artifact-integrity entries.
- `tools/verify_figure_source_consistency.ps1`: local verifier for figure
  source CSV freshness, table/test-result consistency, epsilon-grid coverage,
  official figure triads, and legacy-figure exclusion from the submission
  bundle.
- `tools/verify_paper_export_regeneration.ps1`: local verifier that runs the
  paper-export regeneration command through
  `conda run --no-capture-output -n testtorch python`, checks byte-stable
  CSV/TeX/PNG exports, and reruns figure-source consistency.
- `tools/verify_code_provenance_drift.ps1`: local verifier that compares the
  current source tree with the benchmark manifest code fingerprint and fails on
  unexplained core experiment-code drift.
- `tools/verify_ablation_sensitivity.ps1`: local verifier for ablation
  variants, CSV/JSON consistency, epsilon-sensitivity source rows, and figure
  artifacts.
- `tools/verify_threshold_hyperparameter_audit.ps1`: local verifier for
  validation-only threshold selection, per-seed threshold records,
  aircraft-split overlap, and manifest hyperparameters.
- `tools/verify_baseline_fairness.ps1`: local verifier for shared detector
  construction, shared loaders, common training kwargs, equal class weights,
  validation-only thresholds, and paired metric rows.
- `tools/verify_baseline_competitiveness.ps1`: local verifier that the
  auxiliary table includes PGD-AT, Projection Phys-PGD-AT, and Penalty
  Phys-PGD-AT strong adversarial-training baselines and avoids overclaiming
  single-seed dominance.
- `tools/verify_failure_mode_negative_results.ps1`: local verifier for the
  `CAT-AD w/o Delta X` high-FAR failure mode, PVR diagnostic boundary, and
  conservative paired-comparison interpretation.
- `tools/verify_claim_scope.ps1`: local verifier for manuscript claim-scope
  guardrails and overclaiming checks.
- `tools/verify_novelty_evidence.ps1`: local verifier for novelty-boundary
  evidence, machine-readable C1-C6 prior-art coverage, citation coverage, and
  cautious claim wording.
- `tools/verify_recent_prior_art_challenge.ps1`: local verifier that recent
  ADS-B IDS, adversarial-perturbation detection, and survey challenge
  references are cited in the paper and bounded in the novelty evidence.
- `tools/verify_manuscript_structure.ps1`: local verifier for required
  manuscript sections, inputs, figures, citations, anonymity, and placeholders.
- `tools/verify_completion_audit.ps1`: local verifier for the completion audit
  evidence table and explicit external-boundary statements.
- `tools/verify_reviewer_quickstart.ps1`: local verifier for the reviewer
  quickstart commands, expected outputs, no-download boundary, data boundary,
  and acceptance/TeX external limits.
- `tools/verify_readme_review_entry.ps1`: local verifier for the root README
  reviewer entry, including shortest command, rebuild command, main entry
  points, conda rule, and forbidden overclaims.
- `tools/verify_artifact_license_citation.ps1`: local verifier for the
  anonymous review use statement, citation metadata, public-redistribution
  restriction, and public-license external boundary.
- `tools/verify_artifact_evaluation_guide.ps1`: local verifier for the
  artifact-evaluation guide, badge-readiness boundary, deep evaluation matrix,
  required files, and external limits.
- `tools/verify_workspace_hygiene.ps1`: local verifier that root-level
  scratch files, old archives, and raw snapshots are documented as
  non-submission artifacts and absent from the bundle manifest/zip.
- `tools/verify_tex_source_portability.ps1`: local verifier for TeX source
  closure, official LNCS style hashes, input/figure path resolution,
  citation/BibTeX mapping, path portability, and bundle inclusion of source
  inputs plus the formal PDF.
- `tools/verify_formal_pdf_build_readiness.ps1`: local verifier for the formal
LaTeX build, current 18-page official-LNCS artifact, TeX-log quality, and the
  `SKIPPED_NO_TEX_TOOL` rebuild boundary on machines without a local engine.
- `tools/verify_preview_artifact.ps1`: local verifier that the preview HTML/PDF
  contains review-critical title, result, figure, ethics, limitations, and
  reference markers, has a warning-free Pandoc conversion log, and that every
  PDF page renders.
- `tools/verify_anonymized_bundle.ps1`: local verifier that the submission
  bundle does not expose the current workstation username or absolute local
  project paths.
- `DOUBLE_BLIND_REVIEW_CHECKLIST.md`: reviewer-facing anonymity checklist.
- `tools/verify_double_blind_submission.ps1`: local verifier for anonymous
  manuscript metadata, preview author metadata, contact macro absence, and
  bundle-facing identity checks.
- `output/pdf/catad_submission_preview.pdf`: generated A4 preview PDF for
  local review when a TeX distribution is not installed.
- `output/submission/catad_topconf_submission_bundle.zip`: generated
  submission bundle with manifest files and checksums.
- `outputs/tables/*.tex`: regenerated single-run and multi-seed tables used by the paper draft.
- `figures/*.pdf`: paper figures.
- `outputs/tables/table_multiseed_summary.tex`: paper-facing multi-seed summary
  regenerated from the archived benchmark CSV.
- `outputs/tables/table_paired_multiseed_comparison.tex`: paper-facing paired
  statistical table regenerated from the archived benchmark CSV.

## Final Reproducibility Gate

Run all Python commands through the project conda environment:

```powershell
conda run -n testtorch python tools\run_publication_gate.py `
  --csv sample_adsb_decoded.csv `
  --seeds "42,43,44,45,46" `
  --output-dir outputs\publication_benchmark
```

If the run is already in progress or was interrupted, inspect it with:

```powershell
conda run -n testtorch python tools\benchmark_status.py `
  --benchmark-dir outputs\publication_benchmark `
  --preflight-report outputs\publication_benchmark\preflight_report.json `
  --strict-publication `
  --write-report
```

The current benchmark result is strict-gate ready:

- `outputs/publication_benchmark/verification_report.md` reports `Status: PASSED`.
- The strict gate was rerun with physical metrics, primary-claim checks,
  preflight verification, per-seed logs, deterministic metadata, and artifact
  checksums enabled.
- Completed seeds: `42,43,44,45,46`.
- Main aggregate artifacts:
  `aggregate_selected_summary.tex`, `paired_comparisons.tex`,
  `per_seed_metrics_long.csv`, `per_seed_metrics_wide.csv`,
  `aggregate_summary.csv`, `paired_comparisons.csv`, and
  `benchmark_manifest.json`.

For a one-command local audit of the experiment artifacts and manuscript source,
run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload
```

To rebuild the local preview PDF as part of the audit, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload -BuildPreviewPdf
```

To rebuild both the local preview PDF and the submission bundle, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload -BuildPreviewPdf -BuildSubmissionBundle
```

To require a local TeX/PDF engine as part of the audit, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -RequirePdfTool
```

## No-Download Constraint

The current workflow is local-only. It does not download software, install
packages, or call package managers. The audit flag `-NoDownload` checks the
active build, bundle, benchmark, and preview scripts for installer/download
commands before running the rest of the checks. The preview PDF builder uses
only already-installed local tools: Pandoc and Chrome.

## Current Required Checks

- Done: at least five independent seeds completed.
- Done: the strict gate passed with full data, physical metrics, deterministic
  metadata, primary-claim checks, per-seed logs, and artifact checksums.
- Done: the manuscript includes a generated data split and leakage audit table
  derived from `outputs/publication_benchmark/preflight_report.json`.
- Done: data provenance and ethics checks verify the benchmark CSV SHA-256,
  manifest data hash, preflight rows/aircraft/seeds/zero overlap, bundled-data
  boundary, raw upstream snapshot exclusion from the submission bundle, and
  offline safety restrictions.
- Done: dual-use safety checks verify offline defensive-use wording, no
  operational injection guidance, and no socket/serial/SDR/transmitter
  integration markers in core code/scripts.
- Done: dataset profile checks verify raw CSV row/header/hash/time/feature
  ranges, model-loaded and filtered counts, missing callsign boundary, and
  per-seed split/window coverage.
- Done: external-validity scope checks verify that the manuscript states the
  one-day, 20-raw-aircraft, 19-filtered-aircraft benchmark boundary and avoids
  overbroad transfer claims.
- Done: environment reproducibility checks verify the `testtorch` Python
  executable, torch/numpy/pandas/scikit-learn/matplotlib versions, CUDA
  availability, manifest hashes, and deterministic settings.
- Done: code provenance drift checks compare the current source tree with the
  benchmark manifest fingerprint and allow only documented reviewer-facing
  command-example/test-fixture drift plus the added physical-metric regression
  test.
- Done: ablation and sensitivity checks verify component variants,
  no-differential-feature failure mode, epsilon source rows, figure artifacts,
  and auxiliary-evidence interpretation guardrails.
- Done: threshold and hyperparameter checks verify validation-only threshold
  selection, fixed test-time thresholds, per-seed threshold/validation-F1
  records, zero aircraft-split overlap, and manifest hyperparameter values.
- Done: baseline fairness checks verify shared detector construction,
  train/validation/test loaders, common training kwargs, equal class weights,
  validation-only thresholds, and paired Baseline/Proposed metric rows.
- Done: failure-mode and negative-result checks verify the
  `CAT-AD w/o Delta X` high-FAR ablation failure, non-primary PVR boundary,
  conservative five-seed significance interpretation, and no-certificate
  limitation.
- Done: the paper source includes the generated multi-seed summary and
  paired-comparison tables when those files are present.
- Done: the manuscript source includes references, reproducibility, ethics, and
  limitations sections.
- Done: the manuscript source includes an explicit threats-to-validity section
  covering construct, internal, external, and artifact validity.
- Done: a local A4 manuscript preview PDF can be generated with Pandoc and
  Chrome, and the audit checks that the preview contains multi-seed tables,
  paired comparisons, figures, ethics, limitations, references, A4 metadata,
  a warning-free Pandoc conversion log, and full-page rendering.
- Done: a submission bundle can be generated and verified. The bundle includes
  experiment code, tests, manuscript sources, generated tables and figures,
  benchmark artifacts, verification reports, preview PDF, sample data, and
  SHA-256 manifests.
- Done: a reviewer quickstart documents the shortest no-download audit path,
  expected outputs, data boundary, and external TeX/peer-review limits.
- Done: the submission bundle is sanitized during packaging so reviewer-facing
  JSON, logs, manifests, and text artifacts do not expose the current local
  username or absolute workstation project path.
- Done: double-blind checks verify anonymous manuscript metadata, preview
  author metadata, absence of author contact macros, and bundle-facing identity
  markers.
- Done: the submission bundle can be extracted and verified offline against its
  internal manifest.
- Done: the artifact reproducibility checklist documents included artifacts,
  quick checks, bundle verification, numeric-claim verification, and full
  benchmark rerun commands.
- Done: an artifact-evaluation guide maps common artifact-review concerns to
  concrete evidence commands and explicitly keeps official badges and acceptance
  external.
- Done: TeX source-portability checks verify local manuscript source closure,
  official LNCS style hashes, input and figure path resolution, BibTeX citation
  mapping, forbidden absolute paths and shell-escape commands, and bundle
  inclusion of the formal artifact.
- Done: the formal 18-page LNCS PDF was built with Tectonic 0.16.9 and the
  official LNCS v2.24 class; TeX-log quality and all-page rendering checks pass.
  Machines without a local engine can verify the archived artifact and receive
  `formal_pdf_build=SKIPPED_NO_TEX_TOOL` only for rebuild attempts.
- Done: claim-scope guardrails verify that the paper keeps required limiting
  language and avoids unsupported overclaiming phrases.
- Done: novelty-evidence checks verify that the manuscript, bibliography,
  innovation document, prior-art matrix, and dated prior-art evidence snapshot
  agree on the scoped contribution and do not claim existing ingredients as
  new.
- Done: manuscript-structure checks verify required sections, generated table
  inputs, figure references, citation coverage, anonymized metadata, and absence
  of placeholder markers.
- Done: preview-artifact checks verify that threats-to-validity content appears
  in the rendered local review artifact.
- Done: rendered PDF content checks verify the preview-PDF page count, A4 page
  dimensions, nonblank sampled pixels on every page, and page content bounding
  boxes.
- Done: the no-download audit mode verifies that active workflow scripts do not
  contain installer or download commands.
- Done: the top-conference readiness audit maps novelty, threat model,
  robustness evidence, statistics, reproducibility, ethics, and residual risks
  to concrete repository artifacts.
- Done: the numeric-claims ledger traces primary claims and selected table
  values to the generated benchmark CSV, TeX, and verification report.
- Done: manuscript claim-traceability checks verify that narrative result
  statements about targeted threat model, attack strength, high F1/low ASR,
  PV-ASR suppression, and epsilon sensitivity are backed by code and generated
  artifacts.
- Done: claim-hierarchy checks verify that primary claims are the six five-seed
  paired benchmark claims and that ablation, sensitivity, strong-baseline, and
  PVR evidence are not treated as independent primary claims.
- Done: seed-direction consistency checks verify that all 30 seed-level
  differences behind the six primary claims are positive in the claim direction.
- Done: physical-metric semantics checks verify sample-level ASR/PVR/PV-ASR
  definitions, exact per-sample PV-ASR, and generated metric-row bounds.
- Done: attack-evaluation sanity checks verify targeted PGD direction,
multi-step target-margin strengthening, anomalous-only attack application,
  dropout/LSTM-dropout handling and restoration during PGD, and strong baseline
  ASR under the evaluated attacks.
- Done: attack-strength configuration checks verify fixed benchmark attack
  hyperparameters, PGD step-size coverage, penalty-Phys-PGD schedule/weights,
  high baseline ASR rows, and 24-row epsilon-sensitivity evidence.
- Done: baseline-competitiveness checks verify strong adversarial-training
  baselines in the auxiliary ablation table and prevent CAT-AD from being
  claimed as best on every single-run metric.
- Done: statistical-interpretation checks verify effect-size-first wording,
  paired comparison fields, and absence of overstrong significance claims.
- Done: the paper-artifact provenance verifier maps every manuscript table and
  figure to local CSV, benchmark, figure, and manifest evidence.
- Done: figure-source consistency checks verify that paper-facing figure source
  CSV values match current table/test-result sources, epsilon-sensitivity data
  cover the complete grid, official figure PDF/PNG/SVG triads exist, and legacy
  figures are excluded from the generated submission bundle.
- Done: paper-export regeneration checks run the table/figure export command
  before preview/bundle generation and verify byte-stable CSV, TeX, source CSV,
  and PNG outputs.
- Done: the completion audit maps the original objective to concrete evidence
  and explicitly marks conference acceptance and formal TeX compilation as
  external to the no-download local workflow.
- Remaining external dependency: the current workstation does not expose
  `pdflatex`, `xelatex`, `lualatex`, `latexmk`, `tectonic`, or `bibtex` on
  `PATH`. The preview PDF is useful for review, and `tools/build_submission_pdf.ps1`
  is ready for a provisioned TeX machine, but the final venue-compliant LNCS PDF
  should still be generated where a TeX distribution is already available.

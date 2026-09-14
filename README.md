# CAT-AD Anonymous Review Artifact

This repository contains the anonymous review artifact for CAT-AD, a study of
constrained adversarial training for robust ADS-B trajectory anomaly detection
under targeted anomalous-to-normal evasion.

The artifact is designed for local, no-download verification on the existing
Windows conda environment `testtorch`. It does not claim that a venue has
accepted the paper or granted an artifact badge.

## Shortest Verification Path

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload
```

Expected high-level evidence includes:

- `VERIFY PASSED`
- `numeric_claims=PASSED`
- `seed_direction_consistency=PASSED`
- `physical_metric_semantics=PASSED`
- `terminology_and_naming=PASSED`
- `recent_prior_art_challenge=PASSED`
- `workspace_hygiene=PASSED`
- `manuscript_reviewability=PASSED`
- `preview_artifact=PASSED`
- `anonymized_bundle=PASSED`
- `double_blind_submission=PASSED`
- `status=PASSED`

To rebuild the local preview PDF and submission bundle:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload -BuildPreviewPdf -BuildSubmissionBundle
```

## Main Entry Points

- `paper_lncs/main.tex`: anonymous manuscript source.
- `output/pdf/catad_submission_preview.pdf`: local A4 review preview PDF.
- `tools/build_submission_pdf.ps1`: formal LaTeX PDF build entry point when a
  TeX engine is already installed.
- `output/submission/catad_topconf_submission_bundle.zip`: anonymous submission
  bundle with manifests and checksums.
- `REVIEWER_QUICKSTART.md`: shortest reviewer checklist.
- `ARTIFACT_REPRODUCIBILITY_CHECKLIST.md`: commands and expected outputs.
- `ARTIFACT_EVALUATION_GUIDE.md`: artifact-evaluation evidence matrix.
- `TERMINOLOGY_AND_NAMING_AUDIT.md`: canonical scientific names, first-use
  definitions, and the legacy archive-key compatibility boundary.
- `REVIEWER_OBJECTION_RESPONSE_AUDIT.md`: likely reviewer objections mapped to
  evidence, verifier commands, expected outputs, and claim boundaries.
- `LICENSE`: anonymous review artifact use statement.
- `CITATION.cff`: anonymous review citation metadata.
- `SUBMISSION_COMPLETION_AUDIT.md`: requirement-by-requirement completion
  boundary.
- `TOP_CONFERENCE_READINESS_AUDIT.md`: reviewer-risk and evidence matrix.

## Experiment Evidence

- Strict multi-seed gate: `outputs/publication_benchmark/verification_report.md`
- Completed seeds: `42,43,44,45,46`
- Primary metrics and paired comparisons:
  archived CSVs under `outputs/publication_benchmark/` and paper-facing
  `outputs/tables/table_multiseed_summary.tex` plus
  `outputs/tables/table_paired_multiseed_comparison.tex`
- Published-model reproduction comparison:
  `outputs/literature_benchmark/literature_detection_report.md`,
  `outputs/literature_benchmark/table_literature_detection.tex`, and
  `outputs/literature_benchmark/literature_detection_report_manifest.json`.
This five-split unperturbed-detection comparison covers protocol-aligned
  reimplementations of the 2021 Fried--Last LSTM-AE, 2021 VAE--SVDD, and 2022
  Contextual AE, selected as a representative method-family sample from the
  July 2019--July 2026 publication window; it
  explicitly excludes cross-family attack values that failed the step-size
  sanity check.
- Data/split/provenance boundary:
  `DATA_PROVENANCE_AND_ETHICS.md`, `DATASET_PROFILE_AUDIT.md`, and
  `outputs/publication_benchmark/preflight_report.json`
- External-validity scope boundary:
  `EXTERNAL_VALIDITY_SCOPE_AUDIT.md` and
  `tools/verify_external_validity_scope.ps1`
- Dual-use safety boundary:
  `DUAL_USE_SAFETY_AUDIT.md` and `tools/verify_dual_use_safety.ps1`
- Novelty boundary:
  `INNOVATION_AND_EVIDENCE.md`, `PRIOR_ART_NOVELTY_MATRIX.md`,
  `PRIOR_ART_CRITERIA_COVERAGE.tsv`, `PRIOR_ART_EVIDENCE_SNAPSHOT.md`, and
  `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md`
- Reviewer-objection response:
  `REVIEWER_OBJECTION_RESPONSE_AUDIT.md` and
  `tools/verify_reviewer_objection_response.ps1`
- Attack-strength boundary:
  `ADAPTIVE_ATTACK_AUDIT.md`, `ATTACK_EVALUATION_SANITY_CHECKLIST.md`, and
  `ATTACK_STRENGTH_CONFIGURATION_AUDIT.md`
- Strong-baseline boundary:
  `BASELINE_COMPETITIVENESS_AUDIT.md` and
  `tools/verify_baseline_competitiveness.ps1`
- Concrete published-baseline boundary:
  `LITERATURE_BASELINE_REPRODUCTION_AUDIT.md` and
  `tools/verify_literature_baseline_reproduction.ps1`
- Method-to-implementation boundary:
  `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md` and
  `tools/verify_method_implementation_traceability.ps1`
- Primary/auxiliary claim hierarchy:
  `CLAIM_HIERARCHY_AUDIT.md` and `tools/verify_claim_hierarchy.ps1`
- Per-seed primary-claim consistency:
  `outputs/publication_benchmark/primary_seed_direction_summary.csv`,
  `outputs/publication_benchmark/primary_seed_direction_summary.tex`,
  `SEED_DIRECTION_CONSISTENCY_AUDIT.md`, and
  `tools/verify_seed_direction_consistency.ps1`
- Physical metric semantics:
  `PHYSICAL_METRIC_SEMANTICS_AUDIT.md` and
  `tools/verify_physical_metric_semantics.ps1`
- Compute/runtime boundary:
  `COMPUTE_RESOURCE_AUDIT.md` and
  `tools/verify_compute_resource_audit.ps1`
- Rendered PDF boundary:
  `RENDERED_PDF_CONTENT_AUDIT.md` and
  `tools/verify_rendered_pdf_content.ps1`

## Local Environment

Python commands in this project must use:

```powershell
conda run -n testtorch python
```

The no-download workflow does not install packages, create environments,
download data, or download TeX.

## Artifact Boundary

The review bundle intentionally excludes root-level raw snapshots, old local
archives, and scratch scripts. `WORKSPACE_HYGIENE_AUDIT.md` and
`tools/verify_workspace_hygiene.ps1` document and verify this boundary.

`LICENSE` defines the anonymous review use boundary. `CITATION.cff` provides an
anonymous review citation record and asks readers to cite the final paper and
public artifact record after deanonymization or acceptance.

The bundle includes both a Pandoc/Chrome preview and the formally compiled
18-page LNCS PDF at `output/pdf/catad_submission_latex_updated.pdf`. The formal artifact
uses the official LNCS v2.24 class and passes TeX-log and rendered-page checks.
`tools/build_submission_pdf.ps1` can rebuild it when `latexmk`, `tectonic`, or
`pdflatex` plus `bibtex` is available; otherwise it reports
`formal_pdf_build=SKIPPED_NO_TEX_TOOL` without downloading software.

## External Limits

This artifact can verify code, experiments, manuscript sources, the formal and
preview PDFs, novelty evidence, claim traceability, anonymity, and bundle
integrity. It cannot prove top-conference acceptance, compliance with an
unspecified venue page limit, operational aviation safety, or robustness
against every adaptive attacker.

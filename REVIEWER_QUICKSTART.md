# CAT-AD Reviewer Quickstart

This quickstart is the shortest path for a reviewer or artifact evaluator to
check the CAT-AD submission bundle without downloading software.

## One-Command Audit

Run from the repository root or extracted bundle root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload
```

Expected high-level output includes:

- `OK no-download workflow scripts contain no installer/download commands`
- `VERIFY PASSED`
- `Ran 16 tests`
- `readme_review_entry=PASSED`
- `artifact_license_citation=PASSED`
- `numeric_claims=PASSED`
- `attack_evaluation_sanity=PASSED`
- `attack_strength_configuration=PASSED`
- `method_implementation_traceability=PASSED`
- `claim_hierarchy=PASSED`
- `seed_direction_consistency=PASSED`
- `physical_metric_semantics=PASSED`
- `baseline_competitiveness=PASSED`
- `statistical_interpretation=PASSED`
- `data_provenance_ethics=PASSED`
- `dual_use_safety=PASSED`
- `external_validity_scope=PASSED`
- `environment_reproducibility=PASSED`
- `compute_resource_audit=PASSED`
- `formal_pdf_build_readiness=PASSED`
- `paper_artifact_provenance=PASSED`
- `recent_prior_art_challenge=PASSED`
- `coverage_rows_checked=25`
- `full_prior_art_rows=0`
- `workspace_hygiene=PASSED`
- `manuscript_reviewability=PASSED`
- `completion_audit=PASSED`
- `preview_artifact=PASSED`
- `rendered_pdf_content=PASSED`
- `pandoc_log_warnings=0`
- `anonymized_bundle=PASSED`
- `double_blind_submission=PASSED`
- `status=PASSED`

This command does not install packages or download data. It uses the existing
`testtorch` conda environment and the local tools already present on the
machine.

## Fast Manual Checks

To inspect the strict benchmark gate only:

```powershell
conda run -n testtorch python -m adsb.run `
  --verify-benchmark outputs\publication_benchmark `
  --verify-preflight-report outputs\publication_benchmark\preflight_report.json `
  --verify-require-physical-metrics `
  --verify-require-primary-claims `
  --verify-strict-publication `
  --verify-write-report
```

Expected output includes `VERIFY PASSED`, `seeds=42,43,44,45,46`,
`aggregate_rows=96`, and `comparison_rows=12`.

To verify the generated submission zip:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_submission_bundle.ps1
```

Expected output includes `manifest_files_checked=...`,
`extracted_strict_gate=PASSED`, and `status=PASSED`.

## What Is Being Checked

| Review concern | Evidence command or file |
| --- | --- |
| Root reviewer entry | `README.md`, `tools/verify_readme_review_entry.ps1` |
| Review-use and citation boundary | `LICENSE`, `CITATION.cff`, `tools/verify_artifact_license_citation.ps1` |
| No-download workflow | `check_submission_ready.ps1 -NoDownload` |
| Five-seed robustness claims | `outputs/publication_benchmark/verification_report.md` |
| Numeric claim traceability | `tools/verify_numeric_claims.ps1` |
| Weak-attack / gradient-masking sanity | `tools/verify_attack_evaluation_sanity.ps1`, `ADAPTIVE_ATTACK_AUDIT.md` |
| Fixed attack-strength configuration | `tools/verify_attack_strength_configuration.ps1`, `ATTACK_STRENGTH_CONFIGURATION_AUDIT.md` |
| Method-to-implementation traceability | `tools/verify_method_implementation_traceability.ps1`, `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md` |
| Primary/auxiliary claim hierarchy | `tools/verify_claim_hierarchy.ps1`, `CLAIM_HIERARCHY_AUDIT.md` |
| Per-seed primary-claim direction | `outputs/publication_benchmark/primary_seed_direction_summary.csv`, `outputs/publication_benchmark/primary_seed_direction_summary.tex`, `tools/verify_seed_direction_consistency.ps1`, `SEED_DIRECTION_CONSISTENCY_AUDIT.md` |
| ASR/PVR/PV-ASR metric semantics | `tools/verify_physical_metric_semantics.ps1`, `PHYSICAL_METRIC_SEMANTICS_AUDIT.md` |
| Strong adversarial-training baselines | `tools/verify_baseline_competitiveness.ps1`, `BASELINE_COMPETITIVENESS_AUDIT.md` |
| Data hash, split leakage, and ethics | `tools/verify_data_provenance_ethics.ps1`, `DATA_PROVENANCE_AND_ETHICS.md` |
| External-validity dataset scope | `tools/verify_external_validity_scope.ps1`, `EXTERNAL_VALIDITY_SCOPE_AUDIT.md` |
| Dual-use safety boundary | `tools/verify_dual_use_safety.ps1`, `DUAL_USE_SAFETY_AUDIT.md` |
| Conda environment and key packages | `tools/verify_environment_reproducibility.ps1`, `ENVIRONMENT_REPRODUCIBILITY.md` |
| Compute/runtime profile | `tools/verify_compute_resource_audit.ps1`, `COMPUTE_RESOURCE_AUDIT.md` |
| Novelty boundary | `tools/verify_novelty_evidence.ps1`, `PRIOR_ART_NOVELTY_MATRIX.md`, `PRIOR_ART_CRITERIA_COVERAGE.tsv` |
| Recent prior-art challenge references | `tools/verify_recent_prior_art_challenge.ps1`, `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md` |
| Reviewer-objection response matrix | `tools/verify_reviewer_objection_response.ps1`, `REVIEWER_OBJECTION_RESPONSE_AUDIT.md` |
| Workspace/root artifact boundary | `tools/verify_workspace_hygiene.ps1`, `WORKSPACE_HYGIENE_AUDIT.md` |
| Paper table and figure provenance | `tools/verify_paper_artifact_provenance.ps1` |
| Manuscript reviewability | `tools/verify_manuscript_reviewability.ps1`, `MANUSCRIPT_REVIEWABILITY_AUDIT.md` |
| Formal LaTeX PDF build entry point | `tools/verify_formal_pdf_build_readiness.ps1`, `FORMAL_PDF_BUILD_AUDIT.md` |
| Double-blind and path portability | `tools/verify_double_blind_submission.ps1`, `tools/verify_anonymized_bundle.ps1` |
| Preview PDF reviewability | `tools/verify_preview_artifact.ps1` |
| Rendered PDF content | `tools/verify_rendered_pdf_content.ps1`, `RENDERED_PDF_CONTENT_AUDIT.md` |

## Data Boundary

The benchmark CSV is `sample_adsb_decoded.csv` with SHA-256
`3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72`.
The bundle intentionally excludes larger local raw snapshots
`states_2018-05-28-14.csv` and `states_2022-06-27-23.csv`; the data verifier
checks this boundary.

## External Limits

The bundle includes the Pandoc/Chrome preview and a formally compiled 18-page
LNCS PDF at `output/pdf/catad_submission_latex_updated.pdf`. The formal PDF uses the
official LNCS v2.24 class and passes TeX-log and rendered-page checks. On a
machine without a local TeX engine, rebuild reports
`formal_pdf_build=SKIPPED_NO_TEX_TOOL`, but the archived formal artifact remains
verifiable.

The artifact can demonstrate code, experiment, manuscript, formal rendering,
evidence, and bundle readiness. It cannot guarantee top-conference acceptance
or compliance with an as-yet-unspecified venue page limit.

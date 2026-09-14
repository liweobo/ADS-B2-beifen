# CAT-AD Artifact Evaluation Guide

This guide is written for an artifact evaluator who receives the CAT-AD
submission bundle and wants to decide what the local artifact demonstrates.
It is venue-neutral: it does not claim that any official badge or acceptance
decision has been granted.

## Badge-Readiness Boundary

The local audit supports evidence for these common artifact-review questions:

| Review question | Local evidence |
| --- | --- |
| Is there a standard repository entry page? | `README.md`, `README_REVIEW_ENTRY_AUDIT.md`, and `tools/verify_readme_review_entry.ps1` |
| Is review-use and citation guidance explicit? | `LICENSE`, `CITATION.cff`, `ARTIFACT_LICENSE_AND_CITATION_AUDIT.md`, and `tools/verify_artifact_license_citation.ps1` |
| Is the artifact available in a self-contained bundle? | `output/submission/catad_topconf_submission_bundle.zip`, bundle manifests, and `tools/verify_submission_bundle.ps1` |
| Does the artifact run without downloads? | `check_submission_ready.ps1 -NoDownload` and the no-download script scan |
| Are the core claims reproducible from archived artifacts? | strict publication gate, `outputs/publication_benchmark/verification_report.md`, and extracted-bundle strict-gate rerun |
| Are paper claims traceable? | `tools/verify_numeric_claims.ps1`, `tools/verify_manuscript_claim_traceability.ps1`, and `tools/verify_paper_artifact_provenance.ps1` |
| Are primary and auxiliary claims separated? | `CLAIM_HIERARCHY_AUDIT.md` and `tools/verify_claim_hierarchy.ps1` |
| Are primary claim directions consistent across seeds? | `outputs/publication_benchmark/primary_seed_direction_summary.csv`, `outputs/publication_benchmark/primary_seed_direction_summary.tex`, `SEED_DIRECTION_CONSISTENCY_AUDIT.md`, and `tools/verify_seed_direction_consistency.ps1` |
| Are ASR, PVR, and PV-ASR semantics sample-level and checked? | `PHYSICAL_METRIC_SEMANTICS_AUDIT.md` and `tools/verify_physical_metric_semantics.ps1` |
| Are recent prior-art challenges acknowledged? | `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md`, `PRIOR_ART_CRITERIA_COVERAGE.tsv`, and `tools/verify_recent_prior_art_challenge.ps1` |
| Are likely reviewer objections mapped to evidence? | `REVIEWER_OBJECTION_RESPONSE_AUDIT.md` and `tools/verify_reviewer_objection_response.ps1` |
| Is the local manuscript reviewable? | `MANUSCRIPT_REVIEWABILITY_AUDIT.md` and `tools/verify_manuscript_reviewability.ps1` |
| Does the review PDF render with content on every page? | `RENDERED_PDF_CONTENT_AUDIT.md` and `tools/verify_rendered_pdf_content.ps1` |
| Is the method implementation traceable? | `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md` and `tools/verify_method_implementation_traceability.ps1` |
| Are strong adversarial-training baselines visible? | `BASELINE_COMPETITIVENESS_AUDIT.md` and `tools/verify_baseline_competitiveness.ps1` |
| Are figure sources fresh? | `FIGURE_SOURCE_CONSISTENCY_AUDIT.md` and `tools/verify_figure_source_consistency.ps1` |
| Can paper exports be regenerated? | `PAPER_EXPORT_REGENERATION_AUDIT.md` and `tools/verify_paper_export_regeneration.ps1` |
| Are formal-PDF source inputs portable? | `TEX_SOURCE_PORTABILITY_AUDIT.md` and `tools/verify_tex_source_portability.ps1` |
| Is there a formal LaTeX PDF build entry point? | `FORMAL_PDF_BUILD_AUDIT.md` and `tools/verify_formal_pdf_build_readiness.ps1` |
| Are data and split boundaries visible? | `DATA_PROVENANCE_AND_ETHICS.md`, `DATASET_PROFILE_AUDIT.md`, preflight report, and data split audit table |
| Is external-validity scope bounded? | `EXTERNAL_VALIDITY_SCOPE_AUDIT.md` and `tools/verify_external_validity_scope.ps1` |
| Is the benchmark compute cost bounded? | `COMPUTE_RESOURCE_AUDIT.md`, `outputs/publication_benchmark/benchmark_status.json`, and `tools/verify_compute_resource_audit.ps1` |
| Is dual-use safety bounded? | `DUAL_USE_SAFETY_AUDIT.md` and `tools/verify_dual_use_safety.ps1` |
| Is the review bundle separated from local scratch/raw files? | `WORKSPACE_HYGIENE_AUDIT.md` and `tools/verify_workspace_hygiene.ps1` |
| Are robustness-evaluation risks checked? | attack sanity, attack-strength configuration, baseline fairness, threshold/hyperparameter, failure-mode, and statistical-interpretation audits |
| Is reuse supported? | documented CLI commands, source files, tests, manifests, and explicit external limits |

Official artifact badges, venue acceptance, and camera-ready compliance remain
external decisions by the reviewing venue.

## Required Local Environment

The artifact assumes the pre-existing Windows conda environment `testtorch`.
Python commands must be run through:

```powershell
conda run -n testtorch python
```

The no-download workflow intentionally does not install packages, create conda
environments, download data, or download TeX.

## Fast Evaluation Path

From the repository root or extracted bundle root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload
```

Expected high-level evidence includes:

- `VERIFY PASSED`
- `readme_review_entry=PASSED`
- `artifact_license_citation=PASSED`
- `numeric_claims=PASSED`
- `manuscript_claim_traceability=PASSED`
- `claim_hierarchy=PASSED`
- `seed_direction_consistency=PASSED`
- `physical_metric_semantics=PASSED`
- `recent_prior_art_challenge=PASSED`
- `coverage_rows_checked=25`
- `full_prior_art_rows=0`
- `manuscript_reviewability=PASSED`
- `rendered_pdf_content=PASSED`
- `method_implementation_traceability=PASSED`
- `baseline_competitiveness=PASSED`
- `dataset_profile=PASSED`
- `external_validity_scope=PASSED`
- `compute_resource_audit=PASSED`
- `tex_source_portability=PASSED`
- `formal_pdf_build_readiness=PASSED`
- `figure_source_consistency=PASSED`
- `paper_export_regeneration=PASSED`
- `workspace_hygiene=PASSED`
- `baseline_fairness=PASSED`
- `failure_mode_negative_results=PASSED`
- `anonymized_bundle=PASSED`
- `double_blind_submission=PASSED`
- `status=PASSED`

## Deep Evaluation Matrix

| Concern | Command |
| --- | --- |
| Strict benchmark gate | `conda run -n testtorch python -m adsb.run --verify-benchmark outputs\publication_benchmark --verify-preflight-report outputs\publication_benchmark\preflight_report.json --verify-require-physical-metrics --verify-require-primary-claims --verify-strict-publication --verify-write-report` |
| Root README reviewer entry | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_readme_review_entry.ps1` |
| License and citation boundary | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_artifact_license_citation.ps1` |
| Unit tests | `conda run -n testtorch python -m unittest discover -s tests -p "test*.py"` |
| Bundle integrity and extracted strict gate | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_submission_bundle.ps1` |
| Data profile | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_dataset_profile.ps1` |
| External-validity scope | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_external_validity_scope.ps1` |
| Compute and runtime profile | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_compute_resource_audit.ps1` |
| Numeric claims | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_numeric_claims.ps1` |
| Narrative claims | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_manuscript_claim_traceability.ps1` |
| Claim hierarchy | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_claim_hierarchy.ps1` |
| Seed-direction consistency | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_seed_direction_consistency.ps1` |
| Physical metric semantics | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_physical_metric_semantics.ps1` |
| Recent prior-art challenge references | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_recent_prior_art_challenge.ps1` |
| Reviewer-objection response matrix | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_reviewer_objection_response.ps1` |
| Manuscript reviewability | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_manuscript_reviewability.ps1` |
| Attack sanity | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_evaluation_sanity.ps1` |
| Attack strength configuration | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_strength_configuration.ps1` |
| Method-to-implementation traceability | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_method_implementation_traceability.ps1` |
| Strong adversarial-training baselines | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_baseline_competitiveness.ps1` |
| Dual-use safety | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_dual_use_safety.ps1` |
| Baseline fairness | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_baseline_fairness.ps1` |
| Threshold and hyperparameter boundary | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_threshold_hyperparameter_audit.ps1` |
| Failure modes and negative results | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_failure_mode_negative_results.ps1` |
| Paper artifact provenance | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_paper_artifact_provenance.ps1` |
| Figure source consistency | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_figure_source_consistency.ps1` |
| Paper export regeneration | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_paper_export_regeneration.ps1` |
| Workspace hygiene and bundle boundary | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_workspace_hygiene.ps1` |
| TeX source portability | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_tex_source_portability.ps1` |
| Formal LaTeX PDF build readiness | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_formal_pdf_build_readiness.ps1` |
| Preview PDF reviewability | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_preview_artifact.ps1` |
| Rendered PDF content | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_rendered_pdf_content.ps1` |

## What The Artifact Does Not Prove

- It does not prove top-conference acceptance.
- It does not grant an official artifact badge.
- It does not install a venue TeX toolchain. The verified 18-page formal LNCS
  PDF is included; on machines without an engine, only a rebuild attempt reports
  `formal_pdf_build=SKIPPED_NO_TEX_TOOL`.
- It does not prove that 18 pages comply with a future venue's unspecified limit.
- It does not certify operational aviation safety.
- It does not prove robustness against all adaptive attackers.
- It does not prove transfer to every airspace, date, aircraft population, or
  sensor network.

## Evaluation Summary

The artifact is intended to support a top-conference-style review package:
anonymous manuscript sources, preview PDF, experiment code, tests, benchmark
artifacts, source/data/manuscript provenance, claim traceability, and a
machine-checked submission bundle. The final acceptance and any official
artifact-evaluation badge remain external to this local audit.

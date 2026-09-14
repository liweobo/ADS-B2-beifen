# CAT-AD Reviewer Objection Response Audit

This audit is a reviewer-facing response matrix. It does not invent new
claims. It maps likely top-conference objections to local evidence, verifier
commands, expected outputs, and the remaining boundary that should not be
overstated in the paper or rebuttal.

File: `REVIEWER_OBJECTION_RESPONSE_AUDIT.md`.
Verifier path: `tools/verify_reviewer_objection_response.ps1`.

## Response Matrix

| ID | Likely reviewer objection | Evidence to cite | Verifier and expected output | Boundary to preserve |
| --- | --- | --- | --- | --- |
| O1 | The novelty claim is overstated or stale. | `INNOVATION_AND_EVIDENCE.md`, `PRIOR_ART_NOVELTY_MATRIX.md`, `PRIOR_ART_CRITERIA_COVERAGE.tsv`, `PRIOR_ART_EVIDENCE_SNAPSHOT.md`, and the positioning table in `paper_lncs/main.tex`. | `tools/verify_novelty_evidence.ps1`; expected `novelty_evidence=PASSED`, `coverage_rows_checked=25`, `citation_keys_checked=24`, and `full_prior_art_rows=0`. | This is a dated, scoped prior-art boundary, not a proof of global novelty. |
| O2 | Recent ADS-B work such as IMDM-PC, RDPA, OCREN, Pirolley et al., or Luo et al. may already cover the contribution. | `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md`, `PRIOR_ART_CRITERIA_COVERAGE.tsv`, `paper_lncs/references.bib`, and related-work citations including `zhao2026imdmpc`, `zhong2026rdpaadsb`, `yue2026ocren`, `pirolley2026lowaltitude`, and `luo2024adversarialadsb`. | `tools/verify_recent_prior_art_challenge.ps1`; expected `recent_prior_art_challenge=PASSED`, `recent_sources_checked=12`, `paper_citations_checked=12`, and `criteria_checked=6`. | The response is that sampled recent work does not jointly satisfy C1-C6; it is not a claim that no related method exists anywhere. |
| O3 | The baseline is too weak. | `BASELINE_FAIRNESS_AUDIT.md`, `BASELINE_COMPETITIVENESS_AUDIT.md`, `outputs/tables/table5_ablation_study.csv`, and `paper_lncs/main.tex`. | `tools/verify_baseline_fairness.ps1` and `tools/verify_baseline_competitiveness.ps1`; expected `baseline_fairness=PASSED`, `baseline_competitiveness=PASSED`, and `strong_training_baselines_checked=3`. | Strong adversarial-training baselines are auxiliary single-seed evidence; primary claims remain the five-seed CAT-AD vs. BiLSTM-ERM benchmark. |
| O4 | The ablation and sensitivity evidence is selective or overclaimed. | `CLAIM_HIERARCHY_AUDIT.md`, `ABLATION_AND_SENSITIVITY_AUDIT.md`, `FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md`, `results/fig_epsilon_sensitivity_data.csv`, and `outputs/tables/table5_ablation_study.csv`. | `tools/verify_claim_hierarchy.ps1`, `tools/verify_ablation_sensitivity.ps1`, and `tools/verify_failure_mode_negative_results.ps1`; expected `claim_hierarchy=PASSED`, `ablation_sensitivity=PASSED`, and `failure_mode_negative_results=PASSED`. | Ablation, sensitivity, PVR, and strong-baseline rows remain auxiliary or diagnostic, not upgraded to primary multi-seed claims. |
| O5 | Five seeds are not enough for conclusive statistics. | `STATISTICAL_INTERPRETATION_CHECKLIST.md`, `outputs/publication_benchmark/paired_comparisons.csv`, and the statistical interpretation paragraph in `paper_lncs/main.tex`. | `tools/verify_statistical_interpretation.ps1`; expected `statistical_interpretation=PASSED`, `paired_rows_checked=12`, and `effect_size_rows_checked=12`. | The paper uses effect-size-first directional claims and does not claim conclusive null-hypothesis evidence from five seeds. |
| O6 | A single favorable seed may dominate the mean. | `SEED_DIRECTION_CONSISTENCY_AUDIT.md`, `outputs/publication_benchmark/primary_seed_direction_summary.csv`, and `outputs/publication_benchmark/per_seed_metrics_wide.csv`. | `tools/verify_seed_direction_consistency.ps1`; expected `seed_pairs_checked=30`, `summary_csv_rows_checked=6`, and `minimum_seed_improvement=0.0033259423503325942`. | This rules out a single-seed mean artifact for the six primary claims, but it does not replace more seeds or broader datasets. |
| O7 | ASR, PVR, and PV-ASR may be ambiguous or incorrectly computed. | `PHYSICAL_METRIC_SEMANTICS_AUDIT.md`, `tests/test_physical_metrics.py`, `adsb/training.py`, and generated physical-metric rows. | `tools/verify_physical_metric_semantics.ps1`; expected `physical_metric_semantics=PASSED`, `metric_rows_checked=42`, and `pv_asr_bounds_checked=78`. | PV-ASR semantics are verified for the implemented sample-level metric; this does not certify every possible physical constraint definition. |
| O8 | The attack may be weak or masked by gradients. | `ATTACK_EVALUATION_SANITY_CHECKLIST.md`, `ADAPTIVE_ATTACK_AUDIT.md`, `ATTACK_STRENGTH_CONFIGURATION_AUDIT.md`, `tests/test_physical_metrics.py`, and high baseline ASR rows in `paired_comparisons.csv`. | `tools/verify_attack_evaluation_sanity.ps1` and `tools/verify_attack_strength_configuration.ps1`; expected `attack_evaluation_sanity=PASSED`, `attack_strength_configuration=PASSED`, `paired_attack_rows_checked=3`, and `epsilon_rows_checked=24`. | These are empirical sanity checks under evaluated attacks, not a proof against all adaptive attackers. |
| O9 | Data leakage, threshold tuning, or unfair pairing may inflate results. | `DATA_PROVENANCE_AND_ETHICS.md`, `BASELINE_FAIRNESS_AUDIT.md`, `THRESHOLD_AND_HYPERPARAMETER_AUDIT.md`, `outputs/publication_benchmark/preflight_report.json`, and `outputs/publication_benchmark/data_split_audit.tex`. | `tools/verify_data_provenance_ethics.ps1`, `tools/verify_baseline_fairness.ps1`, and `tools/verify_threshold_hyperparameter_audit.ps1`; expected `aircraft_overlap_violations=0`, `baseline_fairness=PASSED`, and `threshold_hyperparameter_audit=PASSED`. | The checks prove the archived benchmark boundary, not every exploratory run outside the archived artifacts. |
| O10 | The paper may not match the code or generated artifacts. | `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md`, `MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md`, `PAPER_ARTIFACT_PROVENANCE.md`, `CODE_PROVENANCE_DRIFT_AUDIT.md`, and paper-export regeneration logs. | `tools/verify_method_implementation_traceability.ps1`, `tools/verify_manuscript_claim_traceability.ps1`, `tools/verify_paper_artifact_provenance.ps1`, `tools/verify_code_provenance_drift.ps1`, and `tools/verify_paper_export_regeneration.ps1`; expected `method_implementation_traceability=PASSED`, `manuscript_claim_traceability=PASSED`, `paper_artifact_provenance=PASSED`, `code_provenance_drift=PASSED`, and `paper_export_regeneration=PASSED`. | These checks cover local archived artifacts; future core-code drift should trigger a benchmark rerun before updating quantitative claims. |
| O11 | The artifact may not be reproducible, portable, or anonymous. | `ARTIFACT_REPRODUCIBILITY_CHECKLIST.md`, `WORKSPACE_HYGIENE_AUDIT.md`, `DOUBLE_BLIND_REVIEW_CHECKLIST.md`, `output/submission/catad_topconf_submission_bundle.zip`, and bundle manifests. | `tools/verify_submission_bundle.ps1`, `tools/verify_workspace_hygiene.ps1`, `tools/verify_anonymized_bundle.ps1`, and `tools/verify_double_blind_submission.ps1`; expected `status=PASSED`, `workspace_hygiene=PASSED`, `anonymized_bundle=PASSED`, and `double_blind_submission=PASSED`. | Reviewers still need the existing `testtorch` environment; the artifact does not download software. |
| O12 | A locally generated PDF is not the same as an accepted top-conference paper. | `FORMAL_PDF_BUILD_AUDIT.md`, `TEX_SOURCE_PORTABILITY_AUDIT.md`, `output/pdf/catad_submission_latex_updated.pdf`, and `SUBMISSION_COMPLETION_AUDIT.md`. | `tools/verify_formal_pdf_build_readiness.ps1`, `tools/verify_tex_source_portability.ps1`, `tools/verify_rendered_pdf_content.ps1`, and `tools/verify_completion_audit.ps1`; expected `formal_pdf_build_readiness=PASSED`, `formal_pdf_build=PASSED` when an engine is available, `tex_source_portability=PASSED`, `rendered_pdf_content=PASSED`, `formal_pages_checked=18`, and `completion_audit=PASSED`. | The package proves local official-LNCS build and rendering integrity; it does not prove acceptance or a future venue's page-limit compliance. |

## One-Command Verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_reviewer_objection_response.ps1
```

Expected output includes:

- `reviewer_objection_response=PASSED`
- `objections_checked=12`
- `evidence_paths_checked=42`
- `verifier_outputs_checked=49`
- `coverage_rows_checked=25`
- `primary_seed_rows_checked=6`
- `full_prior_art_rows=0`

## Non-Rebuttals

The matrix should not be used to claim any of the following:

- It does not prove top-conference acceptance.
- It does not certify robustness against all adaptive attackers.
- It does not prove transfer to every airspace, aircraft population, date, or
  sensor network.
- It does not make single-seed auxiliary ablations into primary claims.
- It does not supply a TeX engine on machines where no supported TeX tool is
  already installed.

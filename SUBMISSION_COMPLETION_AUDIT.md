# CAT-AD Submission Completion Audit

This audit translates the user-facing goal into evidence that can be checked in
the current repository. It distinguishes submission-ready artifacts from claims
that no local codebase can prove, such as actual conference acceptance.

## Completion Boundary

The repository can support a top-conference-style submission package: executable
experiment code, multi-seed robustness evidence, a complete manuscript source,
claim-scope controls, a formally compiled 18-page LNCS PDF, and an
offline-verifiable submission bundle. It cannot prove that a program committee
will accept the paper or that 18 pages comply with a future venue's unspecified
submission policy.

## Requirement Evidence

| Requirement | Evidence inspected | Status |
| --- | --- | --- |
| No software downloads | `check_submission_ready.ps1 -NoDownload` scans active workflow scripts for installer and download commands. | Proven locally |
| Python commands use the required conda environment | `check_submission_ready.ps1` runs Python through `conda run -n testtorch`; `AGENTS.md` records the rule. | Proven locally |
| Experiment code exists | `adsb/benchmark.py`, `adsb/attacks.py`, `adsb/training.py`, `adsb/verify_artifacts.py`, and `tools/run_publication_gate.py`. | Proven locally |
| Unit-level regression coverage exists | `tests/test_benchmark_stats.py`, `tests/test_physical_metrics.py`, `tests/test_submission_tex_generation.py`, and `tests/test_paper_naming.py`; full audit runs the unit test discovery suite. | Proven locally |
| Publication-grade experiment artifacts exist | `outputs/publication_benchmark/verification_report.md` reports `Status: PASSED` with five seeds, aggregate rows, paired comparisons, physical metrics, and primary claims. | Proven locally |
| Data split, provenance, ethics, and leakage audit are visible | `DATA_PROVENANCE_AND_ETHICS.md`, `tools/verify_data_provenance_ethics.ps1`, `outputs/publication_benchmark/preflight_report.json`, `outputs/publication_benchmark/data_split_audit.tex`, and `tools/build_data_split_audit_table.ps1` expose the benchmark CSV hash, full-data use, aircraft-level split counts, zero aircraft overlap, nonempty anomalous windows, bundled-data boundary, raw snapshot exclusion from the submission bundle, and offline safety restrictions. | Proven locally |
| Dataset profile transparency is visible | `DATASET_PROFILE_AUDIT.md` and `tools/verify_dataset_profile.ps1` check the raw CSV header, byte size, SHA-256, row count, time range, feature ranges, missing callsign boundary, model-loaded/filtering counts, and split/window coverage. | Proven locally |
| External validity scope is bounded | `EXTERNAL_VALIDITY_SCOPE_AUDIT.md` and `tools/verify_external_validity_scope.ps1` check that the paper and guardrails scope claims to one UTC day, 20 raw aircraft identifiers, 19 filtered aircraft, and the archived aircraft-level split/preflight boundary. | Proven locally |
| Threshold and hyperparameter leakage controls are visible | `THRESHOLD_AND_HYPERPARAMETER_AUDIT.md` and `tools/verify_threshold_hyperparameter_audit.ps1` check validation-only threshold selection, fixed test-time thresholds, per-seed threshold and validation-F1 records, zero split overlap, and benchmark manifest hyperparameter values. | Proven locally |
| Baseline comparison fairness is visible | `BASELINE_FAIRNESS_AUDIT.md` and `tools/verify_baseline_fairness.ps1` check shared model construction, shared train/validation/test loaders, common training kwargs, equal class weights, validation-only thresholds, paired metric rows, and paired-comparison seed lists. | Proven locally |
| Baseline competitiveness is visible | `BASELINE_COMPETITIVENESS_AUDIT.md` and `tools/verify_baseline_competitiveness.ps1` check that the auxiliary ablation table includes strong adversarial-training baselines (`PGD-AT`, `Projection Phys-PGD-AT`, and `Penalty Phys-PGD-AT`) and that the manuscript does not claim CAT-AD dominates every single-run ablation metric. | Proven locally |
| Environment reproducibility is checked | `ENVIRONMENT_REPRODUCIBILITY.md`, `tools/verify_environment_reproducibility.ps1`, and `outputs/publication_benchmark/benchmark_manifest.json` verify the `testtorch` conda environment, key package versions, manifest data/code/package hashes, CUDA availability, and deterministic settings. | Proven locally |
| Compute and runtime profile is checked | `COMPUTE_RESOURCE_AUDIT.md`, `tools/verify_compute_resource_audit.ps1`, `outputs/publication_benchmark/benchmark_status.json`, `outputs/publication_benchmark/publication_gate_start.json`, and per-seed `run_record.json`/`run.log` files verify the observed 2h 38m 05s five-seed runtime, RTX 4070 Laptop GPU environment, five completed seeds, captured logs, and 480 per-seed metric rows. | Proven locally |
| Code provenance drift is bounded | `CODE_PROVENANCE_DRIFT_AUDIT.md` and `tools/verify_code_provenance_drift.ps1` compare the current source tree with the benchmark manifest code fingerprint, allow only documented post-benchmark reviewer-facing command-example/test-fixture drift plus the added physical-metric regression test, and fail on unexplained core experiment-code drift. | Proven locally |
| Numeric claims are traceable | `NUMERIC_CLAIMS_LEDGER.md` plus `tools/verify_numeric_claims.ps1` check primary claims and selected table values against generated CSV/TeX/report artifacts. | Proven locally |
| Narrative manuscript claims are traceable | `MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md` plus `tools/verify_manuscript_claim_traceability.ps1` check targeted-threat, attack-strength, high-F1/low-ASR, PV-ASR suppression, sensitivity-stability, and claim-scope wording against code and generated artifacts. | Proven locally |
| Primary and auxiliary claims are separated | `CLAIM_HIERARCHY_AUDIT.md` and `tools/verify_claim_hierarchy.ps1` check that the six primary numeric claims come from five-seed paired comparisons while ablation, sensitivity, strong-baseline, and PVR evidence remain auxiliary or diagnostic. | Proven locally |
| Primary claim directions are seed-consistent | `outputs/publication_benchmark/primary_seed_direction_summary.csv`, `outputs/publication_benchmark/primary_seed_direction_summary.tex`, `SEED_DIRECTION_CONSISTENCY_AUDIT.md`, and `tools/verify_seed_direction_consistency.ps1` recompute the six primary claim directions from per-seed metric rows, verify 30 positive seed-level paired differences, and check the generated summary table against the recomputed values. | Proven locally |
| Physical metric semantics are fixed | `PHYSICAL_METRIC_SEMANTICS_AUDIT.md` and `tools/verify_physical_metric_semantics.ps1` check sample-level ASR/PVR/PV-ASR definitions, code markers, regression tests, and 42 generated metric rows for exact per-sample PV-ASR semantics and PV-ASR bounds. | Proven locally |
| Attack evaluation sanity is checked | `ATTACK_EVALUATION_SANITY_CHECKLIST.md`, `ADAPTIVE_ATTACK_AUDIT.md`, and `tools/verify_attack_evaluation_sanity.ps1` check targeted attack implementation, multi-step attack strengthening, dropout handling and restoration during PGD, anomalous-only attack application, unit tests, and strong BiLSTM-ERM ASR under evaluated attacks. | Proven locally |
| Attack strength configuration is fixed and audited | `ATTACK_STRENGTH_CONFIGURATION_AUDIT.md` and `tools/verify_attack_strength_configuration.ps1` check benchmark-manifest attack hyperparameters, PGD step-size coverage, penalty-Phys-PGD schedule and weights, strong baseline ASR rows, and 24-row epsilon-sensitivity evidence. | Proven locally |
| Method-to-implementation traceability is checked | `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md` and `tools/verify_method_implementation_traceability.ps1` check the manuscript objective against unperturbed CE, anomalous-only adversarial CE, output-level KL consistency, representation MSE consistency, targeted attack code, detector feature outputs, benchmark-manifest hyperparameters, and five seed logs. | Proven locally |
| Statistical interpretation is bounded | `STATISTICAL_INTERPRETATION_CHECKLIST.md` plus `tools/verify_statistical_interpretation.ps1` check paired-comparison row counts, effect sizes, confidence intervals, exact sign-flip p-values, and absence of overstrong significance wording. | Proven locally |
| Dual-use safety boundary is explicit | `DUAL_USE_SAFETY_AUDIT.md` and `tools/verify_dual_use_safety.ps1` check offline defensive-use wording, live-system non-interaction, no operational injection guidance, and absence of socket/serial/SDR/ADS-B transmitter integration markers in core code and scripts. | Proven locally |
| Failure modes and negative results are visible | `FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md` plus `tools/verify_failure_mode_negative_results.ps1` check the `CAT-AD w/o Delta X` high-FAR failure mode, non-primary PVR boundary, conservative five-seed significance interpretation, and no-certificate limitation. | Proven locally |
| Paper tables and figures are traceable | `PAPER_ARTIFACT_PROVENANCE.md` plus `tools/verify_paper_artifact_provenance.ps1` check manuscript table inputs, CSV sources, figure variants, benchmark row counts, and manifest artifact-integrity entries. | Proven locally |
| Figure sources are fresh and consistent | `FIGURE_SOURCE_CONSISTENCY_AUDIT.md` plus `tools/verify_figure_source_consistency.ps1` check that figure-source CSV values match table/test-result sources, the epsilon grid is complete, and legacy figures are excluded from the submission bundle. | Proven locally |
| Paper exports are regenerable | `PAPER_EXPORT_REGENERATION_AUDIT.md` plus `tools/verify_paper_export_regeneration.ps1` run the paper-export regeneration command through `conda run --no-capture-output -n testtorch python`, verify byte-stable CSV/TeX/PNG exports, and rerun figure-source consistency checks before preview and bundle generation. | Proven locally |
| Ablation and sensitivity evidence is bounded | `ABLATION_AND_SENSITIVITY_AUDIT.md` and `tools/verify_ablation_sensitivity.ps1` check ablation variants, CSV/JSON consistency, epsilon-sensitivity source rows, figure artifacts, and interpretation guardrails that keep these results auxiliary to the multi-seed primary claims. | Proven locally |
| Paper source is complete enough for review | `paper_lncs/main.tex`, `paper_lncs/references.bib`, generated tables, and figures are checked by `tools/verify_manuscript_structure.ps1`. | Proven locally |
| Terminology and naming are standardized | `TERMINOLOGY_AND_NAMING_AUDIT.md`, `tools/verify_terminology_and_naming.ps1`, `outputs/audits/terminology_and_naming_verification.json`, and `tests/test_paper_naming.py` check 17 publication surfaces, 22 required first-use definitions, canonical `BiLSTM-ERM` and `Norm-bounded PGD` labels, prohibited legacy display names, and explicit archive-key compatibility mappings. | Proven locally |
| Manuscript reviewability is checked | `MANUSCRIPT_REVIEWABILITY_AUDIT.md` and `tools/verify_manuscript_reviewability.ps1` check anonymous review metadata, bounded abstract word count, exactly three contribution items, ordered review-critical sections, closed citations, placeholder-free preview HTML, and plausible A4 preview-PDF metadata. | Proven locally |
| Rendered PDF content is checked | `RENDERED_PDF_CONTENT_AUDIT.md` and `tools/verify_rendered_pdf_content.ps1` check the 11-page A4 preview and 18-page formal LNCS PDF through metadata, rendered PNG counts, nonblank sampled pixels, dark text/line samples, page content bounding boxes, and clipping guards. | Proven locally |
| TeX source portability is checked | `TEX_SOURCE_PORTABILITY_AUDIT.md` and `tools/verify_tex_source_portability.ps1` check local source closure, official `llncs.cls`/`splncs04.bst` hashes, input and figure resolution, BibTeX mapping, forbidden absolute paths and shell escape, and bundle inclusion of formal-PDF source inputs plus the formal PDF. | Proven locally |
| Formal LaTeX PDF build and log quality are verified | `FORMAL_PDF_BUILD_AUDIT.md`, `tools/build_submission_pdf.ps1`, and `tools/verify_formal_pdf_build_readiness.ps1` verify the official LNCS v2.24 build, `formal_pdf_build=PASSED`, `latex_log_quality=PASSED`, zero overfull boxes, zero undefined citations/references, supported `latexmk`/`tectonic`/`pdflatex` paths, and the `SKIPPED_NO_TEX_TOOL` no-tool rebuild boundary. | Proven locally |
| Threats to validity are explicit | `paper_lncs/main.tex` includes construct, internal, external, and artifact-validity threats; `tools/verify_manuscript_structure.ps1` and `tools/verify_preview_artifact.ps1` check the section and rendered preview markers. | Proven locally |
| Innovation claims are scoped and evidenced | `INNOVATION_AND_EVIDENCE.md`, `PRIOR_ART_NOVELTY_MATRIX.md`, `PRIOR_ART_CRITERIA_COVERAGE.tsv`, `PRIOR_ART_EVIDENCE_SNAPSHOT.md`, `CLAIM_SCOPE_GUARDRAILS.md`, `tools/verify_novelty_evidence.ps1`, and the related-work/positioning table in `paper_lncs/main.tex` separate existing ideas from CAT-AD's combined protocol and verify `full_prior_art_rows=0`. | Proven as a scoped claim |
| Recent prior-art challenges are incorporated | `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md` and `tools/verify_recent_prior_art_challenge.ps1` check that 2025/2026 realistic-attack detection, ADS-B recovery, IDS, attack-vector benchmark, lightweight IDS, physics-consistent trajectory anomaly detection, adversarial-perturbation detection, attack-type detection, xLSTM/Transformer IDS, data-security, and security-survey challenge references are cited in the manuscript, bounded in the novelty matrix/snapshot, and reported as `paper_citations_checked=12`. | Proven locally |
| Reviewer-objection response matrix is available | `REVIEWER_OBJECTION_RESPONSE_AUDIT.md` and `tools/verify_reviewer_objection_response.ps1` map 12 likely reviewer objections to evidence paths, verifier commands, expected outputs, and non-rebuttal boundaries including acceptance, adaptive-attack, transfer, auxiliary-ablation, and TeX limits. | Proven locally |
| Overclaiming is guarded | `tools/verify_claim_scope.ps1` checks required limiting language and forbidden absolute novelty/acceptance claims. | Proven locally |
| Submission bundle is reproducible | `tools/package_submission_bundle.ps1` builds the bundle and manifests; `tools/verify_submission_bundle.ps1` extracts the zip and checks each manifest hash and byte count. | Proven locally |
| Root README reviewer entry is available | `README.md`, `README_REVIEW_ENTRY_AUDIT.md`, and `tools/verify_readme_review_entry.ps1` provide and verify the standard repository landing page, shortest no-download command, rebuild command, main entry points, evidence files, conda rule, artifact boundary, and external limits with `readme_markers_checked=44`. | Proven locally |
| Anonymous review license and citation boundary is available | `LICENSE`, `CITATION.cff`, `ARTIFACT_LICENSE_AND_CITATION_AUDIT.md`, and `tools/verify_artifact_license_citation.ps1` define and verify anonymous-review use permissions, public-redistribution restrictions, citation metadata, and the public-license external boundary with `artifact_license_citation=PASSED`. | Proven locally |
| Reviewer quickstart is available | `REVIEWER_QUICKSTART.md` and `tools/verify_reviewer_quickstart.ps1` provide and verify the shortest no-download reviewer path, expected outputs, data boundary, and external limits. | Proven locally |
| Artifact evaluation guide is available | `ARTIFACT_EVALUATION_GUIDE.md` and `tools/verify_artifact_evaluation_guide.ps1` provide and verify a venue-neutral artifact-evaluation evidence matrix, fast path, deep checks, and official-badge/acceptance boundary. | Proven locally |
| Workspace hygiene and non-submission artifacts are bounded | `WORKSPACE_HYGIENE_AUDIT.md` and `tools/verify_workspace_hygiene.ps1` document local-only root artifacts, including raw snapshots and historical scratch files, and verify `excluded_manifest_paths_checked=9` so those non-submission root artifacts are absent from the review bundle manifest and zip. | Proven locally |
| Submission bundle is anonymous and portable | `tools/verify_anonymized_bundle.ps1` scans the generated zip for local usernames, home-directory paths, and absolute workstation project paths. | Proven locally |
| Double-blind review markers are checked | `DOUBLE_BLIND_REVIEW_CHECKLIST.md` plus `tools/verify_double_blind_submission.ps1` verify anonymous manuscript metadata, preview author metadata, no contact macros, and bundle-facing identity checks. | Proven locally |
| Local review PDF exists | `output/pdf/catad_submission_preview.pdf` is generated by Pandoc/Chrome and checked by `tools/verify_preview_artifact.ps1` for content markers, a warning-free Pandoc log, A4 metadata, and full-page rendering. | Proven locally |
| Formal venue-style PDF exists | `output/pdf/catad_submission_latex_updated.pdf` is an 18-page official-LNCS-class build; TeX-log and all-page render checks pass and the artifact is included in the bundle. | Proven locally |
| Final venue page-limit and portal compliance | The target conference and its page/anonymity/supplement policy have not been specified. | External decision |
| Top-conference acceptance | Requires external peer review and cannot be guaranteed by code, experiments, or a manuscript file. | Not locally provable |

## Evidence Summary

- Strict gate: `outputs/publication_benchmark/verification_report.md`
- Data provenance, ethics, split, and leakage audit:
  `DATA_PROVENANCE_AND_ETHICS.md`,
  `tools/verify_data_provenance_ethics.ps1`,
  `outputs/publication_benchmark/preflight_report.json`,
  `outputs/publication_benchmark/data_split_audit.tex`,
  `tools/build_data_split_audit_table.ps1`
- Dataset profile transparency: `DATASET_PROFILE_AUDIT.md`,
  `tools/verify_dataset_profile.ps1`
- External validity scope: `EXTERNAL_VALIDITY_SCOPE_AUDIT.md`,
  `tools/verify_external_validity_scope.ps1`
- Environment reproducibility: `ENVIRONMENT_REPRODUCIBILITY.md`,
  `tools/verify_environment_reproducibility.ps1`,
  `outputs/publication_benchmark/benchmark_manifest.json`
- Compute and runtime profile: `COMPUTE_RESOURCE_AUDIT.md`,
  `tools/verify_compute_resource_audit.ps1`,
  `outputs/publication_benchmark/benchmark_status.json`
- Threshold and hyperparameter leakage controls:
  `THRESHOLD_AND_HYPERPARAMETER_AUDIT.md`,
  `tools/verify_threshold_hyperparameter_audit.ps1`,
  per-seed `run_record.json` files
- Baseline comparison fairness: `BASELINE_FAIRNESS_AUDIT.md`,
  `tools/verify_baseline_fairness.ps1`
- Baseline competitiveness: `BASELINE_COMPETITIVENESS_AUDIT.md`,
  `tools/verify_baseline_competitiveness.ps1`
- Code provenance drift boundary: `CODE_PROVENANCE_DRIFT_AUDIT.md`,
  `tools/verify_code_provenance_drift.ps1`
- Manuscript: `paper_lncs/main.tex`
- Terminology and naming: `TERMINOLOGY_AND_NAMING_AUDIT.md`,
  `tools/verify_terminology_and_naming.ps1`,
  `outputs/audits/terminology_and_naming_verification.json`
- Manuscript reviewability: `MANUSCRIPT_REVIEWABILITY_AUDIT.md`,
  `tools/verify_manuscript_reviewability.ps1`
- Rendered PDF content: `RENDERED_PDF_CONTENT_AUDIT.md`,
  `tools/verify_rendered_pdf_content.ps1`
- TeX source portability: `TEX_SOURCE_PORTABILITY_AUDIT.md`,
  `tools/verify_tex_source_portability.ps1`
- Formal PDF build readiness: `FORMAL_PDF_BUILD_AUDIT.md`,
  `tools/build_submission_pdf.ps1`,
  `tools/verify_formal_pdf_build_readiness.ps1`
- Attack strength configuration: `ATTACK_STRENGTH_CONFIGURATION_AUDIT.md`,
  `tools/verify_attack_strength_configuration.ps1`
- Method-to-implementation traceability:
  `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md`,
  `tools/verify_method_implementation_traceability.ps1`
- Dual-use safety: `DUAL_USE_SAFETY_AUDIT.md`,
  `tools/verify_dual_use_safety.ps1`
- Threats to validity: `paper_lncs/main.tex`, `tools/verify_manuscript_structure.ps1`,
  `tools/verify_preview_artifact.ps1`
- Innovation and novelty boundary: `INNOVATION_AND_EVIDENCE.md`,
  `PRIOR_ART_NOVELTY_MATRIX.md`, `PRIOR_ART_CRITERIA_COVERAGE.tsv`,
  `PRIOR_ART_EVIDENCE_SNAPSHOT.md`, `tools/verify_novelty_evidence.ps1`
- Recent prior-art challenge boundary:
  `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md`,
  `tools/verify_recent_prior_art_challenge.ps1`
- Reviewer-objection response:
  `REVIEWER_OBJECTION_RESPONSE_AUDIT.md`,
  `tools/verify_reviewer_objection_response.ps1`
- Claim guardrails: `CLAIM_SCOPE_GUARDRAILS.md`
- Root README reviewer entry: `README.md`,
  `README_REVIEW_ENTRY_AUDIT.md`,
  `tools/verify_readme_review_entry.ps1`
- Anonymous review license and citation boundary: `LICENSE`,
  `CITATION.cff`, `ARTIFACT_LICENSE_AND_CITATION_AUDIT.md`,
  `tools/verify_artifact_license_citation.ps1`
- Reviewer quickstart: `REVIEWER_QUICKSTART.md`,
  `tools/verify_reviewer_quickstart.ps1`
- Artifact evaluation guide: `ARTIFACT_EVALUATION_GUIDE.md`,
  `tools/verify_artifact_evaluation_guide.ps1`
- Workspace hygiene: `WORKSPACE_HYGIENE_AUDIT.md`,
  `tools/verify_workspace_hygiene.ps1`
- Numeric traceability: `NUMERIC_CLAIMS_LEDGER.md`
- Manuscript claim traceability: `MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md`,
  `tools/verify_manuscript_claim_traceability.ps1`
- Claim hierarchy: `CLAIM_HIERARCHY_AUDIT.md`,
  `tools/verify_claim_hierarchy.ps1`
- Seed-direction consistency: `SEED_DIRECTION_CONSISTENCY_AUDIT.md`,
  `outputs/publication_benchmark/primary_seed_direction_summary.csv`,
  `outputs/publication_benchmark/primary_seed_direction_summary.tex`,
  `tools/verify_seed_direction_consistency.ps1`
- Physical metric semantics: `PHYSICAL_METRIC_SEMANTICS_AUDIT.md`,
  `tools/verify_physical_metric_semantics.ps1`
- Attack evaluation sanity: `ATTACK_EVALUATION_SANITY_CHECKLIST.md`,
  `ADAPTIVE_ATTACK_AUDIT.md`, `tools/verify_attack_evaluation_sanity.ps1`
- Statistical interpretation: `STATISTICAL_INTERPRETATION_CHECKLIST.md`,
  `tools/verify_statistical_interpretation.ps1`
- Failure modes and negative results:
  `FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md`,
  `tools/verify_failure_mode_negative_results.ps1`
- Paper artifact provenance: `PAPER_ARTIFACT_PROVENANCE.md`,
  `tools/verify_paper_artifact_provenance.ps1`
- Figure source consistency: `FIGURE_SOURCE_CONSISTENCY_AUDIT.md`,
  `tools/verify_figure_source_consistency.ps1`
- Paper export regeneration: `PAPER_EXPORT_REGENERATION_AUDIT.md`,
  `tools/verify_paper_export_regeneration.ps1`
- Ablation and sensitivity evidence: `ABLATION_AND_SENSITIVITY_AUDIT.md`,
  `tools/verify_ablation_sensitivity.ps1`,
  `results/fig_epsilon_sensitivity_data.csv`
- Reproducibility checklist: `ARTIFACT_REPRODUCIBILITY_CHECKLIST.md`
- Readiness audit: `TOP_CONFERENCE_READINESS_AUDIT.md`
- Submission bundle: `output/submission/catad_topconf_submission_bundle.zip`
- Targeted attack and physical metric regression tests:
  `tests/test_physical_metrics.py`
- Preview artifact verifier: `tools/verify_preview_artifact.ps1`
- Bundle anonymity verifier: `tools/verify_anonymized_bundle.ps1`
- Double-blind verifier: `DOUBLE_BLIND_REVIEW_CHECKLIST.md`,
  `tools/verify_double_blind_submission.ps1`

## Completion Decision

Current status: submission-style experimental package is locally verified under
the no-download constraint, including a formally compiled and rendered 18-page
LNCS PDF. The remaining items are external: selecting a target venue, checking
its current page/anonymity/supplement policy, and independent peer-review acceptance.

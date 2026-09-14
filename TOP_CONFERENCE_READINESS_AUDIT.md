# CAT-AD Top-Conference Readiness Audit

This audit maps the submission claims to evidence in the repository. It is not
a guarantee of acceptance. It is a pre-submission checklist intended to reduce
common top-tier review risks: unclear novelty, weak threat model, single-seed
experiments, leakage, missing statistics, missing artifacts, and overclaiming.

## Status

- Readiness level: submission-style experimental package with a no-download
  local audit.
- Strict benchmark gate: passed.
- Independent seeds: 5 (`42,43,44,45,46`).
- Formal TeX PDF: `output/pdf/catad_submission_latex_updated.pdf`, built as an 18-page
  official-LNCS-v2.24 artifact with Tectonic 0.16.9.
- Formal PDF quality: `formal_pdf_build=PASSED`, `latex_log_quality=PASSED`,
  zero overfull boxes, zero undefined citations/references, and all 15 rendered
  pages pass nonblank/content-box/clipping checks.
- Formal PDF build helper: `tools/build_submission_pdf.ps1`; machines without
  a local engine report `formal_pdf_build=SKIPPED_NO_TEX_TOOL` while retaining
  the archived formal artifact.
- Local manuscript preview: available at `output/pdf/catad_submission_preview.pdf`.
- Manuscript reviewability audit: passed locally with anonymous metadata,
  bounded abstract length, contribution count, citation closure, and A4 preview
  PDF metadata checks.
- Submission bundle: available at
  `output/submission/catad_topconf_submission_bundle.zip`.

## Evidence Matrix

| Review criterion | Evidence in repository | Current status |
| --- | --- | --- |
| Clear novelty boundary | `INNOVATION_AND_EVIDENCE.md`; `PRIOR_ART_NOVELTY_MATRIX.md`; `PRIOR_ART_CRITERIA_COVERAGE.tsv`; `PRIOR_ART_EVIDENCE_SNAPSHOT.md`; related-work and positioning table in `paper_lncs/main.tex`; `tools/verify_novelty_evidence.ps1` | Satisfied with scoped claims and machine-checked C1-C6 coverage |
| Recent prior-art challenge coverage | `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md`; `tools/verify_recent_prior_art_challenge.ps1`; 2025/2026 ADS-B IDS, attack-vector benchmark, lightweight IDS, physics-consistent robust trajectory anomaly detection, adversarial-perturbation detection, attack-type detection, xLSTM/Transformer IDS, data-security, ADS-B security survey, and ADS-B/RID survey references in the manuscript | Satisfied with scoped C1-C6 boundary |
| Threat model definition | `paper_lncs/main.tex`, Sections "Threat Model" and "Experimental Setting" | Satisfied |
| Domain-specific physical constraints | `adsb/attacks.py`; `adsb/training.py`; physical feasibility tables | Satisfied |
| Targeted anomalous-to-normal evasion | `adsb/attacks.py`; `adsb/training.py`; manuscript threat model | Satisfied |
| Physical validity metric | PV-ASR implementation in `adsb/training.py`; exported tables in `outputs/tables` and `outputs/publication_benchmark` | Satisfied |
| Paper artifact provenance | `PAPER_ARTIFACT_PROVENANCE.md`; `tools/verify_paper_artifact_provenance.ps1`; benchmark manifest artifact-integrity entries | Satisfied |
| Ablation and sensitivity support | `ABLATION_AND_SENSITIVITY_AUDIT.md`; `tools/verify_ablation_sensitivity.ps1`; `outputs/tables/table5_ablation_study.csv`; `results/fig_epsilon_sensitivity_data.csv` | Satisfied with auxiliary single-run design evidence |
| Robustness against digital PGD | `outputs/publication_benchmark/verification_report.md`; aggregate and paired comparison tables | Satisfied |
| Robustness against physical attacks | Projection-based and penalty-based Phys-PGD metrics in benchmark artifacts | Satisfied |
| Manuscript claim traceability | `MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md`; `tools/verify_manuscript_claim_traceability.ps1`; aggregate, paired, physical-feasibility, and sensitivity artifacts | Satisfied |
| Claim hierarchy | `CLAIM_HIERARCHY_AUDIT.md`; `tools/verify_claim_hierarchy.ps1`; six primary five-seed paired claims separated from auxiliary ablation, sensitivity, strong-baseline, and PVR evidence | Satisfied |
| Seed-direction consistency | `outputs/publication_benchmark/primary_seed_direction_summary.csv`; `outputs/publication_benchmark/primary_seed_direction_summary.tex`; `SEED_DIRECTION_CONSISTENCY_AUDIT.md`; `tools/verify_seed_direction_consistency.ps1`; all 30 seed-level differences for the six primary claims are positive in the claim direction | Satisfied |
| Physical metric semantics | `PHYSICAL_METRIC_SEMANTICS_AUDIT.md`; `tools/verify_physical_metric_semantics.ps1`; paper definitions, code markers, regression tests, and 42 generated metric rows verify sample-level ASR/PVR/PV-ASR semantics | Satisfied |
| Manuscript reviewability | `MANUSCRIPT_REVIEWABILITY_AUDIT.md`; `tools/verify_manuscript_reviewability.ps1`; anonymous metadata, abstract length, contribution items, section order, citation closure, preview HTML, and A4 preview-PDF metadata | Satisfied |
| Attack-strength sanity | `ATTACK_EVALUATION_SANITY_CHECKLIST.md`; `tools/verify_attack_evaluation_sanity.ps1`; unit tests for targeted attacks and PV-ASR; high baseline ASR under evaluated attacks | Satisfied |
| Fixed attack-strength configuration | `ATTACK_STRENGTH_CONFIGURATION_AUDIT.md`; `tools/verify_attack_strength_configuration.ps1`; benchmark-manifest PGD/Phys-PGD hyperparameters, step-size coverage, strong baseline ASR rows, and epsilon-sensitivity evidence | Satisfied |
| Method-to-implementation traceability | `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md`; `tools/verify_method_implementation_traceability.ps1`; manuscript objective, training loss components, targeted attack code, detector feature return path, manifest hyperparameters, and per-seed logs | Satisfied |
| Multi-seed statistical protocol | `adsb/benchmark.py`; `outputs/publication_benchmark/paired_comparisons.csv`; `paired_comparisons.tex` | Satisfied |
| Statistical interpretation boundary | `STATISTICAL_INTERPRETATION_CHECKLIST.md`; `tools/verify_statistical_interpretation.ps1`; manuscript "Statistical Interpretation" paragraph | Satisfied |
| Data leakage control | `adsb/publication_preflight.py`; `outputs/publication_benchmark/preflight_report.json`; `outputs/publication_benchmark/data_split_audit.tex`; `tools/build_data_split_audit_table.ps1` | Satisfied |
| Dataset profile transparency | `DATASET_PROFILE_AUDIT.md`; `tools/verify_dataset_profile.ps1`; raw CSV header/range profile; preflight row counts; split/window coverage | Satisfied |
| External-validity scope | `EXTERNAL_VALIDITY_SCOPE_AUDIT.md`; `tools/verify_external_validity_scope.ps1`; one-day/20-raw-aircraft/19-filtered-aircraft manuscript boundary and overbroad-generalization scan | Satisfied |
| Dual-use safety boundary | `DUAL_USE_SAFETY_AUDIT.md`; `tools/verify_dual_use_safety.ps1`; offline defensive-use wording, no live-system interaction, no operational injection guidance, and core-code scan for socket/serial/SDR/transmitter markers | Satisfied |
| Threshold and hyperparameter leakage control | `THRESHOLD_AND_HYPERPARAMETER_AUDIT.md`; `tools/verify_threshold_hyperparameter_audit.ps1`; per-seed `run_record.json`; benchmark manifest hyperparameter snapshot | Satisfied |
| Baseline comparison fairness | `BASELINE_FAIRNESS_AUDIT.md`; `tools/verify_baseline_fairness.ps1`; shared model constructor, shared loaders, validation-only thresholds, and paired metric rows | Satisfied |
| Baseline competitiveness | `BASELINE_COMPETITIVENESS_AUDIT.md`; `tools/verify_baseline_competitiveness.ps1`; auxiliary ablation table includes PGD-AT, Projection Phys-PGD-AT, and Penalty Phys-PGD-AT strong adversarial-training baselines | Satisfied with single-seed auxiliary evidence |
| Failure modes and negative results | `FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md`; `tools/verify_failure_mode_negative_results.ps1`; ablation CSV; paired PVR rows; manuscript limitation markers | Satisfied |
| Data provenance and ethics | `DATA_PROVENANCE_AND_ETHICS.md`; `tools/verify_data_provenance_ethics.ps1`; manuscript ethics section | Satisfied |
| Environment reproducibility | `ENVIRONMENT_REPRODUCIBILITY.md`; `tools/verify_environment_reproducibility.ps1`; `outputs/publication_benchmark/benchmark_manifest.json` | Satisfied |
| Compute and runtime profile | `COMPUTE_RESOURCE_AUDIT.md`; `tools/verify_compute_resource_audit.ps1`; benchmark start/status records and per-seed logs verify the observed 2h 38m 05s five-seed run on the manifest-recorded RTX 4070 Laptop GPU environment | Satisfied with observed-workstation boundary |
| Code provenance drift boundary | `CODE_PROVENANCE_DRIFT_AUDIT.md`; `tools/verify_code_provenance_drift.ps1`; benchmark manifest code fingerprint | Satisfied with scoped post-benchmark hygiene drift |
| Reproducibility metadata | `outputs/publication_benchmark/benchmark_manifest.json` | Satisfied |
| Artifact checksums | `benchmark_manifest.json`; bundle manifest files in `output/submission` | Satisfied |
| Figure source consistency | `FIGURE_SOURCE_CONSISTENCY_AUDIT.md`; `tools/verify_figure_source_consistency.ps1`; current table/test-result values, figure-source CSVs, official figure triads, and legacy-figure exclusion | Satisfied |
| Paper export regeneration | `PAPER_EXPORT_REGENERATION_AUDIT.md`; `tools/verify_paper_export_regeneration.ps1`; no-capture Conda regeneration command and byte-stable CSV/TeX/PNG checks | Satisfied |
| Root reviewer entry | `README.md`; `README_REVIEW_ENTRY_AUDIT.md`; `tools/verify_readme_review_entry.ps1`; no-download command, rebuild command, entry points, conda rule, artifact boundary, and external limits | Satisfied |
| License and citation boundary | `LICENSE`; `CITATION.cff`; `ARTIFACT_LICENSE_AND_CITATION_AUDIT.md`; `tools/verify_artifact_license_citation.ps1`; anonymous review use statement and citation metadata | Satisfied with public-license boundary |
| Reviewer quickstart | `REVIEWER_QUICKSTART.md`; `tools/verify_reviewer_quickstart.ps1` | Satisfied |
| Artifact evaluation guide | `ARTIFACT_EVALUATION_GUIDE.md`; `tools/verify_artifact_evaluation_guide.ps1`; badge-readiness boundary and deep evaluation matrix | Satisfied |
| Reviewer-objection response | `REVIEWER_OBJECTION_RESPONSE_AUDIT.md`; `tools/verify_reviewer_objection_response.ps1`; 12 likely objections mapped to evidence paths, verifier outputs, and non-rebuttal boundaries | Satisfied |
| Workspace hygiene and bundle boundary | `WORKSPACE_HYGIENE_AUDIT.md`; `tools/verify_workspace_hygiene.ps1`; local raw snapshots, old archives, and scratch scripts are documented as non-submission artifacts and excluded from the bundle manifest/zip | Satisfied |
| Unit-level regression checks | `tests/test_benchmark_stats.py`; `tests/test_physical_metrics.py`; `tests/test_submission_tex_generation.py`; audited by `check_submission_ready.ps1` | Satisfied |
| Paper source completeness | `paper_lncs/main.tex`; `paper_lncs/references.bib`; generated tables and figures | Satisfied |
| TeX source portability | `TEX_SOURCE_PORTABILITY_AUDIT.md`; `tools/verify_tex_source_portability.ps1`; official LNCS style hashes, local input/figure closure, BibTeX mapping, path checks, and bundle inclusion of source plus formal PDF | Satisfied |
| Formal PDF build and log quality | `FORMAL_PDF_BUILD_AUDIT.md`; `tools/build_submission_pdf.ps1`; `tools/verify_formal_pdf_build_readiness.ps1`; official LNCS v2.24, 18-page artifact, zero overfull boxes and undefined references | Satisfied |
| Rendered PDF content | `RENDERED_PDF_CONTENT_AUDIT.md`; `tools/verify_rendered_pdf_content.ps1`; 11-page A4 preview and 18-page formal LNCS metadata, nonblank samples, dark text/line samples, content boxes, and clipping guards | Satisfied |
| Double-blind review readiness | `DOUBLE_BLIND_REVIEW_CHECKLIST.md`; `tools/verify_double_blind_submission.ps1`; anonymous manuscript and preview metadata | Satisfied |
| Ethics, limitations, and threats to validity | `paper_lncs/main.tex`, Sections "Ethical Considerations", "Limitations", and "Threats to Validity"; preview verifier checks rendered markers | Satisfied |
| Completion boundary | `SUBMISSION_COMPLETION_AUDIT.md`; `tools/verify_completion_audit.ps1` | Satisfied |
| No-download workflow | `check_submission_ready.ps1 -NoDownload`; `SUBMISSION_READINESS.md` | Satisfied |
| Venue-style PDF | Formal 18-page LNCS PDF is built, rendered, and bundled | Satisfied locally; final venue page-limit policy remains external |

## Primary Claims Checked by the Strict Gate

The strict gate in `outputs/publication_benchmark/verification_report.md`
currently reports all primary claims as passing:

- Clean F1 is not reduced by CAT-AD.
- Standard PGD ASR is reduced by CAT-AD.
- Projection-based Phys-PGD ASR is reduced by CAT-AD.
- Penalty-based Phys-PGD ASR is reduced by CAT-AD.
- Projection-based Phys-PGD PV-ASR is reduced by CAT-AD.
- Penalty-based Phys-PGD PV-ASR is reduced by CAT-AD.

## Reviewer-Risk Notes

| Risk | Mitigation | Remaining caveat |
| --- | --- | --- |
| Overclaiming novelty | The paper explicitly says LSTM, PGD, ADS-B anomaly detection, adversarial examples, and ADS-B adversarial attacks are not new; `PRIOR_ART_NOVELTY_MATRIX.md`, `PRIOR_ART_CRITERIA_COVERAGE.tsv`, and `PRIOR_ART_EVIDENCE_SNAPSHOT.md` make the novelty boundary falsifiable and source-backed. | Claim should remain "to the best of our knowledge" and tied to evaluated artifacts. |
| Missing recent related work | Recent-prior-art challenge audit adds Cevik and Akleylek 2025, Ahmed et al. 2025, Ahmed et al. 2026, Zhong et al. 2026, Zhao et al. 2026 IMDM-PC, Ngamboe et al. 2025, Khan et al. 2025, Zhang et al. 2025, Shi et al. 2026, and Ahmed et al. 2026 to the manuscript and checks that they do not jointly satisfy CAT-AD's C1-C6 boundary. | This is still a dated sampled evidence check, not a proof of global novelty. |
| Physical realism challenge | The paper reports PVR and PV-ASR and separates digital ASR from physically valid evasion. | Physical constraints are still an evaluated proxy, not an aviation safety certificate. |
| Statistical strength | Five independent seeds, paired comparisons, confidence intervals, and strict gate are included. | Exact sign-flip p-values with five seeds are conservative; emphasize effect sizes and CIs. |
| Component and budget sensitivity challenge | Ablation and sensitivity verifier checks component variants, no-differential-feature failure mode, epsilon source rows, and figure artifacts. | Ablation/sensitivity evidence is auxiliary and single-run; primary claims remain the multi-seed benchmark. |
| Statistical overclaiming | The manuscript frames paired results as effect-size-first and does not claim conclusive hypothesis-test evidence from five seeds. | Additional seeds would strengthen null-hypothesis testing. |
| Validity threats | The manuscript separates construct, internal, external, and artifact validity threats. | Additional datasets and adaptive attackers remain future evaluation work. |
| Data governance | The data provenance statement records the benchmark CSV hash, bundled-data boundary, raw upstream snapshot exclusion from the bundle, preflight split checks, and offline safety restrictions. | Public-data licensing and venue-specific artifact-access forms may still need final portal entries. |
| Dual-use ambiguity | Dual-use safety audit verifies that the manuscript and artifact documentation keep the work at offline decoded-trajectory/model-evaluation level and that core code/scripts do not include socket, serial, SDR, transmitter, or live air-traffic integration markers. | This reduces artifact misuse ambiguity; it does not certify that all downstream uses are safe. |
| Workspace clutter confusing reviewers | Workspace hygiene audit documents local-only raw snapshots, old archives, and scratch scripts, then verifies they are absent from the review bundle manifest and zip. | It documents and excludes local files; it does not delete the user's working copies. |
| Dataset transparency challenge | Dataset-profile audit records raw row counts, time range, raw feature ranges, model-loaded/filtering counts, aircraft counts, and split/window coverage; external-validity scope audit checks that the manuscript states the one-day, 20-raw-aircraft, 19-filtered-aircraft boundary and avoids transfer overclaims. | The sample still covers one UTC day and 20 raw aircraft identifiers, so external validity remains scoped. |
| Threshold or hyperparameter tuning leakage | Threshold/hyperparameter audit verifies validation-only threshold selection, fixed test-time thresholds, per-seed run-record threshold metadata, zero split overlap, and manifest hyperparameter values. | It does not replace an external review of every exploratory run; claims should stay tied to the archived publication benchmark. |
| Unfair baseline comparison | Baseline-fairness audit verifies the same detector constructor, train/validation/test loaders, common training kwargs, class weights, validation-threshold protocol, and paired Baseline/Proposed metric rows. | CAT-AD intentionally adds adversarial training and consistency losses; these are the intervention under test. |
| Weak baseline concern | Baseline-competitiveness audit verifies that the auxiliary table includes PGD-AT, Projection Phys-PGD-AT, and Penalty Phys-PGD-AT strong adversarial-training baselines, and that the manuscript avoids claiming CAT-AD dominates every single-run ablation metric. | These strong-baseline comparisons are auxiliary single-seed evidence; primary quantitative claims remain the five-seed CAT-AD-vs-Standard-BiLSTM benchmark. |
| Selective reporting or hidden failure modes | Failure-mode audit preserves the `CAT-AD w/o Delta X` high-FAR failure case, the non-primary PVR boundary, conservative five-seed significance interpretation, and the no-certificate limitation. | PVR is reported as a diagnostic, not as a primary CAT-AD improvement claim. |
| Result traceability | The paper artifact provenance verifier maps manuscript tables and figures to local CSV, benchmark, figure, and manifest records. | Static single-run summary tables remain secondary to the strict multi-seed benchmark artifacts. |
| Stale figure-source risk | Figure-source consistency verifier checks that `fig_physical_valid_asr_data.csv`, robustness tables, physical-feasibility tables, and epsilon-sensitivity data agree before packaging. | It validates data closure, not rendered pixel geometry. |
| Stale paper-export risk | Paper-export regeneration verifier reruns the exporter before preview/bundle generation and requires byte-stable CSV/TeX/PNG outputs. | PDF/SVG bytes may vary due to plotting metadata, so they are checked as packaged artifacts rather than determinism oracles. |
| Unsupported narrative claims | Manuscript claim-traceability audit maps result wording to code markers, generated CSV tables, physical-feasibility rows, paired comparisons, and epsilon-sensitivity data. | It checks local artifacts, not external reviewer interpretation. |
| Selective-reporting hierarchy | Claim-hierarchy audit verifies that the six primary numeric claims come from the five-seed paired benchmark and that ablation, sensitivity, strong-baseline, and PVR evidence remain auxiliary or diagnostic. | It clarifies evidence priority; it does not make auxiliary experiments multi-seed primary claims. |
| Seed outlier concern | Seed-direction audit recomputes five seed-wise differences for each of the six primary claims, requires all 30 differences to be positive in the claim direction, and verifies the generated `primary_seed_direction_summary` CSV/TeX table against those recomputed values. | It rules out a single-seed mean artifact for the primary claims; it does not replace more seeds, more datasets, or broader attacks. |
| Physical metric ambiguity | Physical-metric semantics audit verifies that ASR, PVR, and PV-ASR are sample-level attacked-anomalous metrics, that PV-ASR is computed as an exact per-sample intersection, and that generated rows satisfy `PV-ASR <= ASR` and `PV-ASR <= 1-PVR`. | It verifies metric semantics and consistency, not the adequacy of every possible physical constraint definition. |
| Manuscript entry-point defects | Manuscript-reviewability audit checks anonymous metadata, bounded abstract length, exactly three contribution items, ordered sections, citation closure, placeholder absence, and A4 preview-PDF metadata. | Final venue portal and page-limit rules remain external. |
| Rendered PDF failure | Rendered-PDF content audit renders all preview and formal pages and checks dimensions, nonblank samples, dark text/line samples, content boxes, and edge clipping; the 18-page formal PDF was also inspected page by page. | It catches blank/truncated rendering failures but does not replace venue policy review. |
| Weak-attack or gradient-masking concern | Attack sanity checks verify dropout/BiLSTM-dropout handling and restoration during PGD, targeted attack direction tests, multi-step target-margin strengthening, anomalous-only attack application, and high BiLSTM-ERM ASR under all evaluated attack families; `ADAPTIVE_ATTACK_AUDIT.md` records the risk model. | This remains an empirical sanity check, not a proof against every adaptive attack. |
| Attack hyperparameters look under-specified | Attack-strength configuration audit verifies manifest-recorded `EVAL_ATTACK_EPS`, `PGD_STEPS`, `PGD_ALPHA`, penalty-Phys-PGD schedule/weights, step-size coverage, high baseline ASR, and epsilon-sensitivity rows. | This documents evaluated settings; it does not certify robustness outside those budgets or against all adaptive attacks. |
| Paper-code method mismatch | Method-implementation traceability audit checks that the paper objective maps to unperturbed CE, anomalous-only adversarial CE, output-level KL consistency, representation MSE consistency, targeted attack code, detector feature outputs, manifest hyperparameters, and seed-log components. | It verifies the archived implementation boundary, not that the design is theoretically optimal. |
| Reproducibility challenge | Bundle includes code, tests, manifests, checksums, official LNCS source/style files, formal and preview PDFs, and sample data. | Full benchmark rerun may still take time on another machine. |
| Environment drift | Environment verifier checks the active `testtorch` environment against the benchmark manifest's key package versions and deterministic flags. | Reviewers need an already provisioned compatible environment because the workflow does not download software. |
| Runtime-cost ambiguity | Compute-resource audit records the manifest GPU/CUDA/PyTorch environment and verifies the observed five-seed wall-clock time from the gate start record and per-seed completions. | It is an observed workstation profile, not a cross-hardware runtime guarantee. |
| Source-code drift after benchmark | Code provenance drift verifier compares the current source tree to the benchmark manifest fingerprint and only allows documented reviewer-facing command-example/test-fixture changes plus the added physical-metric regression test. | Any future drift in model, attack, training, benchmark, data, or verification core should trigger a benchmark rerun before updating quantitative claims. |
| Reviewer navigation | `REVIEWER_QUICKSTART.md` gives the shortest no-download audit command and expected outputs; `REVIEWER_OBJECTION_RESPONSE_AUDIT.md` maps likely reviewer-objection response paths to local evidence and verifier outputs. | Reviewers still need the pre-existing `testtorch` environment. |
| Missing standard repository landing page | Root `README.md` now gives the anonymous review entry, rebuild command, evidence map, artifact boundary, and external limits; `tools/verify_readme_review_entry.ps1` checks it. | It is a review entry page, not a venue portal submission form. |
| Missing license/citation guidance | `LICENSE`, `CITATION.cff`, and `tools/verify_artifact_license_citation.ps1` define anonymous review permissions, citation metadata, and public-redistribution limits. | Public release license selection remains a deanonymized author decision. |
| Artifact badge overclaiming | Artifact-evaluation guide maps local evidence to common review concerns while explicitly saying official badges and acceptance remain external decisions. | Venue-specific badge forms still need final portal entries. |
| Formal PDF source portability | `TEX_SOURCE_PORTABILITY_AUDIT.md` and `tools/verify_tex_source_portability.ps1` check official template hashes, source closure, local paths, BibTeX mapping, and bundle inclusion of the reviewed formal artifact. | A future venue may impose different template or page-limit rules. |
| Formal PDF build entry point | `FORMAL_PDF_BUILD_AUDIT.md` and `tools/verify_formal_pdf_build_readiness.ps1` verify the successful Tectonic/LNCS build and preserve a no-tool `SKIPPED_NO_TEX_TOOL` rebuild boundary. | Local compilation does not imply acceptance. |
| Double-blind leakage | Manuscript, preview HTML, and generated bundle are checked for anonymous metadata, contact macros, current workstation username, and absolute local paths. | Venue-specific anonymity rules may require final portal checks. |
| Tooling limitation | No-download reviewer workflow verifies source, experiments, both PDFs, warning-free conversion, and bundle without installing software. | Rebuilding still needs an already available TeX engine; verification does not. |

## No-Download Audit Command

Use this command to verify the current package without downloading software:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload -BuildPreviewPdf -BuildSubmissionBundle
```

The command verifies the strict benchmark gate, unit tests, manuscript inputs,
preview PDF, submission bundle, and no-download policy. It does not install
packages or download external software.

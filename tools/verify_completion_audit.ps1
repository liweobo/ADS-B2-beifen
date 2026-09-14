$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing completion-audit artifact: $Path"
    }
    return $candidate
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing expected content: $Needle"
    }
}

$auditPath = Require-File "SUBMISSION_COMPLETION_AUDIT.md"
$audit = Get-Content -Raw -LiteralPath $auditPath

$requiredEvidenceFiles = @(
    "AGENTS.md",
    "check_submission_ready.ps1",
    "adsb\benchmark.py",
    "adsb\attacks.py",
    "adsb\training.py",
    "adsb\verify_artifacts.py",
    "tools\run_publication_gate.py",
    "tools\regenerate_paper_exports.py",
    "tools\build_data_split_audit_table.ps1",
    "tools\build_submission_pdf.ps1",
    "tools\verify_numeric_claims.ps1",
    "tools\verify_manuscript_claim_traceability.ps1",
    "tools\verify_claim_hierarchy.ps1",
    "tools\verify_seed_direction_consistency.ps1",
    "tools\verify_physical_metric_semantics.ps1",
    "tools\verify_terminology_and_naming.ps1",
    "tools\verify_manuscript_reviewability.ps1",
    "tools\verify_rendered_pdf_content.ps1",
    "tools\verify_attack_evaluation_sanity.ps1",
    "tools\verify_attack_strength_configuration.ps1",
    "tools\verify_method_implementation_traceability.ps1",
    "tools\verify_statistical_interpretation.ps1",
    "tools\verify_data_provenance_ethics.ps1",
    "tools\verify_dual_use_safety.ps1",
    "tools\verify_dataset_profile.ps1",
    "tools\verify_external_validity_scope.ps1",
    "tools\verify_environment_reproducibility.ps1",
    "tools\verify_compute_resource_audit.ps1",
    "tools\verify_reviewer_quickstart.ps1",
    "tools\verify_readme_review_entry.ps1",
    "tools\verify_artifact_license_citation.ps1",
    "tools\verify_artifact_evaluation_guide.ps1",
    "tools\verify_workspace_hygiene.ps1",
    "tools\verify_tex_source_portability.ps1",
    "tools\verify_formal_pdf_build_readiness.ps1",
    "tools\verify_code_provenance_drift.ps1",
    "tools\verify_ablation_sensitivity.ps1",
    "tools\verify_threshold_hyperparameter_audit.ps1",
    "tools\verify_failure_mode_negative_results.ps1",
    "tools\verify_baseline_fairness.ps1",
    "tools\verify_baseline_competitiveness.ps1",
    "tools\verify_claim_scope.ps1",
    "tools\verify_novelty_evidence.ps1",
    "tools\verify_recent_prior_art_challenge.ps1",
    "tools\verify_paper_artifact_provenance.ps1",
    "tools\verify_figure_source_consistency.ps1",
    "tools\verify_paper_export_regeneration.ps1",
    "tools\verify_manuscript_structure.ps1",
    "tools\verify_preview_artifact.ps1",
    "tools\verify_anonymized_bundle.ps1",
    "tools\verify_double_blind_submission.ps1",
    "tools\verify_submission_bundle.ps1",
    "tests\test_benchmark_stats.py",
    "tests\test_physical_metrics.py",
    "tests\test_submission_tex_generation.py",
    "tests\test_paper_naming.py",
    "ADAPTIVE_ATTACK_AUDIT.md",
    "ATTACK_STRENGTH_CONFIGURATION_AUDIT.md",
    "DATA_PROVENANCE_AND_ETHICS.md",
    "DUAL_USE_SAFETY_AUDIT.md",
    "DATASET_PROFILE_AUDIT.md",
    "EXTERNAL_VALIDITY_SCOPE_AUDIT.md",
    "ENVIRONMENT_REPRODUCIBILITY.md",
    "COMPUTE_RESOURCE_AUDIT.md",
    "CODE_PROVENANCE_DRIFT_AUDIT.md",
    "ABLATION_AND_SENSITIVITY_AUDIT.md",
    "THRESHOLD_AND_HYPERPARAMETER_AUDIT.md",
    "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md",
    "BASELINE_FAIRNESS_AUDIT.md",
    "BASELINE_COMPETITIVENESS_AUDIT.md",
    "outputs\publication_benchmark\verification_report.md",
    "outputs\publication_benchmark\preflight_report.json",
    "outputs\publication_benchmark\data_split_audit.csv",
    "outputs\publication_benchmark\data_split_audit.tex",
    "outputs\publication_benchmark\paired_comparisons.csv",
    "outputs\test_set_results.csv",
    "results\fig_epsilon_sensitivity_data.csv",
    "results\fig_physical_valid_asr_data.csv",
    "paper_lncs\main.tex",
    "paper_lncs\references.bib",
    "paper_lncs\README_compile.txt",
    "paper_lncs\llncs.cls",
    "paper_lncs\splncs04.bst",
    "paper_lncs\SPRINGER_TEMPLATE_PROVENANCE.md",
    "INNOVATION_AND_EVIDENCE.md",
    "PRIOR_ART_NOVELTY_MATRIX.md",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "PRIOR_ART_EVIDENCE_SNAPSHOT.md",
    "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md",
    "PAPER_ARTIFACT_PROVENANCE.md",
    "FIGURE_SOURCE_CONSISTENCY_AUDIT.md",
    "PAPER_EXPORT_REGENERATION_AUDIT.md",
    "DOUBLE_BLIND_REVIEW_CHECKLIST.md",
    "ATTACK_EVALUATION_SANITY_CHECKLIST.md",
    "STATISTICAL_INTERPRETATION_CHECKLIST.md",
    "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md",
    "CLAIM_SCOPE_GUARDRAILS.md",
    "NUMERIC_CLAIMS_LEDGER.md",
    "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md",
    "CLAIM_HIERARCHY_AUDIT.md",
    "SEED_DIRECTION_CONSISTENCY_AUDIT.md",
    "PHYSICAL_METRIC_SEMANTICS_AUDIT.md",
    "TERMINOLOGY_AND_NAMING_AUDIT.md",
    "outputs\audits\terminology_and_naming_verification.json",
    "MANUSCRIPT_REVIEWABILITY_AUDIT.md",
    "RENDERED_PDF_CONTENT_AUDIT.md",
    "LICENSE",
    "CITATION.cff",
    "README.md",
    "README_REVIEW_ENTRY_AUDIT.md",
    "ARTIFACT_LICENSE_AND_CITATION_AUDIT.md",
    "REVIEWER_QUICKSTART.md",
    "ARTIFACT_EVALUATION_GUIDE.md",
    "WORKSPACE_HYGIENE_AUDIT.md",
    "TEX_SOURCE_PORTABILITY_AUDIT.md",
    "FORMAL_PDF_BUILD_AUDIT.md",
    "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md",
    "TOP_CONFERENCE_READINESS_AUDIT.md",
    "output\pdf\catad_submission_preview.pdf",
    "output\pdf\catad_submission_latex_updated.pdf",
    "output\submission\catad_topconf_submission_bundle.zip"
)
foreach ($path in $requiredEvidenceFiles) {
    Require-File $path | Out-Null
}

$requirements = @(
    "No software downloads",
    "Python commands use the required conda environment",
    "Experiment code exists",
    "Unit-level regression coverage exists",
    "Publication-grade experiment artifacts exist",
    "Data split, provenance, ethics, and leakage audit are visible",
    "Dataset profile transparency is visible",
    "External validity scope is bounded",
    "Threshold and hyperparameter leakage controls are visible",
    "Baseline comparison fairness is visible",
    "Baseline competitiveness is visible",
    "Environment reproducibility is checked",
    "Compute and runtime profile is checked",
    "Code provenance drift is bounded",
    "Numeric claims are traceable",
    "Narrative manuscript claims are traceable",
    "Primary and auxiliary claims are separated",
    "Primary claim directions are seed-consistent",
    "Physical metric semantics are fixed",
    "Attack evaluation sanity is checked",
    "Attack strength configuration is fixed and audited",
    "Method-to-implementation traceability is checked",
    "Statistical interpretation is bounded",
    "Dual-use safety boundary is explicit",
    "Failure modes and negative results are visible",
    "Paper tables and figures are traceable",
    "Figure sources are fresh and consistent",
    "Paper exports are regenerable",
    "Ablation and sensitivity evidence is bounded",
    "Paper source is complete enough for review",
    "Terminology and naming are standardized",
    "Manuscript reviewability is checked",
    "Rendered PDF content is checked",
    "TeX source portability is checked",
    "Formal LaTeX PDF build and log quality are verified",
    "Threats to validity are explicit",
    "Innovation claims are scoped and evidenced",
    "Recent prior-art challenges are incorporated",
    "Overclaiming is guarded",
    "Submission bundle is reproducible",
    "Root README reviewer entry is available",
    "Anonymous review license and citation boundary is available",
    "Reviewer quickstart is available",
    "Artifact evaluation guide is available",
    "Workspace hygiene and non-submission artifacts are bounded",
    "Submission bundle is anonymous and portable",
    "Double-blind review markers are checked",
    "Local review PDF exists",
    "Formal venue-style PDF exists",
    "Top-conference acceptance"
)
foreach ($requirement in $requirements) {
    Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit $requirement
}

$requiredStatuses = @(
    "Proven locally",
    "Proven as a scoped claim",
    "External decision",
    "Not locally provable"
)
foreach ($status in $requiredStatuses) {
    Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit $status
}

$verificationReport = Get-Content -Raw -LiteralPath (Require-File "outputs\publication_benchmark\verification_report.md")
Assert-Contains "verification_report.md" $verificationReport "Status: PASSED"
Assert-Contains "verification_report.md" $verificationReport "Seeds: 42,43,44,45,46"
Assert-Contains "verification_report.md" $verificationReport "Require primary claims: True"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "zero aircraft overlap"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "benchmark CSV hash"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "raw snapshot exclusion"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "offline safety restrictions"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "DATA_PROVENANCE_AND_ETHICS.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_data_provenance_ethics.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "DATASET_PROFILE_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_dataset_profile.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "raw CSV header"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "model-loaded/filtering counts"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "EXTERNAL_VALIDITY_SCOPE_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_external_validity_scope.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "20 raw aircraft identifiers"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "19 filtered aircraft"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "THRESHOLD_AND_HYPERPARAMETER_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_threshold_hyperparameter_audit.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "validation-only threshold selection"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "BASELINE_FAIRNESS_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_baseline_fairness.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "shared model construction"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "paired metric rows"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "BASELINE_COMPETITIVENESS_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_baseline_competitiveness.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "strong adversarial-training baselines"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "Penalty Phys-PGD-AT"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "does not claim CAT-AD dominates every single-run ablation metric"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "ENVIRONMENT_REPRODUCIBILITY.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_environment_reproducibility.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "COMPUTE_RESOURCE_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_compute_resource_audit.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "2h 38m 05s"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "RTX 4070 Laptop GPU"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "480 per-seed metric rows"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "CODE_PROVENANCE_DRIFT_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_code_provenance_drift.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "unexplained core experiment-code drift"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "data_split_audit.tex"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tests/test_physical_metrics.py"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tests/test_submission_tex_generation.py"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_manuscript_claim_traceability.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "CLAIM_HIERARCHY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_claim_hierarchy.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "six primary numeric claims"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "auxiliary or diagnostic"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "SEED_DIRECTION_CONSISTENCY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_seed_direction_consistency.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "30 positive seed-level paired differences"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "PHYSICAL_METRIC_SEMANTICS_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_physical_metric_semantics.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "sample-level ASR/PVR/PV-ASR definitions"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "exact per-sample PV-ASR semantics"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "TERMINOLOGY_AND_NAMING_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_terminology_and_naming.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "17 publication surfaces"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "22 required first-use definitions"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "BiLSTM-ERM"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "Norm-bounded PGD"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "MANUSCRIPT_REVIEWABILITY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_manuscript_reviewability.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "abstract word count"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "three contribution items"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "RENDERED_PDF_CONTENT_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_rendered_pdf_content.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "nonblank sampled pixels"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "page content bounding boxes"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "PV-ASR suppression"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "sensitivity-stability"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "PRIOR_ART_NOVELTY_MATRIX.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "PRIOR_ART_CRITERIA_COVERAGE.tsv"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "PRIOR_ART_EVIDENCE_SNAPSHOT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_novelty_evidence.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "full_prior_art_rows=0"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_recent_prior_art_challenge.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "2025/2026 realistic-attack detection"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "paper_citations_checked=12"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "PAPER_ARTIFACT_PROVENANCE.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_paper_artifact_provenance.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "FIGURE_SOURCE_CONSISTENCY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_figure_source_consistency.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "figure-source CSV values"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "legacy figures are excluded"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "PAPER_EXPORT_REGENERATION_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_paper_export_regeneration.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "byte-stable CSV/TeX/PNG exports"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "conda run --no-capture-output -n testtorch python"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "ABLATION_AND_SENSITIVITY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_ablation_sensitivity.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "epsilon-sensitivity source rows"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "REVIEWER_QUICKSTART.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_reviewer_quickstart.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "ARTIFACT_EVALUATION_GUIDE.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_artifact_evaluation_guide.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "venue-neutral artifact-evaluation evidence matrix"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "WORKSPACE_HYGIENE_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_workspace_hygiene.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "non-submission root artifacts"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "excluded_manifest_paths_checked=9"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "TEX_SOURCE_PORTABILITY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_tex_source_portability.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "local source closure"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "formal-PDF source inputs"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "FORMAL_PDF_BUILD_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/build_submission_pdf.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_formal_pdf_build_readiness.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "catad_submission_latex_updated.pdf"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "SKIPPED_NO_TEX_TOOL"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "latexmk"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tectonic"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "pdflatex"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "ATTACK_EVALUATION_SANITY_CHECKLIST.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "ADAPTIVE_ATTACK_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_attack_evaluation_sanity.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "ATTACK_STRENGTH_CONFIGURATION_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_attack_strength_configuration.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "PGD step-size coverage"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_method_implementation_traceability.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "anomalous-only adversarial CE"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "output-level KL consistency"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "representation MSE consistency"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "STATISTICAL_INTERPRETATION_CHECKLIST.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_statistical_interpretation.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "DUAL_USE_SAFETY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_dual_use_safety.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "no operational injection guidance"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_failure_mode_negative_results.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "CAT-AD w/o Delta X"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "non-primary PVR boundary"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "DOUBLE_BLIND_REVIEW_CHECKLIST.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_double_blind_submission.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "construct, internal, external, and artifact-validity threats"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "README.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "README_REVIEW_ENTRY_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_readme_review_entry.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "readme_markers_checked=44"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "LICENSE"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "CITATION.cff"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "ARTIFACT_LICENSE_AND_CITATION_AUDIT.md"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "tools/verify_artifact_license_citation.ps1"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "artifact_license_citation=PASSED"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "warning-free Pandoc log"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $audit "full-page rendering"

$paper = Get-Content -Raw -LiteralPath (Require-File "paper_lncs\main.tex")
Assert-Contains "paper_lncs/main.tex" $paper "\section{Threats to Validity}"
Assert-Contains "paper_lncs/main.tex" $paper "Construct validity"
Assert-Contains "paper_lncs/main.tex" $paper "Internal validity"
Assert-Contains "paper_lncs/main.tex" $paper "External validity"
Assert-Contains "paper_lncs/main.tex" $paper "Artifact validity"

Write-Output "completion_audit=PASSED"
Write-Output "requirements_checked=$($requirements.Count)"
Write-Output "evidence_files_checked=$($requiredEvidenceFiles.Count)"
Write-Output "limits_checked=2"

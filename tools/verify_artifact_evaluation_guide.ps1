$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing artifact-evaluation-guide artifact: $Path"
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

$guidePath = Require-File "ARTIFACT_EVALUATION_GUIDE.md"
$quickstartPath = Require-File "REVIEWER_QUICKSTART.md"
$checklistPath = Require-File "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md"
$completionPath = Require-File "SUBMISSION_COMPLETION_AUDIT.md"
$bundlePath = Join-Path $RepoRoot "output\submission\catad_topconf_submission_bundle.zip"

$requiredFiles = @(
    "check_submission_ready.ps1",
    "tools\verify_submission_bundle.ps1",
    "tools\verify_readme_review_entry.ps1",
    "tools\verify_artifact_license_citation.ps1",
    "tools\verify_dataset_profile.ps1",
    "tools\verify_external_validity_scope.ps1",
    "tools\verify_compute_resource_audit.ps1",
    "tools\verify_numeric_claims.ps1",
    "tools\verify_manuscript_claim_traceability.ps1",
    "tools\verify_claim_hierarchy.ps1",
    "tools\verify_seed_direction_consistency.ps1",
    "tools\verify_physical_metric_semantics.ps1",
    "tools\verify_recent_prior_art_challenge.ps1",
    "tools\verify_manuscript_reviewability.ps1",
    "tools\verify_rendered_pdf_content.ps1",
    "tools\verify_attack_evaluation_sanity.ps1",
    "tools\verify_attack_strength_configuration.ps1",
    "tools\verify_method_implementation_traceability.ps1",
    "tools\verify_baseline_competitiveness.ps1",
    "tools\verify_dual_use_safety.ps1",
    "tools\verify_baseline_fairness.ps1",
    "tools\verify_threshold_hyperparameter_audit.ps1",
    "tools\verify_failure_mode_negative_results.ps1",
    "tools\verify_paper_artifact_provenance.ps1",
    "tools\verify_figure_source_consistency.ps1",
    "tools\verify_paper_export_regeneration.ps1",
    "tools\verify_workspace_hygiene.ps1",
    "tools\verify_tex_source_portability.ps1",
    "tools\build_submission_pdf.ps1",
    "tools\verify_formal_pdf_build_readiness.ps1",
    "tools\verify_preview_artifact.ps1",
    "outputs\publication_benchmark\verification_report.md",
    "LICENSE",
    "CITATION.cff",
    "README.md",
    "README_REVIEW_ENTRY_AUDIT.md",
    "ARTIFACT_LICENSE_AND_CITATION_AUDIT.md",
    "DATA_PROVENANCE_AND_ETHICS.md",
    "DUAL_USE_SAFETY_AUDIT.md",
    "DATASET_PROFILE_AUDIT.md",
    "EXTERNAL_VALIDITY_SCOPE_AUDIT.md",
    "COMPUTE_RESOURCE_AUDIT.md",
    "ATTACK_STRENGTH_CONFIGURATION_AUDIT.md",
    "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md",
    "BASELINE_COMPETITIVENESS_AUDIT.md",
    "FIGURE_SOURCE_CONSISTENCY_AUDIT.md",
    "PAPER_EXPORT_REGENERATION_AUDIT.md",
    "WORKSPACE_HYGIENE_AUDIT.md",
    "TEX_SOURCE_PORTABILITY_AUDIT.md",
    "FORMAL_PDF_BUILD_AUDIT.md",
    "BASELINE_FAIRNESS_AUDIT.md",
    "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md",
    "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md",
    "CLAIM_HIERARCHY_AUDIT.md",
    "SEED_DIRECTION_CONSISTENCY_AUDIT.md",
    "PHYSICAL_METRIC_SEMANTICS_AUDIT.md",
    "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "MANUSCRIPT_REVIEWABILITY_AUDIT.md",
    "RENDERED_PDF_CONTENT_AUDIT.md",
    "output\pdf\catad_submission_preview.pdf"
)
foreach ($path in $requiredFiles) {
    Require-File $path | Out-Null
}

$guide = Get-Content -Raw -Encoding UTF8 -LiteralPath $guidePath
$guideMarkers = @(
    "Badge-Readiness Boundary",
    "Required Local Environment",
    "Fast Evaluation Path",
    "Deep Evaluation Matrix",
    "What The Artifact Does Not Prove",
    "Evaluation Summary",
    "does not claim that any official badge",
    "Official artifact badges",
    "conda run -n testtorch python",
    "check_submission_ready.ps1 -NoDownload",
    "verify_submission_bundle.ps1",
    "verify_readme_review_entry.ps1",
    "verify_artifact_license_citation.ps1",
    "verify_dataset_profile.ps1",
    "verify_external_validity_scope.ps1",
    "verify_compute_resource_audit.ps1",
    "verify_numeric_claims.ps1",
    "verify_manuscript_claim_traceability.ps1",
    "verify_claim_hierarchy.ps1",
    "verify_seed_direction_consistency.ps1",
    "verify_physical_metric_semantics.ps1",
    "verify_recent_prior_art_challenge.ps1",
    "verify_manuscript_reviewability.ps1",
    "verify_rendered_pdf_content.ps1",
    "verify_attack_evaluation_sanity.ps1",
    "verify_attack_strength_configuration.ps1",
    "verify_method_implementation_traceability.ps1",
    "verify_baseline_competitiveness.ps1",
    "verify_dual_use_safety.ps1",
    "verify_baseline_fairness.ps1",
    "verify_threshold_hyperparameter_audit.ps1",
    "verify_failure_mode_negative_results.ps1",
    "verify_paper_artifact_provenance.ps1",
    "verify_figure_source_consistency.ps1",
    "verify_paper_export_regeneration.ps1",
    "verify_workspace_hygiene.ps1",
    "verify_tex_source_portability.ps1",
    "verify_formal_pdf_build_readiness.ps1",
    "verify_preview_artifact.ps1",
    "formal-PDF source inputs",
    "formal_pdf_build_readiness=PASSED",
    "formal_pdf_build=SKIPPED_NO_TEX_TOOL",
    "readme_review_entry=PASSED",
    "artifact_license_citation=PASSED",
    "figure_source_consistency=PASSED",
    "paper_export_regeneration=PASSED",
    "workspace_hygiene=PASSED",
    "recent_prior_art_challenge=PASSED",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "coverage_rows_checked=25",
    "full_prior_art_rows=0",
    "manuscript_reviewability=PASSED",
    "rendered_pdf_content=PASSED",
    "method_implementation_traceability=PASSED",
    "baseline_competitiveness=PASSED",
    "compute_resource_audit=PASSED",
    "external_validity_scope=PASSED",
    "claim_hierarchy=PASSED",
    "seed_direction_consistency=PASSED",
    "physical_metric_semantics=PASSED",
    "tex_source_portability=PASSED",
    "dual-use safety",
    "does not prove top-conference acceptance",
    "formal_pdf_build=SKIPPED_NO_TEX_TOOL"
)
foreach ($marker in $guideMarkers) {
    Assert-Contains "ARTIFACT_EVALUATION_GUIDE.md" $guide $marker
}

$quickstart = Get-Content -Raw -Encoding UTF8 -LiteralPath $quickstartPath
Assert-Contains "REVIEWER_QUICKSTART.md" $quickstart "shortest path"
Assert-Contains "REVIEWER_QUICKSTART.md" $quickstart "status=PASSED"
Assert-Contains "REVIEWER_QUICKSTART.md" $quickstart "readme_review_entry=PASSED"
Assert-Contains "REVIEWER_QUICKSTART.md" $quickstart "artifact_license_citation=PASSED"

$checklist = Get-Content -Raw -Encoding UTF8 -LiteralPath $checklistPath
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify README Review Entry"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Artifact License and Citation"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Artifact Evaluation Guide"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify TeX Source Portability"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Formal PDF Build Readiness"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Figure Source Consistency"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "paper_export_regeneration=PASSED"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Workspace Hygiene"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Recent Prior-Art Challenge"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "coverage_rows_checked=25"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "full_prior_art_rows=0"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Manuscript Reviewability"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Rendered PDF Content"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Attack Strength Configuration"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Method Implementation Traceability"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Baseline Competitiveness"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Dataset Profile"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify External Validity Scope"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Manuscript Claim Traceability"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Claim Hierarchy"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Seed-Direction Consistency"
Assert-Contains "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md" $checklist "Verify Physical Metric Semantics"

$completion = Get-Content -Raw -Encoding UTF8 -LiteralPath $completionPath
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Top-conference acceptance"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Root README reviewer entry is available"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Anonymous review license and citation boundary is available"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "TeX source portability is checked"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Formal LaTeX PDF build and log quality are verified"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Figure sources are fresh and consistent"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Paper exports are regenerable"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Workspace hygiene and non-submission artifacts are bounded"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Recent prior-art challenges are incorporated"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "full_prior_art_rows=0"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Rendered PDF content is checked"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Attack strength configuration is fixed and audited"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Method-to-implementation traceability is checked"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Baseline competitiveness is visible"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Compute and runtime profile is checked"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "External validity scope is bounded"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Primary and auxiliary claims are separated"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Primary claim directions are seed-consistent"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Physical metric semantics are fixed"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Dual-use safety boundary is explicit"
Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion "Not locally provable"

if (Test-Path -LiteralPath $bundlePath -PathType Leaf) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $bundlePath))
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName.Replace("\", "/") })
        if ($entries.Count -lt 180) {
            throw "Submission bundle entry count is unexpectedly small: $($entries.Count)"
        }
    }
    finally {
        $zip.Dispose()
    }
}

Write-Output "artifact_evaluation_guide=PASSED"
Write-Output "guide_markers_checked=$($guideMarkers.Count)"
Write-Output "required_files_checked=$($requiredFiles.Count)"

param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing README review-entry artifact: $Path"
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
        throw "$Name missing README review-entry marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden README review-entry claim: $Needle"
    }
}

$readmePath = Require-File "README.md"
$auditPath = Require-File "README_REVIEW_ENTRY_AUDIT.md"
$readme = Get-Content -Raw -Encoding UTF8 -LiteralPath $readmePath
$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath

$requiredEntryFiles = @(
    "check_submission_ready.ps1",
    "paper_lncs\main.tex",
    "output\pdf\catad_submission_preview.pdf",
    "REVIEWER_QUICKSTART.md",
    "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md",
    "ARTIFACT_EVALUATION_GUIDE.md",
    "SUBMISSION_COMPLETION_AUDIT.md",
    "TOP_CONFERENCE_READINESS_AUDIT.md",
    "FORMAL_PDF_BUILD_AUDIT.md",
    "BASELINE_COMPETITIVENESS_AUDIT.md",
    "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md",
    "COMPUTE_RESOURCE_AUDIT.md",
    "EXTERNAL_VALIDITY_SCOPE_AUDIT.md",
    "CLAIM_HIERARCHY_AUDIT.md",
    "SEED_DIRECTION_CONSISTENCY_AUDIT.md",
    "PHYSICAL_METRIC_SEMANTICS_AUDIT.md",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "RENDERED_PDF_CONTENT_AUDIT.md",
    "tools\verify_method_implementation_traceability.ps1",
    "tools\verify_compute_resource_audit.ps1",
    "tools\verify_external_validity_scope.ps1",
    "tools\verify_claim_hierarchy.ps1",
    "tools\verify_seed_direction_consistency.ps1",
    "tools\verify_physical_metric_semantics.ps1",
    "tools\verify_rendered_pdf_content.ps1",
    "tools\build_submission_pdf.ps1"
)
foreach ($path in $requiredEntryFiles) {
    Require-File $path | Out-Null
}
$repoBundle = Join-Path $RepoRoot "output\submission\catad_topconf_submission_bundle.zip"
$bundleManifest = Join-Path $RepoRoot "BUNDLE_MANIFEST.tsv"
if ((Test-Path -LiteralPath $repoBundle -PathType Leaf)) {
    $bundleEvidence = "repo_zip"
}
elseif ((Test-Path -LiteralPath $bundleManifest -PathType Leaf)) {
    $bundleEvidence = "extracted_manifest"
}
else {
    throw "Missing README review-entry bundle evidence: output\submission\catad_topconf_submission_bundle.zip or BUNDLE_MANIFEST.tsv"
}

$readmeMarkers = @(
    "CAT-AD Anonymous Review Artifact",
    "targeted anomalous-to-normal evasion",
    "check_submission_ready.ps1 -NoDownload",
    "BuildPreviewPdf",
    "BuildSubmissionBundle",
    "VERIFY PASSED",
    "numeric_claims=PASSED",
    "seed_direction_consistency=PASSED",
    "recent_prior_art_challenge=PASSED",
    "workspace_hygiene=PASSED",
    "manuscript_reviewability=PASSED",
    "preview_artifact=PASSED",
    "anonymized_bundle=PASSED",
    "double_blind_submission=PASSED",
    "status=PASSED",
    "paper_lncs/main.tex",
    "output/pdf/catad_submission_preview.pdf",
    "tools/build_submission_pdf.ps1",
    "output/submission/catad_topconf_submission_bundle.zip",
    "REVIEWER_QUICKSTART.md",
    "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md",
    "ARTIFACT_EVALUATION_GUIDE.md",
    "BASELINE_COMPETITIVENESS_AUDIT.md",
    "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md",
    "COMPUTE_RESOURCE_AUDIT.md",
    "EXTERNAL_VALIDITY_SCOPE_AUDIT.md",
    "CLAIM_HIERARCHY_AUDIT.md",
    "SEED_DIRECTION_CONSISTENCY_AUDIT.md",
    "PHYSICAL_METRIC_SEMANTICS_AUDIT.md",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "RENDERED_PDF_CONTENT_AUDIT.md",
    "SUBMISSION_COMPLETION_AUDIT.md",
    "TOP_CONFERENCE_READINESS_AUDIT.md",
    "conda run -n testtorch python",
    "tools/verify_baseline_competitiveness.ps1",
    "tools/verify_method_implementation_traceability.ps1",
    "tools/verify_compute_resource_audit.ps1",
    "tools/verify_external_validity_scope.ps1",
    "tools/verify_claim_hierarchy.ps1",
    "tools/verify_seed_direction_consistency.ps1",
    "tools/verify_physical_metric_semantics.ps1",
    "tools/verify_rendered_pdf_content.ps1",
    "formal_pdf_build=SKIPPED_NO_TEX_TOOL",
    "cannot prove top-conference acceptance"
)
foreach ($marker in $readmeMarkers) {
    Assert-Contains "README.md" $readme $marker
}

foreach ($marker in @(
    "Root README exists",
    "One-command no-download audit is visible",
    "Rebuild command is visible",
    "Required conda environment is visible",
    "External limits are visible",
    "readme_review_entry=PASSED"
)) {
    Assert-Contains "README_REVIEW_ENTRY_AUDIT.md" $audit $marker
}

$forbiddenClaims = @(
    "guaranteed acceptance",
    "guarantees top-conference acceptance",
    "accepted at",
    "camera-ready",
    "official artifact badge granted",
    "certified safe",
    "robust against all attacks",
    "first ever"
)
foreach ($claim in $forbiddenClaims) {
    Assert-NotContains "README.md" $readme $claim
}

Write-Output "readme_review_entry=PASSED"
Write-Output "readme_markers_checked=$($readmeMarkers.Count)"
Write-Output "entry_files_checked=$($requiredEntryFiles.Count)"
Write-Output "bundle_evidence=$bundleEvidence"
Write-Output "forbidden_claims_checked=$($forbiddenClaims.Count)"

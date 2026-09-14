param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing reviewer quickstart artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing reviewer quickstart marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden reviewer quickstart marker: $Needle"
    }
}

$quickstartPath = "REVIEWER_QUICKSTART.md"
Require-File $quickstartPath
$quickstart = Get-Content -Raw -Encoding UTF8 -LiteralPath $quickstartPath

$requiredMarkers = @(
    "One-Command Audit",
    ".\check_submission_ready.ps1 -NoDownload",
    "OK no-download workflow scripts contain no installer/download commands",
    "VERIFY PASSED",
    "Ran 16 tests",
    "readme_review_entry=PASSED",
    "artifact_license_citation=PASSED",
    "numeric_claims=PASSED",
    "attack_evaluation_sanity=PASSED",
    "attack_strength_configuration=PASSED",
    "method_implementation_traceability=PASSED",
    "claim_hierarchy=PASSED",
    "seed_direction_consistency=PASSED",
    "physical_metric_semantics=PASSED",
    "baseline_competitiveness=PASSED",
    "statistical_interpretation=PASSED",
    "data_provenance_ethics=PASSED",
    "dual_use_safety=PASSED",
    "external_validity_scope=PASSED",
    "environment_reproducibility=PASSED",
    "compute_resource_audit=PASSED",
    "formal_pdf_build_readiness=PASSED",
    "paper_artifact_provenance=PASSED",
    "recent_prior_art_challenge=PASSED",
    "coverage_rows_checked=25",
    "full_prior_art_rows=0",
    "workspace_hygiene=PASSED",
    "manuscript_reviewability=PASSED",
    "completion_audit=PASSED",
    "preview_artifact=PASSED",
    "rendered_pdf_content=PASSED",
    "pandoc_log_warnings=0",
    "anonymized_bundle=PASSED",
    "double_blind_submission=PASSED",
    "status=PASSED",
    "conda run -n testtorch python -m adsb.run",
    "tools\verify_submission_bundle.ps1",
    "tools/verify_readme_review_entry.ps1",
    "tools/verify_artifact_license_citation.ps1",
    "tools/verify_environment_reproducibility.ps1",
    "tools/verify_external_validity_scope.ps1",
    "EXTERNAL_VALIDITY_SCOPE_AUDIT.md",
    "tools/verify_claim_hierarchy.ps1",
    "CLAIM_HIERARCHY_AUDIT.md",
    "tools/verify_seed_direction_consistency.ps1",
    "SEED_DIRECTION_CONSISTENCY_AUDIT.md",
    "tools/verify_physical_metric_semantics.ps1",
    "PHYSICAL_METRIC_SEMANTICS_AUDIT.md",
    "tools/verify_compute_resource_audit.ps1",
    "tools/verify_recent_prior_art_challenge.ps1",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "tools/verify_attack_strength_configuration.ps1",
    "tools/verify_method_implementation_traceability.ps1",
    "tools/verify_baseline_competitiveness.ps1",
    "tools/verify_dual_use_safety.ps1",
    "tools/verify_formal_pdf_build_readiness.ps1",
    "tools/verify_workspace_hygiene.ps1",
    "tools/verify_manuscript_reviewability.ps1",
    "tools/verify_rendered_pdf_content.ps1",
    "RENDERED_PDF_CONTENT_AUDIT.md",
    "Data Boundary",
    "External Limits",
    "formal_pdf_build=SKIPPED_NO_TEX_TOOL",
    "cannot guarantee top-conference acceptance"
)
foreach ($marker in $requiredMarkers) {
    Assert-Contains $quickstartPath $quickstart $marker
}

foreach ($needle in @(
    ("pip " + "install"),
    ("pip3 " + "install"),
    ("uv " + "pip " + "install"),
    ("conda " + "install"),
    ("conda " + "create"),
    ("conda " + "env " + "create"),
    ("mamba " + "install"),
    ("micromamba " + "install"),
    ("Invoke-" + "WebRequest"),
    ("Invoke-" + "RestMethod"),
    ("Start-" + "BitsTransfer"),
    ("w" + "get"),
    ("curl" + " "),
    ("curl" + ".exe"),
    ("winget " + "install"),
    ("Download" + "File"),
    "guaranteed acceptance",
    "guarantees top-conference acceptance"
)) {
    Assert-NotContains $quickstartPath $quickstart $needle
}

Write-Output "reviewer_quickstart=PASSED"
Write-Output "quickstart_markers_checked=$($requiredMarkers.Count)"

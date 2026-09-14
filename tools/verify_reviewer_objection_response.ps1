param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing reviewer-objection-response artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing reviewer-objection-response marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains unsupported reviewer-objection-response claim: $Needle"
    }
}

$auditPath = "REVIEWER_OBJECTION_RESPONSE_AUDIT.md"
$topPath = "TOP_CONFERENCE_READINESS_AUDIT.md"
$completionPath = "SUBMISSION_COMPLETION_AUDIT.md"
$quickstartPath = "REVIEWER_QUICKSTART.md"
$guidePath = "ARTIFACT_EVALUATION_GUIDE.md"
$coveragePath = "PRIOR_ART_CRITERIA_COVERAGE.tsv"
$seedSummaryPath = "outputs\publication_benchmark\primary_seed_direction_summary.csv"

foreach ($path in @($auditPath, $topPath, $completionPath, $quickstartPath, $guidePath, $coveragePath, $seedSummaryPath)) {
    Require-File $path
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$top = Get-Content -Raw -Encoding UTF8 -LiteralPath $topPath
$completion = Get-Content -Raw -Encoding UTF8 -LiteralPath $completionPath
$quickstart = Get-Content -Raw -Encoding UTF8 -LiteralPath $quickstartPath
$guide = Get-Content -Raw -Encoding UTF8 -LiteralPath $guidePath

foreach ($marker in @(
    "CAT-AD Reviewer Objection Response Audit",
    "Response Matrix",
    "One-Command Verification",
    "Non-Rebuttals",
    "does not prove top-conference acceptance",
    "does not certify robustness against all adaptive attackers",
    "does not make single-seed auxiliary ablations into primary claims"
)) {
    Assert-Contains $auditPath $audit $marker
}

$objections = @(
    "O1",
    "O2",
    "O3",
    "O4",
    "O5",
    "O6",
    "O7",
    "O8",
    "O9",
    "O10",
    "O11",
    "O12"
)
foreach ($id in $objections) {
    Assert-Contains $auditPath $audit "| $id |"
}

$evidencePaths = @(
    "INNOVATION_AND_EVIDENCE.md",
    "PRIOR_ART_NOVELTY_MATRIX.md",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "PRIOR_ART_EVIDENCE_SNAPSHOT.md",
    "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md",
    "paper_lncs/main.tex",
    "paper_lncs/references.bib",
    "BASELINE_FAIRNESS_AUDIT.md",
    "BASELINE_COMPETITIVENESS_AUDIT.md",
    "outputs/tables/table5_ablation_study.csv",
    "CLAIM_HIERARCHY_AUDIT.md",
    "ABLATION_AND_SENSITIVITY_AUDIT.md",
    "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md",
    "results/fig_epsilon_sensitivity_data.csv",
    "STATISTICAL_INTERPRETATION_CHECKLIST.md",
    "outputs/publication_benchmark/paired_comparisons.csv",
    "SEED_DIRECTION_CONSISTENCY_AUDIT.md",
    "outputs/publication_benchmark/primary_seed_direction_summary.csv",
    "outputs/publication_benchmark/per_seed_metrics_wide.csv",
    "PHYSICAL_METRIC_SEMANTICS_AUDIT.md",
    "tests/test_physical_metrics.py",
    "adsb/training.py",
    "ATTACK_EVALUATION_SANITY_CHECKLIST.md",
    "ADAPTIVE_ATTACK_AUDIT.md",
    "ATTACK_STRENGTH_CONFIGURATION_AUDIT.md",
    "DATA_PROVENANCE_AND_ETHICS.md",
    "THRESHOLD_AND_HYPERPARAMETER_AUDIT.md",
    "outputs/publication_benchmark/preflight_report.json",
    "outputs/publication_benchmark/data_split_audit.tex",
    "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md",
    "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md",
    "PAPER_ARTIFACT_PROVENANCE.md",
    "CODE_PROVENANCE_DRIFT_AUDIT.md",
    "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md",
    "WORKSPACE_HYGIENE_AUDIT.md",
    "DOUBLE_BLIND_REVIEW_CHECKLIST.md",
    "output/submission/catad_topconf_submission_bundle.zip",
    "FORMAL_PDF_BUILD_AUDIT.md",
    "TEX_SOURCE_PORTABILITY_AUDIT.md",
    "output/pdf/catad_submission_latex_updated.pdf",
    "SUBMISSION_COMPLETION_AUDIT.md",
    "REVIEWER_OBJECTION_RESPONSE_AUDIT.md"
)
foreach ($path in $evidencePaths) {
    $filePath = $path.Replace("/", "\")
    if ($path -eq "output/submission/catad_topconf_submission_bundle.zip") {
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf) -and -not (Test-Path -LiteralPath "BUNDLE_MANIFEST.tsv" -PathType Leaf)) {
            throw "Missing reviewer-objection-response bundle evidence: output/submission/catad_topconf_submission_bundle.zip or BUNDLE_MANIFEST.tsv"
        }
    }
    else {
        Require-File $filePath
    }
    Assert-Contains $auditPath $audit $path
}

$verifierPaths = @(
    "tools/verify_novelty_evidence.ps1",
    "tools/verify_recent_prior_art_challenge.ps1",
    "tools/verify_baseline_fairness.ps1",
    "tools/verify_baseline_competitiveness.ps1",
    "tools/verify_claim_hierarchy.ps1",
    "tools/verify_ablation_sensitivity.ps1",
    "tools/verify_failure_mode_negative_results.ps1",
    "tools/verify_statistical_interpretation.ps1",
    "tools/verify_seed_direction_consistency.ps1",
    "tools/verify_physical_metric_semantics.ps1",
    "tools/verify_attack_evaluation_sanity.ps1",
    "tools/verify_attack_strength_configuration.ps1",
    "tools/verify_data_provenance_ethics.ps1",
    "tools/verify_threshold_hyperparameter_audit.ps1",
    "tools/verify_method_implementation_traceability.ps1",
    "tools/verify_manuscript_claim_traceability.ps1",
    "tools/verify_paper_artifact_provenance.ps1",
    "tools/verify_code_provenance_drift.ps1",
    "tools/verify_paper_export_regeneration.ps1",
    "tools/verify_submission_bundle.ps1",
    "tools/verify_workspace_hygiene.ps1",
    "tools/verify_anonymized_bundle.ps1",
    "tools/verify_double_blind_submission.ps1",
    "tools/verify_formal_pdf_build_readiness.ps1",
    "tools/verify_tex_source_portability.ps1",
    "tools/verify_rendered_pdf_content.ps1",
    "tools/verify_completion_audit.ps1",
    "tools/verify_reviewer_objection_response.ps1"
)
foreach ($path in $verifierPaths) {
    Require-File ($path.Replace("/", "\"))
    Assert-Contains $auditPath $audit $path
}

$expectedOutputs = @(
    "novelty_evidence=PASSED",
    "coverage_rows_checked=25",
    "citation_keys_checked=24",
    "full_prior_art_rows=0",
    "recent_prior_art_challenge=PASSED",
    "recent_sources_checked=12",
    "paper_citations_checked=12",
    "criteria_checked=6",
    "baseline_fairness=PASSED",
    "baseline_competitiveness=PASSED",
    "strong_training_baselines_checked=3",
    "claim_hierarchy=PASSED",
    "ablation_sensitivity=PASSED",
    "failure_mode_negative_results=PASSED",
    "statistical_interpretation=PASSED",
    "paired_rows_checked=12",
    "effect_size_rows_checked=12",
    "seed_pairs_checked=30",
    "summary_csv_rows_checked=6",
    "minimum_seed_improvement=0.0033259423503325942",
    "physical_metric_semantics=PASSED",
    "metric_rows_checked=42",
    "pv_asr_bounds_checked=78",
    "attack_evaluation_sanity=PASSED",
    "attack_strength_configuration=PASSED",
    "paired_attack_rows_checked=3",
    "epsilon_rows_checked=24",
    "aircraft_overlap_violations=0",
    "threshold_hyperparameter_audit=PASSED",
    "method_implementation_traceability=PASSED",
    "manuscript_claim_traceability=PASSED",
    "paper_artifact_provenance=PASSED",
    "code_provenance_drift=PASSED",
    "paper_export_regeneration=PASSED",
    "status=PASSED",
    "workspace_hygiene=PASSED",
    "anonymized_bundle=PASSED",
    "double_blind_submission=PASSED",
    "formal_pdf_build_readiness=PASSED",
    "formal_pdf_build=PASSED",
    "tex_source_portability=PASSED",
    "rendered_pdf_content=PASSED",
    "formal_pages_checked=18",
    "completion_audit=PASSED",
    "reviewer_objection_response=PASSED",
    "objections_checked=12",
    "evidence_paths_checked=42",
    "verifier_outputs_checked=49",
    "primary_seed_rows_checked=6"
)
foreach ($marker in $expectedOutputs) {
    Assert-Contains $auditPath $audit $marker
}

foreach ($marker in @(
    "zhao2026imdmpc",
    "zhong2026rdpaadsb",
    "luo2024adversarialadsb",
    "C1-C6",
    "single-seed",
    "all adaptive attackers",
    "testtorch"
)) {
    Assert-Contains $auditPath $audit $marker
}

$coverageRows = @(Import-Csv -Delimiter "`t" -LiteralPath $coveragePath)
if ($coverageRows.Count -ne 25) {
    throw "Expected 25 prior-art coverage rows; found $($coverageRows.Count)"
}
$zhaoRows = @($coverageRows | Where-Object { $_.source_key -eq "zhao2026imdmpc" })
if ($zhaoRows.Count -ne 1) {
    throw "Expected exactly one zhao2026imdmpc prior-art row; found $($zhaoRows.Count)"
}
$fullPriorRows = @(
    $coverageRows | Where-Object {
        $_.source_key -ne "catad_repository" -and
        $_.C1.ToLowerInvariant() -eq "yes" -and
        $_.C2.ToLowerInvariant() -eq "yes" -and
        $_.C3.ToLowerInvariant() -eq "yes" -and
        $_.C4.ToLowerInvariant() -eq "yes" -and
        $_.C5.ToLowerInvariant() -eq "yes" -and
        $_.C6.ToLowerInvariant() -eq "yes"
    }
)
if ($fullPriorRows.Count -ne 0) {
    throw "Prior-art row fully subsumes CAT-AD C1-C6: $($fullPriorRows[0].source_key)"
}

$seedRows = @(Import-Csv -LiteralPath $seedSummaryPath)
if ($seedRows.Count -ne 6) {
    throw "Expected six primary seed-direction rows; found $($seedRows.Count)"
}
foreach ($row in $seedRows) {
    if ([int]$row.seed_count -ne 5 -or [int]$row.positive_seed_count -ne 5) {
        throw "Primary seed-direction row is not 5/5 positive: $($row.claim)"
    }
}

foreach ($marker in @(
    "REVIEWER_OBJECTION_RESPONSE_AUDIT.md",
    "tools/verify_reviewer_objection_response.ps1",
    "reviewer-objection response"
)) {
    Assert-Contains "TOP_CONFERENCE_READINESS_AUDIT.md" $top $marker
    Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion $marker
}
Assert-Contains "REVIEWER_QUICKSTART.md" $quickstart "REVIEWER_OBJECTION_RESPONSE_AUDIT.md"
Assert-Contains "ARTIFACT_EVALUATION_GUIDE.md" $guide "REVIEWER_OBJECTION_RESPONSE_AUDIT.md"

foreach ($needle in @(
    "guaranteed acceptance",
    "guarantees top-conference acceptance",
    "proves acceptance",
    "proves global novelty",
    "certified robust against all attacks",
    "solves ADS-B security"
)) {
    Assert-NotContains $auditPath $audit $needle
}

Write-Output "reviewer_objection_response=PASSED"
Write-Output "objections_checked=$($objections.Count)"
Write-Output "evidence_paths_checked=$($evidencePaths.Count)"
Write-Output "verifier_paths_checked=$($verifierPaths.Count)"
Write-Output "verifier_outputs_checked=$($expectedOutputs.Count)"
Write-Output "coverage_rows_checked=$($coverageRows.Count)"
Write-Output "primary_seed_rows_checked=$($seedRows.Count)"
Write-Output "full_prior_art_rows=0"

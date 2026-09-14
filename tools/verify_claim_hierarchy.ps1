$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing claim-hierarchy artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing claim-hierarchy marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden claim-hierarchy phrase: $Needle"
    }
}

$auditPath = "CLAIM_HIERARCHY_AUDIT.md"
$paperPath = "paper_lncs\main.tex"
$ledgerPath = "NUMERIC_CLAIMS_LEDGER.md"
$pairedPath = "outputs\publication_benchmark\paired_comparisons.csv"
$verificationPath = "outputs\publication_benchmark\verification_report.md"
$ablationAuditPath = "ABLATION_AND_SENSITIVITY_AUDIT.md"
$failureAuditPath = "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md"
$baselineAuditPath = "BASELINE_COMPETITIVENESS_AUDIT.md"
$traceabilityPath = "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md"

foreach ($path in @(
    $auditPath,
    $paperPath,
    $ledgerPath,
    $pairedPath,
    $verificationPath,
    $ablationAuditPath,
    $failureAuditPath,
    $baselineAuditPath,
    $traceabilityPath,
    "outputs/tables/table5_ablation_study.csv",
    "results/fig_epsilon_sensitivity_data.csv"
)) {
    Require-File $path
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$ledger = Get-Content -Raw -Encoding UTF8 -LiteralPath $ledgerPath
$verification = Get-Content -Raw -Encoding UTF8 -LiteralPath $verificationPath
$ablationAudit = Get-Content -Raw -Encoding UTF8 -LiteralPath $ablationAuditPath
$failureAudit = Get-Content -Raw -Encoding UTF8 -LiteralPath $failureAuditPath
$baselineAudit = Get-Content -Raw -Encoding UTF8 -LiteralPath $baselineAuditPath
$traceability = Get-Content -Raw -Encoding UTF8 -LiteralPath $traceabilityPath
$paired = @(Import-Csv -LiteralPath $pairedPath)
$ablationRows = @(Import-Csv -LiteralPath "outputs/tables/table5_ablation_study.csv")
$epsilonRows = @(Import-Csv -LiteralPath "results/fig_epsilon_sensitivity_data.csv")

foreach ($marker in @(
    "Primary Evidence",
    "Auxiliary Evidence",
    "NUMERIC_CLAIMS_LEDGER.md",
    "paired_comparisons.csv",
    '`42,43,44,45,46`',
    "ablation rows",
    "epsilon-sensitivity rows",
    "PVR rows"
)) {
    Assert-Contains $auditPath $audit $marker
}

$expectedClaims = @(
    [pscustomobject]@{ Setting = "Clean"; Metric = "f1" },
    [pscustomobject]@{ Setting = "Standard PGD"; Metric = "asr" },
    [pscustomobject]@{ Setting = "Projection-based phys-PGD"; Metric = "asr" },
    [pscustomobject]@{ Setting = "Penalty-based phys-PGD"; Metric = "asr" },
    [pscustomobject]@{ Setting = "Projection-based phys-PGD"; Metric = "conditional_pv_asr_start_valid" },
    [pscustomobject]@{ Setting = "Penalty-based phys-PGD"; Metric = "conditional_pv_asr_start_valid" }
)
foreach ($claim in $expectedClaims) {
    $rows = @($paired | Where-Object { $_.setting -eq $claim.Setting -and $_.metric -eq $claim.Metric })
    if ($rows.Count -ne 1) {
        throw "Missing primary paired row: $($claim.Setting) / $($claim.Metric)"
    }
    if ([int]$rows[0].n -ne 5 -or $rows[0].seeds -ne "42,43,44,45,46") {
        throw "Primary paired row is not five-seed archived evidence: $($claim.Setting) / $($claim.Metric)"
    }
    Assert-Contains "NUMERIC_CLAIMS_LEDGER.md" $ledger $claim.Setting
    Assert-Contains "NUMERIC_CLAIMS_LEDGER.md" $ledger $claim.Metric
}

$primarySection = [regex]::Match($ledger, "(?s)## Primary Claim Values.*?## Multi-Seed Table Values")
if (-not $primarySection.Success) {
    throw "Could not isolate NUMERIC_CLAIMS_LEDGER primary section"
}
if ([regex]::Matches($primarySection.Value, "\| .* \| .* \| .* \| .* \|").Count -lt 7) {
    throw "Primary claim table appears too small"
}
foreach ($nonPrimaryMetric in @("pvr", "FAR", "ablation", "epsilon")) {
    if ($primarySection.Value.IndexOf($nonPrimaryMetric, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Primary claim section contains non-primary metric/evidence: $nonPrimaryMetric"
    }
}

foreach ($marker in @(
    "Status: PASSED",
    "Seeds: 42,43,44,45,46",
    "Paired comparison rows: 14"
)) {
    Assert-Contains "verification_report.md" $verification $marker
}

$auxiliaryBoundaries = @(
    [pscustomobject]@{ Name = "Ablation"; Text = $ablationAudit; Marker = "auxiliary design evidence" },
    [pscustomobject]@{ Name = "Sensitivity"; Text = $traceability; Marker = "Perturbation-budget sensitivity is a bounded auxiliary result" },
    [pscustomobject]@{ Name = "PVR"; Text = $failureAudit; Marker = "PVR is reported as a diagnostic" },
    [pscustomobject]@{ Name = "Strong baselines"; Text = $baselineAudit; Marker = "auxiliary ablation table" }
)
foreach ($boundary in $auxiliaryBoundaries) {
    Assert-Contains $boundary.Name $boundary.Text $boundary.Marker
}
if ($ablationRows.Count -lt 8) {
    throw "Expected at least eight ablation rows; found $($ablationRows.Count)"
}
if ($epsilonRows.Count -ne 24) {
    throw "Expected 24 epsilon-sensitivity rows; found $($epsilonRows.Count)"
}

foreach ($marker in @(
    "primary robustness claims are tied to F1, ASR, and PV-ASR$\mid V_0$ under the evaluated attacks",
    "trade-off analysis rather than as a ranking",
    "single-seed auxiliary table",
    "does not claim that CAT-AD dominates every metric in the auxiliary ablation table",
    "Pre- and post-attack PVR should therefore be read as physical-validity diagnostics"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$forbidden = @(
    "ablation proves robustness",
    "ablation is the primary evidence",
    "sensitivity proves robustness",
    "epsilon sensitivity proves",
    "PVR is the primary improvement",
    "primary PVR improvement",
    "single-seed primary claim",
    "single seed proves",
    "therefore CAT-AD dominates every metric",
    "CAT-AD is best on every metric"
)
foreach ($needle in $forbidden) {
    Assert-NotContains "paper_lncs/main.tex" $paper $needle
    Assert-NotContains "CLAIM_HIERARCHY_AUDIT.md" $audit $needle
}

Write-Output "claim_hierarchy=PASSED"
Write-Output "primary_claims_checked=$($expectedClaims.Count)"
Write-Output "auxiliary_boundaries_checked=$($auxiliaryBoundaries.Count)"
Write-Output "forbidden_hierarchy_claims_checked=$($forbidden.Count)"

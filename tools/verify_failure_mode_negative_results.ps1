$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing failure-mode audit artifact: $Path"
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

function To-Double {
    param([string]$Value)
    return [double]::Parse(
        $Value,
        [System.Globalization.NumberStyles]::Float,
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function To-Bool {
    param([string]$Value)
    return [System.Convert]::ToBoolean($Value)
}

$auditPath = Require-File "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md"
$paperPath = Require-File "paper_lncs\main.tex"
$ablationPath = Require-File "outputs\tables\table5_ablation_study.csv"
$pairedPath = Require-File "outputs\publication_benchmark\paired_comparisons.csv"
$statPath = Require-File "STATISTICAL_INTERPRETATION_CHECKLIST.md"
$claimPath = Require-File "CLAIM_SCOPE_GUARDRAILS.md"
$readinessPath = Require-File "TOP_CONFERENCE_READINESS_AUDIT.md"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Non-Claim Boundary",
    "Negative Results That Must Stay Visible",
    "CAT-AD is not a formal robustness certificate",
    "Physical violation rate (PVR) is reported as a diagnostic",
    "CAT-AD w/o Delta X",
    "five-seed exact sign-flip p-values"
)) {
    Assert-Contains "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md" $audit $marker
}

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
foreach ($marker in @(
    "ASR alone can overestimate",
    "conditional PV-ASR",
    "Pre- and post-attack PVR should therefore be read as physical-validity diagnostics",
    "not be interpreted as a certificate",
    "Results may change for other airspaces",
    "exact sign-flip p-values are coarse",
    "low attack success is not a valid robustness gain"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$stat = Get-Content -Raw -Encoding UTF8 -LiteralPath $statPath
Assert-Contains "STATISTICAL_INTERPRETATION_CHECKLIST.md" $stat "effect sizes"
Assert-Contains "STATISTICAL_INTERPRETATION_CHECKLIST.md" $stat "confidence intervals"
Assert-Contains "STATISTICAL_INTERPRETATION_CHECKLIST.md" $stat "five seeds"

$claims = Get-Content -Raw -Encoding UTF8 -LiteralPath $claimPath
Assert-Contains "CLAIM_SCOPE_GUARDRAILS.md" $claims "not a certificate"
Assert-Contains "CLAIM_SCOPE_GUARDRAILS.md" $claims "evaluated threat model"

$readiness = Get-Content -Raw -Encoding UTF8 -LiteralPath $readinessPath
Assert-Contains "TOP_CONFERENCE_READINESS_AUDIT.md" $readiness "Failure modes and negative results"
Assert-Contains "TOP_CONFERENCE_READINESS_AUDIT.md" $readiness "PVR is reported as a diagnostic"

$ablation = @(Import-Csv -LiteralPath $ablationPath)
$failureRows = @($ablation | Where-Object { $_.Variant -like "CAT-AD w/o*" })
if ($failureRows.Count -ne 1) {
    throw "Expected one CAT-AD w/o Delta X ablation row, found $($failureRows.Count)"
}
$failure = $failureRows[0]
$failureCleanF1 = To-Double $failure.'Unperturbed F1'
$failureFar = To-Double $failure.FAR
$failurePenaltyPvAsr = To-Double $failure.'Penalty PV-ASR'
if ($failureCleanF1 -ge 0.50) {
    throw "CAT-AD w/o Delta X clean F1 is no longer a documented failure mode: $failureCleanF1"
}
if ($failureFar -le 0.90) {
    throw "CAT-AD w/o Delta X FAR is no longer the documented high-FAR failure mode: $failureFar"
}
if ($failurePenaltyPvAsr -gt 0.05) {
    throw "CAT-AD w/o Delta X no longer demonstrates the low-PV-ASR/high-FAR trap: $failurePenaltyPvAsr"
}

$paired = @(Import-Csv -LiteralPath $pairedPath)
if ($paired.Count -ne 14) {
    throw "Expected 14 paired-comparison rows, found $($paired.Count)"
}
$pvrRows = @($paired | Where-Object {
    $_.metric -eq "introduced_pvr_start_valid" -and
    ($_.setting -eq "Projection-based phys-PGD" -or $_.setting -eq "Penalty-based phys-PGD")
})
if ($pvrRows.Count -ne 2) {
    throw "Expected two physical-attack New-PVR paired rows, found $($pvrRows.Count)"
}
foreach ($row in $pvrRows) {
    $meanImprovement = To-Double $row.mean_improvement
    $holm = To-Bool $row.significant_holm_0_05
    $bh = To-Bool $row.significant_bh_fdr_0_05
    if ([Math]::Abs($meanImprovement) -gt 0.001) {
        throw "New-PVR row is no longer a negligible diagnostic: $($row.setting) mean_improvement=$meanImprovement"
    }
    if ($holm -or $bh) {
        throw "New-PVR row should not be significant improvement evidence: $($row.setting)"
    }
}

$significantRows = @($paired | Where-Object {
    (To-Bool $_.significant_holm_0_05) -or (To-Bool $_.significant_bh_fdr_0_05)
})
if ($significantRows.Count -ne 0) {
    throw "Five-seed paired table now contains significance flags; update the statistical boundary before claiming completion"
}

Write-Output "failure_mode_negative_results=PASSED"
Write-Output "failure_modes_checked=4"
Write-Output "nonclaimed_new_pvr_rows_checked=$($pvrRows.Count)"
Write-Output "paired_rows_checked=$($paired.Count)"

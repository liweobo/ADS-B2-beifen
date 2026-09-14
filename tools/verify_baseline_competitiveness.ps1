$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing baseline-competitiveness artifact: $Path"
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

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains unsupported baseline claim: $Needle"
    }
}

function Get-Row {
    param(
        [object[]]$Rows,
        [string]$Variant
    )
    $matches = @($Rows | Where-Object { $_.Variant -eq $Variant })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one ablation row for ${Variant}; found $($matches.Count)"
    }
    return $matches[0]
}

$auditPath = Require-File "BASELINE_COMPETITIVENESS_AUDIT.md"
$paperPath = Require-File "paper_lncs\main.tex"
$ablationAuditPath = Require-File "ABLATION_AND_SENSITIVITY_AUDIT.md"
$ablationCsvPath = Require-File "outputs\tables\table5_ablation_study.csv"
$ablationTexPath = Require-File "outputs\tables\table5_ablation_study.tex"
$summaryPath = Require-File "outputs\ablation_table5\ablation_table5_summary.json"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$ablationAudit = Get-Content -Raw -Encoding UTF8 -LiteralPath $ablationAuditPath
$ablationTex = Get-Content -Raw -Encoding UTF8 -LiteralPath $ablationTexPath
$summary = Get-Content -Raw -Encoding UTF8 -LiteralPath $summaryPath | ConvertFrom-Json

foreach ($marker in @(
    "Evidence Boundary",
    "stronger adversarial-training baselines",
    "PGD-AT",
    "Projection Phys-PGD-AT",
    "Penalty Phys-PGD-AT",
    "Interpretation Guardrail",
    "The defensible claim is not",
    "CAT-AD beats every baseline in every metric"
)) {
    Assert-Contains "BASELINE_COMPETITIVENESS_AUDIT.md" $audit $marker
}

foreach ($marker in @(
    "PGD-AT",
    "Projection Phys-PGD-AT",
    "Penalty Phys-PGD-AT",
    "trade-off analysis",
    "not intended to guarantee the best value on every individual metric",
    "strong adversarial-training baselines",
    "does not claim that CAT-AD dominates every metric"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

foreach ($marker in @(
    "Eight ablation variants",
    "PGD-AT",
    "projection Phys-PGD-AT",
    "penalty Phys-PGD-AT",
    "primary quantitative claims"
)) {
    Assert-Contains "ABLATION_AND_SENSITIVITY_AUDIT.md" $ablationAudit $marker
}

foreach ($marker in @(
    "PGD-AT",
    "Projection Phys-PGD-AT",
    "Penalty Phys-PGD-AT",
    "CAT-AD w/o"
)) {
    Assert-Contains "outputs/tables/table5_ablation_study.tex" $ablationTex $marker
}

$rows = @(Import-Csv -LiteralPath $ablationCsvPath)
$expectedVariants = @(
    "ERM",
    "PGD-AT",
    "Projection Phys-PGD-AT",
    "Penalty Phys-PGD-AT",
    "+Prediction Consistency",
    "+Feature Consistency",
    "CAT-AD",
    'CAT-AD w/o $\Delta X$'
)
if ($rows.Count -ne $expectedVariants.Count) {
    throw "Expected $($expectedVariants.Count) ablation rows; found $($rows.Count)"
}
foreach ($variant in $expectedVariants) {
    Get-Row $rows $variant | Out-Null
}

$strongBaselines = @(
    "PGD-AT",
    "Projection Phys-PGD-AT",
    "Penalty Phys-PGD-AT"
)
foreach ($variant in $strongBaselines) {
    $row = Get-Row $rows $variant
    if ([double]$row."Unperturbed F1" -lt 0.90) {
        throw "$variant has unexpectedly weak unperturbed F1: $($row.'Unperturbed F1')"
    }
    if ([double]$row."Projection F1" -lt 0.95) {
        throw "$variant has unexpectedly weak projection-attack F1: $($row.'Projection F1')"
    }
    if ([double]$row."Penalty F1" -lt 0.95) {
        throw "$variant has unexpectedly weak penalty-attack F1: $($row.'Penalty F1')"
    }
}

$pgd = Get-Row $rows "PGD-AT"
$projection = Get-Row $rows "Projection Phys-PGD-AT"
$penalty = Get-Row $rows "Penalty Phys-PGD-AT"
$catad = Get-Row $rows "CAT-AD"
$noDiff = Get-Row $rows 'CAT-AD w/o $\Delta X$'

if ([double]$pgd."Penalty ASR" -gt 0.02 -or [double]$pgd."Penalty PV-ASR" -gt 0.02) {
    throw "PGD-AT does not meet the strong-baseline robustness threshold"
}
if ([double]$projection."Penalty ASR" -gt 0.01 -or [double]$projection."Penalty PV-ASR" -gt 0.01) {
    throw "Projection Phys-PGD-AT does not meet the strong-baseline robustness threshold"
}
if ([double]$penalty."Penalty ASR" -gt 0.001 -or [double]$penalty."Penalty PV-ASR" -gt 0.001) {
    throw "Penalty Phys-PGD-AT should expose a very strong physical-AT baseline"
}
if ([double]$catad.FAR -gt 0.05) {
    throw "CAT-AD FAR is too high for the balanced-design interpretation"
}
if ([double]$noDiff.FAR -lt 0.90) {
    throw "No-differential-feature negative result is not visible"
}

$summaryVariants = @($summary.variants.PSObject.Properties | ForEach-Object { [string]$_.Value.row.Variant })
foreach ($variant in $expectedVariants) {
    if ($summaryVariants -notcontains $variant) {
        throw "Ablation summary JSON missing variant: $variant"
    }
}

foreach ($needle in @(
    "dominates every baseline",
    "beats every baseline",
    "strictly outperforms all baselines",
    "CAT-AD is best on every metric",
    "CAT-AD achieves the best value on every metric"
)) {
    Assert-NotContains "paper_lncs/main.tex" $paper $needle
}

Write-Output "baseline_competitiveness=PASSED"
Write-Output "strong_training_baselines_checked=$($strongBaselines.Count)"
Write-Output "ablation_variants_checked=$($rows.Count)"

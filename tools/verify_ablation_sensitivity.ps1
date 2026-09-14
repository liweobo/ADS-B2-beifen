param(
    [string]$AuditPath = "ABLATION_AND_SENSITIVITY_AUDIT.md",
    [string]$AblationCsvPath = "outputs\tables\table5_ablation_study.csv",
    [string]$AblationTexPath = "outputs\tables\table5_ablation_study.tex",
    [string]$AblationSummaryPath = "outputs\ablation_table5\ablation_table5_summary.json",
    [string]$EpsilonCsvPath = "results\fig_epsilon_sensitivity_data.csv"
)

$ErrorActionPreference = "Stop"

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required file: $Path"
    }
    return $Path
}

function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing expected marker: $Needle"
    }
}

function Assert-CloseText {
    param([string]$Name, [string]$Observed, [object]$Expected)
    $expectedText = "{0:F4}" -f ([double]$Expected)
    if ($Observed -ne $expectedText) {
        throw "$Name mismatch: observed=$Observed expected=$expectedText"
    }
}

function Get-Row {
    param([array]$Rows, [string]$Variant)
    $match = @($Rows | Where-Object { $_.Variant -eq $Variant })
    if ($match.Count -ne 1) {
        throw "Expected one row for ablation variant '$Variant'; found $($match.Count)"
    }
    return $match[0]
}

$auditFile = Require-File $AuditPath
$ablationCsvFile = Require-File $AblationCsvPath
$ablationTexFile = Require-File $AblationTexPath
$summaryFile = Require-File $AblationSummaryPath
$epsilonCsvFile = Require-File $EpsilonCsvPath
$paperFile = Require-File "paper_lncs\main.tex"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditFile
$tex = Get-Content -Raw -Encoding UTF8 -LiteralPath $ablationTexFile
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperFile
$summary = Get-Content -Raw -Encoding UTF8 -LiteralPath $summaryFile | ConvertFrom-Json

foreach ($marker in @(
    "Evidence Boundary",
    "What The Checks Establish",
    "Interpretation Guardrail",
    "primary quantitative claims",
    "trade-off and stability support"
)) {
    Assert-Contains $AuditPath $audit $marker
}

foreach ($marker in @(
    "\label{tab:ablation}",
    "Ablation Study",
    "Penalty Phys-PGD-AT",
    "CAT-AD w/o"
)) {
    Assert-Contains $AblationTexPath $tex $marker
}

foreach ($marker in @(
    "\section{Ablation Summary and Sensitivity Analysis}",
    "trade-off analysis",
    "low attack success is not a valid robustness gain",
    "should be interpreted only for the evaluated budget range",
    "fig_epsilon_sensitivity.pdf"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$rows = @(Import-Csv -LiteralPath $ablationCsvFile)
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

$summaryVariants = @($summary.variants.PSObject.Properties)
if ($summaryVariants.Count -ne $expectedVariants.Count) {
    throw "Expected $($expectedVariants.Count) summary variants; found $($summaryVariants.Count)"
}

foreach ($prop in $summaryVariants) {
    $variant = [string]$prop.Value.row.Variant
    $row = Get-Row $rows $variant
    foreach ($column in @("Unperturbed F1", "Projection F1", "Penalty F1", "Penalty ASR", "Penalty PV-ASR", "FAR")) {
        Assert-CloseText "$variant $column" $row.$column $prop.Value.row.$column
    }
}

$erm = Get-Row $rows "ERM"
$catad = Get-Row $rows "CAT-AD"
$noDiff = Get-Row $rows 'CAT-AD w/o $\Delta X$'

if ([double]$erm."Projection F1" -ge 0.20 -or [double]$erm."Penalty F1" -ge 0.20) {
    throw "ERM ablation is not showing the expected physical-attack vulnerability"
}
if ([double]$catad."Projection F1" -le 0.95 -or [double]$catad."Penalty F1" -le 0.95) {
    throw "CAT-AD ablation F1 is below the expected robustness floor"
}
if ([double]$catad.FAR -ge 0.05) {
    throw "CAT-AD ablation FAR is unexpectedly high"
}
if ([double]$noDiff.FAR -le 0.90) {
    throw "No-differential-feature ablation does not expose the expected FAR failure mode"
}

$epsilonRows = @(Import-Csv -LiteralPath $epsilonCsvFile)
if ($epsilonRows.Count -ne 24) {
    throw "Expected 24 epsilon-sensitivity rows; found $($epsilonRows.Count)"
}

$attacks = @($epsilonRows | Select-Object -ExpandProperty attack_setting -Unique | Sort-Object)
$models = @($epsilonRows | Select-Object -ExpandProperty model -Unique | Sort-Object)
$eps = @($epsilonRows | ForEach-Object { "{0:F4}" -f ([double]$_.epsilon) } | Sort-Object -Unique)

if (($attacks -join ",") -ne "penalty_phys_pgd,projection_phys_pgd") {
    throw "Unexpected epsilon attack settings: $($attacks -join ',')"
}
if (($models -join ",") -ne "BiLSTM-ERM,CAT-AD") {
    throw "Unexpected epsilon models: $($models -join ',')"
}
if (($eps -join ",") -ne "0.0500,0.1000,0.2000,0.3000,0.4000,0.5000") {
    throw "Unexpected epsilon grid: $($eps -join ',')"
}

foreach ($attack in $attacks) {
    $catRows = @($epsilonRows | Where-Object { $_.attack_setting -eq $attack -and $_.model -eq "CAT-AD" })
    $stdRows = @($epsilonRows | Where-Object { $_.attack_setting -eq $attack -and $_.model -eq "BiLSTM-ERM" })
    if ($catRows.Count -ne 6 -or $stdRows.Count -ne 6) {
        throw "Unexpected row count for attack $attack"
    }
    $catF1 = @($catRows | ForEach-Object { [double]$_.f1_score })
    $stdF1 = @($stdRows | ForEach-Object { [double]$_.f1_score })
    $catMin = ($catF1 | Measure-Object -Minimum).Minimum
    $catMax = ($catF1 | Measure-Object -Maximum).Maximum
    $stdMin = ($stdF1 | Measure-Object -Minimum).Minimum
    $stdAtSmallBudget = [double](@($stdRows | Where-Object { $_.epsilon -eq "0.0500" })[0].f1_score)
    if ($catMin -lt 0.95 -or ($catMax - $catMin) -gt 0.01) {
        throw "CAT-AD is not stable enough across epsilon for $attack"
    }
    if ($stdAtSmallBudget -lt 0.40 -or $stdMin -gt 0.20) {
        throw "BiLSTM-ERM does not show the expected epsilon sensitivity for $attack"
    }
}

foreach ($path in @(
    "figures\fig_epsilon_sensitivity.pdf",
    "figures\fig_epsilon_sensitivity.png",
    "figures\fig_epsilon_sensitivity.svg"
)) {
    Require-File $path | Out-Null
    $item = Get-Item -LiteralPath $path
    if ($item.Length -lt 1000) {
        throw "Figure artifact is unexpectedly small: $path"
    }
}

Write-Output "ablation_sensitivity=PASSED"
Write-Output "ablation_variants_checked=$($rows.Count)"
Write-Output "epsilon_rows_checked=$($epsilonRows.Count)"
Write-Output "epsilon_attacks_checked=$($attacks.Count)"

param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing statistical-interpretation artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing statistical-interpretation marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains overstrong statistical phrase: $Needle"
    }
}

$paperPath = "paper_lncs\main.tex"
$checklistPath = "STATISTICAL_INTERPRETATION_CHECKLIST.md"
$pairedCsvPath = "outputs\publication_benchmark\paired_comparisons.csv"
$pairedTexPath = "outputs\tables\table_paired_multiseed_comparison.tex"
$verificationPath = "outputs\publication_benchmark\verification_report.md"
$readinessPath = "TOP_CONFERENCE_READINESS_AUDIT.md"

foreach ($path in @($paperPath, $checklistPath, $pairedCsvPath, $pairedTexPath, $verificationPath, $readinessPath)) {
    Require-File $path
}

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$checklist = Get-Content -Raw -Encoding UTF8 -LiteralPath $checklistPath
$pairedTex = Get-Content -Raw -Encoding UTF8 -LiteralPath $pairedTexPath
$verification = Get-Content -Raw -Encoding UTF8 -LiteralPath $verificationPath
$readiness = Get-Content -Raw -Encoding UTF8 -LiteralPath $readinessPath
$paired = @(Import-Csv -LiteralPath $pairedCsvPath)

foreach ($marker in @(
    "Statistical Interpretation",
    "exact sign-flip p-values are coarse",
    "effect sizes",
    "confidence intervals",
    "not interpreted as conclusive hypothesis-test evidence"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

foreach ($marker in @(
    "effect sizes",
    "confidence intervals",
    "exact sign-flip p-values",
    "Holm-adjusted p-values",
    "BH q-values",
    "should not claim"
)) {
    Assert-Contains "STATISTICAL_INTERPRETATION_CHECKLIST.md" $checklist $marker
}

foreach ($marker in @(
    "Mean Improvement",
    "95\% CI",
    "Holm p",
    "BH q",
    "dz",
    "Raw p-values are two-sided paired sign-flip tests"
)) {
    Assert-Contains "table_paired_multiseed_comparison.tex" $pairedTex $marker
}

if ($paired.Count -ne 14) {
    throw "Expected 14 paired-comparison rows; found $($paired.Count)"
}

$effectSizeRows = 0
foreach ($row in $paired) {
    if ([int]$row.n -ne 5) {
        throw "Expected n=5 for paired row $($row.setting)/$($row.metric); found $($row.n)"
    }
    foreach ($field in @("mean_improvement", "ci95_low", "ci95_high", "cohens_dz", "p_two_sided_sign_flip", "p_holm", "q_bh_fdr", "win_rate")) {
        $value = [double]$row.$field
        if ([double]::IsNaN($value)) {
            throw "Field $field is NaN for $($row.setting)/$($row.metric)"
        }
    }
    if ([double]$row.p_two_sided_sign_flip -lt 0.0625) {
        throw "Unexpected exact sign-flip p-value below 0.0625 for five seeds"
    }
    $effectSizeRows += 1
}

foreach ($marker in @(
    "Paired comparison rows: 14",
    "Seeds: 42,43,44,45,46"
)) {
    Assert-Contains "verification_report.md" $verification $marker
}

Assert-Contains "TOP_CONFERENCE_READINESS_AUDIT.md" $readiness "Exact sign-flip p-values with five seeds are conservative"

foreach ($phrase in @(
    "statistically significant",
    "significant improvement",
    "significant improvements",
    "adjusted significance values",
    "proves significance"
)) {
    Assert-NotContains "paper_lncs/main.tex" $paper $phrase
}

Write-Output "statistical_interpretation=PASSED"
Write-Output "paired_rows_checked=$($paired.Count)"
Write-Output "effect_size_rows_checked=$effectSizeRows"

param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing seed-direction-consistency artifact: $Path"
    }
    return $Path
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing seed-direction-consistency marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden seed-direction wording: $Needle"
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

function Format-Double {
    param([double]$Value)
    return $Value.ToString("G17", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-Median {
    param([double[]]$Values)
    $sorted = @($Values | Sort-Object)
    $count = $sorted.Count
    if ($count -eq 0) {
        throw "Cannot compute median of an empty vector"
    }
    if (($count % 2) -eq 1) {
        return [double]$sorted[[int](($count - 1) / 2)]
    }
    $upper = [int]($count / 2)
    $lower = $upper - 1
    return ([double]$sorted[$lower] + [double]$sorted[$upper]) / 2.0
}

function Get-MetricValue {
    param(
        [object[]]$Rows,
        [string]$Seed,
        [string]$Model,
        [string]$Setting,
        [string]$Metric
    )
    $matches = @($Rows | Where-Object { $_.seed -eq $Seed -and $_.model -eq $Model -and $_.setting -eq $Setting })
    if ($matches.Count -ne 1) {
        throw "Expected one row for seed=$Seed model=$Model setting=$Setting, found $($matches.Count)"
    }
    return To-Double $matches[0].$Metric
}

$auditPath = Require-File "SEED_DIRECTION_CONSISTENCY_AUDIT.md"
$paperPath = Require-File "paper_lncs\main.tex"
$ledgerPath = Require-File "NUMERIC_CLAIMS_LEDGER.md"
$pairedPath = Require-File "outputs\publication_benchmark\paired_comparisons.csv"
$widePath = Require-File "outputs\publication_benchmark\per_seed_metrics_wide.csv"
$verificationPath = Require-File "outputs\publication_benchmark\verification_report.md"
$summaryCsvPath = Require-File "outputs\publication_benchmark\primary_seed_direction_summary.csv"
$summaryTexPath = Require-File "outputs\publication_benchmark\primary_seed_direction_summary.tex"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Primary Claims Checked",
    "primary_seed_direction_summary.csv",
    "recomputes the",
    'seeds `42,43,44,45,46`',
    "single outlying seed",
    "Expected Output"
)) {
    Assert-Contains "SEED_DIRECTION_CONSISTENCY_AUDIT.md" $audit $marker
}

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$paperMarkers = @(
    "paired improvement direction is positive in all five seeds",
    "reported as robustness evidence",
    "not as a substitute for broader datasets or additional attack families"
)
foreach ($marker in $paperMarkers) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$ledger = Get-Content -Raw -Encoding UTF8 -LiteralPath $ledgerPath
foreach ($marker in @(
    "Unperturbed detection is not reduced",
    "Digital PGD ASR is reduced",
    "Projection Phys-PGD ASR is reduced",
    "Penalty Phys-PGD ASR is reduced",
    "Projection Phys-PGD PV-ASR given V0 is reduced",
    "Penalty Phys-PGD PV-ASR given V0 is reduced"
)) {
    Assert-Contains "NUMERIC_CLAIMS_LEDGER.md" $ledger $marker
}

$verification = Get-Content -Raw -Encoding UTF8 -LiteralPath $verificationPath
Assert-Contains "verification_report.md" $verification "Seeds: 42,43,44,45,46"
Assert-Contains "verification_report.md" $verification "Status: PASSED"

$claims = @(
    [pscustomobject]@{ Label = "Unperturbed detection is not reduced"; Setting = "Clean"; Metric = "f1"; Direction = "higher" },
    [pscustomobject]@{ Label = "Digital PGD ASR is reduced"; Setting = "Standard PGD"; Metric = "asr"; Direction = "lower" },
    [pscustomobject]@{ Label = "Projection Phys-PGD ASR is reduced"; Setting = "Projection-based phys-PGD"; Metric = "asr"; Direction = "lower" },
    [pscustomobject]@{ Label = "Penalty Phys-PGD ASR is reduced"; Setting = "Penalty-based phys-PGD"; Metric = "asr"; Direction = "lower" },
    [pscustomobject]@{ Label = "Projection Phys-PGD PV-ASR given V0 is reduced"; Setting = "Projection-based phys-PGD"; Metric = "conditional_pv_asr_start_valid"; Direction = "lower" },
    [pscustomobject]@{ Label = "Penalty Phys-PGD PV-ASR given V0 is reduced"; Setting = "Penalty-based phys-PGD"; Metric = "conditional_pv_asr_start_valid"; Direction = "lower" }
)

$expectedSeeds = @("42", "43", "44", "45", "46")
$wideRows = @(Import-Csv -LiteralPath $widePath)
$pairedRows = @(Import-Csv -LiteralPath $pairedPath)
$availableSeeds = @($wideRows | Select-Object -ExpandProperty seed -Unique | Sort-Object)
if (($availableSeeds -join ",") -ne ($expectedSeeds -join ",")) {
    throw "Unexpected seed list in per_seed_metrics_wide.csv: $($availableSeeds -join ',')"
}

$seedPairsChecked = 0
$pairedRowsChecked = 0
$minimumImprovement = [double]::PositiveInfinity
$expectedSummaryRows = @()

foreach ($claim in $claims) {
    $paired = @($pairedRows | Where-Object { $_.setting -eq $claim.Setting -and $_.metric -eq $claim.Metric })
    if ($paired.Count -ne 1) {
        throw "Expected one paired-comparison row for $($claim.Setting) / $($claim.Metric), found $($paired.Count)"
    }
    if ([int]$paired[0].n -ne 5) {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) does not have n=5"
    }
    if ($paired[0].seeds -ne "42,43,44,45,46") {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) has unexpected seeds: $($paired[0].seeds)"
    }
    if ((To-Double $paired[0].win_rate) -ne 1.0) {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) does not have win_rate=1.0"
    }
    if ((To-Double $paired[0].tie_rate) -ne 0.0) {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) does not have tie_rate=0.0"
    }
    if ((To-Double $paired[0].mean_improvement) -le 0.0) {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) has non-positive mean improvement"
    }
    $pairedRowsChecked += 1

    $improvements = @()
    $seedImprovements = @()
    foreach ($seed in $expectedSeeds) {
        $baseline = Get-MetricValue $wideRows $seed "Baseline" $claim.Setting $claim.Metric
        $proposed = Get-MetricValue $wideRows $seed "Proposed" $claim.Setting $claim.Metric
        if ($claim.Direction -eq "higher") {
            $improvement = $proposed - $baseline
        }
        else {
            $improvement = $baseline - $proposed
        }
        if ($improvement -le 0.0) {
            throw "Seed $seed fails $($claim.Label): improvement=$improvement baseline=$baseline proposed=$proposed"
        }
        if ($improvement -lt $minimumImprovement) {
            $minimumImprovement = $improvement
        }
        $improvements += [double]$improvement
        $seedImprovements += ("{0}={1}" -f $seed, (Format-Double $improvement))
        $seedPairsChecked += 1
    }

    $positiveCount = @($improvements | Where-Object { $_ -gt 0.0 }).Count
    $stats = $improvements | Measure-Object -Minimum -Average
    $expectedSummaryRows += [pscustomobject]@{
        claim = $claim.Label
        setting = $claim.Setting
        metric = $claim.Metric
        direction = $claim.Direction
        improvement_definition = if ($claim.Direction -eq "higher") { "Proposed - Baseline" } else { "Baseline - Proposed" }
        seed_count = [string]$expectedSeeds.Count
        positive_seed_count = [string]$positiveCount
        win_rate = Format-Double (To-Double $paired[0].win_rate)
        min_improvement = Format-Double ([double]$stats.Minimum)
        median_improvement = Format-Double ([double](Get-Median $improvements))
        mean_improvement = Format-Double ([double]$stats.Average)
        ci95_low = Format-Double (To-Double $paired[0].ci95_low)
        ci95_high = Format-Double (To-Double $paired[0].ci95_high)
        seed_improvements = ($seedImprovements -join ";")
        seeds = ($expectedSeeds -join ",")
    }
}

$summaryRows = @(Import-Csv -LiteralPath $summaryCsvPath)
if ($summaryRows.Count -ne $expectedSummaryRows.Count) {
    throw "primary_seed_direction_summary.csv has $($summaryRows.Count) rows, expected $($expectedSummaryRows.Count)"
}
$summaryFields = @(
    "claim",
    "setting",
    "metric",
    "direction",
    "improvement_definition",
    "seed_count",
    "positive_seed_count",
    "win_rate",
    "min_improvement",
    "median_improvement",
    "mean_improvement",
    "ci95_low",
    "ci95_high",
    "seed_improvements",
    "seeds"
)
foreach ($expected in $expectedSummaryRows) {
    $actual = @($summaryRows | Where-Object { $_.claim -eq $expected.claim -and $_.setting -eq $expected.setting -and $_.metric -eq $expected.metric })
    if ($actual.Count -ne 1) {
        throw "Expected one seed-direction summary row for $($expected.setting) / $($expected.metric), found $($actual.Count)"
    }
    foreach ($field in $summaryFields) {
        $actualValue = [string]$actual[0].PSObject.Properties[$field].Value
        $expectedValue = [string]$expected.PSObject.Properties[$field].Value
        if ($actualValue -ne $expectedValue) {
            throw "Seed-direction summary mismatch for $($expected.setting) / $($expected.metric) field ${field}: actual=$actualValue expected=$expectedValue"
        }
    }
}

$summaryTex = Get-Content -Raw -Encoding UTF8 -LiteralPath $summaryTexPath
$summaryTexMarkers = @(
    "Per-seed direction check for the six primary CAT-AD claims",
    "Positive seeds",
    "Unperturbed detection is not reduced",
    "Digital PGD ASR is reduced",
    "Projection Phys-PGD PV-ASR given V0 is reduced",
    "Penalty Phys-PGD PV-ASR given V0 is reduced",
    "5/5"
)
foreach ($marker in $summaryTexMarkers) {
    Assert-Contains "primary_seed_direction_summary.tex" $summaryTex $marker
}

foreach ($needle in @(
    "every metric improves",
    "all future seeds",
    "statistically conclusive",
    "guarantees robustness"
)) {
    Assert-NotContains "paper_lncs/main.tex" $paper $needle
    Assert-NotContains "SEED_DIRECTION_CONSISTENCY_AUDIT.md" $audit $needle
}

Write-Output "seed_direction_consistency=PASSED"
Write-Output "primary_claims_checked=$($claims.Count)"
Write-Output "seed_pairs_checked=$seedPairsChecked"
Write-Output "paired_rows_checked=$pairedRowsChecked"
Write-Output "summary_csv_rows_checked=$($summaryRows.Count)"
Write-Output "summary_tex_markers_checked=$($summaryTexMarkers.Count)"
Write-Output "paper_markers_checked=$($paperMarkers.Count)"
Write-Output ("minimum_seed_improvement={0}" -f $minimumImprovement.ToString("G17", [System.Globalization.CultureInfo]::InvariantCulture))
Write-Output "forbidden_seed_overclaims_checked=4"

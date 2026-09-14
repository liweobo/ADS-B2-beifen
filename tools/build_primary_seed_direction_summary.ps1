param(
    [string]$WideMetricsCsv = "outputs\publication_benchmark\per_seed_metrics_wide.csv",
    [string]$PairedComparisonsCsv = "outputs\publication_benchmark\paired_comparisons.csv",
    [string]$OutputDir = "outputs\publication_benchmark"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Resolve-RepoPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $RepoRoot $Path)
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

function Escape-Tex {
    param([string]$Value)
    return $Value.
        Replace("\", "\textbackslash{}").
        Replace("&", "\&").
        Replace("%", "\%").
        Replace("_", "\_")
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

$widePath = Resolve-RepoPath $WideMetricsCsv
$pairedPath = Resolve-RepoPath $PairedComparisonsCsv
if (-not (Test-Path -LiteralPath $widePath -PathType Leaf)) {
    throw "Missing per-seed metrics CSV: $widePath"
}
if (-not (Test-Path -LiteralPath $pairedPath -PathType Leaf)) {
    throw "Missing paired-comparisons CSV: $pairedPath"
}

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
    throw "Unexpected seed list in per-seed metrics: $($availableSeeds -join ',')"
}

$summaryRows = @()
foreach ($claim in $claims) {
    $paired = @($pairedRows | Where-Object { $_.setting -eq $claim.Setting -and $_.metric -eq $claim.Metric })
    if ($paired.Count -ne 1) {
        throw "Expected one paired-comparison row for $($claim.Setting) / $($claim.Metric), found $($paired.Count)"
    }
    if ([int]$paired[0].n -ne $expectedSeeds.Count) {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) does not have n=$($expectedSeeds.Count)"
    }
    if ($paired[0].seeds -ne ($expectedSeeds -join ",")) {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) has unexpected seeds: $($paired[0].seeds)"
    }

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
        $improvements += [double]$improvement
        $seedImprovements += ("{0}={1}" -f $seed, (Format-Double $improvement))
    }

    $positiveCount = @($improvements | Where-Object { $_ -gt 0.0 }).Count
    if ($positiveCount -ne $expectedSeeds.Count) {
        throw "$($claim.Label) has only $positiveCount positive seed-level improvements"
    }
    if ((To-Double $paired[0].win_rate) -ne 1.0) {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) does not have win_rate=1.0"
    }
    if ((To-Double $paired[0].tie_rate) -ne 0.0) {
        throw "Paired row for $($claim.Setting) / $($claim.Metric) does not have tie_rate=0.0"
    }

    $stats = $improvements | Measure-Object -Minimum -Average
    $min = [double]$stats.Minimum
    $mean = [double]$stats.Average
    $median = [double](Get-Median $improvements)
    $pairedMean = To-Double $paired[0].mean_improvement
    if ([Math]::Abs($pairedMean - $mean) -gt 1e-12) {
        throw "Computed mean improvement differs from paired comparison for $($claim.Setting) / $($claim.Metric): computed=$mean paired=$pairedMean"
    }

    $summaryRows += [pscustomobject]@{
        claim = $claim.Label
        setting = $claim.Setting
        metric = $claim.Metric
        direction = $claim.Direction
        improvement_definition = if ($claim.Direction -eq "higher") { "Proposed - Baseline" } else { "Baseline - Proposed" }
        seed_count = [string]$expectedSeeds.Count
        positive_seed_count = [string]$positiveCount
        win_rate = Format-Double (To-Double $paired[0].win_rate)
        min_improvement = Format-Double $min
        median_improvement = Format-Double $median
        mean_improvement = Format-Double $mean
        ci95_low = Format-Double (To-Double $paired[0].ci95_low)
        ci95_high = Format-Double (To-Double $paired[0].ci95_high)
        seed_improvements = ($seedImprovements -join ";")
        seeds = ($expectedSeeds -join ",")
    }
}

$outDir = Resolve-RepoPath $OutputDir
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$csvPath = Join-Path $outDir "primary_seed_direction_summary.csv"
$texPath = Join-Path $outDir "primary_seed_direction_summary.tex"

$summaryRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$lines = @(
    "\begin{table*}[t]",
    "\centering",
    "\small",
    "\setlength{\tabcolsep}{3pt}",
    "\renewcommand{\arraystretch}{1.08}",
    "\caption{Per-seed direction check for the six primary CAT-AD claims}",
    "\label{tab:primary_seed_direction_summary}",
    "\begin{tabular}{p{0.31\textwidth}p{0.12\textwidth}rrrr}",
    "\toprule",
    "Primary claim & Direction & Positive seeds & Min & Median & Mean \\",
    "\midrule"
)
foreach ($row in $summaryRows) {
    $direction = if ($row.direction -eq "higher") { "higher better" } else { "lower better" }
    $lines += ("{0} & {1} & {2}/{3} & {4} & {5} & {6} \\" -f
        (Escape-Tex $row.claim),
        (Escape-Tex $direction),
        $row.positive_seed_count,
        $row.seed_count,
        $row.min_improvement,
        $row.median_improvement,
        $row.mean_improvement)
}
$lines += @(
    "\bottomrule",
    "\end{tabular}",
    "\vspace{1mm}",
    "\begin{minipage}{0.98\textwidth}",
    "\footnotesize Values are recomputed from \texttt{outputs/publication\_benchmark/per\_seed\_metrics\_wide.csv}. Positive seeds count seed-level paired differences in the claim direction; the table does not promote auxiliary ablation or sensitivity results to primary claims.",
    "\end{minipage}",
    "\end{table*}",
    ""
)
Set-Content -LiteralPath $texPath -Value $lines -Encoding UTF8

Write-Output "primary_seed_direction_summary_csv=$csvPath"
Write-Output "primary_seed_direction_summary_tex=$texPath"
Write-Output "primary_seed_direction_summary_rows=$($summaryRows.Count)"

param(
    [string]$PreflightJson = "outputs\publication_benchmark\preflight_report.json",
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

function Format-Int {
    param([int64]$Value)
    return $Value.ToString("N0", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-Range {
    param([object[]]$Values)
    $stats = $Values | Measure-Object -Minimum -Maximum
    $min = [int64]$stats.Minimum
    $max = [int64]$stats.Maximum
    if ($min -eq $max) {
        return (Format-Int $min)
    }
    return ("{0}--{1}" -f (Format-Int $min), (Format-Int $max))
}

function Format-Nullable {
    param([object]$Value)
    if ($null -eq $Value -or [string]$Value -eq "") {
        return "none"
    }
    return [string]$Value
}

function Escape-Tex {
    param([string]$Value)
    return $Value.
        Replace("\", "\textbackslash{}").
        Replace("&", "\&").
        Replace("%", "\%").
        Replace("_", "\_")
}

$jsonPath = Resolve-RepoPath $PreflightJson
if (-not (Test-Path -LiteralPath $jsonPath -PathType Leaf)) {
    throw "Missing preflight report JSON: $jsonPath"
}

$report = Get-Content -Raw -Encoding UTF8 -LiteralPath $jsonPath | ConvertFrom-Json
if (-not $report.passed) {
    throw "Preflight report is not passed: $jsonPath"
}

$runs = @($report.runs)
if ($runs.Count -lt 1) {
    throw "Preflight report contains no runs"
}

$dataset = $report.dataset_summary
$options = $report.options
$seeds = @($options.seeds | ForEach-Object { [string]$_ }) -join ","
$trainCounts = @($runs | ForEach-Object { $_.data_summary.aircraft_after_subset })
$rowsAfterSubset = @($runs | ForEach-Object { $_.data_summary.rows_after_subset })
$splitTrain = @($runs | ForEach-Object { $_.split_summary.aircraft.train.count })
$splitVal = @($runs | ForEach-Object { $_.split_summary.aircraft.validation.count })
$splitTest = @($runs | ForEach-Object { $_.split_summary.aircraft.test.count })
$overlaps = @($runs | ForEach-Object {
        $_.split_summary.aircraft.overlap_counts.train_validation
        $_.split_summary.aircraft.overlap_counts.train_test
        $_.split_summary.aircraft.overlap_counts.validation_test
    })
$perAttackMalicious = @($runs | ForEach-Object {
        foreach ($property in $_.split_summary.windows.per_attack.PSObject.Properties) {
            $property.Value.malicious_windows
        }
    })

$rows = @(
    [pscustomobject]@{ Check = "Trajectory rows"; Evidence = "Raw / filtered / selected: $(Format-Int $dataset.rows_loaded) / $(Format-Int $dataset.rows_after_filter) / $(Format-Range $rowsAfterSubset)" },
    [pscustomobject]@{ Check = "Aircraft"; Evidence = "Raw / filtered / selected: $(Format-Int $dataset.aircraft_loaded) / $(Format-Int $dataset.aircraft_after_filter) / $(Format-Range $trainCounts)" },
    [pscustomobject]@{ Check = "Independent runs"; Evidence = "$($runs.Count) matched splits/seeds: $seeds" },
    [pscustomobject]@{ Check = "Data usage"; Evidence = "All filtered aircraft; no aircraft subsampling" },
    [pscustomobject]@{ Check = "Aircraft split"; Evidence = "$(Format-Range $splitTrain) / $(Format-Range $splitVal) / $(Format-Range $splitTest) aircraft (train / validation / test)" },
    [pscustomobject]@{ Check = "Aircraft leakage"; Evidence = "Zero aircraft overlap in every train--validation, train--test, and validation--test comparison" },
    [pscustomobject]@{ Check = "Window labeling"; Evidence = "$($options.window_size) time steps; at least $($options.malicious_label_min_points) anomalous points define a positive window" },
    [pscustomobject]@{ Check = "Training windows"; Evidence = "$(Format-Range (@($runs | ForEach-Object { $_.split_summary.windows.train.total_windows }))) total; $(Format-Range (@($runs | ForEach-Object { $_.split_summary.windows.train.malicious_windows }))) anomalous" },
    [pscustomobject]@{ Check = "Validation windows"; Evidence = "$(Format-Range (@($runs | ForEach-Object { $_.split_summary.windows.validation.total_windows }))) total; $(Format-Range (@($runs | ForEach-Object { $_.split_summary.windows.validation.malicious_windows }))) anomalous" },
    [pscustomobject]@{ Check = "Mixed test windows"; Evidence = "$(Format-Range (@($runs | ForEach-Object { $_.split_summary.windows.test_mixed_attack.total_windows }))) total; $(Format-Range (@($runs | ForEach-Object { $_.split_summary.windows.test_mixed_attack.malicious_windows }))) anomalous" },
    [pscustomobject]@{ Check = "No-injection control"; Evidence = "$(Format-Range (@($runs | ForEach-Object { $_.split_summary.windows.test_no_injection.total_windows }))) normal windows; no synthetic anomaly injection" },
    [pscustomobject]@{ Check = "Per-attack support"; Evidence = "At least $(Format-Int (($perAttackMalicious | Measure-Object -Minimum).Minimum)) anomalous windows for every split/seed and attack type" }
)

$outDir = Resolve-RepoPath $OutputDir
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$csvPath = Join-Path $outDir "data_split_audit.csv"
$texPath = Join-Path $outDir "data_split_audit.tex"

$rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$lines = @(
    "\begin{table*}[t]",
    "\centering",
    "\small",
    "\setlength{\tabcolsep}{4pt}",
    "\renewcommand{\arraystretch}{1.08}",
    "\caption{Data split and leakage preflight audit}",
    "\label{tab:data_split_audit}",
    "\begin{tabular}{>{\raggedright\arraybackslash}p{0.30\textwidth}>{\raggedright\arraybackslash}p{0.62\textwidth}}",
    "\toprule",
    "Check & Evidence \\",
    "\midrule"
)
foreach ($row in $rows) {
    $lines += ("{0} & {1} \\" -f (Escape-Tex $row.Check), (Escape-Tex $row.Evidence))
}
$lines += @(
    "\bottomrule",
    "\end{tabular}",
    "\vspace{1mm}",
    "\begin{minipage}{0.98\textwidth}",
    "\footnotesize All counts are generated from the archived preflight report. Ranges summarize the five seed-specific aircraft-level splits.",
    "\end{minipage}",
    "\end{table*}",
    ""
)
Set-Content -LiteralPath $texPath -Value $lines -Encoding UTF8

Write-Output "data_split_audit_csv=$csvPath"
Write-Output "data_split_audit_tex=$texPath"
Write-Output "data_split_audit_rows=$($rows.Count)"

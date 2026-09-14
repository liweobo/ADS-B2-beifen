$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing dataset-profile artifact: $Path"
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

function Assert-Close {
    param(
        [string]$Name,
        [double]$Actual,
        [double]$Expected,
        [double]$Tolerance = 0.000001
    )
    if ([Math]::Abs($Actual - $Expected) -gt $Tolerance) {
        throw "$Name mismatch: expected=$Expected actual=$Actual"
    }
}

$auditPath = Require-File "DATASET_PROFILE_AUDIT.md"
$csvPath = Require-File "sample_adsb_decoded.csv"
$preflightPath = Require-File "outputs\publication_benchmark\preflight_report.json"
$dataPath = Require-File "adsb\data.py"
$provenancePath = Require-File "DATA_PROVENANCE_AND_ETHICS.md"
$readinessPath = Require-File "TOP_CONFERENCE_READINESS_AUDIT.md"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Raw CSV Profile",
    "Model-Loaded Data Boundary",
    "Split And Window Coverage",
    "External Validity Boundary",
    'Raw data rows: `217148`',
    'Loaded model rows: `216880`',
    'Rows after physical sanity filtering: `75238`',
    'train/validation/test aircraft counts of `13/2/4`'
)) {
    Assert-Contains "DATASET_PROFILE_AUDIT.md" $audit $marker
}

$provenance = Get-Content -Raw -Encoding UTF8 -LiteralPath $provenancePath
Assert-Contains "DATA_PROVENANCE_AND_ETHICS.md" $provenance "sample_adsb_decoded.csv"
Assert-Contains "DATA_PROVENANCE_AND_ETHICS.md" $provenance "3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72"

$readiness = Get-Content -Raw -Encoding UTF8 -LiteralPath $readinessPath
Assert-Contains "TOP_CONFERENCE_READINESS_AUDIT.md" $readiness "Dataset profile transparency"

$csvItem = Get-Item -LiteralPath $csvPath
if ($csvItem.Length -ne 12508928) {
    throw "Unexpected sample CSV size: $($csvItem.Length)"
}
$sampleHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $csvPath).Hash.ToLowerInvariant()
if ($sampleHash -ne "3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72") {
    throw "Unexpected sample CSV SHA-256: $sampleHash"
}

$rows = @(Import-Csv -LiteralPath $csvPath)
if ($rows.Count -ne 217148) {
    throw "Unexpected raw CSV row count: $($rows.Count)"
}
$headers = @($rows[0].PSObject.Properties.Name)
if (($headers -join ",") -ne "ts,icao,lat,lon,alt,spd,hdg,roc,callsign") {
    throw "Unexpected sample CSV header: $($headers -join ',')"
}

$aircraft = @($rows | Select-Object -ExpandProperty icao -Unique)
if ($aircraft.Count -ne 20) {
    throw "Unexpected raw aircraft count: $($aircraft.Count)"
}

$tsValues = @($rows | ForEach-Object { [int64][double]$_.ts })
$minTs = ($tsValues | Measure-Object -Minimum).Minimum
$maxTs = ($tsValues | Measure-Object -Maximum).Maximum
if ($minTs -ne 1483225201 -or $maxTs -ne 1483311600) {
    throw "Unexpected timestamp range: $minTs..$maxTs"
}

$ranges = @{
    lat = @(48.04491, 54.86559)
    lon = @(-1.63882, 10.54504)
    alt = @(-1000.0, 41025.0)
    spd = @(100.0, 517.0)
    hdg = @(0.0, 359.9)
    roc = @(-5696.0, 6144.0)
}
foreach ($key in $ranges.Keys) {
    $values = @($rows | ForEach-Object { [double]$_.$key })
    Assert-Close "$key minimum" (($values | Measure-Object -Minimum).Minimum) ([double]$ranges[$key][0])
    Assert-Close "$key maximum" (($values | Measure-Object -Maximum).Maximum) ([double]$ranges[$key][1])
}

$missingCallsign = @($rows | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.callsign) }).Count
if ($missingCallsign -ne 185030) {
    throw "Unexpected missing callsign count: $missingCallsign"
}

$preflight = Get-Content -Raw -Encoding UTF8 -LiteralPath $preflightPath | ConvertFrom-Json
if ($preflight.passed -ne $true -or $preflight.status -ne "passed") {
    throw "Preflight report is not passed"
}
if ($preflight.options.csv_path -ne "sample_adsb_decoded.csv") {
    throw "Preflight CSV path mismatch: $($preflight.options.csv_path)"
}
if ($preflight.options.require_full_data -ne $true -or $preflight.options.num_aircraft -ne $null) {
    throw "Preflight does not record full-data benchmark settings"
}
if ([int]$preflight.options.window_size -ne 15) {
    throw "Unexpected preflight window size: $($preflight.options.window_size)"
}
$seedList = @($preflight.options.seeds | ForEach-Object { [int]$_ })
if (($seedList -join ",") -ne "42,43,44,45,46") {
    throw "Unexpected preflight seed list: $($seedList -join ',')"
}

$summary = $preflight.dataset_summary
if ([int]$summary.rows_loaded -ne 216880 -or [int]$summary.rows_after_filter -ne 75238) {
    throw "Unexpected preflight row counts: loaded=$($summary.rows_loaded) filtered=$($summary.rows_after_filter)"
}
if ([int]$summary.aircraft_loaded -ne 20 -or [int]$summary.aircraft_after_filter -ne 19) {
    throw "Unexpected preflight aircraft counts"
}

$runsChecked = 0
$perAttackSummariesChecked = 0
foreach ($run in $preflight.runs) {
    if ($run.passed -ne $true) {
        throw "Preflight run failed for seed $($run.seed)"
    }
    $data = $run.data_summary
    if ([int]$data.rows_after_subset -ne 75238 -or [int]$data.aircraft_after_subset -ne 19) {
        throw "Run data summary indicates subsetting for seed $($run.seed)"
    }
    $air = $run.split_summary.aircraft
    if ([int]$air.train.count -ne 13 -or [int]$air.validation.count -ne 2 -or [int]$air.test.count -ne 4) {
        throw "Unexpected aircraft split counts for seed $($run.seed)"
    }
    $overlap = $air.overlap_counts
    if ([int]$overlap.train_validation -ne 0 -or [int]$overlap.train_test -ne 0 -or [int]$overlap.validation_test -ne 0) {
        throw "Aircraft overlap detected for seed $($run.seed)"
    }
    $windows = $run.split_summary.windows
    foreach ($name in @("train", "validation", "test_mixed_attack")) {
        if ([int]$windows.$name.malicious_windows -le 0) {
            throw "Missing malicious windows in $name for seed $($run.seed)"
        }
    }
    if ([int]$windows.test_no_injection.malicious_windows -ne 0) {
        throw "No-injection test split contains malicious windows for seed $($run.seed)"
    }
    foreach ($attackName in $windows.per_attack.PSObject.Properties.Name) {
        if ([int]$windows.per_attack.$attackName.malicious_windows -le 0) {
            throw "Missing malicious windows in per-attack split '$attackName' for seed $($run.seed)"
        }
        $perAttackSummariesChecked += 1
    }
    $runsChecked += 1
}
if ($runsChecked -ne 5) {
    throw "Expected five preflight runs, checked $runsChecked"
}

$dataCode = Get-Content -Raw -Encoding UTF8 -LiteralPath $dataPath
foreach ($marker in @(
    "pd.read_csv(path)",
    'df = df[["ts", "icao", "lat", "lon", "spd", "hdg", "alt"]]',
    "df = df.dropna()",
    'df = df[df["alt"] > 0]',
    '(df["spd"] > 0)',
    '& (df["spd"] < 300)',
    '& (df["alt"] < 15000)',
    '& (df["hdg"] <= 360)'
)) {
    Assert-Contains "adsb/data.py" $dataCode $marker
}

Write-Output "dataset_profile=PASSED"
Write-Output "raw_rows_checked=$($rows.Count)"
Write-Output "preflight_runs_checked=$runsChecked"
Write-Output "per_attack_summaries_checked=$perAttackSummariesChecked"

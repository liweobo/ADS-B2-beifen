param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing data-provenance artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing data-provenance marker: $Needle"
    }
}

function Assert-Equal {
    param(
        [string]$Name,
        $Actual,
        $Expected
    )
    if ($Actual -ne $Expected) {
        throw "$Name mismatch: actual=$Actual expected=$Expected"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden data-boundary marker: $Needle"
    }
}

$statementPath = "DATA_PROVENANCE_AND_ETHICS.md"
$samplePath = "sample_adsb_decoded.csv"
$preflightPath = "outputs\publication_benchmark\preflight_report.json"
$manifestPath = "outputs\publication_benchmark\benchmark_manifest.json"
$auditTablePath = "outputs\publication_benchmark\data_split_audit.tex"
$paperPath = "paper_lncs\main.tex"

foreach ($path in @($statementPath, $samplePath, $preflightPath, $manifestPath, $auditTablePath, $paperPath)) {
    Require-File $path
}

$statement = Get-Content -Raw -Encoding UTF8 -LiteralPath $statementPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$auditTable = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditTablePath
$preflight = Get-Content -Raw -Encoding UTF8 -LiteralPath $preflightPath | ConvertFrom-Json
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json

$expectedSha = "3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72"
$sampleItem = Get-Item -LiteralPath $samplePath
$sampleSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $samplePath).Hash.ToLowerInvariant()

Assert-Equal "sample size" ([int64]$sampleItem.Length) ([int64]12508928)
Assert-Equal "sample sha256" $sampleSha $expectedSha
Assert-Equal "manifest data path" ([string]$manifest.provenance.data.path) "sample_adsb_decoded.csv"
Assert-Equal "manifest data size" ([int64]$manifest.provenance.data.size_bytes) ([int64]12508928)
Assert-Equal "manifest data sha256" ([string]$manifest.provenance.data.sha256) $expectedSha

$header = Get-Content -LiteralPath $samplePath -TotalCount 1
Assert-Equal "sample header" $header "ts,icao,lat,lon,alt,spd,hdg,roc,callsign"

$rawSnapshotsChecked = 0
$rawSnapshots = @(
    [pscustomobject]@{
        path = "states_2018-05-28-14.csv"
        bytes = [int64]355478519
        sha256 = "285b609039250dd557cf410ef88c2d36892646e3b67ae1dd1113d6fe9e059419"
    },
    [pscustomobject]@{
        path = "states_2022-06-27-23.csv"
        bytes = [int64]430570592
        sha256 = "c5d425f54ab5594029461219bb5f827b504cd1171e67b16077c2baea923ee498"
    }
)
foreach ($raw in $rawSnapshots) {
    if (Test-Path -LiteralPath $raw.path -PathType Leaf) {
        $rawItem = Get-Item -LiteralPath $raw.path
        $rawSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $raw.path).Hash.ToLowerInvariant()
        Assert-Equal "$($raw.path) size" ([int64]$rawItem.Length) ([int64]$raw.bytes)
        Assert-Equal "$($raw.path) sha256" $rawSha $raw.sha256
        $rawSnapshotsChecked += 1
    }
}

$bundleManifestsChecked = 0
foreach ($bundleManifestPath in @(
    "BUNDLE_MANIFEST.tsv",
    "output\submission\catad_topconf_submission_bundle.manifest.tsv"
)) {
    if (Test-Path -LiteralPath $bundleManifestPath -PathType Leaf) {
        $bundleManifest = Get-Content -Raw -LiteralPath $bundleManifestPath
        Assert-Contains $bundleManifestPath $bundleManifest "sample_adsb_decoded.csv"
        Assert-Contains $bundleManifestPath $bundleManifest "DATA_PROVENANCE_AND_ETHICS.md"
        Assert-Contains $bundleManifestPath $bundleManifest "tools/verify_data_provenance_ethics.ps1"
        Assert-NotContains $bundleManifestPath $bundleManifest "states_2018-05-28-14.csv"
        Assert-NotContains $bundleManifestPath $bundleManifest "states_2022-06-27-23.csv"
        $bundleManifestsChecked += 1
    }
}

Assert-Equal "preflight status" ([string]$preflight.status) "passed"
Assert-Equal "preflight passed flag" ([bool]$preflight.passed) $true
Assert-Equal "preflight csv path" ([string]$preflight.options.csv_path) "sample_adsb_decoded.csv"
Assert-Equal "preflight require_full_data" ([bool]$preflight.options.require_full_data) $true
Assert-Equal "preflight rows loaded" ([int64]$preflight.dataset_summary.rows_loaded) ([int64]216880)
Assert-Equal "preflight rows after filter" ([int64]$preflight.dataset_summary.rows_after_filter) ([int64]75238)
Assert-Equal "preflight aircraft loaded" ([int64]$preflight.dataset_summary.aircraft_loaded) ([int64]20)
Assert-Equal "preflight aircraft after filter" ([int64]$preflight.dataset_summary.aircraft_after_filter) ([int64]19)

$expectedSeeds = @(42, 43, 44, 45, 46)
$actualSeeds = @($preflight.options.seeds | ForEach-Object { [int]$_ })
Assert-Equal "preflight seed count" $actualSeeds.Count $expectedSeeds.Count
for ($i = 0; $i -lt $expectedSeeds.Count; $i++) {
    Assert-Equal "preflight seed[$i]" $actualSeeds[$i] $expectedSeeds[$i]
}

$overlapViolations = 0
$runsChecked = 0
foreach ($run in @($preflight.runs)) {
    if (-not [bool]$run.passed) {
        throw "Preflight run failed for seed $($run.seed)"
    }
    Assert-Equal "run rows loaded seed $($run.seed)" ([int64]$run.data_summary.rows_loaded) ([int64]216880)
    Assert-Equal "run rows after subset seed $($run.seed)" ([int64]$run.data_summary.rows_after_subset) ([int64]75238)
    Assert-Equal "run aircraft after subset seed $($run.seed)" ([int64]$run.data_summary.aircraft_after_subset) ([int64]19)
    Assert-Equal "train aircraft seed $($run.seed)" ([int64]$run.split_summary.aircraft.train.count) ([int64]13)
    Assert-Equal "validation aircraft seed $($run.seed)" ([int64]$run.split_summary.aircraft.validation.count) ([int64]2)
    Assert-Equal "test aircraft seed $($run.seed)" ([int64]$run.split_summary.aircraft.test.count) ([int64]4)

    $overlaps = $run.split_summary.aircraft.overlap_counts
    foreach ($name in @("train_validation", "train_test", "validation_test")) {
        if ([int64]$overlaps.$name -ne 0) {
            $overlapViolations += 1
        }
    }

    foreach ($attack in $run.split_summary.windows.per_attack.PSObject.Properties) {
        if ([int64]$attack.Value.malicious_windows -le 0) {
            throw "Missing malicious windows for seed $($run.seed), attack $($attack.Name)"
        }
    }
    $runsChecked += 1
}
Assert-Equal "preflight runs checked" $runsChecked 5
Assert-Equal "aircraft overlap violations" $overlapViolations 0

foreach ($marker in @(
    "sample_adsb_decoded.csv",
    $expectedSha,
    'Rows loaded: `216880`',
    'Rows after filtering: `75238`',
    'Aircraft overlap: `0`',
    "offline evaluations over recorded trajectory data",
    "do not interact with live aircraft",
    "not included in the submission bundle",
    "does not require downloading data or software"
)) {
    Assert-Contains $statementPath $statement $marker
}

foreach ($marker in @(
    "recorded trajectory data",
    "not to interfere with live aviation systems",
    "do not provide operational guidance",
    "layered safety and security architecture",
    "data preflight checks",
    "dataset SHA-256"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

foreach ($marker in @("Data split and leakage preflight audit", "Trajectory rows", "Aircraft", "Zero aircraft overlap")) {
    Assert-Contains "data_split_audit.tex" $auditTable $marker
}

Write-Output "data_provenance_ethics=PASSED"
Write-Output "sample_sha256=$sampleSha"
Write-Output "raw_snapshots_checked=$rawSnapshotsChecked"
Write-Output "preflight_runs_checked=$runsChecked"
Write-Output "aircraft_overlap_violations=$overlapViolations"
Write-Output "bundle_manifests_checked=$bundleManifestsChecked"

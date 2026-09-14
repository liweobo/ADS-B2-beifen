$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing external-validity-scope artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing external-validity marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains overbroad external-validity claim: $Needle"
    }
}

$auditPath = "EXTERNAL_VALIDITY_SCOPE_AUDIT.md"
$datasetAuditPath = "DATASET_PROFILE_AUDIT.md"
$paperPath = "paper_lncs\main.tex"
$preflightPath = "outputs\publication_benchmark\preflight_report.json"
$claimScopePath = "CLAIM_SCOPE_GUARDRAILS.md"
$readinessPath = "TOP_CONFERENCE_READINESS_AUDIT.md"
$completionPath = "SUBMISSION_COMPLETION_AUDIT.md"

foreach ($path in @($auditPath, $datasetAuditPath, $paperPath, $preflightPath, $claimScopePath, $readinessPath, $completionPath)) {
    Require-File $path
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$datasetAudit = Get-Content -Raw -Encoding UTF8 -LiteralPath $datasetAuditPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$claimScope = Get-Content -Raw -Encoding UTF8 -LiteralPath $claimScopePath
$readiness = Get-Content -Raw -Encoding UTF8 -LiteralPath $readinessPath
$completion = Get-Content -Raw -Encoding UTF8 -LiteralPath $completionPath
$preflight = Get-Content -Raw -Encoding UTF8 -LiteralPath $preflightPath | ConvertFrom-Json

$scopeMarkers = @(
    "one UTC day",
    "20 raw aircraft identifiers",
    "19 filtered aircraft",
    'rows after physical sanity filtering: `75238`',
    'raw rows: `217148`',
    "2016-12-31T23:00:01Z",
    "2017-01-01T23:00:00Z",
    'train/validation/test counts per seed: `13/2/4`',
    "other airspaces",
    "time periods",
    "aircraft populations",
    "sensor networks",
    "message fields",
    "operational deployment readiness",
    "universal ADS-B robustness",
    "threat model",
    "EXTERNAL_VALIDITY_SCOPE_AUDIT.md",
    "tools/verify_external_validity_scope.ps1"
)

foreach ($marker in $scopeMarkers[0..15]) {
    Assert-Contains $auditPath $audit $marker
}
foreach ($marker in @(
    "one UTC day",
    "20 raw aircraft identifiers",
    "19 filtered aircraft",
    "75,238 rows",
    "Results may change for other airspaces, time periods, aircraft populations, sensor networks, message fields"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}
foreach ($marker in @(
    "archived one-day decoded ADS-B",
    "20 raw aircraft identifiers",
    "19 filtered aircraft",
    "must not claim transfer to all airspaces"
)) {
    Assert-Contains "CLAIM_SCOPE_GUARDRAILS.md" $claimScope $marker
}
foreach ($marker in @("Dataset profile transparency", "Dataset transparency challenge")) {
    Assert-Contains "TOP_CONFERENCE_READINESS_AUDIT.md" $readiness $marker
}
foreach ($marker in @("External validity scope is bounded", "EXTERNAL_VALIDITY_SCOPE_AUDIT.md")) {
    Assert-Contains "SUBMISSION_COMPLETION_AUDIT.md" $completion $marker
}
Assert-Contains "DATASET_PROFILE_AUDIT.md" $datasetAudit "one UTC day"
Assert-Contains "DATASET_PROFILE_AUDIT.md" $datasetAudit "20 raw aircraft"

$counts = @(
    [pscustomobject]@{ name = "rows_loaded"; actual = [int]$preflight.dataset_summary.rows_loaded; expected = 216880 },
    [pscustomobject]@{ name = "rows_after_filter"; actual = [int]$preflight.dataset_summary.rows_after_filter; expected = 75238 },
    [pscustomobject]@{ name = "aircraft_loaded"; actual = [int]$preflight.dataset_summary.aircraft_loaded; expected = 20 },
    [pscustomobject]@{ name = "aircraft_after_filter"; actual = [int]$preflight.dataset_summary.aircraft_after_filter; expected = 19 },
    [pscustomobject]@{ name = "window_size"; actual = [int]$preflight.options.window_size; expected = 15 },
    [pscustomobject]@{ name = "seed_count"; actual = @($preflight.options.seeds).Count; expected = 5 },
    [pscustomobject]@{ name = "min_seeds"; actual = [int]$preflight.options.min_seeds; expected = 5 },
    [pscustomobject]@{ name = "runs"; actual = @($preflight.runs).Count; expected = 5 }
)
foreach ($count in $counts) {
    if ($count.actual -ne $count.expected) {
        throw "Preflight count mismatch for $($count.name): expected=$($count.expected) actual=$($count.actual)"
    }
}
foreach ($run in $preflight.runs) {
    $aircraft = $run.split_summary.aircraft
    if ([int]$aircraft.train.count -ne 13 -or [int]$aircraft.validation.count -ne 2 -or [int]$aircraft.test.count -ne 4) {
        throw "Unexpected split counts for seed $($run.seed)"
    }
}

$forbidden = @(
    "deployment-ready ADS-B",
    "operationally deployed",
    "universal ADS-B robustness",
    "generalizes to every airspace",
    "generalizes to all airspaces",
    "representative of all aircraft",
    "all sensor networks are covered",
    "proves transfer to"
)
foreach ($needle in $forbidden) {
    Assert-NotContains "paper_lncs/main.tex" $paper $needle
    Assert-NotContains "CLAIM_SCOPE_GUARDRAILS.md" $claimScope $needle
}

Write-Output "external_validity_scope=PASSED"
Write-Output "scope_markers_checked=$($scopeMarkers.Count)"
Write-Output "preflight_counts_checked=$($counts.Count)"
Write-Output "forbidden_generalization_claims_checked=$($forbidden.Count)"

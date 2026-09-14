param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required novelty-evidence file: $Path"
    }
}

function Require-Text {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Novelty evidence missing marker in ${Name}: ${Needle}"
    }
}

function Reject-Text {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Novelty evidence contains overclaim in ${Name}: ${Needle}"
    }
}

$innovationPath = "INNOVATION_AND_EVIDENCE.md"
$matrixPath = "PRIOR_ART_NOVELTY_MATRIX.md"
$snapshotPath = "PRIOR_ART_EVIDENCE_SNAPSHOT.md"
$coveragePath = "PRIOR_ART_CRITERIA_COVERAGE.tsv"
$texPath = "paper_lncs\main.tex"
$bibPath = "paper_lncs\references.bib"

foreach ($path in @($innovationPath, $matrixPath, $snapshotPath, $coveragePath, $texPath, $bibPath)) {
    Require-File $path
}

$innovation = Get-Content -Raw -Encoding UTF8 -LiteralPath $innovationPath
$matrix = Get-Content -Raw -Encoding UTF8 -LiteralPath $matrixPath
$snapshot = Get-Content -Raw -Encoding UTF8 -LiteralPath $snapshotPath
$coverage = Get-Content -Raw -Encoding UTF8 -LiteralPath $coveragePath
$coverageRows = @(Import-Csv -Delimiter "`t" -LiteralPath $coveragePath)
$tex = Get-Content -Raw -Encoding UTF8 -LiteralPath $texPath
$bib = Get-Content -Raw -Encoding UTF8 -LiteralPath $bibPath

$innovationMarkers = @(
    "What Is Not Claimed as New",
    "Literature Boundary Used for the Claim",
    "Falsifiable Novelty Test",
    "Jansen et al.",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "Physically Constrained Adversarial Training",
    "Paired Valid-Start Physical Attack Evaluation",
    "Targeted Anomalous-to-Normal Evasion Protocol",
    "Publication-Grade Reproducibility Gate"
)
foreach ($marker in $innovationMarkers) {
    Require-Text $innovationPath $innovation $marker
}

$matrixMarkers = @(
    "Falsifiable Novelty Criteria",
    "Representative Prior-Art Boundary",
    "Source Notes Checked on 2026-07-12",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "Wireless witnessing for ADS-B attacks",
    "Zhao et al. 2026",
    "ADS-B adversarial attacks: Luo et al.",
    "Exact phrase searches",
    "CAT-AD in this repository",
    "Allowed and Disallowed Claim Wording"
)
foreach ($marker in $matrixMarkers) {
    Require-Text $matrixPath $matrix $marker
}

$snapshotMarkers = @(
    "Checked on 2026-07-12",
    "Novelty Boundary",
    "External Source Evidence",
    "Negative Evidence Checks",
    "Repository Evidence",
    "https://www.ndss-symposium.org/ndss-paper/trust-the-crowd-wireless-witnessing-to-detect-attacks-on-ads-b-based-air-traffic-surveillance/",
    "10.14722/ndss.2021.24552",
    "https://doi.org/10.3390/s24113584",
    "10.1016/j.iot.2024.101416",
    "10.1016/j.array.2026.101012",
    "10.1016/j.cja.2026.104083",
    "10.1016/j.comnet.2026.112476",
    "10.1016/j.ast.2025.111199",
    "10.1016/j.eswa.2025.130781",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "https://doi.org/10.1109/COMST.2014.2365951",
    "https://openreview.net/forum?id=JcRbuE7FCJ",
    "to the best of our knowledge",
    "within the evaluated threat model"
)
foreach ($marker in $snapshotMarkers) {
    Require-Text $snapshotPath $snapshot $marker
}

foreach ($criterion in @("C1", "C2", "C3", "C4", "C5", "C6")) {
    Require-Text $matrixPath $matrix $criterion
    Require-Text $snapshotPath $snapshot $criterion
    Require-Text $coveragePath $coverage $criterion
}

$requiredCoverageColumns = @(
    "source_key",
    "source_label",
    "year",
    "C1",
    "C2",
    "C3",
    "C4",
    "C5",
    "C6",
    "source_url",
    "boundary"
)
$coverageColumns = @($coverageRows[0].PSObject.Properties.Name)
foreach ($column in $requiredCoverageColumns) {
    if ($coverageColumns -notcontains $column) {
        throw "Novelty coverage table missing column: $column"
    }
}
if ($coverageRows.Count -lt 22) {
    throw "Novelty coverage table has too few rows: $($coverageRows.Count)"
}
$allowedCoverageValues = @("yes", "no", "partial")
foreach ($row in $coverageRows) {
    foreach ($criterion in @("C1", "C2", "C3", "C4", "C5", "C6")) {
        $value = [string]$row.$criterion
        if ($allowedCoverageValues -notcontains $value.ToLowerInvariant()) {
            throw "Novelty coverage row $($row.source_key) has invalid ${criterion}: $value"
        }
    }
    if ([string]::IsNullOrWhiteSpace($row.source_key) -or [string]::IsNullOrWhiteSpace($row.boundary)) {
        throw "Novelty coverage row has missing key or boundary"
    }
}
$catadRows = @($coverageRows | Where-Object { $_.source_key -eq "catad_repository" })
if ($catadRows.Count -ne 1) {
    throw "Novelty coverage table must contain exactly one catad_repository row"
}
foreach ($criterion in @("C1", "C2", "C3", "C4", "C5", "C6")) {
    if ($catadRows[0].$criterion.ToLowerInvariant() -ne "yes") {
        throw "CAT-AD coverage row must be yes for $criterion"
    }
}
$fullPriorRows = @(
    $coverageRows | Where-Object {
        $_.source_key -ne "catad_repository" -and
        $_.C1.ToLowerInvariant() -eq "yes" -and
        $_.C2.ToLowerInvariant() -eq "yes" -and
        $_.C3.ToLowerInvariant() -eq "yes" -and
        $_.C4.ToLowerInvariant() -eq "yes" -and
        $_.C5.ToLowerInvariant() -eq "yes" -and
        $_.C6.ToLowerInvariant() -eq "yes"
    }
)
if ($fullPriorRows.Count -ne 0) {
    throw "Prior-art row fully subsumes CAT-AD C1-C6: $($fullPriorRows[0].source_key)"
}

$requiredCitationKeys = @(
    "strohmeier2015security",
    "schaefer2014opensky",
    "jansen2021trust",
    "fried2021autoencoders",
    "luo2021vaesvdd",
    "chevrot2022cae",
    "pirolley2026lowaltitude",
    "yue2026ocren",
    "cevik2025adsbanomalydetection",
    "ahmed2025adsbanomalous",
    "ahmed2026lightweightadsb",
    "ngamboe2025adsbids",
    "luo2024adversarialadsb",
    "zhong2026rdpaadsb",
    "zhao2026imdmpc",
    "shi2026securityadsbrid",
    "khan2025surveyadsbsecurity",
    "zhang2025adsbdatasecurity",
    "ahmed2026secureairtraffic",
    "wu2026reviewtrajectory",
    "goodfellow2015explaining",
    "madry2018towards",
    "carlini2017towards",
    "athalye2018obfuscated"
)
foreach ($key in $requiredCitationKeys) {
    Require-Text $bibPath $bib "{$key,"
    Require-Text $texPath $tex $key
    Require-Text $coveragePath $coverage $key
}

$texMarkers = @(
    "does not claim that ADS-B anomaly detection",
    "novelty claim is narrower",
    "To the best of our knowledge",
    "would subsume CAT-AD only if",
    "Define the valid-start set",
    "exact per-sample intersection"
)
foreach ($marker in $texMarkers) {
    Require-Text $texPath $tex $marker
}

$requiredImplementationRefs = @(
    "adsb/attacks.py",
    "adsb/training.py",
    "adsb/benchmark.py",
    "adsb/verify_artifacts.py",
    "tests/test_physical_metrics.py",
    "outputs/publication_benchmark/verification_report.md"
)
foreach ($ref in $requiredImplementationRefs) {
    Require-Text $innovationPath $innovation $ref
}

$overclaims = @(
    "first ever",
    "guaranteed novel",
    "proves no one has done this",
    "solves ADS-B security",
    "certified robust against all attacks"
)
foreach ($needle in $overclaims) {
    Reject-Text $innovationPath $innovation $needle
    Reject-Text $snapshotPath $snapshot $needle
    Reject-Text $texPath $tex $needle
}

Write-Output "novelty_evidence=PASSED"
Write-Output "innovation_markers_checked=$($innovationMarkers.Count)"
Write-Output "matrix_markers_checked=$($matrixMarkers.Count)"
Write-Output "snapshot_markers_checked=$($snapshotMarkers.Count)"
Write-Output "citation_keys_checked=$($requiredCitationKeys.Count)"
Write-Output "coverage_rows_checked=$($coverageRows.Count)"
Write-Output "full_prior_art_rows=0"

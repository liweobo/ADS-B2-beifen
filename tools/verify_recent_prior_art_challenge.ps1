param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing recent-prior-art artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing recent-prior-art marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden recent-prior-art overclaim: $Needle"
    }
}

$auditPath = "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md"
$innovationPath = "INNOVATION_AND_EVIDENCE.md"
$matrixPath = "PRIOR_ART_NOVELTY_MATRIX.md"
$snapshotPath = "PRIOR_ART_EVIDENCE_SNAPSHOT.md"
$texPath = "paper_lncs\main.tex"
$bibPath = "paper_lncs\references.bib"

foreach ($path in @($auditPath, $innovationPath, $matrixPath, $snapshotPath, $texPath, $bibPath)) {
    Require-File $path
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$auditFlat = [regex]::Replace($audit, "\s+", " ")
$innovation = Get-Content -Raw -Encoding UTF8 -LiteralPath $innovationPath
$matrix = Get-Content -Raw -Encoding UTF8 -LiteralPath $matrixPath
$snapshot = Get-Content -Raw -Encoding UTF8 -LiteralPath $snapshotPath
$tex = Get-Content -Raw -Encoding UTF8 -LiteralPath $texPath
$bib = Get-Content -Raw -Encoding UTF8 -LiteralPath $bibPath

$recentSources = @(
    [pscustomobject]@{
        key = "pirolley2026lowaltitude"
        source = "Pirolley et al., 2026"
        doi = "10.1016/j.ast.2025.111199"
        url = "https://doi.org/10.1016/j.ast.2025.111199"
    },
    [pscustomobject]@{
        key = "yue2026ocren"
        source = "Yue et al., 2026"
        doi = "10.1016/j.eswa.2025.130781"
        url = "https://doi.org/10.1016/j.eswa.2025.130781"
    },
    [pscustomobject]@{
        key = "cevik2025adsbanomalydetection"
        source = "Cevik and Akleylek, 2025"
        doi = "10.1016/j.iot.2024.101416"
        url = "https://doi.org/10.1016/j.iot.2024.101416"
    },
    [pscustomobject]@{
        key = "ahmed2025adsbanomalous"
        source = "Ahmed et al., 2025"
        doi = "10.7717/peerj-cs.2886"
        url = "https://doi.org/10.7717/peerj-cs.2886"
    },
    [pscustomobject]@{
        key = "ahmed2026lightweightadsb"
        source = "Ahmed et al., 2026"
        doi = "10.1016/j.array.2026.101012"
        url = "https://doi.org/10.1016/j.array.2026.101012"
    },
    [pscustomobject]@{
        key = "zhong2026rdpaadsb"
        source = "Zhong et al., 2026"
        doi = "10.1016/j.cja.2026.104083"
        url = "https://doi.org/10.1016/j.cja.2026.104083"
    },
    [pscustomobject]@{
        key = "zhao2026imdmpc"
        source = "Zhao et al., 2026"
        doi = "10.1016/j.comnet.2026.112476"
        url = "https://doi.org/10.1016/j.comnet.2026.112476"
    },
    [pscustomobject]@{
        key = "ngamboe2025adsbids"
        source = "Ngamboe et al., 2025"
        doi = "2510.08333"
        url = "https://arxiv.org/abs/2510.08333"
    },
    [pscustomobject]@{
        key = "khan2025surveyadsbsecurity"
        source = "Khan et al., 2025"
        doi = "10.1109/COMST.2024.3513213"
        url = "https://doi.org/10.1109/COMST.2024.3513213"
    },
    [pscustomobject]@{
        key = "zhang2025adsbdatasecurity"
        source = "Zhang et al., 2025"
        doi = "10.1145/3742763.3760698"
        url = "https://doi.org/10.1145/3742763.3760698"
    },
    [pscustomobject]@{
        key = "shi2026securityadsbrid"
        source = "Shi et al., 2026"
        doi = "10.3390/s26020634"
        url = "https://doi.org/10.3390/s26020634"
    },
    [pscustomobject]@{
        key = "ahmed2026secureairtraffic"
        source = "Ahmed et al., 2026"
        doi = "10.1109/OJCS.2026.3651384"
        url = "https://doi.org/10.1109/OJCS.2026.3651384"
    }
)

foreach ($marker in @(
    "Checked on 2026-07-12",
    "Challenge Sources",
    "Required Manuscript Effect",
    "joint C1-C6 protocol",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "to the best of our knowledge",
    "within the evaluated threat model"
)) {
    Assert-Contains $auditPath $auditFlat $marker
}

foreach ($source in $recentSources) {
    Assert-Contains $auditPath $auditFlat $source.source
    Assert-Contains $auditPath $auditFlat $source.doi
    Assert-Contains $auditPath $auditFlat $source.url
    Assert-Contains $snapshotPath $snapshot $source.doi
    Assert-Contains $snapshotPath $snapshot $source.url
    Assert-Contains $bibPath $bib "{$($source.key),"
    Assert-Contains $texPath $tex $source.key
}

foreach ($criterion in @("C1", "C2", "C3", "C4", "C5", "C6")) {
    Assert-Contains $auditPath $auditFlat $criterion
    Assert-Contains $matrixPath $matrix $criterion
    Assert-Contains $snapshotPath $snapshot $criterion
}

foreach ($marker in @(
    "Recent ADS-B IDS, attack-vector benchmarks, physics-consistent robust trajectory anomaly detection",
    "physics-consistent robust trajectory anomaly detection",
    "does not jointly satisfy C2-C6",
    "does not jointly satisfy C4-C6",
    "does not jointly satisfy C1-C6",
    "does not jointly provide physically constrained targeted adversarial training",
    "exact PV-ASR",
    "multi-seed publication gate"
)) {
    Assert-Contains $auditPath $auditFlat $marker
}

foreach ($marker in @(
    "Recent realistic-attack detectors, recovery methods, ADS-B IDS, security surveys, physics-consistent trajectory AD",
    "Pirolley et al. 2026",
    "Yue et al. 2026",
    "Cevik and Akleylek 2025",
    "Ahmed et al. 2025",
    "Ahmed et al. 2026",
    "Zhong et al. 2026",
    "Zhao et al. 2026",
    "Ngamboe et al. 2025",
    "Khan et al. 2025",
    "Zhang et al. 2025",
    "Shi et al. 2026",
    "Ahmed et al. 2026",
    "exact PV-ASR",
    "multi-seed publication gate"
)) {
    Assert-Contains $matrixPath $matrix $marker
}

foreach ($marker in @(
    "Recent ADS-B intrusion-detection work",
    "attack-vector benchmarks",
    "lightweight intrusion detection system (IDS) designs",
    "adversarial-perturbation detectors",
    "physics-consistent trajectory anomaly detection",
    "transformer and extended long short-term memory (xLSTM) transfer-learning models",
    "ADS-B data-security analyses",
    "ADS-B/Remote Identification (Remote ID) security taxonomies",
    "Same-Protocol Comparison with Recent Published ADS-B Detectors",
    "same-protocol comparison against three recent (2021--2022) ADS-B detectors",
    "controlled reimplementations, not exact reproductions",
    "To the best of our knowledge"
)) {
    Assert-Contains $texPath $tex $marker
}

foreach ($marker in @(
    "does not claim ADS-B IDS",
    "ADS-B anomaly detection",
    "attack-type classification",
    "lightweight IDS",
    "adversarial-perturbation detection",
    "xLSTM",
    "Transformer IDS",
    "data-security",
    "security surveys",
    "ADS-B/RID security surveys"
)) {
    Assert-Contains $auditPath $auditFlat $marker
}

foreach ($needle in @(
    "first ever",
    "guaranteed novel",
    "proves no one has done this",
    "solves ADS-B security",
    "certified robust against all attacks"
)) {
    Assert-NotContains $auditPath $auditFlat $needle
    Assert-NotContains $innovationPath $innovation $needle
    Assert-NotContains $snapshotPath $snapshot $needle
    Assert-NotContains $texPath $tex $needle
}

Write-Output "recent_prior_art_challenge=PASSED"
Write-Output "recent_sources_checked=$($recentSources.Count)"
Write-Output "criteria_checked=6"
Write-Output "paper_citations_checked=$($recentSources.Count)"

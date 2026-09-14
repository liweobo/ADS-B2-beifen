param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing dual-use safety artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing dual-use safety marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden operational marker: $Needle"
    }
}

$auditPath = "DUAL_USE_SAFETY_AUDIT.md"
$paperPath = "paper_lncs\main.tex"
$provenancePath = "DATA_PROVENANCE_AND_ETHICS.md"
$readmePath = "README.md"
$guidePath = "ARTIFACT_EVALUATION_GUIDE.md"
$quickstartPath = "REVIEWER_QUICKSTART.md"
$bundleManifestPath = "output\submission\catad_topconf_submission_bundle.manifest.tsv"

foreach ($path in @($auditPath, $paperPath, $provenancePath, $readmePath, $guidePath, $quickstartPath)) {
    Require-File $path
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$provenance = Get-Content -Raw -Encoding UTF8 -LiteralPath $provenancePath
$readme = Get-Content -Raw -Encoding UTF8 -LiteralPath $readmePath
$guide = Get-Content -Raw -Encoding UTF8 -LiteralPath $guidePath
$quickstart = Get-Content -Raw -Encoding UTF8 -LiteralPath $quickstartPath

$safetyMarkers = @(
    [pscustomobject]@{ Name = $auditPath; Text = $audit; Marker = "Dual-Use Safety Audit" },
    [pscustomobject]@{ Name = $auditPath; Text = $audit; Marker = "defensive, offline robustness evaluation" },
    [pscustomobject]@{ Name = $auditPath; Text = $audit; Marker = "transmit, replay, broadcast, or inject ADS-B messages" },
    [pscustomobject]@{ Name = $auditPath; Text = $audit; Marker = "SDR, radio, receiver-control, socket" },
    [pscustomobject]@{ Name = $auditPath; Text = $audit; Marker = "Disallowed Operational Use" },
    [pscustomobject]@{ Name = $auditPath; Text = $audit; Marker = "dual_use_safety=PASSED" },
    [pscustomobject]@{ Name = $paperPath; Text = $paper; Marker = "evaluated offline on recorded trajectory data" },
    [pscustomobject]@{ Name = $paperPath; Text = $paper; Marker = "not to interfere with live aviation systems" },
    [pscustomobject]@{ Name = $paperPath; Text = $paper; Marker = "do not provide operational guidance for injecting messages" },
    [pscustomobject]@{ Name = $paperPath; Text = $paper; Marker = "dual-use risk" },
    [pscustomobject]@{ Name = $provenancePath; Text = $provenance; Marker = "do not interact with live aircraft" },
    [pscustomobject]@{ Name = $provenancePath; Text = $provenance; Marker = "should not be used to inject, transmit, replay" },
    [pscustomobject]@{ Name = $provenancePath; Text = $provenance; Marker = "defensive anomaly-detection robustness" },
    [pscustomobject]@{ Name = $readmePath; Text = $readme; Marker = "operational aviation safety" },
    [pscustomobject]@{ Name = $readmePath; Text = $readme; Marker = "DUAL_USE_SAFETY_AUDIT.md" },
    [pscustomobject]@{ Name = $guidePath; Text = $guide; Marker = "does not certify operational aviation safety" },
    [pscustomobject]@{ Name = $guidePath; Text = $guide; Marker = "dual-use safety" },
    [pscustomobject]@{ Name = $quickstartPath; Text = $quickstart; Marker = "Dual-use safety boundary" }
)
foreach ($check in $safetyMarkers) {
    Assert-Contains $check.Name $check.Text $check.Marker
}

$codeFiles = @()
$codeFiles += Get-ChildItem -LiteralPath "adsb" -Recurse -File -Include *.py
$codeFiles += Get-ChildItem -LiteralPath "tools" -Recurse -File -Include *.py,*.ps1
$codeFiles = @($codeFiles | Sort-Object FullName -Unique)
$selfPath = (Resolve-Path -LiteralPath $MyInvocation.MyCommand.Path).Path

$forbiddenOperationalMarkers = @(
    "import socket",
    "from socket import",
    "import serial",
    "from serial import",
    "import scapy",
    "from scapy",
    "import rtlsdr",
    "from rtlsdr",
    "HackRF",
    "dump1090",
    "pyModeS",
    "1090ES transmitter",
    "air-traffic infrastructure API"
)

$scannedFiles = @()
foreach ($file in $codeFiles) {
    if ((Resolve-Path -LiteralPath $file.FullName).Path -eq $selfPath) {
        continue
    }
    $scannedFiles += $file
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $file.FullName
    foreach ($needle in $forbiddenOperationalMarkers) {
        Assert-NotContains $file.FullName $text $needle
    }
}

if (Test-Path -LiteralPath $bundleManifestPath -PathType Leaf) {
    $bundleManifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $bundleManifestPath
    Assert-Contains $bundleManifestPath $bundleManifest "DATA_PROVENANCE_AND_ETHICS.md"
    Assert-Contains $bundleManifestPath $bundleManifest "tools/verify_data_provenance_ethics.ps1"
}

Write-Output "dual_use_safety=PASSED"
Write-Output "safety_markers_checked=$($safetyMarkers.Count)"
Write-Output "forbidden_operational_markers_checked=$($forbiddenOperationalMarkers.Count)"
Write-Output "code_files_scanned=$($scannedFiles.Count)"

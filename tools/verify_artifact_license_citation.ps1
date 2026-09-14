param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing artifact-license/citation file: $Path"
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
        throw "$Name missing license/citation marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden license/citation claim: $Needle"
    }
}

$licensePath = Require-File "LICENSE"
$citationPath = Require-File "CITATION.cff"
$auditPath = Require-File "ARTIFACT_LICENSE_AND_CITATION_AUDIT.md"
$readmePath = Require-File "README.md"

$license = Get-Content -Raw -Encoding UTF8 -LiteralPath $licensePath
$citation = Get-Content -Raw -Encoding UTF8 -LiteralPath $citationPath
$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$readme = Get-Content -Raw -Encoding UTF8 -LiteralPath $readmePath

$licenseMarkers = @(
    "CAT-AD Anonymous Review Artifact Use Statement",
    "anonymous peer review",
    "Permitted review uses",
    "inspect the manuscript source",
    "run the documented no-download verification commands",
    "confidential review",
    "Restrictions during anonymous review",
    "do not redistribute the artifact publicly",
    "do not use the attack code against live aviation systems",
    "do not use the artifact to deanonymize the authors",
    "not a public open-source license",
    "public release license"
)
foreach ($marker in $licenseMarkers) {
    Assert-Contains "LICENSE" $license $marker
}

$citationMarkers = @(
    "cff-version: 1.2.0",
    "CAT-AD: Constrained Adversarial Training",
    "Anonymous",
    "Authors",
    "version: `"anonymous-review`"",
    "date-released: `"2026-07-05`"",
    "repository-code: `"anonymous-review-artifact`"",
    "cite the final paper and public artifact record"
)
foreach ($marker in $citationMarkers) {
    Assert-Contains "CITATION.cff" $citation $marker
}

foreach ($marker in @(
    "Review-Use Boundary",
    "Citation Boundary",
    "artifact_license_citation=PASSED",
    "does not grant a public open-source license"
)) {
    Assert-Contains "ARTIFACT_LICENSE_AND_CITATION_AUDIT.md" $audit $marker
}

foreach ($marker in @(
    "LICENSE",
    "CITATION.cff",
    "anonymous review"
)) {
    Assert-Contains "README.md" $readme $marker
}

$forbiddenClaims = @(
    "MIT License",
    "Apache License",
    "BSD License",
    "GPL",
    "CC BY",
    "public domain",
    "official artifact badge granted",
    "guaranteed acceptance"
)
foreach ($claim in $forbiddenClaims) {
    Assert-NotContains "LICENSE" $license $claim
    Assert-NotContains "CITATION.cff" $citation $claim
    Assert-NotContains "ARTIFACT_LICENSE_AND_CITATION_AUDIT.md" $audit $claim
}

Write-Output "artifact_license_citation=PASSED"
Write-Output "license_markers_checked=$($licenseMarkers.Count)"
Write-Output "citation_markers_checked=$($citationMarkers.Count)"
Write-Output "forbidden_claims_checked=$($forbiddenClaims.Count)"

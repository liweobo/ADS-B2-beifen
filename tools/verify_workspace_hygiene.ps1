param(
    [string]$BundlePath = "output\submission\catad_topconf_submission_bundle.zip"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Resolve-RepoPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $RepoRoot $Path)
}

function Require-File {
    param([string]$Path)
    $candidate = Resolve-RepoPath $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing workspace-hygiene artifact: $Path"
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
        throw "$Name missing workspace-hygiene marker: $Needle"
    }
}

function Get-BundleManifestRows {
    $candidates = @(
        (Join-Path $RepoRoot "BUNDLE_MANIFEST.tsv"),
        (Join-Path $RepoRoot "output\submission\catad_topconf_submission_bundle.manifest.tsv")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return @(Import-Csv -Delimiter "`t" -LiteralPath $candidate)
        }
    }
    throw "Could not locate a bundle manifest for workspace hygiene verification"
}

$auditPath = Require-File "WORKSPACE_HYGIENE_AUDIT.md"
$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath

$nonSubmissionArtifacts = @(
    "states_2018-05-28-14.csv",
    "states_2022-06-27-23.csv",
    "zhong.py",
    "lunwen.py",
    "adsb.zip",
    "paper_lncs_bundle.zip",
    "result.txt",
    "test.py",
    "11.txt"
)

$requiredEntrypoints = @(
    "BUNDLE_README.md",
    "check_submission_ready.ps1",
    "SUBMISSION_READINESS.md",
    "REVIEWER_QUICKSTART.md",
    "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md",
    "ARTIFACT_EVALUATION_GUIDE.md",
    "paper_lncs/main.tex",
    "output/pdf/catad_submission_preview.pdf"
)

foreach ($marker in @(
    "Submission Boundary",
    "Non-Submission Root Artifacts",
    "does not delete local files",
    "clean artifact boundary"
)) {
    Assert-Contains "WORKSPACE_HYGIENE_AUDIT.md" $audit $marker
}
foreach ($artifact in $nonSubmissionArtifacts) {
    Assert-Contains "WORKSPACE_HYGIENE_AUDIT.md" $audit $artifact
}

$manifest = @(Get-BundleManifestRows)
$manifestPaths = @($manifest | ForEach-Object { $_.path })
if ($manifestPaths.Count -lt 100) {
    throw "Bundle manifest is unexpectedly small: $($manifestPaths.Count)"
}

foreach ($entrypoint in $requiredEntrypoints) {
    if ($manifestPaths -notcontains $entrypoint) {
        throw "Bundle manifest missing reviewer entry point: $entrypoint"
    }
}

foreach ($artifact in $nonSubmissionArtifacts) {
    if ($manifestPaths -contains $artifact) {
        throw "Non-submission root artifact appears in bundle manifest: $artifact"
    }
    $prefixed = $manifestPaths | Where-Object { $_ -eq $artifact -or $_.StartsWith("$artifact/", [System.StringComparison]::OrdinalIgnoreCase) }
    if (@($prefixed).Count -gt 0) {
        throw "Non-submission artifact path appears in bundle manifest: $($prefixed[0])"
    }
}

$topLevelPython = @($manifestPaths |
    Where-Object { $_ -match '^[^/]+\.py$' } |
    Sort-Object)
if ($topLevelPython.Count -gt 0) {
    throw "Bundle contains unexpected top-level Python scratch files: $($topLevelPython -join ', ')"
}

$bundle = Resolve-RepoPath $BundlePath
$zipEntriesChecked = 0
if (Test-Path -LiteralPath $bundle -PathType Leaf) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $bundle).Path)
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName.Replace("\", "/") })
        foreach ($artifact in $nonSubmissionArtifacts) {
            $zipPath = "catad_topconf_submission_bundle/$artifact"
            if ($entries -contains $zipPath) {
                throw "Non-submission root artifact appears in bundle zip: $zipPath"
            }
            $zipEntriesChecked += 1
        }
        foreach ($entrypoint in $requiredEntrypoints) {
            $zipPath = "catad_topconf_submission_bundle/$entrypoint"
            if ($entries -notcontains $zipPath) {
                throw "Bundle zip missing reviewer entry point: $zipPath"
            }
            $zipEntriesChecked += 1
        }
    }
    finally {
        $zip.Dispose()
    }
}

$localPresent = @($nonSubmissionArtifacts |
    Where-Object { Test-Path -LiteralPath (Join-Path $RepoRoot $_) -PathType Leaf })

Write-Output "workspace_hygiene=PASSED"
Write-Output "non_submission_artifacts_documented=$($nonSubmissionArtifacts.Count)"
Write-Output "local_non_submission_artifacts_present=$($localPresent.Count)"
Write-Output "excluded_manifest_paths_checked=$($nonSubmissionArtifacts.Count)"
Write-Output "entrypoints_checked=$($requiredEntrypoints.Count)"
Write-Output "zip_entries_checked=$zipEntriesChecked"

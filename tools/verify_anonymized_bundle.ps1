param(
    [string]$BundlePath = "output\submission\catad_topconf_submission_bundle.zip",
    [string]$ExtractParent = "",
    [switch]$KeepExtracted
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

function Assert-OwnedTempPath {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $leaf = Split-Path -Leaf $resolved
    if (-not $leaf.StartsWith("catad_bundle_anonymity_", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected directory: $resolved"
    }
    return $resolved
}

function Assert-NoForbiddenText {
    param(
        [string]$Name,
        [string]$Text,
        [string[]]$Needles
    )
    foreach ($needle in $Needles) {
        if ($needle -and $Text.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Anonymity/path leak in ${Name}: ${needle}"
        }
    }
}

$bundle = Resolve-RepoPath $BundlePath
if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) {
    throw "Missing bundle zip: $bundle"
}

$parent = if ($ExtractParent) { Resolve-RepoPath $ExtractParent } else { $env:TEMP }
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$workDir = Join-Path $parent ("catad_bundle_anonymity_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory((Resolve-Path -LiteralPath $bundle).Path, $workDir)

    $bundleRoot = Join-Path $workDir "catad_topconf_submission_bundle"
    if (-not (Test-Path -LiteralPath $bundleRoot -PathType Container)) {
        $dirs = @(Get-ChildItem -LiteralPath $workDir -Directory -Force)
        if ($dirs.Count -eq 1) {
            $bundleRoot = $dirs[0].FullName
        }
        else {
            throw "Could not locate single bundle root under $workDir"
        }
    }

    $userProfile = [string]$env:USERPROFILE
    $userName = [string]$env:USERNAME
    $repoLeaf = Split-Path -Leaf $RepoRoot
    $condaRoot = "anaconda3"
    $forbidden = @(
        $userProfile,
        $userProfile.Replace("\", "/"),
        $userProfile.Replace("\", "\\"),
        "C:\Users\$userName",
        "C:/Users/$userName",
        "C:\\Users\\$userName",
        "Users\$userName\Desktop",
        "Users/$userName/Desktop",
        "Users\\$userName\\Desktop",
        "Desktop\$repoLeaf",
        "Desktop/$repoLeaf",
        "Desktop\\$repoLeaf",
        "$condaRoot\envs\testtorch",
        "$condaRoot/envs/testtorch",
        "$condaRoot\\envs\\testtorch"
    ) | Where-Object { $_ } | Sort-Object -Unique
    $forbiddenPlaceholders = @(
        "<USER_HOME>\Desktop",
        "<USER_HOME>/Desktop",
        "<USER_HOME>\\Desktop"
    ) | Where-Object { $_ } | Sort-Object -Unique

    $textExtensions = @(
        ".csv", ".html", ".json", ".log", ".md", ".ps1", ".py", ".tex", ".tsv", ".txt"
    )
    $files = Get-ChildItem -LiteralPath $bundleRoot -Recurse -Force -File |
        Where-Object { $textExtensions -contains $_.Extension.ToLowerInvariant() }
    foreach ($file in $files) {
        $relative = $file.FullName.Substring((Resolve-Path -LiteralPath $bundleRoot).Path.Length + 1).Replace("\", "/")
        $text = Get-Content -Raw -LiteralPath $file.FullName
        if ($null -eq $text) {
            $text = ""
        }
        Assert-NoForbiddenText $relative $text $forbidden
        if ($relative -notin @("tools/package_submission_bundle.ps1", "tools/verify_anonymized_bundle.ps1")) {
            Assert-NoForbiddenText $relative $text $forbiddenPlaceholders
        }
        if ($relative -notlike "tools/verify_anonymized_bundle.ps1") {
            $driveMatches = [regex]::Matches($text, "(?im)(^|[^A-Za-z])[A-Z]:[\\/]")
            if ($driveMatches.Count -gt 0) {
                throw "Absolute drive path leak in ${relative}: $($driveMatches[0].Value.Trim())"
            }
        }
    }

    $manifestJson = Join-Path $bundleRoot "BUNDLE_MANIFEST.json"
    if (Test-Path -LiteralPath $manifestJson -PathType Leaf) {
        $summary = Get-Content -Raw -LiteralPath $manifestJson | ConvertFrom-Json
        foreach ($field in @("zip_path", "manifest_tsv", "manifest_json")) {
            $value = [string]$summary.$field
            if ([System.IO.Path]::IsPathRooted($value)) {
                throw "Bundle summary field should be relative: $field=$value"
            }
        }
    }

    Write-Output "anonymized_bundle=PASSED"
    Write-Output "text_files_checked=$($files.Count)"
    Write-Output "forbidden_patterns_checked=$($forbidden.Count)"
}
finally {
    if (-not $KeepExtracted -and (Test-Path -LiteralPath $workDir)) {
        $safePath = Assert-OwnedTempPath $workDir
        Remove-Item -LiteralPath $safePath -Recurse -Force
    }
}

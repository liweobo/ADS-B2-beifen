param(
    [string]$ManuscriptPath = "paper_lncs\main.tex",
    [string]$PreviewHtml = "output\pdf\catad_submission_preview.html",
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

function Require-File {
    param([string]$Path)
    $resolved = Resolve-RepoPath $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Missing double-blind review artifact: $Path"
    }
    return (Resolve-Path -LiteralPath $resolved).Path
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing double-blind marker: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Needle -and $Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains identity leak: $Needle"
    }
}

function Assert-NoIdentityText {
    param(
        [string]$Name,
        [string]$Text
    )
    $userProfile = [string]$env:USERPROFILE
    $userName = [string]$env:USERNAME
    $repoLeaf = Split-Path -Leaf $RepoRoot
    $condaRoot = "anaconda3"
    $driveRoot = "C:"
    $windowsUsers = $driveRoot + "\Users"
    $forwardUsers = $driveRoot + "/Users"
    $escapedUsers = $driveRoot + "\\Users"
    $needles = @(
        $userProfile,
        $userProfile.Replace("\", "/"),
        $userProfile.Replace("\", "\\"),
        "$windowsUsers\$userName",
        "$forwardUsers/$userName",
        "$escapedUsers\\$userName",
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
    foreach ($needle in $needles) {
        Assert-NotContains $Name $Text $needle
    }
    if ($userName -and $userName.Length -ge 3) {
        $userNamePattern = "(?i)(^|[^A-Za-z0-9_])" + [regex]::Escape($userName) + "([^A-Za-z0-9_]|$)"
        if ([regex]::IsMatch($Text, $userNamePattern)) {
            throw "$Name contains current username token: $userName"
        }
    }
}

function Assert-NoContactOrAcknowledgment {
    param(
        [string]$Name,
        [string]$Text
    )
    foreach ($needle in @("\thanks", "\email", "\orcid", "\institute{Department", "\institute{University", "Acknowledgments", "Acknowledgements")) {
        Assert-NotContains $Name $Text $needle
    }
    if ([regex]::IsMatch($Text, "(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}")) {
        throw "$Name contains email-like contact information"
    }
    if ([regex]::IsMatch($Text, "(?i)orcid\.org/[0-9X-]{15,}")) {
        throw "$Name contains ORCID-like identifier"
    }
}

function Assert-OwnedTempPath {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $leaf = Split-Path -Leaf $resolved
    if (-not $leaf.StartsWith("catad_double_blind_", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected directory: $resolved"
    }
    return $resolved
}

$manuscriptFile = Require-File $ManuscriptPath
$previewFile = Require-File $PreviewHtml
$bundleFile = Require-File $BundlePath

$manuscript = Get-Content -Raw -Encoding UTF8 -LiteralPath $manuscriptFile
$preview = Get-Content -Raw -Encoding UTF8 -LiteralPath $previewFile

Assert-Contains "paper_lncs/main.tex" $manuscript "\author{Anonymous Authors}"
Assert-Contains "paper_lncs/main.tex" $manuscript "\authorrunning{Anonymous Authors}"
Assert-Contains "paper_lncs/main.tex" $manuscript "\institute{Anonymous Institution}"
Assert-NoContactOrAcknowledgment "paper_lncs/main.tex" $manuscript
Assert-NoIdentityText "paper_lncs/main.tex" $manuscript

Assert-Contains "catad_submission_preview.html" $preview '<meta name="author" content="Anonymous Authors"'
Assert-Contains "catad_submission_preview.html" $preview '<p class="author">Anonymous Authors</p>'
Assert-Contains "catad_submission_preview.html" $preview '<p class="date">Anonymous Institution</p>'
Assert-NoContactOrAcknowledgment "catad_submission_preview.html" $preview
Assert-NoIdentityText "catad_submission_preview.html" $preview

$parent = if ($ExtractParent) { Resolve-RepoPath $ExtractParent } else { $env:TEMP }
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$workDir = Join-Path $parent ("catad_double_blind_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($bundleFile, $workDir)

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

    $bundleManuscriptPath = Join-Path $bundleRoot "paper_lncs\main.tex"
    $bundlePreviewPath = Join-Path $bundleRoot "output\pdf\catad_submission_preview.html"
    $bundleReadmePath = Join-Path $bundleRoot "BUNDLE_README.md"
    foreach ($path in @($bundleManuscriptPath, $bundlePreviewPath, $bundleReadmePath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Extracted bundle missing reviewer-facing file: $path"
        }
    }
    foreach ($item in @(
            @{ Name = "bundle paper_lncs/main.tex"; Path = $bundleManuscriptPath },
            @{ Name = "bundle output/pdf/catad_submission_preview.html"; Path = $bundlePreviewPath },
            @{ Name = "bundle BUNDLE_README.md"; Path = $bundleReadmePath }
        )) {
        $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $item.Path
        Assert-NoIdentityText $item.Name $text
        Assert-NoContactOrAcknowledgment $item.Name $text
    }
    $bundleManuscript = Get-Content -Raw -Encoding UTF8 -LiteralPath $bundleManuscriptPath
    Assert-Contains "bundle paper_lncs/main.tex" $bundleManuscript "\author{Anonymous Authors}"
    Assert-Contains "bundle paper_lncs/main.tex" $bundleManuscript "\authorrunning{Anonymous Authors}"
    Assert-Contains "bundle paper_lncs/main.tex" $bundleManuscript "\institute{Anonymous Institution}"

    Write-Output "double_blind_submission=PASSED"
    Write-Output "manuscript_identity=PASSED"
    Write-Output "preview_identity=PASSED"
    Write-Output "bundle_identity=PASSED"
}
finally {
    if (-not $KeepExtracted -and (Test-Path -LiteralPath $workDir)) {
        $safePath = Assert-OwnedTempPath $workDir
        Remove-Item -LiteralPath $safePath -Recurse -Force
    }
}

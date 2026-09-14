param(
    [string]$PreviewHtml = "output\pdf\catad_submission_preview.html",
    [string]$PreviewPdf = "output\pdf\catad_submission_preview.pdf"
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
        throw "Missing preview artifact: $Path"
    }
    return $candidate
}

function Find-PdfTool {
    param([string]$Name)
    $nativePoppler = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\native\poppler\Library\bin"
    $candidate = Join-Path $nativePoppler "$Name.exe"
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        return $candidate
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    throw "Required PDF verification tool not found: $Name"
}

function Assert-OwnedTempPath {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $leaf = Split-Path -Leaf $resolved
    if (-not $leaf.StartsWith("adsb_preview_artifact_", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected directory: $resolved"
    }
    return $resolved
}

$htmlPath = Require-File $PreviewHtml
$pdfPath = Require-File $PreviewPdf
$pandocLogPath = [System.IO.Path]::ChangeExtension($htmlPath, $null) + "_pandoc.log"
if (Test-Path -LiteralPath $pandocLogPath -PathType Leaf) {
    $pandocLog = Get-Content -Raw -LiteralPath $pandocLogPath
    if ($pandocLog.IndexOf("[WARNING]", [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Preview Pandoc log contains warnings: $pandocLogPath"
    }
}

$html = Get-Content -Raw -Encoding UTF8 -LiteralPath $htmlPath
$requiredHtmlMarkers = @(
    "CAT-AD: Constrained Adversarial Training",
    "The contributions are",
    "Multi-seed detection and robustness summary over five matched aircraft splits/seeds",
    "Paired multi-seed comparison",
    "Projection-based Phys-PGD",
    "Penalty-based Phys-PGD",
    "PV-ASR",
    "Attack Evaluation Sanity Checks",
    "gradient masking",
    "Statistical Interpretation",
    "conclusive hypothesis-test evidence",
    "Ethical Considerations",
    "Limitations",
    "Threats to Validity",
    "Construct Validity",
    "Internal Validity",
    "External Validity",
    "Artifact Validity",
    '<h1 id="references">References</h1>',
    "Luo, Peng",
    "Madry, Aleksander",
    "fig_main_robustness.png",
    "fig_physical_valid_asr.png",
    "fig_epsilon_sensitivity.png"
)
foreach ($marker in $requiredHtmlMarkers) {
    if (-not $html.Contains($marker)) {
        throw "Preview HTML missing expected review marker: $marker"
    }
}

$forbiddenHtmlMarkers = @(
    "begin{aligned}",
    "<embed",
    "TODO",
    "TBD",
    "FIXME",
    "PLACEHOLDER",
    ([string][char]0x9225),
    ([string][char]0x807d)
)
foreach ($marker in $forbiddenHtmlMarkers) {
    if ($html.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Preview HTML contains forbidden marker: $marker"
    }
}

$pdfItem = Get-Item -LiteralPath $pdfPath
if ($pdfItem.Length -lt 100000) {
    throw "Preview PDF is unexpectedly small: $($pdfItem.Length) bytes"
}

$pdfinfo = Find-PdfTool "pdfinfo"
$info = & $pdfinfo $pdfPath 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "pdfinfo failed for preview PDF"
}
$pagesMatch = [regex]::Match($info, "Pages:\s+(\d+)")
if (-not $pagesMatch.Success) {
    throw "pdfinfo did not report a page count"
}
$pages = [int]$pagesMatch.Groups[1].Value
if ($pages -lt 6) {
    throw "Preview PDF has too few pages for the full manuscript: $pages"
}
if ($info -notmatch "Page size:.*A4") {
    throw "Preview PDF is not reported as A4"
}
if ($info -match "Encrypted:\s+yes") {
    throw "Preview PDF should not be encrypted"
}

$pdftoppm = Find-PdfTool "pdftoppm"
$renderDir = Join-Path $env:TEMP ("adsb_preview_artifact_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $renderDir | Out-Null
try {
    $prefix = Join-Path $renderDir "preview"
    & $pdftoppm -png -r 72 $pdfPath $prefix
    if ($LASTEXITCODE -ne 0) {
        throw "pdftoppm failed for preview PDF"
    }

    $rendered = @(Get-ChildItem -LiteralPath $renderDir -Filter "*.png" -File)
    if ($rendered.Count -ne $pages) {
        throw "Preview PDF render check expected $pages page PNGs; found $($rendered.Count)"
    }
    foreach ($png in $rendered) {
        if ($png.Length -lt 10000) {
            throw "Rendered preview page looks too small: $($png.Name)"
        }
    }
}
finally {
    if (Test-Path -LiteralPath $renderDir) {
        $safePath = Assert-OwnedTempPath $renderDir
        Remove-Item -LiteralPath $safePath -Recurse -Force
    }
}

Write-Output "preview_artifact=PASSED"
Write-Output "html_markers_checked=$($requiredHtmlMarkers.Count)"
Write-Output "pandoc_log_warnings=0"
Write-Output "pdf_pages=$pages"
Write-Output "pdf_bytes=$($pdfItem.Length)"
Write-Output "rendered_pages_checked=$($rendered.Count)"

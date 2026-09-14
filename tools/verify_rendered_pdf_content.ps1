param(
    [string]$PreviewHtml = "output\pdf\catad_submission_preview.html",
    [string]$PreviewPdf = "output\pdf\catad_submission_preview.pdf",
    [string]$FormalPdf = "output\pdf\catad_submission_latex_updated.pdf"
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
        throw "Missing rendered-PDF artifact: $Path"
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
        throw "$Name missing rendered-PDF marker: $Needle"
    }
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
    if (-not $leaf.StartsWith("catad_rendered_pdf_", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected directory: $resolved"
    }
    return $resolved
}

function Measure-RenderedPage {
    param([string]$Path)

    Add-Type -AssemblyName System.Drawing
    $bitmap = [System.Drawing.Bitmap]::new($Path)
    try {
        $width = $bitmap.Width
        $height = $bitmap.Height
        $nonWhite = 0
        $dark = 0
        $samples = 0
        $minX = $width
        $minY = $height
        $maxX = 0
        $maxY = 0

        for ($y = 0; $y -lt $height; $y += 4) {
            for ($x = 0; $x -lt $width; $x += 4) {
                $samples += 1
                $color = $bitmap.GetPixel($x, $y)
                $isInk = ($color.R -lt 245 -or $color.G -lt 245 -or $color.B -lt 245)
                if ($isInk) {
                    $nonWhite += 1
                    if ($x -lt $minX) { $minX = $x }
                    if ($x -gt $maxX) { $maxX = $x }
                    if ($y -lt $minY) { $minY = $y }
                    if ($y -gt $maxY) { $maxY = $y }
                    if ($color.R -lt 60 -and $color.G -lt 60 -and $color.B -lt 60) {
                        $dark += 1
                    }
                }
            }
        }

        if ($nonWhite -eq 0) {
            $minX = 0
            $maxX = 0
            $minY = 0
            $maxY = 0
        }

        return [pscustomobject]@{
            Width = $width
            Height = $height
            Samples = $samples
            NonWhite = $nonWhite
            Dark = $dark
            MinX = $minX
            MaxX = $maxX
            MinY = $minY
            MaxY = $maxY
            BoxWidth = [Math]::Max(0, $maxX - $minX)
            BoxHeight = [Math]::Max(0, $maxY - $minY)
            FileBytes = (Get-Item -LiteralPath $Path).Length
        }
    }
    finally {
        $bitmap.Dispose()
    }
}

function Test-RenderedPdf {
    param(
        [string]$Path,
        [string]$PdfTool,
        [int]$PageCount,
        [int]$ExpectedWidth,
        [int]$ExpectedHeight,
        [int64]$MinFileBytes,
        [int]$MinNonWhite,
        [int]$MinDark,
        [int]$MinBoxWidth,
        [int]$MinBoxHeight,
        [string]$Label
    )

    $renderDir = Join-Path $env:TEMP ("catad_rendered_pdf_" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $renderDir | Out-Null
    $nonblankPages = 0
    $sampledPixels = 0
    $totalNonWhite = 0
    $totalDark = 0
    try {
        $prefix = Join-Path $renderDir $Label
        & $PdfTool -png -r 72 $Path $prefix
        if ($LASTEXITCODE -ne 0) {
            throw "pdftoppm failed for $Label PDF"
        }

        $rendered = @(Get-ChildItem -LiteralPath $renderDir -Filter "*.png" -File | Sort-Object Name)
        if ($rendered.Count -ne $PageCount) {
            throw "$Label rendered page count mismatch: expected=$PageCount actual=$($rendered.Count)"
        }

        foreach ($png in $rendered) {
            $stats = Measure-RenderedPage $png.FullName
            $sampledPixels += $stats.Samples
            $totalNonWhite += $stats.NonWhite
            $totalDark += $stats.Dark

            if ($stats.Width -ne $ExpectedWidth -or $stats.Height -ne $ExpectedHeight) {
                throw "$Label rendered page has unexpected dimensions: $($png.Name) width=$($stats.Width) height=$($stats.Height)"
            }
            if ($stats.FileBytes -lt $MinFileBytes) {
                throw "$Label rendered page file is unexpectedly small: $($png.Name) bytes=$($stats.FileBytes)"
            }
            if ($stats.NonWhite -lt $MinNonWhite) {
                throw "$Label rendered page appears too blank: $($png.Name) nonwhite_samples=$($stats.NonWhite)"
            }
            if ($stats.Dark -lt $MinDark) {
                throw "$Label rendered page has too few dark text/line samples: $($png.Name) dark_samples=$($stats.Dark)"
            }
            if ($stats.BoxWidth -lt $MinBoxWidth -or $stats.BoxHeight -lt $MinBoxHeight) {
                throw "$Label rendered page content bounding box is too small: $($png.Name) box=$($stats.BoxWidth)x$($stats.BoxHeight)"
            }
            if ($stats.MinX -le 0 -or $stats.MinY -le 0 -or $stats.MaxX -ge ($stats.Width - 1) -or $stats.MaxY -ge ($stats.Height - 1)) {
                throw "$Label rendered page content appears clipped at the bitmap edge: $($png.Name)"
            }
            $nonblankPages += 1
        }

        return [pscustomobject]@{
            Pages = $nonblankPages
            SampledPixels = $sampledPixels
            NonWhite = $totalNonWhite
            Dark = $totalDark
        }
    }
    finally {
        if (Test-Path -LiteralPath $renderDir) {
            $safePath = Assert-OwnedTempPath $renderDir
            Remove-Item -LiteralPath $safePath -Recurse -Force
        }
    }
}

$htmlPath = Require-File $PreviewHtml
$pdfPath = Require-File $PreviewPdf
$formalPdfPath = Require-File $FormalPdf
$auditPath = Require-File "RENDERED_PDF_CONTENT_AUDIT.md"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Rendered-Artifact Checks",
    "exactly 11 pages",
    "595 x 842",
    "formal LNCS PDF",
    "exactly 18 pages",
    "612 x 792",
    "non-white sampled pixels",
    "content bounding box",
    "blank, truncated, missing major content"
)) {
    Assert-Contains "RENDERED_PDF_CONTENT_AUDIT.md" $audit $marker
}

$html = Get-Content -Raw -Encoding UTF8 -LiteralPath $htmlPath
$requiredHtmlMarkers = @(
    "CAT-AD: Constrained Adversarial Training",
    "The contributions are",
    "Trajectory Detector",
    "CAT-AD Training Objective",
    "methodimplementation-traceability",
    "Experimental Setting",
    "Aircraft leakage",
    "Multi-seed detection and robustness summary over five matched aircraft splits/seeds",
    "Paired multi-seed comparison",
    "Projection-based Phys-PGD",
    "Penalty-based Phys-PGD",
    "PV-ASR",
    "Attack Evaluation Sanity Checks",
    "gradient masking",
    "Statistical Interpretation",
    "Published-Model Comparison",
    "Same-Protocol Comparison",
    "protocol-aligned reimplementations",
    "Ethical Considerations",
    "Limitations",
    "Threats to Validity",
    "Construct validity",
    "External validity",
    '<h1 id="references">References</h1>',
    "fig_main_robustness.png",
    "fig_physical_valid_asr.png",
    "fig_epsilon_sensitivity.png"
)
foreach ($marker in $requiredHtmlMarkers) {
    Assert-Contains "preview HTML" $html $marker
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
if ($pages -ne 11) {
    throw "Expected the current review preview to render as 11 pages; got $pages"
}
if ($info -notmatch "Page size:.*A4") {
    throw "Preview PDF is not reported as A4"
}
if ($info -match "Encrypted:\s+yes") {
    throw "Preview PDF should not be encrypted"
}

$pdftoppm = Find-PdfTool "pdftoppm"
$previewRender = Test-RenderedPdf `
    -Path $pdfPath `
    -PdfTool $pdftoppm `
    -PageCount $pages `
    -ExpectedWidth 595 `
    -ExpectedHeight 842 `
    -MinFileBytes 50000 `
    -MinNonWhite 900 `
    -MinDark 20 `
    -MinBoxWidth 430 `
    -MinBoxHeight 100 `
    -Label "preview"

$formalItem = Get-Item -LiteralPath $formalPdfPath
if ($formalItem.Length -lt 100000) {
    throw "Formal PDF is unexpectedly small: $($formalItem.Length) bytes"
}
$formalInfo = & $pdfinfo $formalPdfPath 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "pdfinfo failed for formal LNCS PDF"
}
$formalPagesMatch = [regex]::Match($formalInfo, "Pages:\s+(\d+)")
if (-not $formalPagesMatch.Success) {
    throw "pdfinfo did not report a formal PDF page count"
}
$formalPages = [int]$formalPagesMatch.Groups[1].Value
if ($formalPages -ne 18) {
    throw "Expected the current formal LNCS PDF to render as 18 pages; got $formalPages"
}
if ($formalInfo -notmatch "Page size:\s+612 x 792 pts") {
    throw "Formal LNCS PDF does not use the expected 612 x 792 point page size"
}
if ($formalInfo -match "Encrypted:\s+yes") {
    throw "Formal LNCS PDF should not be encrypted"
}

$formalRender = Test-RenderedPdf `
    -Path $formalPdfPath `
    -PdfTool $pdftoppm `
    -PageCount $formalPages `
    -ExpectedWidth 612 `
    -ExpectedHeight 792 `
    -MinFileBytes 20000 `
    -MinNonWhite 500 `
    -MinDark 12 `
    -MinBoxWidth 320 `
    -MinBoxHeight 120 `
    -Label "formal"

Write-Output "rendered_pdf_content=PASSED"
Write-Output "pages_checked=$pages"
Write-Output "formal_pages_checked=$formalPages"
Write-Output "html_markers_checked=$($requiredHtmlMarkers.Count)"
Write-Output "nonblank_pages_checked=$($previewRender.Pages)"
Write-Output "formal_nonblank_pages_checked=$($formalRender.Pages)"
Write-Output "sampled_pixels_checked=$($previewRender.SampledPixels)"
Write-Output "formal_sampled_pixels_checked=$($formalRender.SampledPixels)"
Write-Output "nonwhite_samples_checked=$($previewRender.NonWhite)"
Write-Output "formal_nonwhite_samples_checked=$($formalRender.NonWhite)"
Write-Output "dark_samples_checked=$($previewRender.Dark)"
Write-Output "formal_dark_samples_checked=$($formalRender.Dark)"

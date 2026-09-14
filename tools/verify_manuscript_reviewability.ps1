param(
    [string]$PaperTex = "paper_lncs\main.tex",
    [string]$ReferencesBib = "paper_lncs\references.bib",
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
        throw "Missing manuscript-reviewability artifact: $Path"
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
        throw "$Name missing expected reviewability marker: $Needle"
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

$paperPath = Require-File $PaperTex
$bibPath = Require-File $ReferencesBib
$htmlPath = Require-File $PreviewHtml
$pdfPath = Require-File $PreviewPdf

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$bib = Get-Content -Raw -Encoding UTF8 -LiteralPath $bibPath
$html = Get-Content -Raw -Encoding UTF8 -LiteralPath $htmlPath
$htmlFlat = [regex]::Replace($html, "\s+", " ")

Assert-Contains "paper_lncs/main.tex" $paper "\author{Anonymous Authors}"
Assert-Contains "paper_lncs/main.tex" $paper "\institute{Anonymous Institution}"
Assert-Contains "preview HTML" $html '<meta name="author" content="Anonymous Authors"'
Assert-Contains "preview HTML" $html '<p class="author">Anonymous Authors</p>'

$titleMatch = [regex]::Match($paper, "\\title\{([^}]+)\}", [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $titleMatch.Success) {
    throw "Manuscript title is missing"
}
$title = [regex]::Replace($titleMatch.Groups[1].Value, "\s+", " ").Trim()
if ($title.Length -lt 20 -or $title.Length -gt 140) {
    throw "Manuscript title length is outside the reviewability bound: $($title.Length)"
}
Assert-Contains "preview HTML" $html $title

$abstractMatch = [regex]::Match($paper, "\\begin\{abstract\}(.*?)\\end\{abstract\}", [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $abstractMatch.Success) {
    throw "Manuscript abstract is missing"
}
$abstractSource = $abstractMatch.Groups[1].Value
$abstractPlain = [regex]::Replace($abstractSource, "%.*", " ")
$abstractPlain = [regex]::Replace($abstractPlain, "\\cite\{[^}]*\}", " ")
$abstractPlain = [regex]::Replace($abstractPlain, "\\[a-zA-Z]+\*?(?:\[[^\]]*\])?", " ")
$abstractPlain = [regex]::Replace($abstractPlain, "[{}$~^_\\]", " ")
$abstractWords = [regex]::Matches($abstractPlain, "[A-Za-z0-9]+(?:-[A-Za-z0-9]+)?").Count
if ($abstractWords -lt 60 -or $abstractWords -gt 180) {
    throw "Abstract word count is outside the reviewability bound: $abstractWords"
}
foreach ($marker in @(
    "targeted anomalous-to-normal evasion threat model",
    "physically constrained adversarial training",
    "All robustness claims are limited"
)) {
    Assert-Contains "paper_lncs/main.tex abstract" $abstractSource $marker
}

$contribMatch = [regex]::Match($paper, "The contributions are:\s*\\begin\{itemize\}(.*?)\\end\{itemize\}", [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $contribMatch.Success) {
    throw "Contribution itemize block is missing"
}
$contributionItems = @([regex]::Matches($contribMatch.Groups[1].Value, "\\item\s+"))
if ($contributionItems.Count -ne 3) {
    throw "Expected exactly 3 contribution items; found $($contributionItems.Count)"
}
foreach ($marker in @(
    "constrained adversarial training framework",
    "targeted anomalous-to-normal evaluation protocol",
    "reproducible multi-seed benchmark pipeline"
)) {
    Assert-Contains "contribution block" $contribMatch.Groups[1].Value $marker
}

$requiredSections = @(
    "Introduction",
    "Related Work",
    "Method",
    "Experimental Setting",
    "Main Robustness Results",
    "Physical Feasibility Analysis",
    "Ablation Summary and Sensitivity Analysis",
    "Reproducibility and Artifact Availability",
    "Ethical Considerations",
    "Limitations",
    "Threats to Validity",
    "Conclusion"
)
$previousIndex = -1
foreach ($section in $requiredSections) {
    $needle = "\section{$section}"
    $index = $paper.IndexOf($needle, [System.StringComparison]::Ordinal)
    if ($index -lt 0) {
        throw "Manuscript missing required section: $section"
    }
    if ($index -le $previousIndex) {
        throw "Manuscript section order is invalid near: $section"
    }
    $previousIndex = $index
    Assert-Contains "preview HTML" $htmlFlat $section
}
Assert-Contains "preview HTML" $htmlFlat '<h1 id="references">References</h1>'

$requiredReviewMarkers = @(
    "Positioning against prior work",
    "Table~\ref{tab:positioning}",
    "not interpreted as conclusive hypothesis-test evidence",
    "Attack Evaluation Sanity Checks",
    "Peer-review acceptance and venue-specific policy compliance remain external",
    "Construct validity",
    "Internal validity",
    "External validity",
    "Artifact validity"
)
foreach ($marker in $requiredReviewMarkers) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$citeKeys = [regex]::Matches($paper, "\\cite\{([^}]+)\}") |
    ForEach-Object { $_.Groups[1].Value.Split(",") } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ } |
    Sort-Object -Unique
if (@($citeKeys).Count -lt 10) {
    throw "Expected at least 10 unique citation keys; found $(@($citeKeys).Count)"
}
$bibKeys = [regex]::Matches($bib, "@\w+\{([^,]+),") |
    ForEach-Object { $_.Groups[1].Value.Trim() } |
    Sort-Object -Unique
foreach ($key in $citeKeys) {
    if ($bibKeys -notcontains $key) {
        throw "Missing bibliography entry for citation key: $key"
    }
}

$forbiddenMarkers = @(
    "TODO",
    "TBD",
    "FIXME",
    "PLACEHOLDER",
    "???",
    "\lambda_{\rm",
    "begin{aligned}",
    "<embed"
)
foreach ($marker in $forbiddenMarkers) {
    if ($paper.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Manuscript source contains forbidden reviewability marker: $marker"
    }
    if ($html.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Preview HTML contains forbidden reviewability marker: $marker"
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
if ($pages -lt 6 -or $pages -gt 12) {
    throw "Preview PDF page count is outside the reviewability bound: $pages"
}
if ($info -notmatch "Page size:.*A4") {
    throw "Preview PDF is not reported as A4"
}
if ($info -match "Encrypted:\s+yes") {
    throw "Preview PDF should not be encrypted"
}

Write-Output "manuscript_reviewability=PASSED"
Write-Output "title_chars=$($title.Length)"
Write-Output "abstract_words=$abstractWords"
Write-Output "contribution_items_checked=$($contributionItems.Count)"
Write-Output "sections_checked=$($requiredSections.Count)"
Write-Output "citations_checked=$(@($citeKeys).Count)"
Write-Output "pdf_pages=$pages"
Write-Output "pdf_bytes=$($pdfItem.Length)"

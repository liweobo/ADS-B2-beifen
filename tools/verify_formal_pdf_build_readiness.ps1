$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing formal-PDF readiness artifact: $Path"
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
        throw "$Name missing expected content: $Needle"
    }
}

function Assert-NoDownloadCommand {
    param(
        [string]$Name,
        [string]$Text
    )
    $forbidden = @(
        ("Invoke-" + "WebRequest"),
        ("Invoke-" + "RestMethod"),
        ("Start-" + "BitsTransfer"),
        ("winget" + " install"),
        ("pip" + " install"),
        ("conda" + " install"),
        ("mamba" + " install"),
        ("Download" + "File")
    )
    foreach ($needle in $forbidden) {
        if ($Text.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "$Name contains forbidden installer/download command: $needle"
        }
    }
}

$auditPath = Require-File "FORMAL_PDF_BUILD_AUDIT.md"
$buildScriptPath = Require-File "tools\build_submission_pdf.ps1"
$texAuditPath = Require-File "TEX_SOURCE_PORTABILITY_AUDIT.md"
$readmePath = Require-File "paper_lncs\README_compile.txt"
$paperPath = Require-File "paper_lncs\main.tex"
$bibPath = Require-File "paper_lncs\references.bib"
$classPath = Require-File "paper_lncs\llncs.cls"
$bstPath = Require-File "paper_lncs\splncs04.bst"
$templateProvenancePath = Require-File "paper_lncs\SPRINGER_TEMPLATE_PROVENANCE.md"
$formalPdfPath = Require-File "output\pdf\catad_submission_latex_updated.pdf"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$buildScript = Get-Content -Raw -Encoding UTF8 -LiteralPath $buildScriptPath
$texAudit = Get-Content -Raw -Encoding UTF8 -LiteralPath $texAuditPath
$readme = Get-Content -Raw -Encoding UTF8 -LiteralPath $readmePath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$bib = Get-Content -Raw -Encoding UTF8 -LiteralPath $bibPath

foreach ($marker in @(
    "Formal LaTeX Build Entry Point",
    "No-Download Boundary",
    "Supported Engines",
    "Current Workstation Result",
    "SKIPPED_NO_TEX_TOOL",
    "formal_pdf_build=PASSED",
    "latex_log_quality=PASSED",
    "Tectonic 0.16.9",
    "LNCS v2.24",
    "18 pages",
    "catad_submission_latex_updated.pdf",
    "tools/build_submission_pdf.ps1"
)) {
    Assert-Contains "FORMAL_PDF_BUILD_AUDIT.md" $audit $marker
}

foreach ($marker in @(
    "latexmk",
    "tectonic",
    "pdflatex",
    "bibtex",
    "formal_pdf_build=SKIPPED_NO_TEX_TOOL",
    "formal_pdf_build=PASSED",
    "catad_submission_latex_updated.pdf"
)) {
    Assert-Contains "tools/build_submission_pdf.ps1" $buildScript $marker
}

foreach ($marker in @(
    "formal LNCS PDF has been built locally",
    "TeX/BibTeX"
)) {
    Assert-Contains "TEX_SOURCE_PORTABILITY_AUDIT.md" $texAudit $marker
}

foreach ($marker in @(
    "Recommended compilation command",
    "pdflatex -interaction=nonstopmode main.tex",
    "bibtex main",
    "Formal build verified on current workstation"
)) {
    Assert-Contains "paper_lncs/README_compile.txt" $readme $marker
}

foreach ($marker in @(
    "\IfFileExists{llncs.cls}",
    "\bibliography{references}",
    "\includegraphics"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

Assert-Contains "paper_lncs/references.bib" $bib "@"
Assert-NoDownloadCommand "tools/build_submission_pdf.ps1" $buildScript

$formalPdfItem = Get-Item -LiteralPath $formalPdfPath
if ($formalPdfItem.Length -lt 100000) {
    throw "Formal LNCS PDF is unexpectedly small: $($formalPdfItem.Length) bytes"
}

$tools = @("latexmk", "tectonic", "pdflatex", "bibtex")
$found = @()
foreach ($tool in $tools) {
    $cmd = Get-Command $tool -ErrorAction SilentlyContinue
    if ($cmd) {
        $found += "$tool=$($cmd.Source)"
    }
}

if (($found | Where-Object { $_ -like "latexmk=*" -or $_ -like "tectonic=*" }).Count -gt 0 -or
    (($found | Where-Object { $_ -like "pdflatex=*" }).Count -gt 0 -and ($found | Where-Object { $_ -like "bibtex=*" }).Count -gt 0)) {
    $output = & (Join-Path $RepoRoot "tools\build_submission_pdf.ps1")
    $output | ForEach-Object { Write-Output $_ }
    if (($output -join "`n").IndexOf("formal_pdf_build=PASSED", [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Formal PDF build tool was available, but build did not report PASSED"
    }
    if (($output -join "`n").IndexOf("latex_log_quality=PASSED", [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Formal PDF build tool was available, but the TeX log quality gate did not pass"
    }
}
else {
    $output = & (Join-Path $RepoRoot "tools\build_submission_pdf.ps1")
    $output | ForEach-Object { Write-Output $_ }
    if (($output -join "`n").IndexOf("formal_pdf_build=SKIPPED_NO_TEX_TOOL", [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Expected SKIPPED_NO_TEX_TOOL when no supported TeX engine is available"
    }
}

Write-Output "formal_pdf_build_readiness=PASSED"
Write-Output "supported_engines_checked=3"
Write-Output "download_forbidden_markers_checked=8"
Write-Output "tex_tools_found=$($found.Count)"
Write-Output "formal_pdf_artifact_bytes=$($formalPdfItem.Length)"

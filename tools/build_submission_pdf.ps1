param(
    [string]$OutputDir = "output\pdf",
    [ValidateSet("auto", "latexmk", "tectonic", "pdflatex")]
    [string]$Engine = "auto",
    [switch]$RequireTool
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$PaperDir = Join-Path $RepoRoot "paper_lncs"
$OutDir = Join-Path $RepoRoot $OutputDir
$BuildDir = Join-Path $OutDir "latex_build"
$PdfPath = Join-Path $OutDir "catad_submission_latex_updated.pdf"
$LogPath = Join-Path $OutDir "catad_submission_latex_build.log"

function Get-ToolPath {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    return ""
}

function Invoke-Logged {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )
    Add-Content -LiteralPath $LogPath -Value ("> " + $Executable + " " + ($Arguments -join " "))
    # Windows PowerShell can promote benign native stderr warnings to terminating
    # ErrorRecord objects when the caller uses ErrorActionPreference=Stop. Native
    # process success is determined by its exit code; retain both streams in the log.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & $Executable @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($output) {
        $output | ForEach-Object { Add-Content -LiteralPath $LogPath -Value ([string]$_) }
    }
    if ($exitCode -ne 0) {
        throw "LaTeX command failed with exit code ${exitCode}: $Executable"
    }
}

function Select-Engine {
    if ($Engine -ne "auto") {
        return $Engine
    }
    if (Get-ToolPath "latexmk") {
        return "latexmk"
    }
    if (Get-ToolPath "tectonic") {
        return "tectonic"
    }
    if ((Get-ToolPath "pdflatex") -and (Get-ToolPath "bibtex")) {
        return "pdflatex"
    }
    return ""
}

foreach ($path in @(
    (Join-Path $PaperDir "main.tex"),
    (Join-Path $PaperDir "references.bib")
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing manuscript build input: $path"
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$selected = Select-Engine
if (-not $selected) {
    $message = "No supported TeX tool found on PATH. Supported tools: latexmk, tectonic, or pdflatex+bibtex."
    if ($RequireTool) {
        throw $message
    }
    Write-Output "formal_pdf_build=SKIPPED_NO_TEX_TOOL"
    Write-Output "supported_tools=latexmk,tectonic,pdflatex+bibtex"
    Write-Output "pdf=$PdfPath"
    return
}

# Keep the last verified formal PDF until a complete replacement has passed all
# build and log-quality checks. This makes a missing tool or failed rebuild
# non-destructive while ensuring stale build-directory outputs cannot be reused.
Remove-Item -LiteralPath $LogPath -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $BuildDir -Force -ErrorAction SilentlyContinue |
    Remove-Item -Force -Recurse

$classStatus = if (Test-Path -LiteralPath (Join-Path $PaperDir "llncs.cls") -PathType Leaf) {
    "llncs"
}
else {
    "fallback_article"
}

Push-Location $PaperDir
try {
    if ($selected -eq "latexmk") {
        $latexmk = Get-ToolPath "latexmk"
        Invoke-Logged $latexmk @(
            "-pdf",
            "-interaction=nonstopmode",
            "-halt-on-error",
            "-file-line-error",
            "-outdir=$BuildDir",
            "main.tex"
        )
    }
    elseif ($selected -eq "tectonic") {
        $tectonic = Get-ToolPath "tectonic"
        Invoke-Logged $tectonic @(
            "--keep-logs",
            "--outdir",
            $BuildDir,
            "main.tex"
        )
    }
    elseif ($selected -eq "pdflatex") {
        $pdflatex = Get-ToolPath "pdflatex"
        $bibtex = Get-ToolPath "bibtex"
        Invoke-Logged $pdflatex @(
            "-interaction=nonstopmode",
            "-halt-on-error",
            "-file-line-error",
            "-output-directory=$BuildDir",
            "main.tex"
        )
        Invoke-Logged $bibtex @((Join-Path $BuildDir "main"))
        Invoke-Logged $pdflatex @(
            "-interaction=nonstopmode",
            "-halt-on-error",
            "-file-line-error",
            "-output-directory=$BuildDir",
            "main.tex"
        )
        Invoke-Logged $pdflatex @(
            "-interaction=nonstopmode",
            "-halt-on-error",
            "-file-line-error",
            "-output-directory=$BuildDir",
            "main.tex"
        )
    }
    else {
        throw "Unsupported selected engine: $selected"
    }
}
finally {
    Pop-Location
}

$builtPdf = Join-Path $BuildDir "main.pdf"
if (-not (Test-Path -LiteralPath $builtPdf -PathType Leaf)) {
    throw "LaTeX build completed but did not produce expected PDF: $builtPdf"
}

$builtLog = Join-Path $BuildDir "main.log"
if (-not (Test-Path -LiteralPath $builtLog -PathType Leaf)) {
    throw "LaTeX build completed but did not produce expected log: $builtLog"
}
$latexLog = Get-Content -Raw -LiteralPath $builtLog
$forbiddenLogPatterns = @(
    [pscustomobject]@{ Label = "LaTeX error"; Pattern = "(?im)^! (?:LaTeX|Package|Class|Undefined control sequence)" },
    [pscustomobject]@{ Label = "undefined citation"; Pattern = "(?im)Citation .+ undefined" },
    [pscustomobject]@{ Label = "undefined reference"; Pattern = "(?im)Reference .+ undefined" },
    [pscustomobject]@{ Label = "overfull horizontal box"; Pattern = "(?im)Overfull \\hbox" }
)
foreach ($check in $forbiddenLogPatterns) {
    if ([regex]::IsMatch($latexLog, $check.Pattern)) {
        throw "Formal LaTeX log contains $($check.Label): $builtLog"
    }
}

Copy-Item -LiteralPath $builtPdf -Destination $PdfPath -Force
$pdfItem = Get-Item -LiteralPath $PdfPath
if ($pdfItem.Length -lt 100000) {
    throw "Formal LaTeX PDF is unexpectedly small: $($pdfItem.Length) bytes"
}

Write-Output "formal_pdf_build=PASSED"
Write-Output "engine=$selected"
Write-Output "latex_class=$classStatus"
Write-Output "latex_log_quality=PASSED"
Write-Output "overfull_hbox=0"
Write-Output "undefined_citations=0"
Write-Output "undefined_references=0"
Write-Output "pdf=$PdfPath"
Write-Output "pdf_bytes=$($pdfItem.Length)"

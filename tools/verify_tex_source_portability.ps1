$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing TeX source portability artifact: $Path"
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

function Assert-NoPattern {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Pattern
    )
    if ([regex]::IsMatch($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        throw "$Name contains forbidden TeX portability pattern: $Pattern"
    }
}

function Resolve-TexRelative {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath((Join-Path (Join-Path $RepoRoot "paper_lncs") $Path))
}

function Require-ManifestPath {
    param(
        [object[]]$Rows,
        [string]$Path,
        [string]$Source
    )
    $paths = @($Rows | ForEach-Object { $_.path })
    if ($paths -notcontains $Path) {
        throw "$Source missing required path: $Path"
    }
}

$auditPath = Require-File "TEX_SOURCE_PORTABILITY_AUDIT.md"
$paperPath = Require-File "paper_lncs\main.tex"
$bibPath = Require-File "paper_lncs\references.bib"
$readmePath = Require-File "paper_lncs\README_compile.txt"
$classPath = Require-File "paper_lncs\llncs.cls"
$bstPath = Require-File "paper_lncs\splncs04.bst"
$templateProvenancePath = Require-File "paper_lncs\SPRINGER_TEMPLATE_PROVENANCE.md"
$previewPdfPath = Require-File "output\pdf\catad_submission_preview.pdf"
$formalPdfPath = Require-File "output\pdf\catad_submission_latex_updated.pdf"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$bib = Get-Content -Raw -Encoding UTF8 -LiteralPath $bibPath
$readme = Get-Content -Raw -Encoding UTF8 -LiteralPath $readmePath

foreach ($marker in @(
    "Formal PDF Boundary",
    "Source Closure",
    "Portability Checks",
    "Bundle Checks",
    "Current Status",
    "formal LNCS PDF has been built locally",
    "TeX/BibTeX"
)) {
    Assert-Contains "TEX_SOURCE_PORTABILITY_AUDIT.md" $audit $marker
}

foreach ($marker in @(
    "\IfFileExists{llncs.cls}",
    "\documentclass[runningheads]{llncs}",
    "\documentclass[10pt]{article}",
    "\graphicspath{{../figures/}{figures/}}",
    "\bibliographystyle{splncs04}",
    "\bibliographystyle{plain}",
    "\bibliography{references}"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

foreach ($marker in @(
    "Recommended compilation command",
    "pdflatex -interaction=nonstopmode main.tex",
    "bibtex main",
    "Local preview command without TeX",
    "Formal build verified on current workstation",
    "llncs.cls (LNCS v2.24"
)) {
    Assert-Contains "paper_lncs/README_compile.txt" $readme $marker
}

$classHash = (Get-FileHash -LiteralPath $classPath -Algorithm SHA256).Hash.ToLowerInvariant()
$bstHash = (Get-FileHash -LiteralPath $bstPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($classHash -ne "a3cfe775b394aba8db8fbb54b8920ecbb12f4532cf787cd6d9b04712f58d0d1a") {
    throw "Bundled llncs.cls hash differs from the recorded official template"
}
if ($bstHash -ne "f36c3a17e5304a692706359aafa9de709395a085e579eb47c027095aeaa35174") {
    throw "Bundled splncs04.bst hash differs from the recorded official template"
}
$templateProvenance = Get-Content -Raw -Encoding UTF8 -LiteralPath $templateProvenancePath
Assert-Contains "SPRINGER_TEMPLATE_PROVENANCE.md" $templateProvenance $classHash
Assert-Contains "SPRINGER_TEMPLATE_PROVENANCE.md" $templateProvenance $bstHash
if ((Get-Item -LiteralPath $formalPdfPath).Length -lt 100000) {
    throw "Formal LNCS PDF is unexpectedly small"
}

$rawInputs = [regex]::Matches($paper, "\\(?:input|maybeinput)\{([^}]+)\}") |
    ForEach-Object { $_.Groups[1].Value.Trim() } |
    Where-Object { $_ -and -not $_.Contains("#") } |
    Sort-Object -Unique
$inputPaths = @($rawInputs | Where-Object { $_ -like "../*" })
$requiredInputPaths = @(
    "../outputs/literature_benchmark/table_literature_detection.tex",
    "../outputs/publication_benchmark/data_split_audit.tex",
    "../outputs/tables/table_experimental_setup.tex",
    "../outputs/tables/table_multiseed_summary.tex",
    "../outputs/tables/table_paired_multiseed_comparison.tex",
    "../outputs/tables/table_physical_feasibility.tex",
    "../outputs/tables/table5_ablation_study.tex"
)
if ($inputPaths.Count -ne $requiredInputPaths.Count) {
    throw "Expected exactly $($requiredInputPaths.Count) manuscript input paths; found $($inputPaths.Count)"
}
foreach ($requiredInput in $requiredInputPaths) {
    if ($inputPaths -notcontains $requiredInput) {
        throw "Missing required manuscript input path: $requiredInput"
    }
}
foreach ($input in $inputPaths) {
    $resolved = Resolve-TexRelative $input
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Missing TeX input path: $input -> $resolved"
    }
}

$figurePaths = @([regex]::Matches($paper, "\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}") |
    ForEach-Object { $_.Groups[1].Value.Trim() } |
    Where-Object { $_ } |
    Sort-Object -Unique)
if ($figurePaths.Count -ne 3) {
    throw "Expected exactly 3 manuscript figures; found $($figurePaths.Count)"
}
foreach ($figure in $figurePaths) {
    if ([System.IO.Path]::IsPathRooted($figure) -or $figure.Contains("..")) {
        throw "Figure path is not portable through graphicspath: $figure"
    }
    $candidateA = Join-Path (Join-Path $RepoRoot "figures") $figure
    $candidateB = Join-Path (Join-Path $RepoRoot "paper_lncs\figures") $figure
    $candidates = @($candidateA, $candidateB)
    if (-not (@($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count)) {
        throw "Missing figure target: $figure"
    }
}

$citeKeys = @([regex]::Matches($paper, "\\cite\{([^}]+)\}") |
    ForEach-Object { $_.Groups[1].Value.Split(",") } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ } |
    Sort-Object -Unique)
$bibKeys = @([regex]::Matches($bib, "@\w+\{([^,]+),") |
    ForEach-Object { $_.Groups[1].Value.Trim() } |
    Sort-Object)
$uniqueBibKeys = @($bibKeys | Sort-Object -Unique)
if ($bibKeys.Count -ne $uniqueBibKeys.Count) {
    throw "Duplicate BibTeX keys detected"
}
foreach ($key in $citeKeys) {
    if ($uniqueBibKeys -notcontains $key) {
        throw "Missing BibTeX entry for citation key: $key"
    }
}
foreach ($key in $uniqueBibKeys) {
    if ($citeKeys -notcontains $key) {
        throw "Uncited BibTeX entry in current manuscript: $key"
    }
}
$doiCount = ([regex]::Matches($bib, "^\s*doi\s*=", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)).Count
if ($doiCount -lt 8) {
    throw "Expected at least 8 BibTeX DOI fields; found $doiCount"
}

$sourceTexts = @(
    [pscustomobject]@{ name = "paper_lncs/main.tex"; text = $paper },
    [pscustomobject]@{ name = "paper_lncs/references.bib"; text = $bib },
    [pscustomobject]@{ name = "paper_lncs/README_compile.txt"; text = $readme }
)
$forbiddenPatterns = @(
    "[A-Za-z]:\\",
    "\\\\Users\\\\",
    "/home/",
    "file://",
    "\\\\write18",
    "\\\\openout",
    "\\\\read\\b",
    "\\\\includegraphics(?:\[[^\]]*\])?\{https?://",
    "\\\\(?:input|include)\{https?://",
    "\\\\usepackage\{minted\}",
    "\\\\lstinputlisting",
    "\\\\immediate\s*\\\\write"
)
foreach ($source in $sourceTexts) {
    foreach ($pattern in $forbiddenPatterns) {
        Assert-NoPattern $source.name $source.text $pattern
    }
}

$requiredBundlePaths = @(
    "paper_lncs/main.tex",
    "paper_lncs/references.bib",
    "paper_lncs/README_compile.txt",
    "paper_lncs/llncs.cls",
    "paper_lncs/splncs04.bst",
    "paper_lncs/SPRINGER_TEMPLATE_PROVENANCE.md",
    "TEX_SOURCE_PORTABILITY_AUDIT.md",
    "tools/verify_tex_source_portability.ps1",
    "output/pdf/catad_submission_preview.pdf",
    "output/pdf/catad_submission_latex_updated.pdf"
)
foreach ($input in $inputPaths) {
    $relative = $input.TrimStart(".").TrimStart("/").Replace("\", "/")
    $requiredBundlePaths += $relative
}
foreach ($figure in $figurePaths) {
    $requiredBundlePaths += "figures/$figure"
}
$requiredBundlePaths = @($requiredBundlePaths | Sort-Object -Unique)

$stageManifestPath = Join-Path $RepoRoot "BUNDLE_MANIFEST.tsv"
$repoManifestPath = Join-Path $RepoRoot "output\submission\catad_topconf_submission_bundle.manifest.tsv"
$manifestPaths = @($stageManifestPath, $repoManifestPath)
$bundleChecks = 0
foreach ($manifestPath in $manifestPaths) {
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $rows = @(Import-Csv -Delimiter "`t" -LiteralPath $manifestPath)
        foreach ($path in $requiredBundlePaths) {
            Require-ManifestPath $rows $path $manifestPath
            $bundleChecks += 1
        }
    }
}

$bundleZip = Join-Path $RepoRoot "output\submission\catad_topconf_submission_bundle.zip"
if (Test-Path -LiteralPath $bundleZip -PathType Leaf) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $bundleZip))
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName.Replace("\", "/") })
        foreach ($path in $requiredBundlePaths) {
            $zipPath = "catad_topconf_submission_bundle/$path"
            if ($entries -notcontains $zipPath) {
                throw "Bundle zip missing TeX source portability path: $zipPath"
            }
            $bundleChecks += 1
        }
    }
    finally {
        $zip.Dispose()
    }
}

Write-Output "tex_source_portability=PASSED"
Write-Output "tex_inputs_checked=$($inputPaths.Count)"
Write-Output "figures_checked=$($figurePaths.Count)"
Write-Output "citations_checked=$($citeKeys.Count)"
Write-Output "forbidden_patterns_checked=$($forbiddenPatterns.Count)"
Write-Output "bundle_paths_checked=$bundleChecks"

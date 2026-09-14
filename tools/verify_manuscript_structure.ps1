$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing manuscript-structure artifact: $Path"
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

$paperPath = Require-File "paper_lncs\main.tex"
$bibPath = Require-File "paper_lncs\references.bib"
$paper = Get-Content -Raw -LiteralPath $paperPath
$bib = Get-Content -Raw -LiteralPath $bibPath

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
foreach ($section in $requiredSections) {
    Assert-Contains "paper_lncs/main.tex" $paper "\section{$section}"
}

$requiredSubsections = @(
    "Trajectory Detector",
    "Threat Model and Physically Constrained Attacks",
    "CAT-AD Training Objective",
    "Statistical Protocol",
    "Attack Evaluation Sanity Checks"
)
foreach ($subsection in $requiredSubsections) {
    Assert-Contains "paper_lncs/main.tex" $paper "\subsection{$subsection}"
}

$requiredInputs = @(
    "../outputs/tables/table_experimental_setup.tex",
    "../outputs/publication_benchmark/data_split_audit.tex",
    "../outputs/tables/table_multiseed_summary.tex",
    "../outputs/tables/table_paired_multiseed_comparison.tex",
    "../outputs/literature_benchmark/table_literature_detection.tex",
    "../outputs/tables/table_physical_feasibility.tex",
    "../outputs/tables/table5_ablation_study.tex"
)
foreach ($input in $requiredInputs) {
    Assert-Contains "paper_lncs/main.tex" $paper $input
    $resolved = [System.IO.Path]::GetFullPath((Join-Path (Join-Path $RepoRoot "paper_lncs") $input))
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Manuscript input path does not exist: $input -> $resolved"
    }
}

$requiredFigures = @(
    "fig_main_robustness.pdf",
    "fig_physical_valid_asr.pdf",
    "fig_epsilon_sensitivity.pdf"
)
foreach ($figure in $requiredFigures) {
    Assert-Contains "paper_lncs/main.tex" $paper "\includegraphics"
    Assert-Contains "paper_lncs/main.tex" $paper $figure
    $resolved = Join-Path (Join-Path $RepoRoot "figures") $figure
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Figure file does not exist: $resolved"
    }
}

$requiredLabels = @(
    "sec:introduction",
    "sec:related_work",
    "sec:method",
    "sec:experimental_setting",
    "sec:main_results",
    "sec:physical_feasibility",
    "sec:ablation_summary",
    "sec:reproducibility",
    "sec:ethics",
    "sec:limitations",
    "sec:threats_to_validity",
    "sec:conclusion",
    "fig:robustness_comparison",
    "fig:physical_valid_asr",
    "fig:epsilon_sensitivity",
    "tab:positioning"
)
foreach ($label in $requiredLabels) {
    Assert-Contains "paper_lncs/main.tex" $paper "\label{$label}"
}

Assert-Contains "paper_lncs/main.tex" $paper "\title{CAT-AD:"
Assert-Contains "paper_lncs/main.tex" $paper "\author{Anonymous Authors}"
Assert-Contains "paper_lncs/main.tex" $paper "\institute{Anonymous Institution}"
Assert-Contains "paper_lncs/main.tex" $paper "\bibliography{references}"
Assert-Contains "paper_lncs/main.tex" $paper "\label{subsec:attack_sanity}"
Assert-Contains "paper_lncs/main.tex" $paper "Statistical Interpretation"
Assert-Contains "paper_lncs/main.tex" $paper "not interpreted as conclusive hypothesis-test evidence"
Assert-Contains "paper_lncs/main.tex" $paper "Construct validity"
Assert-Contains "paper_lncs/main.tex" $paper "Internal validity"
Assert-Contains "paper_lncs/main.tex" $paper "External validity"
Assert-Contains "paper_lncs/main.tex" $paper "Artifact validity"
Assert-Contains "paper_lncs/main.tex" $paper "compiled locally with the official Lecture Notes in Computer Science (LNCS) v2.24 class"
Assert-Contains "paper_lncs/main.tex" $paper "Peer-review acceptance and venue-specific policy compliance remain external"

$citeKeys = [regex]::Matches($paper, "\\cite\{([^}]+)\}") |
    ForEach-Object { $_.Groups[1].Value.Split(",") } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ } |
    Sort-Object -Unique
if (@($citeKeys).Count -lt 8) {
    throw "Expected at least 8 unique citation keys; found $(@($citeKeys).Count)"
}
$bibKeys = [regex]::Matches($bib, "@\w+\{([^,]+),") |
    ForEach-Object { $_.Groups[1].Value.Trim() } |
    Sort-Object -Unique
foreach ($key in $citeKeys) {
    if ($bibKeys -notcontains $key) {
        throw "Missing bibliography entry for citation key: $key"
    }
}

$forbiddenPlaceholders = @("TODO", "TBD", "FIXME", "???", "INSERT ", "PLACEHOLDER")
foreach ($needle in $forbiddenPlaceholders) {
    if ($paper.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Manuscript contains forbidden placeholder marker: $needle"
    }
}

Write-Output "manuscript_structure=PASSED"
Write-Output "sections_checked=$($requiredSections.Count)"
Write-Output "inputs_checked=$($requiredInputs.Count)"
Write-Output "figures_checked=$($requiredFigures.Count)"
Write-Output "citations_checked=$(@($citeKeys).Count)"

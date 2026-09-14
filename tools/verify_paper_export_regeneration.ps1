$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing paper-export regeneration artifact: $Path"
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
        throw "$Name missing expected regeneration marker: $Needle"
    }
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

$auditPath = Require-File "PAPER_EXPORT_REGENERATION_AUDIT.md"
$scriptPath = Require-File "tools\regenerate_paper_exports.py"
Require-File "tools\verify_figure_source_consistency.ps1" | Out-Null

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Paper Export Regeneration Audit",
    "Regeneration Boundary",
    "conda run --no-capture-output -n testtorch python",
    "Deterministic Outputs",
    "PDF and SVG figure variants",
    "freshly regenerated tables"
)) {
    Assert-Contains "PAPER_EXPORT_REGENERATION_AUDIT.md" $audit $marker
}

$script = Get-Content -Raw -Encoding UTF8 -LiteralPath $scriptPath
foreach ($marker in @(
    "does not train or evaluate models",
    "write_table_clean_performance",
    "write_table_robustness_summary",
    "write_fig4_aggregate_data_csv",
    "plot_fig_physical_valid_asr",
    "plot_fig5_epsilon_sensitivity",
    "_write_selected_tex",
    "_write_paired_comparisons_tex",
    "_display_path"
)) {
    Assert-Contains "tools/regenerate_paper_exports.py" $script $marker
}

$stablePaths = @(
    "outputs\test_set_results.csv",
    "outputs\tables\table_experimental_setup.csv",
    "outputs\tables\table_experimental_setup.tex",
    "outputs\tables\table_clean_performance.csv",
    "outputs\tables\table_clean_performance.tex",
    "outputs\tables\table_robustness_summary.csv",
    "outputs\tables\table_robustness_summary.tex",
    "outputs\tables\table_physical_feasibility.csv",
    "outputs\tables\table_physical_feasibility.tex",
    "outputs\tables\table5_ablation_study.csv",
    "outputs\tables\table5_ablation_study.tex",
    "outputs\tables\table_multiseed_summary.tex",
    "outputs\tables\table_paired_multiseed_comparison.tex",
    "results\fig_main_robustness_data.csv",
    "results\fig_physical_valid_asr_data.csv",
    "results\fig_epsilon_sensitivity_data.csv",
    "figures\fig_main_robustness.png",
    "figures\fig_physical_valid_asr.png",
    "figures\fig_epsilon_sensitivity.png"
)

$before = @{}
foreach ($path in $stablePaths) {
    Require-File $path | Out-Null
    $before[$path] = Get-Sha256 $path
}

Push-Location $RepoRoot
try {
    $output = & conda run --no-capture-output -n testtorch python tools\regenerate_paper_exports.py 2>&1
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
if ($exitCode -ne 0) {
    throw "Paper export regeneration command failed with exit code $exitCode"
}

$outputText = ($output | Out-String)
foreach ($marker in @(
    "Regenerated paper exports:",
    "outputs/tables/table_experimental_setup.csv",
    "outputs/tables/table_robustness_summary.tex",
    "results/fig_main_robustness_data.csv",
    "results/fig_physical_valid_asr_data.csv",
    "figures/fig_main_robustness.png",
    "figures/fig_physical_valid_asr.png",
    "figures/fig_epsilon_sensitivity.png"
)) {
    Assert-Contains "regenerate_paper_exports.py output" $outputText $marker
}
if ($outputText.IndexOf($RepoRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "Regeneration output leaked absolute repository path"
}

$changed = @()
foreach ($path in $stablePaths) {
    $after = Get-Sha256 $path
    if ($after -ne $before[$path]) {
        $changed += $path
    }
}
if ($changed.Count -gt 0) {
    throw "Regeneration changed byte-stable paper exports: $($changed -join ', ')"
}

& (Join-Path $RepoRoot "tools\verify_figure_source_consistency.ps1")

Write-Output "paper_export_regeneration=PASSED"
Write-Output "stable_exports_checked=$($stablePaths.Count)"
Write-Output "regeneration_command=conda run --no-capture-output -n testtorch python tools\regenerate_paper_exports.py"

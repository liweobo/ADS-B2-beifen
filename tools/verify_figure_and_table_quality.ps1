$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing figure/table quality artifact: $Path"
    }
}

function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing quality marker: $Needle"
    }
}

$paperPath = "paper_lncs\main.tex"
$tablePaths = @(
    "outputs\tables\table_experimental_setup.tex",
    "outputs\publication_benchmark\data_split_audit.tex",
    "outputs\tables\table_multiseed_summary.tex",
    "outputs\tables\table_paired_multiseed_comparison.tex",
    "outputs\literature_benchmark\table_literature_detection.tex",
    "outputs\tables\table_physical_feasibility.tex",
    "outputs\tables\table5_ablation_study.tex"
)
$codePaths = @(
    "adsb\paper_style.py",
    "adsb\plots.py",
    "adsb\fig4_asr_pvr_tradeoff.py",
    "adsb\fig5_epsilon_sensitivity.py"
)
$dataPaths = @(
    "results\fig_main_robustness_data.csv",
    "results\fig_physical_valid_asr_data.csv",
    "results\fig_epsilon_sensitivity_data.csv"
)
foreach ($path in @($paperPath) + $tablePaths + $codePaths + $dataPaths + @("FIGURE_AND_TABLE_QUALITY_AUDIT.md")) {
    Require-File $path
}

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$combinedTables = $paper
foreach ($path in $tablePaths) {
    $tex = Get-Content -Raw -Encoding UTF8 -LiteralPath $path
    $combinedTables += "`n" + $tex
    Assert-Contains $path $tex "\toprule"
    Assert-Contains $path $tex "\bottomrule"
}
foreach ($forbidden in @("\resizebox", "\scriptsize")) {
    if ($combinedTables.IndexOf($forbidden, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Manuscript-facing tables use forbidden shrinking: $forbidden"
    }
}

$tableLabels = [regex]::Matches($combinedTables, "\\label\{tab:[^}]+\}") | ForEach-Object { $_.Value } | Sort-Object -Unique
if (@($tableLabels).Count -ne 8) {
    throw "Expected eight unique manuscript table labels; found $(@($tableLabels).Count)"
}
$figureEnvironments = [regex]::Matches($paper, "\\begin\{figure\*?\}").Count
if ($figureEnvironments -ne 2) {
    throw "Expected two numbered figure environments; found $figureEnvironments"
}
if ([regex]::Matches($paper, "\\includegraphics").Count -ne 3) {
    throw "Expected three included vector graphics"
}
foreach ($marker in @("(a) Mean PV-ASR", "(b,c) F1-score sensitivity", "95\% Student-$t$", "Hatches, line styles, and markers")) {
    Assert-Contains $paperPath $paper $marker
}

$style = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\paper_style.py"
foreach ($marker in @('"xtick.labelsize": 7.5', '"ytick.labelsize": 7.5', '"legend.fontsize": 7.5')) {
    Assert-Contains "adsb/paper_style.py" $style $marker
}
$plots = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\plots.py"
$physicalPlot = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\fig4_asr_pvr_tradeoff.py"
$epsilonPlot = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\fig5_epsilon_sensitivity.py"
foreach ($marker in @("aggregate_rows", "ci95_low", "ci95_high", "yerr=", "hatch=")) {
    Assert-Contains "adsb/plots.py" $plots $marker
}
Assert-Contains "adsb/plots.py" $plots "FIG_MAIN_RENDER_FONT_SIZE = 9.0"
foreach ($marker in @("collect_fig4_aggregate_data", "ci95_low", "ci95_high", "yerr=", "hatch=")) {
    Assert-Contains "adsb/fig4_asr_pvr_tradeoff.py" $physicalPlot $marker
}
foreach ($marker in @("ax.set_ylim(0.0, 1.02)", 'linestyle="-" if model_name == "BiLSTM-ERM" else "--"', "markerfacecolor")) {
    Assert-Contains "adsb/fig5_epsilon_sensitivity.py" $epsilonPlot $marker
}
Assert-Contains "adsb/fig5_epsilon_sensitivity.py" $epsilonPlot "FIG5_RENDER_FONT_SIZE = 10.0"

$mainRows = @(Import-Csv -LiteralPath "results\fig_main_robustness_data.csv")
$physicalRows = @(Import-Csv -LiteralPath "results\fig_physical_valid_asr_data.csv")
$epsilonRows = @(Import-Csv -LiteralPath "results\fig_epsilon_sensitivity_data.csv")
if ($mainRows.Count -ne 14 -or @($mainRows | Where-Object { [int]$_.n -ne 5 }).Count -ne 0) {
    throw "Main robustness figure must contain 14 five-run aggregate rows"
}
if ($physicalRows.Count -ne 6 -or @($physicalRows | Where-Object { [int]$_.n -ne 5 }).Count -ne 0) {
    throw "Physical robustness figure must contain six five-run aggregate rows"
}
if ($epsilonRows.Count -ne 24) {
    throw "Epsilon figure must contain the complete 24-row grid"
}
$epsilonValues = @($epsilonRows | ForEach-Object { [double]$_.f1_score })
if (($epsilonValues | Measure-Object -Minimum).Minimum -ge 0.10 -or ($epsilonValues | Measure-Object -Maximum).Maximum -le 0.95) {
    throw "Epsilon source does not span the low and high F1 regions that require a full [0,1] axis"
}

$figureFiles = 0
foreach ($stem in @("fig_main_robustness", "fig_physical_valid_asr", "fig_epsilon_sensitivity")) {
    foreach ($ext in @("pdf", "svg", "png")) {
        $path = "figures\$stem.$ext"
        Require-File $path
        if ((Get-Item -LiteralPath $path).Length -lt 1000) {
            throw "Figure artifact is unexpectedly small: $path"
        }
        $figureFiles += 1
    }
}

Write-Output "figure_and_table_quality=PASSED"
Write-Output "tables_checked=$(@($tableLabels).Count)"
Write-Output "figure_environments_checked=$figureEnvironments"
Write-Output "figure_files_checked=$figureFiles"
Write-Output "main_ci_rows_checked=$($mainRows.Count)"
Write-Output "physical_ci_rows_checked=$($physicalRows.Count)"
Write-Output "epsilon_rows_checked=$($epsilonRows.Count)"

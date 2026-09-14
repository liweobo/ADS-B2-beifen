param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing paper-artifact provenance file: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing expected provenance marker: $Needle"
    }
}

function Assert-MinBytes {
    param(
        [string]$Path,
        [int64]$MinBytes
    )
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -lt $MinBytes) {
        throw "Artifact is unexpectedly small: $Path bytes=$($item.Length)"
    }
}

$paperPath = Require-File "paper_lncs\main.tex"
$provenancePath = Require-File "PAPER_ARTIFACT_PROVENANCE.md"
$manifestPath = Require-File "outputs\publication_benchmark\benchmark_manifest.json"
$verificationPath = Require-File "outputs\publication_benchmark\verification_report.md"

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$provenance = Get-Content -Raw -Encoding UTF8 -LiteralPath $provenancePath
$manifestText = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath
$verification = Get-Content -Raw -Encoding UTF8 -LiteralPath $verificationPath
$manifest = $manifestText | ConvertFrom-Json

foreach ($marker in @(
    "Paper Artifact Provenance",
    "Tables Included by the Manuscript",
    "Figures Included by the Manuscript",
    "Benchmark Manifest Link",
    "paper_artifact_provenance=PASSED"
)) {
    Assert-Contains "PAPER_ARTIFACT_PROVENANCE.md" $provenance $marker
}

$tableSpecs = @(
    [pscustomobject]@{ Label = "tab:experimental_setup"; Tex = "outputs/tables/table_experimental_setup.tex"; Csv = "outputs/tables/table_experimental_setup.csv"; Markers = @("Window length", "15 time steps", "Attack setting", "Consistency weights") },
    [pscustomobject]@{ Label = "tab:data_split_audit"; Tex = "outputs/publication_benchmark/data_split_audit.tex"; Csv = "outputs/publication_benchmark/data_split_audit.csv"; Markers = @("Data split and leakage preflight audit", "no aircraft subsampling", "Aircraft leakage", "Zero aircraft overlap", "Per-attack support") },
    [pscustomobject]@{ Label = "tab:multiseed_summary"; Tex = "outputs/tables/table_multiseed_summary.tex"; Csv = "outputs/publication_benchmark/aggregate_summary.csv"; Markers = @("Multi-seed detection and robustness summary", "BiLSTM-ERM", "CAT-AD", "PV-ASR") },
    [pscustomobject]@{ Label = "tab:paired_multiseed_comparison"; Tex = "outputs/tables/table_paired_multiseed_comparison.tex"; Csv = "outputs/publication_benchmark/paired_comparisons.csv"; Markers = @("Paired multi-seed comparison", "Mean Improvement", "Holm p", "BH q") },
    [pscustomobject]@{ Label = "tab:literature_detection"; Tex = "outputs/literature_benchmark/table_literature_detection.tex"; Csv = "outputs/literature_benchmark/aggregate_summary.csv"; Markers = @("Same-protocol unperturbed detection comparison", "Fried--Last", "VAE--SVDD", "Contextual AE") },
    [pscustomobject]@{ Label = "tab:physical_feasibility"; Tex = "outputs/tables/table_physical_feasibility.tex"; Csv = "outputs/tables/table_physical_feasibility.csv"; Markers = @("Physical Feasibility", "PVR", "PV-ASR", "Head") },
    [pscustomobject]@{ Label = "tab:ablation"; Tex = "outputs/tables/table5_ablation_study.tex"; Csv = "outputs/tables/table5_ablation_study.csv"; Markers = @("Ablation Study", "Penalty Phys-PGD-AT", "CAT-AD", "CAT-AD w/o") }
)

foreach ($spec in $tableSpecs) {
    Require-File $spec.Tex | Out-Null
    Require-File $spec.Csv | Out-Null
    Assert-MinBytes $spec.Tex 100
    Assert-MinBytes $spec.Csv 20

    $tex = Get-Content -Raw -Encoding UTF8 -LiteralPath $spec.Tex
    $csv = Get-Content -Raw -Encoding UTF8 -LiteralPath $spec.Csv
    Assert-Contains "paper_lncs/main.tex" $paper $spec.Tex.Replace("\", "/")
    Assert-Contains $spec.Tex $tex "\label{$($spec.Label)}"
    Assert-Contains "PAPER_ARTIFACT_PROVENANCE.md" $provenance $spec.Label
    Assert-Contains "PAPER_ARTIFACT_PROVENANCE.md" $provenance $spec.Tex.Replace("\", "/")
    Assert-Contains "PAPER_ARTIFACT_PROVENANCE.md" $provenance $spec.Csv.Replace("\", "/")

    foreach ($marker in $spec.Markers) {
        if ($tex.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
            $csv.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "Neither TeX nor CSV contains marker for $($spec.Label): $marker"
        }
    }

    $rows = @(Import-Csv -LiteralPath $spec.Csv)
    if ($rows.Count -lt 1) {
        throw "CSV source has no data rows: $($spec.Csv)"
    }
}

$inlineTableMarkers = @(
    "tab:positioning",
    "ADS-B adversarial attacks",
    "CAT-AD & $\checkmark$ & $\checkmark$ & $\checkmark$ & $\checkmark$ & $\checkmark$"
)
foreach ($marker in $inlineTableMarkers) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$figureSpecs = @(
    [pscustomobject]@{ Label = "fig:robustness_comparison"; Base = "fig_main_robustness"; SourceCsv = "results/fig_main_robustness_data.csv" },
    [pscustomobject]@{ Label = "fig:physical_valid_asr"; Base = "fig_physical_valid_asr"; SourceCsv = "results/fig_physical_valid_asr_data.csv" },
    [pscustomobject]@{ Label = "fig:epsilon_sensitivity"; Base = "fig_epsilon_sensitivity"; SourceCsv = "results/fig_epsilon_sensitivity_data.csv" }
)
foreach ($spec in $figureSpecs) {
    Assert-Contains "paper_lncs/main.tex" $paper $spec.Label
    Assert-Contains "paper_lncs/main.tex" $paper "$($spec.Base).pdf"
    Assert-Contains "PAPER_ARTIFACT_PROVENANCE.md" $provenance $spec.Label
    foreach ($ext in @("pdf", "png", "svg")) {
        $path = "figures/$($spec.Base).$ext"
        Require-File $path | Out-Null
        Assert-MinBytes $path 1000
        Assert-Contains "PAPER_ARTIFACT_PROVENANCE.md" $provenance $path
    }
    if ($spec.PSObject.Properties.Name -contains "SourceCsv") {
        Require-File $spec.SourceCsv | Out-Null
        $sourceRows = @(Import-Csv -LiteralPath $spec.SourceCsv)
        if ($sourceRows.Count -lt 1) {
            throw "Figure source CSV has no rows: $($spec.SourceCsv)"
        }
        Assert-Contains "PAPER_ARTIFACT_PROVENANCE.md" $provenance $spec.SourceCsv
    }
}

$aggregateRows = @(Import-Csv -LiteralPath "outputs\publication_benchmark\aggregate_summary.csv")
$pairedRows = @(Import-Csv -LiteralPath "outputs\publication_benchmark\paired_comparisons.csv")
$longRows = @(Import-Csv -LiteralPath "outputs\publication_benchmark\per_seed_metrics_long.csv")
$wideRows = @(Import-Csv -LiteralPath "outputs\publication_benchmark\per_seed_metrics_wide.csv")
if ($aggregateRows.Count -ne 152) { throw "Expected 152 aggregate rows; found $($aggregateRows.Count)" }
if ($pairedRows.Count -ne 14) { throw "Expected 14 paired comparison rows; found $($pairedRows.Count)" }
if ($longRows.Count -ne 760) { throw "Expected 760 long metric rows; found $($longRows.Count)" }
if ($wideRows.Count -ne 40) { throw "Expected 40 wide metric rows; found $($wideRows.Count)" }

foreach ($marker in @(
    "Status: PASSED",
    "Aggregate rows: 152",
    "Paired comparison rows: 14",
    "Long rows: 760",
    "Wide rows: 40"
)) {
    Assert-Contains "verification_report.md" $verification $marker
}

if (-not $manifest.artifact_integrity -or -not $manifest.artifact_integrity.files) {
    throw "Benchmark manifest missing artifact_integrity.files"
}
$manifestPaths = @($manifest.artifact_integrity.files | ForEach-Object {
    if ($_.benchmark_relative_path) { [string]$_.benchmark_relative_path } else { [string]$_.path }
})
foreach ($path in @(
    "aggregate_selected_summary.tex",
    "paired_comparisons.tex",
    "aggregate_summary.csv",
    "paired_comparisons.csv",
    "per_seed_metrics_long.csv",
    "per_seed_metrics_wide.csv"
)) {
    if ($manifestPaths -notcontains $path) {
        throw "Benchmark manifest artifact_integrity missing paper artifact: $path"
    }
}

Write-Output "paper_artifact_provenance=PASSED"
Write-Output "tables_checked=$($tableSpecs.Count + 1)"
Write-Output "figures_checked=$($figureSpecs.Count)"
Write-Output "benchmark_rows_checked=$($aggregateRows.Count + $pairedRows.Count + $longRows.Count + $wideRows.Count)"

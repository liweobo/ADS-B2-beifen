$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing figure-source artifact: $Path"
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
        throw "$Name missing expected figure-source marker: $Needle"
    }
}

function Get-Key {
    param(
        [string]$Model,
        [string]$Attack
    )
    return "$Model|$Attack"
}

function To-Double {
    param(
        [object]$Value,
        [string]$Label
    )
    $text = [string]$Value
    if ($text -eq "" -or $text -eq "--") {
        throw "Missing numeric value for $Label"
    }
    return [double]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Assert-NearlyEqual {
    param(
        [double]$Actual,
        [double]$Expected,
        [string]$Label
    )
    if ([Math]::Abs($Actual - $Expected) -gt 0.00005) {
        throw "$Label mismatch: actual=$Actual expected=$Expected"
    }
}

function Rows-ByKey {
    param(
        [object[]]$Rows,
        [string]$ModelColumn,
        [string]$AttackColumn
    )
    $map = @{}
    foreach ($row in $Rows) {
        $model = [string]$row.$ModelColumn
        $attack = [string]$row.$AttackColumn
        $map[(Get-Key $model $attack)] = $row
    }
    return $map
}

function Assert-Bundle-NoLegacyFigures {
    param([string]$Source)
    $manifestPath = Join-Path $RepoRoot $Source
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return 0
    }
    $rows = @(Import-Csv -Delimiter "`t" -LiteralPath $manifestPath)
    $legacy = @($rows | Where-Object { ([string]$_.path).Replace("\", "/").StartsWith("figures/legacy/") })
    if ($legacy.Count -gt 0) {
        throw "$Source includes legacy figures: $($legacy[0].path)"
    }
    return $rows.Count
}

$auditPath = Require-File "FIGURE_SOURCE_CONSISTENCY_AUDIT.md"
$paperPath = Require-File "paper_lncs\main.tex"
$regenPath = Require-File "tools\regenerate_paper_exports.py"
$plotsPath = Require-File "adsb\plots.py"
$fig4Path = Require-File "adsb\fig4_asr_pvr_tradeoff.py"
$fig5Path = Require-File "adsb\fig5_epsilon_sensitivity.py"
$paperTablesPath = Require-File "adsb\paper_tables.py"

$testSetPath = Require-File "outputs\test_set_results.csv"
$aggregatePath = Require-File "outputs\publication_benchmark\aggregate_summary.csv"
$cleanPath = Require-File "outputs\tables\table_clean_performance.csv"
$robustnessPath = Require-File "outputs\tables\table_robustness_summary.csv"
$physicalPath = Require-File "outputs\tables\table_physical_feasibility.csv"
$mainFigureSourcePath = Require-File "results\fig_main_robustness_data.csv"
$physicalFigureSourcePath = Require-File "results\fig_physical_valid_asr_data.csv"
$epsilonSourcePath = Require-File "results\fig_epsilon_sensitivity_data.csv"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Figure Source Consistency Audit",
    "Regeneration Command",
    "conda run --no-capture-output -n testtorch python",
    "stale plotting data",
    "figures/legacy",
    "legacy figures"
)) {
    Assert-Contains "FIGURE_SOURCE_CONSISTENCY_AUDIT.md" $audit $marker
}

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
foreach ($marker in @(
    "fig_main_robustness.pdf",
    "fig_physical_valid_asr.pdf",
    "fig_epsilon_sensitivity.pdf"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}
if ($paper.IndexOf("figures/legacy", [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    $paper.IndexOf("fig3_robustness_comparison", [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    $paper.IndexOf("fig4_asr_pvr_tradeoff", [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    $paper.IndexOf("fig5_epsilon_sensitivity", [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "Manuscript references a legacy figure path or stem"
}

$regen = Get-Content -Raw -Encoding UTF8 -LiteralPath $regenPath
foreach ($marker in @(
    "plot_fig_main_robustness",
    "fig_main_robustness_data.csv",
    "write_fig4_aggregate_data_csv",
    "fig_physical_valid_asr_data.csv",
    "write_fig5_csv",
    "plot_fig5_epsilon_sensitivity",
    "_display_path"
)) {
    Assert-Contains "tools/regenerate_paper_exports.py" $regen $marker
}
Assert-Contains "adsb/plots.py" (Get-Content -Raw -Encoding UTF8 -LiteralPath $plotsPath) "fig_main_robustness"
Assert-Contains "adsb/fig4_asr_pvr_tradeoff.py" (Get-Content -Raw -Encoding UTF8 -LiteralPath $fig4Path) "fig_physical_valid_asr"
Assert-Contains "adsb/fig5_epsilon_sensitivity.py" (Get-Content -Raw -Encoding UTF8 -LiteralPath $fig5Path) "fig_epsilon_sensitivity"
Assert-Contains "adsb/paper_tables.py" (Get-Content -Raw -Encoding UTF8 -LiteralPath $paperTablesPath) "relative_to(Path.cwd().resolve())"

$testRows = @(Import-Csv -LiteralPath $testSetPath)
$aggregateRows = @(Import-Csv -LiteralPath $aggregatePath)
$cleanRows = @(Import-Csv -LiteralPath $cleanPath)
$robustnessRows = @(Import-Csv -LiteralPath $robustnessPath)
$physicalRows = @(Import-Csv -LiteralPath $physicalPath)
$mainFigureRows = @(Import-Csv -LiteralPath $mainFigureSourcePath)
$physicalFigureRows = @(Import-Csv -LiteralPath $physicalFigureSourcePath)
$epsilonRows = @(Import-Csv -LiteralPath $epsilonSourcePath)

if ($testRows.Count -ne 8) { throw "Expected 8 test-set result rows; found $($testRows.Count)" }
if ($cleanRows.Count -ne 2) { throw "Expected 2 clean-performance rows; found $($cleanRows.Count)" }
if ($robustnessRows.Count -ne 3) { throw "Expected 3 robustness-summary rows; found $($robustnessRows.Count)" }
if ($physicalRows.Count -ne 6) { throw "Expected 6 physical-feasibility rows; found $($physicalRows.Count)" }
if ($mainFigureRows.Count -ne 14) { throw "Expected 14 main-robustness figure-source rows; found $($mainFigureRows.Count)" }
if ($physicalFigureRows.Count -ne 6) { throw "Expected 6 physical-valid-ASR figure-source rows; found $($physicalFigureRows.Count)" }
if ($epsilonRows.Count -ne 24) { throw "Expected 24 epsilon-sensitivity rows; found $($epsilonRows.Count)" }

$testMap = Rows-ByKey $testRows "Model" "Setting"
$cleanChecked = 0
foreach ($row in $cleanRows) {
    $key = Get-Key ([string]$row.Model) "Unperturbed"
    if (-not $testMap.ContainsKey($key)) {
        throw "Clean table row missing from test-set results: $key"
    }
    Assert-NearlyEqual (To-Double $row."F1-score" "$key clean F1") (To-Double $testMap[$key]."F1-score" "$key test F1") "$key clean F1"
    $cleanChecked += 1
}

$robustnessAttacks = @("Norm-bounded PGD", "Projection-based Phys-PGD", "Penalty-based Phys-PGD")
$mainChecked = 0
foreach ($row in $robustnessRows) {
    $attack = [string]$row.Attack
    if ($robustnessAttacks -notcontains $attack) {
        throw "Unexpected robustness attack row: $attack"
    }
    foreach ($modelSpec in @(
        @{ Model = "BiLSTM-ERM"; F1 = "BiLSTM-ERM F1-score"; ASR = "BiLSTM-ERM ASR" },
        @{ Model = "CAT-AD"; F1 = "CAT-AD F1-score"; ASR = "CAT-AD ASR" }
    )) {
        $key = Get-Key $modelSpec.Model $attack
        if (-not $testMap.ContainsKey($key)) {
            throw "Robustness table row missing from test-set results: $key"
        }
        Assert-NearlyEqual (To-Double $row.($modelSpec.F1) "$key robustness F1") (To-Double $testMap[$key]."F1-score" "$key test F1") "$key robustness F1"
        Assert-NearlyEqual (To-Double $row.($modelSpec.ASR) "$key robustness ASR") (To-Double $testMap[$key].ASR "$key test ASR") "$key robustness ASR"
        $mainChecked += 1
    }
}

$robustnessMap = @{}
foreach ($row in $robustnessRows) {
    $robustnessMap[[string]$row.Attack] = $row
}
$physicalChecked = 0
foreach ($row in $physicalRows) {
    $key = Get-Key ([string]$row.Model) ([string]$row.Attack)
    if (-not $testMap.ContainsKey($key)) {
        throw "Physical table row missing from test-set results: $key"
    }
    Assert-NearlyEqual (To-Double $row.PVR "$key PVR") (To-Double $testMap[$key].PVR "$key test PVR") "$key PVR"
    Assert-NearlyEqual (To-Double $row."PV-ASR" "$key PV-ASR") (To-Double $testMap[$key]."PV-ASR" "$key test PV-ASR") "$key PV-ASR"
    $physicalChecked += 1
}

$modelArchive = @{ "BiLSTM-ERM" = "Baseline"; "CAT-AD" = "Proposed" }
$settingArchive = @{
    "Unperturbed" = "Clean"
    "Norm-bounded PGD" = "Standard PGD"
    "Projection-based Phys-PGD" = "Projection-based phys-PGD"
    "Penalty-based Phys-PGD" = "Penalty-based phys-PGD"
}
$mainAggregateChecked = 0
foreach ($figRow in $mainFigureRows) {
    $archiveModel = $modelArchive[[string]$figRow.model]
    $archiveSetting = $settingArchive[[string]$figRow.setting]
    $matches = @($aggregateRows | Where-Object {
        $_.model -eq $archiveModel -and $_.setting -eq $archiveSetting -and $_.metric -eq [string]$figRow.metric
    })
    if ($matches.Count -ne 1) {
        throw "Main figure source lacks a unique aggregate row: $($figRow.model) | $($figRow.setting) | $($figRow.metric)"
    }
    if ([int]$figRow.n -ne 5) { throw "Main figure row does not use n=5" }
    Assert-NearlyEqual (To-Double $figRow.mean "main figure mean") (To-Double $matches[0].mean "aggregate mean") "main figure mean"
    Assert-NearlyEqual (To-Double $figRow.ci95_low "main figure CI low") (To-Double $matches[0].ci95_low "aggregate CI low") "main figure CI low"
    Assert-NearlyEqual (To-Double $figRow.ci95_high "main figure CI high") (To-Double $matches[0].ci95_high "aggregate CI high") "main figure CI high"
    $mainAggregateChecked += 1
}

$physicalAggregateChecked = 0
foreach ($figRow in $physicalFigureRows) {
    $archiveModel = $modelArchive[[string]$figRow.model]
    $archiveSetting = $settingArchive[[string]$figRow.attack]
    $matches = @($aggregateRows | Where-Object {
        $_.model -eq $archiveModel -and $_.setting -eq $archiveSetting -and $_.metric -eq "conditional_pv_asr_start_valid"
    })
    if ($matches.Count -ne 1) {
        throw "Physical figure source lacks a unique aggregate row: $($figRow.model) | $($figRow.attack)"
    }
    if ([int]$figRow.n -ne 5) { throw "Physical figure row does not use n=5" }
    Assert-NearlyEqual (To-Double $figRow.pv_asr "physical figure mean") (To-Double $matches[0].mean "aggregate mean") "physical figure mean"
    Assert-NearlyEqual (To-Double $figRow.ci95_low "physical figure CI low") (To-Double $matches[0].ci95_low "aggregate CI low") "physical figure CI low"
    Assert-NearlyEqual (To-Double $figRow.ci95_high "physical figure CI high") (To-Double $matches[0].ci95_high "aggregate CI high") "physical figure CI high"
    $physicalAggregateChecked += 1
}

$expectedEps = @("0.0500", "0.1000", "0.2000", "0.3000", "0.4000", "0.5000")
$expectedAttacks = @("projection_phys_pgd", "penalty_phys_pgd")
$expectedModels = @("BiLSTM-ERM", "CAT-AD")
foreach ($attack in $expectedAttacks) {
    foreach ($epsilon in $expectedEps) {
        foreach ($model in $expectedModels) {
            $matches = @($epsilonRows | Where-Object {
                $_.attack_setting -eq $attack -and $_.epsilon -eq $epsilon -and $_.model -eq $model
            })
            if ($matches.Count -ne 1) {
                throw "Epsilon figure source missing unique row: $attack epsilon=$epsilon model=$model count=$($matches.Count)"
            }
            $f1 = To-Double $matches[0].f1_score "$attack $epsilon $model F1"
            if ($f1 -lt 0.0 -or $f1 -gt 1.0) {
                throw "Epsilon F1 outside [0,1]: $attack $epsilon $model F1=$f1"
            }
        }
    }
}

$figureFilesChecked = 0
foreach ($stem in @("fig_main_robustness", "fig_physical_valid_asr", "fig_epsilon_sensitivity")) {
    foreach ($ext in @("pdf", "png", "svg")) {
        $path = Require-File "figures\$stem.$ext"
        $item = Get-Item -LiteralPath $path
        if ($item.Length -lt 1000) {
            throw "Official figure file is unexpectedly small: figures/$stem.$ext bytes=$($item.Length)"
        }
        $figureFilesChecked += 1
    }
}

$manifestRowsChecked = 0
$manifestRowsChecked += Assert-Bundle-NoLegacyFigures "BUNDLE_MANIFEST.tsv"
$manifestRowsChecked += Assert-Bundle-NoLegacyFigures "output\submission\catad_topconf_submission_bundle.manifest.tsv"

$bundleZip = Join-Path $RepoRoot "output\submission\catad_topconf_submission_bundle.zip"
$legacyZipEntries = 0
if (Test-Path -LiteralPath $bundleZip -PathType Leaf) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $bundleZip))
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName.Replace("\", "/") })
        $legacyZipEntries = @($entries | Where-Object { $_ -like "*/figures/legacy/*" }).Count
        if ($legacyZipEntries -gt 0) {
            throw "Bundle zip includes legacy figures"
        }
    }
    finally {
        $zip.Dispose()
    }
}

Write-Output "figure_source_consistency=PASSED"
Write-Output "clean_rows_checked=$cleanChecked"
Write-Output "main_robustness_pairs_checked=$mainChecked"
Write-Output "physical_figure_rows_checked=$physicalChecked"
Write-Output "main_aggregate_figure_rows_checked=$mainAggregateChecked"
Write-Output "physical_aggregate_figure_rows_checked=$physicalAggregateChecked"
Write-Output "epsilon_rows_checked=$($epsilonRows.Count)"
Write-Output "figure_files_checked=$figureFilesChecked"
Write-Output "legacy_bundle_entries=$legacyZipEntries"

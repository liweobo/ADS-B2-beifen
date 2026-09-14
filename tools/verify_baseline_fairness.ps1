$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing baseline-fairness artifact: $Path"
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

function Assert-InRange01 {
    param(
        [string]$Name,
        [double]$Value
    )
    if ($Value -lt 0.0 -or $Value -gt 1.0) {
        throw "$Name is outside [0,1]: $Value"
    }
}

$auditPath = Require-File "BASELINE_FAIRNESS_AUDIT.md"
$paperPath = Require-File "paper_lncs\main.tex"
$experimentPath = Require-File "adsb\experiment.py"
$trainingPath = Require-File "adsb\training.py"
$constantsPath = Require-File "adsb\train_constants.py"
$benchmarkPath = Require-File "adsb\benchmark.py"
$manifestPath = Require-File "outputs\publication_benchmark\benchmark_manifest.json"
$metricsPath = Require-File "outputs\publication_benchmark\per_seed_metrics_long.csv"
$pairedPath = Require-File "outputs\publication_benchmark\paired_comparisons.csv"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Fair Comparison Boundary",
    "same BiLSTM detector constructor",
    "same train and validation loaders",
    "same validation-only threshold-selection protocol",
    "paired seed-wise comparisons"
)) {
    Assert-Contains "BASELINE_FAIRNESS_AUDIT.md" $audit $marker
}

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
foreach ($marker in @(
    "Fairness controls",
    "same BiLSTM architecture",
    "same train, validation, and test loaders",
    "same validation-only threshold-selection protocol",
    "paired seed-wise comparisons"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$experiment = Get-Content -Raw -Encoding UTF8 -LiteralPath $experimentPath
foreach ($marker in @(
    "pack = prepare_train_val_test_loaders",
    "m1 = make_detector(device)",
    "m2 = make_detector(device)",
    "train_with_val(",
    "train_adv_with_val(",
    "m1, pack.train_loader, pack.val_loader",
    "pack.train_loader,",
    "pack.val_loader,",
    "pick_best_threshold(m1, pack.val_loader",
    "pick_best_threshold(m2, pack.val_loader",
    "report_trained_models_test_metrics(",
    "pack.test_loader",
    "pack.test_loader_no_inject",
    "thresholds",
    "validation_f1"
)) {
    Assert-Contains "adsb/experiment.py" $experiment $marker
}

$makeDetectorCalls = [regex]::Matches($experiment, "make_detector\(device\)").Count
if ($makeDetectorCalls -lt 2) {
    throw "Expected at least two make_detector(device) calls in adsb/experiment.py, found $makeDetectorCalls"
}

$constants = Get-Content -Raw -Encoding UTF8 -LiteralPath $constantsPath
Assert-Contains "adsb/train_constants.py" $constants "BASELINE_CE_CLASS_WEIGHTS = (1.0, 6.0)"
Assert-Contains "adsb/train_constants.py" $constants "ADV_CE_CLASS_WEIGHTS = (1.0, 6.0)"
foreach ($marker in @("EPOCHS = 30", "LR = 1e-3", "USE_AMP = True", "EARLY_STOP_PATIENCE = 6")) {
    Assert-Contains "adsb/train_constants.py" $constants $marker
}

$training = Get-Content -Raw -Encoding UTF8 -LiteralPath $trainingPath
foreach ($marker in @(
    "def train_with_val",
    "def train_adv_with_val",
    "torch.optim.Adam(model.parameters(), lr=lr)",
    "torch.optim.lr_scheduler.CosineAnnealingLR",
    "class_weights=BASELINE_CE_CLASS_WEIGHTS",
    "class_weights=ADV_CE_CLASS_WEIGHTS"
)) {
    Assert-Contains "adsb/training.py" $training $marker
}

$benchmark = Get-Content -Raw -Encoding UTF8 -LiteralPath $benchmarkPath
foreach ($marker in @(
    'b_key = (seed, "Baseline", setting, metric)',
    'p_key = (seed, "Proposed", setting, metric)',
    "raw_delta = proposed - baseline",
    "improvement = baseline - proposed if metric in LOWER_BETTER_METRICS else raw_delta"
)) {
    Assert-Contains "adsb/benchmark.py" $benchmark $marker
}

$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
$seeds = @($manifest.config.seeds | ForEach-Object { [int]$_ })
if ($seeds.Count -lt 5) {
    throw "Expected at least five benchmark seeds, found $($seeds.Count)"
}
if ($manifest.config.num_aircraft -ne $null) {
    throw "Publication benchmark should not use a reduced aircraft subset"
}
if ([int]$manifest.config.window_size -ne 15) {
    throw "Unexpected benchmark window size: $($manifest.config.window_size)"
}
if ($manifest.config.deterministic -ne $true) {
    throw "Benchmark manifest is not deterministic"
}
if ($manifest.config.run_ablation -ne $false) {
    throw "Primary benchmark should not mix ablation runs into the main comparison"
}

$runRecordsChecked = 0
foreach ($seed in $seeds) {
    $recordPath = Require-File ("outputs\publication_benchmark\runs\seed_{0}\run_record.json" -f $seed)
    $record = Get-Content -Raw -Encoding UTF8 -LiteralPath $recordPath | ConvertFrom-Json
    if ($record.completed -ne $true) {
        throw "Run record is not complete for seed $seed"
    }
    if ([int]$record.seed -ne [int]$seed) {
        throw "Run record seed mismatch: expected $seed, found $($record.seed)"
    }
    if ([int]$record.split_summary.random_state -ne [int]$seed) {
        throw "Split random_state does not match seed $seed"
    }
    Assert-InRange01 "baseline threshold seed $seed" ([double]$record.thresholds.baseline)
    Assert-InRange01 "proposed threshold seed $seed" ([double]$record.thresholds.proposed)
    Assert-InRange01 "baseline validation F1 seed $seed" ([double]$record.validation_f1.baseline)
    Assert-InRange01 "proposed validation F1 seed $seed" ([double]$record.validation_f1.proposed)
    $overlap = $record.split_summary.aircraft.overlap_counts
    if ([int]$overlap.train_validation -ne 0 -or [int]$overlap.train_test -ne 0 -or [int]$overlap.validation_test -ne 0) {
        throw "Aircraft split overlap detected for seed $seed"
    }
    $runRecordsChecked += 1
}

$metrics = @(Import-Csv -LiteralPath $metricsPath)
if ($metrics.Count -lt 400) {
    throw "Per-seed metrics table is unexpectedly small: $($metrics.Count)"
}
$models = @($metrics | Select-Object -ExpandProperty model -Unique | Sort-Object)
if (($models -join ",") -ne "Baseline,Proposed") {
    throw "Unexpected model set in per-seed metrics: $($models -join ',')"
}
$expectedSettings = @("Clean", "Penalty-based phys-PGD", "Projection-based phys-PGD", "Standard PGD")
$settings = @($metrics | Select-Object -ExpandProperty setting -Unique | Sort-Object)
if (($settings -join "|") -ne ($expectedSettings -join "|")) {
    throw "Unexpected setting set in per-seed metrics: $($settings -join '|')"
}

$groupCounts = @{}
foreach ($row in $metrics) {
    $key = "{0}|{1}|{2}|{3}" -f $row.seed, $row.setting, $row.metric, $row.model
    $groupCounts[$key] = 1
}

$metricPairsChecked = 0
$tupleKeys = @{}
foreach ($row in $metrics) {
    $tuple = "{0}|{1}|{2}" -f $row.seed, $row.setting, $row.metric
    $tupleKeys[$tuple] = 1
}
foreach ($tuple in $tupleKeys.Keys) {
    $baseKey = "$tuple|Baseline"
    $propKey = "$tuple|Proposed"
    if (-not $groupCounts.ContainsKey($baseKey) -or -not $groupCounts.ContainsKey($propKey)) {
        throw "Missing paired Baseline/Proposed metric row for $tuple"
    }
    $metricPairsChecked += 1
}

$paired = @(Import-Csv -LiteralPath $pairedPath)
if ($paired.Count -ne 14) {
    throw "Expected 14 paired-comparison rows, found $($paired.Count)"
}
foreach ($row in $paired) {
    if ($row.seeds -ne ($seeds -join ",")) {
        throw "Paired row uses unexpected seed list for $($row.setting)/$($row.metric): $($row.seeds)"
    }
    if ([int]$row.n -ne $seeds.Count) {
        throw "Paired row n does not match seed count for $($row.setting)/$($row.metric)"
    }
}

Write-Output "baseline_fairness=PASSED"
Write-Output "run_records_checked=$runRecordsChecked"
Write-Output "metric_pairs_checked=$metricPairsChecked"
Write-Output "paired_rows_checked=$($paired.Count)"

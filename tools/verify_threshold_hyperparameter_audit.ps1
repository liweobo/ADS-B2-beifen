param(
    [string]$AuditPath = "THRESHOLD_AND_HYPERPARAMETER_AUDIT.md",
    [string]$ManifestPath = "outputs\publication_benchmark\benchmark_manifest.json",
    [string]$BenchmarkRoot = "outputs\publication_benchmark"
)

$ErrorActionPreference = "Stop"

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required file: $Path"
    }
    return $Path
}

function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing expected marker: $Needle"
    }
}

function Assert-Range {
    param([string]$Name, [object]$Value, [double]$Low, [double]$High)
    $number = [double]$Value
    if ($number -lt $Low -or $number -gt $High) {
        throw "$Name out of range: $number not in [$Low, $High]"
    }
}

function Assert-EqualText {
    param([string]$Name, [object]$Observed, [object]$Expected)
    if ([string]$Observed -ne [string]$Expected) {
        throw "$Name mismatch: observed=$Observed expected=$Expected"
    }
}

$auditFile = Require-File $AuditPath
$manifestFile = Require-File $ManifestPath
Require-File "adsb\experiment.py" | Out-Null
Require-File "adsb\training.py" | Out-Null
Require-File "adsb\eval_report.py" | Out-Null
Require-File "adsb\train_constants.py" | Out-Null
Require-File "paper_lncs\main.tex" | Out-Null

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditFile
$experiment = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\experiment.py"
$training = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\training.py"
$evalReport = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\eval_report.py"
$constants = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\train_constants.py"
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath "paper_lncs\main.tex"
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestFile | ConvertFrom-Json

foreach ($marker in @(
    "Validation-Only Threshold Boundary",
    "Fixed Hyperparameter Boundary",
    "Leakage Guardrail",
    "pick_best_threshold(..., pack.val_loader)",
    "test metrics must not be inflated"
)) {
    Assert-Contains $AuditPath $audit $marker
}

foreach ($marker in @(
    "The decision threshold is selected on the validation split and then held fixed for test evaluation",
    "hyperparameter snapshot",
    "aircraft-level split audits"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

foreach ($marker in @(
    "pick_best_threshold(m1, pack.val_loader",
    "pick_best_threshold(m2, pack.val_loader",
    "b_thr=b_thr",
    "a_thr=a_thr",
    "b_val_f1=b_val_f1",
    "a_val_f1=a_val_f1",
    '"thresholds"',
    '"validation_f1"'
)) {
    Assert-Contains "adsb/experiment.py" $experiment $marker
}

foreach ($marker in @(
    "def pick_best_threshold",
    "np.linspace(0, 1, THRESHOLD_GRID_POINTS)",
    "_metrics_at_threshold"
)) {
    Assert-Contains "adsb/training.py" $training $marker
}

foreach ($marker in @(
    "best threshold on val",
    "threshold=b_thr",
    "threshold=a_thr"
)) {
    Assert-Contains "adsb/eval_report.py" $evalReport $marker
}

$thresholdSelectionPattern = "pick_best_threshold\s*\([^`r`n)]*test_loader"
foreach ($item in @(
    @{ Name = "adsb/experiment.py"; Text = $experiment },
    @{ Name = "adsb/ablation.py"; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\ablation.py") },
    @{ Name = "adsb/ablation_table5.py"; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\ablation_table5.py") }
)) {
    if ([regex]::IsMatch([string]$item.Text, $thresholdSelectionPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        throw "$($item.Name) appears to select a threshold on a test loader"
    }
}

$expectedHyperparameters = @{
    "WINDOW_SIZE" = 15
    "TRAIN_VAL_TEST_HOLDOUT_FRACTION" = 0.2
    "TRAIN_VAL_TEST_VAL_FRACTION" = 0.125
    "EPOCHS" = 30
    "LR" = 0.001
    "ADV_TRAIN_EPS" = 0.1
    "ADV_TRAIN_LAMBDA" = 0.5
    "PGD_STEPS" = 5
    "PGD_ALPHA" = 0.03
    "EVAL_ATTACK_EPS" = 0.1
    "PHYS_OUT_LAMBDA" = 0.01
    "PHYS_FEAT_LAMBDA" = 0.005
    "THRESHOLD_GRID_POINTS" = 50
}

$hyper = $manifest.provenance.hyperparameters
if (-not $hyper) {
    throw "Benchmark manifest missing provenance.hyperparameters"
}

$hyperChecked = 0
foreach ($key in ($expectedHyperparameters.Keys | Sort-Object)) {
    if ($null -eq $hyper.$key) {
        throw "Benchmark manifest missing hyperparameter: $key"
    }
    $observed = [double]$hyper.$key
    $expected = [double]$expectedHyperparameters[$key]
    if ([Math]::Abs($observed - $expected) -gt 1e-12) {
        throw "Hyperparameter $key mismatch: observed=$observed expected=$expected"
    }
    Assert-Contains "adsb/train_constants.py" $constants $key
    $hyperChecked += 1
}

Assert-EqualText "manifest deterministic" $manifest.config.deterministic "True"
Assert-EqualText "manifest run_ablation" $manifest.config.run_ablation "False"
Assert-EqualText "manifest save_models" $manifest.config.save_models "False"

$expectedSeeds = @(42, 43, 44, 45, 46)
$manifestSeeds = @($manifest.config.seeds | ForEach-Object { [int]$_ })
if (($manifestSeeds -join ",") -ne ($expectedSeeds -join ",")) {
    throw "Unexpected manifest seeds: $($manifestSeeds -join ',')"
}

$runRecordsChecked = 0
$thresholdRecordsChecked = 0
foreach ($seed in $expectedSeeds) {
    $recordPath = Join-Path $BenchmarkRoot ("runs\seed_$seed\run_record.json")
    Require-File $recordPath | Out-Null
    $record = Get-Content -Raw -Encoding UTF8 -LiteralPath $recordPath | ConvertFrom-Json
    Assert-EqualText "seed $seed completed" $record.completed "True"
    Assert-EqualText "seed $seed random_state" $record.split_summary.random_state $seed
    foreach ($model in @("baseline", "proposed")) {
        if ($null -eq $record.thresholds.$model) {
            throw "Seed $seed missing threshold for $model"
        }
        if ($null -eq $record.validation_f1.$model) {
            throw "Seed $seed missing validation_f1 for $model"
        }
        Assert-Range "seed $seed $model threshold" $record.thresholds.$model 0.0 1.0
        Assert-Range "seed $seed $model validation_f1" $record.validation_f1.$model 0.0 1.0
        $thresholdRecordsChecked += 1
    }
    $overlap = $record.split_summary.aircraft.overlap_counts
    Assert-EqualText "seed $seed train_validation overlap" $overlap.train_validation 0
    Assert-EqualText "seed $seed train_test overlap" $overlap.train_test 0
    Assert-EqualText "seed $seed validation_test overlap" $overlap.validation_test 0
    if ([int]$record.split_summary.aircraft.validation.count -le 0) {
        throw "Seed $seed has empty validation aircraft split"
    }
    if ([int]$record.split_summary.windows.validation.malicious_windows -le 0) {
        throw "Seed $seed has no malicious validation windows"
    }
    if ([int]$record.split_summary.windows.test_mixed_attack.malicious_windows -le 0) {
        throw "Seed $seed has no malicious test windows"
    }
    $runRecordsChecked += 1
}

Write-Output "threshold_hyperparameter_audit=PASSED"
Write-Output "run_records_checked=$runRecordsChecked"
Write-Output "threshold_records_checked=$thresholdRecordsChecked"
Write-Output "hyperparameters_checked=$hyperChecked"

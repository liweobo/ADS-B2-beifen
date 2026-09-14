param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing attack-strength configuration artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing attack-strength marker: $Needle"
    }
}

function Assert-Close {
    param(
        [string]$Name,
        [double]$Actual,
        [double]$Expected,
        [double]$Tolerance = 1e-9
    )
    if ([Math]::Abs($Actual - $Expected) -gt $Tolerance) {
        throw "$Name mismatch: actual=$Actual expected=$Expected"
    }
}

function Assert-GreaterEqual {
    param(
        [string]$Name,
        [double]$Actual,
        [double]$Threshold
    )
    if ($Actual -lt $Threshold) {
        throw "$Name below threshold: actual=$Actual threshold=$Threshold"
    }
}

function Assert-LessEqual {
    param(
        [string]$Name,
        [double]$Actual,
        [double]$Threshold
    )
    if ($Actual -gt $Threshold) {
        throw "$Name above threshold: actual=$Actual threshold=$Threshold"
    }
}

$auditPath = "ATTACK_STRENGTH_CONFIGURATION_AUDIT.md"
$paperPath = "paper_lncs\main.tex"
$manifestPath = "outputs\publication_benchmark\benchmark_manifest.json"
$pairedPath = "outputs\publication_benchmark\paired_comparisons.csv"
$aggregatePath = "outputs\tables\table_multiseed_summary.tex"
$epsilonPath = "results\fig_epsilon_sensitivity_data.csv"
$attacksPath = "adsb\attacks.py"
$constantsPath = "adsb\train_constants.py"

foreach ($path in @($auditPath, $paperPath, $manifestPath, $pairedPath, $aggregatePath, $epsilonPath, $attacksPath, $constantsPath)) {
    Require-File $path
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$aggregate = Get-Content -Raw -Encoding UTF8 -LiteralPath $aggregatePath
$attacks = Get-Content -Raw -Encoding UTF8 -LiteralPath $attacksPath
$constants = Get-Content -Raw -Encoding UTF8 -LiteralPath $constantsPath
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
$paired = @(Import-Csv -LiteralPath $pairedPath)
$epsilonRows = @(Import-Csv -LiteralPath $epsilonPath)

foreach ($marker in @(
    "Fixed Benchmark Attack Configuration",
    "Empirical Strength Signals",
    "Epsilon-Sensitivity Boundary",
    "not a formal robustness certificate",
    "PGD_STEPS * PGD_ALPHA = 0.15",
    "epsilon-sensitivity CSV",
    "attack_strength_configuration=PASSED"
)) {
    Assert-Contains $auditPath $audit $marker
}

foreach ($marker in @(
    "attack configuration is fixed before paired comparison",
    "PGD uses five steps",
    "0.03",
    "0.1",
    "epsilon-sensitivity sweep"
)) {
    Assert-Contains $paperPath $paper $marker
}

foreach ($marker in @(
    "def _attack_grad_context",
    "for _ in range(steps)",
    "_linf_project",
    "targeted: bool = True",
    "target_label: int = 0",
    "lambda_phys_max: float = 10.0"
)) {
    Assert-Contains $attacksPath $attacks $marker
}

foreach ($marker in @(
    "PGD_STEPS = 5",
    "PGD_ALPHA = 0.03",
    "EVAL_ATTACK_EPS = 0.1",
    "PHYS_PENALTY_LAMBDA_MAX = 10.0",
    "PHYS_PENALTY_FINAL_PROJECTION = True"
)) {
    Assert-Contains $constantsPath $constants $marker
}

Assert-Contains $manifestPath ($manifest.resume.signature.algorithm) "sha256(config, data_sha256, code_sha256, hyperparameters)"
$hp = $manifest.provenance.hyperparameters
$hyperparameterChecks = @(
    [pscustomobject]@{ Name = "PGD_STEPS"; Actual = [double]$hp.PGD_STEPS; Expected = 5.0 },
    [pscustomobject]@{ Name = "PGD_ALPHA"; Actual = [double]$hp.PGD_ALPHA; Expected = 0.03 },
    [pscustomobject]@{ Name = "EVAL_ATTACK_EPS"; Actual = [double]$hp.EVAL_ATTACK_EPS; Expected = 0.1 },
    [pscustomobject]@{ Name = "ADV_TRAIN_EPS"; Actual = [double]$hp.ADV_TRAIN_EPS; Expected = 0.1 },
    [pscustomobject]@{ Name = "PHYS_PENALTY_LAMBDA_MAX"; Actual = [double]$hp.PHYS_PENALTY_LAMBDA_MAX; Expected = 10.0 },
    [pscustomobject]@{ Name = "PHYS_PENALTY_LAMBDA_GAMMA"; Actual = [double]$hp.PHYS_PENALTY_LAMBDA_GAMMA; Expected = 2.0 },
    [pscustomobject]@{ Name = "PHYS_PENALTY_PROJECTION_START_RATIO"; Actual = [double]$hp.PHYS_PENALTY_PROJECTION_START_RATIO; Expected = 0.5 },
    [pscustomobject]@{ Name = "PHYS_PENALTY_W_SPEED"; Actual = [double]$hp.PHYS_PENALTY_W_SPEED; Expected = 1.0 },
    [pscustomobject]@{ Name = "PHYS_PENALTY_W_ALTITUDE"; Actual = [double]$hp.PHYS_PENALTY_W_ALTITUDE; Expected = 1.0 },
    [pscustomobject]@{ Name = "PHYS_PENALTY_W_LATLON"; Actual = [double]$hp.PHYS_PENALTY_W_LATLON; Expected = 1.0 },
    [pscustomobject]@{ Name = "PHYS_PENALTY_W_HEADING"; Actual = [double]$hp.PHYS_PENALTY_W_HEADING; Expected = 10.0 },
    [pscustomobject]@{ Name = "ADV_WARMUP_EPOCHS"; Actual = [double]$hp.ADV_WARMUP_EPOCHS; Expected = 3.0 }
)
foreach ($check in $hyperparameterChecks) {
    Assert-Close $check.Name $check.Actual $check.Expected
}
if (-not [bool]$hp.PHYS_PENALTY_USE_LAMBDA_SCHEDULE) {
    throw "PHYS_PENALTY_USE_LAMBDA_SCHEDULE should be true in benchmark manifest"
}
if (-not [bool]$hp.PHYS_PENALTY_FINAL_PROJECTION) {
    throw "PHYS_PENALTY_FINAL_PROJECTION should be true in benchmark manifest"
}

$stepCoverage = [double]$hp.PGD_STEPS * [double]$hp.PGD_ALPHA
Assert-GreaterEqual "PGD step-size coverage" $stepCoverage ([double]$hp.EVAL_ATTACK_EPS)
Assert-LessEqual "PGD per-step alpha" ([double]$hp.PGD_ALPHA) ([double]$hp.EVAL_ATTACK_EPS)

$pairedChecks = @(
    [pscustomobject]@{ Setting = "Standard PGD"; Metric = "asr"; MinImprovement = 0.90; Aggregate = "Norm-PGD & 0.022" },
    [pscustomobject]@{ Setting = "Projection-based phys-PGD"; Metric = "asr"; MinImprovement = 0.80; Aggregate = "Proj. Phys-PGD & 0.112" },
    [pscustomobject]@{ Setting = "Penalty-based phys-PGD"; Metric = "asr"; MinImprovement = 0.80; Aggregate = "Penalty Phys-PGD & 0.114" }
)
foreach ($check in $pairedChecks) {
    Assert-Contains $aggregatePath $aggregate $check.Aggregate
    $match = @($paired | Where-Object { $_.setting -eq $check.Setting -and $_.metric -eq $check.Metric })
    if ($match.Count -ne 1) {
        throw "Expected one paired attack-strength row for $($check.Setting)/$($check.Metric); found $($match.Count)"
    }
    Assert-GreaterEqual "$($check.Setting) ASR improvement" ([double]$match[0].mean_improvement) ([double]$check.MinImprovement)
    Assert-GreaterEqual "$($check.Setting) ASR win rate" ([double]$match[0].win_rate) 1.0
}

if ($epsilonRows.Count -ne 24) {
    throw "Expected 24 epsilon-sensitivity rows; found $($epsilonRows.Count)"
}
$epsilonLevels = @($epsilonRows | ForEach-Object { [double]$_.epsilon } | Sort-Object -Unique)
if ($epsilonLevels.Count -ne 6) {
    throw "Expected 6 epsilon levels; found $($epsilonLevels.Count)"
}
Assert-Close "epsilon min" ([double]$epsilonLevels[0]) 0.05
Assert-Close "epsilon max" ([double]$epsilonLevels[-1]) 0.5

$attackSettings = @($epsilonRows | Select-Object -ExpandProperty attack_setting -Unique)
foreach ($requiredAttack in @("projection_phys_pgd", "penalty_phys_pgd")) {
    if ($attackSettings -notcontains $requiredAttack) {
        throw "Missing epsilon-sensitivity attack setting: $requiredAttack"
    }
}
$models = @($epsilonRows | Select-Object -ExpandProperty model -Unique)
foreach ($requiredModel in @("BiLSTM-ERM", "CAT-AD")) {
    if ($models -notcontains $requiredModel) {
        throw "Missing epsilon-sensitivity model: $requiredModel"
    }
}
foreach ($attack in @("projection_phys_pgd", "penalty_phys_pgd")) {
    $baselineAtEval = @($epsilonRows | Where-Object {
        $_.attack_setting -eq $attack -and $_.model -eq "BiLSTM-ERM" -and [Math]::Abs(([double]$_.epsilon) - 0.1) -lt 1e-9
    })
    if ($baselineAtEval.Count -ne 1) {
        throw "Expected one baseline epsilon row at 0.1 for $attack; found $($baselineAtEval.Count)"
    }
    Assert-LessEqual "$attack baseline F1 at epsilon 0.1" ([double]$baselineAtEval[0].f1_score) 0.20

    $catRows = @($epsilonRows | Where-Object { $_.attack_setting -eq $attack -and $_.model -eq "CAT-AD" })
    if ($catRows.Count -ne 6) {
        throw "Expected six CAT-AD epsilon rows for $attack; found $($catRows.Count)"
    }
    $catMin = ($catRows | ForEach-Object { [double]$_.f1_score } | Measure-Object -Minimum).Minimum
    Assert-GreaterEqual "$attack CAT-AD minimum epsilon-sweep F1" ([double]$catMin) 0.97
}

Write-Output "attack_strength_configuration=PASSED"
Write-Output "hyperparameters_checked=$($hyperparameterChecks.Count)"
Write-Output "paired_attack_rows_checked=$($pairedChecks.Count)"
Write-Output "epsilon_rows_checked=$($epsilonRows.Count)"
Write-Output "epsilon_levels_checked=$($epsilonLevels.Count)"

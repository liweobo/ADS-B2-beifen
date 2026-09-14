$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing method-traceability artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing method-traceability marker: $Needle"
    }
}

function Assert-Equal {
    param(
        [string]$Name,
        $Actual,
        $Expected
    )
    if ($Actual -ne $Expected) {
        throw "$Name mismatch: actual=$Actual expected=$Expected"
    }
}

$auditPath = "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md"
$paperPath = "paper_lncs\main.tex"
$trainingPath = "adsb\training.py"
$attackPath = "adsb\attacks.py"
$modelPath = "adsb\model.py"
$constantsPath = "adsb\train_constants.py"
$manifestPath = "outputs\publication_benchmark\benchmark_manifest.json"
$quickstartPath = "REVIEWER_QUICKSTART.md"
$guidePath = "ARTIFACT_EVALUATION_GUIDE.md"

foreach ($path in @($auditPath, $paperPath, $trainingPath, $attackPath, $modelPath, $constantsPath, $manifestPath, $quickstartPath, $guidePath)) {
    Require-File $path
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$training = Get-Content -Raw -Encoding UTF8 -LiteralPath $trainingPath
$attacks = Get-Content -Raw -Encoding UTF8 -LiteralPath $attackPath
$model = Get-Content -Raw -Encoding UTF8 -LiteralPath $modelPath
$constants = Get-Content -Raw -Encoding UTF8 -LiteralPath $constantsPath
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
$quickstart = Get-Content -Raw -Encoding UTF8 -LiteralPath $quickstartPath
$guide = Get-Content -Raw -Encoding UTF8 -LiteralPath $guidePath

foreach ($marker in @(
    "CAT-AD Training Objective",
    "unperturbed trajectories and physically constrained adversarial trajectories",
    "attack generator targets the normal class",
    "\lambda_{\mathrm{adv}}\mathcal{L}_{\mathrm{CE}}",
    "\lambda_{\mathrm{out}}T^2\mathrm{KL}",
    "p^{(T)}(z)=\operatorname{softmax}(f_\theta(z)/T)",
    "q=p^{(T)}(x)",
    "q_{\mathrm{adv}}=p^{(T)}(x_{\mathrm{adv}})",
    "\lambda_{\mathrm{rep}}\operatorname{MSE}",
    "\operatorname{sg}[q]",
    "r_{\mathrm{adv}},\operatorname{sg}[r]",
    'implementation uses $T=2$',
    "Method--Implementation Traceability",
    "unperturbed CE",
    "anomalous-only adversarial CE",
    "output-level KL consistency",
    "BiLSTM-representation MSE consistency"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$trainingMarkers = @(
    "def _physical_consistency_losses",
    "malicious = y == 1",
    "F.softmax(logits_clean[malicious].detach() / temp, dim=1)",
    "F.log_softmax(logits_adv[malicious] / temp, dim=1)",
    "F.kl_div(log_p_adv, p_clean, reduction=""batchmean"")",
    "F.normalize(feat_clean[malicious].detach(), p=2, dim=1)",
    "F.normalize(feat_adv[malicious], p=2, dim=1)",
    "F.mse_loss(feat_adv_n, feat_clean_n)",
    "logits_clean, feat_clean = model(X, return_features=True)",
    "apply_pgd_malicious_only(",
    "pgd_phys_penalty",
    "return_diagnostics=True",
    "logits_adv, feat_adv = model(X2, return_features=True)",
    "mal_mask = y == 1",
    "loss_adv = lossf(logits_adv[mal_mask], y[mal_mask])",
    "loss_clean",
    "cur_adv_lambda * loss_adv",
    "adv_cfg[""phys_out_lambda""] * loss_out_cons",
    "adv_cfg[""phys_feat_lambda""] * loss_feat_cons",
    "train_adv_asr",
    "mean_loss_target",
    "mean_loss_phys",
    "mean_lambda_phys"
)
foreach ($marker in $trainingMarkers) {
    Assert-Contains "adsb/training.py" $training $marker
}

$attackMarkers = @(
    "def apply_pgd_malicious_only",
    "mal = y == 1",
    "target_label: int = 0",
    "target = torch.full_like(y, int(target_label))",
    "loss_target = _CE(model(x_in), target)",
    "loss = loss_target + lam * loss_phys",
    "return_diagnostics=False",
    "return (x_adv, diagnostics) if return_diagnostics else x_adv"
)
foreach ($marker in $attackMarkers) {
    Assert-Contains "adsb/attacks.py" $attacks $marker
}

foreach ($marker in @(
    "class LSTMDetector",
    "input_dim=12",
    "hidden_dim=64",
    "num_layers=2",
    "bidirectional=True",
    "nn.LSTM",
    "nn.Linear(64, 2)",
    "return_features",
    "return logits, h"
)) {
    Assert-Contains "adsb/model.py" $model $marker
}

foreach ($marker in @(
    "ADV_TRAIN_EPS = 0.1",
    "ADV_TRAIN_LAMBDA = 0.5",
    "ADV_WARMUP_EPOCHS = 3",
    "PGD_STEPS = 5",
    "PGD_ALPHA = 0.03",
    "USE_PENALTY_PHYS_PGD_TRAIN = True",
    "PHYS_OUT_LAMBDA = 0.01",
    "PHYS_FEAT_LAMBDA = 0.005",
    "PHYS_TEMPERATURE = 2.0"
)) {
    Assert-Contains "adsb/train_constants.py" $constants $marker
}

$hp = $manifest.provenance.hyperparameters
Assert-Equal "manifest ADV_TRAIN_EPS" ([double]$hp.ADV_TRAIN_EPS) 0.1
Assert-Equal "manifest ADV_TRAIN_LAMBDA" ([double]$hp.ADV_TRAIN_LAMBDA) 0.5
Assert-Equal "manifest ADV_WARMUP_EPOCHS" ([int]$hp.ADV_WARMUP_EPOCHS) 3
Assert-Equal "manifest PGD_STEPS" ([int]$hp.PGD_STEPS) 5
Assert-Equal "manifest PGD_ALPHA" ([double]$hp.PGD_ALPHA) 0.03
Assert-Equal "manifest USE_PENALTY_PHYS_PGD_TRAIN" ([bool]$hp.USE_PENALTY_PHYS_PGD_TRAIN) $true
Assert-Equal "manifest PHYS_PENALTY_LAMBDA_MAX" ([double]$hp.PHYS_PENALTY_LAMBDA_MAX) 10.0
Assert-Equal "manifest PHYS_PENALTY_LAMBDA_GAMMA" ([double]$hp.PHYS_PENALTY_LAMBDA_GAMMA) 2.0
Assert-Equal "manifest PHYS_OUT_LAMBDA" ([double]$hp.PHYS_OUT_LAMBDA) 0.01
Assert-Equal "manifest PHYS_FEAT_LAMBDA" ([double]$hp.PHYS_FEAT_LAMBDA) 0.005
Assert-Equal "manifest PHYS_TEMPERATURE" ([double]$hp.PHYS_TEMPERATURE) 2.0

$seeds = @($manifest.config.seeds | ForEach-Object { [int]$_ })
if (($seeds -join ",") -ne "42,43,44,45,46") {
    throw "Unexpected method-traceability seed list: $($seeds -join ',')"
}

$logsChecked = 0
foreach ($seed in $seeds) {
    $logPath = "outputs\publication_benchmark\runs\seed_$seed\run.log"
    Require-File $logPath
    $log = Get-Content -Raw -Encoding UTF8 -LiteralPath $logPath
    foreach ($marker in @(
        "Adv training config",
        "use_penalty_phys_pgd_train=True",
        "lambda_phys_max=10.0",
        "lambda_phys_gamma=2.0",
        "phys_out_lambda=0.01",
        "phys_feat_lambda=0.005",
        "Adv Epoch",
        "clean_loss=",
        "adv_loss=",
        "out_cons=",
        "feat_cons=",
        "adv_delta_mean=",
        "adv_delta_max=",
        "train_adv_asr=",
        "mean_loss_target=",
        "mean_loss_phys=",
        "mean_lambda_phys="
    )) {
        Assert-Contains "seed_$seed/run.log" $log $marker
    }
    $logsChecked += 1
}

foreach ($marker in @(
    "Traceability Boundary",
    "Unperturbed empirical-risk term",
    "Anomalous-only adversarial term",
    "Output-distribution consistency",
    "Representation consistency",
    "target_label=0",
    "lossf(logits_adv[mal_mask], y[mal_mask])",
    "Hyperparameter Boundary",
    "Run-Log Boundary"
)) {
    Assert-Contains $auditPath $audit $marker
}

Assert-Contains "REVIEWER_QUICKSTART.md" $quickstart "method_implementation_traceability=PASSED"
Assert-Contains "REVIEWER_QUICKSTART.md" $quickstart "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md"
Assert-Contains "ARTIFACT_EVALUATION_GUIDE.md" $guide "Method-to-implementation traceability"
Assert-Contains "ARTIFACT_EVALUATION_GUIDE.md" $guide "tools/verify_method_implementation_traceability.ps1"

Write-Output "method_implementation_traceability=PASSED"
Write-Output "training_markers_checked=$($trainingMarkers.Count)"
Write-Output "attack_markers_checked=$($attackMarkers.Count)"
Write-Output "seed_logs_checked=$logsChecked"
Write-Output "manifest_hyperparameters_checked=11"

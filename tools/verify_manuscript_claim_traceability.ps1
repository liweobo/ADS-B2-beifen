$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing manuscript-claim-traceability artifact: $Path"
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

function To-Double {
    param([string]$Value)
    return [double]::Parse(
        $Value,
        [System.Globalization.NumberStyles]::Float,
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-AggregateMean {
    param(
        [object[]]$Rows,
        [string]$Model,
        [string]$Setting,
        [string]$Metric
    )
    $matches = @($Rows | Where-Object { $_.model -eq $Model -and $_.setting -eq $Setting -and $_.metric -eq $Metric })
    if ($matches.Count -ne 1) {
        throw "Expected one aggregate row for $Model / $Setting / $Metric, found $($matches.Count)"
    }
    return To-Double $matches[0].mean
}

$auditPath = Require-File "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md"
$paperPath = Require-File "paper_lncs\main.tex"
$attacksPath = Require-File "adsb\attacks.py"
$trainingPath = Require-File "adsb\training.py"
$modelPath = Require-File "adsb\model.py"
$constantsPath = Require-File "adsb\train_constants.py"
$verificationPath = Require-File "outputs\publication_benchmark\verification_report.md"
$aggregatePath = Require-File "outputs\publication_benchmark\aggregate_summary.csv"
$selectedTexPath = Require-File "outputs\tables\table_multiseed_summary.tex"
$pairedPath = Require-File "outputs\publication_benchmark\paired_comparisons.csv"
$robustnessPath = Require-File "outputs\tables\table_robustness_summary.csv"
$physicalPath = Require-File "outputs\tables\table_physical_feasibility.csv"
$epsilonPath = Require-File "results\fig_epsilon_sensitivity_data.csv"
$numericPath = Require-File "NUMERIC_CLAIMS_LEDGER.md"
$claimScopePath = Require-File "CLAIM_SCOPE_GUARDRAILS.md"
$failurePath = Require-File "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md"
$ablationPath = Require-File "ABLATION_AND_SENSITIVITY_AUDIT.md"
$attackAuditPath = Require-File "ATTACK_EVALUATION_SANITY_CHECKLIST.md"

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Claim-To-Evidence Map",
    "Targeted anomalous-to-normal threat model",
    "Strong evaluated attacks against BiLSTM-ERM",
    "CAT-AD maintains high adversarial F1 and low ASR",
    "CAT-AD suppresses physically valid evasion",
    "Perturbation-budget sensitivity is a bounded auxiliary result"
)) {
    Assert-Contains "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md" $audit $marker
}

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$claimMarkers = @(
    "targeted anomalous-to-normal evasion threat model",
    "We propose constrained adversarial training for anomaly detection (CAT-AD)",
    "All robustness claims are limited to the evaluated perturbation settings and threat model",
    "The evaluated attacks also produce high ASR against BiLSTM-ERM",
    "CAT-AD maintains high F1-score and low ASR",
    "Define the valid-start set",
    "CAT-AD substantially suppresses physically valid anomalous-to-normal evasion",
    "Pre- and post-attack PVR should therefore be read as physical-validity diagnostics",
    "BiLSTM-ERM suffers a clear F1-score drop",
    "CAT-AD remains stable across the evaluated budgets",
    "CAT-AD reduces ASR and PV-ASR$\mid V_0$ while maintaining stable F1-score behavior"
)
foreach ($marker in $claimMarkers) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$attacks = Get-Content -Raw -Encoding UTF8 -LiteralPath $attacksPath
foreach ($marker in @("target_label: int = 0", "def pgd_phys", "def pgd_phys_penalty", "physical_feasibility_sample_flags")) {
    Assert-Contains "adsb/attacks.py" $attacks $marker
}

$training = Get-Content -Raw -Encoding UTF8 -LiteralPath $trainingPath
foreach ($marker in @("def train_adv_with_val", "phys_out_lambda", "phys_feat_lambda", "pv_asr", "attack_success")) {
    Assert-Contains "adsb/training.py" $training $marker
}

$model = Get-Content -Raw -Encoding UTF8 -LiteralPath $modelPath
Assert-Contains "adsb/model.py" $model "return_features"

$constants = Get-Content -Raw -Encoding UTF8 -LiteralPath $constantsPath
foreach ($marker in @("ADV_TRAIN_EPS", "PHYS_OUT_LAMBDA", "PHYS_FEAT_LAMBDA", "EVAL_ATTACK_EPS")) {
    Assert-Contains "adsb/train_constants.py" $constants $marker
}

$verification = Get-Content -Raw -Encoding UTF8 -LiteralPath $verificationPath
foreach ($marker in @(
    "Status: PASSED",
    "PASS: Standard PGD | asr",
    "PASS: Projection-based phys-PGD | asr",
    "PASS: Penalty-based phys-PGD | asr",
    "PASS: Projection-based phys-PGD | conditional_pv_asr_start_valid",
    "PASS: Penalty-based phys-PGD | conditional_pv_asr_start_valid"
)) {
    Assert-Contains "verification_report.md" $verification $marker
}

$numeric = Get-Content -Raw -Encoding UTF8 -LiteralPath $numericPath
Assert-Contains "NUMERIC_CLAIMS_LEDGER.md" $numeric "Primary Claim Values"
Assert-Contains "NUMERIC_CLAIMS_LEDGER.md" $numeric "Reproducibility Claim"

$claimScope = Get-Content -Raw -Encoding UTF8 -LiteralPath $claimScopePath
Assert-Contains "CLAIM_SCOPE_GUARDRAILS.md" $claimScope "evaluated threat model"
Assert-Contains "CLAIM_SCOPE_GUARDRAILS.md" $claimScope "not a certificate"

$failure = Get-Content -Raw -Encoding UTF8 -LiteralPath $failurePath
Assert-Contains "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md" $failure "PVR is reported as a diagnostic"
Assert-Contains "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md" $failure "CAT-AD w/o Delta X"

$ablation = Get-Content -Raw -Encoding UTF8 -LiteralPath $ablationPath
Assert-Contains "ABLATION_AND_SENSITIVITY_AUDIT.md" $ablation "epsilon-sensitivity"

$attackAudit = Get-Content -Raw -Encoding UTF8 -LiteralPath $attackAuditPath
Assert-Contains "ATTACK_EVALUATION_SANITY_CHECKLIST.md" $attackAudit "Baseline digital ASR is high"

$aggregate = @(Import-Csv -LiteralPath $aggregatePath)
$paired = @(Import-Csv -LiteralPath $pairedPath)
$robustness = @(Import-Csv -LiteralPath $robustnessPath)
$physical = @(Import-Csv -LiteralPath $physicalPath)
$epsilon = @(Import-Csv -LiteralPath $epsilonPath)
$selectedTex = Get-Content -Raw -Encoding UTF8 -LiteralPath $selectedTexPath

if ($paired.Count -ne 14) {
    throw "Expected 14 paired-comparison rows, found $($paired.Count)"
}
if ($robustness.Count -ne 3) {
    throw "Expected 3 robustness summary rows, found $($robustness.Count)"
}
if ($physical.Count -ne 6) {
    throw "Expected 6 physical-feasibility rows, found $($physical.Count)"
}
if ($epsilon.Count -ne 24) {
    throw "Expected 24 epsilon-sensitivity rows, found $($epsilon.Count)"
}

foreach ($setting in @("Standard PGD", "Projection-based phys-PGD", "Penalty-based phys-PGD")) {
    $baselineAsr = Get-AggregateMean $aggregate "Baseline" $setting "asr"
    $catF1 = Get-AggregateMean $aggregate "Proposed" $setting "f1"
    $catAsr = Get-AggregateMean $aggregate "Proposed" $setting "asr"
    if ($baselineAsr -lt 0.90) {
        throw "Baseline ASR is not high enough to support attack-strength wording for ${setting}: $baselineAsr"
    }
    if ($catF1 -lt 0.95) {
        throw "CAT-AD F1 is not high enough to support robustness wording for ${setting}: $catF1"
    }
    if ($catAsr -gt 0.01) {
        throw "CAT-AD ASR is not low enough to support robustness wording for ${setting}: $catAsr"
    }
}

$cleanBaselineF1 = Get-AggregateMean $aggregate "Baseline" "Clean" "f1"
$cleanCatF1 = Get-AggregateMean $aggregate "Proposed" "Clean" "f1"
if ($cleanCatF1 -lt $cleanBaselineF1) {
    throw "CAT-AD clean F1 is below baseline clean F1"
}

foreach ($setting in @("Projection-based phys-PGD", "Penalty-based phys-PGD")) {
    $baselinePvAsr = Get-AggregateMean $aggregate "Baseline" $setting "conditional_pv_asr_start_valid"
    $catPvAsr = Get-AggregateMean $aggregate "Proposed" $setting "conditional_pv_asr_start_valid"
    if ($baselinePvAsr -le 0.80) {
        throw "Baseline PV-ASR is too small to support PV-ASR reduction wording for ${setting}: $baselinePvAsr"
    }
    if ($catPvAsr -gt 0.001) {
        throw "CAT-AD PV-ASR is not near zero for ${setting}: $catPvAsr"
    }
}

foreach ($row in $robustness) {
    if ((To-Double $row.'BiLSTM-ERM ASR') -lt 0.90) {
        throw "Single-run robustness table no longer supports high baseline ASR for $($row.Attack)"
    }
    if ((To-Double $row.'CAT-AD F1-score') -lt 0.95 -or (To-Double $row.'CAT-AD ASR') -gt 0.01) {
        throw "Single-run robustness table no longer supports high-F1/low-ASR CAT-AD claim for $($row.Attack)"
    }
}

foreach ($setting in @("Projection-based Phys-PGD", "Penalty-based Phys-PGD")) {
    $catRows = @($physical | Where-Object { $_.Model -eq "CAT-AD" -and $_.Attack -eq $setting })
    if ($catRows.Count -ne 1) {
        throw "Expected one CAT-AD physical-feasibility row for $setting"
    }
    if ((To-Double $catRows[0].'PV-ASR|V0') -gt 0.01) {
        throw "Physical-feasibility table no longer supports CAT-AD PV-ASR suppression for $setting"
    }
}

foreach ($attackSetting in @("projection_phys_pgd", "penalty_phys_pgd")) {
    $std = @($epsilon | Where-Object { $_.attack_setting -eq $attackSetting -and $_.model -eq "BiLSTM-ERM" } | Sort-Object { To-Double $_.epsilon })
    $cat = @($epsilon | Where-Object { $_.attack_setting -eq $attackSetting -and $_.model -eq "CAT-AD" } | Sort-Object { To-Double $_.epsilon })
    if ($std.Count -ne 6 -or $cat.Count -ne 6) {
        throw "Expected six epsilon rows per model for $attackSetting"
    }
    $stdFirst = To-Double $std[0].f1_score
    $stdLast = To-Double $std[-1].f1_score
    $catValues = @($cat | ForEach-Object { To-Double $_.f1_score })
    $catRange = ($catValues | Measure-Object -Maximum).Maximum - ($catValues | Measure-Object -Minimum).Minimum
    if (($stdFirst - $stdLast) -lt 0.30) {
        throw "BiLSTM-ERM epsilon sensitivity no longer shows a clear F1-score drop for $attackSetting"
    }
    if ($catRange -gt 0.01) {
        throw "CAT-AD epsilon sensitivity no longer supports stability for ${attackSetting}: range=$catRange"
    }
}

foreach ($snippet in @(
    "\textbf{CAT-AD}",
    "Norm-PGD & 0.966",
    "Proj. Phys-PGD & 0.968",
    "Penalty Phys-PGD & 0.968"
)) {
    Assert-Contains "table_multiseed_summary.tex" $selectedTex $snippet
}

Write-Output "manuscript_claim_traceability=PASSED"
Write-Output "narrative_claims_checked=$($claimMarkers.Count)"
Write-Output "aggregate_claim_groups_checked=6"
Write-Output "epsilon_settings_checked=2"

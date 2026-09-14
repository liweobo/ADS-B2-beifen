param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing attack sanity artifact: $Path" }
}
function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { throw "$Name missing marker: $Needle" }
}
function Mean-Metric {
    param([object[]]$Rows, [string]$Model, [string]$Setting, [string]$Metric)
    $match = @($Rows | Where-Object { $_.model -eq $Model -and $_.setting -eq $Setting -and $_.metric -eq $Metric })
    if ($match.Count -ne 1) { throw "Missing aggregate metric: $Model / $Setting / $Metric" }
    return [double]$match[0].mean
}

foreach ($path in @(
    "paper_lncs\main.tex",
    "adsb\attacks.py",
    "tests\test_physical_metrics.py",
    "outputs\publication_benchmark\aggregate_summary.csv",
    "outputs\publication_benchmark\verification_report.md",
    "ATTACK_EVALUATION_SANITY_CHECKLIST.md",
    "ADAPTIVE_ATTACK_AUDIT.md"
)) { Require-File $path }

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath "paper_lncs\main.tex"
foreach ($marker in @(
    "Attack Evaluation Sanity Checks",
    "freezes dropout during attack-gradient computation",
    "high ASR against BiLSTM-ERM",
    "do not establish a formal robustness certificate",
    "evaluated attack families"
)) { Assert-Contains "paper_lncs/main.tex" $paper $marker }

$attacks = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\attacks.py"
foreach ($marker in @(
    "def _attack_grad_context",
    "module.dropout = 0.0",
    "targeted: bool = True",
    "target_label: int = 0",
    "def apply_pgd_malicious_only",
    "def pgd(",
    "def physical_penalty",
    "def _hard_limit_delta",
    "final_projection=True"
)) { Assert-Contains "adsb/attacks.py" $attacks $marker }

$tests = Get-Content -Raw -Encoding UTF8 -LiteralPath "tests\test_physical_metrics.py"
$testMarkers = @(
    "test_apply_pgd_malicious_only_preserves_normal_samples",
    "test_default_pgd_moves_malicious_sample_toward_normal_target",
    "test_default_pgd_multistep_strengthens_target_margin_until_budget",
    "test_attack_grad_context_freezes_and_restores_dropout_state",
    "test_pgd_phys_projection_path_invokes_physical_projection",
    "test_pgd_phys_penalty_returns_diagnostics_and_respects_linf_budget",
    "test_asr_counts_targeted_anomalous_to_normal_evasion",
    "test_pv_asr_is_exact_per_sample_not_product_approximation",
    "test_hard_physical_projection_eliminates_all_trajectory_violations",
    "test_physical_attack_outputs_satisfy_the_audited_constraints"
)
foreach ($marker in $testMarkers) { Assert-Contains "tests/test_physical_metrics.py" $tests $marker }

$aggregate = @(Import-Csv -LiteralPath "outputs\publication_benchmark\aggregate_summary.csv")
$standardBaseline = Mean-Metric $aggregate "Baseline" "Standard PGD" "asr"
$standardCat = Mean-Metric $aggregate "Proposed" "Standard PGD" "asr"
if ($standardBaseline -lt 0.90 -or $standardCat -gt 0.01) {
    throw "Digital PGD strength/suppression check failed: baseline=$standardBaseline CAT-AD=$standardCat"
}

foreach ($setting in @("Projection-based phys-PGD", "Penalty-based phys-PGD")) {
    $baseline = Mean-Metric $aggregate "Baseline" $setting "conditional_pv_asr_start_valid"
    $cat = Mean-Metric $aggregate "Proposed" $setting "conditional_pv_asr_start_valid"
    $coverage = Mean-Metric $aggregate "Baseline" $setting "start_valid_rate"
    if ($baseline -lt 0.80 -or $cat -gt 0.01 -or $coverage -lt 0.75) {
        throw "Physical attack strength/suppression check failed: $setting baseline=$baseline CAT-AD=$cat coverage=$coverage"
    }
}

$report = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\publication_benchmark\verification_report.md"
foreach ($marker in @(
    "Status: PASSED",
    "PASS: Standard PGD | asr",
    "PASS: Projection-based phys-PGD | conditional_pv_asr_start_valid",
    "PASS: Penalty-based phys-PGD | conditional_pv_asr_start_valid",
    "Require physical metrics: True"
)) { Assert-Contains "verification_report.md" $report $marker }

$checklist = Get-Content -Raw -Encoding UTF8 -LiteralPath "ATTACK_EVALUATION_SANITY_CHECKLIST.md"
foreach ($marker in @("not a formal robustness certificate", "valid starts", "hard-projected", "trivially weak")) {
    Assert-Contains "ATTACK_EVALUATION_SANITY_CHECKLIST.md" $checklist $marker
}

$adaptive = Get-Content -Raw -Encoding UTF8 -LiteralPath "ADAPTIVE_ATTACK_AUDIT.md"
foreach ($marker in @("Adaptive-Attack Audit", "Wrong attack objective", "Projection path not used", "Attack too weak overall")) {
    Assert-Contains "ADAPTIVE_ATTACK_AUDIT.md" $adaptive $marker
}

Write-Output "attack_evaluation_sanity=PASSED"
Write-Output "attack_code_markers_checked=9"
Write-Output "attack_test_markers_checked=$($testMarkers.Count)"
Write-Output "attack_metric_groups_checked=3"

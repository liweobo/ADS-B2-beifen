param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing physical-metric artifact: $Path"
    }
}

function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing marker: $Needle"
    }
}

function To-Double {
    param([string]$Value)
    return [double]::Parse($Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Assert-Rate {
    param([string]$Name, [double]$Value)
    if ([double]::IsNaN($Value) -or $Value -lt -1e-9 -or $Value -gt 1.000000001) {
        throw "$Name outside [0,1]: $Value"
    }
}

function Get-Metric {
    param([object[]]$Rows, [string]$Metric)
    $matches = @($Rows | Where-Object { $_.metric -eq $Metric })
    if ($matches.Count -ne 1) {
        throw "Expected one $Metric row, found $($matches.Count)"
    }
    return To-Double $matches[0].value
}

foreach ($path in @(
    "PHYSICAL_METRIC_SEMANTICS_AUDIT.md",
    "paper_lncs\main.tex",
    "adsb\training.py",
    "adsb\attacks.py",
    "tests\test_physical_metrics.py",
    "outputs\publication_benchmark\per_seed_metrics_long.csv",
    "outputs\tables\table_physical_feasibility.csv",
    "results\fig_physical_valid_asr_data.csv"
)) {
    Require-File $path
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath "PHYSICAL_METRIC_SEMANTICS_AUDIT.md"
foreach ($marker in @("Paired Sample-Level Definitions", "New-PVR given V0", "exact per-sample intersection", "Executable Evidence")) {
    Assert-Contains "PHYSICAL_METRIC_SEMANTICS_AUDIT.md" $audit $marker
}

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath "paper_lncs\main.tex"
foreach ($marker in @(
    "Define the valid-start set",
    "\mathrm{New\text{-}PVR}\mid V_0",
    "\mathrm{PV\text{-}ASR}\mid V_0",
    "exact per-sample intersection",
    "attack success and physical validity need not be independent"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}

$training = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\training.py"
foreach ($marker in @(
    '"pre_attack_pvr": float(np.mean(pre_any_flags))',
    '"start_valid_rate": float(np.mean(start_valid))',
    '"conditional_asr_start_valid": conditional_asr',
    '"conditional_pv_asr_start_valid": conditional_pv_asr',
    '"introduced_pvr_start_valid": introduced_pvr',
    '"physical_scope": "paired pre/post attacked anomalous samples"',
    '"conditional_physical_method": "conditioned_on_pre_attack_validity"'
)) {
    Assert-Contains "adsb/training.py" $training $marker
}

$attacks = Get-Content -Raw -Encoding UTF8 -LiteralPath "adsb\attacks.py"
foreach ($marker in @("def _hard_limit_delta", "def physical_feasibility_sample_flags", '"physical_any_violation": position | altitude | speed | heading')) {
    Assert-Contains "adsb/attacks.py" $attacks $marker
}

$tests = Get-Content -Raw -Encoding UTF8 -LiteralPath "tests\test_physical_metrics.py"
foreach ($marker in @(
    "test_pv_asr_is_exact_per_sample_not_product_approximation",
    "test_conditional_physical_metrics_are_nan_without_valid_starts",
    "test_hard_physical_projection_eliminates_all_trajectory_violations",
    "test_physical_attack_outputs_satisfy_the_audited_constraints"
)) {
    Assert-Contains "tests/test_physical_metrics.py" $tests $marker
}

$rows = @(Import-Csv -LiteralPath "outputs\publication_benchmark\per_seed_metrics_long.csv")
$seeds = @($rows | Select-Object -ExpandProperty seed -Unique | Sort-Object)
if (($seeds -join ",") -ne "42,43,44,45,46") {
    throw "Unexpected benchmark seeds: $($seeds -join ',')"
}

$groupsChecked = 0
$projectionZero = 0
foreach ($seed in $seeds) {
    foreach ($model in @("Baseline", "Proposed")) {
        foreach ($setting in @("Projection-based phys-PGD", "Penalty-based phys-PGD")) {
            $group = @($rows | Where-Object { $_.seed -eq $seed -and $_.model -eq $model -and $_.setting -eq $setting })
            $pre = Get-Metric $group "pre_attack_pvr"
            $start = Get-Metric $group "start_valid_rate"
            $post = Get-Metric $group "pvr"
            $new = Get-Metric $group "introduced_pvr_start_valid"
            $asr = Get-Metric $group "conditional_asr_start_valid"
            $pv = Get-Metric $group "conditional_pv_asr_start_valid"
            foreach ($item in @(
                [pscustomobject]@{ Name = "pre"; Value = $pre },
                [pscustomobject]@{ Name = "start"; Value = $start },
                [pscustomobject]@{ Name = "post"; Value = $post },
                [pscustomobject]@{ Name = "new"; Value = $new },
                [pscustomobject]@{ Name = "asr"; Value = $asr },
                [pscustomobject]@{ Name = "pv"; Value = $pv }
            )) {
                Assert-Rate "seed=$seed model=$model setting=$setting $($item.Name)" $item.Value
            }
            if ([Math]::Abs(($pre + $start) - 1.0) -gt 1e-9) {
                throw "Pre-PVR and valid-start rate do not partition the group"
            }
            if ($start -lt 0.75) {
                throw "Valid-start coverage is too small: seed=$seed rate=$start"
            }
            if ($pv -gt $asr + 1e-9 -or $pv -gt (1.0 - $new) + 1e-9) {
                throw "Conditional PV-ASR intersection bound failed"
            }
            if ($setting -eq "Projection-based phys-PGD") {
                if ([Math]::Abs($new) -gt 1e-12 -or [Math]::Abs($post) -gt 1e-12) {
                    throw "Hard projection introduced a physical violation: seed=$seed model=$model"
                }
                $projectionZero += 1
            }
            $groupsChecked += 1
        }
    }
}

$aggregate = @(Import-Csv -LiteralPath "outputs\publication_benchmark\aggregate_summary.csv")
foreach ($setting in @("Projection-based phys-PGD", "Penalty-based phys-PGD")) {
    $base = @($aggregate | Where-Object { $_.model -eq "Baseline" -and $_.setting -eq $setting -and $_.metric -eq "conditional_pv_asr_start_valid" })
    $cat = @($aggregate | Where-Object { $_.model -eq "Proposed" -and $_.setting -eq $setting -and $_.metric -eq "conditional_pv_asr_start_valid" })
    if ($base.Count -ne 1 -or $cat.Count -ne 1 -or (To-Double $base[0].mean) -lt 0.80 -or (To-Double $cat[0].mean) -gt 0.01) {
        throw "Conditional physical attack-strength claim failed for $setting"
    }
}

$physicalRows = @(Import-Csv -LiteralPath "outputs\tables\table_physical_feasibility.csv")
if ($physicalRows.Count -ne 6) { throw "Expected 6 physical table rows" }
foreach ($row in $physicalRows) {
    foreach ($metric in @("Valid-start rate", "Pre-PVR", "Post-PVR", "New-PVR|V0", "ASR|V0", "PV-ASR|V0")) {
        Assert-Rate "physical table $($row.Model) $($row.Attack) $metric" (To-Double $row.$metric)
    }
}

$figureRows = @(Import-Csv -LiteralPath "results\fig_physical_valid_asr_data.csv")
if ($figureRows.Count -ne 6) { throw "Expected 6 figure rows" }
$figureColumns = @($figureRows[0].PSObject.Properties.Name)
foreach ($column in @("model", "attack", "n", "pv_asr", "ci95_low", "ci95_high")) {
    if ($figureColumns -notcontains $column) {
        throw "Physical figure source missing column: $column"
    }
}
foreach ($row in $figureRows) {
    $n = To-Double $row.n
    $pv = To-Double $row.pv_asr
    $ciLow = To-Double $row.ci95_low
    $ciHigh = To-Double $row.ci95_high
    if ([Math]::Abs($n - 5.0) -gt 1e-9) {
        throw "Physical figure source must aggregate five seeds: model=$($row.model) attack=$($row.attack) n=$n"
    }
    Assert-Rate "figure PV-ASR|V0 mean" $pv
    if ([double]::IsNaN($ciLow) -or [double]::IsInfinity($ciLow) -or
        [double]::IsNaN($ciHigh) -or [double]::IsInfinity($ciHigh) -or
        $ciLow -gt $pv + 1e-9 -or $ciHigh -lt $pv - 1e-9) {
        throw "Invalid physical figure confidence interval: model=$($row.model) attack=$($row.attack)"
    }
}

Write-Output "physical_metric_semantics=PASSED"
Write-Output "benchmark_groups_checked=$groupsChecked"
Write-Output "projection_zero_new_violation_groups=$projectionZero"
Write-Output "physical_table_rows_checked=$($physicalRows.Count)"
Write-Output "figure_rows_checked=$($figureRows.Count)"

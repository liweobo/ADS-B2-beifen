$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing literature-baseline artifact: $Path"
    }
    return $candidate
}

function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing expected content: $Needle"
    }
}

function Test-Finite {
    param([object]$Value)
    $number = [double]$Value
    return (-not [double]::IsNaN($number)) -and (-not [double]::IsInfinity($number))
}

$auditPath = Require-File "LITERATURE_BASELINE_REPRODUCTION_AUDIT.md"
$paperPath = Require-File "paper_lncs\main.tex"
$benchmarkDir = Join-Path $RepoRoot "outputs\literature_benchmark"
$manifestPath = Require-File "outputs\literature_benchmark\literature_benchmark_manifest.json"
$reportManifestPath = Require-File "outputs\literature_benchmark\literature_detection_report_manifest.json"
$aggregatePath = Require-File "outputs\literature_benchmark\aggregate_summary.csv"
$pairedPath = Require-File "outputs\literature_benchmark\paired_vs_catad.csv"
$tablePath = Require-File "outputs\literature_benchmark\table_literature_detection.tex"
$reportPath = Require-File "outputs\literature_benchmark\literature_detection_report.md"
$attackAuditPath = Require-File "outputs\literature_benchmark\attack_resolution_audit.json"
Require-File "adsb\literature_models.py" | Out-Null
Require-File "adsb\literature_training.py" | Out-Null
Require-File "adsb\literature_benchmark.py" | Out-Null
Require-File "adsb\literature_report.py" | Out-Null
Require-File "tests\test_literature_models.py" | Out-Null
Require-File "tools\audit_literature_attack_resolution.py" | Out-Null

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath $paperPath
$table = Get-Content -Raw -Encoding UTF8 -LiteralPath $tablePath
$report = Get-Content -Raw -Encoding UTF8 -LiteralPath $reportPath
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
$reportManifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $reportManifestPath | ConvertFrom-Json
$attackAudit = Get-Content -Raw -Encoding UTF8 -LiteralPath $attackAuditPath | ConvertFrom-Json

foreach ($marker in @(
    "Question Answered",
    "Fried--Last",
    "VAE--SVDD",
    "Contextual Autoencoder",
    "protocol-aligned reimplementation",
    "Fair Common Protocol",
    "Attack Reporting Guardrail"
)) {
    Assert-Contains "LITERATURE_BASELINE_REPRODUCTION_AUDIT.md" $audit $marker
}

if (-not $manifest.completed) {
    throw "Literature benchmark is not marked complete"
}
$seeds = @($manifest.seeds | ForEach-Object { [int]$_ })
if ($seeds.Count -ne 5 -or (@($seeds | Select-Object -Unique)).Count -ne 5) {
    throw "Expected five unique literature-benchmark seeds"
}
if (-not $manifest.dataset.reference_sha256_match) {
    throw "Literature benchmark dataset hash was not matched to the reference benchmark"
}
if ($manifest.dataset.sha256 -ne "3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72") {
    throw "Unexpected literature benchmark dataset hash"
}

$published = @($manifest.model_reimplementations)
if ($published.Count -ne 3) {
    throw "Expected three published model reimplementations; found $($published.Count)"
}
$window = $manifest.publication_window
if ($window.start -ne "2019-07-15" -or $window.end -ne "2026-07-15") {
    throw "Literature manifest does not record the audited seven-year publication window"
}
if (@($manifest.literature_inclusion_criteria).Count -lt 4) {
    throw "Literature manifest does not record the required inclusion criteria"
}
$expectedKeys = @("fried_lstm_ae", "vae_svdd", "contextual_ae")
$expectedYears = @{
    "fried_lstm_ae" = 2021
    "vae_svdd" = 2021
    "contextual_ae" = 2022
}
foreach ($key in $expectedKeys) {
    $spec = @($published | Where-Object { $_.key -eq $key })
    if ($spec.Count -ne 1) {
        throw "Missing published model specification: $key"
    }
    if ([int]$spec[0].publication_year -ne [int]$expectedYears[$key]) {
        throw "Unexpected publication year for ${key}: $($spec[0].publication_year)"
    }
}

foreach ($seed in $seeds) {
    $literatureRecordPath = Require-File "outputs\literature_benchmark\runs\seed_$seed\run_record.json"
    $referenceRecordPath = Require-File "outputs\publication_benchmark\runs\seed_$seed\run_record.json"
    $literatureRecord = Get-Content -Raw -Encoding UTF8 -LiteralPath $literatureRecordPath | ConvertFrom-Json
    $referenceRecord = Get-Content -Raw -Encoding UTF8 -LiteralPath $referenceRecordPath | ConvertFrom-Json
    if (-not $literatureRecord.completed) {
        throw "Literature run seed $seed is incomplete"
    }
    foreach ($split in @("train", "validation", "test")) {
        $actual = $literatureRecord.split_summary.aircraft.$split.sha256
        $expected = $referenceRecord.split_summary.aircraft.$split.sha256
        if ($actual -ne $expected) {
            throw "Seed $seed split hash mismatch for $split"
        }
    }
    $actualWindows = $literatureRecord.split_summary.windows | ConvertTo-Json -Depth 12 -Compress
    $expectedWindows = $referenceRecord.split_summary.windows | ConvertTo-Json -Depth 12 -Compress
    if ($actualWindows -ne $expectedWindows) {
        throw "Seed $seed window/label counts differ from the reference benchmark"
    }
    foreach ($key in $expectedKeys) {
        $modelRecord = $literatureRecord.models.$key
        if ($null -eq $modelRecord) {
            throw "Seed $seed missing model record for $key"
        }
        $checkpoint = Join-Path $benchmarkDir ([string]$modelRecord.checkpoint).Replace("/", "\")
        if (-not (Test-Path -LiteralPath $checkpoint -PathType Leaf)) {
            throw "Seed $seed missing checkpoint for $key"
        }
        if (-not (Test-Finite $modelRecord.threshold) -or
            -not (Test-Finite $modelRecord.validation_f1)) {
            throw "Seed $seed has non-finite threshold/validation F1 for $key"
        }
    }
}

$aggregate = @(Import-Csv -LiteralPath $aggregatePath)
$clean = @($aggregate | Where-Object {
    $_.setting -eq "Clean" -and $_.metric -in @("f1", "precision", "recall", "far")
})
if ($clean.Count -ne 20) {
    throw "Expected 20 clean aggregate rows; found $($clean.Count)"
}
foreach ($row in $clean) {
    if ([int]$row.n -ne 5) {
        throw "Clean aggregate row does not contain all seeds: $($row.model)/$($row.metric)"
    }
    if (-not (Test-Finite $row.mean) -or
        -not (Test-Finite $row.ci95_half_width)) {
        throw "Non-finite clean aggregate row: $($row.model)/$($row.metric)"
    }
}
$catF1 = $clean | Where-Object { $_.model -eq "CAT-AD" -and $_.metric -eq "f1" } | Select-Object -First 1
$catFar = $clean | Where-Object { $_.model -eq "CAT-AD" -and $_.metric -eq "far" } | Select-Object -First 1
if ([math]::Abs([double]$catF1.mean - 0.908359892535007) -gt 1e-12 -or
    [math]::Abs([double]$catFar.mean - 0.0260436429236961) -gt 1e-12) {
    throw "CAT-AD clean literature-comparison values changed unexpectedly"
}
foreach ($model in @("Standard BiLSTM", "Fried--Last diff. LSTM-AE", "VAE--SVDD", "Contextual AE")) {
    $f1 = $clean | Where-Object { $_.model -eq $model -and $_.metric -eq "f1" } | Select-Object -First 1
    $far = $clean | Where-Object { $_.model -eq $model -and $_.metric -eq "far" } | Select-Object -First 1
    if ([double]$catF1.mean -le [double]$f1.mean -or [double]$catFar.mean -ge [double]$far.mean) {
        throw "CAT-AD does not have the audited F1/FAR direction against $model"
    }
}

$paired = @(Import-Csv -LiteralPath $pairedPath | Where-Object {
    $_.setting -eq "Clean" -and $_.metric -in @("f1", "far")
})
if ($paired.Count -ne 8) {
    throw "Expected eight paired clean F1/FAR rows; found $($paired.Count)"
}
foreach ($row in $paired) {
    if ([int]$row.n -ne 5 -or [int]$row.wins -ne 5 -or [int]$row.ties -ne 0 -or [int]$row.losses -ne 0) {
        throw "Paired clean direction is incomplete for $($row.baseline)/$($row.metric)"
    }
}

if ($attackAudit.status -ne "passed" -or $attackAudit.model -ne "Fried--Last diff. LSTM-AE") {
    throw "Attack-resolution audit is missing or invalid"
}
if ([double]$attackAudit.fixed_classifier_pgd.mean_malicious_probability -le
    [double]$attackAudit.clean.mean_malicious_probability) {
    throw "Fixed classifier-PGD did not reproduce the audited overshoot"
}
if ([double]$attackAudit.finer_step_diagnostic.mean_malicious_probability -ge
    [double]$attackAudit.clean.mean_malicious_probability) {
    throw "Finer-step diagnostic did not reduce malicious probability"
}
if ([double]$attackAudit.finer_step_diagnostic.asr_at_validation_threshold -le
    [double]$attackAudit.fixed_classifier_pgd.asr_at_validation_threshold) {
    throw "Finer-step diagnostic did not reverse the apparent zero-ASR result"
}

if ($reportManifest.status -ne "verified" -or
    $reportManifest.reporting_scope -ne "unperturbed_detection_only") {
    throw "Literature detection report manifest has an invalid status/scope"
}
if ($reportManifest.publication_window.start -ne "2019-07-15" -or
    $reportManifest.publication_window.end -ne "2026-07-15") {
    throw "Literature report manifest does not preserve the seven-year window"
}
foreach ($marker in @(
    "tab:literature_detection",
    "fried2021autoencoders",
    "luo2021vaesvdd",
    "chevrot2022cae",
    "protocol-aligned reimplementations",
    "July 2019--July 2026",
    "(2021)",
    "(2022)",
    "0.908",
    "0.026"
)) {
    Assert-Contains "table_literature_detection.tex" $table $marker
}
if ($table.IndexOf("PGD ASR", [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "Paper-facing literature table must not promote failed cross-family attack values"
}
foreach ($marker in @(
    "Published-Model Comparison Protocol",
    "rolling seven-year publication window",
    "representative, non-exhaustive",
    "published in 2021--2022",
    "protocol-aligned baselines",
    "step-size sanity check",
    "exclude those attack outputs",
    "table_literature_detection.tex",
    "higher F1-scores and lower FARs"
)) {
    Assert-Contains "paper_lncs/main.tex" $paper $marker
}
Assert-Contains "literature_detection_report.md" $report "Seven-year literature window and selection"
Assert-Contains "literature_detection_report.md" $report "Robustness reporting boundary"

$env:PYTHONIOENCODING = "utf-8"
Push-Location $RepoRoot
try {
    & conda run -n testtorch python -m adsb.literature_report `
        --benchmark-dir outputs\literature_benchmark --verify-only
    if ($LASTEXITCODE -ne 0) {
        throw "adsb.literature_report --verify-only failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Output "literature_baseline_reproduction=PASSED"
Write-Output "published_models_checked=$($published.Count)"
Write-Output "paired_splits_checked=$($seeds.Count)"

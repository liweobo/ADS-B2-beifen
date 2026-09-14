$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing compute-resource artifact: $Path" }
}
function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { throw "$Name missing marker: $Needle" }
}
function Assert-Equal {
    param([string]$Name, $Actual, $Expected)
    if ($Actual -ne $Expected) { throw "$Name mismatch: actual=$Actual expected=$Expected" }
}

foreach ($path in @(
    "COMPUTE_RESOURCE_AUDIT.md",
    "outputs\publication_benchmark\benchmark_manifest.json",
    "outputs\publication_benchmark\benchmark_status.json",
    "outputs\publication_benchmark\verification_report.json",
    "paper_lncs\main.tex",
    "REVIEWER_QUICKSTART.md",
    "ARTIFACT_EVALUATION_GUIDE.md"
)) { Require-File $path }

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath "COMPUTE_RESOURCE_AUDIT.md"
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\publication_benchmark\benchmark_manifest.json" | ConvertFrom-Json
$status = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\publication_benchmark\benchmark_status.json" | ConvertFrom-Json
$verification = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\publication_benchmark\verification_report.json" | ConvertFrom-Json

Assert-Equal "manifest conda env" ([string]$manifest.environment.conda.default_env) "testtorch"
Assert-Contains "manifest python" ([string]$manifest.environment.python) "3.9.21"
Assert-Equal "manifest torch" ([string]$manifest.environment.torch) "2.5.1"
Assert-Equal "manifest cuda availability" ([bool]$manifest.environment.cuda_available) $true
Assert-Equal "manifest cuda version" ([string]$manifest.environment.cuda_version) "12.4"
Assert-Equal "manifest cuDNN version" ([string]$manifest.environment.cudnn_version) "90100"
Assert-Equal "manifest GPU" ([string]$manifest.environment.gpu) "NVIDIA GeForce RTX 4070 Laptop GPU"
Assert-Equal "manifest deterministic config" ([bool]$manifest.config.deterministic) $true
Assert-Equal "manifest log capture config" ([bool]$manifest.config.capture_logs) $true
Assert-Equal "manifest save_models config" ([bool]$manifest.config.save_models) $false

$seeds = @($manifest.config.seeds | ForEach-Object { [int]$_ })
if (($seeds -join ",") -ne "42,43,44,45,46") { throw "Unexpected seed list" }
Assert-Equal "status completed seeds" ([int]$status.summary.completed_seeds) 5
Assert-Equal "status incomplete seeds" ([int]$status.summary.incomplete_seeds) 0
Assert-Equal "verification passed" ([bool]$verification.passed) $true
Assert-Equal "verification aggregate rows" ([int]$verification.summary.num_aggregate_rows) 152
Assert-Equal "verification comparison rows" ([int]$verification.summary.num_comparison_rows) 14

$metricsRowsChecked = 0
$logsChecked = 0
$signatures = @()
foreach ($seed in $seeds) {
    $runDir = "outputs\publication_benchmark\runs\seed_$seed"
    $recordPath = Join-Path $runDir "run_record.json"
    $logPath = Join-Path $runDir "run.log"
    $metricsPath = Join-Path $runDir "per_seed_metrics_long.csv"
    foreach ($path in @($recordPath, $logPath, $metricsPath)) { Require-File $path }
    $record = Get-Content -Raw -Encoding UTF8 -LiteralPath $recordPath | ConvertFrom-Json
    Assert-Equal "seed $seed completed" ([bool]$record.completed) $true
    Assert-Equal "seed $seed record seed" ([int]$record.seed) $seed
    Assert-Equal "seed $seed signature" ([string]$record.resume_signature.sha256) ([string]$manifest.resume.signature.sha256)
    $signatures += [string]$record.resume_signature.sha256
    $metricsRows = @(Import-Csv -LiteralPath $metricsPath).Count
    Assert-Equal "seed $seed metrics rows" ([int]$metricsRows) 152
    $metricsRowsChecked += $metricsRows
    $log = Get-Content -Raw -Encoding UTF8 -LiteralPath $logPath
    Assert-Contains "seed $seed run.log" $log "Using device: cuda"
    Assert-Contains "seed $seed run.log" $log "Epoch"
    Assert-Contains "seed $seed run.log" $log "Adv Epoch"
    $logsChecked += 1
}
Assert-Equal "unique run signatures" (@($signatures | Sort-Object -Unique).Count) 1
Assert-Equal "total per-seed metrics" $metricsRowsChecked 760

foreach ($marker in @(
    "Observed Hardware And Environment",
    "Resumable Execution Boundary",
    "760 per-seed metric rows",
    "wall-clock duration is not reconstructed",
    "observed on this workstation",
    "cross-hardware guarantee",
    "expensive"
)) { Assert-Contains "COMPUTE_RESOURCE_AUDIT.md" $audit $marker }

$paper = Get-Content -Raw -Encoding UTF8 -LiteralPath "paper_lncs\main.tex"
Assert-Contains "paper_lncs/main.tex" $paper "NVIDIA GeForce RTX 4070 Laptop graphics processing unit (GPU)"
Assert-Contains "paper_lncs/main.tex" $paper "resumable per-seed records preserve the runtime boundary and source signature"
Assert-Contains "paper_lncs/main.tex" $paper "compute-resource audit verifies the"

$quickstart = Get-Content -Raw -Encoding UTF8 -LiteralPath "REVIEWER_QUICKSTART.md"
$guide = Get-Content -Raw -Encoding UTF8 -LiteralPath "ARTIFACT_EVALUATION_GUIDE.md"
Assert-Contains "REVIEWER_QUICKSTART.md" $quickstart "compute_resource_audit=PASSED"
Assert-Contains "ARTIFACT_EVALUATION_GUIDE.md" $guide "Compute and runtime profile"

Write-Output "compute_resource_audit=PASSED"
Write-Output "seeds_checked=$($seeds.Count)"
Write-Output "logs_checked=$logsChecked"
Write-Output "metrics_rows_checked=$metricsRowsChecked"
Write-Output "unique_run_signatures=1"

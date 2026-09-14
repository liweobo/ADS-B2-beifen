param()

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing environment reproducibility artifact: $Path"
    }
}

function Assert-Contains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing environment marker: $Needle"
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

function Assert-Sha256 {
    param(
        [string]$Name,
        [string]$Value
    )
    if ($Value -notmatch "^[0-9a-f]{64}$") {
        throw "$Name is not a lowercase SHA-256 digest: $Value"
    }
}

$statementPath = "ENVIRONMENT_REPRODUCIBILITY.md"
$manifestPath = "outputs\publication_benchmark\benchmark_manifest.json"

Require-File $statementPath
Require-File $manifestPath

$statement = Get-Content -Raw -Encoding UTF8 -LiteralPath $statementPath
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json

$probeCode = @'
import json
import sys
import torch
import numpy
import pandas
import sklearn
import matplotlib

print(json.dumps({
    "python_executable": sys.executable,
    "python_version": ".".join(map(str, sys.version_info[:3])),
    "torch": torch.__version__.split("+")[0],
    "numpy": numpy.__version__,
    "pandas": pandas.__version__,
    "scikit-learn": sklearn.__version__,
    "matplotlib": matplotlib.__version__,
    "cuda_available": bool(torch.cuda.is_available()),
}, sort_keys=True))
'@

$probePath = Join-Path $env:TEMP ("catad_env_probe_" + [System.Guid]::NewGuid().ToString("N") + ".py")
try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($probePath, $probeCode, $utf8NoBom)
    $probeText = & conda run -n testtorch python $probePath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to probe conda environment testtorch"
    }
}
finally {
    Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
}
$probeJson = ($probeText | Where-Object { $_ -and $_.Trim().StartsWith("{") } | Select-Object -Last 1)
if (-not $probeJson) {
    throw "Environment probe did not return JSON"
}
$probe = $probeJson | ConvertFrom-Json

if ([string]$probe.python_executable -notmatch "testtorch") {
    throw "Python executable is not from testtorch: $($probe.python_executable)"
}
Assert-Equal "manifest conda env" ([string]$manifest.environment.conda.default_env) "testtorch"

$expectedPackages = $manifest.environment.packages.key_packages
$packageMap = @{
    "torch" = [string]$probe.torch
    "numpy" = [string]$probe.numpy
    "pandas" = [string]$probe.pandas
    "scikit-learn" = [string]$probe."scikit-learn"
    "matplotlib" = [string]$probe.matplotlib
}
$packagesChecked = 0
foreach ($name in @("torch", "numpy", "pandas", "scikit-learn", "matplotlib")) {
    Assert-Equal "package $name" $packageMap[$name] ([string]$expectedPackages.$name)
    $packagesChecked += 1
}

Assert-Contains "manifest python" ([string]$manifest.environment.python) "3.9.21"
Assert-Equal "manifest cuda availability" ([bool]$manifest.environment.cuda_available) ([bool]$probe.cuda_available)
Assert-Sha256 "manifest package snapshot" ([string]$manifest.environment.packages.sha256)
Assert-Sha256 "manifest code fingerprint" ([string]$manifest.provenance.code.sha256)
Assert-Sha256 "manifest data hash" ([string]$manifest.provenance.data.sha256)

$determinism = $manifest.environment.determinism
$determinismChecks = @{
    "torch_deterministic_algorithms" = $true
    "cudnn_deterministic" = $true
    "cudnn_benchmark" = $false
    "cuda_matmul_allow_tf32" = $false
    "cudnn_allow_tf32" = $false
}
$determinismChecked = 0
foreach ($entry in $determinismChecks.GetEnumerator()) {
    Assert-Equal "determinism $($entry.Key)" ([bool]$determinism.($entry.Key)) ([bool]$entry.Value)
    $determinismChecked += 1
}

foreach ($marker in @(
    "conda run -n testtorch python",
    'torch | `2.5.1`',
    'numpy | `2.0.1`',
    'pandas | `2.2.3`',
    'scikit-learn | `1.6.1`',
    'matplotlib | `3.9.4`',
    "torch_deterministic_algorithms=true",
    "cudnn_benchmark=false",
    "not turn the empirical robustness result into a formal proof"
)) {
    Assert-Contains $statementPath $statement $marker
}

Write-Output "environment_reproducibility=PASSED"
Write-Output "conda_env=testtorch"
Write-Output "python_executable=$($probe.python_executable)"
Write-Output "packages_checked=$packagesChecked"
Write-Output "determinism_markers_checked=$determinismChecked"

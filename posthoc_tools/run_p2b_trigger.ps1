$ErrorActionPreference = "Stop"
$projectRoot = "D:\ADS-B2 -beifen"
$outputRoot = Join-Path $projectRoot "outputs\attack_audit_c001\p2b"
$env:PYTHONDONTWRITEBYTECODE = "1"
$started = [DateTime]::UtcNow.ToString("o")
Set-Location -LiteralPath $projectRoot
& conda run --no-capture-output -n testtorch python -m posthoc_tools.p2b_reaggregation `
    --phase trigger --project-root $projectRoot *>> (Join-Path $outputRoot "p2b_trigger.log")
$exitCode = $LASTEXITCODE
[ordered]@{
    started_utc = $started
    completed_utc = [DateTime]::UtcNow.ToString("o")
    exit_code = $exitCode
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot "p2b_trigger_process.json") -Encoding UTF8
exit $exitCode

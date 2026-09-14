param(
    [string]$ProjectRoot = 'E:\ads-b\ADS-B2 -beifen'
)

$ErrorActionPreference = 'Stop'
$P3 = Join-Path $ProjectRoot 'outputs\attack_audit_c001\p3_diagnostic'
$GuardianLock = Join-Path $P3 'p3d_guardian.lock'
$GuardianLog = Join-Path $P3 'p3d_guardian.log'
$Conda = 'D:\anaconda3\Scripts\conda.exe'

function Write-GuardianLog([string]$Message) {
    $line = ('{0} {1}' -f ([DateTime]::UtcNow.ToString('o')), $Message)
    Add-Content -LiteralPath $GuardianLog -Value $line -Encoding UTF8
}

function Get-LossCounts([string]$Loss) {
    $inventory = Join-Path $P3 "$Loss\task_inventory.csv"
    if (-not (Test-Path -LiteralPath $inventory)) {
        throw "Missing inventory: $inventory"
    }
    $rows = Import-Csv -LiteralPath $inventory
    return [pscustomobject]@{
        Expected = $rows.Count
        Completed = @($rows | Where-Object { $_.execution_status -eq 'completed' }).Count
        Running = @($rows | Where-Object { $_.execution_status -eq 'running' }).Count
        Scheduled = @($rows | Where-Object { $_.execution_status -eq 'scheduled' }).Count
        Failed = @($rows | Where-Object { $_.execution_status -eq 'failed' }).Count
    }
}

function Assert-NoStaleRunnerLock {
    $runnerLock = Join-Path $P3 'p3d_runner.lock'
    if (-not (Test-Path -LiteralPath $runnerLock)) {
        return $false
    }
    $lock = Get-Content -Raw -LiteralPath $runnerLock | ConvertFrom-Json
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($lock.pid)" -ErrorAction SilentlyContinue
    $pattern = "python(\.exe)?\s+-m\s+audit_tools\.p3d_runner\s+run\s+--loss\s+$($lock.loss)"
    if (-not $process -or $process.CommandLine -notmatch $pattern) {
        throw "Stale or mismatched runner lock; refusing automatic mutation: $($lock | ConvertTo-Json -Compress)"
    }
    return $true
}

if (Test-Path -LiteralPath $GuardianLock) {
    $existing = Get-Content -Raw -LiteralPath $GuardianLock | ConvertFrom-Json
    $process = Get-Process -Id $existing.pid -ErrorAction SilentlyContinue
    if ($process) {
        throw "P3-Diagnostic guardian already active: PID $($existing.pid)"
    }
    throw "Stale guardian lock requires manual forensic review: $GuardianLock"
}

$lockPayload = [ordered]@{
    pid = $PID
    created_at_utc = [DateTime]::UtcNow.ToString('o')
    policy = 'MARGIN_80_THEN_CW_80_THEN_FINALIZE; STOP_ON_FAILED_OR_STALE_LOCK'
}
$lockPayload | ConvertTo-Json | Set-Content -LiteralPath $GuardianLock -Encoding UTF8

try {
    Write-GuardianLog "GUARDIAN_START pid=$PID"
    while ($true) {
        if (Test-Path -LiteralPath (Join-Path $P3 'gates\p3d_final_integrity_gate.json')) {
            Write-GuardianLog 'FINAL_GATE_ALREADY_EXISTS; STOP'
            break
        }

        if (Assert-NoStaleRunnerLock) {
            Start-Sleep -Seconds 30
            continue
        }

        $margin = Get-LossCounts 'margin'
        $cw = Get-LossCounts 'cw'
        Write-GuardianLog ("STATUS margin={0}/80 running={1} failed={2}; cw={3}/80 running={4} failed={5}" -f $margin.Completed, $margin.Running, $margin.Failed, $cw.Completed, $cw.Running, $cw.Failed)

        if ($margin.Expected -ne 80 -or $cw.Expected -ne 80) {
            throw "Inventory cardinality mismatch: margin=$($margin.Expected), cw=$($cw.Expected)"
        }
        if ($margin.Failed -gt 0 -or $cw.Failed -gt 0) {
            throw "A failed task exists; automatic progression is forbidden. margin_failed=$($margin.Failed) cw_failed=$($cw.Failed)"
        }

        if ($margin.Completed -lt 80) {
            $before = $margin.Completed
            Write-GuardianLog "START_MARGIN_RESUME completed=$before"
            & $Conda run --no-capture-output -n testtorch python -m audit_tools.p3d_runner run --loss margin 1>> (Join-Path $P3 'margin_runner.stdout.log') 2>> (Join-Path $P3 'margin_runner.stderr.log')
            $exitCode = $LASTEXITCODE
            $after = (Get-LossCounts 'margin').Completed
            Write-GuardianLog "MARGIN_EXIT code=$exitCode completed=$after"
            if ($exitCode -ne 0 -and $after -le $before) {
                throw "Margin exited nonzero without committed progress: exit=$exitCode completed=$after"
            }
            continue
        }

        if ($margin.Completed -ne 80) {
            throw "Margin completeness is not exactly 80: $($margin.Completed)"
        }

        if ($cw.Completed -lt 80) {
            $before = $cw.Completed
            Write-GuardianLog "START_CW_RESUME completed=$before"
            & $Conda run --no-capture-output -n testtorch python -m audit_tools.p3d_runner run --loss cw 1>> (Join-Path $P3 'cw_runner.stdout.log') 2>> (Join-Path $P3 'cw_runner.stderr.log')
            $exitCode = $LASTEXITCODE
            $after = (Get-LossCounts 'cw').Completed
            Write-GuardianLog "CW_EXIT code=$exitCode completed=$after"
            if ($exitCode -ne 0 -and $after -le $before) {
                throw "CW exited nonzero without committed progress: exit=$exitCode completed=$after"
            }
            continue
        }

        if ($cw.Completed -ne 80) {
            throw "CW completeness is not exactly 80: $($cw.Completed)"
        }

        Write-GuardianLog 'START_FINALIZER margin=80 cw=80'
        & $Conda run --no-capture-output -n testtorch python -m audit_tools.p3d_finalize finalize 1>> (Join-Path $P3 'finalizer.stdout.log') 2>> (Join-Path $P3 'finalizer.stderr.log')
        $exitCode = $LASTEXITCODE
        Write-GuardianLog "FINALIZER_EXIT code=$exitCode"
        if ($exitCode -ne 0) {
            throw "Finalizer failed with exit code $exitCode"
        }
        break
    }
    Write-GuardianLog 'GUARDIAN_COMPLETE'
}
catch {
    Write-GuardianLog ("GUARDIAN_STOP error=" + $_.Exception.Message)
    throw
}
finally {
    Remove-Item -LiteralPath $GuardianLock -Force -ErrorAction SilentlyContinue
}

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required numeric-claims artifact: $Path"
    }
}

function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::Ordinal) -lt 0) {
        throw "$Name missing expected text: $Needle"
    }
}

function Assert-Close {
    param([string]$Name, [double]$Actual, [double]$Expected)
    if ([Math]::Abs($Actual - $Expected) -gt 1e-12) {
        throw "$Name mismatch: expected=$Expected actual=$Actual"
    }
}

foreach ($path in @(
    "NUMERIC_CLAIMS_LEDGER.md",
    "outputs\publication_benchmark\verification_report.md",
    "outputs\publication_benchmark\paired_comparisons.csv",
    "outputs\tables\table_multiseed_summary.tex"
)) {
    Require-File $path
}

$ledger = Get-Content -Raw -Encoding UTF8 -LiteralPath "NUMERIC_CLAIMS_LEDGER.md"
$verification = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\publication_benchmark\verification_report.md"
$aggregateTex = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\tables\table_multiseed_summary.tex"
$paired = @(Import-Csv -LiteralPath "outputs\publication_benchmark\paired_comparisons.csv")

foreach ($marker in @(
    "Primary Claim Values",
    "Multi-Seed Table Values Used in the Manuscript",
    "Reproducibility Claim",
    "conditional_pv_asr_start_valid",
    "No primary row is significant after Holm correction"
)) {
    Assert-Contains "NUMERIC_CLAIMS_LEDGER.md" $ledger $marker
}

foreach ($marker in @(
    "Status: PASSED",
    "Seeds: 42,43,44,45,46",
    "Long rows: 760",
    "Wide rows: 40",
    "Aggregate rows: 152",
    "Paired comparison rows: 14",
    "Warnings",
    "Errors"
)) {
    Assert-Contains "verification_report.md" $verification $marker
}

$expectedClaims = @(
    [pscustomobject]@{ Setting = "Clean"; Metric = "f1"; Expected = 0.02958602649106081 },
    [pscustomobject]@{ Setting = "Standard PGD"; Metric = "asr"; Expected = 0.9838341036621386 },
    [pscustomobject]@{ Setting = "Projection-based phys-PGD"; Metric = "asr"; Expected = 0.9307828179853633 },
    [pscustomobject]@{ Setting = "Penalty-based phys-PGD"; Metric = "asr"; Expected = 0.92884479273289 },
    [pscustomobject]@{ Setting = "Projection-based phys-PGD"; Metric = "conditional_pv_asr_start_valid"; Expected = 0.9334063588276182 },
    [pscustomobject]@{ Setting = "Penalty-based phys-PGD"; Metric = "conditional_pv_asr_start_valid"; Expected = 0.9303760725785777 }
)

foreach ($claim in $expectedClaims) {
    $matches = @($paired | Where-Object { $_.setting -eq $claim.Setting -and $_.metric -eq $claim.Metric })
    if ($matches.Count -ne 1) {
        throw "Expected one paired row for $($claim.Setting) / $($claim.Metric)"
    }
    Assert-Close "$($claim.Setting) / $($claim.Metric)" ([double]$matches[0].mean_improvement) $claim.Expected
    if ([int]$matches[0].n -ne 5 -or [double]$matches[0].win_rate -ne 1.0) {
        throw "Primary claim lacks five-seed directional consistency: $($claim.Setting) / $($claim.Metric)"
    }
    if ([double]$matches[0].p_two_sided_sign_flip -ne 0.0625) {
        throw "Unexpected exact sign-flip p-value: $($claim.Setting) / $($claim.Metric)"
    }
    $expectedText = [string]$matches[0].mean_improvement
    Assert-Contains "NUMERIC_CLAIMS_LEDGER.md" $ledger $expectedText
}

$expectedTableRows = @(
    'Unperturbed & 0.879 (0.036) & -- & -- & 0.038 (0.005)',
    'Norm-PGD & 0.022 (0.036) & 0.988 (0.021)',
    'Proj. Phys-PGD & 0.112 (0.148) & 0.931 (0.095) & 0.934 (0.094)',
    'Penalty Phys-PGD & 0.114 (0.154) & 0.929 (0.099) & 0.931 (0.100)',
    'Unperturbed & 0.908 (0.023) & -- & -- & 0.026 (0.006)',
    'Norm-PGD & 0.966 (0.007) & 0.004 (0.007)',
    'Proj. Phys-PGD & 0.968 (0.006) & 0.0006 (0.0009) & 0.0002 (0.0005)',
    'Penalty Phys-PGD & 0.968 (0.006) & 0.0006 (0.001) & 0.0002 (0.0005)'
)
foreach ($row in $expectedTableRows) {
    Assert-Contains "aggregate_selected_summary.tex" $aggregateTex $row
}

foreach ($ledgerRow in @(
    "BiLSTM-ERM | Unperturbed | F1-score | 0.8788 | 0.0293 | [0.8424, 0.9152]",
    "CAT-AD | Unperturbed | F1-score | 0.9084 | 0.0186 | [0.8852, 0.9315]",
    "BiLSTM-ERM | Norm-bounded PGD | ASR | 0.9878 | 0.0166 | [0.9672, 1.0084]",
    "CAT-AD | Norm-bounded PGD | ASR | 0.0040 | 0.0054 | [-0.0028, 0.0107]",
    "BiLSTM-ERM | Projection-based Phys-PGD | PV-ASR (valid start) | 0.9336 | 0.0760 | [0.8392, 1.0280]",
    "CAT-AD | Projection-based Phys-PGD | PV-ASR (valid start) | 0.0002 | 0.0004 | [-0.0004, 0.0007]",
    "BiLSTM-ERM | Penalty-based Phys-PGD | PV-ASR (valid start) | 0.9306 | 0.0804 | [0.8307, 1.0304]",
    "CAT-AD | Penalty-based Phys-PGD | PV-ASR (valid start) | 0.0002 | 0.0004 | [-0.0004, 0.0007]"
)) {
    Assert-Contains "NUMERIC_CLAIMS_LEDGER.md" $ledger $ledgerRow
}

Write-Output "numeric_claims=PASSED"
Write-Output "primary_claims_checked=$($expectedClaims.Count)"
Write-Output "table_rows_checked=$($expectedTableRows.Count)"

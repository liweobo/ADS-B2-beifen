$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Require-File {
    param([string]$Path)
    $candidate = Join-Path $RepoRoot $Path
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing claim-scope artifact: $Path"
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
        throw "$Name missing required scope text: $Needle"
    }
}

function Assert-NotContains {
    param(
        [string]$Name,
        [string]$Text,
        [string]$Needle
    )
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Name contains forbidden overclaiming phrase: $Needle"
    }
}

$paperPath = Require-File "paper_lncs\main.tex"
$guardrailsPath = Require-File "CLAIM_SCOPE_GUARDRAILS.md"
$innovationPath = Require-File "INNOVATION_AND_EVIDENCE.md"
$readinessPath = Require-File "TOP_CONFERENCE_READINESS_AUDIT.md"

$paper = Get-Content -Raw -LiteralPath $paperPath
$guardrails = Get-Content -Raw -LiteralPath $guardrailsPath
$innovation = Get-Content -Raw -LiteralPath $innovationPath
$readiness = Get-Content -Raw -LiteralPath $readinessPath

$requiredPaperPhrases = @(
    "All robustness claims are limited to the evaluated perturbation settings and threat model.",
    "Therefore, this paper does not claim that ADS-B anomaly detection, recurrent detectors, PGD attacks, adversarial examples, or adversarial training are new.",
    "The novelty claim is narrower",
    "should not be interpreted as a certificate against arbitrary adaptive attackers"
)

foreach ($phrase in $requiredPaperPhrases) {
    Assert-Contains "paper_lncs/main.tex" $paper $phrase
}

$requiredGuardrailPhrases = @(
    "Allowed Claims",
    "Required Limiting Language",
    "Disallowed Claims",
    "Local Check"
)
foreach ($phrase in $requiredGuardrailPhrases) {
    Assert-Contains "CLAIM_SCOPE_GUARDRAILS.md" $guardrails $phrase
}

foreach ($phrase in @(
    "What Is Not Claimed as New",
    "This is evidence for a scoped novelty claim",
    "to the best of our knowledge"
)) {
    Assert-Contains "INNOVATION_AND_EVIDENCE.md" $innovation $phrase
}

foreach ($phrase in @(
    "Overclaiming novelty",
    "Claim should remain",
    "not an aviation safety certificate"
)) {
    Assert-Contains "TOP_CONFERENCE_READINESS_AUDIT.md" $readiness $phrase
}

$forbiddenPaperPhrases = @(
    "state-of-the-art",
    "SOTA",
    "first-ever",
    "certified robustness",
    "guaranteed robustness",
    "solves ADS-B security",
    "proves real-world flight safety",
    "covers all possible adaptive attacks",
    "outperforms all"
)

foreach ($phrase in $forbiddenPaperPhrases) {
    Assert-NotContains "paper_lncs/main.tex" $paper $phrase
}

Write-Output "claim_scope=PASSED"
Write-Output "required_scope_phrases_checked=$($requiredPaperPhrases.Count)"
Write-Output "forbidden_phrases_checked=$($forbiddenPaperPhrases.Count)"

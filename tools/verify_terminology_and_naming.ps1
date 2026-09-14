param(
    [string]$ReportPath = "outputs\audits\terminology_and_naming_verification.json"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing terminology-audit input: $Path"
    }
}

function Assert-Contains {
    param([string]$Label, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::Ordinal) -lt 0) {
        throw "$Label is missing required terminology marker: $Needle"
    }
}

function Assert-NotContainsInsensitive {
    param([string]$Label, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "$Label contains prohibited ambiguous terminology: $Needle"
    }
}

$manuscriptPath = "paper_lncs\main.tex"
$auditPath = "TERMINOLOGY_AND_NAMING_AUDIT.md"
$namingCodePath = "adsb\paper_naming.py"
$modelCodePath = "adsb\model.py"

$publicationSurfaces = @(
    $manuscriptPath,
    "outputs\publication_benchmark\data_split_audit.tex",
    "outputs\tables\table_experimental_setup.tex",
    "outputs\tables\table_clean_performance.tex",
    "outputs\tables\table_robustness_summary.tex",
    "outputs\tables\table_physical_feasibility.tex",
    "outputs\tables\table5_ablation_study.tex",
    "outputs\tables\table_multiseed_summary.tex",
    "outputs\tables\table_paired_multiseed_comparison.tex",
    "outputs\literature_benchmark\table_literature_detection.tex",
    "outputs\literature_benchmark\literature_detection_report.md",
    "outputs\literature_benchmark\table_literature_baselines.tex",
    "results\fig_physical_valid_asr_data.csv",
    "results\fig_epsilon_sensitivity_data.csv",
    "figures\fig_main_robustness.svg",
    "figures\fig_physical_valid_asr.svg",
    "figures\fig_epsilon_sensitivity.svg"
)

foreach ($path in @($auditPath, $namingCodePath, $modelCodePath) + $publicationSurfaces) {
    Require-File $path
}

$manuscript = Get-Content -Raw -Encoding UTF8 -LiteralPath $manuscriptPath
$requiredDefinitions = @(
    'Automatic Dependent Surveillance--Broadcast (ADS-B)',
    'bidirectional long short-term memory (BiLSTM)',
    'constrained adversarial training for anomaly detection (CAT-AD)',
    'norm-bounded projected gradient descent without physical constraints (Norm-bounded PGD)',
    'physically constrained PGD (Phys-PGD)',
    'false alarm rate (FAR)',
    'attack success rate (ASR)',
    'physical violation rates (PVR)',
    'empirical risk minimization (BiLSTM-ERM)',
    'Kullback--Leibler (KL) divergence',
    'mean squared error (MSE)',
    'variational autoencoder (VAE)',
    'radial basis function (RBF)',
    'support vector data description (SVDD)',
    'Contextual Autoencoder (Contextual AE)',
    'Benjamini--Hochberg (BH)',
    'Coordinated Universal Time (UTC)',
    'comma-separated values (CSV)',
    '256-bit Secure Hash Algorithm (SHA-256)',
    'graphics processing unit (GPU)',
    'Portable Document Format (PDF)',
    'Lecture Notes in Computer Science (LNCS)'
)
foreach ($marker in $requiredDefinitions) {
    Assert-Contains "manuscript" $manuscript $marker
}

$requiredHeadings = @(
    '\paragraph{ADS-B Security and Trajectory Data.}',
    '\paragraph{ADS-B Anomaly Detection.}',
    '\paragraph{Adversarial Robustness.}',
    '\paragraph{Positioning against Prior Work.}',
    '\paragraph{Construct Validity.}',
    '\paragraph{Internal Validity.}',
    '\paragraph{External Validity.}',
    '\paragraph{Artifact Validity.}'
)
foreach ($heading in $requiredHeadings) {
    Assert-Contains "manuscript" $manuscript $heading
}

$forbiddenPublicationTerms = @(
    "Standard BiLSTM",
    "standard BiLSTM",
    "Unconstrained PGD",
    "Fried--Last diff. LSTM-AE",
    "Fried--Last AE",
    "Full proposed method",
    "benign view",
    "benign-only",
    "malicious-only",
    "malicious samples",
    "malicious trajectories",
    "malicious windows",
    "clean-detection",
    "clean detection",
    "clean comparison",
    "clean trajectories"
)

foreach ($path in $publicationSurfaces) {
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $path
    foreach ($term in $forbiddenPublicationTerms) {
        Assert-NotContainsInsensitive $path $text $term
    }
    if ($text.IndexOf([char]0xFFFD) -ge 0) {
        throw "$path contains a Unicode replacement character"
    }
}

$robustnessTable = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\tables\table_robustness_summary.tex"
Assert-Contains "robustness table" $robustnessTable 'shortstack{BiLSTM-ERM\\F1-score}'
Assert-Contains "robustness table" $robustnessTable "Norm-bounded PGD"

$literatureTable = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\literature_benchmark\table_literature_detection.tex"
Assert-Contains "literature table" $literatureTable "Fried--Last Differenced"
Assert-Contains "literature table" $literatureTable "VAE--SVDD (2021)"
Assert-Contains "literature table" $literatureTable "Contextual AE (2022)"
Assert-Contains "literature table" $literatureTable "Same-protocol unperturbed detection"

$physicalTable = Get-Content -Raw -Encoding UTF8 -LiteralPath "outputs\tables\table_physical_feasibility.tex"
Assert-Contains "physical table" $physicalTable "Speed VR"
Assert-Contains "physical table" $physicalTable "Speed denotes ground speed"

$namingCode = Get-Content -Raw -Encoding UTF8 -LiteralPath $namingCodePath
Assert-Contains "paper_naming.py" $namingCode 'ERM_BILSTM_DISPLAY_NAME = "BiLSTM-ERM"'
Assert-Contains "paper_naming.py" $namingCode 'NORM_BOUNDED_PGD_DISPLAY_NAME = "Norm-bounded PGD"'
Assert-Contains "paper_naming.py" $namingCode '"Standard BiLSTM": ERM_BILSTM_DISPLAY_NAME'
Assert-Contains "paper_naming.py" $namingCode '"Unconstrained PGD": NORM_BOUNDED_PGD_DISPLAY_NAME'
Assert-Contains "paper_naming.py" $namingCode 'Archived result files retain legacy schema keys'

$modelCode = Get-Content -Raw -Encoding UTF8 -LiteralPath $modelCodePath
Assert-Contains "model.py" $modelCode "index 0 = normal and index 1 = anomalous"
Assert-Contains "model.py" $modelCode "final forward state is at the last time step"
if ($modelCode.IndexOf([char]0xFFFD) -ge 0) {
    throw "model.py contains a Unicode replacement character"
}

$audit = Get-Content -Raw -Encoding UTF8 -LiteralPath $auditPath
foreach ($marker in @(
    "Canonical Scientific Names",
    "Published Comparator Names",
    "Abbreviation Inventory",
    "Code and Archive Compatibility",
    "BiLSTM-ERM",
    "Norm-bounded PGD",
    "Fried--Last Differenced LSTM-AE"
)) {
    Assert-Contains "terminology audit" $audit $marker
}

$report = [ordered]@{
    status = "passed"
    manuscript = $manuscriptPath.Replace("\", "/")
    audit = $auditPath
    publication_surfaces_checked = $publicationSurfaces.Count
    definitions_checked = $requiredDefinitions.Count
    headings_checked = $requiredHeadings.Count
    prohibited_terms_checked_per_surface = $forbiddenPublicationTerms.Count
    canonical_model_names = @("BiLSTM-ERM", "CAT-AD")
    canonical_attack_names = @(
        "Norm-bounded PGD",
        "Projection-based Phys-PGD",
        "Penalty-based Phys-PGD"
    )
    archive_compatibility = "legacy keys accepted only through explicit aliases"
}

$reportFile = if ([System.IO.Path]::IsPathRooted($ReportPath)) {
    $ReportPath
} else {
    Join-Path $RepoRoot $ReportPath
}
$reportDir = Split-Path -Parent $reportFile
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportFile -Encoding UTF8

Write-Output "terminology_and_naming=PASSED"
Write-Output "publication_surfaces_checked=$($publicationSurfaces.Count)"
Write-Output "definitions_checked=$($requiredDefinitions.Count)"
Write-Output "report=$reportFile"

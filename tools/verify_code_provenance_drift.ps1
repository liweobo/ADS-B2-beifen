param(
    [string]$ManifestPath = "outputs\publication_benchmark\benchmark_manifest.json",
    [string]$AuditPath = "CODE_PROVENANCE_DRIFT_AUDIT.md"
)

$ErrorActionPreference = "Stop"

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required file: $Path"
    }
    return $Path
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Normalize-PathText {
    param([string]$Path)
    return $Path.Replace("\", "/")
}

function Get-CurrentCodeFiles {
    $sourceRoots = @("adsb", "tools", "tests")
    $suffixes = @(".py", ".md", ".txt", ".toml", ".yaml", ".yml")
    $files = @()
    foreach ($root in $sourceRoots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        Get-ChildItem -LiteralPath $root -Recurse -File |
            Where-Object {
                $_.FullName -notmatch "__pycache__" -and
                $suffixes -contains $_.Extension.ToLowerInvariant()
            } |
            ForEach-Object {
                $relative = $_.FullName.Substring((Resolve-Path .).Path.Length + 1)
                $files += (Normalize-PathText $relative)
            }
    }
    foreach ($name in @("AGENTS.md", "EXPERIMENTS.md", "requirements.txt")) {
        if (Test-Path -LiteralPath $name -PathType Leaf) {
            $files += $name
        }
    }
    return @($files | Sort-Object -Unique)
}

function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$Name missing expected marker: $Needle"
    }
}

$manifestFile = Require-File $ManifestPath
$auditFile = Require-File $AuditPath
$manifest = Get-Content -Raw -LiteralPath $manifestFile | ConvertFrom-Json
$audit = Get-Content -Raw -LiteralPath $auditFile

foreach ($marker in @(
    "Current Drift Boundary",
    "Allowed changed files",
    "Allowed added files",
    "Guardrail",
    "rerun before making updated quantitative claims"
)) {
    Assert-Contains $AuditPath $audit $marker
}

$manifestEntries = @{}
foreach ($entry in @($manifest.provenance.code.files)) {
    $path = Normalize-PathText ([string]$entry.path)
    $manifestEntries[$path] = $entry
}

if ($manifestEntries.Count -lt 20) {
    throw "Manifest code file list is unexpectedly small: $($manifestEntries.Count)"
}

$currentFiles = Get-CurrentCodeFiles
$currentSet = @{}
foreach ($path in $currentFiles) {
    $currentSet[$path] = $true
}

$allowedChanged = @{
    "adsb/ablation_table5.py" = "paper-export table typography"
    "adsb/benchmark.py" = "paper-export LaTeX typography and table layout"
    "adsb/run.py" = "conda entry-point documentation"
    "adsb/trajectory_compare.py" = "conda helper text"
    "adsb/paper_tables.py" = "canonical paper-facing names, metric labels, and table notes"
    "adsb/paper_naming.py" = "canonical publication names with legacy archive aliases"
    "adsb/paper_style.py" = "BiLSTM-ERM style alias"
    "adsb/plots.py" = "canonical model names in publication-facing plot labels"
    "adsb/fig4_asr_pvr_tradeoff.py" = "paired valid-start physical figure export"
    "adsb/fig5_epsilon_sensitivity.py" = "canonical model names and English figure-export documentation"
    "adsb/model.py" = "comment-only clarification of class logits and bidirectional state selection"
    "adsb/dataloading.py" = "additive clean one-class loader views with legacy split/window outputs checked unchanged"
    "tools/regenerate_paper_exports.py" = "paper-export relative path logging"
    "tools/build_zhong.py" = "conda generated-script examples"
    "tools/build_primary_seed_direction_summary.ps1" = "conditional primary-claim summary"
    "tools/verify_numeric_claims.ps1" = "corrected numeric-claim audit"
    "tools/verify_manuscript_claim_traceability.ps1" = "conditional physical-claim audit"
    "tools/verify_claim_hierarchy.ps1" = "conditional primary-claim hierarchy"
    "tools/verify_seed_direction_consistency.ps1" = "conditional primary seed directions"
    "tools/verify_physical_metric_semantics.ps1" = "paired pre/post physical-metric audit"
    "tools/verify_attack_evaluation_sanity.ps1" = "hard-projection and attack-strength audit"
    "tools/verify_novelty_evidence.ps1" = "valid-start novelty criterion"
    "tools/verify_figure_source_consistency.ps1" = "conditional physical-figure provenance"
    "tools/verify_code_provenance_drift.ps1" = "explicit post-benchmark drift boundary"
    "tests/test_benchmark_stats.py" = "conda synthetic manifest fixture"
    "tests/test_submission_tex_generation.py" = "canonical physical-table terminology regression"
    "EXPERIMENTS.md" = "documented independently manifested published-model comparison"
}
$allowedAdded = @{
    "tests/test_physical_metrics.py" = "post-benchmark physical-metric regression tests"
    "tests/test_submission_tex_generation.py" = "post-benchmark paper-export regression tests"
    "adsb/literature_models.py" = "independently manifested published ADS-B model reimplementations"
    "adsb/literature_training.py" = "benign-only training for independently manifested literature baselines"
    "adsb/literature_benchmark.py" = "same-split published-model benchmark with exact reference-split checks"
    "adsb/literature_report.py" = "unperturbed-detection report generator and hash verifier"
    "tools/audit_literature_attack_resolution.py" = "cross-objective PGD step-size diagnostic"
    "tests/test_literature_models.py" = "published-model architecture and gradient regression tests"
    "tests/test_literature_report.py" = "clean literature-report scope regression tests"
    "tests/test_paper_naming.py" = "canonical display-name and legacy-alias regression tests"
}

$criticalUnchanged = @(
    "adsb/attacks.py",
    "adsb/data.py",
    "adsb/dataset.py",
    "adsb/publication_claims.py",
    "adsb/training.py",
    "adsb/verify_artifacts.py",
    "tools/preflight_publication_data.py",
    "tools/run_publication_gate.py"
)

$changed = @()
$missing = @()
foreach ($path in ($manifestEntries.Keys | Sort-Object)) {
    if (-not $currentSet.ContainsKey($path)) {
        $missing += $path
        continue
    }
    $item = Get-Item -LiteralPath ($path.Replace("/", "\"))
    $currentSha = Get-Sha256 ($path.Replace("/", "\"))
    $entry = $manifestEntries[$path]
    if ([int64]$entry.size_bytes -ne [int64]$item.Length -or [string]$entry.sha256 -ne $currentSha) {
        $changed += $path
    }
}

$added = @($currentFiles | Where-Object { -not $manifestEntries.ContainsKey($_) } | Sort-Object)

if ($missing.Count -gt 0) {
    throw "Manifest code files missing from current tree: $($missing -join ', ')"
}

foreach ($path in $changed) {
    if (-not $allowedChanged.ContainsKey($path)) {
        throw "Unapproved code provenance drift: $path"
    }
}

foreach ($path in $added) {
    if (-not $allowedAdded.ContainsKey($path)) {
        throw "Unapproved code file added after benchmark manifest: $path"
    }
}

foreach ($path in $criticalUnchanged) {
    if ($changed -contains $path) {
        throw "Critical experiment file drifted from benchmark manifest: $path"
    }
    if ($missing -contains $path) {
        throw "Critical experiment file missing from current tree: $path"
    }
}

Assert-Contains "adsb/run.py" (Get-Content -Raw -LiteralPath "adsb\run.py") "conda run -n testtorch python -m adsb.run"
Assert-Contains "adsb/ablation_table5.py" (Get-Content -Raw -LiteralPath "adsb\ablation_table5.py") 'r"\footnotesize"'
Assert-Contains "adsb/ablation_table5.py" (Get-Content -Raw -LiteralPath "adsb\ablation_table5.py") 'r"\setlength{\tabcolsep}{3pt}"'
$benchmarkText = Get-Content -Raw -LiteralPath "adsb\benchmark.py"
Assert-Contains "adsb/benchmark.py" $benchmarkText 'r"\caption{Multi-seed detection and robustness summary over five matched aircraft splits/seeds.'
Assert-Contains "adsb/benchmark.py" $benchmarkText 'Entries are mean (95\% confidence-interval half-width).'
Assert-Contains "adsb/benchmark.py" $benchmarkText 'r"\textit{(a) Effect estimates}\par\smallskip"'
Assert-Contains "adsb/benchmark.py" $benchmarkText 'r"\textit{(b) Multiplicity-adjusted inference}\par\smallskip"'
Assert-Contains "adsb/benchmark.py" $benchmarkText 'require_all_primary: bool = False'
Assert-Contains "adsb/trajectory_compare.py" (Get-Content -Raw -LiteralPath "adsb\trajectory_compare.py") "conda run -n testtorch python test.py"
Assert-Contains "adsb/paper_tables.py" (Get-Content -Raw -LiteralPath "adsb\paper_tables.py") "relative_to(Path.cwd().resolve())"
Assert-Contains "tools/regenerate_paper_exports.py" (Get-Content -Raw -LiteralPath "tools\regenerate_paper_exports.py") "_display_path"
Assert-Contains "tools/regenerate_paper_exports.py" (Get-Content -Raw -LiteralPath "tools\regenerate_paper_exports.py") "require_all_primary=True"
Assert-Contains "tools/build_zhong.py" (Get-Content -Raw -LiteralPath "tools\build_zhong.py") "conda run -n testtorch python zhong.py"
Assert-Contains "tests/test_benchmark_stats.py" (Get-Content -Raw -LiteralPath "tests\test_benchmark_stats.py") '"conda", "run", "-n", "testtorch", "python"'
Assert-Contains "tests/test_physical_metrics.py" (Get-Content -Raw -LiteralPath "tests\test_physical_metrics.py") "test_pv_asr_is_exact_per_sample_not_product_approximation"
Assert-Contains "tests/test_submission_tex_generation.py" (Get-Content -Raw -LiteralPath "tests\test_submission_tex_generation.py") "test_statistical_tables_escape_percent_and_keep_two_panels"
Assert-Contains "adsb/literature_benchmark.py" (Get-Content -Raw -LiteralPath "adsb\literature_benchmark.py") "_assert_matching_reference_split"
Assert-Contains "adsb/literature_report.py" (Get-Content -Raw -LiteralPath "adsb\literature_report.py") "unperturbed_detection_only"
Assert-Contains "tests/test_literature_models.py" (Get-Content -Raw -LiteralPath "tests\test_literature_models.py") "test_fried_lstm_ae_exposes_finite_differentiable_logits"
Assert-Contains "tests/test_literature_report.py" (Get-Content -Raw -LiteralPath "tests\test_literature_report.py") "test_unperturbed_table_contains_published_models_but_no_attack_columns"
Assert-Contains "tests/test_paper_naming.py" (Get-Content -Raw -LiteralPath "tests\test_paper_naming.py") "test_norm_bounded_pgd_name_preserves_legacy_archive_key"

Write-Output "code_provenance_drift=PASSED"
Write-Output "manifest_code_files=$($manifestEntries.Count)"
Write-Output "current_code_files=$($currentFiles.Count)"
Write-Output "changed_files_checked=$($changed.Count)"
Write-Output "added_files_checked=$($added.Count)"

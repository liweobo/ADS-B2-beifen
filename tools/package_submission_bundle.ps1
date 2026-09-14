param(
    [string]$OutputDir = "output\submission",
    [string]$BundleName = "catad_topconf_submission_bundle",
    [switch]$NoSampleData,
    [switch]$BuildPreviewPdf
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$OutDir = Join-Path $RepoRoot $OutputDir
$StageDir = Join-Path $OutDir "stage"
$BundleRootName = $BundleName
$BundleRoot = Join-Path $StageDir $BundleRootName
$ZipPath = Join-Path $OutDir "$BundleName.zip"
$ManifestPath = Join-Path $OutDir "$BundleName.manifest.tsv"
$ManifestJsonPath = Join-Path $OutDir "$BundleName.manifest.json"

function Assert-ChildPath {
    param(
        [string]$ChildPath,
        [string]$ParentPath
    )
    $childFull = [System.IO.Path]::GetFullPath($ChildPath).TrimEnd("\")
    $parentFull = [System.IO.Path]::GetFullPath($ParentPath).TrimEnd("\")
    if (-not $childFull.StartsWith($parentFull + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate outside expected directory: $childFull"
    }
    return $childFull
}

function Remove-OwnedStageDir {
    if (-not (Test-Path -LiteralPath $StageDir)) {
        return
    }
    $safeStage = Assert-ChildPath $StageDir $OutDir
    if ((Split-Path -Leaf $safeStage) -ne "stage") {
        throw "Refusing to remove unexpected stage directory: $safeStage"
    }
    Remove-Item -LiteralPath $safeStage -Recurse -Force
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Value
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Copy-SubmissionItem {
    param(
        [string]$RelativePath,
        [string]$DestinationRelativePath = $RelativePath
    )

    $source = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing submission item: $RelativePath"
    }

    $destination = Join-Path $BundleRoot $DestinationRelativePath
    $destinationParent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Force -Path $destinationParent | Out-Null

    if (Test-Path -LiteralPath $source -PathType Container) {
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        Get-ChildItem -LiteralPath $source -Force |
            ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force
            }
    }
    else {
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
}

function Remove-JunkFromStage {
    $junkDirs = @("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache")
    foreach ($name in $junkDirs) {
        Get-ChildItem -LiteralPath $BundleRoot -Recurse -Force -Directory -Filter $name |
            Remove-Item -Recurse -Force
    }
    Get-ChildItem -LiteralPath $BundleRoot -Recurse -Force -File |
        Where-Object { $_.Extension -in @(".pyc", ".pyo") } |
        Remove-Item -Force
    $previewLog = Join-Path $BundleRoot "output\pdf\catad_submission_preview_pandoc.log"
    Remove-Item -LiteralPath $previewLog -Force -ErrorAction SilentlyContinue
    $formalLog = Join-Path $BundleRoot "output\pdf\catad_submission_latex_build.log"
    Remove-Item -LiteralPath $formalLog -Force -ErrorAction SilentlyContinue
    $latexBuildDir = Join-Path $BundleRoot "output\pdf\latex_build"
    Remove-Item -LiteralPath $latexBuildDir -Recurse -Force -ErrorAction SilentlyContinue
    $legacyFigures = Join-Path $BundleRoot "figures\legacy"
    Remove-Item -LiteralPath $legacyFigures -Recurse -Force -ErrorAction SilentlyContinue
}

function Get-SensitivePathPairs {
    $pairs = @()
    $repoFull = (Resolve-Path -LiteralPath $RepoRoot).Path
    $userProfile = [string]$env:USERPROFILE
    $repoLeaf = Split-Path -Leaf $RepoRoot
    $condaCandidates = @()
    if ($env:CONDA_PREFIX) {
        $condaCandidates += [string]$env:CONDA_PREFIX
    }
    $conda = Get-Command conda -ErrorAction SilentlyContinue
    if ($conda) {
        try {
            $condaInfo = (& conda run -n testtorch python -c "import sys; print(sys.prefix); print(sys.executable)" 2>$null)
            if ($LASTEXITCODE -eq 0) {
                $condaCandidates += @($condaInfo | Where-Object { $_ })
            }
        }
        catch {
            # Best-effort path sanitization; explicit repo/home replacements still apply.
        }
    }
    foreach ($item in @(
        @{ value = $repoFull; replacement = "<REPO_ROOT>" },
        @{ value = $repoFull.Replace("\", "/"); replacement = "<REPO_ROOT>" },
        @{ value = $repoFull.Replace("\", "\\"); replacement = "<REPO_ROOT>" },
        @{ value = $userProfile; replacement = "<USER_HOME>" },
        @{ value = $userProfile.Replace("\", "/"); replacement = "<USER_HOME>" },
        @{ value = $userProfile.Replace("\", "\\"); replacement = "<USER_HOME>" }
    )) {
        if ($item.value) {
            $pairs += [pscustomobject]$item
        }
    }
    foreach ($candidate in ($condaCandidates | Sort-Object -Unique)) {
        $value = [string]$candidate
        if ($value -and [System.IO.Path]::IsPathRooted($value)) {
            $replacement = if ($value.EndsWith("python.exe", [System.StringComparison]::OrdinalIgnoreCase)) {
                "<CONDA_ENV>\python.exe"
            }
            else {
                "<CONDA_ENV>"
            }
            $pairs += [pscustomobject]@{ value = $value; replacement = $replacement }
            $pairs += [pscustomobject]@{ value = $value.Replace("\", "/"); replacement = $replacement.Replace("\", "/") }
            $pairs += [pscustomobject]@{ value = $value.Replace("\", "\\"); replacement = $replacement.Replace("\", "\\") }
        }
    }
    foreach ($desktopPath in @(
        "<USER_HOME>\Desktop\$repoLeaf",
        "<USER_HOME>/Desktop/$repoLeaf",
        "<USER_HOME>\\Desktop\\$repoLeaf"
    )) {
        $pairs += [pscustomobject]@{ value = $desktopPath; replacement = "<REPO_ROOT>" }
    }
    return $pairs
}

function Update-BenchmarkIntegrity {
    param([string]$BenchmarkRoot)

    $manifestPath = Join-Path $BenchmarkRoot "benchmark_manifest.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return
    }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if (-not $manifest.artifact_integrity -or -not $manifest.artifact_integrity.files) {
        return
    }

    $digest = [System.Security.Cryptography.SHA256]::Create()
    $buffer = New-Object System.Collections.Generic.List[byte]
    foreach ($entry in $manifest.artifact_integrity.files) {
        $rel = [string]$entry.benchmark_relative_path
        if (-not $rel) {
            $rel = [string]$entry.project_relative_path
        }
        if (-not $rel) {
            continue
        }
        $file = Join-Path $BenchmarkRoot ($rel.Replace("/", "\"))
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            continue
        }
        $item = Get-Item -LiteralPath $file
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
        $entry.path = $rel
        $entry.size_bytes = [int64]$item.Length
        $entry.sha256 = $hash

        foreach ($part in @($rel, [string]$item.Length, $hash)) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($part)
            $buffer.AddRange($bytes)
            $buffer.Add(0)
        }
    }
    $hashBytes = $digest.ComputeHash($buffer.ToArray())
    $manifest.artifact_integrity.sha256 = -join ($hashBytes | ForEach-Object { $_.ToString("x2") })

    Write-Utf8NoBom $manifestPath ($manifest | ConvertTo-Json -Depth 100)
}

function Sanitize-SubmissionStage {
    $pairs = @(Get-SensitivePathPairs)
    if ($pairs.Count -eq 0) {
        return
    }

    $textExtensions = @(".csv", ".html", ".json", ".log", ".md", ".ps1", ".py", ".tex", ".tsv", ".txt")
    $files = Get-ChildItem -LiteralPath $BundleRoot -Recurse -Force -File |
        Where-Object { $textExtensions -contains $_.Extension.ToLowerInvariant() }
    foreach ($file in $files) {
        $text = Get-Content -Raw -LiteralPath $file.FullName
        if ($null -eq $text) {
            $text = ""
        }
        $updated = $text
        for ($pass = 0; $pass -lt 3; $pass++) {
            foreach ($pair in $pairs) {
                $updated = $updated.Replace($pair.value, $pair.replacement)
            }
            $updated = [regex]::Replace(
                $updated,
                "<USER_HOME>(?:\\\\|\\|/)Desktop(?:\\\\|\\|/)[^`"'\r\n]+?(?=(?:\\\\|\\|/)(?:outputs|results|figures|paper_lncs|checkpoints)(?:\\\\|\\|/))",
                "<REPO_ROOT>"
            )
        }
        if ($file.Extension.Equals(".json", [System.StringComparison]::OrdinalIgnoreCase)) {
            $updated = [regex]::Replace($updated, '(?<!\\)\\(?!["\\/bfnrtu])', '\\')
            try {
                $null = $updated | ConvertFrom-Json
            }
            catch {
                throw "Sanitized JSON is invalid: $($file.FullName): $($_.Exception.Message)"
            }
        }
        if ($updated -ne $text) {
            Write-Utf8NoBom $file.FullName $updated
        }
    }

    Update-BenchmarkIntegrity (Join-Path $BundleRoot "outputs\publication_benchmark")
}

function New-ManifestRows {
    $files = Get-ChildItem -LiteralPath $BundleRoot -Recurse -Force -File |
        Where-Object { $_.Name -notin @("BUNDLE_MANIFEST.tsv", "BUNDLE_MANIFEST.json") } |
        Sort-Object FullName

    $rootPrefix = (Resolve-Path -LiteralPath $BundleRoot).Path.TrimEnd("\") + "\"
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($rootPrefix.Length)
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName
        [pscustomobject]@{
            path = $relative.Replace("\", "/")
            bytes = $file.Length
            sha256 = $hash.Hash.ToLowerInvariant()
        }
    }
}

function Assert-StageBinaryMatchesRepo {
    param([string]$RelativePath)

    $source = Join-Path $RepoRoot $RelativePath
    $staged = Join-Path $BundleRoot $RelativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing source file for stage-match check: $RelativePath"
    }
    if (-not (Test-Path -LiteralPath $staged -PathType Leaf)) {
        throw "Missing staged file for stage-match check: $RelativePath"
    }
    $sourceItem = Get-Item -LiteralPath $source
    $stagedItem = Get-Item -LiteralPath $staged
    if ($sourceItem.Length -ne $stagedItem.Length) {
        throw "Staged file size differs from source for ${RelativePath}: source=$($sourceItem.Length) staged=$($stagedItem.Length)"
    }
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()
    $stagedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $staged).Hash.ToLowerInvariant()
    if ($sourceHash -ne $stagedHash) {
        throw "Staged file hash differs from source for ${RelativePath}: source=$sourceHash staged=$stagedHash"
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Remove-OwnedStageDir
Remove-Item -LiteralPath $ZipPath, $ManifestPath, $ManifestJsonPath -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $BundleRoot | Out-Null

& (Join-Path $RepoRoot "tools\build_data_split_audit_table.ps1")
& (Join-Path $RepoRoot "tools\build_primary_seed_direction_summary.ps1")

if ($BuildPreviewPdf -or -not (Test-Path -LiteralPath (Join-Path $RepoRoot "output\pdf\catad_submission_preview.pdf") -PathType Leaf)) {
    & (Join-Path $RepoRoot "tools\build_submission_preview_pdf.ps1")
}

& (Join-Path $RepoRoot "tools\verify_terminology_and_naming.ps1")

$items = @(
    "adsb",
    "tools",
    "tests",
    "paper_lncs",
    "figures",
    "outputs\publication_benchmark",
    "outputs\literature_benchmark",
    "outputs\test_set_results.csv",
    "outputs\ablation_table5\ablation_table5_summary.json",
    "outputs\audits\terminology_and_naming_verification.json",
    "outputs\tables",
    "results\fig_epsilon_sensitivity_data.csv",
    "results\fig_main_robustness_data.csv",
    "results\fig_physical_valid_asr_data.csv",
    "output\pdf",
    "LICENSE",
    "CITATION.cff",
    "README.md",
    "AGENTS.md",
    "requirements.txt",
    "EXPERIMENTS.md",
    "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md",
    "ADAPTIVE_ATTACK_AUDIT.md",
    "ATTACK_STRENGTH_CONFIGURATION_AUDIT.md",
    "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md",
    "CLAIM_SCOPE_GUARDRAILS.md",
    "DATA_PROVENANCE_AND_ETHICS.md",
    "DUAL_USE_SAFETY_AUDIT.md",
    "DATASET_PROFILE_AUDIT.md",
    "EXTERNAL_VALIDITY_SCOPE_AUDIT.md",
    "ENVIRONMENT_REPRODUCIBILITY.md",
    "COMPUTE_RESOURCE_AUDIT.md",
    "CODE_PROVENANCE_DRIFT_AUDIT.md",
    "ABLATION_AND_SENSITIVITY_AUDIT.md",
    "THRESHOLD_AND_HYPERPARAMETER_AUDIT.md",
    "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md",
    "BASELINE_FAIRNESS_AUDIT.md",
    "BASELINE_COMPETITIVENESS_AUDIT.md",
    "LITERATURE_BASELINE_REPRODUCTION_AUDIT.md",
    "INNOVATION_AND_EVIDENCE.md",
    "PRIOR_ART_NOVELTY_MATRIX.md",
    "PRIOR_ART_CRITERIA_COVERAGE.tsv",
    "PRIOR_ART_EVIDENCE_SNAPSHOT.md",
    "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md",
    "REVIEWER_OBJECTION_RESPONSE_AUDIT.md",
    "PAPER_ARTIFACT_PROVENANCE.md",
    "FIGURE_SOURCE_CONSISTENCY_AUDIT.md",
    "FIGURE_AND_TABLE_QUALITY_AUDIT.md",
    "PAPER_EXPORT_REGENERATION_AUDIT.md",
    "DOUBLE_BLIND_REVIEW_CHECKLIST.md",
    "ATTACK_EVALUATION_SANITY_CHECKLIST.md",
    "STATISTICAL_INTERPRETATION_CHECKLIST.md",
    "NUMERIC_CLAIMS_LEDGER.md",
    "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md",
    "CLAIM_HIERARCHY_AUDIT.md",
    "SEED_DIRECTION_CONSISTENCY_AUDIT.md",
    "PHYSICAL_METRIC_SEMANTICS_AUDIT.md",
    "TERMINOLOGY_AND_NAMING_AUDIT.md",
    "MANUSCRIPT_REVIEWABILITY_AUDIT.md",
    "RENDERED_PDF_CONTENT_AUDIT.md",
    "README_REVIEW_ENTRY_AUDIT.md",
    "ARTIFACT_LICENSE_AND_CITATION_AUDIT.md",
    "REVIEWER_QUICKSTART.md",
    "ARTIFACT_EVALUATION_GUIDE.md",
    "WORKSPACE_HYGIENE_AUDIT.md",
    "TEX_SOURCE_PORTABILITY_AUDIT.md",
    "FORMAL_PDF_BUILD_AUDIT.md",
    "TOP_CONFERENCE_READINESS_AUDIT.md",
    "SUBMISSION_COMPLETION_AUDIT.md",
    "SUBMISSION_READINESS.md",
    "check_submission_ready.ps1"
)

foreach ($item in $items) {
    Copy-SubmissionItem $item
}

if (-not $NoSampleData) {
    Copy-SubmissionItem "sample_adsb_decoded.csv"
}

Remove-JunkFromStage
Sanitize-SubmissionStage
Assert-StageBinaryMatchesRepo "output\pdf\catad_submission_preview.pdf"
Assert-StageBinaryMatchesRepo "output\pdf\catad_submission_latex_updated.pdf"

$manifestRows = @(New-ManifestRows)
$manifestHeader = "path`tbytes`tsha256"
$manifestLines = @($manifestHeader) + ($manifestRows | ForEach-Object { "{0}`t{1}`t{2}" -f $_.path, $_.bytes, $_.sha256 })
Set-Content -LiteralPath (Join-Path $BundleRoot "BUNDLE_MANIFEST.tsv") -Value $manifestLines -Encoding UTF8

$readme = @'
# CAT-AD Submission Bundle

This bundle contains the experiment code, tests, manuscript sources, generated
tables and figures, multi-seed benchmark artifacts, verification reports, the
formal 18-page LNCS PDF, and a local A4 preview for the CAT-AD study.

## Key Entry Points

- `paper_lncs/main.tex`: manuscript source.
- `paper_lncs/llncs.cls` and `paper_lncs/splncs04.bst`: official Springer proceedings styles.
- `paper_lncs/SPRINGER_TEMPLATE_PROVENANCE.md`: official template source and hashes.
- `README.md`: root reviewer landing page.
- `LICENSE`: anonymous review artifact use statement.
- `CITATION.cff`: anonymous review citation metadata.
- `output/pdf/catad_submission_preview.pdf`: local manuscript preview PDF.
- `output/pdf/catad_submission_latex_updated.pdf`: formally compiled LNCS manuscript PDF.
- `REVIEWER_QUICKSTART.md`: shortest reviewer path for no-download checks.
- `ARTIFACT_REPRODUCIBILITY_CHECKLIST.md`: artifact-evaluation commands and expected outputs.
- `ADAPTIVE_ATTACK_AUDIT.md`: weak-attack and gradient-masking risk audit.
- `ATTACK_STRENGTH_CONFIGURATION_AUDIT.md`: fixed attack-budget, PGD-step, penalty, and epsilon-sensitivity configuration audit.
- `METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md`: paper objective, training-code, attack-code, model-feature, manifest, and seed-log traceability audit.
- `CLAIM_SCOPE_GUARDRAILS.md`: allowed/disallowed claim wording boundaries.
- `DATA_PROVENANCE_AND_ETHICS.md`: dataset hash, preflight split, bundled-data, and safety-use boundary.
- `DUAL_USE_SAFETY_AUDIT.md`: offline defensive-use and operational-misuse boundary audit.
- `DATASET_PROFILE_AUDIT.md`: raw CSV, model-loaded rows, filtering, split, and coverage profile.
- `EXTERNAL_VALIDITY_SCOPE_AUDIT.md`: one-day/aircraft-count dataset-scope and external-validity boundary.
- `ENVIRONMENT_REPRODUCIBILITY.md`: conda environment and key-package reproducibility statement.
- `COMPUTE_RESOURCE_AUDIT.md`: observed hardware and five-seed benchmark runtime boundary.
- `CODE_PROVENANCE_DRIFT_AUDIT.md`: post-benchmark source-fingerprint drift boundary.
- `ABLATION_AND_SENSITIVITY_AUDIT.md`: ablation-table and epsilon-sensitivity evidence boundary.
- `THRESHOLD_AND_HYPERPARAMETER_AUDIT.md`: validation-only threshold and fixed-hyperparameter boundary.
- `FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md`: visible failure modes, non-claims, and negative-result boundaries.
- `BASELINE_FAIRNESS_AUDIT.md`: shared-architecture, shared-split, paired-comparison fairness boundary.
- `BASELINE_COMPETITIVENESS_AUDIT.md`: strong adversarial-training baseline and auxiliary ablation interpretation boundary.
- `LITERATURE_BASELINE_REPRODUCTION_AUDIT.md`: same-protocol five-split comparison with three concrete published ADS-B detectors and the cross-family attack-reporting guardrail.
- `PRIOR_ART_NOVELTY_MATRIX.md`: falsifiable prior-art boundary for novelty claims.
- `PRIOR_ART_CRITERIA_COVERAGE.tsv`: machine-readable C1-C6 prior-art coverage table for novelty claims.
- `PRIOR_ART_EVIDENCE_SNAPSHOT.md`: dated external-source and search-evidence snapshot for novelty claims.
- `RECENT_PRIOR_ART_CHALLENGE_AUDIT.md`: recent 2025/2026 ADS-B IDS and survey challenge-reference audit.
- `REVIEWER_OBJECTION_RESPONSE_AUDIT.md`: likely reviewer objections mapped to evidence, verifier outputs, and claim boundaries.
- `PAPER_ARTIFACT_PROVENANCE.md`: table, figure, CSV, and benchmark provenance map.
- `FIGURE_SOURCE_CONSISTENCY_AUDIT.md`: figure-source freshness, data consistency, and legacy-figure packaging boundary.
- `FIGURE_AND_TABLE_QUALITY_AUDIT.md`: manuscript visual inventory, font/scaling, confidence-interval, grayscale, and full-axis quality boundary.
- `PAPER_EXPORT_REGENERATION_AUDIT.md`: paper table/figure regeneration command, deterministic outputs, and no-capture Conda boundary.
- `DOUBLE_BLIND_REVIEW_CHECKLIST.md`: double-blind review anonymity checks.
- `ATTACK_EVALUATION_SANITY_CHECKLIST.md`: weak-attack and gradient-masking sanity checks.
- `STATISTICAL_INTERPRETATION_CHECKLIST.md`: effect-size-first interpretation of paired statistics.
- `outputs/publication_benchmark/verification_report.md`: strict benchmark gate.
- `outputs/publication_benchmark/data_split_audit.tex`: generated data split and leakage audit table.
- `outputs/publication_benchmark/primary_seed_direction_summary.tex`: generated per-seed direction summary for the six primary claims.
- `outputs/publication_benchmark/benchmark_manifest.json`: experiment provenance.
- `NUMERIC_CLAIMS_LEDGER.md`: numeric claim-to-artifact ledger.
- `MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md`: narrative claim-to-evidence map.
- `CLAIM_HIERARCHY_AUDIT.md`: primary-vs-auxiliary evidence hierarchy audit.
- `SEED_DIRECTION_CONSISTENCY_AUDIT.md`: per-seed primary-claim direction audit.
- `PHYSICAL_METRIC_SEMANTICS_AUDIT.md`: sample-level ASR/PVR/PV-ASR semantics audit.
- `TERMINOLOGY_AND_NAMING_AUDIT.md`: canonical model, attack, class, feature, and metric naming audit, including the archive-key compatibility boundary.
- `MANUSCRIPT_REVIEWABILITY_AUDIT.md`: manuscript entry-point, contribution, citation, preview, and PDF-shape audit.
- `RENDERED_PDF_CONTENT_AUDIT.md`: rendered preview-PDF page and pixel-content audit.
- `README_REVIEW_ENTRY_AUDIT.md`: root README reviewer-entry audit.
- `ARTIFACT_LICENSE_AND_CITATION_AUDIT.md`: anonymous review license/citation boundary audit.
- `TOP_CONFERENCE_READINESS_AUDIT.md`: reviewer-risk and evidence matrix.
- `SUBMISSION_COMPLETION_AUDIT.md`: requirement-by-requirement completion audit.
- `ARTIFACT_EVALUATION_GUIDE.md`: venue-neutral artifact-evaluation evidence matrix.
- `WORKSPACE_HYGIENE_AUDIT.md`: local root artifact and submission-bundle boundary audit.
- `TEX_SOURCE_PORTABILITY_AUDIT.md`: TeX source portability, source-closure, and formal-PDF boundary audit.
- `FORMAL_PDF_BUILD_AUDIT.md`: formal LaTeX build entry point, supported engines, and no-TeX boundary audit.
- `check_submission_ready.ps1`: local audit command.
- `tools/build_data_split_audit_table.ps1`: regenerate the manuscript data split audit table.
- `tools/build_primary_seed_direction_summary.ps1`: regenerate the primary-claim seed direction summary table.
- `tools/build_submission_pdf.ps1`: build the formal LaTeX PDF when a TeX engine is already installed.
- `tools/run_publication_gate.py`: rerun preflight, benchmark, and strict gate.
- `tools/verify_novelty_evidence.ps1`: novelty-boundary and prior-art evidence verifier.
- `tools/verify_recent_prior_art_challenge.ps1`: recent-prior-art challenge-reference verifier.
- `tools/verify_reviewer_objection_response.ps1`: reviewer-objection response matrix verifier.
- `tools/verify_paper_artifact_provenance.ps1`: manuscript table/figure provenance verifier.
- `tools/verify_figure_source_consistency.ps1`: figure-source freshness and data-consistency verifier.
- `tools/verify_figure_and_table_quality.ps1`: manuscript figure/table readability and visual-encoding verifier.
- `tools/verify_paper_export_regeneration.ps1`: paper table/figure export regeneration verifier.
- `tools/verify_attack_evaluation_sanity.ps1`: attack-strength and gradient-masking sanity verifier.
- `tools/verify_attack_strength_configuration.ps1`: fixed attack-strength configuration verifier.
- `tools/verify_method_implementation_traceability.ps1`: method-to-implementation traceability verifier.
- `tools/verify_statistical_interpretation.ps1`: statistical interpretation and overclaiming verifier.
- `tools/verify_data_provenance_ethics.ps1`: data provenance, split leakage, and offline-safety verifier.
- `tools/verify_dual_use_safety.ps1`: dual-use safety and operational-misuse boundary verifier.
- `tools/verify_external_validity_scope.ps1`: dataset-scope and external-validity overclaim verifier.
- `tools/verify_environment_reproducibility.ps1`: conda environment and manifest package verifier.
- `tools/verify_compute_resource_audit.ps1`: compute-resource and wall-clock boundary verifier.
- `tools/verify_reviewer_quickstart.ps1`: reviewer quickstart verifier.
- `tools/verify_readme_review_entry.ps1`: root README reviewer-entry verifier.
- `tools/verify_artifact_license_citation.ps1`: anonymous review license/citation verifier.
- `tools/verify_artifact_evaluation_guide.ps1`: artifact-evaluation guide verifier.
- `tools/verify_workspace_hygiene.ps1`: workspace root hygiene and submission-boundary verifier.
- `tools/verify_tex_source_portability.ps1`: TeX source portability and source-closure verifier.
- `tools/verify_formal_pdf_build_readiness.ps1`: formal LaTeX PDF build readiness verifier.
- `tools/verify_baseline_competitiveness.ps1`: strong adversarial-training baseline verifier.
- `tools/verify_literature_baseline_reproduction.ps1`: published-model split, metric, report, and artifact-integrity verifier.
- `tools/verify_manuscript_structure.ps1`: manuscript structure, citation, and placeholder checks.
- `tools/verify_terminology_and_naming.ps1`: manuscript, generated-artifact, and code-facing terminology verifier.
- `tools/verify_manuscript_reviewability.ps1`: manuscript reviewability, contribution, citation, preview, and PDF-shape verifier.
- `tools/verify_rendered_pdf_content.ps1`: rendered preview-PDF content verifier.
- `tools/verify_completion_audit.ps1`: completion-audit verifier.
- `tools/verify_preview_artifact.ps1`: preview HTML/PDF reviewability verifier.
- `tools/verify_anonymized_bundle.ps1`: bundle anonymity/path-portability verifier.
- `tools/verify_double_blind_submission.ps1`: manuscript, preview, and bundle double-blind verifier.

## Recheck Command

Run from the bundle root on Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check_submission_ready.ps1 -NoDownload -BuildPreviewPdf -BuildSubmissionBundle
```

To regenerate the manuscript data split and leakage audit table from the preflight report:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build_data_split_audit_table.ps1
```

To regenerate the primary-claim per-seed direction summary table:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build_primary_seed_direction_summary.ps1
```

To verify the zip contents, manifest hashes, and extracted strict publication gate from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_submission_bundle.ps1
```

To verify the headline numeric claims from local CSV/TeX/report artifacts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_numeric_claims.ps1
```

To verify narrative manuscript claims against code and generated artifacts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_manuscript_claim_traceability.ps1
```

To verify primary-vs-auxiliary claim hierarchy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_claim_hierarchy.ps1
```

To verify per-seed primary-claim direction consistency:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_seed_direction_consistency.ps1
```

To verify sample-level ASR/PVR/PV-ASR semantics:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_physical_metric_semantics.ps1
```

To verify attack-strength and gradient-masking sanity evidence:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_evaluation_sanity.ps1
```

To verify fixed attack-strength configuration and epsilon-sensitivity evidence:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_strength_configuration.ps1
```

To verify method-to-implementation traceability:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_method_implementation_traceability.ps1
```

To verify effect-size-first statistical interpretation and paired-comparison boundaries:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_statistical_interpretation.ps1
```

To verify dual-use safety and operational-misuse boundaries:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_dual_use_safety.ps1
```

To verify the dataset profile, filtering boundary, and split/window coverage:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_dataset_profile.ps1
```

To verify the dataset-scope and external-validity boundary:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_external_validity_scope.ps1
```

To verify the observed compute-resource and runtime boundary:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_compute_resource_audit.ps1
```

To verify the root README review entry:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_readme_review_entry.ps1
```

To verify the anonymous review license and citation boundary:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_artifact_license_citation.ps1
```

To verify TeX source closure, path portability, bibliography mapping, and bundle packaging:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_tex_source_portability.ps1
```

To build the formal LaTeX PDF when `latexmk`, `tectonic`, or `pdflatex`/`bibtex` is already installed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build_submission_pdf.ps1
```

To verify the formal PDF build entry point and no-download boundary:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_formal_pdf_build_readiness.ps1
```

To verify root-level scratch files and raw snapshots are excluded from the review bundle:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_workspace_hygiene.ps1
```

To verify failure-mode, PVR non-claim, and negative-result boundaries:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_failure_mode_negative_results.ps1
```

To verify baseline-vs-CAT-AD fairness controls:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_baseline_fairness.ps1
```

To verify strong adversarial-training baselines in the auxiliary ablation table:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_baseline_competitiveness.ps1
```

To verify the same-protocol comparison with concrete published ADS-B detectors:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_literature_baseline_reproduction.ps1
```

To verify manuscript claim scope and overclaiming guardrails:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_claim_scope.ps1
```

To verify the novelty evidence matrix, cautious claim wording, and citation boundary:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_novelty_evidence.ps1
```

To verify recent ADS-B IDS and survey challenge references are cited and bounded:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_recent_prior_art_challenge.ps1
```

To verify the reviewer-objection response matrix:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_reviewer_objection_response.ps1
```

To verify that manuscript tables and figures trace to local CSV, benchmark, and figure artifacts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_paper_artifact_provenance.ps1
```

To regenerate paper-facing tables and figures without Conda stdout capture:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_paper_export_regeneration.ps1
```

This runs `conda run --no-capture-output -n testtorch python tools\regenerate_paper_exports.py`
and checks byte-stable paper CSV/TeX/PNG exports. To verify figure source
freshness, table consistency, and legacy-figure exclusion without rerunning the
exporter:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_figure_source_consistency.ps1
```

To verify manuscript structure, required inputs, figures, citations, and placeholders:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_manuscript_structure.ps1
```

To verify canonical terminology, first-use definitions, generated labels, and
legacy archive-key mappings:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_terminology_and_naming.ps1
```

To verify manuscript reviewability, contribution shape, citations, and preview PDF metadata:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_manuscript_reviewability.ps1
```

To verify the local preview HTML/PDF contains review-critical content and renders:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_preview_artifact.ps1
```

To verify rendered preview-PDF page content:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_rendered_pdf_content.ps1
```

To verify the bundle does not expose local usernames or absolute workstation paths:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_anonymized_bundle.ps1
```

To verify manuscript, preview, and bundle double-blind markers:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_double_blind_submission.ps1
```

Python commands in this project must use the `testtorch` conda environment.
This bundle workflow does not download software or install packages; it uses
the artifacts and local tools already present on the machine.

## Formal PDF Note

The bundle includes both the convenience preview and the formally compiled
LNCS PDF. The formal artifact was built with Tectonic 0.16.9 and the official
LNCS v2.24 class, has 18 pages, and passes the TeX-log and rendered-page gates.
Acceptance and compliance with a future venue's unspecified page limit remain
external decisions.
'@
Set-Content -LiteralPath (Join-Path $BundleRoot "BUNDLE_README.md") -Value $readme -Encoding UTF8

$manifestRows = @(New-ManifestRows)
$manifestLines = @($manifestHeader) + ($manifestRows | ForEach-Object { "{0}`t{1}`t{2}" -f $_.path, $_.bytes, $_.sha256 })
Set-Content -LiteralPath (Join-Path $BundleRoot "BUNDLE_MANIFEST.tsv") -Value $manifestLines -Encoding UTF8
Set-Content -LiteralPath $ManifestPath -Value $manifestLines -Encoding UTF8

$summary = [pscustomobject]@{
    bundle_name = $BundleName
    generated_utc = (Get-Date).ToUniversalTime().ToString("o")
    file_count = $manifestRows.Count
    total_bytes = ($manifestRows | Measure-Object -Property bytes -Sum).Sum
    includes_sample_data = (-not $NoSampleData)
    zip_path = (Join-Path $OutputDir "$BundleName.zip")
    manifest_tsv = (Join-Path $OutputDir "$BundleName.manifest.tsv")
    manifest_json = (Join-Path $OutputDir "$BundleName.manifest.json")
    required_gate = "outputs/publication_benchmark/verification_report.md"
    formal_pdf_note = "Formal 18-page LNCS PDF and preview PDF included; acceptance and venue-specific page limits remain external."
    files = $manifestRows
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ManifestJsonPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $BundleRoot "BUNDLE_MANIFEST.json") -Encoding UTF8

Compress-Archive -LiteralPath $BundleRoot -DestinationPath $ZipPath -Force
Remove-OwnedStageDir

$zipHash = Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath
$zipItem = Get-Item -LiteralPath $ZipPath

Write-Output "bundle=$ZipPath"
Write-Output "bundle_bytes=$($zipItem.Length)"
Write-Output "bundle_sha256=$($zipHash.Hash.ToLowerInvariant())"
Write-Output "manifest=$ManifestPath"
Write-Output "manifest_json=$ManifestJsonPath"
Write-Output "file_count=$($manifestRows.Count)"

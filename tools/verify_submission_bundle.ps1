param(
    [string]$BundlePath = "output\submission\catad_topconf_submission_bundle.zip",
    [string]$ExtractParent = "",
    [switch]$KeepExtracted
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Resolve-RepoPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $RepoRoot $Path)
}

function Assert-OwnedTempPath {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $leaf = Split-Path -Leaf $resolved
    if (-not $leaf.StartsWith("catad_bundle_verify_", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected directory: $resolved"
    }
    return $resolved
}

$bundle = Resolve-RepoPath $BundlePath
if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) {
    throw "Missing bundle zip: $bundle"
}

$parent = if ($ExtractParent) { Resolve-RepoPath $ExtractParent } else { $env:TEMP }
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$workDir = Join-Path $parent ("catad_bundle_verify_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $bundle).Path)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace("\", "/")
            if ($name.StartsWith("/") -or $name.Contains(":") -or $name.Contains("../") -or $name.Contains("/..")) {
                throw "Unsafe zip entry path: $name"
            }
        }
    }
    finally {
        $zip.Dispose()
    }

    [System.IO.Compression.ZipFile]::ExtractToDirectory((Resolve-Path -LiteralPath $bundle).Path, $workDir)

    $bundleRoot = Join-Path $workDir "catad_topconf_submission_bundle"
    if (-not (Test-Path -LiteralPath $bundleRoot -PathType Container)) {
        $dirs = @(Get-ChildItem -LiteralPath $workDir -Directory -Force)
        if ($dirs.Count -eq 1) {
            $bundleRoot = $dirs[0].FullName
        }
        else {
            throw "Could not locate single bundle root under $workDir"
        }
    }

    $manifestPath = Join-Path $bundleRoot "BUNDLE_MANIFEST.tsv"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Missing BUNDLE_MANIFEST.tsv in extracted bundle"
    }

    $manifest = @(Import-Csv -Delimiter "`t" -LiteralPath $manifestPath)
    if ($manifest.Count -lt 100) {
        throw "Bundle manifest is unexpectedly small: $($manifest.Count) files"
    }

    $required = @(
        "adsb/benchmark.py",
        "adsb/attacks.py",
        "adsb/paper_naming.py",
        "tests/test_benchmark_stats.py",
        "tests/test_physical_metrics.py",
        "tests/test_submission_tex_generation.py",
        "tests/test_paper_naming.py",
        "paper_lncs/main.tex",
        "paper_lncs/references.bib",
        "paper_lncs/llncs.cls",
        "paper_lncs/splncs04.bst",
        "paper_lncs/SPRINGER_TEMPLATE_PROVENANCE.md",
        "output/pdf/catad_submission_preview.pdf",
        "output/pdf/catad_submission_latex_updated.pdf",
        "outputs/publication_benchmark/verification_report.md",
        "outputs/publication_benchmark/benchmark_manifest.json",
        "outputs/test_set_results.csv",
        "outputs/publication_benchmark/data_split_audit.csv",
        "outputs/publication_benchmark/data_split_audit.tex",
        "outputs/publication_benchmark/primary_seed_direction_summary.csv",
        "outputs/publication_benchmark/primary_seed_direction_summary.tex",
        "outputs/tables/table_multiseed_summary.tex",
        "outputs/tables/table_paired_multiseed_comparison.tex",
        "outputs/ablation_table5/ablation_table5_summary.json",
        "outputs/audits/terminology_and_naming_verification.json",
        "results/fig_epsilon_sensitivity_data.csv",
        "results/fig_physical_valid_asr_data.csv",
        "LICENSE",
        "CITATION.cff",
        "README.md",
        "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md",
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
        "INNOVATION_AND_EVIDENCE.md",
        "PRIOR_ART_NOVELTY_MATRIX.md",
        "PRIOR_ART_CRITERIA_COVERAGE.tsv",
        "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md",
        "REVIEWER_OBJECTION_RESPONSE_AUDIT.md",
        "PAPER_ARTIFACT_PROVENANCE.md",
        "FIGURE_SOURCE_CONSISTENCY_AUDIT.md",
        "PAPER_EXPORT_REGENERATION_AUDIT.md",
        "DOUBLE_BLIND_REVIEW_CHECKLIST.md",
        "ATTACK_EVALUATION_SANITY_CHECKLIST.md",
        "ATTACK_STRENGTH_CONFIGURATION_AUDIT.md",
        "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md",
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
        "tools/verify_numeric_claims.ps1",
        "tools/verify_manuscript_claim_traceability.ps1",
        "tools/verify_claim_hierarchy.ps1",
        "tools/verify_seed_direction_consistency.ps1",
        "tools/verify_physical_metric_semantics.ps1",
        "tools/verify_terminology_and_naming.ps1",
        "tools/verify_manuscript_reviewability.ps1",
        "tools/verify_attack_evaluation_sanity.ps1",
        "tools/verify_attack_strength_configuration.ps1",
        "tools/verify_method_implementation_traceability.ps1",
        "tools/verify_statistical_interpretation.ps1",
        "tools/verify_data_provenance_ethics.ps1",
        "tools/verify_dual_use_safety.ps1",
        "tools/verify_dataset_profile.ps1",
        "tools/verify_external_validity_scope.ps1",
        "tools/verify_environment_reproducibility.ps1",
        "tools/verify_compute_resource_audit.ps1",
        "tools/verify_reviewer_quickstart.ps1",
        "tools/verify_readme_review_entry.ps1",
        "tools/verify_artifact_license_citation.ps1",
        "tools/verify_artifact_evaluation_guide.ps1",
        "tools/verify_workspace_hygiene.ps1",
        "tools/verify_tex_source_portability.ps1",
        "tools/build_submission_pdf.ps1",
        "tools/verify_formal_pdf_build_readiness.ps1",
        "tools/verify_code_provenance_drift.ps1",
        "tools/verify_ablation_sensitivity.ps1",
        "tools/verify_threshold_hyperparameter_audit.ps1",
        "tools/verify_failure_mode_negative_results.ps1",
        "tools/verify_baseline_fairness.ps1",
        "tools/verify_baseline_competitiveness.ps1",
        "tools/verify_literature_baseline_reproduction.ps1",
        "tools/audit_literature_attack_resolution.py",
        "tools/verify_claim_scope.ps1",
        "tools/verify_novelty_evidence.ps1",
        "tools/verify_recent_prior_art_challenge.ps1",
        "tools/verify_reviewer_objection_response.ps1",
        "tools/verify_paper_artifact_provenance.ps1",
        "tools/verify_figure_source_consistency.ps1",
        "tools/verify_paper_export_regeneration.ps1",
        "tools/regenerate_paper_exports.py",
        "tools/build_data_split_audit_table.ps1",
        "tools/build_primary_seed_direction_summary.ps1",
        "tools/verify_manuscript_structure.ps1",
        "tools/verify_completion_audit.ps1",
        "tools/verify_preview_artifact.ps1",
        "tools/verify_rendered_pdf_content.ps1",
        "tools/verify_anonymized_bundle.ps1",
        "tools/verify_double_blind_submission.ps1",
        "sample_adsb_decoded.csv",
        "BUNDLE_README.md"
    )
    $required += @(
        "adsb/literature_models.py",
        "adsb/literature_training.py",
        "adsb/literature_benchmark.py",
        "adsb/literature_report.py",
        "tests/test_literature_models.py",
        "tests/test_literature_report.py",
        "LITERATURE_BASELINE_REPRODUCTION_AUDIT.md",
        "outputs/literature_benchmark/literature_benchmark_manifest.json",
        "outputs/literature_benchmark/literature_detection_report_manifest.json",
        "outputs/literature_benchmark/literature_detection_report.md",
        "outputs/literature_benchmark/table_literature_detection.tex",
        "outputs/literature_benchmark/attack_resolution_audit.json"
    )
    $manifestPaths = @($manifest | ForEach-Object { $_.path })
    foreach ($path in $required) {
        if ($manifestPaths -notcontains $path) {
            throw "Manifest missing required bundle path: $path"
        }
    }
    foreach ($path in @("states_2018-05-28-14.csv", "states_2022-06-27-23.csv")) {
        if ($manifestPaths -contains $path) {
            throw "Bundle should not include raw upstream snapshot: $path"
        }
    }

    $formalPdf = Join-Path $bundleRoot "output\pdf\catad_submission_latex_updated.pdf"
    $formalPdfBytes = (Get-Item -LiteralPath $formalPdf).Length
    if ($formalPdfBytes -lt 100000) {
        throw "Extracted formal LNCS PDF is unexpectedly small: $formalPdfBytes bytes"
    }

    $checked = 0
    foreach ($row in $manifest) {
        $rel = $row.path.Replace("/", "\")
        if ($rel.Contains("..\")) {
            throw "Unsafe manifest path: $($row.path)"
        }
        $file = Join-Path $bundleRoot $rel
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "Manifest file missing after extraction: $($row.path)"
        }
        $item = Get-Item -LiteralPath $file
        if ([int64]$row.bytes -ne [int64]$item.Length) {
            throw "Size mismatch for $($row.path): manifest=$($row.bytes) actual=$($item.Length)"
        }
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
        if ($hash -ne $row.sha256.ToLowerInvariant()) {
            throw "SHA-256 mismatch for $($row.path)"
        }
        $checked += 1
    }

    $verificationReport = Get-Content -Raw -LiteralPath (Join-Path $bundleRoot "outputs\publication_benchmark\verification_report.md")
    if ($verificationReport -notmatch "Status:\s+PASSED") {
        throw "Extracted verification report does not show PASSED status"
    }

    $readinessAudit = Get-Content -Raw -LiteralPath (Join-Path $bundleRoot "TOP_CONFERENCE_READINESS_AUDIT.md")
    foreach ($marker in @("Evidence Matrix", "Reviewer-Risk Notes", "No-Download Audit Command", "PRIOR_ART_NOVELTY_MATRIX.md", "PRIOR_ART_CRITERIA_COVERAGE.tsv", "PAPER_ARTIFACT_PROVENANCE.md")) {
        if (-not $readinessAudit.Contains($marker)) {
            throw "Extracted readiness audit missing marker: $marker"
        }
    }

    Push-Location $bundleRoot
    try {
        & "tools\verify_novelty_evidence.ps1"
        & "tools\verify_recent_prior_art_challenge.ps1"
        & "tools\verify_paper_export_regeneration.ps1"
        & "tools\verify_paper_artifact_provenance.ps1"
        & "tools\verify_figure_source_consistency.ps1"
        & "tools\verify_manuscript_claim_traceability.ps1"
        & "tools\verify_claim_hierarchy.ps1"
        & "tools\verify_seed_direction_consistency.ps1"
        & "tools\verify_physical_metric_semantics.ps1"
        & "tools\verify_terminology_and_naming.ps1"
        & "tools\verify_manuscript_reviewability.ps1"
        & "tools\verify_rendered_pdf_content.ps1"
        & "tools\verify_attack_evaluation_sanity.ps1"
        & "tools\verify_attack_strength_configuration.ps1"
        & "tools\verify_method_implementation_traceability.ps1"
        & "tools\verify_statistical_interpretation.ps1"
        & "tools\verify_data_provenance_ethics.ps1"
        & "tools\verify_dual_use_safety.ps1"
        & "tools\verify_dataset_profile.ps1"
        & "tools\verify_external_validity_scope.ps1"
        & "tools\verify_environment_reproducibility.ps1"
        & "tools\verify_compute_resource_audit.ps1"
        & "tools\verify_reviewer_quickstart.ps1"
        & "tools\verify_readme_review_entry.ps1"
        & "tools\verify_artifact_license_citation.ps1"
        & "tools\verify_artifact_evaluation_guide.ps1"
        & "tools\verify_reviewer_objection_response.ps1"
        & "tools\verify_workspace_hygiene.ps1"
        & "tools\verify_tex_source_portability.ps1"
        & "tools\verify_formal_pdf_build_readiness.ps1"
        & "tools\verify_code_provenance_drift.ps1"
        & "tools\verify_ablation_sensitivity.ps1"
        & "tools\verify_threshold_hyperparameter_audit.ps1"
        & "tools\verify_failure_mode_negative_results.ps1"
        & "tools\verify_baseline_fairness.ps1"
        & "tools\verify_baseline_competitiveness.ps1"
        & "tools\verify_literature_baseline_reproduction.ps1"
        & "tools\verify_double_blind_submission.ps1" -BundlePath $bundle
    }
    finally {
        Pop-Location
    }

    Push-Location $bundleRoot
    try {
        conda run -n testtorch python -m adsb.run `
            --verify-benchmark outputs\publication_benchmark `
            --verify-preflight-report outputs\publication_benchmark\preflight_report.json `
            --verify-require-physical-metrics `
            --verify-require-primary-claims `
            --verify-strict-publication `
            --verify-write-report
        if ($LASTEXITCODE -ne 0) {
            throw "Extracted bundle strict publication gate failed"
        }
    }
    finally {
        Pop-Location
    }

    Write-Output "bundle=$bundle"
    Write-Output "extracted_root=$bundleRoot"
    Write-Output "manifest_files_checked=$checked"
    Write-Output "formal_pdf_bytes=$formalPdfBytes"
    Write-Output "extracted_novelty_evidence=PASSED"
    Write-Output "extracted_recent_prior_art_challenge=PASSED"
    Write-Output "extracted_reviewer_objection_response=PASSED"
    Write-Output "extracted_paper_export_regeneration=PASSED"
    Write-Output "extracted_paper_artifact_provenance=PASSED"
    Write-Output "extracted_figure_source_consistency=PASSED"
    Write-Output "extracted_manuscript_claim_traceability=PASSED"
    Write-Output "extracted_claim_hierarchy=PASSED"
    Write-Output "extracted_seed_direction_consistency=PASSED"
    Write-Output "extracted_physical_metric_semantics=PASSED"
    Write-Output "extracted_terminology_and_naming=PASSED"
    Write-Output "extracted_manuscript_reviewability=PASSED"
    Write-Output "extracted_rendered_pdf_content=PASSED"
    Write-Output "extracted_attack_evaluation_sanity=PASSED"
    Write-Output "extracted_attack_strength_configuration=PASSED"
    Write-Output "extracted_method_implementation_traceability=PASSED"
    Write-Output "extracted_statistical_interpretation=PASSED"
    Write-Output "extracted_data_provenance_ethics=PASSED"
    Write-Output "extracted_dual_use_safety=PASSED"
    Write-Output "extracted_dataset_profile=PASSED"
    Write-Output "extracted_external_validity_scope=PASSED"
    Write-Output "extracted_environment_reproducibility=PASSED"
    Write-Output "extracted_compute_resource_audit=PASSED"
    Write-Output "extracted_reviewer_quickstart=PASSED"
    Write-Output "extracted_readme_review_entry=PASSED"
    Write-Output "extracted_artifact_license_citation=PASSED"
    Write-Output "extracted_artifact_evaluation_guide=PASSED"
    Write-Output "extracted_workspace_hygiene=PASSED"
    Write-Output "extracted_tex_source_portability=PASSED"
    Write-Output "extracted_formal_pdf_build_readiness=PASSED"
    Write-Output "extracted_code_provenance_drift=PASSED"
    Write-Output "extracted_ablation_sensitivity=PASSED"
    Write-Output "extracted_threshold_hyperparameter_audit=PASSED"
    Write-Output "extracted_failure_mode_negative_results=PASSED"
    Write-Output "extracted_baseline_fairness=PASSED"
    Write-Output "extracted_baseline_competitiveness=PASSED"
    Write-Output "extracted_literature_baseline_reproduction=PASSED"
    Write-Output "extracted_double_blind_submission=PASSED"
    Write-Output "extracted_strict_gate=PASSED"
    Write-Output "status=PASSED"
}
finally {
    if (-not $KeepExtracted -and (Test-Path -LiteralPath $workDir)) {
        $safePath = Assert-OwnedTempPath $workDir
        Remove-Item -LiteralPath $safePath -Recurse -Force
    }
}

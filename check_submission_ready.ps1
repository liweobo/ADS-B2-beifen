param(
    [switch]$RequirePdfTool,
    [switch]$BuildPreviewPdf,
    [switch]$BuildSubmissionBundle,
    [switch]$NoDownload
)

$ErrorActionPreference = "Stop"

function Run-Step {
    param(
        [string]$Name,
        [scriptblock]$Block
    )
    Write-Host ""
    Write-Host "== $Name =="
    & $Block
}

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required file: $Path"
    }
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Run-Step "No-download policy" {
    if (-not $NoDownload) {
        Write-Host "SKIP pass -NoDownload to enforce the local-only workflow check"
        return
    }

    $scriptPaths = @(
        "tools\build_data_split_audit_table.ps1",
        "tools\build_primary_seed_direction_summary.ps1",
        "tools\build_submission_preview_pdf.ps1",
        "tools\build_submission_pdf.ps1",
        "tools\package_submission_bundle.ps1",
        "tools\verify_submission_bundle.ps1",
        "tools\verify_numeric_claims.ps1",
        "tools\verify_manuscript_claim_traceability.ps1",
        "tools\verify_claim_hierarchy.ps1",
        "tools\verify_seed_direction_consistency.ps1",
        "tools\verify_physical_metric_semantics.ps1",
        "tools\verify_terminology_and_naming.ps1",
        "tools\verify_manuscript_reviewability.ps1",
        "tools\verify_attack_evaluation_sanity.ps1",
        "tools\verify_attack_strength_configuration.ps1",
        "tools\verify_method_implementation_traceability.ps1",
        "tools\verify_statistical_interpretation.ps1",
        "tools\verify_data_provenance_ethics.ps1",
        "tools\verify_dual_use_safety.ps1",
        "tools\verify_dataset_profile.ps1",
        "tools\verify_external_validity_scope.ps1",
        "tools\verify_environment_reproducibility.ps1",
        "tools\verify_compute_resource_audit.ps1",
        "tools\verify_reviewer_quickstart.ps1",
        "tools\verify_readme_review_entry.ps1",
        "tools\verify_artifact_license_citation.ps1",
        "tools\verify_artifact_evaluation_guide.ps1",
        "tools\verify_reviewer_objection_response.ps1",
        "tools\verify_workspace_hygiene.ps1",
        "tools\verify_tex_source_portability.ps1",
        "tools\verify_formal_pdf_build_readiness.ps1",
        "tools\verify_code_provenance_drift.ps1",
        "tools\verify_ablation_sensitivity.ps1",
        "tools\verify_threshold_hyperparameter_audit.ps1",
        "tools\verify_failure_mode_negative_results.ps1",
        "tools\verify_baseline_fairness.ps1",
        "tools\verify_baseline_competitiveness.ps1",
        "tools\verify_literature_baseline_reproduction.ps1",
        "tools\audit_literature_attack_resolution.py",
        "tools\verify_claim_scope.ps1",
        "tools\verify_novelty_evidence.ps1",
        "tools\verify_recent_prior_art_challenge.ps1",
        "tools\verify_paper_artifact_provenance.ps1",
        "tools\verify_figure_source_consistency.ps1",
        "tools\verify_figure_and_table_quality.ps1",
        "tools\verify_paper_export_regeneration.ps1",
        "tools\verify_manuscript_structure.ps1",
        "tools\verify_completion_audit.ps1",
        "tools\verify_preview_artifact.ps1",
        "tools\verify_rendered_pdf_content.ps1",
        "tools\verify_anonymized_bundle.ps1",
        "tools\verify_double_blind_submission.ps1",
        "tools\run_publication_gate.py",
        "tools\regenerate_paper_exports.py",
        "tools\preflight_publication_data.py",
        "tools\benchmark_status.py"
    )
    $forbidden = @(
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "Start-BitsTransfer",
        "winget install",
        "wget",
        "curl ",
        "curl.exe",
        "pip install",
        "pip3 install",
        "uv pip install",
        "conda install",
        "conda create",
        "conda env create",
        "mamba install",
        "micromamba install",
        "DownloadFile"
    )
    foreach ($path in $scriptPaths) {
        Require-File $path
        $text = Get-Content -Raw -LiteralPath $path
        foreach ($needle in $forbidden) {
            if ($text.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "No-download policy violation in ${path}: ${needle}"
            }
        }
    }
    Write-Host "OK no-download workflow scripts contain no installer/download commands"
}

Run-Step "Strict publication gate" {
    conda run -n testtorch python -m adsb.run `
        --verify-benchmark outputs\publication_benchmark `
        --verify-preflight-report outputs\publication_benchmark\preflight_report.json `
        --verify-require-physical-metrics `
        --verify-require-primary-claims `
        --verify-strict-publication `
        --verify-write-report
}

Run-Step "Unit tests" {
    conda run -n testtorch python -m unittest discover -s tests -p "test*.py"
}

Run-Step "Build data split audit table" {
    & "tools\build_data_split_audit_table.ps1"
}

Run-Step "Build primary seed direction summary" {
    & "tools\build_primary_seed_direction_summary.ps1"
}

Run-Step "Paper export regeneration" {
    Require-File "PAPER_EXPORT_REGENERATION_AUDIT.md"
    & "tools\verify_paper_export_regeneration.ps1"
}

Run-Step "Terminology and naming" {
    Require-File "TERMINOLOGY_AND_NAMING_AUDIT.md"
    & "tools\verify_terminology_and_naming.ps1"
}

Run-Step "Build submission preview PDF" {
    $previewScript = "tools\build_submission_preview_pdf.ps1"
    $previewPdf = "output\pdf\catad_submission_preview.pdf"
    if ($BuildPreviewPdf -or -not (Test-Path -LiteralPath $previewPdf -PathType Leaf)) {
        & $previewScript
    }
    else {
        Write-Host "OK preview PDF already exists"
    }
}

Run-Step "Build submission bundle" {
    $bundleScript = "tools\package_submission_bundle.ps1"
    $bundleZip = "output\submission\catad_topconf_submission_bundle.zip"
    if ($BuildSubmissionBundle -or -not (Test-Path -LiteralPath $bundleZip -PathType Leaf)) {
        & $bundleScript
    }
    else {
        Write-Host "OK submission bundle already exists"
    }
}

Run-Step "Required artifacts" {
    $required = @(
        "outputs\publication_benchmark\verification_report.md",
        "outputs\publication_benchmark\benchmark_manifest.json",
        "outputs\publication_benchmark\data_split_audit.csv",
        "outputs\publication_benchmark\data_split_audit.tex",
        "outputs\publication_benchmark\primary_seed_direction_summary.csv",
        "outputs\publication_benchmark\primary_seed_direction_summary.tex",
        "outputs\publication_benchmark\aggregate_selected_summary.tex",
        "outputs\publication_benchmark\paired_comparisons.tex",
        "outputs\tables\table_multiseed_summary.tex",
        "outputs\tables\table_paired_multiseed_comparison.tex",
        "outputs\publication_benchmark\per_seed_metrics_long.csv",
        "outputs\publication_benchmark\per_seed_metrics_wide.csv",
        "outputs\literature_benchmark\literature_benchmark_manifest.json",
        "outputs\literature_benchmark\literature_detection_report_manifest.json",
        "outputs\literature_benchmark\literature_detection_report.md",
        "outputs\literature_benchmark\table_literature_detection.tex",
        "outputs\literature_benchmark\attack_resolution_audit.json",
        "outputs\literature_benchmark\aggregate_summary.csv",
        "outputs\literature_benchmark\paired_vs_catad.csv",
        "outputs\audits\terminology_and_naming_verification.json",
        "outputs\test_set_results.csv",
        "outputs\ablation_table5\ablation_table5_summary.json",
        "results\fig_epsilon_sensitivity_data.csv",
        "results\fig_main_robustness_data.csv",
        "results\fig_physical_valid_asr_data.csv",
        "paper_lncs\main.tex",
        "paper_lncs\references.bib",
        "tools\build_data_split_audit_table.ps1",
        "tools\build_primary_seed_direction_summary.ps1",
        "tools\build_submission_preview_pdf.ps1",
        "tools\build_submission_pdf.ps1",
        "tools\package_submission_bundle.ps1",
        "tools\verify_submission_bundle.ps1",
        "tools\verify_numeric_claims.ps1",
        "tools\verify_manuscript_claim_traceability.ps1",
        "tools\verify_claim_hierarchy.ps1",
        "tools\verify_seed_direction_consistency.ps1",
        "tools\verify_physical_metric_semantics.ps1",
        "tools\verify_terminology_and_naming.ps1",
        "tools\verify_manuscript_reviewability.ps1",
        "tools\verify_attack_evaluation_sanity.ps1",
        "tools\verify_attack_strength_configuration.ps1",
        "tools\verify_method_implementation_traceability.ps1",
        "tools\verify_statistical_interpretation.ps1",
        "tools\verify_data_provenance_ethics.ps1",
        "tools\verify_dual_use_safety.ps1",
        "tools\verify_dataset_profile.ps1",
        "tools\verify_external_validity_scope.ps1",
        "tools\verify_environment_reproducibility.ps1",
        "tools\verify_compute_resource_audit.ps1",
        "tools\verify_reviewer_quickstart.ps1",
        "tools\verify_readme_review_entry.ps1",
        "tools\verify_artifact_license_citation.ps1",
        "tools\verify_artifact_evaluation_guide.ps1",
        "tools\verify_reviewer_objection_response.ps1",
        "tools\verify_workspace_hygiene.ps1",
        "tools\verify_tex_source_portability.ps1",
        "tools\verify_formal_pdf_build_readiness.ps1",
        "tools\verify_code_provenance_drift.ps1",
        "tools\verify_ablation_sensitivity.ps1",
        "tools\verify_threshold_hyperparameter_audit.ps1",
        "tools\verify_failure_mode_negative_results.ps1",
        "tools\verify_baseline_fairness.ps1",
        "tools\verify_baseline_competitiveness.ps1",
        "tools\verify_literature_baseline_reproduction.ps1",
        "tools\audit_literature_attack_resolution.py",
        "tools\verify_claim_scope.ps1",
        "tools\verify_novelty_evidence.ps1",
        "tools\verify_recent_prior_art_challenge.ps1",
        "tools\verify_manuscript_structure.ps1",
        "tools\verify_figure_source_consistency.ps1",
        "tools\verify_paper_export_regeneration.ps1",
        "tools\verify_completion_audit.ps1",
        "tools\verify_preview_artifact.ps1",
        "tools\verify_rendered_pdf_content.ps1",
        "tools\verify_anonymized_bundle.ps1",
        "tools\verify_double_blind_submission.ps1",
        "output\pdf\catad_submission_preview.html",
        "output\pdf\catad_submission_preview.pdf",
        "output\submission\catad_topconf_submission_bundle.zip",
        "output\submission\catad_topconf_submission_bundle.manifest.tsv",
        "output\submission\catad_topconf_submission_bundle.manifest.json",
        "LICENSE",
        "CITATION.cff",
        "README.md",
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
        "INNOVATION_AND_EVIDENCE.md",
        "PRIOR_ART_NOVELTY_MATRIX.md",
        "PRIOR_ART_CRITERIA_COVERAGE.tsv",
        "PRIOR_ART_EVIDENCE_SNAPSHOT.md",
        "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md",
        "REVIEWER_OBJECTION_RESPONSE_AUDIT.md",
        "PAPER_ARTIFACT_PROVENANCE.md",
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
        "FIGURE_SOURCE_CONSISTENCY_AUDIT.md",
        "PAPER_EXPORT_REGENERATION_AUDIT.md",
        "CODE_PROVENANCE_DRIFT_AUDIT.md",
        "ABLATION_AND_SENSITIVITY_AUDIT.md",
        "THRESHOLD_AND_HYPERPARAMETER_AUDIT.md",
        "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md",
        "BASELINE_FAIRNESS_AUDIT.md",
        "BASELINE_COMPETITIVENESS_AUDIT.md",
        "LITERATURE_BASELINE_REPRODUCTION_AUDIT.md",
        "TOP_CONFERENCE_READINESS_AUDIT.md",
        "SUBMISSION_COMPLETION_AUDIT.md",
        "SUBMISSION_READINESS.md"
    )
    foreach ($path in $required) {
        Require-File $path
        $item = Get-Item -LiteralPath $path
        Write-Host ("OK {0} ({1} bytes)" -f $path, $item.Length)
    }
}

Run-Step "Top-conference readiness audit" {
    $auditPath = "TOP_CONFERENCE_READINESS_AUDIT.md"
    Require-File $auditPath
    $audit = Get-Content -Raw -LiteralPath $auditPath
    $markers = @(
        "Evidence Matrix",
        "Reviewer-Risk Notes",
        "No-Download Audit Command",
        "Formal TeX PDF",
        "Strict benchmark gate"
    )
    foreach ($marker in $markers) {
        if (-not $audit.Contains($marker)) {
            throw "Top-conference readiness audit missing marker: $marker"
        }
    }
    Write-Host "OK top-conference readiness audit markers"
}

Run-Step "Claim scope guardrails" {
    Require-File "CLAIM_SCOPE_GUARDRAILS.md"
    & "tools\verify_claim_scope.ps1"
}

Run-Step "Novelty evidence" {
    Require-File "INNOVATION_AND_EVIDENCE.md"
    Require-File "PRIOR_ART_NOVELTY_MATRIX.md"
    Require-File "PRIOR_ART_CRITERIA_COVERAGE.tsv"
    & "tools\verify_novelty_evidence.ps1"
}

Run-Step "Recent prior-art challenge" {
    Require-File "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md"
    & "tools\verify_recent_prior_art_challenge.ps1"
}

Run-Step "Numeric claims traceability" {
    Require-File "NUMERIC_CLAIMS_LEDGER.md"
    & "tools\verify_numeric_claims.ps1"
}

Run-Step "Manuscript claim traceability" {
    Require-File "MANUSCRIPT_CLAIM_TRACEABILITY_AUDIT.md"
    & "tools\verify_manuscript_claim_traceability.ps1"
}

Run-Step "Claim hierarchy" {
    Require-File "CLAIM_HIERARCHY_AUDIT.md"
    & "tools\verify_claim_hierarchy.ps1"
}

Run-Step "Seed-direction consistency" {
    Require-File "SEED_DIRECTION_CONSISTENCY_AUDIT.md"
    & "tools\verify_seed_direction_consistency.ps1"
}

Run-Step "Physical metric semantics" {
    Require-File "PHYSICAL_METRIC_SEMANTICS_AUDIT.md"
    & "tools\verify_physical_metric_semantics.ps1"
}

Run-Step "Attack evaluation sanity" {
    Require-File "ATTACK_EVALUATION_SANITY_CHECKLIST.md"
    Require-File "ADAPTIVE_ATTACK_AUDIT.md"
    & "tools\verify_attack_evaluation_sanity.ps1"
}

Run-Step "Attack strength configuration" {
    Require-File "ATTACK_STRENGTH_CONFIGURATION_AUDIT.md"
    & "tools\verify_attack_strength_configuration.ps1"
}

Run-Step "Method implementation traceability" {
    Require-File "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md"
    & "tools\verify_method_implementation_traceability.ps1"
}

Run-Step "Statistical interpretation" {
    Require-File "STATISTICAL_INTERPRETATION_CHECKLIST.md"
    & "tools\verify_statistical_interpretation.ps1"
}

Run-Step "Data provenance and ethics" {
    Require-File "DATA_PROVENANCE_AND_ETHICS.md"
    & "tools\verify_data_provenance_ethics.ps1"
}

Run-Step "Dual-use safety" {
    Require-File "DUAL_USE_SAFETY_AUDIT.md"
    & "tools\verify_dual_use_safety.ps1"
}

Run-Step "Dataset profile" {
    Require-File "DATASET_PROFILE_AUDIT.md"
    & "tools\verify_dataset_profile.ps1"
}

Run-Step "External validity scope" {
    Require-File "EXTERNAL_VALIDITY_SCOPE_AUDIT.md"
    & "tools\verify_external_validity_scope.ps1"
}

Run-Step "Environment reproducibility" {
    Require-File "ENVIRONMENT_REPRODUCIBILITY.md"
    & "tools\verify_environment_reproducibility.ps1"
}

Run-Step "Compute resource audit" {
    Require-File "COMPUTE_RESOURCE_AUDIT.md"
    & "tools\verify_compute_resource_audit.ps1"
}

Run-Step "Reviewer quickstart" {
    Require-File "REVIEWER_QUICKSTART.md"
    & "tools\verify_reviewer_quickstart.ps1"
}

Run-Step "README review entry" {
    Require-File "README.md"
    Require-File "README_REVIEW_ENTRY_AUDIT.md"
    & "tools\verify_readme_review_entry.ps1"
}

Run-Step "Artifact license and citation" {
    Require-File "LICENSE"
    Require-File "CITATION.cff"
    Require-File "ARTIFACT_LICENSE_AND_CITATION_AUDIT.md"
    & "tools\verify_artifact_license_citation.ps1"
}

Run-Step "Artifact evaluation guide" {
    Require-File "ARTIFACT_EVALUATION_GUIDE.md"
    & "tools\verify_artifact_evaluation_guide.ps1"
}

Run-Step "Reviewer objection response" {
    Require-File "REVIEWER_OBJECTION_RESPONSE_AUDIT.md"
    & "tools\verify_reviewer_objection_response.ps1"
}

Run-Step "Workspace hygiene" {
    Require-File "WORKSPACE_HYGIENE_AUDIT.md"
    & "tools\verify_workspace_hygiene.ps1"
}

Run-Step "Code provenance drift" {
    Require-File "CODE_PROVENANCE_DRIFT_AUDIT.md"
    & "tools\verify_code_provenance_drift.ps1"
}

Run-Step "Paper artifact provenance" {
    Require-File "PAPER_ARTIFACT_PROVENANCE.md"
    & "tools\verify_paper_artifact_provenance.ps1"
}

Run-Step "Figure source consistency" {
    Require-File "FIGURE_SOURCE_CONSISTENCY_AUDIT.md"
    & "tools\verify_figure_source_consistency.ps1"
}

Run-Step "Figure and table quality" {
    Require-File "FIGURE_AND_TABLE_QUALITY_AUDIT.md"
    & "tools\verify_figure_and_table_quality.ps1"
}

Run-Step "Ablation and sensitivity" {
    Require-File "ABLATION_AND_SENSITIVITY_AUDIT.md"
    & "tools\verify_ablation_sensitivity.ps1"
}

Run-Step "Threshold and hyperparameter audit" {
    Require-File "THRESHOLD_AND_HYPERPARAMETER_AUDIT.md"
    & "tools\verify_threshold_hyperparameter_audit.ps1"
}

Run-Step "Failure-mode and negative-result audit" {
    Require-File "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md"
    & "tools\verify_failure_mode_negative_results.ps1"
}

Run-Step "Baseline fairness audit" {
    Require-File "BASELINE_FAIRNESS_AUDIT.md"
    & "tools\verify_baseline_fairness.ps1"
}

Run-Step "Baseline competitiveness audit" {
    Require-File "BASELINE_COMPETITIVENESS_AUDIT.md"
    & "tools\verify_baseline_competitiveness.ps1"
}

Run-Step "Published ADS-B baseline reproduction audit" {
    Require-File "LITERATURE_BASELINE_REPRODUCTION_AUDIT.md"
    & "tools\verify_literature_baseline_reproduction.ps1"
}

Run-Step "Artifact reproducibility checklist" {
    $checklistPath = "ARTIFACT_REPRODUCIBILITY_CHECKLIST.md"
    Require-File $checklistPath
    $checklist = Get-Content -Raw -LiteralPath $checklistPath
    $markers = @(
        "Quick Verification",
        "Rebuild Local Review Artifacts",
        "Verify Bundle Integrity Offline",
        "Verify Numeric Claims",
        "Verify Compute Resource Audit",
        "Verify Method Implementation Traceability",
        "Verify Rendered PDF Content",
        "Verify Unit Tests",
        "Verify Completion Audit",
        "Full Benchmark Rerun",
        "Known Limitation"
    )
    foreach ($marker in $markers) {
        if (-not $checklist.Contains($marker)) {
            throw "Artifact reproducibility checklist missing marker: $marker"
        }
    }
    Write-Host "OK artifact reproducibility checklist markers"
}

Run-Step "Manuscript references and inputs" {
    $texPath = "paper_lncs\main.tex"
    $bibPath = "paper_lncs\references.bib"
    $tex = Get-Content -Raw -LiteralPath $texPath
    $bib = Get-Content -Raw -LiteralPath $bibPath

    $citeKeys = [regex]::Matches($tex, "\\cite\{([^}]+)\}") |
        ForEach-Object { $_.Groups[1].Value.Split(",") } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ } |
        Sort-Object -Unique
    $bibKeys = [regex]::Matches($bib, "@\w+\{([^,]+),") |
        ForEach-Object { $_.Groups[1].Value.Trim() } |
        Sort-Object -Unique
    $missing = $citeKeys | Where-Object { $bibKeys -notcontains $_ }
    if ($missing) {
        throw "Missing bibliography entries: $($missing -join ', ')"
    }
    Write-Host "OK cited bibliography keys: $($citeKeys.Count)"

    $inputKeys = [regex]::Matches($tex, "\\(?:input|maybeinput)\{([^}]+)\}") |
        ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $_ -like "../*" } |
        Sort-Object -Unique
    foreach ($input in $inputKeys) {
        $candidate = [System.IO.Path]::GetFullPath((Join-Path "paper_lncs" $input))
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "Missing manuscript input: $input -> $candidate"
        }
        Write-Host "OK input $input"
    }
}

Run-Step "Manuscript structure" {
    & "tools\verify_manuscript_structure.ps1"
}

Run-Step "Manuscript reviewability" {
    Require-File "MANUSCRIPT_REVIEWABILITY_AUDIT.md"
    & "tools\verify_manuscript_reviewability.ps1"
}

Run-Step "TeX source portability" {
    Require-File "TEX_SOURCE_PORTABILITY_AUDIT.md"
    & "tools\verify_tex_source_portability.ps1"
}

Run-Step "Formal PDF build readiness" {
    Require-File "FORMAL_PDF_BUILD_AUDIT.md"
    & "tools\verify_formal_pdf_build_readiness.ps1"
}

Run-Step "Completion audit" {
    & "tools\verify_completion_audit.ps1"
}

Run-Step "Preview artifact" {
    & "tools\verify_preview_artifact.ps1"
}

Run-Step "Rendered PDF content" {
    Require-File "RENDERED_PDF_CONTENT_AUDIT.md"
    & "tools\verify_rendered_pdf_content.ps1"
}

Run-Step "Finalize submission bundle" {
    # The formal-PDF readiness check may rebuild the PDF and change its binary hash.
    & "tools\package_submission_bundle.ps1"
}

Run-Step "Submission bundle" {
    $bundleZip = "output\submission\catad_topconf_submission_bundle.zip"
    $manifestTsv = "output\submission\catad_topconf_submission_bundle.manifest.tsv"
    $manifestJson = "output\submission\catad_topconf_submission_bundle.manifest.json"

    Require-File $bundleZip
    Require-File $manifestTsv
    Require-File $manifestJson

    $manifest = Import-Csv -Delimiter "`t" -LiteralPath $manifestTsv
    if ($manifest.Count -lt 100) {
        throw "Submission bundle manifest is unexpectedly small: $($manifest.Count) files"
    }

    $requiredBundlePaths = @(
        "adsb/benchmark.py",
        "adsb/attacks.py",
        "adsb/literature_models.py",
        "adsb/literature_training.py",
        "adsb/literature_benchmark.py",
        "adsb/literature_report.py",
        "adsb/paper_naming.py",
        "tests/test_benchmark_stats.py",
        "tests/test_physical_metrics.py",
        "tests/test_submission_tex_generation.py",
        "tests/test_literature_models.py",
        "tests/test_literature_report.py",
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
        "outputs/publication_benchmark/primary_seed_direction_summary.csv",
        "outputs/publication_benchmark/primary_seed_direction_summary.tex",
        "outputs/literature_benchmark/literature_benchmark_manifest.json",
        "outputs/literature_benchmark/literature_detection_report_manifest.json",
        "outputs/literature_benchmark/literature_detection_report.md",
        "outputs/literature_benchmark/table_literature_detection.tex",
        "outputs/literature_benchmark/attack_resolution_audit.json",
        "outputs/audits/terminology_and_naming_verification.json",
        "outputs/test_set_results.csv",
        "results/fig_physical_valid_asr_data.csv",
        "sample_adsb_decoded.csv",
        "LICENSE",
        "CITATION.cff",
        "README.md",
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
        "PRIOR_ART_NOVELTY_MATRIX.md",
        "PRIOR_ART_CRITERIA_COVERAGE.tsv",
        "RECENT_PRIOR_ART_CHALLENGE_AUDIT.md",
        "REVIEWER_OBJECTION_RESPONSE_AUDIT.md",
        "PAPER_ARTIFACT_PROVENANCE.md",
        "DOUBLE_BLIND_REVIEW_CHECKLIST.md",
        "ATTACK_EVALUATION_SANITY_CHECKLIST.md",
        "STATISTICAL_INTERPRETATION_CHECKLIST.md",
        "FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md",
        "BASELINE_FAIRNESS_AUDIT.md",
        "LITERATURE_BASELINE_REPRODUCTION_AUDIT.md",
        "FIGURE_SOURCE_CONSISTENCY_AUDIT.md",
        "PAPER_EXPORT_REGENERATION_AUDIT.md",
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
        "WORKSPACE_HYGIENE_AUDIT.md",
        "TOP_CONFERENCE_READINESS_AUDIT.md",
        "SUBMISSION_COMPLETION_AUDIT.md",
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
        "tools/verify_reviewer_objection_response.ps1",
        "tools/verify_workspace_hygiene.ps1",
        "tools/verify_tex_source_portability.ps1",
        "tools/verify_formal_pdf_build_readiness.ps1",
        "tools/verify_numeric_claims.ps1",
        "tools/verify_manuscript_claim_traceability.ps1",
        "tools/verify_claim_hierarchy.ps1",
        "tools/verify_seed_direction_consistency.ps1",
        "tools/build_primary_seed_direction_summary.ps1",
        "tools/verify_physical_metric_semantics.ps1",
        "tools/verify_terminology_and_naming.ps1",
        "tools/verify_manuscript_reviewability.ps1",
        "tools/verify_claim_scope.ps1",
        "tools/verify_novelty_evidence.ps1",
        "tools/verify_recent_prior_art_challenge.ps1",
        "tools/verify_paper_artifact_provenance.ps1",
        "tools/verify_figure_source_consistency.ps1",
        "tools/verify_paper_export_regeneration.ps1",
        "tools/regenerate_paper_exports.py",
        "tools/verify_failure_mode_negative_results.ps1",
        "tools/verify_baseline_fairness.ps1",
        "tools/verify_baseline_competitiveness.ps1",
        "tools/verify_literature_baseline_reproduction.ps1",
        "tools/audit_literature_attack_resolution.py",
        "tools/verify_manuscript_structure.ps1",
        "tools/verify_completion_audit.ps1",
        "tools/verify_preview_artifact.ps1",
        "tools/verify_rendered_pdf_content.ps1",
        "tools/verify_anonymized_bundle.ps1",
        "tools/verify_double_blind_submission.ps1",
        "TEX_SOURCE_PORTABILITY_AUDIT.md",
        "FORMAL_PDF_BUILD_AUDIT.md",
        "BASELINE_COMPETITIVENESS_AUDIT.md",
        "LITERATURE_BASELINE_REPRODUCTION_AUDIT.md",
        "METHOD_IMPLEMENTATION_TRACEABILITY_AUDIT.md",
        "COMPUTE_RESOURCE_AUDIT.md",
        "RENDERED_PDF_CONTENT_AUDIT.md",
        "BUNDLE_README.md"
    )
    $manifestPaths = @($manifest | ForEach-Object { $_.path })
    foreach ($path in $requiredBundlePaths) {
        if ($manifestPaths -notcontains $path) {
            throw "Submission bundle manifest missing: $path"
        }
    }
    $previewPdfManifest = $manifest | Where-Object { $_.path -eq "output/pdf/catad_submission_preview.pdf" } | Select-Object -First 1
    if (-not $previewPdfManifest) {
        throw "Submission bundle manifest missing preview PDF row"
    }
    $previewPdfItem = Get-Item -LiteralPath "output\pdf\catad_submission_preview.pdf"
    $previewPdfHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $previewPdfItem.FullName).Hash.ToLowerInvariant()
    if ([int64]$previewPdfManifest.bytes -ne [int64]$previewPdfItem.Length) {
        throw "Submission bundle preview PDF size differs from current preview PDF: manifest=$($previewPdfManifest.bytes) current=$($previewPdfItem.Length)"
    }
    if ($previewPdfManifest.sha256.ToLowerInvariant() -ne $previewPdfHash) {
        throw "Submission bundle preview PDF hash differs from current preview PDF"
    }
    $formalPdfManifest = $manifest | Where-Object { $_.path -eq "output/pdf/catad_submission_latex_updated.pdf" } | Select-Object -First 1
    if (-not $formalPdfManifest) {
        throw "Submission bundle manifest missing formal LNCS PDF row"
    }
    $formalPdfItem = Get-Item -LiteralPath "output\pdf\catad_submission_latex_updated.pdf"
    $formalPdfHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $formalPdfItem.FullName).Hash.ToLowerInvariant()
    if ([int64]$formalPdfManifest.bytes -ne [int64]$formalPdfItem.Length) {
        throw "Submission bundle formal PDF size differs from current formal PDF: manifest=$($formalPdfManifest.bytes) current=$($formalPdfItem.Length)"
    }
    if ($formalPdfManifest.sha256.ToLowerInvariant() -ne $formalPdfHash) {
        throw "Submission bundle formal PDF hash differs from current formal PDF"
    }
    foreach ($path in @("states_2018-05-28-14.csv", "states_2022-06-27-23.csv")) {
        if ($manifestPaths -contains $path) {
            throw "Submission bundle should not include raw upstream snapshot: $path"
        }
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $bundleZip))
    try {
        $zipPaths = @($zip.Entries | ForEach-Object { $_.FullName.Replace("\", "/") })
        foreach ($path in $requiredBundlePaths) {
            $zipPath = "catad_topconf_submission_bundle/$path"
            if ($zipPaths -notcontains $zipPath) {
                throw "Submission bundle zip missing: $zipPath"
            }
        }
        foreach ($path in @("states_2018-05-28-14.csv", "states_2022-06-27-23.csv")) {
            $zipPath = "catad_topconf_submission_bundle/$path"
            if ($zipPaths -contains $zipPath) {
                throw "Submission bundle zip should not include raw upstream snapshot: $zipPath"
            }
        }
        Write-Host "OK submission bundle entries: $($zip.Entries.Count)"
    }
    finally {
        $zip.Dispose()
    }

    $zipHash = Get-FileHash -Algorithm SHA256 -LiteralPath $bundleZip
    Write-Host "OK submission bundle SHA-256: $($zipHash.Hash.ToLowerInvariant())"

    & "tools\verify_submission_bundle.ps1" -BundlePath $bundleZip
}

Run-Step "Anonymized submission bundle" {
    & "tools\verify_anonymized_bundle.ps1" -BundlePath "output\submission\catad_topconf_submission_bundle.zip"
}

Run-Step "Double-blind submission" {
    Require-File "DOUBLE_BLIND_REVIEW_CHECKLIST.md"
    & "tools\verify_double_blind_submission.ps1" -BundlePath "output\submission\catad_topconf_submission_bundle.zip"
}

Run-Step "Pandoc parse check" {
    $pandoc = Get-Command pandoc -ErrorAction SilentlyContinue
    if (-not $pandoc) {
        Write-Host "SKIP pandoc not found"
        return
    }
    $tmp = Join-Path $env:TEMP "adsb_pandoc_parse_check.txt"
    $log = Join-Path $env:TEMP "adsb_pandoc_parse_check.log"
    try {
        Push-Location paper_lncs
        pandoc -s main.tex --bibliography=references.bib --citeproc -t plain -o $tmp 2> $log
        if ($LASTEXITCODE -ne 0) {
            if (Test-Path -LiteralPath $log) {
                Get-Content -LiteralPath $log
            }
            throw "pandoc parse check failed"
        }
        if ((Test-Path -LiteralPath $log) -and ((Get-Item -LiteralPath $log).Length -gt 0)) {
            $pandocLog = Get-Content -Raw -LiteralPath $log
            if ($pandocLog.IndexOf("[WARNING]", [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                Get-Content -LiteralPath $log
                throw "pandoc parse check emitted warnings"
            }
        }
    }
    finally {
        Pop-Location
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force
        }
        if (Test-Path -LiteralPath $log) {
            Remove-Item -LiteralPath $log -Force
        }
    }
    Write-Host "OK pandoc parsed manuscript source"
}

Run-Step "Submission preview PDF" {
    $previewScript = "tools\build_submission_preview_pdf.ps1"
    $previewHtml = "output\pdf\catad_submission_preview.html"
    $previewPdf = "output\pdf\catad_submission_preview.pdf"

    if (-not (Test-Path -LiteralPath $previewPdf -PathType Leaf)) {
        & $previewScript
    }

    Require-File $previewHtml
    Require-File $previewPdf

    $html = Get-Content -Raw -Encoding UTF8 -LiteralPath $previewHtml
    $requiredMarkers = @(
        "Multi-seed detection and robustness summary over five matched aircraft splits/seeds",
        "Paired multi-seed comparison",
        "fig_main_robustness.png",
        "fig_physical_valid_asr.png",
        "fig_epsilon_sensitivity.png",
        '<h1 id="references">References</h1>'
    )
    foreach ($marker in $requiredMarkers) {
        if (-not $html.Contains($marker)) {
            throw "Preview HTML missing marker: $marker"
        }
    }
    $forbiddenMarkers = @(
        "begin{aligned}",
        ([string][char]0x9225),
        ([string][char]0x807d),
        "<embed"
    )
    foreach ($marker in $forbiddenMarkers) {
        if ($html.Contains($marker)) {
            throw "Preview HTML contains forbidden marker: $marker"
        }
    }
    Write-Host "OK preview HTML markers"

    $nativePoppler = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\native\poppler\Library\bin"
    $pdfinfo = Join-Path $nativePoppler "pdfinfo.exe"
    if (-not (Test-Path -LiteralPath $pdfinfo -PathType Leaf)) {
        $cmd = Get-Command pdfinfo -ErrorAction SilentlyContinue
        if ($cmd) {
            $pdfinfo = $cmd.Source
        }
    }
    $previewPages = $null
    if (Test-Path -LiteralPath $pdfinfo -PathType Leaf) {
        $info = & $pdfinfo $previewPdf 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "pdfinfo failed for preview PDF"
        }
        if ($info -notmatch "Pages:\s+(\d+)") {
            throw "pdfinfo did not report a page count"
        }
        $previewPages = [int]$Matches[1]
        if ($info -notmatch "Page size:.*A4") {
            Write-Host "WARN preview PDF page size is not reported as A4"
        }
        Write-Host "OK preview PDF metadata"
    }
    else {
        Write-Host "WARN pdfinfo not found; skipped preview PDF metadata check"
    }

    $pdftoppm = Join-Path $nativePoppler "pdftoppm.exe"
    if (-not (Test-Path -LiteralPath $pdftoppm -PathType Leaf)) {
        $cmd = Get-Command pdftoppm -ErrorAction SilentlyContinue
        if ($cmd) {
            $pdftoppm = $cmd.Source
        }
    }
    if (Test-Path -LiteralPath $pdftoppm -PathType Leaf) {
        $renderDir = Join-Path $env:TEMP "adsb_preview_render_check"
        New-Item -ItemType Directory -Force -Path $renderDir | Out-Null
        $prefix = Join-Path $renderDir "preview"
        Get-ChildItem -LiteralPath $renderDir -Filter "preview-*.png" -ErrorAction SilentlyContinue | Remove-Item -Force
        & $pdftoppm -png -r 72 $previewPdf $prefix
        if ($LASTEXITCODE -ne 0) {
            throw "pdftoppm failed for preview PDF"
        }
        $rendered = @(Get-ChildItem -LiteralPath $renderDir -Filter "preview-*.png" | Sort-Object Name)
        if ($rendered.Count -eq 0) {
            throw "Preview PDF render check did not create any page PNGs"
        }
        if ($previewPages -and $rendered.Count -ne $previewPages) {
            throw "Preview PDF render page count mismatch: expected $previewPages, got $($rendered.Count)"
        }
        foreach ($renderedItem in $rendered) {
            if ($renderedItem.Length -lt 10000) {
                throw "Preview PDF render looks too small: $($renderedItem.Name)"
            }
        }
        Write-Host "OK preview PDF full-page render ($($rendered.Count) pages)"
    }
    else {
        Write-Host "WARN pdftoppm not found; skipped preview PDF render check"
    }
}

Run-Step "PDF tool availability" {
    $pdfTools = @("latexmk", "tectonic", "pdflatex", "xelatex", "lualatex", "bibtex")
    $found = @()
    foreach ($tool in $pdfTools) {
        $cmd = Get-Command $tool -ErrorAction SilentlyContinue
        if ($cmd) {
            $found += "$tool=$($cmd.Source)"
        }
    }
    if ($found.Count -eq 0) {
        $message = "No TeX/PDF tool found on PATH. Install a TeX distribution or Tectonic to build the final PDF."
        if ($RequirePdfTool) {
            throw $message
        }
        Write-Host "WARN $message"
    }
    else {
        $found | ForEach-Object { Write-Host "OK $_" }
    }
}

Write-Host ""
Write-Host "Submission source and experiment checks completed."

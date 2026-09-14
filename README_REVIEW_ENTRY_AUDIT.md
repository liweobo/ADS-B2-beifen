# CAT-AD README Review Entry Audit

This audit verifies that the repository has a standard root-level reviewer
entry point. The goal is to prevent a reviewer or artifact evaluator from
having to infer the correct command, bundle, manuscript, and external limits
from scattered files.

## Checked Entry Requirements

| Requirement | Local evidence |
| --- | --- |
| Root README exists | `README.md` |
| One-command no-download audit is visible | `check_submission_ready.ps1 -NoDownload` |
| Rebuild command is visible | `check_submission_ready.ps1 -NoDownload -BuildPreviewPdf -BuildSubmissionBundle` |
| Required conda environment is visible | `conda run -n testtorch python` |
| Manuscript and preview PDF are linked | `paper_lncs/main.tex`, `output/pdf/catad_submission_preview.pdf` |
| Submission bundle is linked | `output/submission/catad_topconf_submission_bundle.zip` |
| Evidence documents are linked | reviewer quickstart, reproducibility checklist, artifact guide, completion audit, readiness audit |
| External limits are visible | no acceptance guarantee, no TeX download, no operational safety certificate, no universal robustness certificate |

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_readme_review_entry.ps1
```

Expected output includes:

- `readme_review_entry=PASSED`
- `readme_markers_checked=44`
- `entry_files_checked=26`
- `forbidden_claims_checked=8`

## External Limit

This audit verifies the root review entry, not the full experiment. The full
gate remains `check_submission_ready.ps1 -NoDownload -BuildPreviewPdf
-BuildSubmissionBundle`.

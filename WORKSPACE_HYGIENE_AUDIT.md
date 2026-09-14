# CAT-AD Workspace Hygiene Audit

This audit separates the live working directory from the submission bundle that
reviewers should inspect. The repository root contains historical scripts,
intermediate archives, and large raw snapshots that are useful for local
development or provenance but should not be treated as part of the anonymous
artifact package.

## Submission Boundary

The authoritative review artifact is:

- `output/submission/catad_topconf_submission_bundle.zip`

Reviewer entry points inside that bundle are:

- `BUNDLE_README.md`
- `check_submission_ready.ps1`
- `SUBMISSION_READINESS.md`
- `REVIEWER_QUICKSTART.md`
- `ARTIFACT_REPRODUCIBILITY_CHECKLIST.md`
- `ARTIFACT_EVALUATION_GUIDE.md`
- `paper_lncs/main.tex`
- `output/pdf/catad_submission_preview.pdf`

## Non-Submission Root Artifacts

The following root-level files are documented as local-only and must not appear
as root entries in the submission bundle:

| Local root artifact | Reason it is excluded from the review bundle |
| --- | --- |
| `states_2018-05-28-14.csv` | Large raw upstream snapshot; the review bundle uses `sample_adsb_decoded.csv` plus provenance hashes instead. |
| `states_2022-06-27-23.csv` | Large raw upstream snapshot; excluded to keep the anonymous bundle compact and reviewable. |
| `zhong.py` | Historical local script outside the audited `adsb/`, `tools/`, and `tests/` entry points. |
| `lunwen.py` | Historical local manuscript/helper script outside the audited paper source. |
| `adsb.zip` | Historical local archive, not the current submission bundle. |
| `paper_lncs_bundle.zip` | Historical local archive, not the current submission bundle. |
| `result.txt` | Local scratch/result text outside the audited generated artifacts. |
| `test.py` | Local scratch script outside the audited test suite. |
| `11.txt` | Empty local scratch file. |

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_workspace_hygiene.ps1
```

Expected output includes:

- `workspace_hygiene=PASSED`
- `non_submission_artifacts_documented=9`
- `excluded_manifest_paths_checked=9`
- `entrypoints_checked=8`

## External Limit

This audit does not delete local files. It proves that the review bundle and
its manifest preserve a clean artifact boundary despite local development
material remaining in the working directory.

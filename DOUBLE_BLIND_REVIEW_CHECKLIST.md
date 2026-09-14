# CAT-AD Double-Blind Review Checklist

This checklist documents the local double-blind review checks for the CAT-AD
submission package. It does not replace a venue's official anonymity policy,
but it makes common identity leaks machine-checkable before submission.

## Reviewer-Facing Anonymity Requirements

- `paper_lncs/main.tex` must use `\author{Anonymous Authors}`.
- `paper_lncs/main.tex` must use `\institute{Anonymous Institution}`.
- The local preview HTML must expose `Anonymous Authors` as the author metadata.
- The manuscript source must not contain author emails, ORCID identifiers,
  `\thanks`, `\email`, `\orcid`, author-running headers, acknowledgments, or
  workstation paths.
- The generated submission bundle must include the same anonymous manuscript
  source and reviewer-facing README.
- The generated submission bundle must not expose the current workstation
  username, home directory, desktop project path, or conda environment path.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_double_blind_submission.ps1
```

Expected output includes:

- `double_blind_submission=PASSED`
- `manuscript_identity=PASSED`
- `preview_identity=PASSED`
- `bundle_identity=PASSED`

## Scope Boundary

The bibliography intentionally contains real author names from cited prior
work. Those names are not submission-identity leaks. The verifier therefore
checks manuscript metadata, local paths, contact macros, preview metadata, and
the generated bundle rather than forbidding all personal names in references.


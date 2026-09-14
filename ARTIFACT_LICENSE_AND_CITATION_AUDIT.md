# CAT-AD Artifact License and Citation Audit

This audit verifies that the anonymous review artifact has a clear use and
citation boundary. It avoids claiming a public open-source license on behalf of
the authors while still telling reviewers what they may do during confidential
artifact evaluation.

## Review-Use Boundary

`LICENSE` is an anonymous review artifact use statement. It permits local
inspection, no-download verification, benchmark checks, and confidential review
copying. It forbids public redistribution, live aviation-system use,
deanonymization, and representing the artifact as accepted, camera-ready,
certified-safe, or officially badged.

The statement deliberately says that the public release license remains an
author/deanonymized-artifact decision. This is a limitation, but it is safer
than silently omitting license information or inventing an open-source license
without author approval.

## Citation Boundary

`CITATION.cff` provides an anonymous review citation record:

- `cff-version: 1.2.0`
- title: `CAT-AD: Constrained Adversarial Training for Robust ADS-B Trajectory Anomaly Detection`
- author placeholder: `Anonymous Authors`
- version: `anonymous-review`
- date: `2026-07-05`

The citation message instructs reviewers to cite the final paper and public
artifact record after deanonymization or acceptance.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_artifact_license_citation.ps1
```

Expected output includes:

- `artifact_license_citation=PASSED`
- `license_markers_checked=12`
- `citation_markers_checked=8`
- `forbidden_claims_checked=8`

## External Limit

This audit does not grant a public open-source license. It makes the review-use
and citation boundary explicit until the authors choose a public release
license for a deanonymized artifact.

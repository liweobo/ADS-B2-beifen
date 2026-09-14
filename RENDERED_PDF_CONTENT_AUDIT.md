# CAT-AD Rendered PDF Content Audit

This audit verifies both manuscript PDFs as rendered artifacts, not only as
source files or HTML. It complements `MANUSCRIPT_REVIEWABILITY_AUDIT.md` and
`tools/verify_preview_artifact.ps1`.

## Source Evidence

- Preview HTML: `output/pdf/catad_submission_preview.html`
- Preview PDF: `output/pdf/catad_submission_preview.pdf`
- Formal LNCS PDF: `output/pdf/catad_submission_latex_updated.pdf`
- Poppler metadata/rendering tools: `pdfinfo` and `pdftoppm`
- Rendered page PNGs generated in owned temporary directories during verification

## Rendered-Artifact Checks

`tools/verify_rendered_pdf_content.ps1` checks that:

- the preview HTML contains review-critical markers for the title,
  contributions, method traceability, multi-seed result tables, PV-ASR,
  attack sanity checks, statistics, ethics, limitations, threats to validity,
  references, and all three official figure assets;
- the preview PDF is A4, unencrypted, and has exactly 11 pages;
- preview rendering produces exactly 11 PNG pages at `595 x 842` pixels;
- the formal LNCS PDF is unencrypted and has exactly 18 pages;
- formal rendering produces exactly 18 PNG pages at `612 x 792` pixels;
- every rendered page has enough non-white sampled pixels and dark sampled
  pixels to rule out blank or severely incomplete output;
- every rendered page has a nontrivial content bounding box and no content at
  the bitmap edge, guarding against clipping;
- rendered page files are large enough to catch obvious missing-content
  failures.

The formal build additionally fails when its TeX log contains an overfull
horizontal box, undefined citation, undefined reference, or LaTeX error.

## Boundary

This audit is a machine guardrail against blank, clipped, missing, or
incorrectly paginated output. Page-level PNG inspection was also performed for
the current 18-page LNCS artifact. Neither check proves peer-review acceptance
or compliance with a future venue's as-yet-unspecified page limit and policy.
In particular, it catches output that is blank, truncated, missing major content,
or clipped at a page boundary.

## Machine-Checked Guardrail

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_rendered_pdf_content.ps1
```

Expected output includes `rendered_pdf_content=PASSED`, `pages_checked=11`,
`formal_pages_checked=18`, `nonblank_pages_checked=11`, and
`formal_nonblank_pages_checked=18`.

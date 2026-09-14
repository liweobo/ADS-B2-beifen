# CAT-AD Manuscript Reviewability Audit

This audit checks that the anonymous manuscript has the structure and evidence
a reviewer needs. It does not claim venue acceptance or final portal-policy
compliance.

## Reviewability Boundary

The repository includes three manuscript-facing artifacts:

- `paper_lncs/main.tex`: formal source using the bundled official LNCS v2.24 class;
- `output/pdf/catad_submission_latex_updated.pdf`: formally compiled 18-page LNCS PDF;
- `output/pdf/catad_submission_preview.pdf`: 11-page A4 Pandoc/Chrome preview.

The reviewability verifier checks source structure, preview HTML, citation
closure, anonymity, placeholders, and preview metadata. Formal and preview PDFs
are rendered page by page by `tools/verify_rendered_pdf_content.ps1`.

## Checked Review Questions

| Review question | Local evidence |
| --- | --- |
| Is the manuscript anonymous? | `\author{Anonymous Authors}`, `\authorrunning{Anonymous Authors}`, `\institute{Anonymous Institution}`, and preview metadata. |
| Is the abstract bounded? | `\begin{abstract}...\end{abstract}` with a checked word count. |
| Are contributions explicit? | Exactly three introduction bullets covering CAT-AD, targeted anomalous-to-normal evaluation, and multi-seed reproducibility. |
| Are critical sections ordered? | Introduction, related work, method, experiments, results, physical feasibility, ablation, reproducibility, ethics, limitations, threats, conclusion, and references. |
| Are citations closed? | Every `\cite{...}` key resolves to `paper_lncs/references.bib`. |
| Are rendered artifacts plausible? | Preview and formal PDFs are unencrypted, page-count checked, nonblank, unclipped, and larger than placeholder PDFs. |
| Is the remaining boundary explicit? | Peer-review acceptance and venue-specific policy compliance remain external. |

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_manuscript_reviewability.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_rendered_pdf_content.ps1
```

Expected outputs include `manuscript_reviewability=PASSED`,
`contribution_items_checked=3`, `citations_checked=24`, `pdf_pages=11`, and
`formal_pages_checked=18`.

## External Limits

These checks prove local source/rendering integrity. They cannot prove
acceptance, compliance with an unspecified conference page limit, or final
camera-ready portal requirements.

# CAT-AD Formal PDF Build Audit

This audit records the formal LaTeX build path and the current verified LNCS
artifact. The HTML/Chrome PDF remains a review preview; it is not used as a
substitute for the formal manuscript.
The repository entry point is `tools/build_submission_pdf.ps1`.

## Formal LaTeX Build Entry Point

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build_submission_pdf.ps1
```

Successful output includes:

```text
formal_pdf_build=PASSED
latex_class=llncs
latex_log_quality=PASSED
overfull_hbox=0
undefined_citations=0
undefined_references=0
```

The build writes:

- `output/pdf/catad_submission_latex_updated.pdf`
- `output/pdf/catad_submission_latex_build.log`

## No-Download Boundary

The build helper itself does not download or install software. It uses a TeX
engine already available on `PATH`. On a machine without one, it reports
`formal_pdf_build=SKIPPED_NO_TEX_TOOL`; the already archived formal PDF and
source closure remain independently verifiable.

## Supported Engines

The helper supports `latexmk`, `tectonic`, or `pdflatex` plus `bibtex`. The
automatic order is latexmk, Tectonic, then pdflatex/BibTeX.

## Official Template Inputs

The source bundle includes the official Springer proceedings files:

- `paper_lncs/llncs.cls`, LNCS v2.24 (2024-01-29)
- `paper_lncs/splncs04.bst`
- `paper_lncs/SPRINGER_TEMPLATE_PROVENANCE.md`

Their official source URL and SHA-256 values are recorded in the provenance
document.

## Current Workstation Result

The manuscript was compiled with Tectonic 0.16.9 using the official LNCS v2.24
class. The pinned Windows Tectonic archive was verified with SHA-256
`131a24604785a9600989a3d91225f597df52ac06f00aeffe86fd529f99ee5cdd`.

Current artifact evidence:

- `formal_pdf_build=PASSED`
- `latex_class=llncs`
- `latex_log_quality=PASSED`
- 18 pages at 612 x 792 points
- 0 overfull horizontal boxes
- 0 undefined citations
- 0 undefined references
- all 17 rendered pages pass nonblank, content-box, and edge-clipping checks

The formal PDF was also inspected page by page after Poppler rendering. This
proves local build and rendering integrity, not peer-review acceptance or
compliance with a future venue's unspecified page limit.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_formal_pdf_build_readiness.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_rendered_pdf_content.ps1
```

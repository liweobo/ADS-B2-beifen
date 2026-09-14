This directory contains the Springer LNCS single-column LaTeX manuscript.

Main source:
  main.tex
  references.bib

Official Springer template files:
  llncs.cls (LNCS v2.24, 2024-01-29)
  splncs04.bst
  SPRINGER_TEMPLATE_PROVENANCE.md

Figure assets:
  ../figures/fig_main_robustness.pdf
  ../figures/fig_physical_valid_asr.pdf
  ../figures/fig_epsilon_sensitivity.pdf

Publication benchmark tables:
  ../outputs/publication_benchmark/aggregate_selected_summary.tex
  ../outputs/publication_benchmark/paired_comparisons.tex

Recommended compilation command from this directory:
  pdflatex -interaction=nonstopmode main.tex
  bibtex main
  pdflatex -interaction=nonstopmode main.tex
  pdflatex -interaction=nonstopmode main.tex

Formal build helper from the repository root:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build_submission_pdf.ps1

Formal output:
  output/pdf/catad_submission_latex_updated.pdf

Local preview command without TeX:
  powershell -NoProfile -ExecutionPolicy Bypass -File ..\tools\build_submission_preview_pdf.ps1

Preview output:
  ../output/pdf/catad_submission_preview.pdf

Formal build verified on current workstation:
  - Tectonic 0.16.9
  - official Springer LNCS v2.24 class
  - 17 pages at 612 x 792 points
  - no overfull horizontal boxes
  - no undefined citations or references

Notes:
  - main.tex prefers the bundled llncs.cls and retains an article fallback for
    source checks if the class is deliberately removed.
  - Run the strict publication benchmark before compiling so all generated
    multi-seed tables are current.
  - The preview PDF is for convenient review; the formal LNCS PDF is the
    submission-format artifact.
  - The build helper supports latexmk, Tectonic, or pdflatex plus BibTeX when
    one of those engines is available on PATH.
  - On a machine without a supported engine, the helper reports
    formal_pdf_build=SKIPPED_NO_TEX_TOOL without downloading software.

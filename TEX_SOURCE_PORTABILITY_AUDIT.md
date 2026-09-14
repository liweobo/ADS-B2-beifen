# CAT-AD TeX Source Portability Audit

This audit verifies that the manuscript source closure is portable,
self-contained in the submission bundle, and reproducibly connected to the
formal LNCS PDF.

## Formal PDF Boundary

- The no-download build helper does not install TeX, Tectonic, or BibTeX.
- The formal LNCS PDF has been built locally with Tectonic 0.16.9 and the
  official LNCS v2.24 class.
- Machines without a TeX/BibTeX toolchain can still verify the archived formal
  PDF, preview PDF, source closure, hashes, and rendered-page checks.
- Peer-review acceptance and venue-specific policy remain external outcomes.

## Source Closure

The manuscript references only local, repository-bundled inputs:

- `paper_lncs/main.tex`
- `paper_lncs/references.bib`
- `paper_lncs/llncs.cls`
- `paper_lncs/splncs04.bst`
- generated tables under `outputs/tables/`
- generated multi-seed tables under `outputs/publication_benchmark/`
- generated figures under `figures/`
- `output/pdf/catad_submission_latex_updated.pdf`
- `output/pdf/catad_submission_preview.pdf`

All cited keys in `main.tex` have BibTeX entries, and all current BibTeX entries
are cited by the manuscript.

## Portability Checks

`tools/verify_tex_source_portability.ps1` checks:

- all `\input` and `\maybeinput` targets resolve from `paper_lncs/`;
- all three `\includegraphics` targets resolve through `\graphicspath`;
- no source file contains absolute workstation paths, home-directory paths,
  remote input URLs, or shell-escape commands;
- the bibliography has unique keys, DOI metadata, and a one-to-one citation
  mapping for the current manuscript;
- the official LNCS class, bibliography style, and template provenance are
  present and hash-verifiable;
- `paper_lncs/README_compile.txt` documents both the standard pdflatex/BibTeX
  path and the verified formal build helper.

## Bundle Checks

When a bundle or extracted manifest is present, the verifier checks that the
TeX source, bibliography, official style files, figures, generated tables,
formal and preview PDFs, audit documents, and verifier scripts are present.
This prevents a locally valid paper from being packaged without a compile-time
input or the reviewed formal artifact.

## Current Status

The TeX source portability check, formal build, TeX log quality, and rendered
18-page LNCS PDF are locally verified. Conference acceptance and the final
venue's page-limit decision are not locally provable.

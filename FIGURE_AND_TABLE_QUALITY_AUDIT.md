# CAT-AD Figure and Table Quality Audit

This audit locks the manuscript-facing visual presentation to a readable,
traceable, and print-safe boundary. It follows the Springer proceedings
requirements that illustrations be clear and legible, figure lettering remain
readable, vector graphics be preferred, tables remain editable, captions and
cross-references be present, and figures remain distinguishable in grayscale.

## Manuscript Inventory

The paper contains eight tables and two numbered figure environments. The
second numbered figure contains three explicitly named panels, so the complete
visual inventory is three vector figure files and eight editable LaTeX tables.

## Locked Quality Boundary

- Manuscript tables use `\small` or `\footnotesize`, booktabs rules, and no
  `\resizebox` or `\scriptsize` shrinking.
- Figure 1 and Fig. 2(a) use five-run means with unbounded 95% Student-t
  confidence intervals and machine-readable source CSV files.
- Figure 1 and the two epsilon panels use generator-side font compensation so
  final LNCS scaling keeps figure lettering at or above 6 pt.
- Bars use distinct hatches; sensitivity curves use distinct line styles and
  markers so model identity does not depend on color.
- The epsilon-sensitivity panels display the complete F1 range from 0 to 1;
  low BiLSTM-ERM values are not clipped.
- Every paper figure is included as vector PDF and also exported as SVG and PNG
  for inspection and preview generation.
- The two single-run summary tables removed from the manuscript remain archived
  as auxiliary CSV/TeX exports; no underlying result evidence is deleted.

## Verification

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_figure_and_table_quality.ps1
```

The verifier checks the complete inventory, font/scaling boundary, vector
artifacts, grayscale encodings, confidence-interval sources, panel labels, and
the full epsilon-axis range. Pixel-level layout is then checked by rendering the
formal PDF to page images under `tmp/pdfs`.

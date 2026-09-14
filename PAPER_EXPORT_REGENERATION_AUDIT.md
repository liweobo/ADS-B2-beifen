# CAT-AD Paper Export Regeneration Audit

This audit verifies that paper-facing tables and figure sources can be
regenerated from archived local result CSV files without training models or
running new attacks. It complements the figure-source consistency audit by
checking the regeneration command itself.

## Regeneration Boundary

The regeneration command is:

```powershell
conda run --no-capture-output -n testtorch python tools\regenerate_paper_exports.py
```

The `--no-capture-output` form is intentional on Windows: it keeps Conda from
re-encoding captured stdout through a legacy console code page. The script
prints repository-relative paths and does not download packages or data.

## Deterministic Outputs

`tools/verify_paper_export_regeneration.ps1` runs the regeneration command and
then verifies byte-stable hashes for:

- paper-facing CSV and TeX tables under `outputs/tables/`, including compact
  multi-seed and paired-comparison tables regenerated from archived benchmark CSVs;
- `outputs/test_set_results.csv`;
- figure source CSV files under `results/`;
- PNG variants of the three official manuscript figures.

PDF and SVG figure variants are regenerated and checked for existence by the
figure-source and TeX-portability verifiers, but their bytes are not treated as
the determinism oracle because common plotting backends may rewrite metadata or
object identifiers.

## Current Status

The paper export regeneration check is locally verifiable and is run before the
preview PDF and submission bundle are rebuilt. The generated bundle therefore
contains the freshly regenerated tables, figure source CSVs, and figure assets.

# CAT-AD Seed-Direction Consistency Audit

This audit checks whether the six primary CAT-AD claims are supported by every
paired seed, rather than by a mean value dominated by one or two favorable runs.

## Primary Claims Checked

The audit covers the same six primary claims listed in
`NUMERIC_CLAIMS_LEDGER.md`:

| Claim | Setting | Metric | Direction |
| --- | --- | --- | --- |
| Unperturbed detection is not reduced | `Clean` (archive key) | `f1` | CAT-AD minus BiLSTM-ERM is positive |
| Norm-bounded PGD ASR is reduced | `Standard PGD` (archive key) | `asr` | BiLSTM-ERM minus CAT-AD is positive |
| Projection Phys-PGD ASR is reduced | `Projection-based phys-PGD` (archive key) | `asr` | BiLSTM-ERM minus CAT-AD is positive |
| Penalty Phys-PGD ASR is reduced | `Penalty-based phys-PGD` (archive key) | `asr` | BiLSTM-ERM minus CAT-AD is positive |
| Projection Phys-PGD PV-ASR is reduced | `Projection-based phys-PGD` (archive key) | `pv_asr` | BiLSTM-ERM minus CAT-AD is positive |
| Penalty Phys-PGD PV-ASR is reduced | `Penalty-based phys-PGD` (archive key) | `pv_asr` | BiLSTM-ERM minus CAT-AD is positive |

For each claim, `tools/verify_seed_direction_consistency.ps1` recomputes the
paired seed differences directly from
`outputs/publication_benchmark/per_seed_metrics_wide.csv` and requires all five
seeds `42,43,44,45,46` to have positive improvement in the claim direction.

The same per-seed recomputation is exposed as reviewer-facing generated
artifacts:

- `outputs/publication_benchmark/primary_seed_direction_summary.csv`
- `outputs/publication_benchmark/primary_seed_direction_summary.tex`

These files report, for each primary claim, the seed count, positive seed count,
minimum seed-level improvement, median improvement, mean improvement,
confidence-interval bounds inherited from `paired_comparisons.csv`, and the
five seed-level improvement values.

## Evidence Boundary

This audit strengthens the interpretation of the five-seed paired comparison:
the headline claim directions are not caused by a single outlying seed. It does
not turn five seeds into conclusive hypothesis-test evidence, and it does not
claim that every metric, auxiliary ablation, or future dataset improves.

The verifier also cross-checks the six paired-comparison rows in
`outputs/publication_benchmark/paired_comparisons.csv` for `n=5`,
`win_rate=1.0`, `tie_rate=0.0`, and the expected seed list. It also checks that
`primary_seed_direction_summary.csv` and
`primary_seed_direction_summary.tex` exactly match the recomputed values, so the
review table cannot drift from the underlying per-seed metric rows.

## Expected Output

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_seed_direction_consistency.ps1
```

Expected output includes:

- `seed_direction_consistency=PASSED`
- `primary_claims_checked=6`
- `seed_pairs_checked=30`
- `paired_rows_checked=6`
- `summary_csv_rows_checked=6`
- `summary_tex_markers_checked=7`
- `paper_markers_checked=3`

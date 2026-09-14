# CAT-AD Statistical Interpretation Checklist

This checklist records how the paper should interpret the multi-seed paired
comparison table. The goal is to make the statistical claims defensible without
overstating hypothesis-test evidence from five seeds.

## Interpretation Boundary

- The primary claims are directional, artifact-checked improvements under the
  evaluated seeds and threat model.
- The paired table reports effect sizes, confidence intervals, exact sign-flip
  p-values, Holm-adjusted p-values, and BH q-values.
- With five seeds, exact sign-flip p-values are coarse and conservative.
- The manuscript should emphasize effect sizes, confidence intervals, win
  rates, and reproducible paired differences rather than claiming conclusive
  hypothesis-test evidence.
- The manuscript should not claim "statistically significant" improvements
  unless a future revision adds a larger seed count or a different preregistered
  statistical protocol.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_statistical_interpretation.ps1
```

Expected output includes:

- `statistical_interpretation=PASSED`
- `paired_rows_checked=12`
- `effect_size_rows_checked=12`


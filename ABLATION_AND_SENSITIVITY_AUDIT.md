# CAT-AD Ablation and Sensitivity Audit

This audit records how the auxiliary ablation table and perturbation-budget
sensitivity figure support the CAT-AD design. These artifacts complement the
five-seed publication benchmark; they do not replace the multi-seed primary
claims in `outputs/publication_benchmark/verification_report.md`.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_ablation_sensitivity.ps1
```

Expected output includes:

```text
ablation_sensitivity=PASSED
ablation_variants_checked=8
epsilon_rows_checked=24
```

## Evidence Boundary

- The ablation table is generated from `outputs/ablation_table5/` and rendered
  as `outputs/tables/table5_ablation_study.tex`.
- The source CSV for the table is `outputs/tables/table5_ablation_study.csv`.
- The summary JSON is `outputs/ablation_table5/ablation_table5_summary.json`.
- The perturbation-budget sensitivity source CSV is
  `results/fig_epsilon_sensitivity_data.csv`.
- The rendered figure artifacts are `figures/fig_epsilon_sensitivity.pdf`,
  `figures/fig_epsilon_sensitivity.png`, and
  `figures/fig_epsilon_sensitivity.svg`.

## What The Checks Establish

The verifier checks that:

- Eight ablation variants are present: ERM, PGD-AT, projection Phys-PGD-AT,
  penalty Phys-PGD-AT, prediction consistency, feature consistency, CAT-AD, and
  CAT-AD without differential trajectory features.
- The ablation CSV and summary JSON agree on the displayed table values.
- ERM is vulnerable under physically constrained attacks, while CAT-AD keeps
  high F1-score and low FAR in the ablation setting.
- The no-differential-feature variant has unacceptable FAR, so low ASR is not
  counted as a valid robustness gain.
- The epsilon-sensitivity CSV contains two attacks, six perturbation budgets,
  two models, and 24 total rows.
- CAT-AD remains stable across the evaluated epsilon range, whereas the
BiLSTM-ERM drops sharply under both physically constrained attacks.

## Interpretation Guardrail

The ablation and sensitivity artifacts are auxiliary design evidence. The paper
therefore phrases them as trade-off and stability support, not as independent
proof of universal robustness. The primary quantitative claims remain the
multi-seed paired comparisons checked by the strict publication gate.

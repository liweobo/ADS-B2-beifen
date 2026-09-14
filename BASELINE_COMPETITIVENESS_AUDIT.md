# CAT-AD Baseline Competitiveness Audit

This audit records how the artifact addresses the top-conference risk that the
main comparison only uses an easy ERM baseline. It separates the five-seed
primary benchmark from the auxiliary single-seed baseline/ablation table.

## Evidence Boundary

The five-seed primary benchmark compares BiLSTM-ERM against CAT-AD under a
strict paired protocol. The auxiliary ablation table additionally includes
stronger adversarial-training baselines:

- `ERM`
- `PGD-AT`
- `Projection Phys-PGD-AT`
- `Penalty Phys-PGD-AT`
- `+Prediction Consistency`
- `+Feature Consistency`
- `CAT-AD`
- `CAT-AD w/o $\Delta X$`

The ablation table is not treated as a replacement for multi-seed primary
claims. It is used to show that CAT-AD is evaluated next to stronger training
baselines and that the final method is a balanced design rather than an
unconditional winner on every single metric.

## What The Checks Establish

`tools/verify_baseline_competitiveness.ps1` checks that:

- the ablation table contains adversarial-training baselines beyond ERM;
- `PGD-AT`, `Projection Phys-PGD-AT`, and `Penalty Phys-PGD-AT` achieve strong
  robust F1 scores, so they are not weak straw baselines;
- `Penalty Phys-PGD-AT` exposes that physical adversarial training alone can be
  very strong in the single-seed table;
- the manuscript describes the table as a trade-off and baseline-strength
  analysis, not as evidence that CAT-AD dominates every metric;
- the no-differential-feature variant remains visible as a negative result.

## Interpretation Guardrail

The defensible claim is not "CAT-AD beats every baseline in every metric." The
defensible claim is that CAT-AD combines physically constrained adversarial
training, output/representation consistency, exact PV-ASR evaluation, and a
multi-seed publication gate, while the auxiliary table demonstrates that the
method is compared against strong adversarial-training variants and that design
trade-offs are visible.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_baseline_competitiveness.ps1
```

Expected output includes:

- `baseline_competitiveness=PASSED`
- `strong_training_baselines_checked=3`
- `ablation_variants_checked=8`

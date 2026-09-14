# CAT-AD Attack Evaluation Sanity Checklist

This checklist records the local sanity checks used to reduce common robustness
evaluation risks, especially weak attacks and accidental gradient masking.
It is not a formal robustness certificate and it does not claim coverage of all
adaptive attackers.

## Sanity Checks

- The manuscript discusses strong-attack evaluation and cites robustness
  evaluation warnings from Carlini and Wagner plus Athalye et al.
- The attack implementation freezes dropout during PGD gradient computation to
  reduce stochastic gradient confusion.
- The attack objective is targeted anomalous-to-normal evasion with
  `target_label=0`.
- Attacks are applied to malicious/anomalous windows only; normal windows are
  preserved by the attack wrapper.
- The evaluated attack suite includes Norm-bounded PGD, Projection-based
  Phys-PGD, and Penalty-based Phys-PGD.
- Baseline digital ASR is high, and baseline PV-ASR conditioned on valid starts
  exceeds 0.80 under both physically constrained attack families.
- Projection-based Phys-PGD is hard-projected after every update; benchmark and
  unit-test checks require zero attack-introduced physical violations.
- The high baseline conditional attack success shows that physical projection
  has not made the attacks trivially weak.
- Unit tests cover targeted PGD direction, anomalous-only attack application,
  multi-step target-margin strengthening, dropout/LSTM-dropout attack-gradient
  context restoration, projection-path plumbing, penalty-attack diagnostics,
  perturbation budget bounds, hard-projection feasibility, paired pre/post
  metrics, ASR, and exact conditional PV-ASR.
- `ADAPTIVE_ATTACK_AUDIT.md` records the weak-attack and gradient-masking risk
  model, local tests, and current multi-seed attack-strength signals.
- The manuscript explicitly says the result is not a formal robustness certificate and is
  limited to the evaluated perturbation budgets and attack families.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_evaluation_sanity.ps1
```

Expected output includes:

- `attack_evaluation_sanity=PASSED`
- `attack_code_markers_checked=8`
- `attack_test_markers_checked=9`
- `attack_metric_rows_checked=6`
- `adaptive_attack_markers_checked=8`

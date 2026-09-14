# CAT-AD Adaptive-Attack Audit

This audit records the evidence used to reduce weak-attack and gradient-masking
review risks. It is not a formal robustness certificate and does not claim
security against every adaptive attacker.

## Risk Model

Top-tier robustness reviews commonly ask whether a defense only appears strong
because the attack is weak, stochastic, incorrectly targeted, or blocked by
implementation details. CAT-AD addresses this as an empirical audit question:
the repository must show that attack gradients are usable, attacks target the
operational anomalous-to-normal evasion goal, and the baseline detector is
vulnerable under the evaluated attacks.

## Evidence Checks

| Risk | Evidence |
| --- | --- |
| Wrong attack objective | `adsb/attacks.py` defaults to `targeted=True` and `target_label=0`; `tests/test_physical_metrics.py` checks targeted normal-direction behavior. |
| Normal samples accidentally attacked | `apply_pgd_malicious_only` only attacks `y==1`; `test_apply_pgd_malicious_only_preserves_normal_samples` verifies normal windows are unchanged. |
| Single-step-only sanity | `test_default_pgd_multistep_strengthens_target_margin_until_budget` verifies multi-step PGD further increases the normal-target margin until the L-infinity budget is reached on a deterministic model. |
| Stochastic gradient confusion | `_attack_grad_context` freezes `nn.Dropout` modules and sets LSTM dropout to zero during attack-gradient computation; `test_attack_grad_context_freezes_and_restores_dropout_state` verifies both freezing and restoration. |
| Projection path not used | `test_pgd_phys_projection_path_invokes_physical_projection` checks projection-based Phys-PGD actually calls the physical projection component. |
| Penalty attack lacks diagnostics | `test_pgd_phys_penalty_returns_diagnostics_and_respects_linf_budget` verifies penalty diagnostics and perturbation-budget bounds. |
| Attack too weak overall | The strict benchmark reports high BiLSTM-ERM ASR under Norm-bounded PGD, Projection-based Phys-PGD, and Penalty-based Phys-PGD before CAT-AD defense. |
| Metric overstatement | `test_pv_asr_is_exact_per_sample_not_product_approximation` verifies PV-ASR is exact per sample rather than ASR multiplied by physical validity rate. |

## Current Empirical Attack-Strength Signals

The multi-seed benchmark reports the following baseline attack-success rates
for BiLSTM-ERM:

- Norm-bounded PGD ASR: `0.9878`
- Projection-based Phys-PGD ASR: `0.9563`
- Penalty-based Phys-PGD ASR: `0.9178`

These high baseline ASR values are sanity evidence that the evaluated attacks
are capable of finding evasions in the tested threat model. CAT-AD's lower ASR
and PV-ASR should still be interpreted empirically, not as certified
robustness.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_evaluation_sanity.ps1
```

Expected output includes:

- `attack_evaluation_sanity=PASSED`
- `adaptive_attack_markers_checked=8`
- `attack_test_markers_checked=9`

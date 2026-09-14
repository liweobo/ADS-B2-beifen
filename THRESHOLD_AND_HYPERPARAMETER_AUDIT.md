# CAT-AD Threshold and Hyperparameter Audit

This audit records the boundary between validation-time model selection and
test-time reporting. It is intended to make a common review concern explicit:
test metrics must not be inflated by choosing thresholds or hyperparameters on
the test set.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_threshold_hyperparameter_audit.ps1
```

Expected output includes:

```text
threshold_hyperparameter_audit=PASSED
run_records_checked=5
threshold_records_checked=10
hyperparameters_checked=12
```

## Validation-Only Threshold Boundary

The main experiment selects detector thresholds with
`pick_best_threshold(..., pack.val_loader)` and then evaluates all clean and
adversarial test settings with the fixed threshold values. Per-seed
`run_record.json` files store the selected thresholds and validation F1 scores
so that the threshold source can be audited after the benchmark finishes.

## Fixed Hyperparameter Boundary

The publication benchmark manifest records the effective hyperparameter
snapshot from `adsb/train_constants.py`. The verifier checks the core
configuration used by the reported benchmark, including the train/validation
split fractions, window size, epochs, optimizer learning rate, adversarial
training budget, evaluation budget, PGD step size/steps, consistency weights,
physical penalty weights, and threshold grid size.

## Leakage Guardrail

This audit complements the data split audit. It checks that aircraft-level
train/validation/test overlap is zero in every per-seed run record and that
threshold selection is represented as validation-based rather than test-based.
If future changes tune thresholds, hyperparameters, or early stopping against
test metrics, this audit should fail and the quantitative claims should not be
used for submission until the benchmark is rerun with a clean protocol.

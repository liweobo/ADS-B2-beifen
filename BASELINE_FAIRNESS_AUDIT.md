# CAT-AD Baseline-Fairness Audit

This audit records the fairness boundary for comparing BiLSTM-ERM
baseline against CAT-AD. The purpose is to make the comparison defensible for
review: CAT-AD should win because of the training protocol, not because it uses
different data, a different architecture, a different thresholding rule, or a
different test set.

## Fair Comparison Boundary

The audited comparison uses:

- the same decoded ADS-B CSV and the same aircraft-level split for both models;
- the same BiLSTM detector constructor and architecture;
- the same train and validation loaders for baseline and CAT-AD training;
- the same common optimizer schedule, epoch count, learning rate, AMP setting,
  and early-stopping configuration passed through `train_common_kwargs`;
- the same validation-only threshold-selection protocol for both models;
- the same test loaders, target-label convention, and attack settings for both
  models;
- paired seed-wise comparisons between Baseline and Proposed rows.

CAT-AD adds physically constrained adversarial training and consistency losses.
Those additions are the intervention under test; the audit therefore does not
require the baseline to receive adversarial samples.

## Evidence In The Repository

- `adsb/experiment.py` creates `m1 = make_detector(device)` and
  `m2 = make_detector(device)`, then trains both models from the same
  `pack.train_loader` and `pack.val_loader`.
- `adsb/train_constants.py` records identical class weights for the clean
  baseline and CAT-AD cross-entropy terms.
- `adsb/training.py` uses the same optimizer family and scheduler structure in
  `train_with_val` and `train_adv_with_val`.
- `outputs/publication_benchmark/runs/seed_*/run_record.json` stores the shared
  split summary, validation thresholds, and validation F1 values for every
  seed.
- `outputs/publication_benchmark/per_seed_metrics_long.csv` stores paired
  Baseline and Proposed metric rows for every seed, setting, and metric.
- `outputs/publication_benchmark/paired_comparisons.csv` computes paired
  seed-wise comparisons from those rows.

## Machine-Checked Guardrail

`tools/verify_baseline_fairness.ps1` checks the code markers, manifest
metadata, per-seed run records, metric-row pairing, and manuscript fairness
wording. If future edits change the baseline architecture, split protocol,
threshold protocol, class weights, or paired-row structure, this audit should
fail until the manuscript and experiments are reconciled.

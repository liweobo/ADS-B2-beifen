# CAT-AD Paired Physical-Metric Semantics Audit

This audit fixes the meaning of physical feasibility across the paper, code,
tests, tables, and five-seed benchmark.

## Paired Sample-Level Definitions

Let A be the attacked anomalous sample set. For each sample i:

- s_i is one when the perturbed sample is classified as normal;
- v_i^0 is one when the source trajectory violates an audited constraint;
- v_i^1 is one when the perturbed trajectory violates an audited constraint;
- V0 is the subset with v_i^0 equal to zero.

The primary physical metrics are:

- start-valid rate = |V0| / |A|;
- Pre-PVR = mean of v_i^0 over A;
- Post-PVR = mean of v_i^1 over A;
- New-PVR given V0 = mean of v_i^1 over V0;
- ASR given V0 = mean of s_i over V0;
- PV-ASR given V0 = mean of s_i times (1 - v_i^1) over V0.

PV-ASR given V0 is an exact per-sample intersection. It is not estimated as a
product of aggregate rates. Conditioning prevents invalid source trajectories
from being credited as attack-introduced violations.

## Executable Evidence

- paper_lncs/main.tex states the paired definitions and valid-start denominator.
- adsb/training.py records pre/post flags and all conditional metrics.
- adsb/attacks.py implements hard displacement limits and trajectory-level
  feasibility flags.
- tests/test_physical_metrics.py checks hard projection, paired metrics, empty
  valid-start behavior, targeted ASR, and exact conditional PV-ASR.
- outputs/publication_benchmark/per_seed_metrics_long.csv contains all five
  seeds and is checked for identities, bounds, coverage, and attack strength.
- outputs/tables/table_physical_feasibility.csv and
  results/fig_physical_valid_asr_data.csv are regenerated from seed 42 without
  passing through rounded legacy results.

## Expected Output

Run tools/verify_physical_metric_semantics.ps1. Expected output includes:

- physical_metric_semantics=PASSED
- benchmark_groups_checked=20
- projection_zero_new_violation_groups=10
- physical_table_rows_checked=6
- figure_rows_checked=6

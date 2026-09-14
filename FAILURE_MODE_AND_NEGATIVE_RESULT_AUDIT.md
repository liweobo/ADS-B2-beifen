# CAT-AD Failure-Mode and Negative-Result Audit

This audit records result boundaries that should remain visible in a
top-conference submission. It is designed to reduce selective-reporting risk:
the paper should show what CAT-AD improves, what it does not claim to improve,
and which observed failure modes constrain the interpretation.

## Non-Claim Boundary

CAT-AD is not claimed to solve all ADS-B robustness problems. The supported
claim is narrower: under the evaluated targeted anomalous-to-normal evasion
threat model, CAT-AD reduces ASR and PV-ASR while preserving clean F1.

The following are explicitly not claimed:

- CAT-AD is not a formal robustness certificate.
- CAT-AD is not an aviation-safety certificate.
- CAT-AD is not claimed to generalize to every airspace, time period, sensor
  network, perturbation budget, or adaptive attacker.
- CAT-AD is not claimed to improve every metric in the paired comparison table.
- Physical violation rate (PVR) is reported as a diagnostic, not as a primary
  improvement claim. PVR is reported as a diagnostic boundary for interpreting
  physical validity, not as a CAT-AD superiority claim.

## Negative Results That Must Stay Visible

1. The ablation variant without differential trajectory features fails as a
   useful detector despite low attack-success numbers. In
   `outputs/tables/table5_ablation_study.csv`, `CAT-AD w/o Delta X` has
   unperturbed F1 below `0.50` and FAR above `0.90`. This prevents the paper
   from treating low ASR as sufficient evidence of robustness.
2. The paired New-PVR given V0 rows are feasibility diagnostics, not primary
   CAT-AD improvement evidence. Projection is tied at zero and the penalty
   difference is negligible; neither row is Holm- or BH-significant.
3. The five-seed exact sign-flip p-values are intentionally interpreted
   conservatively. The manuscript emphasizes effect sizes, confidence
   intervals, and win rates rather than claiming decisive null-hypothesis
   significance.
4. The physical constraints are experimental kinematic proxies over decoded
   ADS-B trajectory variables. They do not prove operational safety or complete
   aircraft-dynamics validity.

## Why This Matters

Top-tier robustness reviews often look for cherry-picked metrics, hidden
failure cases, or inflated claims from weak evidence. This audit keeps the
negative and non-claimed parts attached to the submission package:

- the failure-mode ablation guards against a degenerate low-ASR detector;
- the paired New-PVR boundary prevents conflating robustness with a
  physical-validity-rate improvement;
- the statistical boundary prevents overclaiming five-seed sign-flip tests;
- the construct-validity boundary prevents treating PV-ASR as a certificate.

## Machine-Checked Evidence

`tools/verify_failure_mode_negative_results.ps1` checks:

- this document contains the non-claim and negative-result boundaries;
- the manuscript states the certificate, external-validity, ASR/PV-ASR, and
  PVR interpretation limits;
- the ablation CSV contains the `CAT-AD w/o Delta X` failure mode with low F1
  and high FAR;
- the paired New-PVR rows remain negligible diagnostic evidence rather than
  primary claim evidence;
- no Holm/BH significance flag is used to overstate the five-seed paired
  comparisons.

If any of these boundaries disappear, the submission audit should fail until
the manuscript and evidence are reconciled.

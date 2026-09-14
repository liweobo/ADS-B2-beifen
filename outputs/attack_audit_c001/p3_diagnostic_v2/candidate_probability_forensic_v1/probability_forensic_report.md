# C0-01 P3-Diagnostic v2 Candidate Probability Integrity Forensic Audit

## 1. Scope

- Canonical root: `E:\ads-b\ADS-B2 -beifen`
- New attacks executed: NO
- Margin/CW rerun: NO
- CE rerun: NO
- Threshold checker modified: NO
- Raw modified: NO
- Reaggregation executed: NO

This audit diagnoses only the historical `class_probability_sum` integrity failure. It does not interpret loss outcomes or alter any prior forensic history.

## 2. Original class_probability_sum Checker

- Source: `outputs/attack_audit_c001/p3_diagnostic_v2/threshold_precision_forensic_v1/forensic_driver.py`, function `scan_rows`, line 588
- Exact expression: `counters["class_probability_sum_failure"] += int((np.abs((p64 + pnormal) - 1.0) > 2e-8).sum())`
- Effective rule: `abs(float64(parsed p_anomaly) + float64(parsed p_normal) - 1.0) > 2e-8`
- Dtype: NumPy `float64` after pandas decimal parsing
- Equality/tolerance: strict `>` against the immutable historical tolerance `2e-8`; no exact equality, `np.isclose`, or `math.isclose`
- Probability fields: `p_normal`, `p_anomaly`
- Class mapping: normal = 0; anomaly = 1

The checker was not modified and no replacement tolerance was introduced.

## 3. Runtime Probability Semantics

- Logits dtype: `torch.float32`
- Softmax dtype: `torch.float32`
- Classes: 2
- Normal index: 0
- Anomaly index: 1
- Autocast: disabled by `_fp32_eval_mode`
- Runtime path: `model(packed.float())` followed by `torch.softmax(logits, dim=1)`
- Probability extraction: `probabilities[:, 0]` and `probabilities[:, 1]` from the same softmax tensor
- Archive path: each tensor field is exported with `.detach().cpu().tolist()` and written to gzip CSV
- Serialization precision: finite Python floats are formatted with `.9g`

The selected-candidate NPZ files contain anomaly-probability arrays but no complete paired per-step `p_normal`/`p_anomaly` binary representation. Therefore representation C and logit replay are `NOT AVAILABLE`; this is not treated as a failure.

## 4. Failure Scale

- Total rows: 101,761,920
- Original checker failures: 65,934,165
- Failure rate: 0.6479257172034489 (64.79257172034489%)
- Margin failures: 32,752,702
- CW failures: 33,181,463
- ERM failures: 32,621,712
- CAT-AD failures: 33,312,453
- Maximum absolute archived-sum error: 8.968999998248961e-08
- Median: 2.9999999928698173e-08
- 95th percentile: 6.329700008578243e-08
- 99th percentile: 7.694000014879521e-08
- 99.9th percentile: 8.526600003833096e-08

Counts by attack family, K, split, and all 160 loss/model/attack/K/split tasks are recorded in `probability_sum_summary.csv`. These are integrity counts, not comparative loss-performance interpretations.

## 5. Probability Validity

- NaN: 0
- Positive infinity: 0
- Negative infinity: 0
- `p_normal < 0`: 0
- `p_anomaly < 0`: 0
- `p_normal > 1`: 0
- `p_anomaly > 1`: 0
- Class-alignment anomalies: 0
- Serialization-roundtrip unexplained mismatches: 0
- Raw-artifact failures: 0

All 101,761,920 pairs were finite and in range. The anomaly-only file contains only its header because no alignment anomaly was found.

## 6. Representation Comparison

Representation A parses the archived `.9g` decimal fields into `float64` and sums them in `float64`; this is the historical checker domain and produces 65,934,165 failures.

Representation B casts both archived fields back to `float32`. Its `float32` sum is exactly one on 79,420,386 rows and nonunit on 22,341,534 rows. When the two restored FP32 values are separately promoted and summed in `float64`, 65,967,643 rows exceed the historical `2e-8` criterion. These representation counts demonstrate that exact or near-exact unity depends on the precision domain used for reconstruction and summation.

The explicit all-row validation applied `archived decimal -> float32 -> .9g text -> float32` and compared `uint32` bit patterns. All 203,523,840 probability values across 101,761,920 rows round-tripped exactly; `p_normal` mismatches = 0 and `p_anomaly` mismatches = 0. The supported claim is `ROUNDTRIP REPRESENTATION CONSISTENT`, not `BITWISE ORIGINAL VERIFIED`, because the paired original binary per-step representation was not archived.

Representation C is `NOT AVAILABLE` for complete paired per-step probabilities and is not counted as a failure.

## 7. Failed-Row Explanation

- P1 finite-precision representation effect plus P3 checker mismatch: 65,847,578 rows
- P2 serialization sum-reconstruction effect plus P3 checker mismatch: 86,587 rows
- Checker-specification failure rows: 65,934,165
- Total explained failures: 65,934,165
- Unexplained failures: 0
- True raw inconsistencies: 0

The two classified populations are disjoint and sum exactly to the original checker-failure count. Detailed failed-row evidence is in `probability_sum_failed_rows.parquet`; the control artifact contains 4,000 rows covering pass-near-one, larger-pass-error, near-boundary, and failed strata for both losses.

## 8. Root Cause

`P7_MULTIPLE_CAUSES`.

The contributing causes are `P1_FLOAT32_SOFTMAX_SUM_REPRESENTATION_EFFECT`, `P2_SERIALIZATION_SUM_RECONSTRUCTION_EFFECT`, and `P3_CHECKER_SPECIFICATION_MISMATCH`. All failed rows are explained by verified finite-precision/serialization behavior combined with the historical checker semantics; none requires P4 class misalignment, P5 invalid probability values, or P6 raw corruption.

## 9. Raw Candidate Identity Reconsideration

- RC1 source identity preserved: PASS
- RC2 all failed-row raw artifacts readable: PASS
- RC3 failed-row artifact identities consistent: PASS
- RC4 class-alignment anomalies = 0: PASS
- RC5 NaN/Inf = 0: PASS
- RC6 probability outside [0,1] = 0: PASS
- RC7 serialization round-trip has no unexplained mismatch: PASS
- RC8 every `class_probability_sum` failure is explained: PASS
- RC9 unexplained probability-pair inconsistencies = 0: PASS
- RC10 no evidence of raw corruption: PASS

`RAW_CANDIDATE_IDENTITY_RECONSIDERATION = PASS`

The identity check covers all 160 unique failed/control tasks, rehashes each in-scope candidate NPZ once, validates recorded sizes and SHA-256 identities, performs ZIP CRC reads, validates task identities, and confirms complete gzip stream readability and ledger row counts. It does not rehash the entire P3 raw tree.

## 10. RA2 / RA8

- Original RA2: FAIL
- Reconsidered RA2: PASS
- Original RA8: FAIL
- Reconsidered RA8: PASS

The reconsideration is based on the new probability-forensic evidence. The historical `threshold_precision_forensic_v1` artifacts remain unchanged. Prior RA1, RA3-RA7, and RA9-RA15 remain PASS in the existing repair criteria and were not rerun.

## 11. Threshold Repair Status

`READY FOR THRESHOLD REPAIR REAUTHORIZATION`

No threshold repair, checker modification, or reaggregation was performed in this audit.

## 12. Research Status

- Restart saturation: NOT ESTABLISHED
- Attack adequacy: NOT ESTABLISHED
- Formal P3 clearance: DENIED
- P3-Diagnostic v2 formal integrity: FAIL
- Robustness claims: SUSPENDED

These statuses are unchanged. This forensic outcome does not restore a robustness claim or grant formal P3 clearance.

## 13. Stop Confirmation

- No attack was executed.
- Margin/CW were not rerun.
- CE was not rerun.
- No threshold checker was modified.
- No raw artifact was modified.
- No archived probability was modified.
- No arbitrary tolerance was introduced.
- No reaggregation was executed.
- No loss result was interpreted.
- No failed evidence was deleted.
- No project-wide archive or backup was created.
- No project-wide hash verification was performed.
- P4-P6 were not executed.
- The manuscript was not modified.

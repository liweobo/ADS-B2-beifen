# CAT-AD Numeric Claims Ledger

This ledger binds every headline number in the manuscript to the corrected
five-seed benchmark. Physical claims are conditioned on anomalous trajectories
that satisfy every audited constraint before perturbation (V0).

## Source Artifacts

- Strict gate report: outputs/publication_benchmark/verification_report.md
- Paired comparisons: outputs/publication_benchmark/paired_comparisons.csv
- Paper multi-seed summary: outputs/tables/table_multiseed_summary.tex
- Full aggregate summary: outputs/publication_benchmark/aggregate_summary.csv
- Benchmark provenance: outputs/publication_benchmark/benchmark_manifest.json

## Primary Claim Values

| Claim | Setting | Metric | Direction | Mean improvement | Source |
| --- | --- | --- | --- | ---: | --- |
| Unperturbed detection is not reduced | Clean (archive key) | f1 | higher is better | 0.02958602649106081 | paired_comparisons.csv |
| Digital PGD ASR is reduced | Standard PGD | asr | lower is better | 0.9838341036621386 | paired_comparisons.csv |
| Projection Phys-PGD ASR is reduced | Projection-based phys-PGD | asr | lower is better | 0.9307828179853633 | paired_comparisons.csv |
| Penalty Phys-PGD ASR is reduced | Penalty-based phys-PGD | asr | lower is better | 0.92884479273289 | paired_comparisons.csv |
| Projection Phys-PGD PV-ASR given V0 is reduced | Projection-based phys-PGD | conditional_pv_asr_start_valid | lower is better | 0.9334063588276182 | paired_comparisons.csv |
| Penalty Phys-PGD PV-ASR given V0 is reduced | Penalty-based phys-PGD | conditional_pv_asr_start_valid | lower is better | 0.9303760725785777 | paired_comparisons.csv |

All six rows improve in the stated direction for all five paired seeds. The
exact two-sided sign-flip p-value is 0.0625 for each non-tied primary row.
No primary row is significant after Holm correction, so the manuscript treats
these as large, consistent effect estimates rather than conclusive
population-level hypothesis tests.

## Multi-Seed Table Values Used in the Manuscript

| Model | Setting | Metric | Mean | Std. | 95% CI |
| --- | --- | --- | ---: | ---: | --- |
| BiLSTM-ERM | Unperturbed | F1-score | 0.8788 | 0.0293 | [0.8424, 0.9152] |
| CAT-AD | Unperturbed | F1-score | 0.9084 | 0.0186 | [0.8852, 0.9315] |
| BiLSTM-ERM | Norm-bounded PGD | ASR | 0.9878 | 0.0166 | [0.9672, 1.0084] |
| CAT-AD | Norm-bounded PGD | ASR | 0.0040 | 0.0054 | [-0.0028, 0.0107] |
| BiLSTM-ERM | Projection-based Phys-PGD | PV-ASR (valid start) | 0.9336 | 0.0760 | [0.8392, 1.0280] |
| CAT-AD | Projection-based Phys-PGD | PV-ASR (valid start) | 0.0002 | 0.0004 | [-0.0004, 0.0007] |
| BiLSTM-ERM | Penalty-based Phys-PGD | PV-ASR (valid start) | 0.9306 | 0.0804 | [0.8307, 1.0304] |
| CAT-AD | Penalty-based Phys-PGD | PV-ASR (valid start) | 0.0002 | 0.0004 | [-0.0004, 0.0007] |

These rows are rendered in table_multiseed_summary.tex. Confidence
intervals are unbounded Student-t intervals across five seeds and may extend
outside [0,1]; they are not clipped.

## Reproducibility Claim

The corrected strict verification report records:

- status: PASSED
- seeds: 42,43,44,45,46
- long rows: 760
- wide rows: 40
- aggregate rows: 152
- paired comparison rows: 14
- warnings: None
- errors: None

These values are checked by tools/verify_numeric_claims.ps1 in the local
no-download audit.

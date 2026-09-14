# CAT-AD Manuscript Claim-Traceability Audit

This audit maps the manuscript's narrative claims to concrete repository
evidence. It complements `NUMERIC_CLAIMS_LEDGER.md`: the ledger checks headline
numbers, while this audit checks that qualitative statements such as "strong
baseline attacks", "high F1 and low ASR", "PV-ASR suppression", and "budget
sensitivity stability" are supported by generated artifacts.

## Claim-To-Evidence Map

| Manuscript claim family | Evidence source |
| --- | --- |
| Targeted anomalous-to-normal threat model | `paper_lncs/main.tex`, `adsb/attacks.py`, `tests/test_physical_metrics.py` |
| Physically constrained adversarial training with consistency regularization | `adsb/training.py`, `adsb/model.py`, `adsb/train_constants.py` |
| Strong evaluated attacks against BiLSTM-ERM | `outputs/publication_benchmark/aggregate_summary.csv`, `outputs/tables/table_robustness_summary.csv`, `tools/verify_attack_evaluation_sanity.ps1` |
| CAT-AD maintains high adversarial F1 and low ASR | `outputs/publication_benchmark/aggregate_summary.csv`, `outputs/tables/table_multiseed_summary.tex`, `NUMERIC_CLAIMS_LEDGER.md` |
| CAT-AD suppresses physically valid evasion | `outputs/publication_benchmark/aggregate_summary.csv`, `outputs/tables/table_physical_feasibility.csv`, `outputs/publication_benchmark/paired_comparisons.csv` |
| Perturbation-budget sensitivity is a bounded auxiliary result | `results/fig_epsilon_sensitivity_data.csv`, `ABLATION_AND_SENSITIVITY_AUDIT.md` |
| Claims are scoped rather than absolute | `CLAIM_SCOPE_GUARDRAILS.md`, `FAILURE_MODE_AND_NEGATIVE_RESULT_AUDIT.md`, `paper_lncs/main.tex` |

## Guardrail

The manuscript should not contain unsupported broad claims. Its central
result-level statements must remain tied to:

- the evaluated targeted anomalous-to-normal threat model;
- the evaluated PGD, Projection-based Phys-PGD, and Penalty-based Phys-PGD
  attacks;
- the five archived seeds in `outputs/publication_benchmark`;
- the generated aggregate, paired-comparison, physical-feasibility, and
  epsilon-sensitivity artifacts.

`tools/verify_manuscript_claim_traceability.ps1` enforces this boundary by
reading the manuscript, source-code markers, benchmark CSV files, generated
tables, and review-facing guardrail documents.

# CAT-AD Claim Hierarchy Audit

This audit separates the paper's primary quantitative claims from auxiliary
design evidence. The goal is to avoid selective-reporting ambiguity: the main
CAT-AD claims must come from the archived five-seed paired benchmark, while
ablation, sensitivity, PVR, and strong-baseline evidence remain supporting
analyses with explicit limits.

## Primary Evidence

The primary quantitative claims are the six rows in
`NUMERIC_CLAIMS_LEDGER.md` under `Primary Claim Values`:

- Clean F1 is not reduced.
- Standard PGD ASR is reduced.
- Projection-based Phys-PGD ASR is reduced.
- Penalty-based Phys-PGD ASR is reduced.
- Projection-based Phys-PGD PV-ASR given V0 is reduced.
- Penalty-based Phys-PGD PV-ASR given V0 is reduced.

All six primary claims are drawn from
`outputs/publication_benchmark/paired_comparisons.csv` with seeds
`42,43,44,45,46`, and are summarized by the strict publication gate in
`outputs/publication_benchmark/verification_report.md`.

## Auxiliary Evidence

The following evidence is deliberately not treated as an independent primary
claim:

- ablation rows in `outputs/tables/table5_ablation_study.csv`;
- epsilon-sensitivity rows in `results/fig_epsilon_sensitivity_data.csv`;
- strong adversarial-training baselines in the auxiliary ablation table;
- PVR rows, which are physical-validity diagnostics rather than primary CAT-AD
  improvement claims.

## Machine-Checked Guardrail

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_claim_hierarchy.ps1
```

Expected output includes:

- `claim_hierarchy=PASSED`
- `primary_claims_checked=6`
- `auxiliary_boundaries_checked=4`
- `forbidden_hierarchy_claims_checked=10`

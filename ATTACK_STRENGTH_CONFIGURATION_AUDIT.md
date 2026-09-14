# CAT-AD Attack-Strength Configuration Audit

This audit records the fixed attack-strength configuration used by the
publication benchmark and the supplemental epsilon-sensitivity evidence. It
reduces the review risk that CAT-AD's robustness claim is based on an
accidentally weak or undocumented attack setup.

It is not a formal robustness certificate and does not claim coverage of all
adaptive attacks. The claim remains limited to the evaluated attack families,
budgets, physical constraints, and seeds.

## Fixed Benchmark Attack Configuration

The benchmark manifest records the source-code, data, and hyperparameter
signature used for the publication run:

- Signature algorithm: `sha256(config, data_sha256, code_sha256, hyperparameters)`.
- Evaluation attack budget: `EVAL_ATTACK_EPS=0.1`.
- PGD steps: `PGD_STEPS=5`.
- PGD step size: `PGD_ALPHA=0.03`.
- Step-size coverage: `PGD_STEPS * PGD_ALPHA = 0.15`, which exceeds the
  evaluation budget `0.1` before the L-infinity projection.
- Adversarial-training budget: `ADV_TRAIN_EPS=0.1`.
- Penalty-based Phys-PGD uses a lambda schedule with
  `PHYS_PENALTY_LAMBDA_MAX=10.0`, `PHYS_PENALTY_LAMBDA_GAMMA=2.0`, and
  `PHYS_PENALTY_FINAL_PROJECTION=True`.
- Physical penalty weights are explicit:
  speed `1.0`, altitude `1.0`, latitude/longitude `1.0`, and heading `10.0`.

## Empirical Strength Signals

The paired-comparison and aggregate benchmark artifacts show that the attacks
are strong enough to substantially compromise the undefended BiLSTM-ERM in
the evaluated threat model:

- Standard PGD ASR reduction after CAT-AD: mean improvement `0.983834`.
- Projection-based Phys-PGD ASR reduction after CAT-AD: mean improvement
  `0.930783`.
- Penalty-based Phys-PGD ASR reduction after CAT-AD: mean improvement
  `0.928845`.

The aggregate table also records high baseline ASR under all three evaluated
attack families:

- BiLSTM-ERM under Norm-bounded PGD: `0.9878`.
- BiLSTM-ERM under Projection-based Phys-PGD: `0.9314`.
- BiLSTM-ERM under Penalty-based Phys-PGD: `0.9295`.

## Epsilon-Sensitivity Boundary

The supplemental epsilon-sensitivity CSV evaluates both physical attack
families over six exported budgets from `0.05` to `0.50`, for both the Standard
BiLSTM and CAT-AD. This sensitivity evidence is auxiliary to the five-seed
publication benchmark, but it helps show that the robustness pattern is not
visible only at one narrow physical-attack budget.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_attack_strength_configuration.ps1
```

Expected output includes:

- `attack_strength_configuration=PASSED`
- `hyperparameters_checked=12`
- `paired_attack_rows_checked=3`
- `epsilon_rows_checked=24`
- `epsilon_levels_checked=6`

## Interpretation Limit

This audit supports the narrower statement that the evaluated attacks are
documented, multi-step, budget-reaching, physically configured, and empirically
strong against the baseline detector. It does not prove certified robustness,
operational aviation safety, or resistance to arbitrary unseen adaptive
attackers.

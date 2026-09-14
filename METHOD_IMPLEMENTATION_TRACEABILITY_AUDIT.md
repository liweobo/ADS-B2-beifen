# CAT-AD Method Implementation Traceability Audit

This audit links the CAT-AD method description in the manuscript to the exact
training, attack, model, hyperparameter, and run-log evidence used by the
archived publication benchmark.

## Traceability Boundary

The manuscript defines CAT-AD as a physically constrained adversarial training
procedure with four training components:

| Method component | Code and artifact evidence |
| --- | --- |
| Unperturbed empirical-risk term | `adsb/training.py` computes `loss_clean = lossf(logits_clean, y)` from `model(X, return_features=True)`; `clean` is retained only as a source-code variable name. |
| Anomalous-only adversarial term | `adsb/training.py` calls the legacy API `apply_pgd_malicious_only`, then computes `loss_adv = lossf(logits_adv[mal_mask], y[mal_mask])` for `mal_mask = y == 1`. |
| Output-distribution consistency | `_physical_consistency_losses` computes a temperature-scaled KL term with `F.kl_div` between unperturbed and adversarial anomalous-sample output distributions. |
| Representation consistency | `_physical_consistency_losses` computes `F.mse_loss` between normalized unperturbed and adversarial BiLSTM representations. |

The attack generator is targeted anomalous-to-normal: `adsb/attacks.py`
defaults `target_label=0` and `apply_pgd_malicious_only` attacks only samples
with `y == 1`. During training, the adversarial sample is still supervised with
the original anomalous label through `lossf(logits_adv[mal_mask], y[mal_mask])`.

## Hyperparameter Boundary

The archived benchmark manifest records the method hyperparameters:

- `ADV_TRAIN_EPS=0.1`
- `ADV_TRAIN_LAMBDA=0.5`
- `ADV_WARMUP_EPOCHS=3`
- `PGD_STEPS=5`
- `PGD_ALPHA=0.03`
- `USE_PENALTY_PHYS_PGD_TRAIN=true`
- `PHYS_PENALTY_LAMBDA_MAX=10.0`
- `PHYS_PENALTY_LAMBDA_GAMMA=2.0`
- `PHYS_OUT_LAMBDA=0.01`
- `PHYS_FEAT_LAMBDA=0.005`
- `PHYS_TEMPERATURE=2.0`

The detector code records the paper-facing architecture: 12-dimensional input,
two-layer bidirectional LSTM, hidden size 64, and a two-class classifier head.

## Run-Log Boundary

Every archived seed log in `outputs/publication_benchmark/runs/seed_*/run.log`
records the adversarial-training configuration and epoch-level components:
`clean_loss`, `adv_loss`, `out_cons`, `feat_cons`, `adv_delta_mean`,
`adv_delta_max`, `train_adv_asr`, `mean_loss_target`, `mean_loss_phys`, and
`mean_lambda_phys`.

This does not prove that the method is optimal or accepted by reviewers. It
does make the paper-to-code implementation boundary falsifiable in the local
artifact.

## Machine-Checked Guardrail

`tools/verify_method_implementation_traceability.ps1` checks the manuscript,
training code, attack code, model code, constants, benchmark manifest, and
five seed logs for the method-to-implementation markers above.

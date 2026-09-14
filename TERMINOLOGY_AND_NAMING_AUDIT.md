# Terminology and Naming Audit

## Decision

The manuscript-facing terminology is standardized and unambiguous. Model,
attack, class, metric, feature, and artifact names are defined at first use and
used consistently across the manuscript, generated tables, plotted data, and
publication-facing reports. Historical result files retain legacy schema keys
only for reproducibility; those keys are converted to the canonical display
names below before publication.

This audit follows the official Springer proceedings guidance that abbreviations
must be defined at first mention and used consistently, headings must follow the
proceedings capitalization convention, and figures/tables must be clear and
legible:

- <https://dam.springernature.com/file/Aa3ajpgoqnj98v-KtAvsqK/%2A/Springer_Instructions_for_Authors_of_Proceedings_CS.pdf>
- <https://www.springernature.com/de/authors/publish-a-book/step-by-step-conference-proceedings>

## Canonical Scientific Names

| Concept | Canonical manuscript name | Definition and boundary |
|---|---|---|
| Surveillance data | Automatic Dependent Surveillance--Broadcast (ADS-B) | Expanded independently in the abstract and main text. |
| Proposed method | constrained adversarial training for anomaly detection (CAT-AD) | The method combines physically constrained adversarial training with prediction- and feature-level consistency regularization. |
| Reference classifier | bidirectional long short-term memory trained by empirical risk minimization (BiLSTM-ERM) | Replaces the ambiguous display name `Standard BiLSTM`; CAT-AD and BiLSTM-ERM share the same BiLSTM architecture. |
| Digital reference attack | norm-bounded projected gradient descent without physical constraints (Norm-bounded PGD) | Replaces `Unconstrained PGD`, which was inaccurate because the attack is constrained by the normalized L-infinity budget. |
| Physical attacks | Projection-based Phys-PGD and Penalty-based Phys-PGD | Phys-PGD means physically constrained projected gradient descent; the two names identify the enforcement mechanism. |
| Evaluation without attack | unperturbed evaluation/detection | Replaces ambiguous manuscript uses of `clean`; `Clean` remains only a legacy archive setting key. |
| Class 0 | normal | The detector label and attack target are y=0. |
| Class 1 | anomalous | The original detector label is y=1; `malicious` and `benign` are not used as manuscript class names. |
| Physical fields | position (latitude/longitude), altitude, ground speed, and heading | `Ground speed` replaces the inconsistent manuscript label `velocity`; source metric key `vel_vr` remains a compatibility key. |
| Primary physical metric | physically valid attack success rate among pre-attack-valid samples (PV-ASR conditioned on V0) | The denominator and exact success-validity intersection are defined mathematically. |

## Published Comparator Names

The same-protocol comparison uses the exact method identities and publication
years below. It is a controlled reimplementation on common aircraft splits,
windows, threshold selection, and test data, not a copy of source-paper scores.

| Canonical name | Year | Manuscript citation key |
|---|---:|---|
| Fried--Last Differenced LSTM Autoencoder (Fried--Last Differenced LSTM-AE) | 2021 | `fried2021autoencoders` |
| variational autoencoder with support vector data description boundary (VAE--SVDD) | 2021 | `luo2021vaesvdd` |
| Contextual Autoencoder (Contextual AE) | 2022 | `chevrot2022cae` |

## Abbreviation Inventory

The manuscript defines the following abbreviations at first substantive use:

- ADS-B: Automatic Dependent Surveillance--Broadcast
- AE: autoencoder
- ASR: attack success rate
- BH: Benjamini--Hochberg
- BiLSTM: bidirectional long short-term memory
- CAT-AD: constrained adversarial training for anomaly detection
- CE: cross-entropy
- CSV: comma-separated values
- ERM: empirical risk minimization
- FAR: false alarm rate
- GPS: Global Positioning System
- GPU: graphics processing unit
- IDS: intrusion detection system
- KL: Kullback--Leibler
- LNCS: Lecture Notes in Computer Science
- MSE: mean squared error
- PDF: Portable Document Format
- PGD: projected gradient descent
- PGD-AT: PGD adversarial training
- Phys-PGD: physically constrained PGD
- PVR: physical violation rate
- PV-ASR: physically valid attack success rate
- RBF: radial basis function
- SHA-256: 256-bit Secure Hash Algorithm
- SVDD: support vector data description
- TNAI-FGSM: Time Neighborhood Accumulation Iteration Fast Gradient Sign Method
- UTC: Coordinated Universal Time
- VAE: variational autoencoder
- xLSTM: extended long short-term memory

Table-only abbreviations (`Acc.`, `Prec.`, `Std.`, `VR`, `Unpert.`, `Proj.`,
`Pen.`, and `Delta X`) are expanded in the corresponding table notes.

## Code and Archive Compatibility

`adsb/paper_naming.py` is the single publication-facing naming layer. The
archive keys `Baseline`, `Proposed`, `Standard PGD`, `Clean`, and historical
model spellings are intentionally accepted as inputs so the five-seed result
archive remains byte-traceable. They are never emitted as ambiguous
publication-facing names:

- `Baseline` and `Standard BiLSTM` map to `BiLSTM-ERM`.
- `Proposed` maps to `CAT-AD`.
- `Standard PGD` and `Unconstrained PGD` map to `Norm-bounded PGD`.
- `Clean` maps to `Unperturbed`.
- `Fried--Last diff. LSTM-AE` is accepted when reading historical results and
  normalized to `Fried--Last Differenced LSTM-AE`.

The archived fields `malicious_windows`, `malicious_ratio`,
`malicious_label_min_points`, `prob_malicious`, and
`physical_malicious_count` are likewise frozen data-contract identifiers from
the benchmark-time code. In that schema, `malicious` means the injected
positive anomaly class (`y=1`); it does not assert attacker intent. Generated
paper artifacts translate this class to `anomalous`, and user-facing tables and
reports do not expose the legacy wording. Renaming these stored keys without a
full benchmark rerun would break manifest hashes and result traceability.

The detector class remains `LSTMDetector` because it names the implemented
architecture rather than an experimental role. Its class-logit and
bidirectional-state comments are explicit English statements. No model weights,
metrics, seeds, or experiment conditions were changed by this naming revision.

## Automated Evidence

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\verify_terminology_and_naming.ps1
```

The verifier checks first definitions, title-case run-in headings, canonical
names on every publication surface, absence of the prohibited ambiguous names,
legacy-key compatibility, and code comments. It writes
`outputs/audits/terminology_and_naming_verification.json`.

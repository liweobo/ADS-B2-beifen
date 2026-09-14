# Published ADS-B Baseline Reproduction Audit

## Question Answered

Yes. CAT-AD is compared empirically with three concrete ADS-B
anomaly-detection designs published within a prespecified recent seven-year
window and evaluated under a common five-split protocol:

1. Fried--Last differencing recurrent autoencoder, based on *Facing Airborne
   Attacks on ADS-B Data with Autoencoders*, Computers & Security 109 (2021),
   DOI: [10.1016/j.cose.2021.102405](https://doi.org/10.1016/j.cose.2021.102405).
2. VAE--SVDD, based on *ADS-B Anomaly Data Detection Model Based on VAE-SVDD*,
   Computers & Security 104 (2021), DOI:
   [10.1016/j.cose.2021.102213](https://doi.org/10.1016/j.cose.2021.102213).
3. Contextual Autoencoder, based on *CAE: Contextual Auto-Encoder for
   Multivariate Time-Series Anomaly Detection in Air Transportation*,
   Computers & Security 116 (2022), DOI:
    [10.1016/j.cose.2022.102652](https://doi.org/10.1016/j.cose.2022.102652).

## Seven-Year Window and Inclusion Boundary

The rolling review window is `2019-07-15` through `2026-07-15`, anchored to the
manuscript revision date. An included comparator must be a peer-reviewed ADS-B
message- or trajectory-level anomaly detector, specify its architecture and
training objective sufficiently for protocol alignment, and operate on decoded
trajectory variables available in the archive without additional sensors.
The selected 2021--2022 models represent three distinct recent anomaly-detection
designs. They are a reproducible method-family sample, not an exhaustive census
of every ADS-B model published within the window.

The Fried--Last and Contextual AE implementations were additionally checked
against their authors' public repositories. The experiment is described as a
protocol-aligned reimplementation, not as a byte-identical execution of the
original frameworks and not as a comparison with numbers copied from different
datasets.

## Reimplementation Boundary

The implementations preserve each paper's defining mechanism:

- recurrent reconstruction of differenced trajectory channels for
  Fried--Last;
- recurrent variational reconstruction residuals followed by an RBF
  support-vector data-description boundary for VAE--SVDD;
- a shared bidirectional recurrent encoder and climb/cruise/descent decoders
  for Contextual AE.

To make the empirical comparison controlled, original feature sets, sequence
lengths, datasets, and software frameworks are replaced by CAT-AD's common
input contract. Therefore, these results quantify the methods under the
archived CAT-AD protocol; they do not assert exact agreement with the source
papers' absolute numbers.

## Fair Common Protocol

For seeds `42,43,44,45,46`, every method uses:

- the same source CSV with SHA-256
  `3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72`;
- identical train/validation/test aircraft IDs and split hashes;
- identical window and label counts;
- normalized 15-step windows with 12 raw-plus-differential channels;
- the same mixed validation split and maximum-F1 threshold scan;
- the same injected mixed test windows and metric implementation.

Training views follow the methods' declared objectives rather than forcing an
invalid training signal: the one-class models train on normal-only windows from the
shared split, whereas BiLSTM-ERM and CAT-AD train on the corresponding
labeled/injected windows.

## Audited Unperturbed-Detection Result

The paper-facing table is
`outputs/literature_benchmark/table_literature_detection.tex`. Means and
Student-t 95% confidence-interval half-widths are computed over the five
aircraft-level splits.

| Model | F1 | FAR |
|---|---:|---:|
| BiLSTM-ERM | 0.879 ± 0.036 | 0.038 ± 0.005 |
| Fried--Last Differenced LSTM-AE | 0.577 ± 0.023 | 0.422 ± 0.107 |
| VAE--SVDD | 0.447 ± 0.048 | 0.515 ± 0.550 |
| Contextual AE | 0.569 ± 0.020 | 0.453 ± 0.104 |
| CAT-AD | **0.908 ± 0.023** | **0.026 ± 0.006** |

CAT-AD has higher F1 and lower FAR on all five matched splits against each of
the four comparators. The one-class models achieve moderate-to-high recall but
high FAR, while VAE--SVDD also shows substantial split sensitivity.

## Attack Reporting Guardrail

The cross-family paper table deliberately excludes adversarial columns. The
training records retain exploratory five-step classifier-PGD outputs, but the
deterministic diagnostic in
`outputs/literature_benchmark/attack_resolution_audit.json` proves that those
values are not admissible robustness evidence for a reconstruction-score
surface.

For the seed-42 Fried--Last diagnostic batch, the fixed classifier setting
`eps=0.1, alpha=0.03, steps=5` raises the mean malicious probability to 1.0000
and reports ASR 0.0000. Holding the budget fixed while using
`alpha=0.003, steps=40` lowers the mean malicious probability to 0.4566 and
reports ASR 1.0000. The apparent zero ASR is therefore optimizer overshoot, not
robustness. CAT-AD's adversarial claims remain confined to the pre-specified
BiLSTM-ERM--CAT-AD comparison whose attack objective passed the existing
sanity checks.

## Reproduction and Verification

Full training:

```powershell
conda run -n testtorch python -m adsb.literature_benchmark `
  --csv sample_adsb_decoded.csv `
  --seeds "42,43,44,45,46" `
  --epochs 30 `
  --reference-benchmark outputs\publication_benchmark `
  --output-dir outputs\literature_benchmark `
  --force
```

Report/audit regeneration and verification:

```powershell
conda run -n testtorch python tools\audit_literature_attack_resolution.py
conda run -n testtorch python -m adsb.literature_report `
  --benchmark-dir outputs\literature_benchmark
conda run -n testtorch python -m adsb.literature_report `
  --benchmark-dir outputs\literature_benchmark `
  --verify-only
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\tools\verify_literature_baseline_reproduction.ps1
```

Expected final markers:

- `literature_baseline_reproduction=PASSED`
- `published_models_checked=3`
- `paired_splits_checked=5`

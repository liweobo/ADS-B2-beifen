# CAT-AD Prior-Art Novelty Matrix

This matrix records the evidence boundary used for CAT-AD's novelty claim.
It is designed for reviewer audit: the claim is falsifiable, scoped, and tied
to concrete source papers plus repository artifacts.

## Scope and Standard

This document does not claim an absolute proof that no related paper exists.
The defensible claim is narrower:

> To the best of our knowledge, prior ADS-B anomaly-detection and adversarial
> ADS-B work does not jointly cover the CAT-AD protocol: targeted
> anomalous-to-normal ADS-B trajectory evasion, physically constrained attack
> generation or training, paired pre/post physical auditing with exact PV-ASR
> conditioned on valid starts,
> consistency-regularized adversarial training, and a multi-seed publication
> gate with machine-checked artifacts.

A prior method would subsume the CAT-AD contribution only if it jointly
satisfied all six criteria below.

## Falsifiable Novelty Criteria

| Criterion | Required for CAT-AD novelty boundary | Implemented evidence |
|---|---|---|
| C1 | ADS-B trajectory anomaly-detection setting | `paper_lncs/main.tex`, `adsb/data.py`, `adsb/training.py` |
| C2 | Targeted anomalous-to-normal evasion objective | `adsb/attacks.py`, `tests/test_physical_metrics.py` |
| C3 | Physical trajectory constraints in attack generation or training | `adsb/attacks.py`, `adsb/training.py` |
| C4 | Paired pre/post physical flags and exact PV-ASR conditioned on pre-attack-valid samples | `adsb/training.py`, `tests/test_physical_metrics.py` |
| C5 | Output- and representation-consistency regularization during adversarial training | `adsb/model.py`, `adsb/training.py` |
| C6 | Multi-seed publication gate with split leakage checks, paired comparisons, logs, and artifact hashes | `adsb/benchmark.py`, `adsb/publication_preflight.py`, `adsb/verify_artifacts.py` |

## Representative Prior-Art Boundary

| Representative line of work | C1 | C2 | C3 | C4 | C5 | C6 | Boundary evidence |
|---|---:|---:|---:|---:|---:|---:|---|
| ADS-B security survey: Strohmeier et al., IEEE Communications Surveys & Tutorials 2015, DOI `10.1109/COMST.2014.2365951` | partial | no | partial | no | no | no | Establishes ADS-B security risks and countermeasure taxonomy, not CAT-AD's evaluated learning protocol. |
| OpenSky data infrastructure: Schaefer et al., IPSN 2014, DOI `10.1109/IPSN.2014.6846743` | partial | no | partial | no | no | no | Establishes large-scale ADS-B research data collection and physical localization validation context, not adversarial training. |
| Wireless witnessing for ADS-B attacks: Jansen et al., NDSS 2021, DOI `10.14722/ndss.2021.24552` | partial | partial | partial | no | no | no | Establishes top-tier ADS-B security prior art for distributed receiver cross-validation and spoofing/Sybil attack detection, not CAT-AD's trajectory anomaly-detector training/evaluation protocol. |
| ADS-B anomaly detection: Fried and Last 2021, Luo et al. 2021, Chevrot et al. 2022 | yes | no | partial | no | no | no | Establishes ADS-B or air-transport anomaly detection, but focuses on detection rather than targeted physical evasion robustness. |
| Recent realistic-attack detectors, recovery methods, ADS-B IDS, security surveys, physics-consistent trajectory AD, adversarial-perturbation detectors, and attack-type classifiers: Pirolley et al. 2026, Yue et al. 2026, Cevik and Akleylek 2025, Ahmed et al. 2025, Ahmed et al. 2026, Zhong et al. 2026, Zhao et al. 2026, Ngamboe et al. 2025, Khan et al. 2025, Zhang et al. 2025, Shi et al. 2026, Ahmed et al. 2026 | partial | partial | partial | no | no | no | Recent realistic-attack, detection/recovery, IDS, attack-vector, lightweight, adversarial-perturbation, physics-consistent trajectory, transfer-learning, data-security, and survey work strengthens the context, but does not jointly provide physically constrained targeted adversarial training, exact PV-ASR, and CAT-AD's multi-seed publication gate. |
| General adversarial robustness: Goodfellow et al. 2015, Madry et al. 2018, Carlini and Wagner 2017, Athalye et al. 2018 | no | yes | no | no | partial | partial | Establishes adversarial examples, PGD-style training, and robustness-evaluation principles outside the ADS-B trajectory setting. |
| ADS-B adversarial attacks: Luo et al., Sensors 2024, DOI `10.3390/s24113584` | yes | yes | no | no | partial | no | Establishes adversarial vulnerability of ADS-B unsupervised anomaly detectors and adversarial-training baselines; it does not report physically constrained targeted training or exact PV-ASR. |
| Abnormal flight and trajectory anomaly review: Wu et al., Aerospace 2026, DOI `10.3390/aerospace13030209` | yes | no | partial | no | no | no | Establishes the importance of speed, altitude, and heading deviations for trajectory anomaly detection, not adversarial robustness protocol design. |
| CAT-AD in this repository | yes | yes | yes | yes | yes | yes | Joint protocol implemented and verified by the strict publication gate and manuscript audit. |

## Source Notes Checked on 2026-07-12

The machine-readable companion file `PRIOR_ART_CRITERIA_COVERAGE.tsv` records
the C1-C6 coverage values for each source. The novelty verifier parses that TSV
and fails if any non-CAT-AD row jointly satisfies C1-C6.

- Luo et al. 2024 explicitly studies adversarial attacks against
  deep-learning-based ADS-B unsupervised anomaly detection models and reports
  adversarial training as a defense baseline. This is why CAT-AD does not claim
  "ADS-B adversarial attacks" or "adversarial training" as new.
- Strohmeier et al. 2015 and OpenSky 2014 establish the security-sensitive ADS-B
  setting and large-scale data context, but they are not CAT-AD-style robustness
  training papers.
- Jansen et al. 2021 establishes top-tier ADS-B attack-detection prior art
  through wireless witnessing and distributed receiver cross-validation; it is
  security-critical related work, but it is not physically constrained targeted
  adversarial training for a trajectory anomaly detector and does not report
  exact PV-ASR.
- Wu et al. 2026 motivates operationally meaningful trajectory constraints
  through speed, altitude, and heading deviations.
- Pirolley et al. 2026 and Yue et al. 2026 add realistic low-altitude attack
  detection and ATC-oriented attack detection/recovery challenge boundaries;
  neither reports CAT-AD's targeted physical adversarial-training and PV-ASR protocol.
- Cevik and Akleylek 2025, Ahmed et al. 2025, Ahmed et al. 2026, Zhong et al.
  2026, Zhao et al. 2026, Ngamboe et al. 2025, Khan et al. 2025, Zhang et al.
  2025, Shi et al. 2026, and Ahmed et al. 2026 were added as recent challenge
  references. They strengthen the ADS-B IDS, attack-vector benchmark,
  adversarial-perturbation detection, physics-consistent trajectory anomaly
  detection, data-security, and security-survey landscape but do not remove the
  C1-C6 novelty boundary because the sampled methods still do not jointly
  report exact PV-ASR, consistency-regularized physically constrained targeted
  training, and a multi-seed publication gate.
- Exact phrase searches for `"PV-ASR" "ADS-B"`, `"physically valid attack
  success rate" adversarial`, and `"physically constrained" "ADS-B"
  "adversarial training"` did not reveal a directly matching ADS-B CAT-AD-style
  protocol in the sampled web results. This is a weak absence signal, not a
  proof of global novelty.

## Allowed and Disallowed Claim Wording

Allowed:

- "to the best of our knowledge"
- "within the evaluated threat model"
- "representative prior work does not jointly cover"
- "the contribution is the combined ADS-B trajectory security protocol"

Disallowed:

- "first ever"
- "guaranteed novel"
- "proves no one has done this"
- "solves ADS-B security"
- "certified robust against all attacks"

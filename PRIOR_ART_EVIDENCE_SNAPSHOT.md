# CAT-AD Prior-Art Evidence Snapshot

Checked on 2026-07-12.

This snapshot records the external evidence used to bound CAT-AD's novelty
claim. It is not a proof that no related work exists anywhere. It is a
reviewer-facing audit trail that separates known prior ideas from the narrower
CAT-AD contribution implemented in this repository.

## Novelty Boundary

CAT-AD should be claimed as a combined ADS-B trajectory security protocol, not
as a new LSTM, a new PGD attack, a new adversarial-training principle, or the
first ADS-B anomaly detector.

A prior method would subsume the CAT-AD claim only if it jointly covered all
six criteria below:

| Criterion | Meaning |
| --- | --- |
| C1 | ADS-B trajectory anomaly-detection setting. |
| C2 | Targeted anomalous-to-normal evasion objective. |
| C3 | Physical trajectory constraints in attack generation or training. |
| C4 | Exact per-sample physically valid ASR (PV-ASR), not ASR times validity rate. |
| C5 | Output- and representation-consistency regularization during adversarial training. |
| C6 | Multi-seed publication gate with split leakage checks, paired comparisons, logs, and artifact hashes. |

## External Source Evidence

| Source | What it establishes | Boundary relative to CAT-AD |
| --- | --- | --- |
| Strohmeier et al., 2015, DOI `10.1109/COMST.2014.2365951`, https://doi.org/10.1109/COMST.2014.2365951 | ADS-B is a security-sensitive broadcast protocol with known authentication and integrity concerns. | Supports the security motivation; it is not an adversarial-training or PV-ASR protocol. |
| Schaefer et al., 2014, DOI `10.1109/IPSN.2014.6846743`, https://doi.org/10.1109/IPSN.2014.6846743 | OpenSky provides large-scale ADS-B data infrastructure for research. | Supports the trajectory-data context; it is not a robustness-training method. |
| Jansen et al., 2021, DOI `10.14722/ndss.2021.24552`, https://www.ndss-symposium.org/ndss-paper/trust-the-crowd-wireless-witnessing-to-detect-attacks-on-ads-b-based-air-traffic-surveillance/ | Wireless witnessing uses distributed receivers to detect attacks on ADS-B-based air-traffic surveillance. | Top-tier ADS-B security prior art for sensor-network cross-validation and spoofing/Sybil detection; it is not a trajectory anomaly-detector adversarial-training protocol with exact PV-ASR. |
| Fried and Last, 2021, DOI `10.1016/j.cose.2021.102405`, https://doi.org/10.1016/j.cose.2021.102405 | Autoencoder-based ADS-B anomaly detection for airborne attack scenarios. | Covers ADS-B anomaly detection, but not targeted physically constrained adversarial training with exact PV-ASR. |
| Luo et al., 2021, DOI `10.1016/j.cose.2021.102213`, https://doi.org/10.1016/j.cose.2021.102213 | VAE-SVDD-style ADS-B anomaly detection. | Covers ADS-B anomaly detection, but not CAT-AD's targeted physical evasion protocol. |
| Chevrot et al., 2022, DOI `10.1016/j.cose.2022.102652`, https://doi.org/10.1016/j.cose.2022.102652 | Contextual auto-encoder anomaly detection for multivariate air-transport time series. | Covers trajectory/time-series anomaly detection context, but not physically constrained adversarial training or PV-ASR. |
| Pirolley et al., 2026, DOI `10.1016/j.ast.2025.111199`, https://doi.org/10.1016/j.ast.2025.111199 | Four realistic low-altitude ADS-B attack scenarios with specialized detection or correction methods. | Challenges broad realistic-attack and LSTM-correction novelty claims, but not CAT-AD's targeted physically constrained adversarial training, exact PV-ASR, consistency losses, or publication gate. |
| Yue et al., 2026, DOI `10.1016/j.eswa.2025.130781`, https://doi.org/10.1016/j.eswa.2025.130781 | OCREN uses flight plans, online classification, and NARX recovery for ADS-B attacks. | Challenges broad ADS-B attack detection/recovery novelty claims, but does not jointly cover CAT-AD's C2-C6 protocol. |
| Cevik and Akleylek, 2025, DOI `10.1016/j.iot.2024.101416`, https://doi.org/10.1016/j.iot.2024.101416 | ADS-B anomaly-detection system comparing attack vectors and machine-learning models. | Recent challenge reference for attack-vector and ML-model ADS-B detection; it does not jointly cover targeted physically constrained adversarial training, exact PV-ASR, and CAT-AD's publication gate. |
| Ahmed et al., 2025, DOI `10.7717/peerj-cs.2886`, https://doi.org/10.7717/peerj-cs.2886 | Deep-learning architecture for ADS-B anomalous-message and attack-type detection. | Recent challenge reference for ADS-B IDS and attack classification; it does not jointly cover physically constrained targeted adversarial training, exact PV-ASR, and CAT-AD's publication gate. |
| Ahmed et al., 2026, DOI `10.1016/j.array.2026.101012`, https://doi.org/10.1016/j.array.2026.101012 | Realistic and lightweight intrusion detection for ADS-B. | Recent lightweight-IDS challenge reference; it does not jointly cover CAT-AD's physically constrained targeted adversarial training, exact PV-ASR, and multi-seed publication gate. |
| Ngamboe et al., 2025, arXiv `2510.08333`, https://arxiv.org/abs/2510.08333 | xLSTM/Transformer transfer-learning approaches for ADS-B intrusion detection. | Recent challenge reference for ADS-B IDS model design; it is not a CAT-AD-style targeted physical evasion robustness protocol. |
| Luo et al., 2024, DOI `10.3390/s24113584`, https://doi.org/10.3390/s24113584 | Adversarial attacks against deep-learning-based ADS-B unsupervised anomaly detection models, including ADS-B-specific attack/defense baselines. | This is the closest prior boundary: it means CAT-AD must not claim ADS-B adversarial attacks or adversarial training as new. It does not jointly cover physically constrained targeted training, exact PV-ASR, and the multi-seed publication gate used here. |
| Zhong et al., 2026, DOI `10.1016/j.cja.2026.104083`, https://doi.org/10.1016/j.cja.2026.104083 | RDPA detects adversarial attack perturbation patterns in ADS-B trajectory data. | Recent adversarial-perturbation detection challenge reference; it is detection-oriented and does not jointly provide CAT-AD's physical adversarial training, exact PV-ASR, and publication gate. |
| Zhao et al., 2026, DOI `10.1016/j.comnet.2026.112476`, https://doi.org/10.1016/j.comnet.2026.112476 | IMDM-PC studies physics-consistent robust ADS-B trajectory anomaly detection under perturbations. | Recent close challenge reference for physics-consistent robust ADS-B trajectory anomaly detection; it does not jointly provide targeted anomalous-to-normal adversarial training, exact per-sample PV-ASR, and CAT-AD's multi-seed publication gate. |
| Khan et al., 2025, DOI `10.1109/COMST.2024.3513213`, https://doi.org/10.1109/COMST.2024.3513213 | Broad survey of ADS-B protocol security challenges, potential solutions, and future directions. | Recent challenge reference for the security landscape; it is not an implemented CAT-AD-style targeted physical evasion training/evaluation protocol. |
| Zhang et al., 2025, DOI `10.1145/3742763.3760698`, https://doi.org/10.1145/3742763.3760698 | ADS-B data-security analysis and safeguarding strategies. | Challenges any broad "ADS-B data security is new" claim; it does not jointly cover CAT-AD's physically constrained adversarial training, exact PV-ASR, and publication gate. |
| Shi et al., 2026, DOI `10.3390/s26020634`, https://doi.org/10.3390/s26020634 | Survey of ADS-B and Remote ID cyberattacks, detection techniques, and countermeasures. | Recent challenge reference for the broader ADS-B/RID security taxonomy; it is a survey and not the CAT-AD training/evaluation protocol. |
| Ahmed et al., 2026, DOI `10.1109/OJCS.2026.3651384`, https://doi.org/10.1109/OJCS.2026.3651384 | Survey of ADS-B threats, existing solutions, and future research for secure air-traffic surveillance. | Recent challenge reference for ADS-B threat taxonomy and solution space; it strengthens the threat-model boundary but does not subsume CAT-AD's C1-C6 protocol. |
| Goodfellow et al., 2015, https://arxiv.org/abs/1412.6572 | Adversarial examples and FGSM-style training principles. | General adversarial robustness, not ADS-B trajectory-specific physical constraints or PV-ASR. |
| Madry et al., 2018, https://openreview.net/forum?id=JcRbuE7FCJ | PGD-style adversarial training as a robust optimization framework. | General robust optimization, not ADS-B trajectory anomaly detection or CAT-AD's physically valid evasion metric. |
| Carlini and Wagner, 2017, DOI `10.1109/SP.2017.49`, https://doi.org/10.1109/SP.2017.49 | Stronger adversarial attack evaluation for neural networks. | Supports careful robustness evaluation; it is not the ADS-B CAT-AD protocol. |
| Athalye et al., 2018, https://proceedings.mlr.press/v80/athalye18a.html | Robustness claims can be misleading when attacks are weak or gradients are obscured. | Supports the attack-sanity checks; it is not an ADS-B trajectory method. |
| Wu et al., 2026, DOI `10.3390/aerospace13030209`, https://doi.org/10.3390/aerospace13030209 | Review of abnormal flight behavior and trajectory anomaly-detection methods, including operationally meaningful trajectory deviations. | Supports the need for physical trajectory constraints; it is not a CAT-AD-style adversarial training protocol. |

## Negative Evidence Checks

The following exact-phrase and targeted searches were used as weak absence
signals when writing the novelty boundary:

- `"PV-ASR" "ADS-B"`
- `"physically valid attack success rate" "ADS-B"`
- `"physically constrained" "ADS-B" "adversarial training"`
- `"Constrained Adversarial Training" "ADS-B"`
- `"ADS-B" "PV-ASR" "adversarial training"`
- `"ADS-B intrusion detection" "physically valid attack success rate"`
- `"Trust the Crowd" "ADS-B" "PV-ASR"`
- `"RDPA" "ADS-B" "PV-ASR"`
- `"Toward realistic and lightweight intrusion detection for ADS-B" "PV-ASR"`
- `"IMDM-PC" "PV-ASR"`
- `"10.1016/j.comnet.2026.112476" "physically valid attack success rate"`
- `"10.1016/j.ast.2025.111199" "PV-ASR"`
- `"10.1016/j.eswa.2025.130781" "PV-ASR"`

These searches did not reveal a sampled result that jointly matched C1-C6.
This does not prove global novelty. It supports the scoped wording used in the
paper: "to the best of our knowledge" and "within the evaluated threat model."

## Repository Evidence

The repository implements the six criteria through the following artifacts.
The companion `PRIOR_ART_CRITERIA_COVERAGE.tsv` records the same criteria in a
machine-readable form; the novelty verifier fails if any non-CAT-AD row is
marked as covering all six criteria.

| Criterion | Local evidence |
| --- | --- |
| C1 | `paper_lncs/main.tex`, `adsb/data.py`, `adsb/training.py` |
| C2 | `adsb/attacks.py`, `adsb/training.py`, `tests/test_physical_metrics.py` |
| C3 | `adsb/attacks.py`, `adsb/training.py`, `adsb/train_constants.py` |
| C4 | `adsb/training.py`, `adsb/paper_tables.py`, `tests/test_physical_metrics.py` |
| C5 | `adsb/model.py`, `adsb/training.py`, `outputs/tables/table5_ablation_study.tex` |
| C6 | `adsb/benchmark.py`, `adsb/publication_preflight.py`, `adsb/verify_artifacts.py`, `outputs/publication_benchmark/verification_report.md` |

The novelty claim is therefore evidence-bounded: representative prior work
covers important pieces of the problem, but the checked boundary does not show
the full C1-C6 combination before CAT-AD.

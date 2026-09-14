# CAT-AD Recent Prior-Art Challenge Audit

This audit records the newest challenge references added to the manuscript and
novelty boundary. Its purpose is to make the innovation claim harder to overstate:
recent ADS-B IDS, attack-classification, physics-consistent robust trajectory
anomaly detection, adversarial-perturbation detection, and survey work must be
acknowledged
before CAT-AD can claim a scoped contribution.

Checked on 2026-07-12.

## Challenge Sources

| Source | What it challenges | CAT-AD boundary after inspection |
| --- | --- | --- |
| Pirolley et al., 2026, Aerospace Science and Technology, DOI `10.1016/j.ast.2025.111199`, https://doi.org/10.1016/j.ast.2025.111199 | Four realistic low-altitude ADS-B attacks and specialized detection/correction methods. | Challenges any broad claim that realistic ADS-B attack scenarios or LSTM-based correction are new. It does not jointly satisfy C2-C6 because it does not implement CAT-AD's targeted physically constrained adversarial training, exact PV-ASR, consistency losses, or publication gate. |
| Yue et al., 2026, Expert Systems with Applications, DOI `10.1016/j.eswa.2025.130781`, https://doi.org/10.1016/j.eswa.2025.130781 | OCREN combines a flight-plan restriction domain, online attack detection, and NARX recovery. | Challenges any broad claim that ADS-B attack detection/recovery is new. It does not jointly satisfy C2-C6 because it is not CAT-AD's targeted anomalous-to-normal adversarial-training and exact PV-ASR protocol. |
| Cevik and Akleylek, 2025, Internet of Things, DOI `10.1016/j.iot.2024.101416`, https://doi.org/10.1016/j.iot.2024.101416 | ADS-B anomaly-detection system with attack vectors and machine-learning models. | Challenges any broad "ADS-B attack-vector detection is new" claim. It does not jointly satisfy C2-C6 because it is not the physically constrained targeted adversarial-training and exact PV-ASR protocol used by CAT-AD. |
| Ahmed et al., 2025, PeerJ Computer Science, DOI `10.7717/peerj-cs.2886`, https://doi.org/10.7717/peerj-cs.2886 | ADS-B anomalous-message and attack-type detection with deep learning. | Challenges any broad "ADS-B IDS is new" claim. It does not jointly satisfy C2-C6 because it is not the physically constrained targeted adversarial-training and exact PV-ASR protocol used by CAT-AD. |
| Ahmed et al., 2026, Array, DOI `10.1016/j.array.2026.101012`, https://doi.org/10.1016/j.array.2026.101012 | Realistic and lightweight ADS-B intrusion detection. | Challenges any claim that efficient ADS-B IDS design is new. It does not jointly satisfy C2-C6 because it is not CAT-AD's targeted physical evasion robustness protocol. |
| Zhong et al., 2026, Chinese Journal of Aeronautics, DOI `10.1016/j.cja.2026.104083`, https://doi.org/10.1016/j.cja.2026.104083 | RDPA detects adversarial attack perturbation patterns in ADS-B trajectory data. | Challenges any broad "ADS-B adversarial perturbation detection is new" claim. It does not jointly satisfy C4-C6 because it is detection-oriented and does not report exact PV-ASR, consistency-regularized physical adversarial training, or CAT-AD's publication gate. |
| Zhao et al., 2026, Computer Networks, DOI `10.1016/j.comnet.2026.112476`, https://doi.org/10.1016/j.comnet.2026.112476 | IMDM-PC studies physics-consistent robust ADS-B trajectory anomaly detection under perturbations. | Challenges any broad "physics-consistent robust ADS-B trajectory anomaly detection is new" claim. It does not jointly satisfy C2-C6 because it is not CAT-AD's targeted anomalous-to-normal adversarial-training protocol with exact PV-ASR and a multi-seed publication gate. |
| Ngamboe et al., 2025, arXiv `2510.08333`, https://arxiv.org/abs/2510.08333 | xLSTM/Transformer transfer-learning models for ADS-B intrusion detection. | Challenges any broad "new ADS-B detector architecture" claim. It does not jointly satisfy C2-C6 because it targets IDS model design rather than CAT-AD's targeted physical evasion robustness protocol. |
| Khan et al., 2025, IEEE Communications Surveys & Tutorials, DOI `10.1109/COMST.2024.3513213`, https://doi.org/10.1109/COMST.2024.3513213 | ADS-B protocol security challenges, countermeasures, and future directions. | Challenges any narrow or stale threat survey boundary. It does not jointly satisfy C1-C6 because it is a survey rather than an implemented targeted physical evasion training/evaluation protocol. |
| Zhang et al., 2025, ACM, DOI `10.1145/3742763.3760698`, https://doi.org/10.1145/3742763.3760698 | ADS-B data-security analysis and safeguarding strategies. | Challenges any broad "ADS-B data security is new" claim. It does not jointly satisfy C2-C6 because it is not CAT-AD's physically constrained adversarial-training and exact PV-ASR protocol. |
| Shi et al., 2026, Sensors, DOI `10.3390/s26020634`, https://doi.org/10.3390/s26020634 | Survey of ADS-B and Remote ID cyberattacks, detection techniques, and countermeasures. | Challenges narrow coverage of the threat landscape. It supports broader security positioning but does not jointly satisfy C1-C6 as an implemented CAT-AD-style training/evaluation method. |
| Ahmed et al., 2026, IEEE Open Journal of the Computer Society, DOI `10.1109/OJCS.2026.3651384`, https://doi.org/10.1109/OJCS.2026.3651384 | Survey of ADS-B threats, existing solutions, and future research for secure air-traffic surveillance. | Challenges the freshness of ADS-B threat coverage. It strengthens threat-model positioning but does not jointly satisfy C1-C6 as a CAT-AD-style robustness method. |

## Required Manuscript Effect

The manuscript must cite these recent challenge references in Related Work and
the positioning table must preserve the scoped novelty boundary:

- ADS-B IDS and attack classifiers are acknowledged as related work.
- Recent attack-vector benchmarks, lightweight IDS, physics-consistent robust
  trajectory anomaly detection, and adversarial-perturbation detectors are
  acknowledged as related work.
- CAT-AD does not claim ADS-B IDS, ADS-B anomaly detection, attack-type
  classification, lightweight IDS, physics-consistent trajectory anomaly
  detection, adversarial-perturbation detection,
  xLSTM/Transformer IDS, or ADS-B/RID security surveys as new.
- The novelty claim remains the joint C1-C6 protocol:
  targeted anomalous-to-normal ADS-B trajectory evasion, physically constrained
  attack generation/training, paired valid-start PV-ASR, consistency-regularized
  adversarial training, and a multi-seed publication gate.
- Recent ADS-B IDS, attack-vector benchmarks, physics-consistent robust
  trajectory anomaly detection, adversarial-perturbation detectors,
  data-security papers, security surveys, and attack-type classifiers are
  treated as challenge references, but the sampled work does not jointly provide
  physically constrained targeted adversarial training, exact PV-ASR, and a
  multi-seed publication gate.

## Explicit Criteria

- C1: ADS-B trajectory anomaly-detection setting.
- C2: Targeted anomalous-to-normal evasion objective.
- C3: Physical trajectory constraints in attack generation or training.
- C4: Paired pre/post physical auditing and exact PV-ASR on valid starts.
- C5: Output- and representation-consistency regularization during adversarial
  training.
- C6: Multi-seed publication gate with split checks, paired comparisons, logs,
  and artifact hashes.

## Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_recent_prior_art_challenge.ps1
```

Expected output includes:

- `recent_prior_art_challenge=PASSED`
- `recent_sources_checked=12`
- `criteria_checked=6`
- `paper_citations_checked=12`

## External Limit

This audit is a dated prior-art challenge check, not a proof of global novelty.
It strengthens the claim by adding nearby recent work and preserving cautious
wording such as "to the best of our knowledge" and "within the evaluated threat model."

The companion `PRIOR_ART_CRITERIA_COVERAGE.tsv` is the machine-readable C1-C6
coverage record used by `tools/verify_novelty_evidence.ps1` to reject any
non-CAT-AD row that would fully subsume the contribution.

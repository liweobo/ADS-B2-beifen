# CAT-AD Innovation Points and Evidence

This note summarizes the paper-level innovation claims, why each claim is
meaningful, and which experiment artifacts support it. The claims are scoped to
the implemented ADS-B trajectory anomaly-detection setting and the evaluated
threat model.

## What Is Not Claimed as New

The novelty claim deliberately excludes ideas that already exist:

- LSTM/BiLSTM sequence detectors are not new.
- PGD, FGSM, adversarial examples, and adversarial training are not new.
- ADS-B trajectory anomaly detection is not new.
- ADS-B adversarial attacks are not new; Luo et al. (Sensors 2024,
  DOI `10.3390/s24113584`) already study adversarial attacks against
  ADS-B unsupervised anomaly detection models.

The defensible claim is the combined ADS-B trajectory security protocol
implemented here: physically constrained targeted anomalous-to-normal
adversarial training, physically valid attack-success evaluation, and a
machine-checked multi-seed publication gate.

## Literature Boundary Used for the Claim

Representative prior work supports the following boundary:

- Strohmeier et al. (IEEE Communications Surveys & Tutorials 2015,
  DOI `10.1109/COMST.2014.2365951`) establish the ADS-B security problem.
- Schaefer et al. (IPSN 2014, DOI `10.1109/IPSN.2014.6846743`) establish
  OpenSky as a large-scale ADS-B research data source.
- Jansen et al. (NDSS 2021, DOI `10.14722/ndss.2021.24552`) establish
  wireless witnessing as top-tier ADS-B attack-detection prior art through
  distributed receiver cross-validation, but not CAT-AD's trajectory-detector
  adversarial-training and PV-ASR protocol.
- Fried and Last (Computers & Security 2021, DOI `10.1016/j.cose.2021.102405`),
  Luo et al. (Computers & Security 2021, DOI `10.1016/j.cose.2021.102213`),
  and Chevrot et al. (Computers & Security 2022, DOI
  `10.1016/j.cose.2022.102652`) establish ADS-B or air-transport anomaly
  detection, but do not provide CAT-AD's physically constrained targeted
  adversarial-training protocol with PV-ASR.
- Pirolley et al. (Aerospace Science and Technology 2026, DOI
  `10.1016/j.ast.2025.111199`) and Yue et al. (Expert Systems with
  Applications 2026, DOI `10.1016/j.eswa.2025.130781`) establish realistic
  low-altitude ADS-B attack detection and ATC-oriented attack detection/recovery,
  but not CAT-AD's targeted physical adversarial-training and PV-ASR protocol.
- Cevik and Akleylek (Internet of Things 2025, DOI
  `10.1016/j.iot.2024.101416`), Ahmed et al. (PeerJ Computer Science 2025,
  DOI `10.7717/peerj-cs.2886`), Ahmed et al. (Array 2026, DOI
  `10.1016/j.array.2026.101012`), Zhong et al. (Chinese Journal of
  Aeronautics 2026, DOI `10.1016/j.cja.2026.104083`), Zhao et al.
  (Computer Networks 2026, DOI `10.1016/j.comnet.2026.112476`), Ngamboe et
  al. (arXiv 2025, `2510.08333`), Khan et al. (IEEE Communications Surveys &
  Tutorials 2025, DOI `10.1109/COMST.2024.3513213`), Zhang et al. (ACM 2025,
  DOI `10.1145/3742763.3760698`), Shi et al. (Sensors 2026, DOI
  `10.3390/s26020634`), and Ahmed et al. (IEEE Open Journal of the Computer
  Society 2026, DOI `10.1109/OJCS.2026.3651384`) are recent challenge
  references for ADS-B IDS, attack-vector benchmarks, attack-type detection,
  lightweight IDS, adversarial-perturbation detection, physics-consistent
  trajectory anomaly detection, xLSTM/Transformer IDS, ADS-B data-security
  safeguards, and ADS-B/RID security surveys; they strengthen the related-work
  boundary but still do not jointly provide exact PV-ASR,
  consistency-regularized physically constrained targeted adversarial training,
  and CAT-AD's multi-seed publication gate.
- Goodfellow et al. (ICLR 2015), Madry et al. (ICLR 2018), Carlini and Wagner
  (IEEE S&P 2017, DOI `10.1109/SP.2017.49`), and Athalye et al. (ICML 2018)
  establish adversarial examples, adversarial training, and robustness
  evaluation principles, but are not ADS-B trajectory-specific.
- Wu et al. (Aerospace 2026, DOI `10.3390/aerospace13030209`) survey abnormal
  flight behavior and trajectory anomaly detection, reinforcing the need for
  operationally meaningful trajectory constraints.

This is evidence for a scoped novelty claim, not a mathematical proof that no
paper anywhere contains a similar idea. In the manuscript, the correct wording
is therefore "to the best of our knowledge" and the claim must remain tied to
the evaluated threat model and artifacts.

## Falsifiable Novelty Test

The accompanying `PRIOR_ART_NOVELTY_MATRIX.md` turns the novelty claim into a
reviewer-checkable test. A prior method would subsume CAT-AD only if it jointly
covered all of the following:

1. ADS-B trajectory anomaly detection.
2. Targeted anomalous-to-normal evasion.
3. Physical trajectory constraints in attack generation or training.
4. Paired pre/post physical auditing and exact PV-ASR conditioned on
   pre-attack-valid trajectories, not an aggregate-rate product.
5. Output- and representation-consistency regularization during adversarial
   training.
6. A multi-seed publication gate with split leakage checks, paired
   comparisons, logs, and artifact hashes.

The claim is therefore not "each ingredient is new." The claim is that the
joint ADS-B trajectory security protocol is not covered by the representative
prior-art boundary documented in the matrix and manuscript.

The machine-readable table `PRIOR_ART_CRITERIA_COVERAGE.tsv` makes this test
auditable: `tools/verify_novelty_evidence.ps1` parses every prior-art row,
checks C1-C6 values, and fails if any non-CAT-AD source is marked as covering
all six criteria.

## 1. Physically Constrained Adversarial Training for ADS-B Trajectory Anomaly Detection

**Innovation.** CAT-AD trains an ADS-B trajectory anomaly detector with
targeted anomalous-to-normal adversarial samples that are generated under
physical trajectory constraints.

**Why it matters.** Standard adversarial training can optimize perturbations in
feature space that do not correspond to plausible aircraft motion. For ADS-B
security, robustness against physically invalid perturbations is not enough:
the detector must be evaluated against evasions that respect position,
altitude, speed, and heading-change constraints.

**Code evidence.**

- `adsb/attacks.py`: projection-based Phys-PGD, penalty-based Phys-PGD,
  physical projection, physical penalty, and physical feasibility flags.
- `adsb/training.py`: CAT-AD adversarial training loop with physically
  constrained adversarial samples.
- `adsb/train_constants.py`: single source of attack/training hyperparameters.

**Experiment evidence.**

- Strict gate: `outputs/publication_benchmark/verification_report.md`
- Projection-based phys-PGD ASR reduction: mean improvement `0.930783`.
- Penalty-based phys-PGD ASR reduction: mean improvement `0.928845`.

## 2. Paired Valid-Start Physical Attack Evaluation

**Innovation.** The benchmark records physical validity before and after attack,
then reports New-PVR, ASR, and exact PV-ASR on the common valid-start set V0.

**Why it matters.** ASR alone can overstate practical attack risk because an
attack may succeed only by producing trajectories that violate aircraft-motion
constraints. A post-attack rate alone can also blame the attack for a trajectory
that was already invalid. Valid-start conditioning separates inherited
invalidity, attack-introduced violations, and physically valid evasion.

**Code evidence.**

- `adsb/training.py`: paired pre/post flags and exact conditional PV-ASR.
- `adsb/paper_tables.py`: physical-feasibility and PV-ASR table export.
- `adsb/verify_artifacts.py`: strict gate can require physical metrics.
- `tests/test_physical_metrics.py`: regression tests for targeted
  anomalous-to-normal ASR, hard projection, paired physical-validity flags, and
  exact conditional PV-ASR rather than an aggregate-rate product approximation.

**Experiment evidence.**

- Projection-based phys-PGD PV-ASR given V0 reduction: `0.933406`.
- Penalty-based phys-PGD PV-ASR given V0 reduction: `0.930376`.
- Baseline conditional PV-ASR: `0.9336` and `0.9306`; CAT-AD: `0.0002` for both.
- Mean valid-start coverage is `0.8423`; projection New-PVR given V0 is zero.

## 3. Prediction- and Representation-Consistency Regularization

**Innovation.** CAT-AD combines adversarial training with output-distribution
consistency and latent representation consistency between clean and physically
constrained adversarial trajectories.

**Why it matters.** For sequential trajectory detectors, robustness should not
only be a decision-boundary effect at the final classifier head. Stabilizing
both predictions and LSTM representations makes the detector less sensitive to
physically constrained perturbations while preserving unperturbed detection quality.

**Code evidence.**

- `adsb/model.py`: detector can return LSTM features for representation
  consistency.
- `adsb/training.py`: KL output consistency and normalized feature-consistency
  losses in CAT-AD training.
- `outputs/tables/table5_ablation_study.tex`: ablation table for training
  components.

**Experiment evidence.**

- Clean F1 mean improvement: `0.029586`.
- Baseline clean F1: `0.8788`; CAT-AD clean F1: `0.9084`.
- Standard PGD F1 mean improvement: `0.944556`.

## 4. Targeted Anomalous-to-Normal Evasion Protocol

**Innovation.** The evaluation explicitly attacks malicious/anomalous windows
with target label normal, while detector evaluation keeps the original
malicious labels.

**Why it matters.** In ADS-B anomaly detection, the most relevant evasion goal
is not arbitrary misclassification: it is hiding malicious trajectories as
normal. This protocol aligns the adversarial objective with the operational
threat model and makes ASR directly interpretable.

**Code evidence.**

- `adsb/attacks.py`: targeted attack generation with `target_label=0`.
- `adsb/training.py`: ASR and FAR computation under fixed evaluation labels.
- `paper_lncs/main.tex`: threat model and metric definitions.
- `tests/test_physical_metrics.py`: regression tests that normal samples remain
unchanged by anomalous-only attacks and that default PGD moves anomalous
  samples toward the normal target class; the same tests also verify that the
  projection-based Phys-PGD path invokes the physical projection component when
  `project_physical=True`, and that penalty-based Phys-PGD returns physical
  diagnostics while respecting the perturbation budget.

**Experiment evidence.**

- Baseline Standard PGD ASR: `0.9878`; CAT-AD Standard PGD ASR: `0.0040`.
- Baseline Projection-based phys-PGD ASR: `0.9314`; CAT-AD: `0.0006`.
- Baseline Penalty-based phys-PGD ASR: `0.9295`; CAT-AD: `0.0006`.

## 5. Publication-Grade Reproducibility Gate

**Innovation.** The experiment pipeline includes a strict publication gate:
data preflight, aircraft-level leakage checks, multi-seed execution, paired
comparisons, deterministic metadata, package snapshots, source-code
fingerprints, per-seed logs, and artifact checksums.

**Why it matters.** Top-tier reviews often reject robustness papers when the
evaluation is single-seed, non-reproducible, leakage-prone, or missing
statistical support. The gate turns these review risks into machine-checkable
conditions before numbers are copied into the paper.

**Code evidence.**

- `adsb/benchmark.py`: multi-seed benchmark, aggregate statistics, paired
  comparisons, environment/provenance manifest, artifact integrity.
- `adsb/publication_preflight.py`: full-data, split, leakage, and malicious
  window checks.
- `adsb/verify_artifacts.py`: strict publication verification.
- `tools/run_publication_gate.py`: one-command preflight + benchmark + gate.
- `check_submission_ready.ps1`: local submission audit wrapper.

**Experiment evidence.**

- `outputs/publication_benchmark/verification_report.md`: `Status: PASSED`.
- Completed seeds: `42,43,44,45,46`.
- Aggregate rows: `152`; paired comparison rows: `14`.
- Warnings: `None`; errors: `None`.

## Top-Conference Positioning

The strongest positioning is not "we get higher accuracy." The defensible
claim is:

> CAT-AD improves robustness of ADS-B trajectory anomaly detection under a
> targeted anomalous-to-normal evasion threat model by combining physically
> constrained adversarial training, consistency regularization, paired
> valid-start physical attack evaluation, and publication-grade reproducibility
> checks.

This is more suitable for a top-tier venue because it connects a domain-specific
security threat model, a method, a metric, and a reproducible statistical
evaluation protocol.

# CAT-AD Dual-Use Safety Audit

This audit separates CAT-AD's defensive, offline robustness evaluation from
operational ADS-B message manipulation. It is intended to make the dual-use
boundary explicit for reviewers of a security-sensitive aviation artifact.

## Safety Boundary

- The artifact evaluates models offline on recorded decoded trajectory data.
- The attack code optimizes tensors in the benchmark threat model; it does not
  transmit, replay, broadcast, or inject ADS-B messages into live systems.
- The repository does not include SDR, radio, receiver-control, socket,
  serial-port, Mode-S transmitter, or air-traffic infrastructure integration.
- The manuscript does not provide operational guidance for interfering with
  live aviation systems.
- The contribution is defensive robustness evaluation for anomaly detection,
  not an operational attack tool.

## Allowed Research Use

Allowed within this review artifact:

- rerunning the no-download benchmark on `sample_adsb_decoded.csv`;
- inspecting tensor-level PGD and Phys-PGD attacks against local models;
- verifying PV-ASR, attack sanity, and attack-strength configuration;
- reading the manuscript, generated preview PDF, and evidence audits.

## Disallowed Operational Use

The artifact must not be used to:

- transmit, replay, or broadcast ADS-B messages;
- connect to live receivers, aircraft, or air-traffic infrastructure;
- provide instructions for operational interference;
- certify aviation safety or regulatory compliance;
- make deployment decisions without independent safety engineering review.

## Evidence Checked

- `paper_lncs/main.tex` includes an ethical-considerations section that says the
  attacks are offline and not intended to interfere with live aviation systems.
- `DATA_PROVENANCE_AND_ETHICS.md` states that the workflow does not interact
  with live aircraft, receivers, air-traffic infrastructure, or operational
  aviation systems.
- `README.md` and `ARTIFACT_EVALUATION_GUIDE.md` preserve external limits:
  no top-conference acceptance guarantee, no aviation-safety certificate, and
  no proof against every adaptive attacker.
- `tools/verify_dual_use_safety.ps1` scans core code and scripts for forbidden
  operational integration markers such as socket/serial/SDR transmitter imports
  or live ADS-B radio tooling.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_dual_use_safety.ps1
```

Expected output includes:

- `dual_use_safety=PASSED`
- `safety_markers_checked=18`
- `forbidden_operational_markers_checked=13`
- `code_files_scanned=134`

## Interpretation Limit

This audit reduces misuse ambiguity in the submitted artifact. It does not
guarantee that every possible downstream use is safe, does not certify
operational aviation safety, and does not replace venue-specific ethics or
artifact-access review.

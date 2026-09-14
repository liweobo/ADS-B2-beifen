# CAT-AD Data Provenance and Ethics Statement

This statement records the data boundary used by the CAT-AD experiments and
the safety constraints for reviewing or rerunning the artifact.

## Dataset Used by the Experiments

The publication benchmark uses the local decoded ADS-B CSV:

- Path: `sample_adsb_decoded.csv`
- Size: `12508928` bytes
- SHA-256: `3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72`
- Header: `ts,icao,lat,lon,alt,spd,hdg,roc,callsign`

Despite the filename, this file is the benchmark CSV used by the strict
publication gate in this repository. The gate is run with `num_aircraft=none`
and `require_full_data=true`, meaning it does not use a reduced aircraft subset
of this CSV for the final claims.

Two larger local upstream state snapshots are present in the workspace for
traceability, but they are not required by the packaged benchmark rerun and are
not included in the submission bundle:

- `states_2018-05-28-14.csv`: `355478519` bytes,
  SHA-256 `285b609039250dd557cf410ef88c2d36892646e3b67ae1dd1113d6fe9e059419`
- `states_2022-06-27-23.csv`: `430570592` bytes,
  SHA-256 `c5d425f54ab5594029461219bb5f827b504cd1171e67b16077c2baea923ee498`

## Preflight Evidence

The authoritative data audit is
`outputs/publication_benchmark/preflight_report.json`.

The current preflight report records:

- Status: `passed`
- Seeds: `42,43,44,45,46`
- Rows loaded: `216880`
- Rows after filtering: `75238`
- Aircraft loaded: `20`
- Aircraft after filtering: `19`
- Aircraft split: `13/2/4` train/validation/test aircraft per seed
- Aircraft overlap: `0` for train-validation, train-test, and validation-test
  in every checked seed
- Per-attack malicious windows: nonempty for every seed and attack setting

The generated table `outputs/publication_benchmark/data_split_audit.tex` is
included by the manuscript so that split size and leakage evidence is visible
in the paper draft.

## Manifest Evidence

The benchmark manifest
`outputs/publication_benchmark/benchmark_manifest.json` records the same data
path, byte size, and SHA-256 hash under `provenance.data`. It also records the
Python executable, conda environment metadata, package snapshot, code
fingerprint, hyperparameters, deterministic settings, per-seed split summaries,
and artifact checksums.

The submission bundle includes `sample_adsb_decoded.csv`, the benchmark
manifest, the preflight report, and SHA-256 manifests for bundled files. It
does not require downloading data or software.

## Ethics and Safety Boundary

The experiments are offline evaluations over recorded trajectory data. The
workflow and experiments do not interact with live aircraft, receivers,
air-traffic infrastructure, or any operational aviation system.

The attack code is included to evaluate defensive robustness under an explicit
threat model. It should not be used to inject, transmit, replay, or operationally
manipulate ADS-B messages. The manuscript therefore avoids operational attack
instructions and frames CAT-AD as a defensive anomaly-detection robustness
study.

The physical constraints and PV-ASR metric are experimental proxies over
decoded trajectory variables. They do not certify flight safety, regulatory
plausibility, aircraft dynamics, or operational deployment readiness.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_data_provenance_ethics.ps1
```

Expected output includes:

- `data_provenance_ethics=PASSED`
- `sample_sha256=3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72`
- `raw_snapshots_checked=...`
- `preflight_runs_checked=5`
- `aircraft_overlap_violations=0`
- `bundle_manifests_checked=...`

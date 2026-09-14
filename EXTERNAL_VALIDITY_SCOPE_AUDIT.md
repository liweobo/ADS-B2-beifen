# CAT-AD External Validity Scope Audit

This audit records the dataset-scope boundary used by the CAT-AD manuscript.
Its purpose is to prevent a reviewer from reading the experiment as a claim of
transfer to every airspace, date, aircraft population, sensor network, message
field, or operational setting.

## Dataset Scope

The archived publication benchmark uses:

- raw CSV: `sample_adsb_decoded.csv`
- raw rows: `217148`
- raw aircraft identifiers: `20`
- time range: `2016-12-31T23:00:01Z` to `2017-01-01T23:00:00Z`
- model-loaded rows: `216880`
- rows after physical sanity filtering: `75238`
- filtered aircraft used by the benchmark: `19`
- benchmark seeds: `42,43,44,45,46`
- aircraft-level train/validation/test counts per seed: `13/2/4`

## Manuscript Boundary

The manuscript states that the benchmark is an offline decoded ADS-B sample
covering one UTC day, 20 raw aircraft identifiers, 75,238 filtered rows, and
19 filtered aircraft. Its external-validity paragraph says that results may
change for other airspaces, time periods, aircraft populations, sensor
networks, message fields, or adaptive attackers with different physical
capabilities.

## Disallowed Generalization

The artifact must not claim:

- transfer to all airspaces or dates;
- transfer to all aircraft populations or sensor networks;
- operational deployment readiness;
- universal ADS-B robustness;
- robustness for message fields, sensors, or attackers outside the evaluated
  threat model.

## Machine-Checked Guardrail

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_external_validity_scope.ps1
```

Expected output includes:

- `external_validity_scope=PASSED`
- `scope_markers_checked=18`
- `preflight_counts_checked=8`
- `forbidden_generalization_claims_checked=8`

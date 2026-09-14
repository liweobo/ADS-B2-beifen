# CAT-AD Dataset Profile Audit

This audit records the dataset profile used by the CAT-AD publication
benchmark. It complements `DATA_PROVENANCE_AND_ETHICS.md`: provenance records
where the data came from and how it is packaged, while this profile records
what is in the benchmark CSV and how it is filtered before model training.

## Raw CSV Profile

- File: `sample_adsb_decoded.csv`
- Size: `12508928` bytes
- SHA-256:
  `3098dd4d2f2bdc274c0bb8475bb23234be1d2486b0fef7581a93169691619f72`
- Header: `ts,icao,lat,lon,alt,spd,hdg,roc,callsign`
- Raw data rows: `217148`
- Unique raw aircraft identifiers: `20`
- Time range: `2016-12-31T23:00:01Z` to `2017-01-01T23:00:00Z`
- Raw latitude range: `48.04491` to `54.86559`
- Raw longitude range: `-1.63882` to `10.54504`
- Raw altitude range: `-1000` to `41025`
- Raw speed range: `100` to `517`
- Raw heading range: `0` to `359.9`
- Raw rate-of-climb range: `-5696` to `6144`

The `callsign` field is present for traceability but is not used by the model
pipeline. It has missing values in the raw CSV; the model loader selects only
`ts`, `icao`, `lat`, `lon`, `spd`, `hdg`, and `alt`.

## Model-Loaded Data Boundary

The publication benchmark uses `adsb.data.load_data`, which:

1. reads `sample_adsb_decoded.csv`;
2. selects the seven model fields `ts`, `icao`, `lat`, `lon`, `spd`, `hdg`,
   and `alt`;
3. drops rows with missing selected model fields;
4. keeps positive-altitude rows;
5. sorts by aircraft and timestamp.

The authoritative preflight report records:

- Loaded model rows: `216880`
- Rows after physical sanity filtering: `75238`
- Aircraft loaded by the model pipeline: `20`
- Aircraft after filtering: `19`
- Final benchmark uses all filtered aircraft: `num_aircraft=null` and
  `require_full_data=true`

The filtering step keeps rows satisfying `0 < spd < 300`, `0 < alt < 15000`,
and `0 <= hdg <= 360`.

## Split And Window Coverage

For seeds `42,43,44,45,46`, the preflight report verifies:

- train/validation/test aircraft counts of `13/2/4` per seed;
- zero train-validation, train-test, and validation-test aircraft overlap;
- nonempty malicious windows in train, validation, and mixed-attack test
  splits;
- zero malicious windows in the no-injection test split;
- nonempty malicious windows for gradual-drift, position-shift, and physically
  plausible spoofing test variants.

## External Validity Boundary

The profile is intentionally explicit about scope. The benchmark is an
offline, decoded ADS-B sample covering one UTC day and 20 raw aircraft
identifiers. It is sufficient for the archived CAT-AD robustness experiment but
does not prove transfer to all airspaces, dates, aircraft populations, sensor
networks, message fields, or operational environments.

## Machine-Checked Guardrail

`tools/verify_dataset_profile.ps1` checks the raw CSV header, byte size,
SHA-256, raw row count, aircraft count, timestamp range, key raw feature
ranges, preflight model-loaded counts, split leakage, malicious-window
coverage, and loader/filter code markers.

# ADS-B Publication Experiment Guide

This project uses the conda environment `testtorch`. Run Python only through:

```powershell
conda run -n testtorch python
```

## Single Full Paper Run

Use this command to train the baseline and CAT-AD model, generate paper tables/figures, and save checkpoints:

```powershell
conda run -n testtorch python -m adsb.run --csv sample_adsb_decoded.csv
```

Useful options:

```powershell
conda run -n testtorch python -m adsb.run --csv sample_adsb_decoded.csv --num-aircraft 100
conda run -n testtorch python -m adsb.run --csv sample_adsb_decoded.csv --skip-ablation
conda run -n testtorch python -m adsb.run --csv sample_adsb_decoded.csv --max-epochs 5
```

## Multi-Seed Benchmark

Use this command for publication-grade repeated runs. It writes per-seed logs, per-seed metrics, aggregate mean/std/95% confidence intervals, and a manifest with environment and provenance metadata.

Before spending GPU time on a full benchmark, run the data preflight. It uses the same filtering, aircraft split, sliding-window construction, and anomaly injection path as training, but stops before model training:

```powershell
conda run -n testtorch python tools\preflight_publication_data.py `
  --csv sample_adsb_decoded.csv `
  --seeds "42,43,44,45,46" `
  --output-dir outputs\publication_preflight
```

The preflight writes `preflight_report.json` and `preflight_report.md`; it exits nonzero if any seed lacks malicious windows, has aircraft leakage, uses an invalid window size for the malicious-label threshold, or violates the full-data requirement.

```powershell
conda run -n testtorch python -m adsb.run `
  --csv sample_adsb_decoded.csv `
  --benchmark-seeds "42,43,44,45,46" `
  --benchmark-output-dir outputs\multiseed_benchmark `
  --skip-ablation
```

Benchmark artifacts:

- `benchmark_manifest.json`: config, invocation, conda environment, package snapshot, provenance, per-seed split audits, artifact checksums, run logs, and artifact paths.
- `per_seed_metrics_long.csv`: one metric per row for statistical analysis.
- `per_seed_metrics_wide.csv`: one model/setting per row for spreadsheet inspection.
- `aggregate_summary.csv`: mean, std, stderr, and 95% confidence interval.
- `aggregate_selected_summary.tex`: LaTeX summary table for the paper.
- `paired_comparisons.csv`: paired CAT-AD vs baseline deltas, bootstrap confidence intervals, sign-flip p-values, Holm-adjusted p-values, BH-FDR q-values, and paired Cohen's dz.
- `paired_comparisons.tex`: LaTeX paired-comparison table with raw and adjusted p-values for the paper.
- `verification_report.json`: machine-readable artifact verification report, written by `--verify-write-report`.
- `verification_report.md`: human-readable artifact verification report, written by `--verify-write-report`.
- `runs\seed_<N>\run.log`: complete stdout/stderr for each seed.
- `runs\seed_<N>\run_record.json`: completion marker, resume signature, thresholds, validation scores, split/data summaries, and per-seed artifact paths.
- `runs\seed_<N>\per_seed_metrics_long.csv`: per-seed metric rows used when resuming interrupted benchmarks.

By default, benchmark runs capture per-seed logs into `run.log` to avoid Windows console encoding failures from legacy text. Use `--benchmark-stream-logs` only when you explicitly need live logs.

Benchmark runs are resumable by default. After each seed finishes, the runner writes seed-local completion artifacts; rerunning the same command reuses completed seeds only when the config, dataset SHA-256, source-code fingerprint, and hyperparameter signature match. Use `--benchmark-force-rerun` to deliberately rerun all seeds, or `--benchmark-no-resume` to ignore cached seed artifacts.

Inspect progress or a completed benchmark directory without restarting the experiment:

```powershell
conda run -n testtorch python tools\benchmark_status.py `
  --benchmark-dir outputs\publication_benchmark `
  --verify `
  --write-report
```

For final paper artifacts, include the matching preflight report and strict publication checks:

```powershell
conda run -n testtorch python tools\benchmark_status.py `
  --benchmark-dir outputs\publication_benchmark `
  --preflight-report outputs\publication_benchmark\preflight_report.json `
  --strict-publication `
  --write-report
```

Verify the benchmark artifacts before copying numbers into the paper:

```powershell
conda run -n testtorch python -m adsb.run `
  --verify-benchmark outputs\multiseed_benchmark `
  --verify-require-physical-metrics `
  --verify-require-primary-claims `
  --verify-write-report
```

For final paper numbers, use the strict publication gate:

```powershell
conda run -n testtorch python -m adsb.run `
  --verify-benchmark outputs\multiseed_benchmark `
  --verify-preflight-report outputs\publication_preflight\preflight_report.json `
  --verify-strict-publication `
  --verify-write-report
```

Strict verification requires at least five independent seeds, deterministic benchmark mode, CUDA determinism metadata with `CUBLAS_WORKSPACE_CONFIG=:4096:8` or `:16:8` when CUDA is used, complete physical metrics, supported primary CAT-AD claims, no `--benchmark-max-epochs` cap, no `--num-aircraft` subset, `CONDA_DEFAULT_ENV=testtorch`, and per-seed logs. The primary claim gate requires nonnegative clean F1 improvement and positive ASR/PV-ASR reductions for the standard and physical attacks.

To run the benchmark and strict gate as one end-to-end command:

```powershell
conda run -n testtorch python tools\run_publication_gate.py `
  --csv sample_adsb_decoded.csv `
  --seeds "42,43,44,45,46" `
  --output-dir outputs\publication_benchmark
```

This command exits nonzero if strict verification fails and writes `verification_report.json` plus `verification_report.md`.
It also runs the publication data preflight first unless `--skip-preflight` is supplied.
The one-command gate is resumable as well; add `--force-rerun` only when you intentionally want to discard matching completed seed runs.

For smoke tests or tiny subsets, omit `--verify-require-physical-metrics` and `--verify-require-primary-claims` because the sample can contain too few attacked malicious windows to populate PVR/PV-ASR rows or support the paper claims.

In `paired_comparisons.csv`, positive improvement always means CAT-AD is better. For F1 this is `CAT-AD - baseline`; for ASR, FAR, PVR, and PV-ASR this is `baseline - CAT-AD`. The raw p-value column is a two-sided paired sign-flip test across seeds; `p_holm` controls family-wise error across all paired rows, `q_bh_fdr` controls false discovery rate, and `cohens_dz` reports the paired standardized mean improvement.
The same statistical definitions and the machine-readable primary-claim gate are recorded in `benchmark_manifest.json` under the `statistics` field. The `invocation` field records argv, Python executable, and working directory; `environment.conda` records the active conda environment. The `environment.packages` field records a full Python package snapshot, a package-list SHA-256, and key versions for torch, numpy, pandas, scikit-learn, and matplotlib. The `provenance` field records the dataset SHA-256, a source-code fingerprint over experiment files, and the effective hyperparameter snapshot used for the benchmark. The `artifact_integrity` field records SHA-256 checksums for the benchmark CSV/TEX files and per-seed logs; verification recomputes these hashes to detect post-run edits. Per-seed run/log paths include benchmark-relative fields so a copied artifact directory can be verified independently of its original location. Each run also records a `data_summary` with row/aircraft counts before and after filtering/subsetting, plus a `split_summary` with train/validation/test aircraft IDs, split hashes, overlap counts, and window/label counts so the benchmark can be audited for full-data usage and aircraft-level leakage.

## Same-Protocol Published-Model Comparison

The literature benchmark trains protocol-aligned reimplementations of three
concrete ADS-B anomaly detectors published in 2021--2022 and selected as a
representative, non-exhaustive method-family sample from the rolling
2019-07-15--2026-07-15 publication window. They use the same five aircraft
splits as the archived BiLSTM-ERM/CAT-AD benchmark:

- Fried--Last differencing recurrent autoencoder (2021);
- VAE--SVDD (2021);
- Contextual Autoencoder with phase-specific decoders (2022).

Run the full comparison with:

```powershell
conda run -n testtorch python -m adsb.literature_benchmark `
  --csv sample_adsb_decoded.csv `
  --seeds "42,43,44,45,46" `
  --epochs 30 `
  --reference-benchmark outputs\publication_benchmark `
  --output-dir outputs\literature_benchmark `
  --force
```

The runner checks the dataset SHA-256 and each seed's aircraft/window split
against `outputs/publication_benchmark` before training. The published
one-class models receive the benign view of the shared train/validation
windows; BiLSTM-ERM and CAT-AD retain the labeled view required by their
supervised objectives.

Reproduce the attack-resolution counterexample, build the paper-facing clean
detection table, and verify its hashes with:

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

The manuscript table reports clean F1, precision, recall, and FAR only. The
training records retain exploratory attack outputs, but those values are not
used as cross-family robustness evidence: the fixed classifier-PGD step size
overshoots a reconstruction-score surface, and a finer step reverses the
apparent zero-ASR result. The adversarial claims therefore remain confined to
the pre-specified BiLSTM-ERM--CAT-AD comparison.

## Smoke Test

This verifies the benchmark pipeline without claiming meaningful performance:

```powershell
conda run -n testtorch python -m adsb.run `
  --benchmark-seeds 1 `
  --benchmark-max-epochs 0 `
  --num-aircraft 5 `
  --window-size 3 `
  --skip-ablation `
  --benchmark-output-dir outputs\smoke_multiseed_benchmark
```

Then verify the smoke artifacts:

```powershell
conda run -n testtorch python -m adsb.run --verify-benchmark outputs\smoke_multiseed_benchmark
```

## Notes

- Full benchmark runs should use multiple independent seeds and the full dataset unless the paper explicitly studies low-data regimes.
- Ablation is intentionally off in the multi-seed command above because it multiplies runtime. Run Table V ablations separately with the single full paper run, or enable them with benchmark only when enough compute is available.
- Benchmark mode uses deterministic PyTorch settings by default. Use `--benchmark-nondeterministic` only for speed-oriented exploratory runs.

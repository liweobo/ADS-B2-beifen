# CAT-AD Compute Resource Audit

This audit records the execution boundary for the corrected five-seed CAT-AD
benchmark. It verifies the archived hardware, environment, per-seed records,
logs, and metric counts without inventing a continuous runtime from resumed
sessions.

## Source Evidence

- outputs/publication_benchmark/benchmark_manifest.json
- outputs/publication_benchmark/benchmark_status.json
- outputs/publication_benchmark/verification_report.json
- outputs/publication_benchmark/runs/seed_*/run_record.json
- outputs/publication_benchmark/runs/seed_*/run.log

## Observed Hardware And Environment

| Item | Recorded value |
| --- | --- |
| Conda environment | testtorch |
| Python | 3.9.21 |
| torch | 2.5.1 |
| CUDA available | true |
| CUDA version | 12.4 |
| cuDNN version | 90100 |
| GPU | NVIDIA GeForce RTX 4070 Laptop GPU |
| Deterministic mode | true |
| Log capture | capture_logs=true |
| Model checkpoint saving | save_models=false |

The manifest also records the package snapshot, source fingerprint, dataset
SHA-256, hyperparameters, and generated-artifact checksums.

## Resumable Execution Boundary

The corrected benchmark was completed with the built-in resume mechanism:
seeds 42--44 were produced in the first invocation, and seeds 45--46 were
executed by the final invocation after signature validation. Every run record
contains the same resume signature, and the final manifest records three reused
seeds and two executed seeds.

The five corrected completion records span 2026-07-12 and 2026-07-13. Because
the benchmark crossed invocations and an interrupted terminal session, a
continuous wall-clock duration is not reconstructed from those timestamps.
This is more accurate than treating elapsed calendar time as active compute.

Each seed has a completed run record, a CUDA run log, and 152 metric rows.
Across five seeds the benchmark contains 760 per-seed metric rows, 152 aggregate
rows, and 14 paired-comparison rows.

## Review Boundary

The hardware facts are observed on this workstation and are not a
cross-hardware guarantee. Reviewers can use the fast path to verify archived
artifacts without retraining; the full benchmark rerun remains the expensive
path. The archive supports interruption-safe continuation while rejecting
stale runs whose code, data, or hyperparameter signature differs.

## Machine-Checked Guardrail

tools/verify_compute_resource_audit.ps1 checks the audit against the manifest,
status report, strict verification report, five per-seed records, five logs,
metric counts, and the manuscript wording.

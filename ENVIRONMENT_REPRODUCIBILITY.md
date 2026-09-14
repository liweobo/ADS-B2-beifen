# CAT-AD Environment Reproducibility Statement

This statement records the local environment boundary used by the CAT-AD
publication benchmark and the no-download review workflow.

## Required Execution Environment

All Python commands for this repository must run through the Windows conda
environment `testtorch`:

```powershell
conda run -n testtorch python
```

The no-download workflow does not create or modify this environment. It checks
that the already available environment matches the key package versions
recorded in `outputs/publication_benchmark/benchmark_manifest.json`.

## Key Package Versions

The current benchmark manifest records:

| Package | Version |
| --- | --- |
| Python | `3.9.21` |
| torch | `2.5.1` |
| numpy | `2.0.1` |
| pandas | `2.2.3` |
| scikit-learn | `1.6.1` |
| matplotlib | `3.9.4` |

The manifest also records CUDA availability, CUDA/cuDNN metadata, deterministic
settings, package snapshot SHA-256, source-code fingerprint, hyperparameter
snapshot, dataset SHA-256, and artifact checksums.

## Determinism Boundary

The benchmark manifest records deterministic execution settings:

- `torch_deterministic_algorithms=true`
- `cudnn_deterministic=true`
- `cudnn_benchmark=false`
- `cuda_matmul_allow_tf32=false`
- `cudnn_allow_tf32=false`

These settings improve run-to-run reproducibility for the evaluated artifact,
but they do not turn the empirical robustness result into a formal proof or a
hardware-independent certificate.

## Verification Command

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_environment_reproducibility.ps1
```

Expected output includes:

- `environment_reproducibility=PASSED`
- `conda_env=testtorch`
- `packages_checked=5`
- `determinism_markers_checked=5`

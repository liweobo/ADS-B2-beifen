"""Reproduce the step-size counterexample used to scope literature reporting."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import torch

from adsb.attacks import pgd
from adsb.data import filter_data, load_data
from adsb.dataloading import prepare_train_val_test_loaders
from adsb.literature_models import build_literature_model
from adsb.train_constants import EVAL_ATTACK_EPS, PGD_ALPHA, PGD_STEPS, WINDOW_SIZE
from adsb.utils import set_seed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evaluate_probability(model, x: torch.Tensor, threshold: float) -> dict[str, float]:
    with torch.no_grad():
        probability = torch.softmax(model(x), dim=1)[:, 1]
    return {
        "mean_malicious_probability": float(probability.mean().item()),
        "min_malicious_probability": float(probability.min().item()),
        "max_malicious_probability": float(probability.max().item()),
        "asr_at_validation_threshold": float((probability < threshold).float().mean().item()),
    }


def run_audit(
    *,
    csv_path: str | Path,
    benchmark_dir: str | Path,
    output_path: str | Path,
    seed: int = 42,
) -> dict[str, object]:
    dataset = Path(csv_path).resolve()
    benchmark = Path(benchmark_dir).resolve()
    output = Path(output_path).resolve()
    checkpoint_path = benchmark / "runs" / f"seed_{seed}" / "fried_lstm_ae" / "checkpoint.pt"
    if not checkpoint_path.is_file():
        raise FileNotFoundError(f"Missing literature checkpoint: {checkpoint_path}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    set_seed(int(seed))
    pack = prepare_train_val_test_loaders(
        filter_data(load_data(dataset)),
        pin_memory=False,
        random_state=int(seed),
        window_size=WINDOW_SIZE,
    )
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    model = build_literature_model(
        "fried_lstm_ae",
        sequence_length=WINDOW_SIZE,
        norm_mean=pack.norm_mean,
        norm_std=pack.norm_std,
        device=device,
    )
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()

    x, y = next(iter(pack.test_loader))
    malicious = y == 1
    x = x[malicious].to(device)
    y = y[malicious].to(device)
    if len(y) == 0:
        raise RuntimeError("The deterministic diagnostic batch contains no malicious samples.")
    threshold = float(checkpoint["threshold"])
    with torch.no_grad():
        clean_probability = torch.softmax(model(x), dim=1)[:, 1]

    coarse_x = pgd(
        model,
        x,
        y,
        eps=EVAL_ATTACK_EPS,
        m=pack.norm_mean,
        s=pack.norm_std,
        alpha=PGD_ALPHA,
        steps=PGD_STEPS,
    )
    fine_alpha = 0.003
    fine_steps = 40
    fine_x = pgd(
        model,
        x,
        y,
        eps=EVAL_ATTACK_EPS,
        m=pack.norm_mean,
        s=pack.norm_std,
        alpha=fine_alpha,
        steps=fine_steps,
    )
    with torch.no_grad():
        coarse_probability = torch.softmax(model(coarse_x), dim=1)[:, 1]
        fine_probability = torch.softmax(model(fine_x), dim=1)[:, 1]

    clean = _evaluate_probability(model, x, threshold)
    coarse = _evaluate_probability(model, coarse_x, threshold)
    fine = _evaluate_probability(model, fine_x, threshold)
    coarse["fraction_probability_decreased_vs_clean"] = float(
        (coarse_probability < clean_probability).float().mean().item()
    )
    fine["fraction_probability_decreased_vs_clean"] = float(
        (fine_probability < clean_probability).float().mean().item()
    )
    passed = (
        coarse["mean_malicious_probability"] > clean["mean_malicious_probability"]
        and coarse["fraction_probability_decreased_vs_clean"] < 0.05
        and fine["mean_malicious_probability"] < clean["mean_malicious_probability"]
        and fine["fraction_probability_decreased_vs_clean"] > 0.95
        and fine["asr_at_validation_threshold"] > coarse["asr_at_validation_threshold"]
    )
    if not passed:
        raise RuntimeError("The expected cross-objective PGD step-size counterexample was not reproduced.")

    payload: dict[str, object] = {
        "status": "passed",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "deterministic first malicious test batch; diagnostic only",
        "conclusion": (
            "The fixed classifier-PGD step size overshoots the Fried--Last reconstruction-score "
            "surface; its zero ASR is not admissible robustness evidence."
        ),
        "seed": int(seed),
        "model": "Fried--Last diff. LSTM-AE",
        "malicious_samples": int(len(y)),
        "validation_threshold": threshold,
        "dataset_sha256": _sha256(dataset),
        "checkpoint_sha256": _sha256(checkpoint_path),
        "clean": clean,
        "fixed_classifier_pgd": {
            "eps": float(EVAL_ATTACK_EPS),
            "alpha": float(PGD_ALPHA),
            "steps": int(PGD_STEPS),
            **coarse,
        },
        "finer_step_diagnostic": {
            "eps": float(EVAL_ATTACK_EPS),
            "alpha": fine_alpha,
            "steps": fine_steps,
            **fine,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default="sample_adsb_decoded.csv")
    parser.add_argument("--benchmark-dir", default="outputs/literature_benchmark")
    parser.add_argument(
        "--output",
        default="outputs/literature_benchmark/attack_resolution_audit.json",
    )
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    payload = run_audit(
        csv_path=args.csv,
        benchmark_dir=args.benchmark_dir,
        output_path=args.output,
        seed=args.seed,
    )
    print(
        "literature_attack_resolution=PASSED "
        f"samples={payload['malicious_samples']} seed={payload['seed']}"
    )


if __name__ == "__main__":
    main()

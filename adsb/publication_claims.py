"""Machine-readable publication claim specifications."""

from __future__ import annotations

from typing import Any


PRIMARY_CLAIMS: tuple[dict[str, Any], ...] = (
    {
        "setting": "Clean",
        "metric": "f1",
        "relation": "nonnegative",
        "threshold": 0.0,
        "description": "CAT-AD should not reduce clean F1.",
    },
    {
        "setting": "Standard PGD",
        "metric": "asr",
        "relation": "positive",
        "threshold": 0.0,
        "description": "CAT-AD should reduce standard PGD attack success rate.",
    },
    {
        "setting": "Projection-based phys-PGD",
        "metric": "asr",
        "relation": "positive",
        "threshold": 0.0,
        "description": "CAT-AD should reduce projection-based phys-PGD attack success rate.",
    },
    {
        "setting": "Penalty-based phys-PGD",
        "metric": "asr",
        "relation": "positive",
        "threshold": 0.0,
        "description": "CAT-AD should reduce penalty-based phys-PGD attack success rate.",
    },
    {
        "setting": "Projection-based phys-PGD",
        "metric": "conditional_pv_asr_start_valid",
        "relation": "positive",
        "threshold": 0.0,
        "description": "CAT-AD should reduce physically valid projection attack success among valid starts.",
    },
    {
        "setting": "Penalty-based phys-PGD",
        "metric": "conditional_pv_asr_start_valid",
        "relation": "positive",
        "threshold": 0.0,
        "description": "CAT-AD should reduce physically valid penalty attack success among valid starts.",
    },
)


def primary_claim_manifest() -> list[dict[str, Any]]:
    return [dict(claim) for claim in PRIMARY_CLAIMS]


__all__ = ["PRIMARY_CLAIMS", "primary_claim_manifest"]

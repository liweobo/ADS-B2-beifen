"""Canonical, publication-facing names for CAT-AD experiments.

Archived result files retain legacy schema keys such as ``Baseline``,
``Proposed``, and ``Standard PGD``. The mappings below deliberately preserve
those keys while presenting precise, stable names in the manuscript, tables,
and figures.
"""

from __future__ import annotations


ERM_BILSTM_DISPLAY_NAME = "BiLSTM-ERM"
CATAD_DISPLAY_NAME = "CAT-AD"
NORM_BOUNDED_PGD_DISPLAY_NAME = "Norm-bounded PGD"


MODEL_NAME_MAP = {
    "Baseline": ERM_BILSTM_DISPLAY_NAME,
    "Standard BiLSTM": ERM_BILSTM_DISPLAY_NAME,
    "BiLSTM-ERM": ERM_BILSTM_DISPLAY_NAME,
    "Proposed": CATAD_DISPLAY_NAME,
    "CAT-AD": CATAD_DISPLAY_NAME,
    "Full proposed method": CATAD_DISPLAY_NAME,
    "Proposed method": CATAD_DISPLAY_NAME,
}

SETTING_NAME_MAP = {
    "Clean": "Unperturbed",
    "Unperturbed": "Unperturbed",
    "Standard PGD": NORM_BOUNDED_PGD_DISPLAY_NAME,
    "Unconstrained PGD": NORM_BOUNDED_PGD_DISPLAY_NAME,
    "Norm-bounded PGD": NORM_BOUNDED_PGD_DISPLAY_NAME,
    "Projection-based phys-PGD": "Projection-based Phys-PGD",
    "Projection-based Phys-PGD": "Projection-based Phys-PGD",
    "Penalty-based phys-PGD": "Penalty-based Phys-PGD",
    "Penalty-based Phys-PGD": "Penalty-based Phys-PGD",
}

SHORT_SETTING_NAME_MAP = {
    "Unperturbed": "Unperturbed",
    "Norm-bounded PGD": "Norm-PGD",
    "Projection-based Phys-PGD": "Proj. Phys-PGD",
    "Penalty-based Phys-PGD": "Penalty Phys-PGD",
}

ABLATION_NAME_MAP = {
    "Standard training": "ERM",
    "Std.": "ERM",
    "ERM": "ERM",
    "Vanilla PGD adversarial training": "PGD-AT",
    "PGD-AT": "PGD-AT",
    "Projection-based phys-PGD adversarial training": "Projection Phys-PGD-AT",
    "Proj-Phys-AT": "Projection Phys-PGD-AT",
    "Projection Phys-PGD-AT": "Projection Phys-PGD-AT",
    "Penalty-based phys-PGD w/o consistency": "Penalty Phys-PGD-AT",
    "Penalty-based phys-PGD without consistency": "Penalty Phys-PGD-AT",
    "Penalty-Phys-AT": "Penalty Phys-PGD-AT",
    "Penalty Phys-PGD-AT": "Penalty Phys-PGD-AT",
    "Output consistency only": "+Prediction Consistency",
    "+OutCons": "+Prediction Consistency",
    "+Prediction Consistency": "+Prediction Consistency",
    "Representation consistency only": "+Feature Consistency",
    "+RepCons": "+Feature Consistency",
    "+Feature Consistency": "+Feature Consistency",
    "Full proposed method": "CAT-AD",
    "CAT-AD": "CAT-AD",
    "Full proposed method w/o differential features": r"CAT-AD w/o $\Delta X$",
    "Full proposed method without differential features": r"CAT-AD w/o $\Delta X$",
    r"CAT-AD w/o $\Delta X$": r"CAT-AD w/o $\Delta X$",
}

METRIC_NAME_MAP = {
    "Accuracy": "Acc.",
    "acc": "Acc.",
    "Precision": "Prec.",
    "precision": "Prec.",
    "Recall": "Recall",
    "F1-score": "F1-score",
    "F1": "F1-score",
    "FAR": "FAR",
    "False alarm rate": "FAR",
    "ASR": "ASR",
    "Attack success rate": "ASR",
    "PVR": "PVR",
    "Physical violation rate": "PVR",
    "PV-ASR": "PV-ASR",
    "Physically valid attack success rate": "PV-ASR",
    "Pre-attack PVR": "Pre-PVR",
    "Valid-start rate": r"Valid-start rate",
    "New-PVR|valid-start": "New-PVR (valid start)",
    "ASR|valid-start": "ASR (valid start)",
    "PV-ASR|valid-start": "PV-ASR (valid start)",
}


def model_display_name(name: str) -> str:
    return MODEL_NAME_MAP.get(str(name), str(name))


def setting_display_name(name: str, short: bool = False) -> str:
    full = SETTING_NAME_MAP.get(str(name), str(name))
    return SHORT_SETTING_NAME_MAP.get(full, full) if short else full


def attack_display_name(name: str, short: bool = False) -> str:
    return setting_display_name(name, short=short)


def ablation_display_name(name: str) -> str:
    return ABLATION_NAME_MAP.get(str(name), str(name))


def metric_display_name(name: str) -> str:
    return METRIC_NAME_MAP.get(str(name), str(name))


def canonical_model_key(name: str) -> str:
    name = str(name)
    if name in {"Standard BiLSTM", "BiLSTM-ERM"}:
        return "Baseline"
    if name == "CAT-AD":
        return "Proposed"
    return name


def canonical_setting_key(name: str) -> str:
    name = str(name)
    aliases = {
        "Unperturbed": "Clean",
        "Unconstrained PGD": "Standard PGD",
        "Norm-bounded PGD": "Standard PGD",
        "Norm-PGD": "Standard PGD",
        "PGD": "Standard PGD",
        "Proj. Phys-PGD": "Projection-based phys-PGD",
        "Projection-based Phys-PGD": "Projection-based phys-PGD",
        "Penalty Phys-PGD": "Penalty-based phys-PGD",
        "Penalty-based Phys-PGD": "Penalty-based phys-PGD",
    }
    return aliases.get(name, name)

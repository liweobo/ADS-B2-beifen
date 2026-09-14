"""Shared plotting style for CAT-AD paper figures."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt


MODEL_COLORS = {
    "BiLSTM-ERM": "#6F8FA8",
    "Standard BiLSTM": "#6F8FA8",
    "Baseline": "#6F8FA8",
    "CAT-AD": "#C78F4B",
    "Proposed": "#C78F4B",
}

MODEL_MARKERS = {
    "BiLSTM-ERM": "o",
    "Standard BiLSTM": "o",
    "Baseline": "o",
    "CAT-AD": "s",
    "Proposed": "s",
}


def setup_paper_style() -> None:
    """Apply compact, editable-font Matplotlib settings for two-column papers."""
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif", "serif"],
            "mathtext.fontset": "dejavuserif",
            "axes.unicode_minus": False,
            "figure.dpi": 150,
            "savefig.dpi": 300,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
            "axes.labelsize": 8.5,
            "axes.titlesize": 9.0,
            "xtick.labelsize": 7.5,
            "ytick.labelsize": 7.5,
            "legend.fontsize": 7.5,
            "lines.linewidth": 1.6,
            "lines.markersize": 4.0,
            "axes.linewidth": 0.8,
            "grid.linewidth": 0.5,
        }
    )


def save_figure(fig, base_path: str | Path) -> dict[str, Path]:
    """Save a figure as PDF, SVG, and PNG using the same semantic base path."""
    base = Path(base_path)
    base.parent.mkdir(parents=True, exist_ok=True)
    paths = {
        "pdf": base.with_suffix(".pdf"),
        "svg": base.with_suffix(".svg"),
        "png": base.with_suffix(".png"),
    }
    for suffix, path in paths.items():
        kwargs = {"bbox_inches": "tight", "pad_inches": 0.02}
        if suffix == "png":
            kwargs["dpi"] = 300
        fig.savefig(path, **kwargs)
    return paths

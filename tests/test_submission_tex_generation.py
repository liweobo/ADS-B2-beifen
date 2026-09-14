from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from adsb.benchmark import _write_paired_comparisons_tex, _write_selected_tex
from adsb.paper_tables import write_table4_physical_feasibility


class SubmissionTexGenerationTest(unittest.TestCase):
    def test_statistical_tables_escape_percent_and_keep_two_panels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            aggregate_path = root / "aggregate.tex"
            _write_selected_tex(
                aggregate_path,
                [
                    {
                        "model": "Baseline",
                        "setting": "Clean",
                        "metric": "f1",
                        "mean": 0.8,
                        "std": 0.1,
                        "ci95_low": 0.7,
                        "ci95_high": 0.9,
                        "ci95_half_width": 0.1,
                    }
                ],
            )
            aggregate = aggregate_path.read_text(encoding="utf-8")
            self.assertIn(r"95\% confidence-interval", aggregate)
            self.assertIn("not clipped", aggregate)
            self.assertNotIn(r"\resizebox", aggregate)

            paired_path = root / "paired.tex"
            _write_paired_comparisons_tex(
                paired_path,
                [
                    {
                        "setting": setting,
                        "metric": metric,
                        "n": 5,
                        "mean_improvement": 0.1,
                        "ci95_low": 0.05,
                        "ci95_high": 0.15,
                        "p_two_sided_sign_flip": 0.0625,
                        "p_holm": 0.75,
                        "q_bh_fdr": 0.0833,
                        "cohens_dz": 2.0,
                    }
                    for setting, metric in (
                        ("Clean", "f1"),
                        ("Standard PGD", "asr"),
                        ("Projection-based phys-PGD", "asr"),
                        ("Penalty-based phys-PGD", "asr"),
                        ("Projection-based phys-PGD", "conditional_pv_asr_start_valid"),
                        ("Penalty-based phys-PGD", "conditional_pv_asr_start_valid"),
                    )
                ],
            )
            paired = paired_path.read_text(encoding="utf-8")
            self.assertIn("(a) Effect estimates", paired)
            self.assertIn("(b) Multiplicity-adjusted inference", paired)
            self.assertIn(r"95\% CI", paired)
            self.assertIn("2.0000", paired)
            self.assertIn("six pre-specified primary claims", paired)

    def test_physical_table_uses_readable_two_panel_layout(self) -> None:
        results = {}
        for model in ("Baseline", "Proposed"):
            for setting in (
                "Standard PGD",
                "Projection-based phys-PGD",
                "Penalty-based phys-PGD",
            ):
                results[(model, setting)] = {
                    "pvr": 0.9,
                    "pv_asr": 0.1,
                    "position_vr": 0.7,
                    "alt_vr": 0.0,
                    "vel_vr": 0.01,
                    "head_vr": 0.8,
                }

        with tempfile.TemporaryDirectory() as tmp:
            _, tex_path = write_table4_physical_feasibility(results, Path(tmp))
            tex = tex_path.read_text(encoding="utf-8")
            self.assertIn("(a) Aggregate physical feasibility", tex)
            self.assertIn("(b) Constraint-specific violation rates", tex)
            self.assertIn("Model & Attack & Post-PVR & New-PVR", tex)
            self.assertIn("Pos. VR & Alt. VR & Speed VR & Head. VR", tex)
            self.assertIn(r"\raggedright\footnotesize", tex)
            self.assertNotIn(r"\resizebox", tex)


if __name__ == "__main__":
    unittest.main()

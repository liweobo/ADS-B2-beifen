import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from adsb.literature_report import COLUMNS, MODEL_ORDER, _clean_index, _write_table


def _aggregate_rows(n: int = 5):
    rows = []
    for model_index, model in enumerate(MODEL_ORDER):
        for metric, _label, higher_better in COLUMNS:
            base = 0.5 + 0.05 * model_index
            mean = base if higher_better else 0.5 - 0.05 * model_index
            rows.append(
                {
                    "model": model,
                    "setting": "Clean",
                    "metric": metric,
                    "n": str(n),
                    "mean": str(mean),
                    "ci95_half_width": "0.01",
                }
            )
    return rows


class LiteratureReportTest(unittest.TestCase):
    def test_clean_index_requires_all_seeds(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "expected 5"):
            _clean_index(_aggregate_rows(n=4), seed_count=5)

    def test_unperturbed_table_contains_published_models_but_no_attack_columns(self) -> None:
        index = _clean_index(_aggregate_rows(), seed_count=5)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "table.tex"
            _write_table(path, index, seed_count=5)
            text = path.read_text(encoding="utf-8")
        self.assertIn("fried2021autoencoders", text)
        self.assertIn("luo2021vaesvdd", text)
        self.assertIn("chevrot2022cae", text)
        self.assertIn("BiLSTM-ERM", text)
        self.assertIn("Fried--Last Differenced", text)
        self.assertIn("Fried--Last LSTM-AE (2021)", text)
        self.assertIn("Same-protocol unperturbed detection", text)
        self.assertNotIn("Standard BiLSTM", text)
        self.assertNotIn("PGD ASR", text)
        self.assertIn(r"\label{tab:literature_detection}", text)

    def test_clean_index_normalizes_legacy_archive_model_names(self) -> None:
        rows = _aggregate_rows()
        for row in rows:
            if row["model"] == "BiLSTM-ERM":
                row["model"] = "Standard BiLSTM"
            elif row["model"] == "Fried--Last Differenced LSTM-AE":
                row["model"] = "Fried--Last diff. LSTM-AE"
        index = _clean_index(rows, seed_count=5)
        self.assertIn(("BiLSTM-ERM", "f1"), index)
        self.assertIn(("Fried--Last Differenced LSTM-AE", "far"), index)


if __name__ == "__main__":
    unittest.main()

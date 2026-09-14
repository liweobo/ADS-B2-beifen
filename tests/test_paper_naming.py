import unittest

from adsb.paper_naming import (
    canonical_model_key,
    canonical_setting_key,
    model_display_name,
    setting_display_name,
)


class PaperNamingTest(unittest.TestCase):
    def test_legacy_model_keys_have_unambiguous_publication_names(self) -> None:
        self.assertEqual(model_display_name("Baseline"), "BiLSTM-ERM")
        self.assertEqual(model_display_name("Standard BiLSTM"), "BiLSTM-ERM")
        self.assertEqual(model_display_name("Proposed"), "CAT-AD")
        self.assertEqual(canonical_model_key("BiLSTM-ERM"), "Baseline")

    def test_norm_bounded_pgd_name_preserves_legacy_archive_key(self) -> None:
        self.assertEqual(setting_display_name("Standard PGD"), "Norm-bounded PGD")
        self.assertEqual(setting_display_name("Unconstrained PGD"), "Norm-bounded PGD")
        self.assertEqual(setting_display_name("Standard PGD", short=True), "Norm-PGD")
        self.assertEqual(canonical_setting_key("Norm-bounded PGD"), "Standard PGD")


if __name__ == "__main__":
    unittest.main()

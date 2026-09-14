from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from tools.build_external_validation_samples import (
    build_sample,
    convert_chunk,
    deterministic_selection,
    resample_tracks,
)


class ExternalSnapshotSamplesTest(unittest.TestCase):
    def test_unit_conversion_and_filtering(self) -> None:
        chunk = pd.DataFrame(
            {
                "time": [1, 2],
                "icao24": ["abc123", "bad999"],
                "lat": [1.0, 2.0],
                "lon": [3.0, 4.0],
                "velocity": [100.0, 200.0],
                "heading": [90.0, 90.0],
                "vertrate": [1.0, 0.0],
                "callsign": [" TEST ", "BAD"],
                "baroaltitude": [1000.0, 5000.0],
            }
        )
        converted = convert_chunk(chunk)
        self.assertEqual(converted["icao"].tolist(), ["ABC123"])
        self.assertAlmostEqual(float(converted.iloc[0]["spd"]), 194.38444924406)
        self.assertAlmostEqual(float(converted.iloc[0]["alt"]), 3280.8398950131)
        self.assertEqual(converted.iloc[0]["callsign"], "TEST")

    def test_selection_and_manifest_are_deterministic(self) -> None:
        self.assertEqual(
            deterministic_selection("source.csv", ["b", "a", "c"], 2),
            deterministic_selection("source.csv", ["c", "b", "a"], 2),
        )
        rows = []
        for icao in ("a", "b", "c"):
            for step in range(30):
                rows.append(
                    {
                        "time": step * 10,
                        "icao24": icao,
                        "lat": 1.0,
                        "lon": 2.0,
                        "velocity": 100.0,
                        "heading": 90.0,
                        "vertrate": 0.0,
                        "callsign": icao,
                        "baroaltitude": 1000.0,
                    }
                )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.csv"
            output = root / "sample.csv"
            manifest = root / "manifest.json"
            pd.DataFrame(rows).to_csv(source, index=False)
            first = build_sample(
                source,
                output,
                manifest,
                aircraft_count=2,
                min_segment_points=30,
                gap_seconds=60,
                resample_seconds=None,
                chunksize=25,
            )
            first_bytes = output.read_bytes()
            second = build_sample(
                source,
                output,
                manifest,
                aircraft_count=2,
                min_segment_points=30,
                gap_seconds=60,
                resample_seconds=None,
                chunksize=17,
            )
            self.assertEqual(first_bytes, output.read_bytes())
            self.assertEqual(first["output"]["sha256"], second["output"]["sha256"])
            self.assertEqual(first["output"]["rows"], 60)

    def test_resampling_uses_circular_heading_interpolation(self) -> None:
        frame = pd.DataFrame(
            {
                "ts": [0.0, 10.0],
                "icao": ["ABC123", "ABC123"],
                "lat": [1.0, 2.0],
                "lon": [3.0, 4.0],
                "alt": [1000.0, 1100.0],
                "spd": [100.0, 110.0],
                "hdg": [350.0, 10.0],
                "roc": [0.0, 0.0],
                "callsign": ["TEST", "TEST"],
            }
        )
        resampled = resample_tracks(frame, interval_seconds=1.0, gap_seconds=60.0)
        self.assertEqual(len(resampled), 11)
        self.assertAlmostEqual(float(resampled.iloc[5]["hdg"]), 0.0, places=6)
        self.assertAlmostEqual(float(resampled.iloc[5]["lat"]), 1.5, places=6)


if __name__ == "__main__":
    unittest.main()

"""Compute max values for ADS-B differential features and save them."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adsb.data import (  # noqa: E402
    TRACK_GAP_SECONDS,
    assign_track_segments,
    filter_data,
    heading_to_sincos,
    load_data,
    subset_df_by_aircraft,
)
from adsb.train_constants import SEED, WINDOW_SIZE  # noqa: E402


DIFF_FEATURE_NAMES = ("d_lat", "d_lon", "d_alt", "d_spd", "d_sin_hdg", "d_cos_hdg")


def _track_raw_features(g: pd.DataFrame) -> np.ndarray:
    base = g[["lat", "lon", "alt", "spd"]].values.astype(np.float32)
    hs, hc = heading_to_sincos(g["hdg"].values)
    return np.concatenate([base, hs.reshape(-1, 1), hc.reshape(-1, 1)], axis=1).astype(np.float32)


def _collect_time_scaled_differentials(
    df: pd.DataFrame,
    *,
    window_size: int,
    gap_seconds: float,
) -> np.ndarray:
    """
    Collect differential features by track segment.

    For adjacent points with ``dt = ts[t] - ts[t-1]``:
    - if ``dt > 1``, use ``delta / dt``;
    - otherwise, keep the original ``delta``.

    The first point of each segment keeps zero differentials, matching ``build_raw_windows``.
    """
    df = assign_track_segments(df, gap_seconds=gap_seconds)
    parts: list[np.ndarray] = []
    for _track_id, g in df.groupby("track_id", sort=False):
        g = g.sort_values("ts")
        raw = _track_raw_features(g)
        if len(raw) < int(window_size):
            continue

        diff = np.zeros_like(raw, dtype=np.float32)
        delta = raw[1:] - raw[:-1]
        dt = np.diff(g["ts"].values.astype(np.float32)).reshape(-1, 1)
        scale = np.where(dt > 1.0, dt, 1.0).astype(np.float32)
        diff[1:] = delta / scale
        parts.append(diff)

    if not parts:
        return np.empty((0, 6), dtype=np.float32)
    return np.concatenate(parts, axis=0)


def compute_differential_feature_stats(
    csv_path: str | Path,
    *,
    window_size: int = WINDOW_SIZE,
    gap_seconds: float = TRACK_GAP_SECONDS,
    num_aircraft: int | None = None,
    random_state: int = SEED,
) -> pd.DataFrame:
    df = filter_data(load_data(csv_path))
    df = subset_df_by_aircraft(df, max_aircraft=num_aircraft, random_state=random_state)
    diff = _collect_time_scaled_differentials(
        df, window_size=window_size, gap_seconds=gap_seconds
    )
    if len(diff) == 0:
        raise ValueError("No valid track segments were found; try a smaller window_size or more aircraft.")
    rows = []
    for i, name in enumerate(DIFF_FEATURE_NAMES):
        values = diff[:, i]
        rows.append(
            {
                "feature": name,
                "min": float(np.min(values)),
                "max": float(np.max(values)),
                "max_abs": float(np.max(np.abs(values))),
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "n_values": int(values.size),
            }
        )
    return pd.DataFrame(rows)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compute max values for ADS-B differential features.")
    p.add_argument("--csv", type=str, default="sample_adsb_decoded.csv", help="ADS-B CSV path.")
    p.add_argument(
        "--out",
        type=Path,
        default=ROOT / "outputs" / "differential_feature_max.csv",
        help="Output CSV path.",
    )
    p.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional JSON output path.",
    )
    p.add_argument("--window-size", type=int, default=WINDOW_SIZE, help="Sliding window length.")
    p.add_argument(
        "--gap-seconds",
        type=float,
        default=TRACK_GAP_SECONDS,
        help="Split track segments when adjacent ts gap is greater than this value.",
    )
    p.add_argument(
        "--num-aircraft",
        type=int,
        default=None,
        help="Randomly keep N unique icao values before computing stats.",
    )
    p.add_argument("--seed", type=int, default=SEED, help="Random seed for aircraft subsampling.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    stats = compute_differential_feature_stats(
        args.csv,
        window_size=args.window_size,
        gap_seconds=args.gap_seconds,
        num_aircraft=args.num_aircraft,
        random_state=args.seed,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    stats.to_csv(args.out, index=False, encoding="utf-8-sig")
    print(f"Saved differential feature max stats: {args.out.resolve()}")
    print(stats.to_string(index=False))

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = {}
        for _, row in stats.iterrows():
            payload[row["feature"]] = {
                k: row[k].item() if hasattr(row[k], "item") else row[k]
                for k in row.index
                if k != "feature"
            }
        args.json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Saved JSON stats: {args.json_out.resolve()}")


if __name__ == "__main__":
    main()

"""Build deterministic local ADS-B samples from OpenSky state-vector snapshots.

The source and derived CSV files remain local because OpenSky data access is
subject to its current data-license terms. Only manifests and experiment
results are intended for the anonymous artifact bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd


KNOTS_PER_MPS = 1.9438444924406
FEET_PER_METER = 3.2808398950131
FEET_PER_MINUTE_PER_MPS = 196.85039370079
REQUIRED_COLUMNS = (
    "time",
    "icao24",
    "lat",
    "lon",
    "velocity",
    "heading",
    "vertrate",
    "callsign",
    "baroaltitude",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def convert_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    converted = pd.DataFrame(
        {
            "ts": chunk["time"],
            "icao": chunk["icao24"].astype("string").str.upper(),
            "lat": chunk["lat"],
            "lon": chunk["lon"],
            "alt": chunk["baroaltitude"] * FEET_PER_METER,
            "spd": chunk["velocity"] * KNOTS_PER_MPS,
            "hdg": chunk["heading"],
            "roc": chunk["vertrate"] * FEET_PER_MINUTE_PER_MPS,
            "callsign": chunk["callsign"].astype("string").str.strip(),
        }
    )
    converted = converted.dropna(subset=["ts", "icao", "lat", "lon", "alt", "spd", "hdg"])
    return converted[
        (converted["spd"] > 0)
        & (converted["spd"] < 300)
        & (converted["alt"] > 0)
        & (converted["alt"] < 15000)
        & (converted["hdg"] >= 0)
        & (converted["hdg"] <= 360)
    ]


def eligible_aircraft(
    frame: pd.DataFrame,
    *,
    gap_seconds: float,
    min_segment_points: int,
) -> list[str]:
    ordered = frame[["ts", "icao"]].sort_values(["icao", "ts"]).copy()
    gaps = ordered.groupby("icao", sort=False)["ts"].diff()
    ordered["segment"] = (gaps.isna() | (gaps > gap_seconds)).groupby(
        ordered["icao"], sort=False
    ).cumsum()
    sizes = ordered.groupby(["icao", "segment"], sort=False).size()
    return sorted(
        str(icao)
        for icao in sizes[sizes >= min_segment_points].index.get_level_values(0).unique()
    )


def deterministic_selection(source_name: str, aircraft: list[str], count: int) -> list[str]:
    ranked = sorted(
        aircraft,
        key=lambda icao: hashlib.sha256(f"{source_name}|{icao}".encode("utf-8")).hexdigest(),
    )
    return ranked[:count]


def _linear_interpolate(times: np.ndarray, values: np.ndarray, grid: np.ndarray) -> np.ndarray:
    finite = np.isfinite(values)
    if not finite.any():
        return np.full(len(grid), np.nan)
    if finite.sum() == 1:
        return np.full(len(grid), float(values[finite][0]))
    return np.interp(grid, times[finite], values[finite])


def resample_tracks(
    frame: pd.DataFrame,
    *,
    interval_seconds: float,
    gap_seconds: float,
) -> pd.DataFrame:
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    ordered = frame.sort_values(["icao", "ts"]).copy()
    gaps = ordered.groupby("icao", sort=False)["ts"].diff()
    ordered["segment"] = (gaps.isna() | (gaps > gap_seconds)).groupby(
        ordered["icao"], sort=False
    ).cumsum()
    resampled: list[pd.DataFrame] = []
    for (icao, _segment), track in ordered.groupby(["icao", "segment"], sort=False):
        track = track.drop_duplicates("ts", keep="last").sort_values("ts")
        if len(track) < 2:
            continue
        times = track["ts"].to_numpy(dtype=np.float64)
        grid = np.arange(times[0], times[-1] + interval_seconds / 2, interval_seconds)
        data: dict[str, object] = {"ts": grid, "icao": str(icao)}
        for column in ("lat", "lon", "alt", "spd", "roc"):
            data[column] = _linear_interpolate(
                times,
                track[column].to_numpy(dtype=np.float64),
                grid,
            )
        heading = np.unwrap(np.deg2rad(track["hdg"].to_numpy(dtype=np.float64)))
        data["hdg"] = np.rad2deg(np.interp(grid, times, heading)) % 360.0
        callsigns = track["callsign"].dropna().astype(str)
        data["callsign"] = callsigns.iloc[0] if len(callsigns) else ""
        resampled.append(pd.DataFrame(data))
    if not resampled:
        return frame.iloc[0:0].drop(columns=["segment"], errors="ignore")
    return pd.concat(resampled, ignore_index=True).sort_values(["icao", "ts"])


def build_sample(
    source: Path,
    output: Path,
    manifest_path: Path,
    *,
    aircraft_count: int,
    min_segment_points: int,
    gap_seconds: float,
    resample_seconds: float | None,
    chunksize: int,
) -> dict[str, object]:
    source_rows = 0
    valid_chunks: list[pd.DataFrame] = []
    for chunk in pd.read_csv(source, usecols=list(REQUIRED_COLUMNS), chunksize=chunksize):
        source_rows += len(chunk)
        valid_chunks.append(convert_chunk(chunk))

    valid = pd.concat(valid_chunks, ignore_index=True)
    eligible = eligible_aircraft(
        valid,
        gap_seconds=gap_seconds,
        min_segment_points=min_segment_points,
    )
    if len(eligible) < aircraft_count:
        raise RuntimeError(
            f"{source} has only {len(eligible)} eligible aircraft; requested {aircraft_count}"
        )
    selected_ids = deterministic_selection(source.name, eligible, aircraft_count)
    selected = valid[valid["icao"].isin(selected_ids)].sort_values(["icao", "ts"])
    source_selected_rows = len(selected)
    if resample_seconds is not None:
        selected = resample_tracks(
            selected,
            interval_seconds=resample_seconds,
            gap_seconds=gap_seconds,
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    selected.to_csv(output, index=False, lineterminator="\n", float_format="%.10f")

    manifest: dict[str, object] = {
        "schema_version": 1,
        "source": {
            "filename": source.name,
            "bytes": source.stat().st_size,
            "sha256": sha256_file(source),
            "rows": source_rows,
        },
        "selection": {
            "method": "ascending SHA-256(source filename | ICAO24) among eligible aircraft",
            "aircraft_count": aircraft_count,
            "eligible_aircraft": len(eligible),
            "min_segment_points": min_segment_points,
            "gap_seconds": gap_seconds,
            "selected_ids_sha256": hashlib.sha256(
                ",".join(selected_ids).encode("utf-8")
            ).hexdigest(),
            "source_selected_rows": source_selected_rows,
        },
        "conversion": {
            "velocity": "m/s to knots",
            "baroaltitude": "meters to feet",
            "vertrate": "m/s to feet/minute",
            "filter": "0 < spd < 300 knots; 0 < alt < 15000 feet; 0 <= hdg <= 360",
            "resample_seconds": resample_seconds,
            "heading_interpolation": "circular unwrap/interpolate/wrap" if resample_seconds else None,
        },
        "output": {
            "filename": output.name,
            "rows": len(selected),
            "aircraft": int(selected["icao"].nunique()),
            "bytes": output.stat().st_size,
            "sha256": sha256_file(output),
            "time_min": float(selected["ts"].min()),
            "time_max": float(selected["ts"].max()),
        },
        "license_boundary": (
            "Source and derived CSV remain local; consult the current OpenSky "
            "Data License Agreement before use or redistribution."
        ),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--aircraft-count", type=int, default=100)
    parser.add_argument("--min-segment-points", type=int, default=30)
    parser.add_argument("--gap-seconds", type=float, default=60.0)
    parser.add_argument("--resample-seconds", type=float, default=None)
    parser.add_argument("--chunksize", type=int, default=500_000)
    args = parser.parse_args()
    manifest = build_sample(
        args.source,
        args.output,
        args.manifest,
        aircraft_count=args.aircraft_count,
        min_segment_points=args.min_segment_points,
        gap_seconds=args.gap_seconds,
        resample_seconds=args.resample_seconds,
        chunksize=args.chunksize,
    )
    print(f"external_sample={args.output}")
    print(f"external_sample_rows={manifest['output']['rows']}")
    print(f"external_sample_aircraft={manifest['output']['aircraft']}")
    print(f"external_sample_sha256={manifest['output']['sha256']}")


if __name__ == "__main__":
    main()

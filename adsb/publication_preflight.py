"""Preflight checks for publication benchmark data coverage."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adsb.anomalies import MALICIOUS_LABEL_MIN_POINTS
from adsb.benchmark import parse_seed_list
from adsb.data import filter_data, load_data, subset_df_by_aircraft
from adsb.dataloading import prepare_train_val_test_loaders
from adsb.train_constants import SEED, WINDOW_SIZE
from adsb.utils import set_seed


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _display_path(path: str | Path) -> str:
    return str(path).replace("\\", "/").encode("ascii", errors="backslashreplace").decode("ascii")


def _data_summary(csv_path: str | Path, loaded_df, filtered_df, subset_df) -> dict[str, Any]:
    return {
        "csv_path": str(csv_path),
        "rows_loaded": int(len(loaded_df)),
        "rows_after_filter": int(len(filtered_df)),
        "rows_after_subset": int(len(subset_df)),
        "aircraft_loaded": int(loaded_df["icao"].nunique()),
        "aircraft_after_filter": int(filtered_df["icao"].nunique()),
        "aircraft_after_subset": int(subset_df["icao"].nunique()),
    }


def _label_errors(split_summary: dict[str, Any], seed: int) -> list[str]:
    errors: list[str] = []
    split_window = _int_or_none(split_summary.get("window_size"))
    label_min = _int_or_none(split_summary.get("malicious_label_min_points"))
    if label_min != MALICIOUS_LABEL_MIN_POINTS:
        errors.append(
            f"seed {seed}: malicious_label_min_points {label_min} != expected {MALICIOUS_LABEL_MIN_POINTS}"
        )
    if split_window is None or split_window < MALICIOUS_LABEL_MIN_POINTS:
        errors.append(
            f"seed {seed}: window_size must be >= malicious label threshold {MALICIOUS_LABEL_MIN_POINTS}"
        )

    aircraft = split_summary.get("aircraft", {})
    overlaps = aircraft.get("overlap_counts", {}) if isinstance(aircraft, dict) else {}
    for name in ("train_validation", "train_test", "validation_test"):
        observed = _int_or_none(overlaps.get(name)) if isinstance(overlaps, dict) else None
        if observed != 0:
            errors.append(f"seed {seed}: aircraft leakage in {name}: {observed}")

    windows = split_summary.get("windows", {})
    if not isinstance(windows, dict):
        return [*errors, f"seed {seed}: split_summary.windows missing"]
    for name in ("train", "validation", "test_mixed_attack"):
        summary = windows.get(name, {})
        malicious = _int_or_none(summary.get("malicious_windows")) if isinstance(summary, dict) else None
        if malicious is None or malicious <= 0:
            errors.append(f"seed {seed}: {name} must contain at least one malicious window")
    no_injection = windows.get("test_no_injection", {})
    no_injection_mal = (
        _int_or_none(no_injection.get("malicious_windows")) if isinstance(no_injection, dict) else None
    )
    if no_injection_mal != 0:
        errors.append(f"seed {seed}: test_no_injection must contain zero malicious windows")

    per_attack = windows.get("per_attack", {})
    if not isinstance(per_attack, dict) or not per_attack:
        errors.append(f"seed {seed}: per_attack summaries missing")
    elif isinstance(per_attack, dict):
        for name, summary in per_attack.items():
            malicious = _int_or_none(summary.get("malicious_windows")) if isinstance(summary, dict) else None
            if malicious is None or malicious <= 0:
                errors.append(f"seed {seed}: per_attack.{name} must contain at least one malicious window")
    return errors


def run_publication_preflight(
    *,
    seeds: list[int],
    csv_path: str | Path,
    window_size: int = WINDOW_SIZE,
    num_aircraft: int | None = None,
    min_seeds: int = 5,
    require_full_data: bool = True,
) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).isoformat()
    options = {
        "csv_path": str(csv_path),
        "seeds": [int(seed) for seed in seeds],
        "window_size": int(window_size),
        "num_aircraft": num_aircraft,
        "min_seeds": int(min_seeds),
        "require_full_data": bool(require_full_data),
        "malicious_label_min_points": int(MALICIOUS_LABEL_MIN_POINTS),
    }
    errors: list[str] = []
    warnings: list[str] = []
    if len(seeds) < int(min_seeds):
        errors.append(f"preflight has {len(seeds)} seeds but requires at least {int(min_seeds)}")
    if require_full_data and num_aircraft is not None:
        errors.append("publication preflight requires num_aircraft=None for full-data experiments")
    if int(window_size) < MALICIOUS_LABEL_MIN_POINTS:
        errors.append(f"window_size must be >= malicious label threshold {MALICIOUS_LABEL_MIN_POINTS}")

    loaded_df = load_data(csv_path)
    filtered_df = filter_data(loaded_df)
    dataset_summary = {
        "csv_path": str(csv_path),
        "rows_loaded": int(len(loaded_df)),
        "rows_after_filter": int(len(filtered_df)),
        "aircraft_loaded": int(loaded_df["icao"].nunique()),
        "aircraft_after_filter": int(filtered_df["icao"].nunique()),
    }

    runs: list[dict[str, Any]] = []
    for seed in seeds:
        set_seed(int(seed))
        run_errors: list[str] = []
        try:
            subset_df = subset_df_by_aircraft(filtered_df, max_aircraft=num_aircraft, random_state=int(seed))
            summary = _data_summary(csv_path, loaded_df, filtered_df, subset_df)
            if require_full_data and summary["aircraft_after_subset"] != summary["aircraft_after_filter"]:
                run_errors.append(f"seed {seed}: data_summary indicates aircraft subsetting")
            pack = prepare_train_val_test_loaders(
                subset_df,
                pin_memory=False,
                random_state=int(seed),
                window_size=int(window_size),
            )
            split_summary = pack.split_summary
            run_errors.extend(_label_errors(split_summary, int(seed)))
        except Exception as exc:
            summary = {}
            split_summary = {}
            run_errors.append(f"seed {seed}: preflight failed: {exc}")
        runs.append(
            {
                "seed": int(seed),
                "passed": not run_errors,
                "errors": run_errors,
                "data_summary": summary,
                "split_summary": split_summary,
            }
        )
        errors.extend(run_errors)

    passed = not errors
    return {
        "schema_version": 1,
        "created_at_utc": created_at,
        "status": "passed" if passed else "failed",
        "passed": passed,
        "options": options,
        "dataset_summary": dataset_summary,
        "runs": runs,
        "warnings": warnings,
        "errors": errors,
    }


def _preflight_report_markdown(report: dict[str, Any]) -> str:
    options = report.get("options", {})
    lines = [
        "# ADS-B Publication Preflight Report",
        "",
        f"- Status: {'PASSED' if report.get('passed') else 'FAILED'}",
        f"- Generated UTC: {report.get('created_at_utc')}",
        f"- CSV: {_display_path(options.get('csv_path', ''))}",
        f"- Seeds: {','.join(str(seed) for seed in options.get('seeds', []))}",
        f"- Window size: {options.get('window_size')}",
        f"- Require full data: {bool(options.get('require_full_data'))}",
        "",
        "## Runs",
        "",
    ]
    for run in report.get("runs", []):
        data = run.get("data_summary", {})
        lines.append(
            f"- seed {run.get('seed')}: {'PASS' if run.get('passed') else 'FAIL'} | "
            f"rows={data.get('rows_after_subset', '--')} | aircraft={data.get('aircraft_after_subset', '--')}"
        )
        for error in run.get("errors", []):
            lines.append(f"  - {error}")
    lines.extend(["", "## Errors", ""])
    errors = report.get("errors", [])
    if errors:
        lines.extend(f"- {error}" for error in errors)
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def write_preflight_report(report: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / "preflight_report.json"
    md_path = target / "preflight_report.md"
    json_path.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
    md_path.write_text(_preflight_report_markdown(report), encoding="utf-8")
    return {"json": _display_path(json_path), "markdown": _display_path(md_path)}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preflight ADS-B publication benchmark data coverage.")
    parser.add_argument("--csv", default="sample_adsb_decoded.csv")
    parser.add_argument("--seeds", default=f"{SEED},{SEED + 1},{SEED + 2},{SEED + 3},{SEED + 4}")
    parser.add_argument("--window-size", type=int, default=WINDOW_SIZE)
    parser.add_argument("--num-aircraft", type=int, default=None)
    parser.add_argument("--min-seeds", type=int, default=5)
    parser.add_argument("--allow-subset", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("outputs") / "publication_preflight")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    report = run_publication_preflight(
        seeds=parse_seed_list(args.seeds),
        csv_path=args.csv,
        window_size=args.window_size,
        num_aircraft=args.num_aircraft,
        min_seeds=args.min_seeds,
        require_full_data=not args.allow_subset,
    )
    paths = write_preflight_report(report, args.output_dir)
    print(f"preflight_json={paths['json']}")
    print(f"preflight_markdown={paths['markdown']}")
    if not report.get("passed"):
        print("PREFLIGHT FAILED")
        for error in report.get("errors", []):
            print(error)
        raise SystemExit(1)
    print("PREFLIGHT PASSED")


if __name__ == "__main__":
    main()


__all__ = ["run_publication_preflight", "write_preflight_report"]

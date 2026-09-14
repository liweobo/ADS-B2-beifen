"""Progress/status reporting for multi-seed benchmark directories."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adsb.verify_artifacts import build_verification_report


def _display_path(path: str | Path) -> str:
    return str(path).replace("\\", "/").encode("ascii", errors="backslashreplace").decode("ascii")


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _path_from_record(root: Path, record: dict[str, Any], rel_key: str, path_key: str, default: Path) -> Path:
    rel = str(record.get(rel_key) or "")
    if rel:
        return root / rel
    text = str(record.get(path_key) or "")
    return Path(text) if text else default


def _line_count(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", newline="") as f:
            return max(0, sum(1 for _ in f) - 1)
    except OSError:
        return 0


def _seed_status(root: Path, seed: int, manifest: dict[str, Any] | None) -> dict[str, Any]:
    run_dir = root / "runs" / f"seed_{seed}"
    record_path = run_dir / "run_record.json"
    record = _read_json(record_path) if record_path.exists() else None
    resume = manifest.get("resume", {}) if isinstance(manifest, dict) else {}
    signature = resume.get("signature", {}) if isinstance(resume, dict) else {}
    expected_sig = signature.get("sha256") if isinstance(signature, dict) else None
    errors: list[str] = []
    warnings: list[str] = []

    metrics_path = run_dir / "per_seed_metrics_long.csv"
    log_path = run_dir / "run.log"
    completed = False
    signature_matches = None
    if record is not None:
        completed = record.get("completed") is True
        record_sig = record.get("resume_signature", {})
        if isinstance(record_sig, dict) and expected_sig:
            signature_matches = record_sig.get("sha256") == expected_sig
        metrics_path = _path_from_record(root, record, "metrics_path_benchmark_relative", "metrics_path", metrics_path)
        log_path = _path_from_record(root, record, "log_path_benchmark_relative", "log_path", log_path)
    else:
        errors.append("missing run_record.json")

    metrics_exists = metrics_path.exists() and metrics_path.is_file()
    log_exists = log_path.exists() and log_path.is_file()
    if not metrics_exists:
        errors.append("missing per-seed metrics CSV")
    if record is not None and not completed:
        errors.append("run_record.json does not mark completion")
    if signature_matches is False:
        errors.append("run_record resume signature does not match manifest")

    manifest_run = None
    if isinstance(manifest, dict):
        for run in manifest.get("runs", []):
            if isinstance(run, dict) and int(run.get("seed", -1)) == int(seed):
                manifest_run = run
                break
    if manifest is not None and manifest_run is None:
        warnings.append("seed is not present in manifest runs")

    return {
        "seed": int(seed),
        "state": "complete" if completed and metrics_exists and not errors else "incomplete",
        "run_dir": _display_path(run_dir),
        "record_path": _display_path(record_path),
        "record_exists": record is not None,
        "completed": bool(completed),
        "signature_matches_manifest": signature_matches,
        "metrics_path": _display_path(metrics_path),
        "metrics_exists": bool(metrics_exists),
        "metrics_rows": _line_count(metrics_path) if metrics_exists else 0,
        "log_path": _display_path(log_path),
        "log_exists": bool(log_exists),
        "log_size_bytes": int(log_path.stat().st_size) if log_exists else 0,
        "resumed_in_last_manifest": int(seed) in set(resume.get("resumed_seeds", [])) if isinstance(resume, dict) else False,
        "executed_in_last_manifest": int(seed) in set(resume.get("executed_seeds", [])) if isinstance(resume, dict) else False,
        "errors": errors,
        "warnings": warnings,
    }


def build_benchmark_status(
    benchmark_dir: str | Path,
    *,
    preflight_report: str | Path | None = None,
    verify: bool = False,
    strict_publication: bool = False,
) -> dict[str, Any]:
    root = Path(benchmark_dir)
    manifest_path = root / "benchmark_manifest.json"
    manifest = _read_json(manifest_path) if manifest_path.exists() else None
    if manifest is not None:
        seeds = [int(seed) for seed in manifest.get("config", {}).get("seeds", [])]
    else:
        seeds = []
        runs_dir = root / "runs"
        if runs_dir.exists():
            for child in runs_dir.iterdir():
                if child.is_dir() and child.name.startswith("seed_"):
                    try:
                        seeds.append(int(child.name.split("_", 1)[1]))
                    except ValueError:
                        continue
        seeds.sort()

    seed_rows = [_seed_status(root, seed, manifest) for seed in seeds]
    completed = [row for row in seed_rows if row["state"] == "complete"]
    verification = None
    if verify or strict_publication:
        verification = build_verification_report(
            root,
            publication_ready=bool(strict_publication),
            preflight_report=preflight_report,
        )

    return {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_dir": _display_path(root),
        "manifest_path": _display_path(manifest_path),
        "manifest_exists": manifest is not None,
        "summary": {
            "total_seeds": len(seed_rows),
            "completed_seeds": len(completed),
            "incomplete_seeds": len(seed_rows) - len(completed),
            "resumed_in_last_manifest": sum(1 for row in seed_rows if row["resumed_in_last_manifest"]),
            "executed_in_last_manifest": sum(1 for row in seed_rows if row["executed_in_last_manifest"]),
        },
        "config": manifest.get("config", {}) if isinstance(manifest, dict) else {},
        "resume": manifest.get("resume", {}) if isinstance(manifest, dict) else {},
        "seeds": seed_rows,
        "verification": verification,
    }


def _status_markdown(status: dict[str, Any]) -> str:
    summary = status.get("summary", {})
    lines = [
        "# ADS-B Benchmark Status",
        "",
        f"- Generated UTC: {status.get('created_at_utc')}",
        f"- Benchmark directory: {status.get('benchmark_dir')}",
        f"- Manifest exists: {bool(status.get('manifest_exists'))}",
        f"- Seeds complete: {summary.get('completed_seeds')}/{summary.get('total_seeds')}",
        f"- Resumed in last manifest: {summary.get('resumed_in_last_manifest')}",
        f"- Executed in last manifest: {summary.get('executed_in_last_manifest')}",
        "",
        "## Seeds",
        "",
    ]
    for row in status.get("seeds", []):
        lines.append(
            f"- seed {row.get('seed')}: {row.get('state')} | "
            f"metrics_rows={row.get('metrics_rows')} | log_bytes={row.get('log_size_bytes')}"
        )
        for error in row.get("errors", []):
            lines.append(f"  - ERROR: {error}")
        for warning in row.get("warnings", []):
            lines.append(f"  - WARNING: {warning}")
    verification = status.get("verification")
    if verification:
        lines.extend(
            [
                "",
                "## Verification",
                "",
                f"- Status: {verification.get('status')}",
                f"- Passed: {bool(verification.get('passed'))}",
            ]
        )
        for error in verification.get("errors", []):
            lines.append(f"- ERROR: {error}")
    lines.append("")
    return "\n".join(lines)


def write_benchmark_status_report(status: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / "benchmark_status.json"
    md_path = target / "benchmark_status.md"
    json_path.write_text(json.dumps(status, ensure_ascii=True, indent=2), encoding="utf-8")
    md_path.write_text(_status_markdown(status), encoding="utf-8")
    return {"json": _display_path(json_path), "markdown": _display_path(md_path)}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect ADS-B multi-seed benchmark progress/status.")
    parser.add_argument("--benchmark-dir", type=Path, required=True)
    parser.add_argument("--preflight-report", type=Path, default=None)
    parser.add_argument("--verify", action="store_true", help="Run normal artifact verification and include it.")
    parser.add_argument("--strict-publication", action="store_true", help="Run strict publication verification.")
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--report-dir", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    status = build_benchmark_status(
        args.benchmark_dir,
        preflight_report=args.preflight_report,
        verify=args.verify,
        strict_publication=args.strict_publication,
    )
    summary = status["summary"]
    print(f"benchmark_dir={status['benchmark_dir']}")
    print(f"manifest_exists={status['manifest_exists']}")
    print(f"completed_seeds={summary['completed_seeds']}/{summary['total_seeds']}")
    print(f"resumed_in_last_manifest={summary['resumed_in_last_manifest']}")
    print(f"executed_in_last_manifest={summary['executed_in_last_manifest']}")
    for row in status["seeds"]:
        print(f"seed={row['seed']} state={row['state']} metrics_rows={row['metrics_rows']}")
    if status.get("verification"):
        print(f"verification_status={status['verification']['status']}")
    if args.write_report:
        paths = write_benchmark_status_report(status, args.report_dir or args.benchmark_dir)
        print(f"status_json={paths['json']}")
        print(f"status_markdown={paths['markdown']}")


if __name__ == "__main__":
    main()


__all__ = ["build_benchmark_status", "write_benchmark_status_report"]

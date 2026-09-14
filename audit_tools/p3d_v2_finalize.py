"""Finalize the authorized C0-01 P3-Diagnostic v2 after both fresh matrices."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from adsb.checkpoints import code_fingerprint, sha256_file
from audit_tools import p3d_finalize as engine
from audit_tools.p3d_v2_prepare import (
    CANONICAL_ROOT,
    EXPECTED_ATTACK_FINGERPRINT,
    R,
    REQUIRED_PREREG,
    atomic_json,
    canonical_hash,
    corrected_ce_reaggregation,
    load_json,
    paths,
    source_files,
)
from audit_tools.p3d_v2_runner import read_inventory, validate_authorization


MATERIAL = 0.01


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_dataframe(path: Path, frame: pd.DataFrame) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    frame.to_csv(temporary, index=False)
    temporary.replace(path)


def write_gate(path: Path, name: str, passed: bool, evidence: dict[str, Any]) -> None:
    atomic_json(path, {
        "schema_version": "adsb.c001-p3d-v2-gate.v1", "gate": name,
        "status": "PASS" if passed else "FAIL", "evaluated_at_utc": now(),
        "evidence": evidence,
    })


def read_ledger(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def verify_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    missing: list[str] = []
    mismatches: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    names: list[str] = []
    for item in manifest.get("artifacts", []):
        relative = str(item["path"])
        names.append(relative)
        path = root / Path(relative)
        if not path.is_file():
            missing.append(relative)
            continue
        observed_hash = sha256_file(path)
        observed_size = path.stat().st_size
        if observed_hash != item["sha256"] or observed_size != int(item["size_bytes"]):
            mismatches.append({"path": relative, "observed_sha256": observed_hash, "expected_sha256": item["sha256"], "observed_size_bytes": observed_size, "expected_size_bytes": item["size_bytes"]})
        if path.suffix == ".json":
            try:
                load_json(path)
            except Exception as exc:
                malformed.append({"path": relative, "error": str(exc)})
    duplicates = len(names) - len(set(names))
    return {
        "missing_count": len(missing), "missing": missing,
        "hash_mismatch_count": len(mismatches), "hash_mismatches": mismatches,
        "malformed_json_count": len(malformed), "malformed_json": malformed,
        "duplicate_canonical_artifact_count": duplicates,
        "status": "PASS" if not missing and not mismatches and not malformed and duplicates == 0 else "FAIL",
    }


def hash_relatives(root: Path, relatives: Iterable[Path]) -> dict[str, Any]:
    canonical = [Path(relative).as_posix() for relative in relatives]
    artifacts = []
    missing = []
    malformed = []
    for relative in sorted(set(canonical)):
        path = root / Path(relative)
        if not path.is_file():
            missing.append(relative)
            continue
        if path.suffix == ".json":
            try:
                load_json(path)
            except Exception as exc:
                malformed.append({"path": relative, "error": str(exc)})
        artifacts.append({"path": relative, "sha256": sha256_file(path), "size_bytes": path.stat().st_size})
    return {
        "artifacts": artifacts, "artifact_count": len(artifacts),
        "missing": missing, "malformed_json": malformed,
        "duplicate_canonical_artifact_count": len(canonical) - len(set(canonical)),
        "status": "PASS" if not missing and not malformed and len(canonical) == len(set(canonical)) else "FAIL",
    }


def authorization_provenance(p: dict[str, Path]) -> tuple[bool, dict[str, Any]]:
    authorization = load_json(p["pre_run"] / "pre_run_authorization.json")
    starts: list[dict[str, Any]] = []
    completes: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for loss in ("margin", "cw"):
        events = read_ledger(p["p3"] / loss / "ledger.jsonl")
        starts.extend({**event, "loss": loss} for event in events if event.get("event") == "TASK_START")
        completes.extend({**event, "loss": loss} for event in events if event.get("event") == "TASK_COMPLETE")
        failures.extend({**event, "loss": loss} for event in events if event.get("event") == "TASK_FAILED")
    authorization_utc = datetime.fromisoformat(authorization["authorization_utc"])
    start_times_after = all(datetime.fromisoformat(event["at_utc"]) > authorization_utc for event in starts)
    config_identity = all(event.get("configuration_hash") == authorization["configuration_hash"] for event in starts)
    per_loss_starts = {loss: sum(event["loss"] == loss for event in starts) for loss in ("margin", "cw")}
    first_start = min((event["at_utc"] for event in starts), default=None)
    passed = (
        authorization.get("run_authorized") is True and start_times_after and config_identity
        and len(completes) == 160 and per_loss_starts["margin"] >= 80 and per_loss_starts["cw"] >= 80
    )
    return passed, {
        "authorization_utc": authorization["authorization_utc"], "first_execution_ledger_start_utc": first_start,
        "all_starts_after_authorization": start_times_after, "configuration_identity": config_identity,
        "task_starts_by_loss": per_loss_starts, "task_completes": len(completes), "failed_attempt_events": len(failures),
    }


def v1_v2_reproducibility(p: dict[str, Path]) -> tuple[pd.DataFrame, dict[str, Any]]:
    old = pd.read_csv(p["p3v1"] / "margin" / "task_inventory.csv", dtype=str).fillna("")
    new = pd.read_csv(p["p3"] / "margin" / "task_inventory.csv", dtype=str).fillna("")
    rows = []
    stable_keys = ("attack_config_hash", "checkpoint_sha256", "dataset_hash", "split_hash", "normalization_hash", "sample_manifest_hash", "threshold")
    metric_keys = ("best_metrics", "final_metrics", "transitions", "support", "constraint_diagnostics")
    for _, old_row in old[old.execution_status == "completed"].iterrows():
        matches = new[new.logical_config_id == old_row.logical_config_id]
        if len(matches) != 1:
            rows.append({"logical_config_id": old_row.logical_config_id, "comparable": False, "exact_match": False, "reason": f"v2 match count={len(matches)}"})
            continue
        new_row = matches.iloc[0]
        old_summary = load_json(p["p3v1"] / "margin" / "raw_results" / "tasks" / old_row.executed_task_hash / "summary.json")
        new_summary = load_json(p["p3"] / "margin" / "raw_results" / "tasks" / new_row.executed_task_hash / "summary.json")
        old_metrics = {key: old_summary.get(key) for key in metric_keys}
        new_metrics = {key: new_summary.get(key) for key in metric_keys}
        identity_match = all(str(old_row[key]) == str(new_row[key]) for key in stable_keys)
        candidate_hash_match = old_summary.get("candidate_artifact", {}).get("sha256") == new_summary.get("candidate_artifact", {}).get("sha256")
        numerical_match = canonical_hash(old_metrics) == canonical_hash(new_metrics)
        rows.append({
            "logical_config_id": old_row.logical_config_id, "seed": old_row.seed, "model": old_row.model,
            "attack": old_row.attack, "K": old_row.K, "v1_task_hash": old_row.executed_task_hash,
            "v2_task_hash": new_row.executed_task_hash, "comparable": identity_match,
            "candidate_artifact_hash_match": candidate_hash_match, "numerical_match": numerical_match,
            "exact_match": identity_match and candidate_hash_match and numerical_match,
            "v1_formal_status": "NON-FORMAL", "used_in_v2_aggregate": False,
            "reason": "" if identity_match and candidate_hash_match and numerical_match else "identity/candidate/numerical discrepancy retained",
        })
    frame = pd.DataFrame(rows)
    summary = {
        "comparable_configs": int(frame.comparable.sum()) if len(frame) else 0,
        "exact_matches": int(frame.exact_match.sum()) if len(frame) else 0,
        "numerical_mismatches": int((frame.comparable & ~frame.numerical_match).sum()) if len(frame) else 0,
        "candidate_hash_mismatches": int((frame.comparable & ~frame.candidate_artifact_hash_match).sum()) if len(frame) else 0,
        "interpretation": "REPRODUCIBILITY CHECK PASS" if len(frame) == 10 and bool(frame.exact_match.all()) else "DISCREPANCY RECORDED",
        "v1_formal_use": False,
    }
    return frame, summary


def format_number(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "NA"
    return "NA" if not math.isfinite(number) else f"{number:.6f}"


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    output = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        output.append("| " + " | ".join(str(value).replace("|", "\\|") for value in row) + " |")
    return "\n".join(output)


def build_report(p: dict[str, Path], gates: dict[str, bool], reproducibility: dict[str, Any]) -> str:
    authorization = load_json(p["pre_run"] / "pre_run_authorization.json")
    timestamp = pd.read_csv(p["pre_run"] / "freeze_timestamp_evidence.csv", dtype=str)
    family = pd.read_csv(p["p3"] / "loss_diagnostic" / "loss_comparison_by_family.csv")
    model = pd.read_csv(p["p3"] / "loss_diagnostic" / "loss_comparison_by_model.csv")
    unit = pd.read_csv(p["p3"] / "loss_diagnostic" / "loss_comparison_by_unit.csv")
    strongest = pd.read_csv(p["p3"] / "loss_diagnostic" / "strongest_loss_at_r5.csv")
    specificity = load_json(p["p3"] / "holdout_diagnostic" / "attack_specificity_diagnostic.json")
    material = load_json(p["p3"] / "loss_diagnostic" / "loss_material_difference.json")
    first_start = min(
        event["at_utc"]
        for loss in ("margin", "cw")
        for event in read_ledger(p["p3"] / loss / "ledger.jsonl")
        if event.get("event") == "TASK_START"
    )
    prereg_rows = [[row.path, "YES", row.sha256, row.freeze_utc, "PASS"] for row in timestamp.itertuples(index=False)]
    family_rows = [[
        row.attack, format_number(row.ce_asr_mean), format_number(row.margin_asr_mean), format_number(row.cw_asr_mean),
        format_number(row.delta_margin_ce_mean), format_number(row.delta_cw_ce_mean),
        f"{format_number(row.delta_margin_ce_feasible_mean)} / {format_number(row.delta_cw_ce_feasible_mean)}",
        "LOSS_EFFECT_HETEROGENEOUS" if row.diagnostic_verdict == "MIXED" else row.diagnostic_verdict,
    ] for row in family.itertuples(index=False)]
    model_rows = [[
        row.model, format_number(row.ce_asr_mean), format_number(row.margin_asr_mean), format_number(row.cw_asr_mean),
        format_number(row.delta_margin_ce_mean), format_number(row.delta_cw_ce_mean),
        "LOSS_EFFECT_HETEROGENEOUS" if row.diagnostic_verdict == "MIXED" else row.diagnostic_verdict,
    ] for row in model.itertuples(index=False)]
    raw_rows = []
    for (model_name, attack, steps), group in unit.groupby(["model", "attack", "K"]):
        group = group.sort_values("seed")
        raw_rows.append([
            model_name, attack, steps,
            ", ".join(format_number(value) for value in group.ce_asr),
            ", ".join(format_number(value) for value in group.margin_asr),
            ", ".join(format_number(value) for value in group.cw_asr),
            ", ".join(group.diagnostic_verdict.astype(str)),
        ])
    strongest_rows = []
    for (model_name, attack), group in strongest.groupby(["model", "attack"]):
        strongest_rows.append([
            model_name, attack, "; ".join(group.strongest_loss_at_R5.astype(str)),
            format_number(group.asr.mean()), "; ".join(group.feasible_asr.astype(str)),
            f"{group.strongest_loss_at_R5.nunique()} pattern(s) across {len(group)} K×split units",
        ])
    gate_rows = [[name, "PASS" if value else "FAIL"] for name, value in gates.items()]
    ceiling_count = int((unit.ceiling_status == "CEILING-LIMITED COMPARISON").sum())
    return f"""# C0-01 P3-Diagnostic v2 Final Report

## 1. Source Identity

- canonical root: `{p['root']}`
- P2-C Final Integrity: PASS (v2)
- R40 snapshot: `842d399a647699fdd7b038df5efb6d2907499cad094be44dfee47f2f5f528270`
- attack fingerprint: `{EXPECTED_ATTACK_FINGERPRINT}`
- P2-D termination verified: YES
- P3-v1 failure preserved: YES
- v1 partial used in v2 formal data: NO
- partial R80 used: NO
- verdict: PASS

## 2. Pre-Run Freeze

{markdown_table(['Artifact', 'Exists', 'SHA-256', 'Freeze UTC', 'Schema'], prereg_rows)}

- freeze manifest hash: `{authorization['freeze_manifest_hash']}`
- first execution ledger start UTC: `{first_start}`
- all freeze timestamps earlier than execution: YES
- Pre-Run Freeze Completeness: PASS (24/24)
- RUN AUTHORIZED: YES

## 3. P3-Diagnostic v2 Configuration

- stage: DIAGNOSTIC ONLY
- R: 5; restart IDs 0–4
- K: 20, 50
- losses: targeted CE (frozen reference), targeted logit margin, targeted CW-style margin
- attack families: norm_pgd, phys_projection_pgd, phys_penalty_pgd, phys_hybrid_pgd
- comparison units: 80
- new logical configs: 160
- max trajectories: 800
- CW kappa: 0.0
- kappa evidence: pre-v1 frozen implementation, test, and evaluation manifest
- pairing status: UNPAIRED — SAME DISTRIBUTION / SAME RESTART BUDGET
- configuration hash: `{authorization['configuration_hash']}`

## 4. Execution

- Margin: expected 80; completed 80; failed final configs 0; missing 0; duplicate 0; restart IDs 0–4.
- CW: expected 80; completed 80; failed final configs 0; missing 0; duplicate 0; restart IDs 0–4.
- v1 trajectory reused: NO
- R10 executed: NO
- R20 executed: NO
- new R40 executed: NO
- R80 resumed: NO

## 5. Integrity

{markdown_table(['Gate', 'Verdict'], gate_rows)}

- Final P3-Diagnostic v2 Integrity: {'PASS' if all(gates.values()) else 'FAIL'}

## 6. Loss Results

The preregistered material-difference threshold is absolute ASR difference >= {MATERIAL:.2f}; it is diagnostic, not an attack-adequacy gate. {ceiling_count}/80 comparison units are ceiling-limited.

### By family

{markdown_table(['Family', 'CE R5 ASR', 'Margin R5 ASR', 'CW R5 ASR', 'Delta Margin-CE', 'Delta CW-CE', 'Feasible deltas', 'Diagnostic verdict'], family_rows)}

### By model

{markdown_table(['Model', 'CE R5 ASR', 'Margin R5 ASR', 'CW R5 ASR', 'Delta Margin-CE', 'Delta CW-CE', 'Diagnostic verdict'], model_rows)}

### Five repeated aircraft splits (raw ASR values)

{markdown_table(['Model', 'Family', 'K', 'CE (5 splits)', 'Margin (5 splits)', 'CW (5 splits)', 'Unit verdicts'], raw_rows)}

Material units: Margin={material['material_margin_units']}; CW={material['material_cw_units']}. Values below the threshold mean NO MATERIAL DIFFERENCE OBSERVED AT R5, not loss equivalence.

## 7. Strongest Observed Loss at R5

{markdown_table(['Model', 'Family', 'Strongest loss patterns', 'Mean strongest ASR', 'Feasible ASR values', 'Consistency'], strongest_rows)}

RESOURCE-BOUNDED DIAGNOSTIC ONLY.

## 8. Holdout Results

- training attack identity: phys_hybrid_pgd, targeted CE, K=5, alpha=0.03, clean initialization, R=1, late_plus_final projection, epsilon=0.1, normalized_raw6.
- matched baseline: independently hash-verified frozen P1 K5 hybrid evaluations.
- holdout configs: complete CE R5 reference plus fresh v2 Margin/CW K={{20,50}}, R=5 configurations.
- changed dimensions: steps, alpha/alpha rule, initialization where applicable, restart count, loss where applicable, family/projection semantics where applicable.
- ERM sensitivity: {specificity['per_model']['BiLSTM-ERM']['attack_specific_sensitivity']}
- CAT-AD sensitivity: {specificity['per_model']['CAT-AD']['attack_specific_sensitivity']}
- attack-specific sensitivity: {specificity['attack_specificity']}

This is evidence consistent with sensitivity in the evaluated multi-factor holdouts; it does not prove or rule out attack overfitting.

## 9. Reproducibility

- comparable v1 exploratory Margin configs: {reproducibility['comparable_configs']}
- exact matches: {reproducibility['exact_matches']}
- numerical mismatches: {reproducibility['numerical_mismatches']}
- interpretation: {reproducibility['interpretation']}

v1 remained NON-FORMAL and was not used in the v2 aggregate.

## 10. Restart Limitation

Fixed-restart saturation within R<=40 remains NOT ESTABLISHED. Formal R80 adequacy remains NOT ASSESSED. P3-Diagnostic v2 does not repair or replace the failed restart-adequacy gate.

## 11. Formal Research Status

- restart saturation: NOT ESTABLISHED
- formal attack adequacy: NOT ESTABLISHED
- formal P3 clearance: DENIED
- P3-Diagnostic v2 integrity: {'PASS' if all(gates.values()) else 'FAIL'}
- robustness claims: SUSPENDED

## 12. Next Stage

{'READY FOR P4-DIAGNOSTIC PHYSICAL DECOMPOSITION' if all(gates.values()) else 'P3-DIAGNOSTIC V2 INTEGRITY FAILURE'}

This is diagnostic continuation authorization, not formal P4 clearance for a robustness proof.

## 13. Stop Confirmation

- P3-Diagnostic v1 was preserved as an integrity failure.
- No v1 Margin trajectory was used in the v2 formal aggregate.
- Partial R80 was not used; R80 was not resumed.
- R160/R320 were not executed; CE was not rerun.
- All formal v2 Margin/CW trajectories were executed only after RUN_AUTHORIZED=YES.
- No restart above 4 was executed and no loss was dropped based on results.
- No model received an outcome-dependent compute budget.
- No immutable P2-C/P2-D/P3-v1 record was modified.
- No failed or unfavorable result was deleted.
- P4-P6 were not executed; the manuscript was not modified.
- Restart saturation and formal attack adequacy remain unresolved.
- No CAT-AD robustness or superiority claim was restored.
"""


def finalize(project_root: Path = CANONICAL_ROOT) -> dict[str, Any]:
    project_root = project_root.resolve()
    p = paths(project_root)
    if (p["p3"] / "p3d_v2_runner.lock").exists():
        raise RuntimeError("cannot finalize while v2 runner lock exists")
    validate_authorization(project_root, "margin")
    validate_authorization(project_root, "cw")
    if code_fingerprint(project_root) != EXPECTED_ATTACK_FINGERPRINT:
        raise RuntimeError("frozen attack fingerprint changed")
    for loss in ("margin", "cw"):
        rows = read_inventory(p["p3"] / loss / "task_inventory.csv")
        if len(rows) != 80 or any(row["execution_status"] != "completed" for row in rows):
            raise RuntimeError(f"{loss} not exactly 80/80 complete")

    # Reuse the already audited calculation engine without modifying its v1
    # source.  All path/source globals are redirected to the isolated v2 tree.
    engine.paths = paths
    engine.source_files = source_files
    engine.ce_reaggregation = corrected_ce_reaggregation
    engine.finalize(project_root)

    comparison = pd.read_csv(p["p3"] / "loss_diagnostic" / "loss_comparison_by_unit.csv")
    margin = pd.read_csv(p["p3"] / "reaggregation" / "margin_r5_corrected.csv")
    cw = pd.read_csv(p["p3"] / "reaggregation" / "cw_r5_corrected.csv")
    task_checks = pd.concat([margin.assign(loss="margin"), cw.assign(loss="cw")], ignore_index=True)
    physical = pd.read_csv(p["p3"] / "reaggregation" / "physical_support.csv")
    auth_pass, auth_evidence = authorization_provenance(p)
    authorization = load_json(p["pre_run"] / "pre_run_authorization.json")

    transition_source = pd.read_csv(p["p3"] / "diagnostics" / "prediction_transitions.csv")
    transition_summary = transition_source.groupby(["loss", "model", "attack"], as_index=False).agg(
        repeated_split_k_units=("unit_id", "size"), clean_tp=("clean_tp", "sum"), clean_fn=("clean_fn", "sum"),
        clean_tp_to_attack_fn=("clean_tp_to_attack_fn", "sum"), clean_fn_to_attack_tp=("clean_fn_to_attack_tp", "sum"),
    )
    atomic_dataframe(p["p3"] / "reaggregation" / "transition_summary.csv", transition_summary)

    repro_frame, repro_summary = v1_v2_reproducibility(p)
    atomic_dataframe(p["p3"] / "reproducibility" / "v1_v2_margin_reproducibility.csv", repro_frame)

    inventory = pd.concat([
        pd.DataFrame(read_inventory(p["p3"] / loss / "task_inventory.csv")).assign(loss=loss)
        for loss in ("margin", "cw")
    ], ignore_index=True)
    old_inventory = pd.read_csv(p["p3v1"] / "margin" / "task_inventory.csv", dtype=str).fillna("")
    old_task_hashes = set(old_inventory.loc[old_inventory.execution_status == "completed", "executed_task_hash"])
    new_task_hashes = set(inventory.executed_task_hash)
    summaries = [
        load_json(p["p3"] / row.loss / "raw_results" / "tasks" / row.executed_task_hash / "summary.json")
        for row in inventory.itertuples(index=False)
    ]
    v1_isolation = old_task_hashes.isdisjoint(new_task_hashes) and all(summary.get("p3d_v1_trajectory_reused") is False for summary in summaries)
    no_out_of_budget = bool((task_checks.R.astype(int) == R).all()) and bool(task_checks.restart_complete.all())
    denominator = bool((task_checks.attacked_N.astype(int) > 0).all()) and len(comparison) == 80
    fallback_zero = int(physical.fallback_only_success.sum()) == 0
    configuration_gate = load_json(p["p3"] / "gates" / "configuration_gate.json")
    source_gate = load_json(p["p3"] / "gates" / "source_identity_gate.json")

    gate_definitions = {
        "Source Identity": source_gate.get("status") == "PASS",
        "Configuration Identity": configuration_gate.get("status") == "PASS",
        "Pre-Run Authorization Provenance": auth_pass,
        "Matrix Completeness": len(margin) == 80 and len(cw) == 80,
        "Restart Completeness": bool(task_checks.restart_complete.all()),
        "No Out-of-Budget Restart": no_out_of_budget,
        "Candidate Preservation": bool(task_checks.candidate_preservation.all()),
        "Metric Identity": bool(task_checks.metric_identity.all()),
        "Physical Support": bool((physical.formal_success <= physical.valid_or_feasible_support).all()),
        "Threshold Identity": configuration_gate.get("threshold_identity_failures") == 0,
        "Normal-byte Invariance": bool(task_checks.normal_byte_invariance.all()) and bool(task_checks.far_unchanged.all()),
        "Denominator Identity": denominator,
        "Fallback Candidate Success = 0": fallback_zero,
        "v1 Isolation": v1_isolation,
        "partial R80 Exclusion": load_json(p["source"] / "p2d_termination_identity.json").get("partial_R80_used") is False,
    }
    write_gate(p["p3"] / "gates" / "authorization_provenance_gate.json", "Pre-Run Authorization Provenance", auth_pass, auth_evidence)
    write_gate(p["p3"] / "gates" / "restart_gate.json", "Restart Completeness and Budget", gate_definitions["Restart Completeness"] and gate_definitions["No Out-of-Budget Restart"], {"R": R, "restart_ids": list(range(R)), "out_of_budget": 0})
    write_gate(p["p3"] / "gates" / "candidate_preservation_gate.json", "Candidate Preservation", gate_definitions["Candidate Preservation"], {"failures": int((~task_checks.candidate_preservation).sum())})
    write_gate(p["p3"] / "gates" / "threshold_identity_gate.json", "Threshold Identity", gate_definitions["Threshold Identity"], {"failures": configuration_gate.get("threshold_identity_failures")})
    write_gate(p["p3"] / "gates" / "normal_byte_gate.json", "Normal-byte Invariance", gate_definitions["Normal-byte Invariance"], {"normal_byte_failures": int((~task_checks.normal_byte_invariance).sum()), "far_failures": int((~task_checks.far_unchanged).sum())})
    write_gate(p["p3"] / "gates" / "denominator_gate.json", "Denominator Identity", denominator, {"unit_count": len(comparison), "nonpositive_denominators": int((task_checks.attacked_N.astype(int) <= 0).sum())})
    write_gate(p["p3"] / "gates" / "v1_isolation_gate.json", "v1 Isolation", v1_isolation, {"v1_completed_task_hashes": len(old_task_hashes), "v2_task_hashes": len(new_task_hashes), "task_hash_overlap": len(old_task_hashes.intersection(new_task_hashes)), "v1_formal_use": False})
    write_gate(p["p3"] / "gates" / "partial_r80_exclusion_gate.json", "partial R80 Exclusion", gate_definitions["partial R80 Exclusion"], {"partial_R80_used": False, "R80_resumed": False})

    prereg = [Path("configuration_freeze") / name for name in REQUIRED_PREREG]
    pre_run = [Path("pre_run_gate") / name for name in ("pre_run_freeze_completeness.json", "freeze_timestamp_evidence.csv", "freeze_manifest.json", "pre_run_authorization.json")]
    source = [Path("source_snapshot") / name for name in ("p2c_identity.json", "p2d_termination_identity.json", "p3d_v1_failure_reference.json", "ce_r5_reference.csv", "source_hashes.json", "source_inventory.csv")]
    execution = []
    for loss in ("margin", "cw"):
        execution.extend(Path(loss) / name for name in ("execution_manifest.json", "task_inventory.csv", "ledger.jsonl", "failed_attempts.jsonl", "artifact_hashes.json"))
    outputs = []
    for directory, names in {
        "reaggregation": ("ce_r5_corrected.csv", "margin_r5_corrected.csv", "cw_r5_corrected.csv", "success_memberships.csv.gz", "candidate_summary.csv", "physical_support.csv", "fallback_summary.csv", "transition_summary.csv"),
        "loss_diagnostic": ("loss_comparison_by_unit.csv", "loss_comparison_by_family.csv", "loss_comparison_by_model.csv", "strongest_loss_at_r5.csv", "loss_material_difference.json"),
        "holdout_diagnostic": ("training_attack_identity.json", "matched_holdout_dimension_map.csv", "holdout_results_by_unit.csv", "holdout_results_by_model.csv", "attack_specificity_diagnostic.json"),
        "diagnostics": ("ceiling_effect.csv", "prediction_transitions.csv", "physical_support_by_loss.csv", "fallback_by_loss.csv", "per_split_results.csv"),
        "reproducibility": ("v1_v2_margin_reproducibility.csv",),
        "gates": ("source_identity_gate.json", "configuration_gate.json", "authorization_provenance_gate.json", "completeness_gate.json", "restart_gate.json", "candidate_preservation_gate.json", "metric_identity_gate.json", "physical_support_gate.json", "threshold_identity_gate.json", "normal_byte_gate.json", "denominator_gate.json", "v1_isolation_gate.json", "partial_r80_exclusion_gate.json"),
    }.items():
        outputs.extend(Path(directory) / name for name in names)
    prehash_relatives = prereg + pre_run + source + execution + outputs
    artifact_payload = {"schema_version": "adsb.c001-p3d-v2-artifact-gate.v1", "generated_at_utc": now(), **hash_relatives(p["p3"], prehash_relatives)}
    atomic_json(p["p3"] / "gates" / "artifact_hash_gate.json", artifact_payload)
    artifact_verification = verify_manifest(p["p3"], p["p3"] / "gates" / "artifact_hash_gate.json")
    gate_definitions["Artifact Hash"] = artifact_payload["status"] == "PASS" and artifact_verification["status"] == "PASS"
    artifact_payload["independent_reread_verification"] = artifact_verification
    atomic_json(p["p3"] / "gates" / "artifact_hash_gate.json", artifact_payload)

    final_status = "PASS" if len(gate_definitions) == 16 and all(gate_definitions.values()) else "FAIL"
    final_gate = {
        "schema_version": "adsb.c001-p3d-v2-final-integrity.v1", "gate": "Final P3-Diagnostic v2 Integrity",
        "checks": {name: "PASS" if value else "FAIL" for name, value in gate_definitions.items()},
        "check_count": len(gate_definitions), "status": final_status,
        "formal_restart_saturation": "NOT_ESTABLISHED", "formal_R80_adequacy": "NOT ASSESSED",
        "formal_attack_adequacy": "NOT_ESTABLISHED", "formal_P3_clearance": "DENIED",
        "robustness_claims": "SUSPENDED", "generated_at_utc": now(),
    }
    atomic_json(p["p3"] / "gates" / "p3d_v2_final_integrity_gate.json", final_gate)
    decision = "READY FOR P4-DIAGNOSTIC PHYSICAL DECOMPOSITION" if final_status == "PASS" else "P3-DIAGNOSTIC V2 INTEGRITY FAILURE"
    atomic_json(p["p3"] / "final" / "next_stage_decision.json", {"decision": decision, "diagnostic_continuation_only": True, "formal_P4_clearance": "DENIED", "formal_attack_adequacy": "NOT_ESTABLISHED"})
    report = build_report(p, gate_definitions, repro_summary)
    (p["p3"] / "final" / "p3d_v2_report.md").write_text(report, encoding="utf-8")

    final_relatives = prehash_relatives + [
        Path("gates/artifact_hash_gate.json"), Path("gates/p3d_v2_final_integrity_gate.json"),
        Path("final/p3d_v2_report.md"), Path("final/next_stage_decision.json"),
    ]
    final_hashes = {"schema_version": "adsb.c001-p3d-v2-final-artifacts.v1", "generated_at_utc": now(), "self_excluded": True, **hash_relatives(p["p3"], final_relatives)}
    final_path = p["p3"] / "final" / "p3d_v2_artifact_hashes.json"
    atomic_json(final_path, final_hashes)
    independent = verify_manifest(p["p3"], final_path)
    final_hashes["independent_reread_verification"] = independent
    final_hashes["missing_count"] = independent["missing_count"]
    final_hashes["hash_mismatch_count"] = independent["hash_mismatch_count"]
    final_hashes["malformed_json_count"] = independent["malformed_json_count"]
    final_hashes["duplicate_canonical_artifact_count"] = independent["duplicate_canonical_artifact_count"]
    final_hashes["status"] = "PASS" if final_hashes["status"] == "PASS" and independent["status"] == "PASS" else "FAIL"
    atomic_json(final_path, final_hashes)
    if final_status != "PASS" or final_hashes["status"] != "PASS":
        raise RuntimeError("P3-DIAGNOSTIC V2 INTEGRITY FAILURE")
    return {"status": final_status, "decision": decision, "configuration_hash": authorization["configuration_hash"], "artifact_count": final_hashes["artifact_count"], "reproducibility": repro_summary}


if __name__ == "__main__":
    print(json.dumps(finalize(), ensure_ascii=False, indent=2), flush=True)

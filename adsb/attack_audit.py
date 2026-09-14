"""P0 strong-attack audit primitives.

This module is deliberately separate from the legacy training attacks.  It
implements the frozen C0-01 threat-model semantics and returns every candidate
status instead of silently substituting a final iterate.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator, Literal

import torch
import torch.nn.functional as F

from adsb.attacks import (
    PHYS_DALT_MAX,
    PHYS_DH_DEG_MAX,
    PHYS_DLAT_MAX,
    PHYS_DLON_MAX,
    PHYS_DV_MAX,
    _attack_grad_context,
    _as_f32_ms,
    _pack_norm12_from_raw_norm,
    _raw12_context,
    _sanitize_raw_phys,
    physical_penalty,
    physical_proj,
    wrap,
)
from adsb.data import denormalize

AttackId = Literal["norm_pgd", "phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd"]
LossId = Literal["targeted_ce", "targeted_logit_margin", "targeted_cw_margin"]
InitializationId = Literal["clean", "uniform_budget", "feasible_random"]

ATTACK_RESULT_SCHEMA_VERSION = "adsb.attack-result.v1"
ATTACK_CONFIG_SCHEMA_VERSION = "adsb.attack-config.v1"
ALLOWED_ATTACK_IDS = {"norm_pgd", "phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd"}
ALLOWED_LOSSES = {"targeted_ce", "targeted_logit_margin", "targeted_cw_margin"}
ALLOWED_INITIALIZATIONS = {"clean", "uniform_budget", "feasible_random"}


def _canonical_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class AttackConfig:
    attack_id: AttackId
    loss: LossId
    steps: int
    alpha: float
    epsilon: float
    initialization: InitializationId = "clean"
    restarts: int = 1
    target_label: int = 0
    normal_class: int = 0
    anomaly_class: int = 1
    budget_scope: str = "normalized_raw6"
    derived_difference_consistency: str = "recomputed_from_raw"
    projection_schedule: str = "none"
    hard_projection_start_ratio: float = 0.5
    seed: int = 42
    cw_kappa: float = 0.0
    lambda_phys: float = 10.0
    projection_tolerance: float | None = None
    budget_abs_tol: float | None = None
    kinematic_rel_tol: float | None = None
    projection_residual_tol: float | None = None
    maximum_alternating_projection_iterations: int | None = None
    feasible_random_resampling_count: int | None = None
    seen_during_training: bool = False
    differing_dimensions: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = ATTACK_CONFIG_SCHEMA_VERSION

    def validate(self, *, for_execution: bool = True) -> None:
        if self.attack_id not in ALLOWED_ATTACK_IDS:
            raise ValueError(f"unknown attack_id: {self.attack_id}")
        if self.loss not in ALLOWED_LOSSES:
            raise ValueError(f"unknown loss: {self.loss}")
        if self.initialization not in ALLOWED_INITIALIZATIONS:
            raise ValueError(f"unknown initialization: {self.initialization}")
        if self.budget_scope != "normalized_raw6":
            raise ValueError("P0 audit supports only budget_scope=normalized_raw6")
        if self.derived_difference_consistency != "recomputed_from_raw":
            raise ValueError("difference features must be recomputed_from_raw")
        if (self.normal_class, self.anomaly_class, self.target_label) != (0, 1, 0):
            raise ValueError("frozen class mapping is normal=0, anomaly=1, target=0")
        if self.steps < 0 or self.alpha < 0 or self.epsilon < 0 or self.restarts < 1:
            raise ValueError("steps/alpha/epsilon/restarts are outside their valid ranges")
        if not 0.0 <= float(self.hard_projection_start_ratio) <= 1.0:
            raise ValueError("hard_projection_start_ratio must be in [0,1]")
        if self.seen_during_training is False and "holdout" in self.projection_schedule.lower():
            if len(set(self.differing_dimensions)) < 2:
                raise ValueError("a holdout attack must differ from training in at least two dimensions")
        needs_projection = self.attack_id in {"phys_projection_pgd", "phys_hybrid_pgd"}
        if for_execution and needs_projection:
            legacy = self.projection_tolerance
            if (
                (self.budget_abs_tol is None and legacy is None)
                or (self.kinematic_rel_tol is None and legacy is None)
                or (self.projection_residual_tol is None and legacy is None)
                or self.maximum_alternating_projection_iterations is None
            ):
                raise ValueError("[AUTHOR VERIFY] projection tolerances and maximum iterations are unresolved")
        if for_execution and self.initialization == "feasible_random" and self.feasible_random_resampling_count is None:
            raise ValueError("[AUTHOR VERIFY] feasible-random resampling count is unresolved")

    @property
    def config_hash(self) -> str:
        self.validate(for_execution=False)
        return _canonical_hash(asdict(self))

    def restart_seed(self, restart_id: int) -> int:
        # Deliberately exclude ``restarts``: R=5 must contain the exact R=1 restart 0.
        payload = asdict(self)
        payload.pop("restarts", None)
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + f":restart:{int(restart_id)}".encode("ascii")
        ).digest()
        return int.from_bytes(digest[:8], "big") % (2**31 - 1)


@dataclass(frozen=True)
class ProjectionStatus:
    success: bool
    reason: str
    iterations: int
    budget_residual: float
    kinematic_residual: float
    domain_residual: float
    source_valid: bool
    independently_checked: bool
    projection_residual: float = 0.0


@dataclass(frozen=True)
class InitializationStatus:
    success: bool
    initialization: str
    restart_id: int
    seed: int
    attempts: int
    reason: str


@dataclass
class AttackResult:
    final_iterate: torch.Tensor
    best_target_loss_iterate: torch.Tensor | None
    first_threshold_success_iterate: torch.Tensor | None
    first_argmax_success_iterate: torch.Tensor | None
    best_feasible_successful_iterate: torch.Tensor | None
    best_feasible_iterate: torch.Tensor | None
    per_step_diagnostics: list[dict[str, Any]]
    projection_status: list[ProjectionStatus]
    initialization_status: list[InitializationStatus]
    restart_id: torch.Tensor
    final_restart_id: torch.Tensor
    attack_config_hash: str
    best_target_loss: torch.Tensor
    threshold_success: torch.Tensor
    argmax_success: torch.Tensor
    feasible_success: torch.Tensor
    final_feasible: torch.Tensor
    failure_reasons: list[str]
    schema_version: str = ATTACK_RESULT_SCHEMA_VERSION


@dataclass(frozen=True)
class ProjectionResult:
    tensor: torch.Tensor
    statuses: list[ProjectionStatus]


def budget_project(raw_normalized: torch.Tensor, clean_raw_normalized: torch.Tensor, epsilon: float) -> torch.Tensor:
    return torch.maximum(
        torch.minimum(raw_normalized, clean_raw_normalized + float(epsilon)),
        clean_raw_normalized - float(epsilon),
    )


def raw_domain_sanitize(raw_normalized: torch.Tensor, mean_raw: torch.Tensor, std_raw: torch.Tensor) -> torch.Tensor:
    physical = denormalize(raw_normalized.float(), mean_raw, std_raw)
    return ((_sanitize_raw_phys(physical) - mean_raw) / std_raw).to(dtype=raw_normalized.dtype)


def kinematic_project(
    raw_normalized: torch.Tensor,
    *,
    mean_raw: torch.Tensor,
    std_raw: torch.Tensor,
    raw_prev: torch.Tensor,
) -> torch.Tensor:
    physical = denormalize(raw_normalized.float(), mean_raw, std_raw)
    projected = physical_proj(physical, raw_prev=raw_prev, soft_limit=False, use_direction=False)
    return ((projected - mean_raw) / std_raw).to(dtype=raw_normalized.dtype)


def _constraint_residuals(
    raw_normalized: torch.Tensor,
    clean_raw_normalized: torch.Tensor,
    *,
    epsilon: float,
    mean_raw: torch.Tensor,
    std_raw: torch.Tensor,
    raw_prev: torch.Tensor,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    budget = (raw_normalized - clean_raw_normalized).abs().flatten(1).amax(1) - float(epsilon)
    physical = denormalize(raw_normalized.float(), mean_raw, std_raw)
    prev = torch.cat([raw_prev.reshape(-1, 1, 6), physical[:, :-1]], dim=1)
    dlat = (physical[..., 0] - prev[..., 0]).abs() / PHYS_DLAT_MAX - 1.0
    dlon = (physical[..., 1] - prev[..., 1]).abs() / PHYS_DLON_MAX - 1.0
    dalt = (physical[..., 2] - prev[..., 2]).abs() / PHYS_DALT_MAX - 1.0
    speed_delta = (physical[..., 3] - prev[..., 3]).abs() / PHYS_DV_MAX - 1.0
    h_prev = torch.atan2(prev[..., 4], prev[..., 5])
    h_cur = torch.atan2(physical[..., 4], physical[..., 5])
    heading = wrap((h_cur - h_prev) * (180.0 / torch.pi)).abs() / PHYS_DH_DEG_MAX - 1.0
    kinematic = torch.stack(
        [dlat.amax(1), dlon.amax(1), dalt.amax(1), speed_delta.amax(1), heading.amax(1)], dim=1
    ).amax(1)
    speed_domain = -physical[..., 3].amin(1)
    heading_domain = (torch.linalg.norm(physical[..., 4:6], dim=-1) - 1.0).abs().amax(1)
    domain = torch.maximum(speed_domain, heading_domain)
    return budget.clamp_min(0.0), kinematic.clamp_min(0.0), domain.clamp_min(0.0)


def _kinematic_violation_components(
    raw_normalized: torch.Tensor,
    *,
    mean_raw: torch.Tensor,
    std_raw: torch.Tensor,
    raw_prev: torch.Tensor,
) -> dict[str, torch.Tensor]:
    physical = denormalize(raw_normalized.float(), mean_raw, std_raw)
    prev = torch.cat([raw_prev.reshape(-1, 1, 6), physical[:, :-1]], dim=1)
    h_prev = torch.atan2(prev[..., 4], prev[..., 5])
    h_cur = torch.atan2(physical[..., 4], physical[..., 5])
    values = {
        "kinematic_latitude_rel_violation": (physical[..., 0] - prev[..., 0]).abs() / PHYS_DLAT_MAX - 1.0,
        "kinematic_longitude_rel_violation": (physical[..., 1] - prev[..., 1]).abs() / PHYS_DLON_MAX - 1.0,
        "kinematic_altitude_rel_violation": (physical[..., 2] - prev[..., 2]).abs() / PHYS_DALT_MAX - 1.0,
        "kinematic_speed_rel_violation": (physical[..., 3] - prev[..., 3]).abs() / PHYS_DV_MAX - 1.0,
        "kinematic_heading_rel_violation": wrap((h_cur - h_prev) * (180.0 / torch.pi)).abs()
        / PHYS_DH_DEG_MAX
        - 1.0,
    }
    return {key: value.amax(1).clamp_min(0.0) for key, value in values.items()}


def strict_intersection_project(
    raw_normalized: torch.Tensor,
    clean_raw_normalized: torch.Tensor,
    *,
    epsilon: float,
    mean_raw: torch.Tensor,
    std_raw: torch.Tensor,
    raw_prev: torch.Tensor,
    tolerance: float | None = None,
    budget_abs_tol: float | None = None,
    kinematic_rel_tol: float | None = None,
    projection_residual_tol: float | None = None,
    maximum_iterations: int,
) -> ProjectionResult:
    """Alternating projection with explicit per-sample convergence status."""
    budget_tol = float(budget_abs_tol if budget_abs_tol is not None else tolerance)
    kinematic_tol = float(kinematic_rel_tol if kinematic_rel_tol is not None else tolerance)
    residual_tol = float(projection_residual_tol if projection_residual_tol is not None else tolerance)
    if maximum_iterations < 1 or min(budget_tol, kinematic_tol, residual_tol) < 0:
        raise ValueError("projection maximum_iterations must be >=1 and tolerances >=0")
    clean_res = _constraint_residuals(
        clean_raw_normalized,
        clean_raw_normalized,
        epsilon=epsilon,
        mean_raw=mean_raw,
        std_raw=std_raw,
        raw_prev=raw_prev,
    )
    source_valid = (clean_res[1] <= kinematic_tol) & (clean_res[2] <= kinematic_tol)
    current = raw_normalized.detach().float().clone()
    success = torch.zeros(len(current), dtype=torch.bool, device=current.device)
    infeasible_fixed_point = torch.zeros(len(current), dtype=torch.bool, device=current.device)
    pending = torch.ones(len(current), dtype=torch.bool, device=current.device)
    iterations = torch.zeros(len(current), dtype=torch.long, device=current.device)
    b_res = torch.full((len(current),), float("inf"), device=current.device)
    k_res = torch.full((len(current),), float("inf"), device=current.device)
    d_res = torch.full((len(current),), float("inf"), device=current.device)
    projection_residual = torch.full((len(current),), float("inf"), device=current.device)
    for iteration in range(1, maximum_iterations + 1):
        indices = pending.nonzero(as_tuple=False).flatten()
        if len(indices) == 0:
            break
        previous = current.index_select(0, indices).clone()
        clean_active = clean_raw_normalized.index_select(0, indices)
        raw_prev_active = raw_prev.index_select(0, indices)
        projected = budget_project(previous, clean_active, epsilon)
        projected = raw_domain_sanitize(projected, mean_raw, std_raw)
        projected = kinematic_project(
            projected, mean_raw=mean_raw, std_raw=std_raw, raw_prev=raw_prev_active
        )
        # A final budget projection is mandatory; the next round can repair any
        # kinematic residual introduced by it.
        projected = budget_project(projected, clean_active, epsilon)
        b_active, k_active, d_active = _constraint_residuals(
            projected,
            clean_active,
            epsilon=epsilon,
            mean_raw=mean_raw,
            std_raw=std_raw,
            raw_prev=raw_prev_active,
        )
        residual_active = (projected - previous).abs().flatten(1).amax(1)
        constraints_active = (
            (b_active <= budget_tol)
            & (k_active <= kinematic_tol)
            & (d_active <= kinematic_tol)
        )
        converged_active = constraints_active & (residual_active <= residual_tol)
        # The projection map is deterministic.  If it returns the exact same
        # FP32 tensor while constraints remain violated, further applications
        # cannot make progress and this is an infeasible fixed point, not a
        # maximum-iteration convergence failure.
        fixed_point_active = (~constraints_active) & (residual_active == 0)
        current[indices] = projected
        b_res[indices] = b_active
        k_res[indices] = k_active
        d_res[indices] = d_active
        projection_residual[indices] = residual_active
        iterations[indices] = iteration
        converged_indices = indices[converged_active]
        fixed_point_indices = indices[fixed_point_active]
        success[converged_indices] = True
        infeasible_fixed_point[fixed_point_indices] = True
        pending[indices[converged_active | fixed_point_active]] = False
    # Independent checker: recompute from the returned tensor, never reuse a
    # projector-internal success flag.
    cb, ck, cd = _constraint_residuals(
        current,
        clean_raw_normalized,
        epsilon=epsilon,
        mean_raw=mean_raw,
        std_raw=std_raw,
        raw_prev=raw_prev,
    )
    checked = (cb <= budget_tol) & (ck <= kinematic_tol) & (cd <= kinematic_tol)
    success = success & checked
    statuses: list[ProjectionStatus] = []
    for i in range(len(current)):
        if bool(success[i]):
            reason = "converged"
        elif bool(infeasible_fixed_point[i]) and not bool(source_valid[i]):
            reason = "source_invalid_and_infeasible_fixed_point"
        elif bool(infeasible_fixed_point[i]):
            reason = "infeasible_fixed_point"
        elif not bool(source_valid[i]):
            reason = "source_invalid_and_projection_not_converged"
        else:
            reason = "projection_not_converged"
        statuses.append(
            ProjectionStatus(
                success=bool(success[i]),
                reason=reason,
                iterations=int(iterations[i].detach().cpu()),
                budget_residual=float(b_res[i].detach().cpu()),
                kinematic_residual=float(k_res[i].detach().cpu()),
                domain_residual=float(d_res[i].detach().cpu()),
                source_valid=bool(source_valid[i]),
                independently_checked=bool(checked[i]),
                projection_residual=float(projection_residual[i].detach().cpu()),
            )
        )
    return ProjectionResult(current.detach(), statuses)


def targeted_losses(logits: torch.Tensor, loss_id: LossId, *, kappa: float = 0.0) -> dict[str, torch.Tensor]:
    target = torch.zeros(len(logits), dtype=torch.long, device=logits.device)
    target_ce = F.cross_entropy(logits, target, reduction="none")
    # All objectives are minimized.  z_anomaly-z_normal is the untruncated
    # ranking value even when the CW hinge reaches zero.
    ranking_margin = logits[:, 1] - logits[:, 0]
    if loss_id == "targeted_ce":
        objective = target_ce
    elif loss_id == "targeted_logit_margin":
        objective = ranking_margin
    elif loss_id == "targeted_cw_margin":
        objective = torch.relu(ranking_margin + float(kappa))
    else:
        raise ValueError(f"unknown targeted loss: {loss_id}")
    probabilities = torch.softmax(logits, dim=1)
    return {
        "objective": objective,
        "ranking_margin": ranking_margin,
        "z_normal_minus_z_anomaly": logits[:, 0] - logits[:, 1],
        "p_normal": probabilities[:, 0],
        "p_anomaly": probabilities[:, 1],
        "target_ce": target_ce,
    }


def perturbation_distances(candidate: torch.Tensor, clean: torch.Tensor) -> dict[str, torch.Tensor]:
    return {
        "linf_raw6_normalized": (candidate[..., :6] - clean[..., :6]).abs().flatten(1).amax(1),
        "linf_difference6_normalized": (candidate[..., 6:12] - clean[..., 6:12]).abs().flatten(1).amax(1),
        "linf_full12_normalized": (candidate - clean).abs().flatten(1).amax(1),
    }


def _assert_recomputed(candidate: torch.Tensor, raw: torch.Tensor, ctx: dict[str, torch.Tensor]) -> None:
    rebuilt = _pack_norm12_from_raw_norm(raw, ctx["raw_prev"], ctx["m32"], ctx["s32"])
    if not torch.allclose(candidate.float(), rebuilt.float(), atol=1e-6, rtol=1e-5):
        raise AssertionError("difference features were not recomputed from attacked raw")


@contextmanager
def _fp32_eval_mode(model: torch.nn.Module) -> Iterator[None]:
    # cuDNN RNN backward requires training mode.  The shared attack context
    # uses training mode while disabling every dropout source, then restores
    # the caller's exact mode on exit.
    with _attack_grad_context(model):
        with torch.autocast(device_type=next(model.parameters()).device.type, enabled=False):
            yield


def _initialize(
    config: AttackConfig,
    restart_id: int,
    ctx: dict[str, torch.Tensor],
) -> tuple[torch.Tensor, list[InitializationStatus], list[ProjectionStatus]]:
    seed = config.restart_seed(restart_id)
    generator = torch.Generator(device=ctx["raw_n0"].device)
    generator.manual_seed(seed)
    clean = ctx["raw_n0"]
    if config.initialization == "clean":
        return clean.clone(), [InitializationStatus(True, "clean", restart_id, seed, 1, "ok")] * len(clean), []
    attempts = 1 if config.initialization == "uniform_budget" else int(config.feasible_random_resampling_count or 0)
    last = clean.clone()
    projection_statuses: list[ProjectionStatus] = []
    init_ok = torch.zeros(len(clean), dtype=torch.bool, device=clean.device)
    selected = clean.clone()
    used_attempt = torch.zeros(len(clean), dtype=torch.long, device=clean.device)
    for attempt in range(1, attempts + 1):
        noise = torch.empty(clean.shape, device=clean.device, dtype=torch.float32).uniform_(
            -config.epsilon, config.epsilon, generator=generator
        )
        candidate = raw_domain_sanitize(clean + noise, ctx["m_r"], ctx["s_r"])
        candidate = budget_project(candidate, clean, config.epsilon)
        last = candidate
        if config.initialization == "uniform_budget":
            selected = candidate
            init_ok[:] = True
            used_attempt[:] = 1
            break
        projected = strict_intersection_project(
            candidate,
            clean,
            epsilon=config.epsilon,
            mean_raw=ctx["m_r"],
            std_raw=ctx["s_r"],
            raw_prev=ctx["raw_prev"],
            tolerance=config.projection_tolerance,
            budget_abs_tol=config.budget_abs_tol,
            kinematic_rel_tol=config.kinematic_rel_tol,
            projection_residual_tol=config.projection_residual_tol,
            maximum_iterations=int(config.maximum_alternating_projection_iterations),
        )
        projection_statuses.extend(projected.statuses)
        ok = torch.tensor([status.success for status in projected.statuses], device=clean.device)
        take = ok & ~init_ok
        selected[take] = projected.tensor[take]
        used_attempt[take] = attempt
        init_ok |= ok
        if bool(init_ok.all()):
            break
    statuses = [
        InitializationStatus(
            success=bool(init_ok[i]),
            initialization=config.initialization,
            restart_id=restart_id,
            seed=seed,
            attempts=int(used_attempt[i]) if bool(init_ok[i]) else attempts,
            reason="ok" if bool(init_ok[i]) else "feasible_random_exhausted",
        )
        for i in range(len(clean))
    ]
    # Failed samples retain a deterministic tensor only for logging.  Their
    # explicit failure mask prevents it from becoming a valid candidate.
    selected[~init_ok] = last[~init_ok]
    return selected, statuses, projection_statuses


def _samplewise_assign(destination: torch.Tensor, source: torch.Tensor, mask: torch.Tensor) -> None:
    destination[mask] = source[mask].detach()


def run_attack(
    model: torch.nn.Module,
    clean: torch.Tensor,
    labels: torch.Tensor,
    *,
    norm_mean: Any,
    norm_std: Any,
    frozen_threshold: float,
    config: AttackConfig,
) -> AttackResult:
    """Run a P0 audit attack in FP32 and preserve all diagnostic directions."""
    config.validate(for_execution=True)
    if clean.ndim != 3 or clean.shape[-1] != 12:
        raise ValueError("audit attack requires normalized (B,T,12) input")
    if not bool((labels == 1).all()):
        raise ValueError("run_attack accepts anomaly-labelled samples only; use attack_malicious_only")
    clean32 = clean.detach().float()
    ctx = _raw12_context(clean32, norm_mean, norm_std)
    batch = len(clean32)
    best_loss = torch.full((batch,), float("inf"), device=clean.device)
    best_rank = torch.full((batch,), float("inf"), device=clean.device)
    best_iterate = torch.full_like(clean32, float("nan"))
    have_best = torch.zeros(batch, dtype=torch.bool, device=clean.device)
    final_iterate = clean32.clone()
    selected_restart = torch.full((batch,), -1, dtype=torch.long, device=clean.device)
    selected_final_restart = torch.full((batch,), -1, dtype=torch.long, device=clean.device)
    best_final_loss = torch.full((batch,), float("inf"), device=clean.device)
    best_final_rank = torch.full((batch,), float("inf"), device=clean.device)
    first_threshold: list[torch.Tensor | None] = [None] * batch
    first_argmax: list[torch.Tensor | None] = [None] * batch
    best_feasible: list[torch.Tensor | None] = [None] * batch
    best_feasible_rank = torch.full((batch,), float("inf"), device=clean.device)
    best_feasible_any: list[torch.Tensor | None] = [None] * batch
    best_feasible_any_rank = torch.full((batch,), float("inf"), device=clean.device)
    all_diags: list[dict[str, Any]] = []
    all_projection: list[ProjectionStatus] = []
    all_initialization: list[InitializationStatus] = []
    final_threshold = torch.zeros(batch, dtype=torch.bool, device=clean.device)
    final_argmax = torch.zeros(batch, dtype=torch.bool, device=clean.device)
    final_feasible = torch.zeros(batch, dtype=torch.bool, device=clean.device)
    clean_b_res, clean_k_res, clean_d_res = _constraint_residuals(
        ctx["raw_n0"],
        ctx["raw_n0"],
        epsilon=config.epsilon,
        mean_raw=ctx["m_r"],
        std_raw=ctx["s_r"],
        raw_prev=ctx["raw_prev"],
    )
    clean_source_valid = (clean_k_res <= float(config.kinematic_rel_tol or config.projection_tolerance or 0.0)) & (
        clean_d_res <= float(config.kinematic_rel_tol or config.projection_tolerance or 0.0)
    )

    with _fp32_eval_mode(model):
        for restart in range(config.restarts):
            raw, init_status, init_projection = _initialize(config, restart, ctx)
            all_initialization.extend(init_status)
            all_projection.extend(init_projection)
            active = torch.tensor([status.success for status in init_status], device=clean.device)
            last_projection = [
                ProjectionStatus(True, "not_required", 0, 0.0, 0.0, 0.0, True, True)
                for _ in range(batch)
            ]
            for step in range(config.steps + 1):
                raw = raw.detach().requires_grad_(step < config.steps)
                packed = _pack_norm12_from_raw_norm(raw, ctx["raw_prev"], ctx["m32"], ctx["s32"])
                _assert_recomputed(packed, raw, ctx)
                logits = model(packed.float())
                losses = targeted_losses(logits, config.loss, kappa=config.cw_kappa)
                threshold_ok = losses["p_anomaly"] < float(frozen_threshold)
                argmax_ok = logits.argmax(1) == config.normal_class
                physical = denormalize(raw.float(), ctx["m_r"], ctx["s_r"])
                b_res, k_res, d_res = _constraint_residuals(
                    raw,
                    ctx["raw_n0"],
                    epsilon=config.epsilon,
                    mean_raw=ctx["m_r"],
                    std_raw=ctx["s_r"],
                    raw_prev=ctx["raw_prev"],
                )
                budget_tol = float(
                    config.budget_abs_tol
                    if config.budget_abs_tol is not None
                    else (config.projection_tolerance or 0.0)
                )
                kinematic_tol = float(
                    config.kinematic_rel_tol
                    if config.kinematic_rel_tol is not None
                    else (config.projection_tolerance or 0.0)
                )
                feasible = (b_res <= budget_tol) & (k_res <= kinematic_tol) & (d_res <= kinematic_tol)
                distances = perturbation_distances(packed, clean32)
                if bool((distances["linf_raw6_normalized"] > config.epsilon + 1e-6).any()):
                    raise AssertionError("budget_scope does not match normalized_raw6 projector")
                objective = losses["objective"].detach()
                ranking = losses["ranking_margin"].detach()
                # CW ties are resolved using the untruncated margin.
                stronger = active & ((objective < best_loss) | ((objective == best_loss) & (ranking < best_rank)))
                _samplewise_assign(best_iterate, packed, stronger)
                best_loss[stronger] = objective[stronger]
                best_rank[stronger] = ranking[stronger]
                selected_restart[stronger] = restart
                have_best |= stronger
                for i in range(batch):
                    if bool(active[i] & feasible[i]) and ranking[i] < best_feasible_any_rank[i]:
                        best_feasible_any[i] = packed[i].detach().clone()
                        best_feasible_any_rank[i] = ranking[i]
                    if bool(active[i] & threshold_ok[i]) and first_threshold[i] is None:
                        first_threshold[i] = packed[i].detach().clone()
                    if bool(active[i] & argmax_ok[i]) and first_argmax[i] is None:
                        first_argmax[i] = packed[i].detach().clone()
                    if bool(active[i] & (threshold_ok[i] | argmax_ok[i]) & feasible[i]):
                        if ranking[i] < best_feasible_rank[i]:
                            best_feasible[i] = packed[i].detach().clone()
                            best_feasible_rank[i] = ranking[i]
                components = _kinematic_violation_components(
                    raw, mean_raw=ctx["m_r"], std_raw=ctx["s_r"], raw_prev=ctx["raw_prev"]
                )
                raw_delta = (raw.detach() - ctx["raw_n0"]).abs()
                saturation_tolerance = max(1e-7, budget_tol)
                raw_saturation = raw_delta >= max(float(config.epsilon) - saturation_tolerance, 0.0)
                raw_boundary_saturation_rate = raw_saturation.float().mean(dim=(1, 2))
                raw_feature_saturation = raw_saturation.any(dim=1)
                nan_vector = torch.full((batch,), float("nan"), device=clean.device)
                gradient_l1 = nan_vector
                gradient_l2 = nan_vector
                gradient_linf = nan_vector
                zero_gradient = torch.zeros(batch, dtype=torch.bool, device=clean.device)
                pre_projection_loss = objective
                post_projection_loss = objective
                pre_projection_target_ce = losses["target_ce"].detach()
                post_projection_target_ce = losses["target_ce"].detach()
                pre_projection_margin = losses["z_normal_minus_z_anomaly"].detach()
                post_projection_margin = losses["z_normal_minus_z_anomaly"].detach()
                projection_residual_step = torch.zeros(batch, device=clean.device)
                projection_iterations_step = torch.zeros(batch, dtype=torch.long, device=clean.device)
                projection_converged_step = torch.ones(batch, dtype=torch.bool, device=clean.device)
                projection_reason_step = ["not_required"] * batch
                projection_source_valid_step = torch.ones(batch, dtype=torch.bool, device=clean.device)
                projection_independently_checked_step = torch.ones(
                    batch, dtype=torch.bool, device=clean.device
                )
                raw_next = raw.detach()
                if step < config.steps:
                    scalar = losses["objective"].mean()
                    if config.attack_id in {"phys_penalty_pgd", "phys_hybrid_pgd"}:
                        scalar = scalar + float(config.lambda_phys) * physical_penalty(
                            physical, raw_prev=ctx["raw_prev"]
                        )
                    (gradient,) = torch.autograd.grad(scalar, raw)
                    flat_gradient = gradient.detach().flatten(1)
                    gradient_l1 = flat_gradient.abs().sum(1)
                    gradient_l2 = torch.linalg.vector_norm(flat_gradient, ord=2, dim=1)
                    gradient_linf = flat_gradient.abs().amax(1)
                    zero_gradient = gradient_linf <= 1e-12
                    with torch.no_grad():
                        raw_next = raw - float(config.alpha) * gradient.sign()
                        raw_next = budget_project(raw_next, ctx["raw_n0"], config.epsilon)
                        raw_next = raw_domain_sanitize(raw_next, ctx["m_r"], ctx["s_r"])
                        raw_next = budget_project(raw_next, ctx["raw_n0"], config.epsilon)
                        pre_packed = _pack_norm12_from_raw_norm(
                            raw_next, ctx["raw_prev"], ctx["m32"], ctx["s32"]
                        )
                        pre_projection_values = targeted_losses(
                            model(pre_packed.float()), config.loss, kappa=config.cw_kappa
                        )
                        pre_projection_loss = pre_projection_values["objective"].detach()
                        pre_projection_target_ce = pre_projection_values["target_ce"].detach()
                        pre_projection_margin = pre_projection_values["z_normal_minus_z_anomaly"].detach()
                        use_hard = config.attack_id == "phys_projection_pgd"
                        if config.attack_id == "phys_hybrid_pgd":
                            if config.projection_schedule == "none":
                                use_hard = False
                            elif config.projection_schedule == "final_only":
                                use_hard = step + 1 == config.steps
                            else:
                                use_hard = (
                                    float(step + 1) / max(float(config.steps), 1.0)
                                    >= float(config.hard_projection_start_ratio)
                                ) or step + 1 == config.steps
                        if use_hard:
                            projected = strict_intersection_project(
                                raw_next,
                                ctx["raw_n0"],
                                epsilon=config.epsilon,
                                mean_raw=ctx["m_r"],
                                std_raw=ctx["s_r"],
                                raw_prev=ctx["raw_prev"],
                                tolerance=config.projection_tolerance,
                                budget_abs_tol=config.budget_abs_tol,
                                kinematic_rel_tol=config.kinematic_rel_tol,
                                projection_residual_tol=config.projection_residual_tol,
                                maximum_iterations=int(config.maximum_alternating_projection_iterations),
                            )
                            raw_next = projected.tensor
                            last_projection = projected.statuses
                            all_projection.extend(projected.statuses)
                            projection_ok = torch.tensor(
                                [status.success for status in projected.statuses], device=clean.device
                            )
                            projection_residual_step = torch.tensor(
                                [status.projection_residual for status in projected.statuses], device=clean.device
                            )
                            projection_iterations_step = torch.tensor(
                                [status.iterations for status in projected.statuses], device=clean.device
                            )
                            projection_converged_step = projection_ok
                            projection_reason_step = [status.reason for status in projected.statuses]
                            projection_source_valid_step = torch.tensor(
                                [status.source_valid for status in projected.statuses], device=clean.device
                            )
                            projection_independently_checked_step = torch.tensor(
                                [status.independently_checked for status in projected.statuses],
                                device=clean.device,
                            )
                            active &= projection_ok
                        post_packed = _pack_norm12_from_raw_norm(
                            raw_next, ctx["raw_prev"], ctx["m32"], ctx["s32"]
                        )
                        post_projection_values = targeted_losses(
                            model(post_packed.float()), config.loss, kappa=config.cw_kappa
                        )
                        post_projection_loss = post_projection_values["objective"].detach()
                        post_projection_target_ce = post_projection_values["target_ce"].detach()
                        post_projection_margin = post_projection_values["z_normal_minus_z_anomaly"].detach()
                all_diags.append(
                    {
                        "restart_id": restart,
                        "step": step,
                        "objective": objective.cpu().tolist(),
                        "untruncated_z_anomaly_minus_z_normal": ranking.cpu().tolist(),
                        "z_normal_minus_z_anomaly": losses["z_normal_minus_z_anomaly"].detach().cpu().tolist(),
                        "p_normal": losses["p_normal"].detach().cpu().tolist(),
                        "p_anomaly": losses["p_anomaly"].detach().cpu().tolist(),
                        "target_ce": losses["target_ce"].detach().cpu().tolist(),
                        "threshold_success": threshold_ok.detach().cpu().tolist(),
                        "argmax_success": argmax_ok.detach().cpu().tolist(),
                        "candidate_active": active.detach().cpu().tolist(),
                        "feasible": feasible.detach().cpu().tolist(),
                        "budget_valid": (b_res <= budget_tol).detach().cpu().tolist(),
                        "kinematic_valid": ((k_res <= kinematic_tol) & (d_res <= kinematic_tol)).detach().cpu().tolist(),
                        "budget_residual": b_res.detach().cpu().tolist(),
                        "kinematic_residual": k_res.detach().cpu().tolist(),
                        "domain_residual": d_res.detach().cpu().tolist(),
                        "gradient_l1": gradient_l1.detach().cpu().tolist(),
                        "gradient_l2": gradient_l2.detach().cpu().tolist(),
                        "gradient_linf": gradient_linf.detach().cpu().tolist(),
                        "zero_gradient": zero_gradient.detach().cpu().tolist(),
                        "zero_gradient_flag": zero_gradient.detach().cpu().tolist(),
                        "pre_projection_loss": pre_projection_loss.detach().cpu().tolist(),
                        "post_projection_loss": post_projection_loss.detach().cpu().tolist(),
                        "pre_projection_target_ce": pre_projection_target_ce.detach().cpu().tolist(),
                        "post_projection_target_ce": post_projection_target_ce.detach().cpu().tolist(),
                        "pre_projection_margin": pre_projection_margin.detach().cpu().tolist(),
                        "post_projection_margin": post_projection_margin.detach().cpu().tolist(),
                        "projection_residual": projection_residual_step.detach().cpu().tolist(),
                        "projection_iterations": projection_iterations_step.detach().cpu().tolist(),
                        "projection_converged": projection_converged_step.detach().cpu().tolist(),
                        "projection_reason": projection_reason_step,
                        "projection_status": projection_reason_step,
                        "projection_source_valid": projection_source_valid_step.detach().cpu().tolist(),
                        "projection_independently_checked": projection_independently_checked_step.detach().cpu().tolist(),
                        "initialization_status": [status.reason for status in init_status],
                        "initialization_success": [status.success for status in init_status],
                        "initialization_attempts": [status.attempts for status in init_status],
                        "source_valid": clean_source_valid.detach().cpu().tolist(),
                        "post_valid": feasible.detach().cpu().tolist(),
                        "feasible_success": (feasible & threshold_ok).detach().cpu().tolist(),
                        "raw_boundary_saturation_rate": raw_boundary_saturation_rate.detach().cpu().tolist(),
                        "raw_latitude_saturated": raw_feature_saturation[:, 0].detach().cpu().tolist(),
                        "raw_longitude_saturated": raw_feature_saturation[:, 1].detach().cpu().tolist(),
                        "raw_altitude_saturated": raw_feature_saturation[:, 2].detach().cpu().tolist(),
                        "raw_speed_saturated": raw_feature_saturation[:, 3].detach().cpu().tolist(),
                        "raw_heading_sin_saturated": raw_feature_saturation[:, 4].detach().cpu().tolist(),
                        "raw_heading_cos_saturated": raw_feature_saturation[:, 5].detach().cpu().tolist(),
                        **{key: value.detach().cpu().tolist() for key, value in components.items()},
                        **{key: value.detach().cpu().tolist() for key, value in distances.items()},
                    }
                )
                if step == config.steps:
                    final_eligible = active & (feasible if config.attack_id in {"phys_projection_pgd", "phys_penalty_pgd", "phys_hybrid_pgd"} else torch.ones_like(active))
                    stronger_final = final_eligible & (
                        (objective < best_final_loss) | ((objective == best_final_loss) & (ranking < best_final_rank))
                    )
                    _samplewise_assign(final_iterate, packed, stronger_final)
                    best_final_loss[stronger_final] = objective[stronger_final]
                    best_final_rank[stronger_final] = ranking[stronger_final]
                    selected_final_restart[stronger_final] = restart
                    final_threshold[stronger_final] = threshold_ok[stronger_final].detach()
                    final_argmax[stronger_final] = argmax_ok[stronger_final].detach()
                    final_feasible[stronger_final] = feasible[stronger_final].detach()
                    break
                raw = raw_next

    def _stack_optional(items: list[torch.Tensor | None]) -> torch.Tensor | None:
        if not any(item is not None for item in items):
            return None
        output = torch.full_like(clean32, float("nan"))
        for i, item in enumerate(items):
            if item is not None:
                output[i] = item
        return output

    feasible_mask = torch.tensor([item is not None for item in best_feasible], device=clean.device)
    failures = ["ok" if bool(have_best[i]) else "no_valid_candidate" for i in range(batch)]
    return AttackResult(
        final_iterate=final_iterate,
        best_target_loss_iterate=best_iterate.detach() if bool(have_best.any()) else None,
        first_threshold_success_iterate=_stack_optional(first_threshold),
        first_argmax_success_iterate=_stack_optional(first_argmax),
        best_feasible_successful_iterate=_stack_optional(best_feasible),
        best_feasible_iterate=_stack_optional(best_feasible_any),
        per_step_diagnostics=all_diags,
        projection_status=all_projection or last_projection,
        initialization_status=all_initialization,
        restart_id=selected_restart,
        final_restart_id=selected_final_restart,
        attack_config_hash=config.config_hash,
        best_target_loss=best_loss,
        threshold_success=torch.tensor([item is not None for item in first_threshold], device=clean.device),
        argmax_success=torch.tensor([item is not None for item in first_argmax], device=clean.device),
        feasible_success=feasible_mask,
        final_feasible=final_feasible,
        failure_reasons=failures,
    )


def attack_malicious_only(
    model: torch.nn.Module,
    inputs: torch.Tensor,
    labels: torch.Tensor,
    **kwargs: Any,
) -> tuple[torch.Tensor, AttackResult | None]:
    """Attack y=1 rows while preserving every normal row bit-for-bit."""
    malicious = labels == 1
    if not bool(malicious.any()):
        return inputs.clone(), None
    result = run_attack(model, inputs[malicious], labels[malicious], **kwargs)
    output = inputs.clone()
    chosen = result.best_target_loss_iterate
    if chosen is not None:
        valid = result.restart_id >= 0
        malicious_indices = malicious.nonzero(as_tuple=False).flatten()
        output[malicious_indices[valid]] = chosen[valid].to(dtype=output.dtype)
    if not torch.equal(output[~malicious], inputs[~malicious]):
        raise AssertionError("normal samples changed inside malicious-only attack")
    return output, result


__all__ = [
    "AttackConfig",
    "AttackResult",
    "InitializationStatus",
    "ProjectionResult",
    "ProjectionStatus",
    "attack_malicious_only",
    "budget_project",
    "kinematic_project",
    "perturbation_distances",
    "raw_domain_sanitize",
    "run_attack",
    "strict_intersection_project",
    "targeted_losses",
]

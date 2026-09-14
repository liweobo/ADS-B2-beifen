from __future__ import annotations

from contextlib import contextmanager
from typing import Callable

import numpy as np
import torch
import torch.nn as nn

from adsb.data import denormalize
from adsb.utils import _autocast_disabled_for

_CE = nn.CrossEntropyLoss()
_DEG_PER_RAD = 180.0 / np.pi
_RAD_PER_DEG = np.pi / 180.0

# 反归一化后 raw 空间、相邻窗口时间步之间的增量上界（与 ``physical_proj`` / 物理可行性评价一致）
PHYS_DV_MAX = 20.0       #速度增量上界
PHYS_DALT_MAX = 1000.0   #高度增量上界
PHYS_DH_DEG_MAX = 5.0   #航向增量上界
PHYS_DLAT_MAX = 0.045   #纬度增量上界
PHYS_DLON_MAX = 0.05   #经度增量上界
PHYS_DIRECTION_MIN_REF_NORM = 1e-9   #方向约束最小参考范数
PHYS_USE_DIRECTION_CONSTRAINT = False   #关闭 diff_ref 方向对齐约束；仍保留软限幅和物理阈值


@contextmanager
def _attack_grad_context(model: nn.Module):     #在PGD发动期间，强行冻结网络中所有的Dropout层
    """
    对抗梯度：冻结 Dropout（含 ``nn.LSTM`` 层间 dropout），避免 PGD 每步梯度混淆；
    保持 ``model.train()`` 且 **不** 关闭 cuDNN，LSTM 仍走快速 fused RNN 反传。
    """
    was_training = model.training
    dropout_restore: list[tuple[nn.Dropout, bool]] = []
    lstm_dropout_restore: list[tuple[nn.LSTM, float]] = []

    model.train()
    for module in model.modules():
        if isinstance(module, nn.Dropout):
            dropout_restore.append((module, module.training))
            module.eval()
        elif isinstance(module, nn.LSTM) and float(module.dropout) > 0.0:
            lstm_dropout_restore.append((module, float(module.dropout)))
            module.dropout = 0.0

    try:
        yield
    finally:
        for module, prev in dropout_restore:
            module.train(prev)
        for module, prev_drop in lstm_dropout_restore:
            module.dropout = prev_drop
        model.train(was_training)


def _as_f32_ms(m, s, device: torch.device) -> tuple[torch.Tensor, torch.Tensor]:        #将m和s转换为float32类型
    m32 = torch.as_tensor(m, dtype=torch.float32, device=device)
    s32 = torch.as_tensor(s, dtype=torch.float32, device=device)
    return m32, s32


def _linf_project(x: torch.Tensor, x0: torch.Tensor, eps: float) -> torch.Tensor:       #将x投影到x0的epsilon范围内
    return torch.max(torch.min(x, x0 + eps), x0 - eps)


def _attack_grad(
    model: nn.Module,
    x_in: torch.Tensor,
    y: torch.Tensor,
    var: torch.Tensor,
    *,
    targeted: bool = True,
    target_label: int = 0,
) -> torch.Tensor:
    logits = model(x_in)
    if targeted:
        target = torch.full_like(y, int(target_label))
        loss = _CE(logits, target)
        sign = -1.0
    else:
        loss = _CE(logits, y)
        sign = 1.0
    (gr,) = torch.autograd.grad(loss, var, retain_graph=False, create_graph=False)
    return sign * gr


def _raw_prev_from_window_denorm(X_norm: torch.Tensor, m: torch.Tensor, s: torch.Tensor) -> torch.Tensor:       #获取上一帧的raw数据
    m32, s32 = _as_f32_ms(m, s, X_norm.device)
    xr = denormalize(X_norm.detach().float(), m32, s32)
    return (xr[:, 0, :6] - xr[:, 0, 6:12]).detach()


def _diff_phys_from_raw(raw_phys: torch.Tensor, raw_prev_phys: torch.Tensor) -> torch.Tensor:       #计算差分特征
    B, T, _ = raw_phys.shape
    d = torch.zeros_like(raw_phys)
    d[:, 0, :] = raw_phys[:, 0, :] - raw_prev_phys
    if T > 1:
        d[:, 1:, :] = raw_phys[:, 1:, :] - raw_phys[:, :-1, :]
    return d


def _pack_norm12_from_raw_norm(
    raw_norm: torch.Tensor,
    raw_prev_phys: torch.Tensor,
    m: torch.Tensor,
    s: torch.Tensor,
) -> torch.Tensor:
    m32, s32 = _as_f32_ms(m, s, raw_norm.device)
    m_r, s_r = m32[..., :6], s32[..., :6]
    m_d, s_d = m32[..., 6:12], s32[..., 6:12]
    raw_phys = denormalize(raw_norm.float(), m_r, s_r)       #反归一化raw数据
    diff_phys = _diff_phys_from_raw(raw_phys, raw_prev_phys.to(device=raw_phys.device, dtype=raw_phys.dtype))       #计算差分特征
    diff_norm = (diff_phys - m_d) / s_d       #归一化差分特征
    return torch.cat([raw_norm.float(), diff_norm], dim=-1).to(dtype=raw_norm.dtype)       #将归一化后的原始raw数据和归一化后的差分特征拼接在一起 


def _diff_phys_ref_from_norm(x_norm: torch.Tensor, m, s) -> torch.Tensor:       #反归一化差分特征
    m32, s32 = _as_f32_ms(m, s, x_norm.device)
    return denormalize(x_norm[..., 6:12].detach().float(), m32[..., 6:12], s32[..., 6:12])


def _sanitize_raw_phys(raw_phys: torch.Tensor) -> torch.Tensor:
    raw = raw_phys.clone()
    raw[..., 3] = raw[..., 3].clamp_min(0.0)
    hdg = raw[..., 4:6]
    n = torch.linalg.norm(hdg, dim=-1, keepdim=True)
    hdg_unit = hdg / n.clamp_min(1e-6)
    default = torch.zeros_like(hdg_unit)
    default[..., 1] = 1.0
    raw[..., 4:6] = torch.where(n > 1e-6, hdg_unit, default)
    return raw


def _sanitize_norm_raw(
    raw_n: torch.Tensor,
    raw_n0: torch.Tensor,
    m_r: torch.Tensor,
    s_r: torch.Tensor,
    eps: float,
) -> torch.Tensor:
    raw_phys = denormalize(raw_n.float(), m_r, s_r)
    raw_n = ((_sanitize_raw_phys(raw_phys) - m_r) / s_r).to(dtype=raw_n.dtype)
    return _linf_project(raw_n, raw_n0, eps)


def _use_raw_only_attack(X: torch.Tensor, m, s) -> bool:        #判断是否是12维
    return m is not None and s is not None and X.dim() == 3 and int(X.shape[-1]) == 12


def _raw12_context(X: torch.Tensor, m, s) -> dict[str, torch.Tensor]:       
    x0 = X.detach().to(dtype=torch.float32)
    m32, s32 = _as_f32_ms(m, s, x0.device)
    return {
        "x0": x0,
        "m32": m32,
        "s32": s32,
        "m_r": m32[..., :6],        #差分特征的均值
        "s_r": s32[..., :6],        #差分特征的标准差
        "raw_n0": x0[..., :6].clone(),      # raw特征
        "raw_prev": _raw_prev_from_window_denorm(x0, m32, s32),  # 窗口起点在轨迹上的前一点 raw
        "diff_ref": _diff_phys_ref_from_norm(x0, m32, s32),  # 反归一化后的差分（物理投影方向参考）
    }


def _pgd_full_tensor(
    model: nn.Module,
    x0: torch.Tensor,
    y: torch.Tensor,
    eps: float,
    alpha: float,
    steps: int,
    *,
    after_step: Callable[[torch.Tensor], torch.Tensor] | None = None,
    targeted: bool = True,
    target_label: int = 0,
) -> torch.Tensor:
    x_adv = x0.clone()
    for _ in range(steps):
        x_adv.requires_grad_(True)
        gr = _attack_grad(
            model,
            x_adv,
            y,
            x_adv,
            targeted=targeted,
            target_label=target_label,
        )
        with torch.no_grad():
            x_adv = _linf_project(x_adv.detach() + alpha * gr.sign(), x0, eps)
            if after_step is not None:
                x_adv = after_step(x_adv)
    return x_adv.detach()


def _pgd_raw12(
    model: nn.Module,
    y: torch.Tensor,
    ctx: dict[str, torch.Tensor],
    eps: float,
    alpha: float,       #PGD步长
    steps: int,       #PGD步数
    *,
    after_raw_step: Callable[[torch.Tensor], torch.Tensor] | None = None,
    targeted: bool = True,
    target_label: int = 0,
) -> torch.Tensor:
    raw_n = ctx["raw_n0"].clone()  # 当前扰动中的 raw（归一化）
    raw_n0 = ctx["raw_n0"]  # 干净 raw，用于 L∞ 投影
    for _ in range(steps):
        raw_n.requires_grad_(True)
        # 每步由 raw_n 重算 diff 并拼接 12 维，梯度经 diff 链式回传至 raw_n
        x_in = _pack_norm12_from_raw_norm(raw_n, ctx["raw_prev"], ctx["m32"], ctx["s32"])
        gr = _attack_grad(
            model,
            x_in,
            y,
            raw_n,
            targeted=targeted,
            target_label=target_label,
        )  # 计算梯度
        with torch.no_grad():
            raw_n = _linf_project(raw_n.detach() + alpha * gr.sign(), raw_n0, eps)
            if after_raw_step is not None:
                raw_n = after_raw_step(raw_n)
    # 返回与训练一致的 12 维：最终 raw + 由其推导的 diff
    return _pack_norm12_from_raw_norm(raw_n.detach(), ctx["raw_prev"], ctx["m32"], ctx["s32"])


def _project_phys_on_norm_raw(
    raw_n: torch.Tensor,
    *,      
    m_r: torch.Tensor,      #差分特征的均值
    s_r: torch.Tensor,      #差分特征的标准差
    raw_prev: torch.Tensor,      #窗口起点在轨迹上的前一点 raw
    diff_ref: torch.Tensor,      #差分特征
    soft_limit: bool,      #软约束
) -> torch.Tensor:
    rp = denormalize(raw_n.float(), m_r, s_r)
    rp = physical_proj(rp, raw_prev=raw_prev, diff_ref=diff_ref, soft_limit=soft_limit)
    raw_n = ((rp - m_r) / s_r).to(dtype=raw_n.dtype)
    return raw_n


def _project_phys_on_norm_full(
    x_adv: torch.Tensor,
    *,
    m32: torch.Tensor,
    s32: torch.Tensor,
    diff_ref: torch.Tensor | None,
    soft_limit: bool,
) -> torch.Tensor:
    xr = denormalize(x_adv, m32, s32)
    if int(xr.shape[-1]) == 6:
        xr = physical_proj(xr, diff_ref=diff_ref, soft_limit=soft_limit)
    else:
        raw_prev_phys = xr[:, 0, :6] - xr[:, 0, 6:12]
        xr[:, :, :6] = physical_proj(
            xr[:, :, :6], raw_prev=raw_prev_phys, diff_ref=diff_ref, soft_limit=soft_limit
        )
    x_adv = (xr - m32) / s32
    return x_adv


def apply_pgd_malicious_only(model, X, y, attack_fn, *attack_args, **attack_kwargs):        #仅在恶意样本上应用攻击函数
    """仅在 y==1（恶意）样本上应用 attack_fn，正常样本保持原输入不变。"""
    mal = y == 1
    if not mal.any():
        return X
    X_out = X.clone()
    attacked = attack_fn(model, X[mal], y[mal], *attack_args, **attack_kwargs)
    if isinstance(attacked, tuple):
        X_adv, diagnostics = attacked
        X_out[mal] = X_adv
        return X_out, diagnostics
    X_out[mal] = attacked
    return X_out


def pgd(model, X, y, eps=0.05, m=None, s=None, alpha=0.003, steps=5, targeted=True, target_label=0):
    """Targeted PGD（L_inf）。默认把恶意样本推向正常类 ``target_label=0``。"""
    with _attack_grad_context(model):
        with _autocast_disabled_for(X):
            if _use_raw_only_attack(X, m, s):
                ctx = _raw12_context(X, m, s)
                x_adv = _pgd_raw12(
                    model,
                    y,
                    ctx,
                    eps,
                    alpha,
                    steps,
                    targeted=targeted,
                    target_label=target_label,
                )
                return x_adv.to(dtype=X.dtype)
            x0 = X.detach().to(dtype=torch.float32)
            return _pgd_full_tensor(
                model,
                x0,
                y,
                eps,
                alpha,
                steps,
                targeted=targeted,
                target_label=target_label,
            ).to(dtype=X.dtype)


def wrap(d):
    return (d + 180.0) % 360.0 - 180.0


def _soft_limit_delta(delta: torch.Tensor, limit: float) -> torch.Tensor:       #软约束处理
    lim = float(limit)
    return lim * torch.tanh(delta / lim)


def _hard_limit_delta(delta: torch.Tensor, limit: float) -> torch.Tensor:
    # Keep a tiny interior margin so float32 reconstruction cannot cross the audited bound.
    lim = float(limit) * 0.999
    return delta.clamp(min=-lim, max=lim)


def _soft_limit_scalar_with_direction(      
    d_act: torch.Tensor,
    d_ref: torch.Tensor | None,
    limit: float,
    *,
    soft_limit: bool = False,
) -> torch.Tensor:
    if d_ref is None:
        return _soft_limit_delta(d_act, limit) if soft_limit else _hard_limit_delta(d_act, limit)
    ref_abs = d_ref.abs()
    mag = _soft_limit_delta(d_act.abs(), limit) if soft_limit else _hard_limit_delta(d_act.abs(), limit)
    sign_ref = torch.sign(d_ref)
    sign_ref = torch.where(sign_ref == 0, torch.sign(d_act), sign_ref)
    sign_ref = torch.where(sign_ref == 0, torch.ones_like(sign_ref), sign_ref)
    out = sign_ref * mag
    use_ref = ref_abs > PHYS_DIRECTION_MIN_REF_NORM
    fallback = _soft_limit_delta(d_act, limit) if soft_limit else _hard_limit_delta(d_act, limit)
    return torch.where(use_ref, out, fallback)


def _soft_limit_vector_with_direction(       #向量增量方向约束
    d_act: torch.Tensor,        #经度和纬度的差值（PGD攻击后）
    d_ref: torch.Tensor | None,      #经度和纬度的差分特征(PGD攻击前)
    limit: float,       #经度和纬度大小约束中的最大值
    *,
    axis_limits: tuple[float, ...] | None = None,
    soft_limit: bool = False,
) -> torch.Tensor:
    if d_ref is None:
        if axis_limits is not None and d_act.shape[-1] == len(axis_limits):
            limiter = _soft_limit_delta if soft_limit else _hard_limit_delta
            return torch.stack(
                [limiter(d_act[..., i], lim) for i, lim in enumerate(axis_limits)],
                dim=-1,
            )
        if soft_limit:
            return float(limit) * torch.tanh(d_act / float(limit))
        norm = torch.linalg.norm(d_act, dim=-1, keepdim=True)
        scale = (float(limit) * 0.999 / norm.clamp_min(1e-12)).clamp_max(1.0)
        return d_act * scale
    ref_n = torch.linalg.norm(d_ref, dim=-1)        #移动大小(PGD攻击前，归一化)
    act_n = torch.linalg.norm(d_act, dim=-1)        #移动大小（PGD攻击后，反归一化）
    mag = _soft_limit_delta(act_n, limit) if soft_limit else _hard_limit_delta(act_n, limit)
    dir_ref = d_ref / ref_n.unsqueeze(-1).clamp_min(PHYS_DIRECTION_MIN_REF_NORM)        #确定移动方向的单位向量
    d_aligned = dir_ref * mag.unsqueeze(-1)     #攻击前的移动方向*攻击后的移动大小
    if axis_limits is not None:
        d_aligned = torch.stack(
            [_hard_limit_delta(d_aligned[..., i], lim) for i, lim in enumerate(axis_limits)],
            dim=-1,
        )
    use_ref = ref_n > PHYS_DIRECTION_MIN_REF_NORM
    if soft_limit:
        if axis_limits is not None:
            fallback = torch.stack(
                [_soft_limit_delta(d_act[..., i], lim) for i, lim in enumerate(axis_limits)],
                dim=-1,
            )
        else:
            fallback = dir_ref * _soft_limit_delta(act_n, limit).unsqueeze(-1)
    else:
        if axis_limits is not None:
            fallback = torch.stack(
                [_hard_limit_delta(d_act[..., i], lim) for i, lim in enumerate(axis_limits)],
                dim=-1,
            )
        else:
            scale = (float(limit) * 0.999 / act_n.clamp_min(1e-12)).clamp_max(1.0)
            fallback = d_act * scale.unsqueeze(-1)
    return torch.where(use_ref.unsqueeze(-1), d_aligned, fallback)


def _soft_limit_latlon_with_direction(      #经纬度增量方向约束
    dlat: torch.Tensor,     #当前时间步的值减去上一步的值的差值（PGD攻击后）
    dlon: torch.Tensor,     #当前时间步的值减去上一步的值的差值（PGD攻击后）
    dlat_ref: torch.Tensor | None,      #当前时间步的经度的差分特征（PGD攻击前）
    dlon_ref: torch.Tensor | None,      #当前时间步的纬度的差分特征（PGD攻击前）
    *,
    soft_limit: bool = False,
) -> tuple[torch.Tensor, torch.Tensor]:
    if dlat_ref is None or dlon_ref is None:
        if soft_limit:      #判断软约束是否开启，如果开启进行处理，如果没有开启则不进行处理
            return _soft_limit_delta(dlat, PHYS_DLAT_MAX), _soft_limit_delta(dlon, PHYS_DLON_MAX)
        return _hard_limit_delta(dlat, PHYS_DLAT_MAX), _hard_limit_delta(dlon, PHYS_DLON_MAX)
    d_out = _soft_limit_vector_with_direction(
        torch.stack([dlat, dlon], dim=-1),
        torch.stack([dlat_ref, dlon_ref], dim=-1),
        float(max(PHYS_DLAT_MAX, PHYS_DLON_MAX)),
        axis_limits=(PHYS_DLAT_MAX, PHYS_DLON_MAX),
        soft_limit=soft_limit,
    )
    return d_out[..., 0], d_out[..., 1]     #返回修改后的经度和纬度


def _soft_limit_sincos_with_direction(       #航向增量方向约束
    sin1: torch.Tensor,
    cos1: torch.Tensor,
    sin2: torch.Tensor,
    cos2: torch.Tensor,
    ds_ref: torch.Tensor | None,
    dc_ref: torch.Tensor | None,
    *,
    soft_limit: bool = False,
) -> tuple[torch.Tensor, torch.Tensor]:
    h1 = torch.atan2(sin1, cos1) * _DEG_PER_RAD
    h2 = torch.atan2(sin2, cos2) * _DEG_PER_RAD
    dh_act = wrap(h2 - h1)
    if ds_ref is not None and dc_ref is not None:
        h2_ref = torch.atan2(sin1 + ds_ref, cos1 + dc_ref) * _DEG_PER_RAD
        dh = _soft_limit_scalar_with_direction(
            dh_act, wrap(h2_ref - h1), PHYS_DH_DEG_MAX, soft_limit=soft_limit
        )
    else:
        dh = (
            _soft_limit_delta(dh_act, PHYS_DH_DEG_MAX)
            if soft_limit
            else _hard_limit_delta(dh_act, PHYS_DH_DEG_MAX)
        )
    r = (h1 + dh) * _RAD_PER_DEG
    return torch.sin(r), torch.cos(r)



def _project_one_step(
    cur: torch.Tensor,      #当前时间步的PGD攻击后又限制在epsilon范围内的反归一化特征
    prev: torch.Tensor,     #窗口前一时间步的物理状态
    t: int,      #时间步
    diff_ref: torch.Tensor | None,      #差分特征
    *,
    soft_limit: bool,
    use_direction: bool,
) -> None:
    dref = diff_ref[:, t] if (use_direction and diff_ref is not None) else None     #当前时间步的方向参考；关闭方向约束时不使用
    dlat, dlon = _soft_limit_latlon_with_direction(
        cur[:, 0] - prev[:, 0],
        cur[:, 1] - prev[:, 1],
        dref[:, 0] if dref is not None else None,      #当前时间步的经度的差分特征
        dref[:, 1] if dref is not None else None,      #当前时间步的纬度的差分特征
        soft_limit=soft_limit,
    )
    cur[:, 0] = prev[:, 0] + dlat
    cur[:, 1] = prev[:, 1] + dlon
    cur[:, 2] = prev[:, 2] + _soft_limit_scalar_with_direction(
        cur[:, 2] - prev[:, 2], dref[:, 2] if dref is not None else None, PHYS_DALT_MAX, soft_limit=soft_limit
    )
    cur[:, 3] = prev[:, 3] + _soft_limit_scalar_with_direction(
        cur[:, 3] - prev[:, 3], dref[:, 3] if dref is not None else None, PHYS_DV_MAX, soft_limit=soft_limit
    )
    cur[:, 4], cur[:, 5] = _soft_limit_sincos_with_direction(
        prev[:, 4],
        prev[:, 5],
        cur[:, 4],
        cur[:, 5],
        dref[:, 4] if dref is not None else None,
        dref[:, 5] if dref is not None else None,
        soft_limit=soft_limit,
    )


def physical_proj(
    X,
    raw_prev=None,
    diff_ref=None,
    *,
    soft_limit: bool = False,
    use_direction: bool = PHYS_USE_DIRECTION_CONSTRAINT,
):
    """
    对相邻时刻增量施加物理约束，再累积到状态上。
    ``soft_limit=True`` 时使用 tanh 幅值软限幅，否则执行硬限幅投影。
    ``use_direction=True`` 时才按 ``diff_ref`` 保持原运动方向；当前默认关闭方向约束。
    """
    Xp = X.clone()      #PGD攻击后又限制在epsilon范围内的反归一化特征
    _, T, _ = Xp.shape      #时间步数

    if raw_prev is not None:
        prev = torch.as_tensor(raw_prev, device=Xp.device, dtype=Xp.dtype)
        _project_one_step(
            Xp[:, 0], prev, 0, diff_ref, soft_limit=soft_limit, use_direction=bool(use_direction)
        )

    for t in range(1, T):
        _project_one_step(
            Xp[:, t], Xp[:, t - 1], t, diff_ref, soft_limit=soft_limit, use_direction=bool(use_direction)
        )

    return Xp


def physical_feasibility_counts(X_real, raw_prev=None) -> dict[str, torch.Tensor]:
    """
    统计 raw 物理量轨迹的物理可行性。

    ``X_real`` 形状为 ``(B, T, 6)``，列顺序为 lat/lon/alt/spd/sin_hdg/cos_hdg。
    若提供 ``raw_prev``，则会把窗口首点相对轨迹前一点的增量也纳入统计。
    """
    if X_real.ndim != 3 or int(X_real.shape[-1]) != 6:
        raise ValueError("physical_feasibility_counts 仅支持形状 (B, T, 6) 的 raw 物理量")

    B, T, _ = X_real.shape
    if raw_prev is not None:
        prev = torch.as_tensor(raw_prev, device=X_real.device, dtype=X_real.dtype).reshape(B, 1, 6)
        prev = torch.cat([prev, X_real[:, :-1]], dim=1)
        cur = X_real
    else:
        if T < 2:
            z = torch.zeros((), device=X_real.device, dtype=torch.float32)
            return {
                "physical_total_steps": z,
                "physical_any_violations": z,
                "physical_latlon_violations": z,
                "physical_altitude_violations": z,
                "physical_speed_violations": z,
                "physical_heading_violations": z,
            }
        prev = X_real[:, :-1]
        cur = X_real[:, 1:]

    dlat = (cur[..., 0] - prev[..., 0]).abs() > PHYS_DLAT_MAX
    dlon = (cur[..., 1] - prev[..., 1]).abs() > PHYS_DLON_MAX
    dalt = (cur[..., 2] - prev[..., 2]).abs() > PHYS_DALT_MAX
    dv = (cur[..., 3] - prev[..., 3]).abs() > PHYS_DV_MAX
    h_prev = torch.atan2(prev[..., 4], prev[..., 5]) * _DEG_PER_RAD
    h_cur = torch.atan2(cur[..., 4], cur[..., 5]) * _DEG_PER_RAD
    dh = wrap(h_cur - h_prev).abs() > PHYS_DH_DEG_MAX

    latlon = dlat | dlon
    any_violation = latlon | dalt | dv | dh
    total = torch.as_tensor(any_violation.numel(), device=X_real.device, dtype=torch.float32)
    return {
        "physical_total_steps": total,
        "physical_any_violations": any_violation.sum(dtype=torch.float32),
        "physical_latlon_violations": latlon.sum(dtype=torch.float32),
        "physical_altitude_violations": dalt.sum(dtype=torch.float32),
        "physical_speed_violations": dv.sum(dtype=torch.float32),
        "physical_heading_violations": dh.sum(dtype=torch.float32),
    }


def physical_feasibility_sample_flags(X_real, raw_prev=None) -> dict[str, torch.Tensor]:
    """返回每条轨迹是否违反各类物理约束，供 trajectory-level PVR/PV-ASR 统计。"""
    if X_real.ndim != 3 or int(X_real.shape[-1]) != 6:
        raise ValueError("physical_feasibility_sample_flags 仅支持形状 (B, T, 6) 的 raw 物理量")

    B, T, _ = X_real.shape
    if raw_prev is not None:
        prev = torch.as_tensor(raw_prev, device=X_real.device, dtype=X_real.dtype).reshape(B, 1, 6)
        prev = torch.cat([prev, X_real[:, :-1]], dim=1)
        cur = X_real
    else:
        if T < 2:
            empty = torch.zeros(B, device=X_real.device, dtype=torch.bool)
            return {
                "physical_any_violation": empty,
                "physical_position_violation": empty.clone(),
                "physical_altitude_violation": empty.clone(),
                "physical_speed_violation": empty.clone(),
                "physical_heading_violation": empty.clone(),
            }
        prev = X_real[:, :-1]
        cur = X_real[:, 1:]

    dlat = (cur[..., 0] - prev[..., 0]).abs() > PHYS_DLAT_MAX
    dlon = (cur[..., 1] - prev[..., 1]).abs() > PHYS_DLON_MAX
    dalt = (cur[..., 2] - prev[..., 2]).abs() > PHYS_DALT_MAX
    dv = (cur[..., 3] - prev[..., 3]).abs() > PHYS_DV_MAX
    h_prev = torch.atan2(prev[..., 4], prev[..., 5]) * _DEG_PER_RAD
    h_cur = torch.atan2(cur[..., 4], cur[..., 5]) * _DEG_PER_RAD
    # 航向差沿用项目已有的 circular wrap 逻辑，避免 0/360 度附近误判。
    dh = wrap(h_cur - h_prev).abs() > PHYS_DH_DEG_MAX

    position = (dlat | dlon).any(dim=1)
    altitude = dalt.any(dim=1)
    speed = dv.any(dim=1)
    heading = dh.any(dim=1)
    return {
        "physical_any_violation": position | altitude | speed | heading,
        "physical_position_violation": position,
        "physical_altitude_violation": altitude,
        "physical_speed_violation": speed,
        "physical_heading_violation": heading,
    }


def physical_penalty(
    raw_phys: torch.Tensor,
    raw_prev=None,
    *,
    dv_max: float = PHYS_DV_MAX,
    dalt_max: float = PHYS_DALT_MAX,
    dlat_max: float = PHYS_DLAT_MAX,
    dlon_max: float = PHYS_DLON_MAX,
    dheading_max_rad: float = PHYS_DH_DEG_MAX * _RAD_PER_DEG,
    w_speed: float = 1.0,
    w_altitude: float = 1.0,
    w_latlon: float = 1.0,
    w_heading: float = 1.0,
    return_parts: bool = False,
) -> torch.Tensor | tuple[torch.Tensor, dict[str, torch.Tensor]]:
    """
    可微物理越界惩罚。``raw_phys`` 为物理空间 raw 轨迹，形状 ``(B, T, 6)``，
    列顺序为 lat/lon/alt/speed/sin_heading/cos_heading。
    """
    if raw_phys.ndim != 3 or int(raw_phys.shape[-1]) != 6:
        raise ValueError("physical_penalty 仅支持形状 (B, T, 6) 的 raw 物理量")

    B, T, _ = raw_phys.shape
    if raw_prev is not None:
        prev = torch.as_tensor(raw_prev, device=raw_phys.device, dtype=raw_phys.dtype).reshape(B, 1, 6)
        prev = torch.cat([prev, raw_phys[:, :-1]], dim=1)
        cur = raw_phys
    else:
        if T < 2:
            zero = raw_phys.sum() * 0.0
            if return_parts:
                return zero, {
                    "speed_penalty": zero,
                    "altitude_penalty": zero,
                    "latlon_penalty": zero,
                    "heading_penalty": zero,
                }
            return zero
        prev = raw_phys[:, :-1]
        cur = raw_phys[:, 1:]

    dlat = cur[..., 0] - prev[..., 0]
    dlon = cur[..., 1] - prev[..., 1]
    dalt = cur[..., 2] - prev[..., 2]
    dv = cur[..., 3] - prev[..., 3]
    sin_delta = cur[..., 4] * prev[..., 5] - cur[..., 5] * prev[..., 4]
    cos_delta = cur[..., 5] * prev[..., 5] + cur[..., 4] * prev[..., 4]
    dheading = torch.atan2(sin_delta, cos_delta)

    loss_speed = torch.relu(dv.abs() / max(float(dv_max), 1e-12) - 1.0).pow(2).mean()
    loss_altitude = torch.relu(dalt.abs() / max(float(dalt_max), 1e-12) - 1.0).pow(2).mean()
    loss_lat = torch.relu(dlat.abs() / max(float(dlat_max), 1e-12) - 1.0).pow(2).mean()
    loss_lon = torch.relu(dlon.abs() / max(float(dlon_max), 1e-12) - 1.0).pow(2).mean()
    loss_heading = torch.relu(dheading.abs() / max(float(dheading_max_rad), 1e-12) - 1.0).pow(2).mean()
    loss = (
        float(w_speed) * loss_speed
        + float(w_altitude) * loss_altitude
        + float(w_latlon) * (loss_lat + loss_lon)
        + float(w_heading) * loss_heading
    )
    if return_parts:
        return loss, {
            "speed_penalty": loss_speed,
            "altitude_penalty": loss_altitude,
            "latlon_penalty": loss_lat + loss_lon,
            "heading_penalty": loss_heading,
        }
    return loss


def _lambda_phys_for_step(
    step: int,
    steps: int,
    *,
    lambda_phys_max: float,
    lambda_phys_gamma: float,
    use_lambda_schedule: bool,
) -> float:
    if not use_lambda_schedule:
        return float(lambda_phys_max)
    progress = float(step + 1) / max(int(steps), 1)
    return float(lambda_phys_max) * progress ** float(lambda_phys_gamma)


def _pgd_phys_penalty_raw(
    model: nn.Module,
    y: torch.Tensor,
    raw_n0: torch.Tensor,
    *,
    m_r: torch.Tensor,
    s_r: torch.Tensor,
    raw_prev: torch.Tensor | None,
    eps: float,
    alpha: float,
    steps: int,
    pack_input: Callable[[torch.Tensor], torch.Tensor],
    diff_ref: torch.Tensor | None = None,
    target_label: int = 0,
    lambda_phys_max: float = 10.0,
    lambda_phys_gamma: float = 2.0,
    use_lambda_schedule: bool = True,
    use_soft_projection: bool = False,
    projection_start_ratio: float = 0.5,
    final_projection: bool = True,
    dv_max: float = PHYS_DV_MAX,
    dalt_max: float = PHYS_DALT_MAX,
    dlat_max: float = PHYS_DLAT_MAX,
    dlon_max: float = PHYS_DLON_MAX,
    dheading_max_rad: float = PHYS_DH_DEG_MAX * _RAD_PER_DEG,
    w_speed: float = 1.0,
    w_altitude: float = 1.0,
    w_latlon: float = 1.0,
    w_heading: float = 1.0,
) -> torch.Tensor | tuple[torch.Tensor, dict[str, float]]:
    raw_n = raw_n0.clone()
    diag = {
        "mean_loss_target": 0.0,
        "mean_loss_phys": 0.0,
        "mean_lambda_phys": 0.0,
        "speed_penalty": 0.0,
        "altitude_penalty": 0.0,
        "latlon_penalty": 0.0,
        "heading_penalty": 0.0,
    }
    projection_start = int(max(0.0, min(1.0, float(projection_start_ratio))) * max(int(steps), 1))
    for step in range(int(steps)):
        raw_n.requires_grad_(True)
        x_in = pack_input(raw_n)
        raw_phys = denormalize(raw_n.float(), m_r, s_r)
        target = torch.full_like(y, int(target_label))
        loss_target = _CE(model(x_in), target)      #交叉熵损失，分类损失
        loss_phys, parts = physical_penalty(    
            raw_phys,
            raw_prev=raw_prev,
            dv_max=dv_max,
            dalt_max=dalt_max,
            dlat_max=dlat_max,
            dlon_max=dlon_max,
            dheading_max_rad=dheading_max_rad,
            w_speed=w_speed,
            w_altitude=w_altitude,
            w_latlon=w_latlon,
            w_heading=w_heading,
            return_parts=True,
        )      #物理越界损失
        lam = _lambda_phys_for_step(
            step,
            steps,
            lambda_phys_max=lambda_phys_max,
            lambda_phys_gamma=lambda_phys_gamma,
            use_lambda_schedule=use_lambda_schedule,
        )       #物理越界损失权重
        loss = loss_target + lam * loss_phys      #总损失
        (gr,) = torch.autograd.grad(loss, raw_n, retain_graph=False, create_graph=False)
        diag["mean_loss_target"] += float(loss_target.detach().cpu().item())      #分类损失
        diag["mean_loss_phys"] += float(loss_phys.detach().cpu().item())      #物理越界损失
        diag["mean_lambda_phys"] += float(lam)      #物理越界损失权重
        for k, v in parts.items():
            diag[k] += float(v.detach().cpu().item())
        with torch.no_grad():
            # targeted attack：最小化目标类 CE + 可微物理惩罚，因此沿负梯度方向更新。
            raw_n = _linf_project(raw_n.detach() - float(alpha) * gr.sign(), raw_n0, float(eps))
            raw_n = _sanitize_norm_raw(raw_n, raw_n0, m_r, s_r, float(eps))
            if step >= projection_start:
                raw_phys = denormalize(raw_n.float(), m_r, s_r)
                # soft_limit 只控制 tanh 幅值软限幅；方向约束默认关闭，不再按 diff_ref 对齐。
                raw_phys = physical_proj(
                    raw_phys,
                    raw_prev=raw_prev,
                    diff_ref=diff_ref,
                    soft_limit=bool(use_soft_projection),
                )
                raw_n = ((raw_phys - m_r) / s_r).to(dtype=raw_n.dtype)
                raw_n = _linf_project(raw_n, raw_n0, float(eps))
                raw_n = _sanitize_norm_raw(raw_n, raw_n0, m_r, s_r, float(eps))     #修正raw值：速度不能小于 0；航向 sin/cos 必须构成合法单位圆向量
    with torch.no_grad():
        if final_projection:
            raw_phys = denormalize(raw_n.float(), m_r, s_r)
            # 最终投影同样仅使用软限幅/物理阈值；方向约束默认关闭。
            raw_phys = physical_proj(
                raw_phys,
                raw_prev=raw_prev,
                diff_ref=diff_ref,
                soft_limit=bool(use_soft_projection),
            )
            raw_n = ((raw_phys - m_r) / s_r).to(dtype=raw_n.dtype)
            raw_n = _linf_project(raw_n, raw_n0, float(eps))
            raw_n = _sanitize_norm_raw(raw_n, raw_n0, m_r, s_r, float(eps))
    denom = max(int(steps), 1)
    diag = {k: v / denom for k, v in diag.items()}
    return raw_n.detach(), diag


def pgd_phys(
    model,
    X,
    y,
    m,
    s,
    eps=0.01,
    alpha=0.003,
    steps=5,
    project_physical=True,
    targeted=True,
    target_label=0,
):
    """Targeted PGD-phys：默认把恶意样本推向正常类，并可选 ``physical_proj``。"""
    with _attack_grad_context(model):       #在PGD发动期间，强行冻结网络中所有的Dropout层
        with _autocast_disabled_for(X):
            x0 = X.detach().to(dtype=torch.float32)
            if _use_raw_only_attack(x0, m, s):      #判断是否是12维
                ctx = _raw12_context(X, m, s)       #数据准备
                after_raw_step = None
                if project_physical:

                    def after_raw_step(raw_n: torch.Tensor) -> torch.Tensor:
                        return _project_phys_on_norm_raw(
                            raw_n,      #PGD攻击后又限制在epsilon范围内
                            m_r=ctx["m_r"],
                            s_r=ctx["s_r"],
                            raw_prev=ctx["raw_prev"],   #窗口起点在轨迹上的前一点 raw
                            diff_ref=ctx["diff_ref"],   #差分特征
                            soft_limit=False,
                        )

                x_adv = _pgd_raw12(
                    model,
                    y,
                    ctx,
                    eps,
                    alpha,
                    steps,
                    after_raw_step=after_raw_step,
                    targeted=targeted,
                    target_label=target_label,
                )
                return x_adv.to(dtype=X.dtype)

            m32, s32 = _as_f32_ms(m, s, x0.device)
            diff_ref = _diff_phys_ref_from_norm(x0, m32, s32) if int(x0.shape[-1]) == 12 else None
            after_step_fn = None
            if project_physical:

                def after_step_fn(x_adv: torch.Tensor) -> torch.Tensor:
                    return _project_phys_on_norm_full(
                        x_adv, m32=m32, s32=s32, diff_ref=diff_ref, soft_limit=False
                    )

            return _pgd_full_tensor(
                model,
                x0,
                y,
                eps,
                alpha,
                steps,
                after_step=after_step_fn,
                targeted=targeted,
                target_label=target_label,
            ).to(dtype=X.dtype)


def pgd_phys_hybrid(
    model,
    X,
    y,
    m,
    s,
    eps=0.01,
    alpha=0.003,
    steps=5,
    target_label=0,
    lambda_phys_max=10.0,
    lambda_phys_gamma=2.0,
    use_lambda_schedule=True,
    use_soft_projection=False,
    projection_start_ratio=0.5,
    final_projection=True,
    dv_max=PHYS_DV_MAX,
    dalt_max=PHYS_DALT_MAX,
    dlat_max=PHYS_DLAT_MAX,
    dlon_max=PHYS_DLON_MAX,
    dheading_max_rad=PHYS_DH_DEG_MAX * _RAD_PER_DEG,
    w_speed=1.0,
    w_altitude=1.0,
    w_latlon=1.0,
    w_heading=1.0,
    return_diagnostics=False,
):
    """Classification + physical penalty + scheduled hard projection."""
    if m is None or s is None:
        raise ValueError("pgd_phys_hybrid requires m and s for the raw-space penalty")

    with _attack_grad_context(model):
        with _autocast_disabled_for(X):
            x0 = X.detach().to(dtype=torch.float32)
            if _use_raw_only_attack(x0, m, s):
                ctx = _raw12_context(X, m, s)

                def pack_input(raw_n: torch.Tensor) -> torch.Tensor:
                    return _pack_norm12_from_raw_norm(raw_n, ctx["raw_prev"], ctx["m32"], ctx["s32"])

                raw_n, diagnostics = _pgd_phys_penalty_raw(
                    model,
                    y,
                    ctx["raw_n0"],
                    m_r=ctx["m_r"],
                    s_r=ctx["s_r"],
                    raw_prev=ctx["raw_prev"],
                    eps=eps,
                    alpha=alpha,
                    steps=steps,
                    pack_input=pack_input,
                    diff_ref=ctx["diff_ref"],
                    target_label=target_label,
                    lambda_phys_max=lambda_phys_max,
                    lambda_phys_gamma=lambda_phys_gamma,
                    use_lambda_schedule=use_lambda_schedule,
                    use_soft_projection=use_soft_projection,
                    projection_start_ratio=projection_start_ratio,
                    final_projection=final_projection,
                    dv_max=dv_max,
                    dalt_max=dalt_max,
                    dlat_max=dlat_max,
                    dlon_max=dlon_max,
                    dheading_max_rad=dheading_max_rad,
                    w_speed=w_speed,
                    w_altitude=w_altitude,
                    w_latlon=w_latlon,
                    w_heading=w_heading,
                )
                x_adv = _pack_norm12_from_raw_norm(raw_n, ctx["raw_prev"], ctx["m32"], ctx["s32"]).to(
                    dtype=X.dtype
                )
                return (x_adv, diagnostics) if return_diagnostics else x_adv

            m32, s32 = _as_f32_ms(m, s, x0.device)
            if int(x0.shape[-1]) == 6:
                raw_n0 = x0.clone()
                m_r, s_r = m32[..., :6], s32[..., :6]
                raw_prev = None
                diff_ref = None

                def pack_input(raw_n: torch.Tensor) -> torch.Tensor:
                    return raw_n

                raw_n, diagnostics = _pgd_phys_penalty_raw(
                    model,
                    y,
                    raw_n0,
                    m_r=m_r,
                    s_r=s_r,
                    raw_prev=raw_prev,
                    eps=eps,
                    alpha=alpha,
                    steps=steps,
                    pack_input=pack_input,
                    diff_ref=diff_ref,
                    target_label=target_label,
                    lambda_phys_max=lambda_phys_max,
                    lambda_phys_gamma=lambda_phys_gamma,
                    use_lambda_schedule=use_lambda_schedule,
                    use_soft_projection=use_soft_projection,
                    projection_start_ratio=projection_start_ratio,
                    final_projection=final_projection,
                    dv_max=dv_max,
                    dalt_max=dalt_max,
                    dlat_max=dlat_max,
                    dlon_max=dlon_max,
                    dheading_max_rad=dheading_max_rad,
                    w_speed=w_speed,
                    w_altitude=w_altitude,
                    w_latlon=w_latlon,
                    w_heading=w_heading,
                )
                x_adv = raw_n.to(dtype=X.dtype)
                return (x_adv, diagnostics) if return_diagnostics else x_adv

            x_adv = pgd_phys(
                model,
                X,
                y,
                m,
                s,
                eps=eps,
                alpha=alpha,
                steps=steps,
                project_physical=use_soft_projection,
                targeted=True,
                target_label=target_label,
            )
            diagnostics = {
                "mean_loss_target": 0.0,
                "mean_loss_phys": 0.0,
                "mean_lambda_phys": 0.0,
                "speed_penalty": 0.0,
                "altitude_penalty": 0.0,
                "latlon_penalty": 0.0,
                "heading_penalty": 0.0,
            }
            return (x_adv, diagnostics) if return_diagnostics else x_adv


def pgd_phys_penalty(
    model,
    X,
    y,
    m,
    s,
    eps=0.01,
    alpha=0.003,
    steps=5,
    target_label=0,
    lambda_phys_max=10.0,
    lambda_phys_gamma=2.0,
    use_lambda_schedule=True,
    dv_max=PHYS_DV_MAX,
    dalt_max=PHYS_DALT_MAX,
    dlat_max=PHYS_DLAT_MAX,
    dlon_max=PHYS_DLON_MAX,
    dheading_max_rad=PHYS_DH_DEG_MAX * _RAD_PER_DEG,
    w_speed=1.0,
    w_altitude=1.0,
    w_latlon=1.0,
    w_heading=1.0,
    return_diagnostics=False,
):
    """True penalty-only PGD; never invokes the kinematic hard projector."""
    return pgd_phys_hybrid(
        model,
        X,
        y,
        m,
        s,
        eps=eps,
        alpha=alpha,
        steps=steps,
        target_label=target_label,
        lambda_phys_max=lambda_phys_max,
        lambda_phys_gamma=lambda_phys_gamma,
        use_lambda_schedule=use_lambda_schedule,
        use_soft_projection=False,
        projection_start_ratio=1.0,
        final_projection=False,
        dv_max=dv_max,
        dalt_max=dalt_max,
        dlat_max=dlat_max,
        dlon_max=dlon_max,
        dheading_max_rad=dheading_max_rad,
        w_speed=w_speed,
        w_altitude=w_altitude,
        w_latlon=w_latlon,
        w_heading=w_heading,
        return_diagnostics=return_diagnostics,
    )

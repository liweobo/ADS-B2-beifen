from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable

import numpy as np


RawWindow = np.ndarray
RngLike = Any
ScenarioFn = Callable[[RawWindow, dict[str, float], RngLike], RawWindow]


@dataclass(frozen=True)
class AttackScenario:
    """可复现实验中的一种正式攻击场景。"""

    code: str
    name: str
    title: str
    description: str
    parameter_ranges: dict[str, tuple[float, float]]
    apply: ScenarioFn


@dataclass(frozen=True)
class AttackEvent:
    """一次被注入的攻击事件，使用窗口内时间步定位。"""

    window_index: int
    track_id: object | None
    window_start: int | None
    segment_start: int
    segment_length: int
    scenario_code: str
    scenario_name: str
    parameters: dict[str, float]


# 窗口内被投毒时间步数达到该阈值时，整窗标签为恶意 (y=1)
MALICIOUS_LABEL_MIN_POINTS = 5


def _rng(random_state: int | RngLike | None = None) -> RngLike:
    if random_state is None:
        return np.random
    if isinstance(random_state, (np.random.Generator, np.random.RandomState)):
        return random_state
    return np.random.default_rng(int(random_state))


def _uniform(rng: RngLike, low: float, high: float) -> float:
    return float(rng.uniform(low, high))


def _randint(rng: RngLike, low: int, high_exclusive: int) -> int:
    if hasattr(rng, "integers"):
        return int(rng.integers(low, high_exclusive))
    return int(rng.randint(low, high_exclusive))


def _random(rng: RngLike) -> float:
    if hasattr(rng, "random"):
        return float(rng.random())
    return float(rng.rand())


def _choice(rng: RngLike, values: tuple[str, ...]) -> str:
    return str(rng.choice(values))


def _heading_deg(row: np.ndarray) -> float:
    return float((np.degrees(np.arctan2(row[4], row[5])) + 360.0) % 360.0)


def _set_heading(row: np.ndarray, heading_deg: float) -> None:
    r = np.deg2rad(heading_deg % 360.0)
    row[4] = np.sin(r)
    row[5] = np.cos(r)


def _sample_parameters(scenario: AttackScenario, rng: RngLike) -> dict[str, float]:
    return {
        name: _uniform(rng, lo, hi)
        for name, (lo, hi) in scenario.parameter_ranges.items()
    }


def _drift_attack(seq: RawWindow, params: dict[str, float], rng: RngLike) -> RawWindow:
    """温水煮青蛙式 ADS-B 欺骗：速度和航向随时间逐步偏离。"""
    speed_rate = params["speed_rate"]
    heading_rate = params["heading_rate_deg"]

    for t in range(len(seq)):
        seq[t, 3] += speed_rate * t
        _set_heading(seq[t], _heading_deg(seq[t]) + heading_rate * t)
    return seq


def _shift_attack(seq: RawWindow, params: dict[str, float], rng: RngLike) -> RawWindow:
    """位置欺骗：整段轨迹被平移，并加入轻微线性偏移以模拟持续诱导。"""
    lat_offset = params["lat_offset_deg"]
    lon_offset = params["lon_offset_deg"]
    lat_ramp = params["lat_ramp_deg"]
    lon_ramp = params["lon_ramp_deg"]
    if len(seq) <= 1:
        progress = np.zeros(len(seq), dtype=np.float32)
    else:
        progress = np.linspace(0.0, 1.0, len(seq), dtype=np.float32)

    seq[:, 0] += lat_offset + lat_ramp * progress
    seq[:, 1] += lon_offset + lon_ramp * progress
    return seq


def _physical_attack(seq: RawWindow, params: dict[str, float], rng: RngLike) -> RawWindow:
    """物理可行的伪轨迹：限制速度与航向变化率，生成看似平滑但错误的状态。"""
    speed_delta_max = params["speed_delta_max"]
    heading_delta_max = params["heading_delta_max_deg"]
    climb_bias = params["altitude_bias"]

    for t in range(1, len(seq)):
        seq[t, 3] = seq[t - 1, 3] + _uniform(rng, -speed_delta_max, speed_delta_max)
        heading = _heading_deg(seq[t - 1]) + _uniform(rng, -heading_delta_max, heading_delta_max)
        _set_heading(seq[t], heading)
        seq[t, 2] += climb_bias * t
    return seq


ATTACK_SCENARIOS: dict[str, AttackScenario] = {
    "d": AttackScenario(
        code="d",
        name="gradual_drift",
        title="gradual drift spoofing",
        description="速度和航向逐步偏离的温水煮青蛙式 ADS-B 欺骗场景。",
        parameter_ranges={
            "speed_rate": (0.1, 0.3),
            "heading_rate_deg": (0.2, 0.8),
        },
        apply=_drift_attack,
    ),
    "s": AttackScenario(
        code="s",
        name="position_shift",
        title="position shift spoofing",
        description="经纬度整体平移并轻微持续漂移的位置欺骗场景。",
        parameter_ranges={
            "lat_offset_deg": (0.01, 0.05),
            "lon_offset_deg": (0.01, 0.05),
            "lat_ramp_deg": (-0.005, 0.005),
            "lon_ramp_deg": (-0.005, 0.005),
        },
        apply=_shift_attack,
    ),
    "p": AttackScenario(
        code="p",
        name="kinematic_spoofing",
        title="physically plausible spoofing",
        description="速度、航向和高度变化率受限的物理可行伪轨迹场景。",
        parameter_ranges={
            "speed_delta_max": (0.5, 2.0),
            "heading_delta_max_deg": (0.5, 2.0),
            "altitude_bias": (-2.0, 2.0),
        },
        apply=_physical_attack,
    ),
}

SCENARIO_ALIASES = {
    "drift": "d",
    "gradual_drift": "d",
    "warm": "d",
    "shift": "s",
    "position_shift": "s",
    "offset": "s",
    "physical": "p",
    "phys": "p",
    "kinematic": "p",
    "kinematic_spoofing": "p",
}


def resolve_scenario(code: str) -> AttackScenario:
    key = str(code).lower()
    key = SCENARIO_ALIASES.get(key, key)
    if key not in ATTACK_SCENARIOS:
        valid = ", ".join(sorted([*ATTACK_SCENARIOS.keys(), *SCENARIO_ALIASES.keys()]))
        raise ValueError(f"未知攻击场景 {code!r}；可选值: {valid}")
    return ATTACK_SCENARIOS[key]


def apply_attack_scenario(
    seq: RawWindow,
    scenario: str | AttackScenario,
    *,
    random_state: int | RngLike | None = None,
) -> RawWindow:
    """对单个 raw 片段应用攻击场景，返回被修改的片段。"""
    if seq.ndim != 2 or seq.shape[1] != 6:
        raise ValueError("攻击场景仅支持形状 (T, 6) 的 raw 片段。")
    rng = _rng(random_state)
    resolved = resolve_scenario(scenario) if isinstance(scenario, str) else scenario
    params = _sample_parameters(resolved, rng)
    return resolved.apply(seq, params, rng)


def anomaly_drift(seq):     #漂移异常/温水煮青蛙攻击：修改速度和航向
    return apply_attack_scenario(seq, "d")


def anomaly_shift(seq):     #位置偏移攻击：修改经度和纬度
    return apply_attack_scenario(seq, "s")


def anomaly_physical(seq):     #物理异常/物理攻击：修改速度、航向和高度
    return apply_attack_scenario(seq, "p")


def _propagate_poison_on_track(
    d: np.ndarray,
    mal_pts: np.ndarray,
    scenario_pts: np.ndarray,
    sub: np.ndarray,
    *,
    anchor_idx: int,
    start: int,
    L: int,
    track_windows: list[tuple[int, int]],
    T: int,
    scenario_bit: int,
) -> None:
    """将 ``[start, start+L)`` 的投毒子段按轨迹绝对时间步同步到同轨迹所有重叠滑窗。"""
    ws_anchor = next(ws for j, ws in track_windows if j == anchor_idx)
    abs_s = ws_anchor + int(start)
    abs_e = abs_s + int(L)
    for j, ws in track_windows:
        o_s = max(abs_s, ws)
        o_e = min(abs_e, ws + T)
        if o_s >= o_e:
            continue
        src_lo = o_s - abs_s
        src_hi = o_e - abs_s
        dst_lo = o_s - ws
        dst_hi = o_e - ws
        d[j, dst_lo:dst_hi] = sub[src_lo:src_hi]
        mal_pts[j, dst_lo:dst_hi] = True
        scenario_pts[j, dst_lo:dst_hi] |= np.uint8(scenario_bit)


def inject(
    data,
    ratio=0.2,
    anomaly_types=("d", "s", "p"),
    poison_len_min=5,
    poison_len_max=10,
    seq_len: int | None = None,
    track_ids=None,
    window_starts=None,
    random_state: int | RngLike | None = None,
    return_events: bool = False,
    return_metadata: bool = False,
):
    """
    在 **6 维 raw 窗口** ``(N, T, 6)`` 中生成正式攻击场景；差分应在投毒之后由
    ``add_differential_to_windows`` 再构建。

    ``anomaly_types`` 可继续使用旧代码 ``("d", "s", "p")``，也可使用场景名：
    ``gradual_drift``、``position_shift``、``kinematic_spoofing``。每次攻击会先采样
    一个场景，再采样该场景的参数，并写入连续子段 ``[start, start+L)``。

    返回标签 ``y``：0 为正常，1 为恶意。仅当窗口内被投毒的时间步数
    ``>= MALICIOUS_LABEL_MIN_POINTS``（默认 5）时标为 1。

    若提供 ``track_ids`` 与 ``window_starts``（与 ``build_raw_windows`` 一致），则同轨迹上
    凡滑窗与投毒段在绝对时间步上重叠的样本，会同步写入相同恶意数据；前后重叠窗口若
    覆盖恶意时间步数 ≥ 阈值，标签亦为 1。

    ``return_events=True`` 时额外返回 ``AttackEvent`` 列表，便于审计每次注入的场景。
    """
    if data.ndim != 3 or data.shape[2] != 6:
        raise ValueError("inject 仅支持形状 (N, T, 6) 的 raw 特征；请先投毒再调用 add_differential_to_windows。")
    d = data.copy()
    n = len(data)
    lo, hi = int(poison_len_min), int(poison_len_max)
    if lo > hi:
        raise ValueError("poison_len_min 不能大于 poison_len_max")
    T = int(data.shape[1])
    step = int(seq_len if seq_len is not None else T)
    if step < 1:
        raise ValueError("seq_len 须为 >= 1 的整数")

    rng = _rng(random_state)
    scenario_codes = tuple(resolve_scenario(c).code for c in anomaly_types)
    if len(scenario_codes) == 0:
        raise ValueError("anomaly_types 至少需要包含一个攻击场景")

    use_track_meta = track_ids is not None and window_starts is not None
    if use_track_meta:
        if len(track_ids) != n or len(window_starts) != n:
            raise ValueError("track_ids 与 window_starts 长度须与 data 窗口数 N 一致")
        track_ids = np.asarray(track_ids)
        window_starts = np.asarray(window_starts, dtype=np.int64)
        track_to_windows: dict = defaultdict(list)
        for j in range(n):
            track_to_windows[track_ids[j]].append((j, int(window_starts[j])))
    else:
        track_to_windows = None

    mal_pts = np.zeros((n, T), dtype=bool)
    scenario_pts = np.zeros((n, T), dtype=np.uint8)
    scenario_bits = {"d": 1, "s": 2, "p": 4}
    events: list[AttackEvent] = []

    i = 0
    while i < n:
        if _random(rng) < ratio:
            scenario = resolve_scenario(_choice(rng, scenario_codes))
            if T < lo:
                L = T
            else:
                L = _randint(rng, lo, hi + 1)
                L = min(L, T)
            start_max = T - L
            start = _randint(rng, 0, start_max + 1) if start_max >= 0 else 0
            sub = d[i, start : start + L].copy()
            params = _sample_parameters(scenario, rng)
            sub = scenario.apply(sub, params, rng)
            if use_track_meta:
                _propagate_poison_on_track(
                    d,
                    mal_pts,
                    scenario_pts,
                    sub,
                    anchor_idx=i,
                    start=start,
                    L=L,
                    track_windows=track_to_windows[track_ids[i]],
                    T=T,
                    scenario_bit=scenario_bits[scenario.code],
                )
                event_track_id = track_ids[i]
                event_window_start = int(window_starts[i])
            else:
                d[i, start : start + L] = sub
                mal_pts[i, start : start + L] = True
                scenario_pts[i, start : start + L] |= np.uint8(scenario_bits[scenario.code])
                event_track_id = None
                event_window_start = None

            events.append(
                AttackEvent(
                    window_index=i,
                    track_id=event_track_id,
                    window_start=event_window_start,
                    segment_start=start,
                    segment_length=L,
                    scenario_code=scenario.code,
                    scenario_name=scenario.name,
                    parameters=params,
                )
            )
            i += step
        else:
            i += 1

    y = (mal_pts.sum(axis=1) >= MALICIOUS_LABEL_MIN_POINTS).astype(np.int64)
    anomaly_bitmask = np.bitwise_or.reduce(scenario_pts, axis=1).astype(np.uint8)
    anomaly_bitmask[y == 0] = 0
    metadata = {
        "anomaly_bitmask": anomaly_bitmask,
        "poisoned_point_count": mal_pts.sum(axis=1).astype(np.int64),
        "scenario_bit_definition": {"gradual_drift": 1, "position_shift": 2, "kinematic_spoofing": 4},
    }
    if return_events and return_metadata:
        return d, y, events, metadata
    if return_events:
        return d, y, events
    if return_metadata:
        return d, y, metadata
    return d, y

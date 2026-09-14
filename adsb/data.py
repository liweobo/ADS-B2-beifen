from __future__ import annotations

import numpy as np
import pandas as pd

from adsb.train_constants import WINDOW_SIZE

TRACK_GAP_SECONDS = 60.0


def assign_track_segments(df: pd.DataFrame, gap_seconds: float = TRACK_GAP_SECONDS) -> pd.DataFrame:
    """
    同一 ``icao`` 内按时间排序；若相邻 ``ts`` 差值大于 ``gap_seconds``，则拆为独立轨迹段。

    新增列 ``track_id``，形如 ``{icao}_{段序号}``（段序号从 0 起）。
    """
    if gap_seconds <= 0:
        raise ValueError("gap_seconds 须为正数")

    out = df.sort_values(["icao", "ts"]).copy()
    dt = out.groupby("icao", sort=False)["ts"].diff()
    new_seg = dt.isna() | (dt > gap_seconds)
    seg_idx = new_seg.groupby(out["icao"], sort=False).cumsum()
    out["track_id"] = out["icao"].astype(str) + "_" + seg_idx.astype(str)
    return out


def subset_df_by_aircraft(
    df: pd.DataFrame,
    max_aircraft: int | None = None,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    按飞机（icao）子集化轨迹表。

    ``max_aircraft``:
        ``None`` — 不裁剪，使用全部飞机。
        正整数 — 随机抽取该数量的不同 ``icao``；若唯一机数不足则保留全部。
    """
    if max_aircraft is None:
        return df
    n = int(max_aircraft)
    if n < 1:
        raise ValueError("max_aircraft 须为 >= 1 的整数，或 None 表示使用全部飞机")

    ids = df["icao"].unique()
    if len(ids) <= n:
        return df

    rng = np.random.default_rng(random_state)
    picked = rng.choice(ids, size=n, replace=False)
    return df.loc[df["icao"].isin(picked)].copy()


def load_data(path):
    df = pd.read_csv(path)
    df = df[["ts", "icao", "lat", "lon", "spd", "hdg", "alt"]]
    df = df.dropna()    #删除包含NaN的行
    df = df[df["alt"] > 0]
    df = df.sort_values(["icao", "ts"])
    return df


def filter_data(df):
    return df[
        (df["spd"] > 0)
        & (df["spd"] < 300)
        & (df["alt"] > 0)
        & (df["alt"] < 15000)
        & (df["hdg"] >= 0)
        & (df["hdg"] <= 360)
    ]


def heading_to_sincos(deg):     #将飞机的航向角转换为sin值和cos值
    rad = np.deg2rad(deg.astype(np.float64) if isinstance(deg, np.ndarray) else deg)
    return np.sin(rad), np.cos(rad)


def build_raw_windows(df, seq_len: int = WINDOW_SIZE, gap_seconds: float = TRACK_GAP_SECONDS):
    """
    仅滑窗 raw（6 维），不拼接差分。返回每条窗口在轨迹上紧前一点的 raw ``raw_prev``，
    用于之后 ``add_differential_to_windows``：首行差分为 ``raw[0]-raw_prev``（与整条轨迹上
    ``d_raw[0]=0`` 的语义一致：窗口起点在轨迹 ``i==0`` 时取 ``raw_prev=raw[0]``，差分为 0）。

    同一 ``icao`` 内相邻 ``ts`` 间隔超过 ``gap_seconds``（默认 60 秒）的片段视为不同轨迹，
    滑窗不跨片段边界。

    ``seq_len`` 为每条窗口的时间步数（默认见 ``train_constants.WINDOW_SIZE``）。
    """
    if int(seq_len) < 1:
        raise ValueError("seq_len 须为 >= 1 的整数")
    seq_len = int(seq_len)
    df = assign_track_segments(df, gap_seconds=gap_seconds)
    seqs, prevs, ids, win_starts = [], [], [], []
    for track_id, g in df.groupby("track_id", sort=False):
        g = g.sort_values("ts")

        base = g[["lat", "lon", "alt", "spd"]].values.astype(np.float32)
        hs, hc = heading_to_sincos(g["hdg"].values)
        raw = np.concatenate([base, hs.reshape(-1, 1), hc.reshape(-1, 1)], axis=1).astype(
            np.float32
        )
        lf = len(raw)
        if lf < seq_len:
            continue

        for i in range(lf - seq_len + 1):
            seqs.append(raw[i : i + seq_len])
            prevs.append(raw[i - 1] if i > 0 else raw[0])
            ids.append(track_id)
            win_starts.append(i)

    return (
        np.array(seqs, dtype=np.float32),
        np.array(prevs, dtype=np.float32),
        np.array(ids),
        np.array(win_starts, dtype=np.int64),
    )


def add_differential_to_windows(X_raw: np.ndarray, raw_prev: np.ndarray) -> np.ndarray:
    """
    对已（或未）投毒的 raw 窗口 ``(N, T, 6)`` 按与原先 ``build_sequences`` 相同的定义拼上差分，
    得到 ``(N, T, 12)``。``raw_prev[k]`` 为第 ``k`` 条窗口在整条轨迹上窗口起点的前一点 raw。
    """
    if X_raw.ndim != 3 or X_raw.shape[2] != 6:
        raise ValueError("X_raw 须为 (N, T, 6)")
    if raw_prev.ndim != 2 or raw_prev.shape[0] != X_raw.shape[0] or raw_prev.shape[1] != 6:
        raise ValueError("raw_prev 须为 (N, 6)，且 N 与 X_raw 一致")
    n = 6
    n_samples, T, _ = X_raw.shape
    d = np.zeros((n_samples, T, n), dtype=np.float32)
    d[:, 0] = X_raw[:, 0] - raw_prev
    if T > 1:
        d[:, 1:] = X_raw[:, 1:] - X_raw[:, :-1]
    return np.concatenate([X_raw, d], axis=2).astype(np.float32)


def build_sequences(df, seq_len: int = WINDOW_SIZE, use_differential=True):
    """
    Each timestep is either:
    - ``use_differential=True`` (default): concat(raw, Δraw) → 12 dims（由 ``build_raw_windows``
      + ``add_differential_to_windows`` 组成，与原先逐点拼差分再滑窗等价）。
    - ``use_differential=False``: raw channels only → 6 dims — ablation without differential features.
    """
    X_raw, raw_prev, ids_arr, _win_starts = build_raw_windows(df, seq_len=seq_len)
    if use_differential:
        return add_differential_to_windows(X_raw, raw_prev), ids_arr
    return X_raw, ids_arr


def normalize(train, test):     #标准化：(x-均值)/标准差，使得数据符合标准正态分布
    m = train.mean((0, 1), keepdims=True)       #计算训练集和验证集的均值
    s = train.std((0, 1), keepdims=True) + 1e-6     #计算训练集和验证集的标准差
    return (train - m) / s, (test - m) / s, m, s    #对训练集和验证集进行标准化


def denormalize(X, m, s):
    return X * s + m

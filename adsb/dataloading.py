"""训练 / 验证 / 测试 DataLoader 与归一化统计量的构建。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader

from adsb.anomalies import ATTACK_SCENARIOS, MALICIOUS_LABEL_MIN_POINTS, inject
from adsb.data import (
    add_differential_to_windows,
    build_raw_windows,
    normalize,
)
from adsb.dataset import DS
from adsb.train_constants import (
    EVAL_BATCH_SIZE,
    INJECT_RATIO,
    PER_ATTACK_INJECT_RATIO,
    SEED,
    TRAIN_BATCH_SIZE,
    TRAIN_VAL_TEST_HOLDOUT_FRACTION,
    TRAIN_VAL_TEST_VAL_FRACTION,
    WINDOW_SIZE,
)


def _build_split_raw_windows(
    df: pd.DataFrame,
    icao_ids: np.ndarray,
    *,
    window_size: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    split_df = df.loc[df["icao"].isin(icao_ids)].copy()
    return build_raw_windows(split_df, seq_len=window_size)


def _require_non_empty_split(name: str, X_raw: np.ndarray) -> None:
    if len(X_raw) == 0:
        raise ValueError(
            f"{name} split has no windows after gap-based track segmentation; "
            "try increasing the number of aircraft or reducing window_size/gap_seconds."
        )


def _print_malicious_ratio(name: str, y: np.ndarray) -> None:
    total = int(len(y))
    malicious = int(np.asarray(y, dtype=np.int64).sum())
    ratio = malicious / total if total > 0 else 0.0
    print(f"{name}: malicious={malicious}/{total} ({ratio:.2%})")


def _id_values(ids: np.ndarray) -> list[str]:
    return sorted(str(value) for value in np.asarray(ids).tolist())


def _id_digest(values: list[str]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _id_manifest(ids: np.ndarray) -> dict[str, object]:
    values = _id_values(ids)
    return {"count": len(values), "sha256": _id_digest(values), "ids": values}


def _label_summary(y: np.ndarray) -> dict[str, object]:
    labels = np.asarray(y, dtype=np.int64)
    total = int(labels.size)
    malicious = int(labels.sum())
    normal = total - malicious
    return {
        "total_windows": total,
        "normal_windows": normal,
        "malicious_windows": malicious,
        "malicious_ratio": float(malicious / total) if total > 0 else 0.0,
    }


def _overlap_count(left: np.ndarray, right: np.ndarray) -> int:
    return len(set(_id_values(left)).intersection(_id_values(right)))


@dataclass(frozen=True)
class TrainValTestLoaders:
    train_loader: DataLoader
    val_loader: DataLoader
    train_loader_clean: DataLoader
    val_loader_clean: DataLoader
    test_loader: DataLoader
    audit_test_loader: DataLoader
    test_loader_no_inject: DataLoader
    per_attack_test_loaders: list[tuple[str, DataLoader]]
    norm_mean: np.ndarray       #均值
    norm_std: np.ndarray       #标准差
    seq_no_diff: np.ndarray
    mtr: np.ndarray
    mva: np.ndarray
    mte: np.ndarray
    #: 测试划分上 **未注入** 的 raw 窗口 ``(N, T, 6)``，与 ``build_raw_windows`` 列顺序一致（lat, lon, alt, spd, sin_hdg, cos_hdg）。
    #: 与 ``X_raw`` 同行的轨迹段 id 与滑窗起点（供 ``inject`` 重叠传播）。
    track_ids: np.ndarray
    window_starts: np.ndarray
    test_raw_windows_clean: np.ndarray
    window_size: int
    split_summary: dict[str, object]
    audit_metadata: dict[str, dict[str, np.ndarray]]


def _sample_metadata(
    track_ids: np.ndarray,
    window_starts: np.ndarray,
    labels: np.ndarray,
    anomaly_bitmask: np.ndarray,
    *,
    seed: int,
    split: str,
) -> dict[str, np.ndarray]:
    segments = np.asarray([str(value) for value in track_ids])
    aircraft = np.asarray([value.rsplit("_", 1)[0] for value in segments])
    starts = np.asarray(window_starts, dtype=np.int64)
    sample_ids = []
    for segment, start in zip(segments.tolist(), starts.tolist()):
        payload = f"adsb-sample-v1|{seed}|{split}|{segment}|{start}".encode("utf-8")
        sample_ids.append(hashlib.sha256(payload).hexdigest())
    return {
        "sample_id": np.asarray(sample_ids),
        "aircraft_id": aircraft,
        "segment_id": segments,
        "window_start": starts,
        "anomaly_bitmask": np.asarray(anomaly_bitmask, dtype=np.uint8),
        "seed": np.full(len(segments), int(seed), dtype=np.int64),
        "split": np.full(len(segments), str(split)),
        "original_label": np.asarray(labels, dtype=np.int64),
    }


def prepare_train_val_test_loaders(     #划分训练、验证和测试数据集并给每个数据集投毒
    df: pd.DataFrame,
    *,
    pin_memory: bool,
    random_state: int = SEED,
    inject_ratio: float = INJECT_RATIO,
    anomaly_types: tuple[str, ...] = ("d", "s", "p"),
    per_attack_ratio: float = PER_ATTACK_INJECT_RATIO,
    window_size: int = WINDOW_SIZE,
) -> TrainValTestLoaders:
    """
    从已 ``filter_data`` / ``subset_df_by_aircraft`` 的轨迹表构建 12 维差分特征与各类测试集 DataLoader。

    所有返回的 ``y``：0=正常，1=恶意（窗口内投毒时间步数≥5，含滑窗重叠传播；``test_loader_no_inject`` 中全为 0）。
    """
    aircraft_ids = np.unique(df["icao"])
    trv_icao, te_icao = train_test_split(
        aircraft_ids, test_size=TRAIN_VAL_TEST_HOLDOUT_FRACTION, random_state=random_state
    )     #先按 icao 划分训练、验证和测试数据集
    tr_icao, va_icao = train_test_split(
        trv_icao, test_size=TRAIN_VAL_TEST_VAL_FRACTION, random_state=random_state
    )

    Xtr_r, prev_tr, ids_tr, starts_tr = _build_split_raw_windows(
        df, tr_icao, window_size=window_size
    )
    Xva_r, prev_va, ids_va, starts_va = _build_split_raw_windows(
        df, va_icao, window_size=window_size
    )
    Xte_r, prev_te, ids_te, starts_te = _build_split_raw_windows(
        df, te_icao, window_size=window_size
    )
    for split_name, split_raw in (("train", Xtr_r), ("validation", Xva_r), ("test", Xte_r)):
        _require_non_empty_split(split_name, split_raw)
        if split_raw.ndim != 3 or split_raw.shape[2] != 6:
            raise RuntimeError(f"{split_name} build_raw_windows should return (N, T, 6) raw windows.")

    X_raw = np.concatenate([Xtr_r, Xva_r, Xte_r], axis=0)
    raw_prev = np.concatenate([prev_tr, prev_va, prev_te], axis=0)
    ids = np.concatenate([ids_tr, ids_va, ids_te], axis=0)
    win_starts = np.concatenate([starts_tr, starts_va, starts_te], axis=0)
    seq_no_diff = X_raw.copy()
    mtr = np.zeros(len(X_raw), dtype=bool)
    mva = np.zeros(len(X_raw), dtype=bool)
    mte = np.zeros(len(X_raw), dtype=bool)
    tr_end = len(Xtr_r)
    va_end = tr_end + len(Xva_r)
    mtr[:tr_end] = True
    mva[tr_end:va_end] = True
    mte[va_end:] = True
    Xtr_base_raw = Xtr_r.copy()
    Xva_base_raw = Xva_r.copy()
    Xte_base_raw = Xte_r.copy()

    Xtr_r, ytr, meta_tr_inject = inject(
        Xtr_r,
        ratio=inject_ratio,
        anomaly_types=anomaly_types,
        track_ids=ids_tr,
        window_starts=starts_tr,
        random_state=random_state + 101,
        return_metadata=True,
    )     #投毒
    Xva_r, yva, meta_va_inject = inject(
        Xva_r,
        ratio=inject_ratio,
        anomaly_types=anomaly_types,
        track_ids=ids_va,
        window_starts=starts_va,
        random_state=random_state + 202,
        return_metadata=True,
    )
    Xte_r, yte, meta_te_inject = inject(
        Xte_r,
        ratio=inject_ratio,
        anomaly_types=anomaly_types,
        track_ids=ids_te,
        window_starts=starts_te,
        random_state=random_state + 303,
        return_metadata=True,
    )
    print("\n=== Dataset malicious ratios ===")
    _print_malicious_ratio("train", ytr)
    _print_malicious_ratio("validation", yva)
    _print_malicious_ratio("test mixed attack", yte)

    Xtr = add_differential_to_windows(Xtr_r, prev_tr)       #拼接差分
    Xva = add_differential_to_windows(Xva_r, prev_va)
    Xte = add_differential_to_windows(Xte_r, prev_te)
    Xtr, Xva, m, s = normalize(Xtr, Xva)
    Xte = (Xte - m) / s

    train_metadata = _sample_metadata(
        ids_tr, starts_tr, ytr, meta_tr_inject["anomaly_bitmask"], seed=random_state + 101, split="train"
    )
    validation_metadata = _sample_metadata(
        ids_va, starts_va, yva, meta_va_inject["anomaly_bitmask"], seed=random_state + 202, split="validation"
    )
    train_loader = DataLoader(
        DS(Xtr, ytr, metadata=train_metadata),
        batch_size=TRAIN_BATCH_SIZE, shuffle=True, pin_memory=pin_memory, num_workers=0
    )
    val_loader = DataLoader(
        DS(Xva, yva, metadata=validation_metadata),
        batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0
    )
    # Published unsupervised ADS-B baselines are trained only on benign
    # trajectories.  Expose clean views of the *same* aircraft split and
    # normalization used by the supervised CAT-AD experiment so literature
    # comparisons do not silently change the data protocol.
    Xtr_clean = add_differential_to_windows(Xtr_base_raw, prev_tr)
    Xva_clean = add_differential_to_windows(Xva_base_raw, prev_va)
    Xtr_clean = (Xtr_clean - m) / s
    Xva_clean = (Xva_clean - m) / s
    train_loader_clean = DataLoader(
        DS(Xtr_clean, np.zeros(len(Xtr_clean), dtype=np.int64)),
        batch_size=TRAIN_BATCH_SIZE,
        shuffle=True,
        pin_memory=pin_memory,
        num_workers=0,
    )
    val_loader_clean = DataLoader(
        DS(Xva_clean, np.zeros(len(Xva_clean), dtype=np.int64)),
        batch_size=EVAL_BATCH_SIZE,
        shuffle=False,
        pin_memory=pin_memory,
        num_workers=0,
    )
    test_loader = DataLoader(
        DS(Xte, yte), batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0
    )
    test_metadata = _sample_metadata(
        ids_te,
        starts_te,
        yte,
        meta_te_inject["anomaly_bitmask"],
        seed=random_state + 303,
        split="test",
    )
    audit_test_loader = DataLoader(
        DS(Xte, yte, metadata=test_metadata, return_metadata=True),
        batch_size=EVAL_BATCH_SIZE,
        shuffle=False,
        pin_memory=pin_memory,
        num_workers=0,
    )

    Xte_no_inj = add_differential_to_windows(Xte_base_raw, prev_te)       #无投毒数据的raw窗口拼接差分
    Xte_no_inj = (Xte_no_inj - m) / s
    yte_no_inj = np.zeros(len(Xte_no_inj), dtype=np.int64)
    _print_malicious_ratio("test no injection", yte_no_inj)
    test_loader_no_inject = DataLoader(
        DS(Xte_no_inj, yte_no_inj), batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0
    )

    per_attack_test_loaders: list[tuple[str, DataLoader]] = []     #每种攻击类型的测试数据集
    per_attack_summaries: dict[str, dict[str, object]] = {}
    for code_index, code in enumerate(("d", "s", "p")):
        scenario = ATTACK_SCENARIOS[code]
        title = f"{scenario.title} only"
        Xi_raw, yi = inject(
            Xte_base_raw.copy(),
            ratio=per_attack_ratio,
            anomaly_types=(code,),
            track_ids=ids_te,
            window_starts=starts_te,
            random_state=random_state + 404 + code_index,
        )
        Xi = add_differential_to_windows(Xi_raw, prev_te)
        Xi = (Xi - m) / s
        _print_malicious_ratio(f"test {title}", yi)
        per_attack_summaries[title] = _label_summary(yi)
        per_attack_test_loaders.append(
            (title, DataLoader(DS(Xi, yi), batch_size=EVAL_BATCH_SIZE, shuffle=False, pin_memory=pin_memory, num_workers=0))
        )

    split_summary = {
        "random_state": int(random_state),
        "window_size": int(window_size),
        "malicious_label_min_points": int(MALICIOUS_LABEL_MIN_POINTS),
        "inject_ratio": float(inject_ratio),
        "per_attack_ratio": float(per_attack_ratio),
        "anomaly_types": [str(code) for code in anomaly_types],
        "aircraft": {
            "train": _id_manifest(tr_icao),
            "validation": _id_manifest(va_icao),
            "test": _id_manifest(te_icao),
            "overlap_counts": {
                "train_validation": _overlap_count(tr_icao, va_icao),
                "train_test": _overlap_count(tr_icao, te_icao),
                "validation_test": _overlap_count(va_icao, te_icao),
            },
        },
        "windows": {
            "train": _label_summary(ytr),
            "validation": _label_summary(yva),
            "test_mixed_attack": _label_summary(yte),
            "test_no_injection": _label_summary(yte_no_inj),
            "per_attack": per_attack_summaries,
        },
    }

    return TrainValTestLoaders(
        train_loader=train_loader,
        val_loader=val_loader,
        train_loader_clean=train_loader_clean,
        val_loader_clean=val_loader_clean,
        test_loader=test_loader,
        audit_test_loader=audit_test_loader,
        test_loader_no_inject=test_loader_no_inject,
        per_attack_test_loaders=per_attack_test_loaders,
        norm_mean=m,
        norm_std=s,
        seq_no_diff=seq_no_diff,
        mtr=mtr,
        mva=mva,
        mte=mte,
        track_ids=ids,
        window_starts=win_starts,
        test_raw_windows_clean=Xte_base_raw,
        window_size=window_size,
        split_summary=split_summary,
        audit_metadata={
            "train": train_metadata,
            "validation": validation_metadata,
            "test": test_metadata,
        },
    )

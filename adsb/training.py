from __future__ import annotations

import copy
from contextlib import nullcontext

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import f1_score, precision_score, recall_score

from adsb.attacks import (
    apply_pgd_malicious_only,
    physical_feasibility_sample_flags,
    pgd,
    pgd_phys,
    pgd_phys_penalty,
    pgd_phys_hybrid,
)
from adsb.data import denormalize
from adsb.train_constants import (
    ADV_CE_CLASS_WEIGHTS,
    ADV_PROJECT_PHYSICAL,
    ADV_TRAIN_EPS,
    ADV_TRAIN_LAMBDA,
    ADV_WARMUP_EPOCHS,
    BASELINE_CE_CLASS_WEIGHTS,
    EARLY_STOP_PATIENCE,
    EPOCHS,
    EVAL_ATTACK_EPS,
    GRAD_CLIP_MAX_NORM,
    LR,
    PGD_ALPHA,
    PGD_STEPS,
    PHYS_FEAT_LAMBDA,
    PHYS_OUT_LAMBDA,
    PHYS_PENALTY_FINAL_PROJECTION,
    PHYS_PENALTY_LAMBDA_GAMMA,
    PHYS_PENALTY_LAMBDA_MAX,
    PHYS_PENALTY_PROJECTION_START_RATIO,
    PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
    PHYS_PENALTY_USE_SOFT_PROJECTION,
    PHYS_PENALTY_W_ALTITUDE,
    PHYS_PENALTY_W_HEADING,
    PHYS_PENALTY_W_LATLON,
    PHYS_PENALTY_W_SPEED,
    PHYS_TEMPERATURE,
    THRESHOLD_GRID_POINTS,
    USE_PENALTY_PHYS_PGD_TRAIN,
    USE_AMP,
)


def _maybe_apply_eval_attack(
    model,
    X: torch.Tensor,
    y: torch.Tensor,
    *,
    mode,
    m,
    s,
    adv_eps: float,
    pgd_alpha: float,
    pgd_steps: int,
    phys_penalty_lambda_max: float,
    phys_penalty_lambda_gamma: float,
    phys_penalty_use_lambda_schedule: bool,
    phys_penalty_w_speed: float,
    phys_penalty_w_altitude: float,
    phys_penalty_w_latlon: float,
    phys_penalty_w_heading: float,
    phys_penalty_use_soft_projection: bool,
    phys_penalty_projection_start_ratio: float,
    phys_penalty_final_projection: bool,
) -> torch.Tensor:      #返回攻击后的样本
    if mode == "pgd":
        if m is not None and s is not None:
            return apply_pgd_malicious_only(
                model,
                X,
                y,
                pgd,
                eps=adv_eps,
                m=m,
                s=s,
                alpha=pgd_alpha,
                steps=pgd_steps,
            )
        return apply_pgd_malicious_only(
            model, X, y, pgd, eps=adv_eps, alpha=pgd_alpha, steps=pgd_steps
        )
    if mode == "phys":
        return apply_pgd_malicious_only(
            model,
            X,
            y,
            pgd_phys,
            m,
            s,
            eps=adv_eps,
            alpha=pgd_alpha,
            steps=pgd_steps,
            project_physical=True,
        )
    if mode == "phys_penalty_pgd":
        return apply_pgd_malicious_only(
            model,
            X,
            y,
            pgd_phys_penalty,
            m,
            s,
            eps=adv_eps,
            alpha=pgd_alpha,
            steps=pgd_steps,
            lambda_phys_max=phys_penalty_lambda_max,
            lambda_phys_gamma=phys_penalty_lambda_gamma,
            use_lambda_schedule=phys_penalty_use_lambda_schedule,
            w_speed=phys_penalty_w_speed,
            w_altitude=phys_penalty_w_altitude,
            w_latlon=phys_penalty_w_latlon,
            w_heading=phys_penalty_w_heading,
        )
    if mode in ("phys_hybrid_pgd", "phys_penalty", "phys-penalty", "phys_pgd_penalty"):
        return apply_pgd_malicious_only(
            model,
            X,
            y,
            pgd_phys_hybrid,
            m,
            s,
            eps=adv_eps,
            alpha=pgd_alpha,
            steps=pgd_steps,
            lambda_phys_max=phys_penalty_lambda_max,
            lambda_phys_gamma=phys_penalty_lambda_gamma,
            use_lambda_schedule=phys_penalty_use_lambda_schedule,
            w_speed=phys_penalty_w_speed,
            w_altitude=phys_penalty_w_altitude,
            w_latlon=phys_penalty_w_latlon,
            w_heading=phys_penalty_w_heading,
            use_soft_projection=phys_penalty_use_soft_projection,
            projection_start_ratio=phys_penalty_projection_start_ratio,
            final_projection=phys_penalty_final_projection,
        )
    return X


def _collect_malicious_probs(
    model,
    loader,
    device,
    *,
    mode=None,
    m=None,
    s=None,
    adv_eps=EVAL_ATTACK_EPS,
    pgd_alpha=PGD_ALPHA,
    pgd_steps=PGD_STEPS,
    phys_penalty_lambda_max=PHYS_PENALTY_LAMBDA_MAX,
    phys_penalty_lambda_gamma=PHYS_PENALTY_LAMBDA_GAMMA,
    phys_penalty_use_lambda_schedule=PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
    phys_penalty_w_speed=PHYS_PENALTY_W_SPEED,
    phys_penalty_w_altitude=PHYS_PENALTY_W_ALTITUDE,
    phys_penalty_w_latlon=PHYS_PENALTY_W_LATLON,
    phys_penalty_w_heading=PHYS_PENALTY_W_HEADING,
    phys_penalty_use_soft_projection=PHYS_PENALTY_USE_SOFT_PROJECTION,
    phys_penalty_projection_start_ratio=PHYS_PENALTY_PROJECTION_START_RATIO,
    phys_penalty_final_projection=PHYS_PENALTY_FINAL_PROJECTION,
    physical_m=None,
    physical_s=None,
    return_sample_details: bool = False,
):
    """验证/测试集上前向一次，返回 ``(y_true, prob_malicious)``（均在 CPU、numpy）。"""
    model.eval()
    y_parts: list[torch.Tensor] = []        #保存每个batch的真实标签
    prob_parts: list[torch.Tensor] = []     #
    sample_flag_parts: dict[str, list[torch.Tensor]] = {}
    pre_attack_sample_flag_parts: dict[str, list[torch.Tensor]] = {}
    malicious_prob_parts: list[torch.Tensor] = []
    for X, y in loader:
        X = X.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        X_pre_attack = X.detach()
        X = _maybe_apply_eval_attack(      #应用评估攻击函数，返回攻击后的样本
            model,
            X,
            y,
            mode=mode,
            m=m,
            s=s,
            adv_eps=adv_eps,
            pgd_alpha=pgd_alpha,
            pgd_steps=pgd_steps,
            phys_penalty_lambda_max=phys_penalty_lambda_max,
            phys_penalty_lambda_gamma=phys_penalty_lambda_gamma,
            phys_penalty_use_lambda_schedule=phys_penalty_use_lambda_schedule,
            phys_penalty_w_speed=phys_penalty_w_speed,
            phys_penalty_w_altitude=phys_penalty_w_altitude,
            phys_penalty_w_latlon=phys_penalty_w_latlon,
            phys_penalty_w_heading=phys_penalty_w_heading,
            phys_penalty_use_soft_projection=phys_penalty_use_soft_projection,
            phys_penalty_projection_start_ratio=phys_penalty_projection_start_ratio,
            phys_penalty_final_projection=phys_penalty_final_projection,
        )
        with torch.no_grad():
            logits = model(X)       #模型预测值，形状为[batch_size, 2]，第0列为正常类分数，第1列为恶意类分数
            prob_malicious = torch.softmax(logits, dim=1)[:, 1]     #先将模型预测的分数转化为概率，然后保留恶意类的概率
        malicious_mask = y == 1     #找出当前 batch 中的恶意样本，并创建一个布尔掩码
        if physical_m is not None and physical_s is not None and malicious_mask.any():      #只有进行pgd攻击，physical_m和physical_s才不为None
            m32 = torch.as_tensor(physical_m, dtype=torch.float32, device=X.device)
            s32 = torch.as_tensor(physical_s, dtype=torch.float32, device=X.device)
            X_pre_real = denormalize(X_pre_attack.to(dtype=torch.float32), m32, s32)
            X_real = denormalize(X.detach().to(dtype=torch.float32), m32, s32)
            X_pre_malicious = X_pre_real[malicious_mask]
            X_malicious = X_real[malicious_mask]
            raw_pre = X_pre_malicious[..., :6]
            raw_real = X_malicious[..., :6]
            raw_pre_prev = (
                X_pre_malicious[:, 0, :6] - X_pre_malicious[:, 0, 6:12]
                if int(X_pre_malicious.shape[-1]) == 12
                else None
            )
            raw_prev = (        #获取第0时间步的前一个时间步的状态
                X_malicious[:, 0, :6] - X_malicious[:, 0, 6:12]
                if int(X_malicious.shape[-1]) == 12
                else None
            )
            pre_batch_flags = physical_feasibility_sample_flags(raw_pre, raw_prev=raw_pre_prev)
            batch_flags = physical_feasibility_sample_flags(raw_real, raw_prev=raw_prev)
            for k, v in pre_batch_flags.items():
                pre_attack_sample_flag_parts.setdefault(k, []).append(v.detach().cpu())
            for k, v in batch_flags.items():
                sample_flag_parts.setdefault(k, []).append(v.detach().cpu())
            malicious_prob_parts.append(prob_malicious[malicious_mask].detach().cpu())
        y_parts.append(y.detach().cpu())        #保存真实标签
        prob_parts.append(prob_malicious.detach().cpu())        #保存模型的预测意类的概率
    if not y_parts:     #如果loader是空的，则返回空数组
        base = (np.array([], dtype=np.int64), np.array([], dtype=np.float64), {})
        return (*base, {}) if return_sample_details else base
    physical_metrics: dict[str, float] = {}
    base = (torch.cat(y_parts, dim=0).numpy(), torch.cat(prob_parts, dim=0).numpy(), physical_metrics)
    if not return_sample_details:
        return base
    sample_details = {
        k: torch.cat(parts, dim=0).numpy() for k, parts in sample_flag_parts.items() if parts
    }
    sample_details.update(
        {
            f"pre_attack_{k}": torch.cat(parts, dim=0).numpy()
            for k, parts in pre_attack_sample_flag_parts.items()
            if parts
        }
    )
    sample_details["prob_malicious"] = (
        torch.cat(malicious_prob_parts, dim=0).numpy()
        if malicious_prob_parts
        else np.array([], dtype=np.float64)
    )
    return (*base, sample_details)


def _metrics_at_threshold(          #计算accuracy,precision，recall，f1，asr,far结果指标
    y_true: np.ndarray, prob_malicious: np.ndarray, threshold: float
) -> dict[str, float]:
    """由缓存的恶意类概率与阈值计算分类指标。"""
    if len(y_true) == 0:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "asr": 0.0,
            "far": 0.0,
        }
    y_pred = (prob_malicious >= threshold).astype(np.int64)
    acc = float((y_pred == y_true).mean())
    normal = y_true == 0
    malicious = y_true == 1
    asr = float((y_pred[malicious] == 0).mean()) if malicious.any() else 0.0
    far = float((y_pred[normal] == 1).mean()) if normal.any() else 0.0
    prec = float(
        precision_score(y_true, y_pred, average="binary", pos_label=1, labels=[0, 1], zero_division=0)
    )
    rec = float(
        recall_score(y_true, y_pred, average="binary", pos_label=1, labels=[0, 1], zero_division=0)
    )
    f1 = float(f1_score(y_true, y_pred, average="binary", pos_label=1, labels=[0, 1], zero_division=0))
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "asr": asr,
        "far": far,
    }


def evaluate_with_threshold(
    model,
    loader,
    device,
    threshold=0.5,
    mode=None,
    m=None,
    s=None,
    adv_eps=EVAL_ATTACK_EPS,
    pgd_alpha=PGD_ALPHA,
    pgd_steps=PGD_STEPS,
    phys_penalty_lambda_max=PHYS_PENALTY_LAMBDA_MAX,
    phys_penalty_lambda_gamma=PHYS_PENALTY_LAMBDA_GAMMA,
    phys_penalty_use_lambda_schedule=PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
    phys_penalty_w_speed=PHYS_PENALTY_W_SPEED,
    phys_penalty_w_altitude=PHYS_PENALTY_W_ALTITUDE,
    phys_penalty_w_latlon=PHYS_PENALTY_W_LATLON,
    phys_penalty_w_heading=PHYS_PENALTY_W_HEADING,
    phys_penalty_use_soft_projection=PHYS_PENALTY_USE_SOFT_PROJECTION,
    phys_penalty_projection_start_ratio=PHYS_PENALTY_PROJECTION_START_RATIO,
    phys_penalty_final_projection=PHYS_PENALTY_FINAL_PROJECTION,
    physical_m=None,
    physical_s=None,
):
    """``loader`` 中 ``y`` 须为 0=正常、1=恶意；预测 ``p`` 同编码。F1 等以恶意类 ``pos_label=1`` 汇报。"""
    y_true, prob_malicious, physical_metrics, sample_details = _collect_malicious_probs(        #计算真实标签，模型预测为恶意样本概率，恶意样本中各物理特征超过界限占所有恶意样本的比例
        model,
        loader,
        device,
        mode=mode,
        m=m,
        s=s,
        adv_eps=adv_eps,
        pgd_alpha=pgd_alpha,
        pgd_steps=pgd_steps,
        phys_penalty_lambda_max=phys_penalty_lambda_max,
        phys_penalty_lambda_gamma=phys_penalty_lambda_gamma,
        phys_penalty_use_lambda_schedule=phys_penalty_use_lambda_schedule,
        phys_penalty_w_speed=phys_penalty_w_speed,
        phys_penalty_w_altitude=phys_penalty_w_altitude,
        phys_penalty_w_latlon=phys_penalty_w_latlon,
        phys_penalty_w_heading=phys_penalty_w_heading,
        phys_penalty_use_soft_projection=phys_penalty_use_soft_projection,
        phys_penalty_projection_start_ratio=phys_penalty_projection_start_ratio,
        phys_penalty_final_projection=phys_penalty_final_projection,
        physical_m=physical_m,
        physical_s=physical_s,
        return_sample_details=True,
    )
    metrics = _metrics_at_threshold(y_true, prob_malicious, float(threshold))       #计算accuracy,precision，recall，f1，asr,far结果指标
    metrics.update(physical_metrics)        #合并metrics和physical_metrics
    any_flags = sample_details.get("physical_any_violation")
    if any_flags is not None and len(any_flags) > 0:
        # Table IV 使用 attacked anomalous samples 的逐轨迹统计；PV-ASR 与 ASR 使用同一验证集阈值。
        malicious_probs = sample_details["prob_malicious"]
        attack_success = malicious_probs < float(threshold)
        pre_any_flags = sample_details.get("pre_attack_physical_any_violation")
        if pre_any_flags is None or len(pre_any_flags) != len(any_flags):
            raise RuntimeError("Paired pre/post physical flags are required for physical evaluation.")
        start_valid = ~pre_any_flags
        start_valid_count = int(np.sum(start_valid))
        malicious_count = int(len(any_flags))
        if start_valid_count > 0:
            conditional_asr = float(np.mean(attack_success[start_valid]))
            conditional_pv_asr = float(np.mean((attack_success & ~any_flags)[start_valid]))
            introduced_pvr = float(np.mean(any_flags[start_valid]))
        else:
            conditional_asr = float("nan")
            conditional_pv_asr = float("nan")
            introduced_pvr = float("nan")
        metrics.update(
            {
                "pvr": float(np.mean(any_flags)),
                "pre_attack_pvr": float(np.mean(pre_any_flags)),
                "start_valid_rate": float(np.mean(start_valid)),
                "start_valid_count": start_valid_count,
                "physical_malicious_count": malicious_count,
                "conditional_asr_start_valid": conditional_asr,
                "conditional_pv_asr_start_valid": conditional_pv_asr,
                "introduced_pvr_start_valid": introduced_pvr,
                "position_vr": float(np.mean(sample_details["physical_position_violation"])),
                "alt_vr": float(np.mean(sample_details["physical_altitude_violation"])),
                "vel_vr": float(np.mean(sample_details["physical_speed_violation"])),
                "head_vr": float(np.mean(sample_details["physical_heading_violation"])),
                "pv_asr": float(np.mean(attack_success & ~any_flags)),
                "physical_scope": "paired pre/post attacked anomalous samples",
                "pv_asr_method": "exact_per_sample",
                "conditional_physical_method": "conditioned_on_pre_attack_validity",
            }
        )
    return metrics


def pick_best_threshold(model, loader, device):
    """在验证集上只前向一次，再在 CPU 上扫描阈值网格。"""
    y_true, prob_malicious, _physical_metrics = _collect_malicious_probs(model, loader, device)
    candidates = np.linspace(0, 1, THRESHOLD_GRID_POINTS)  # 原来是 (0.2, 0.8, 25)
    best_t, best_f1 = 0.5, -1.0
    for t in candidates:
        f1 = _metrics_at_threshold(y_true, prob_malicious, float(t))["f1"]
        if f1 > best_f1:
            best_f1 = f1
            best_t = float(t)
    return best_t, best_f1


def _physical_consistency_losses(
    logits_clean: torch.Tensor,
    feat_clean: torch.Tensor,
    logits_adv: torch.Tensor,
    feat_adv: torch.Tensor,
    y: torch.Tensor,
    temperature: float,
) -> tuple[torch.Tensor, torch.Tensor]:
    malicious = y == 1
    zero = logits_clean.detach().sum() * 0.0
    if not malicious.any():
        return zero, zero

    temp = max(float(temperature), 1e-6)
    p_clean = F.softmax(logits_clean[malicious].detach() / temp, dim=1)
    log_p_adv = F.log_softmax(logits_adv[malicious] / temp, dim=1)
    loss_out_cons = F.kl_div(log_p_adv, p_clean, reduction="batchmean") * temp * temp

    feat_clean_n = F.normalize(feat_clean[malicious].detach(), p=2, dim=1)
    feat_adv_n = F.normalize(feat_adv[malicious], p=2, dim=1)
    loss_feat_cons = F.mse_loss(feat_adv_n, feat_clean_n)
    return loss_out_cons, loss_feat_cons


def _run_epoch_train(model, loader, device, lossf, opt, scaler, autocast_ctx, scheduler=None):      #单轮循环函数
    model.train()
    tot = 0.0
    n_batches = 0
    for X, y in loader:
        X = X.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        opt.zero_grad(set_to_none=True)
        with autocast_ctx():
            loss = lossf(model(X), y)
        if scaler is None:
            loss.backward()     #反向传播
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP_MAX_NORM)      #梯度裁剪  
            opt.step()      #更新模型参数
        else:
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP_MAX_NORM)
            scaler.step(opt)
            scaler.update()
        tot += float(loss.detach().item())
        n_batches += 1
    if scheduler is not None and n_batches > 0:
        scheduler.step()
    return tot / max(len(loader), 1)      #返回平均损失


def _run_epoch_train_adv(
    model, loader, device, lossf, opt, scaler, autocast_ctx, m, s, epoch_idx, adv_cfg, scheduler=None
):        #对抗训练单轮训练+计算损失函数
    model.train()
    tot = 0.0
    n_batches = 0
    stats = {
        "loss_clean": 0.0,
        "loss_adv": 0.0,
        "loss_out_cons": 0.0,
        "loss_feat_cons": 0.0,
        "mean_loss_target": 0.0,
        "mean_loss_phys": 0.0,
        "mean_lambda_phys": 0.0,
        "train_adv_delta_mean": 0.0,
        "train_adv_delta_max": 0.0,
        "train_adv_asr": 0.0,
    }
    cur_adv_lambda = 0.0 if epoch_idx < adv_cfg["warmup_epochs"] else adv_cfg["adv_lambda"]      #对抗训练的lambda
    need_pgd = cur_adv_lambda > 0.0      #是否需要PGD攻击
    for X, y in loader:
        X = X.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        opt.zero_grad(set_to_none=True)
        attack_diagnostics = {}
        with autocast_ctx():
            logits_clean, feat_clean = model(X, return_features=True)       #干净样本的输出特征和隐藏特征
            loss_clean = lossf(logits_clean, y)      #干净样本损失
            if need_pgd:
                if adv_cfg.get("use_penalty_phys_pgd_train", True):
                    attacked = apply_pgd_malicious_only(
                        model,
                        X,
                        y,
                        pgd_phys_hybrid,
                        m,
                        s,
                        eps=adv_cfg["adv_eps"],
                        alpha=adv_cfg["pgd_alpha"],
                        steps=adv_cfg["pgd_steps"],
                        lambda_phys_max=adv_cfg["lambda_phys_max"],
                        lambda_phys_gamma=adv_cfg["lambda_phys_gamma"],
                        use_lambda_schedule=adv_cfg["use_lambda_schedule"],
                        use_soft_projection=adv_cfg["use_soft_projection"],
                        projection_start_ratio=adv_cfg["projection_start_ratio"],
                        final_projection=adv_cfg["final_projection"],
                        return_diagnostics=True,
                    )
                    if isinstance(attacked, tuple):
                        X2, attack_diagnostics = attacked
                    else:
                        X2 = attacked
                        attack_diagnostics = {}
                else:
                    X2 = apply_pgd_malicious_only(
                        model,
                        X,
                        y,
                        pgd_phys,
                        m,
                        s,
                        eps=adv_cfg["adv_eps"],
                        alpha=adv_cfg["pgd_alpha"],
                        steps=adv_cfg["pgd_steps"],
                        project_physical=adv_cfg.get("project_physical", True),
                    )
                logits_adv, feat_adv = model(X2, return_features=True)
                mal_mask = y == 1
                if mal_mask.any():
                    loss_adv = lossf(logits_adv[mal_mask], y[mal_mask])
                else:
                    loss_adv = loss_clean.detach() * 0.0
                loss_out_cons, loss_feat_cons = _physical_consistency_losses(
                    logits_clean,
                    feat_clean,
                    logits_adv,
                    feat_adv,
                    y,
                    adv_cfg["phys_temperature"],
                )
            else:
                X2 = X
                loss_adv = loss_clean.detach() * 0.0
                loss_out_cons = loss_clean.detach() * 0.0
                loss_feat_cons = loss_clean.detach() * 0.0

            loss = (
                loss_clean
                + cur_adv_lambda * loss_adv
                + adv_cfg["phys_out_lambda"] * loss_out_cons
                + adv_cfg["phys_feat_lambda"] * loss_feat_cons
            )
            if not torch.isfinite(loss):
                loss = loss_clean

        if scaler is None:
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP_MAX_NORM)
            opt.step()
        else:
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP_MAX_NORM)
            scaler.step(opt)
            scaler.update()
        tot += float(loss.detach().item())
        stats["loss_clean"] += float(loss_clean.detach().item())
        stats["loss_adv"] += float(loss_adv.detach().item())
        stats["loss_out_cons"] += float(loss_out_cons.detach().item())
        stats["loss_feat_cons"] += float(loss_feat_cons.detach().item())
        with torch.no_grad():
            mal_mask = y == 1
            if need_pgd and mal_mask.any():
                delta = (X2[mal_mask] - X[mal_mask]).abs()
                stats["train_adv_delta_mean"] += float(delta.mean().item())
                stats["train_adv_delta_max"] += float(delta.max().item())
                pred_adv = logits_adv[mal_mask].argmax(dim=1)
                stats["train_adv_asr"] += float((pred_adv == 0).float().mean().item())
        for k in ("mean_loss_target", "mean_loss_phys", "mean_lambda_phys"):
            stats[k] += float(attack_diagnostics.get(k, 0.0))
        n_batches += 1
    if scheduler is not None and n_batches > 0:
        scheduler.step()
    denom = max(n_batches, 1)
    out = {"train_loss": tot / max(len(loader), 1)}
    out.update({k: v / denom for k, v in stats.items()})
    return out


def _validation_loss(model, loader, device, lossf):     #验证集损失函数
    model.eval()
    tot = 0.0
    with torch.no_grad():
        for X, y in loader:
            X = X.to(device, non_blocking=True)
            y = y.to(device, non_blocking=True)
            tot += float(lossf(model(X), y).item())
    return tot / max(len(loader), 1)


def _validation_threshold_metrics(model, loader, device, *, metric: str) -> tuple[float, float, dict[str, float]]:
    """在验证集上扫描阈值；返回 ``(score, threshold, metrics)``，score 越大越好。"""
    y_true, prob_malicious, _physical_metrics = _collect_malicious_probs(model, loader, device)
    candidates = np.linspace(0, 1, THRESHOLD_GRID_POINTS)
    best_score = -float("inf")
    best_rank = (-float("inf"), -float("inf"))
    best_t = 0.5
    best_metrics: dict[str, float] = {}
    for t in candidates:
        metrics = _metrics_at_threshold(y_true, prob_malicious, float(t))
        if metric == "clean_recall":
            rank = (metrics["recall"], metrics["f1"])
        else:
            rank = (metrics["f1"], metrics["recall"])
        if rank > best_rank:
            best_rank = rank
            best_score = float(rank[0])
            best_t = float(t)
            best_metrics = metrics
    return best_score, best_t, best_metrics


def _validation_attack_loss(model, loader, device, lossf, m, s, adv_cfg) -> float:
    """验证集 phys-PGD penalty 扰动后的分类损失，仅供可选 early stopping 诊断使用。"""
    model.eval()
    tot = 0.0
    n_batches = 0
    for X, y in loader:
        X = X.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        X_adv = _maybe_apply_eval_attack(
            model,
            X,
            y,
            mode="phys_hybrid_pgd",
            m=m,
            s=s,
            adv_eps=adv_cfg["adv_eps"],
            pgd_alpha=adv_cfg["pgd_alpha"],
            pgd_steps=adv_cfg["pgd_steps"],
            phys_penalty_lambda_max=adv_cfg["lambda_phys_max"],
            phys_penalty_lambda_gamma=adv_cfg["lambda_phys_gamma"],
            phys_penalty_use_lambda_schedule=adv_cfg["use_lambda_schedule"],
            phys_penalty_w_speed=PHYS_PENALTY_W_SPEED,
            phys_penalty_w_altitude=PHYS_PENALTY_W_ALTITUDE,
            phys_penalty_w_latlon=PHYS_PENALTY_W_LATLON,
            phys_penalty_w_heading=PHYS_PENALTY_W_HEADING,
            phys_penalty_use_soft_projection=adv_cfg["use_soft_projection"],
            phys_penalty_projection_start_ratio=adv_cfg["projection_start_ratio"],
            phys_penalty_final_projection=adv_cfg["final_projection"],
        )
        with torch.no_grad():
            tot += float(lossf(model(X_adv), y).item())
        n_batches += 1
    return tot / max(n_batches, 1)


def train_with_val(
    model,
    train_loader,
    val_loader,
    device,
    epochs=EPOCHS,
    lr=LR,
    use_amp=USE_AMP,
    class_weights=BASELINE_CE_CLASS_WEIGHTS,
    early_stop_patience=EARLY_STOP_PATIENCE,
):
    opt = torch.optim.Adam(model.parameters(), lr=lr)       #Adam优化器
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(epochs, 1))       #余弦退火学习率调度器
    weights = torch.tensor(class_weights, device=device)
    lossf = nn.CrossEntropyLoss(weight=weights)       #交叉熵损失函数

    amp_enabled = bool(use_amp) and device.type == "cuda"
    if amp_enabled:
        scaler = torch.amp.GradScaler("cuda")
        autocast_ctx = lambda: torch.amp.autocast(device_type="cuda", enabled=True)
    else:
        scaler = None
        autocast_ctx = lambda: nullcontext()

    best_state = copy.deepcopy(model.state_dict())      #最佳模型参数
    best_val = float("inf")      #最佳验证集损失
    wait = 0
    for e in range(epochs):      #训练轮数
        tr_loss = _run_epoch_train(
            model, train_loader, device, lossf, opt, scaler, autocast_ctx, scheduler=scheduler
        )      #训练损失
        lr_now = opt.param_groups[0]["lr"]
        val_loss = _validation_loss(model, val_loader, device, lossf)       #验证集损失
        print(f"Epoch {e + 1:02d} | train_loss={tr_loss:.4f} | val_loss={val_loss:.4f} | lr={lr_now:.6f}")
        if val_loss < best_val - 1e-6:
            best_val = val_loss
            best_state = copy.deepcopy(model.state_dict())
            wait = 0
        else:
            wait += 1
            if wait >= early_stop_patience:
                print(f"Early stopping at epoch {e + 1}. best_val={best_val:.4f}")
                break
    model.load_state_dict(best_state)
    return model


def train_adv_with_val(
    model,
    train_loader,
    val_loader,
    m,      #训练集和验证集的均值
    s,      #训练集和验证集的标准差
    device,
    epochs=EPOCHS,      #训练轮数，40
    lr=LR,      #学习率，1e-3
    use_amp=USE_AMP,        #是否使用混合精度训练，默认为True
    adv_eps=ADV_TRAIN_EPS,      #PGD攻击epsilon，默认为0.05
    adv_lambda=ADV_TRAIN_LAMBDA,      #攻击权重，默认为0.1
    warmup_epochs=ADV_WARMUP_EPOCHS,      #预热轮数，默认为3
    pgd_steps=PGD_STEPS,      #PGD步数，默认为10
    pgd_alpha=PGD_ALPHA,      #PGD步长，默认为0.01
    project_physical=ADV_PROJECT_PHYSICAL,      #Phys-PGD 是否进行物理投影，默认为True
    phys_out_lambda=PHYS_OUT_LAMBDA,      #物理一致性输出分布 KL 约束权重
    phys_feat_lambda=PHYS_FEAT_LAMBDA,      #物理一致性隐藏表征 MSE 约束权重
    phys_temperature=PHYS_TEMPERATURE,      #物理一致性 KL 蒸馏温度
    class_weights=ADV_CE_CLASS_WEIGHTS,      #类别权重，默认为[1, 1]
    early_stop_patience=EARLY_STOP_PATIENCE,      #早停轮数，默认为10
    early_stop_metric="clean_loss",      #clean_loss / clean_f1 / clean_recall / robust_score
    use_penalty_phys_pgd_train=USE_PENALTY_PHYS_PGD_TRAIN,      #训练扰动生成器是否使用 penalty-based phys-PGD
    lambda_phys_max=PHYS_PENALTY_LAMBDA_MAX,      #penalty phys-PGD 最大物理惩罚权重
    lambda_phys_gamma=PHYS_PENALTY_LAMBDA_GAMMA,      #penalty phys-PGD lambda 调度指数
    use_lambda_schedule=PHYS_PENALTY_USE_LAMBDA_SCHEDULE,      #是否逐步增大物理惩罚权重
    use_soft_projection=PHYS_PENALTY_USE_SOFT_PROJECTION,      #是否在后半程使用软物理投影辅助
    projection_start_ratio=PHYS_PENALTY_PROJECTION_START_RATIO,      #软投影开始比例
    final_projection=PHYS_PENALTY_FINAL_PROJECTION,      #PGD 结束后是否做最终物理投影
):
    opt = torch.optim.Adam(model.parameters(), lr=lr)       #Adam优化器
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(epochs, 1))       #余弦退火学习率调度器
    weights = torch.tensor(class_weights, device=device)
    lossf = nn.CrossEntropyLoss(weight=weights)       #交叉熵损失函数
    adv_cfg = {
        "adv_eps": adv_eps,     #对抗训练的epsilon，0.3
        "adv_lambda": adv_lambda,      #对抗训练的lambda，0.5
        "warmup_epochs": warmup_epochs,      #预热轮数，3
        "pgd_steps": pgd_steps,      #PGD步数，10
        "pgd_alpha": pgd_alpha,      #PGD步长，0.03
        "project_physical": project_physical,      #Phys-PGD 是否进行物理投影，True
        "use_penalty_phys_pgd_train": bool(use_penalty_phys_pgd_train),
        "lambda_phys_max": lambda_phys_max,
        "lambda_phys_gamma": lambda_phys_gamma,
        "use_lambda_schedule": bool(use_lambda_schedule),
        "use_soft_projection": bool(use_soft_projection),
        "projection_start_ratio": projection_start_ratio,
        "final_projection": bool(final_projection),
        "phys_out_lambda": phys_out_lambda,     #物理一致性输出分布 KL 约束权重，0.05
        "phys_feat_lambda": phys_feat_lambda,      #物理一致性隐藏表征 MSE 约束权重，0.02
        "phys_temperature": phys_temperature,      #物理一致性 KL 蒸馏温度，2.0
    }
    print(
        "Adv training config | "
        f"use_penalty_phys_pgd_train={adv_cfg['use_penalty_phys_pgd_train']} | "
        f"lambda_phys_max={adv_cfg['lambda_phys_max']} | "
        f"lambda_phys_gamma={adv_cfg['lambda_phys_gamma']} | "
        f"use_lambda_schedule={adv_cfg['use_lambda_schedule']} | "
        f"use_soft_projection={adv_cfg['use_soft_projection']} | "
        f"projection_start_ratio={adv_cfg['projection_start_ratio']} | "
        f"final_projection={adv_cfg['final_projection']} | "
        f"phys_out_lambda={adv_cfg['phys_out_lambda']} | "
        f"phys_feat_lambda={adv_cfg['phys_feat_lambda']} | "
        f"early_stop_metric={early_stop_metric}"
    )
    early_stop_metric = str(early_stop_metric).lower()
    if early_stop_metric not in {"clean_loss", "clean_f1", "clean_recall", "robust_score"}:
        raise ValueError("early_stop_metric must be one of: clean_loss, clean_f1, clean_recall, robust_score")

    amp_enabled = bool(use_amp) and device.type == "cuda"
    if amp_enabled:
        scaler = torch.amp.GradScaler("cuda")
        autocast_ctx = lambda: torch.amp.autocast(device_type="cuda", enabled=True)
    else:
        scaler = None
        autocast_ctx = lambda: nullcontext()

    best_state = copy.deepcopy(model.state_dict())
    best_score = -float("inf")
    best_metric_value = float("inf") if early_stop_metric == "clean_loss" else -float("inf")
    wait = 0
    for e in range(epochs):
        tr_stats = _run_epoch_train_adv(
            model,      #模型
            train_loader,
            device,
            lossf,      #损失函数
            opt,      #优化器
            scaler,      #混合精度训练的梯度缩放器
            autocast_ctx,      #混合精度训练的上下文
            m,      #训练集和验证集的均值
            s,      #训练集和验证集的标准差
            e,      #训练轮数
            adv_cfg,
            scheduler=scheduler,
        )
        tr_loss = tr_stats["train_loss"]
        lr_now = opt.param_groups[0]["lr"]      #当前学习率
        val_loss = _validation_loss(model, val_loader, device, lossf)      #验证集损失
        val_extra = ""
        if early_stop_metric == "clean_loss":
            cur_score = -val_loss
            cur_metric_value = val_loss
        elif early_stop_metric in {"clean_f1", "clean_recall"}:
            cur_score, val_thr, val_metrics = _validation_threshold_metrics(
                model, val_loader, device, metric=early_stop_metric
            )
            cur_metric_value = cur_score
            val_extra = (
                f" | val_thr={val_thr:.3f} | val_f1={val_metrics.get('f1', 0.0):.4f} "
                f"| val_recall={val_metrics.get('recall', 0.0):.4f}"
            )
        else:
            robust_val_loss = _validation_attack_loss(model, val_loader, device, lossf, m, s, adv_cfg)
            cur_score = -(val_loss + robust_val_loss)
            cur_metric_value = val_loss + robust_val_loss
            val_extra = f" | robust_val_loss={robust_val_loss:.4f} | robust_score_loss={cur_metric_value:.4f}"
        print(
            f"Adv Epoch {e + 1:02d} | train_loss={tr_loss:.4f} | val_loss={val_loss:.4f} "
            f"| clean_loss={tr_stats['loss_clean']:.4f} | adv_loss={tr_stats['loss_adv']:.4f} "
            f"| out_cons={tr_stats['loss_out_cons']:.4f} | feat_cons={tr_stats['loss_feat_cons']:.4f} "
            f"| adv_delta_mean={tr_stats['train_adv_delta_mean']:.6f} "
            f"| adv_delta_max={tr_stats['train_adv_delta_max']:.6f} "
            f"| train_adv_asr={tr_stats['train_adv_asr']:.4f} "
            f"| mean_loss_target={tr_stats['mean_loss_target']:.4f} "
            f"| mean_loss_phys={tr_stats['mean_loss_phys']:.4f} "
            f"| mean_lambda_phys={tr_stats['mean_lambda_phys']:.4f} "
            f"| early_stop_{early_stop_metric}={cur_metric_value:.4f}{val_extra} | lr={lr_now:.6f}"
        )
        if cur_score > best_score + 1e-6:
            best_score = cur_score
            best_metric_value = cur_metric_value
            best_state = copy.deepcopy(model.state_dict())
            wait = 0
        else:
            wait += 1
            if wait >= early_stop_patience:
                print(
                    f"Adv early stopping at epoch {e + 1}. "
                    f"best_{early_stop_metric}={best_metric_value:.4f}"
                )
                break
    model.load_state_dict(best_state)
    return model


def evaluate(
    model,
    loader,
    device,
    threshold=0.5,
    mode=None,
    m=None,
    s=None,
    adv_eps=EVAL_ATTACK_EPS,
    pgd_alpha=PGD_ALPHA,
    pgd_steps=PGD_STEPS,
    phys_penalty_lambda_max=PHYS_PENALTY_LAMBDA_MAX,
    phys_penalty_lambda_gamma=PHYS_PENALTY_LAMBDA_GAMMA,
    phys_penalty_use_lambda_schedule=PHYS_PENALTY_USE_LAMBDA_SCHEDULE,
    phys_penalty_w_speed=PHYS_PENALTY_W_SPEED,
    phys_penalty_w_altitude=PHYS_PENALTY_W_ALTITUDE,
    phys_penalty_w_latlon=PHYS_PENALTY_W_LATLON,
    phys_penalty_w_heading=PHYS_PENALTY_W_HEADING,
    phys_penalty_use_soft_projection=PHYS_PENALTY_USE_SOFT_PROJECTION,
    phys_penalty_projection_start_ratio=PHYS_PENALTY_PROJECTION_START_RATIO,
    phys_penalty_final_projection=PHYS_PENALTY_FINAL_PROJECTION,
    physical_m=None,        #physical_m=m
    physical_s=None,        #physical_s=s
):
    return evaluate_with_threshold(
        model,
        loader,
        device,
        threshold=threshold,
        mode=mode,
        m=m,
        s=s,
        adv_eps=adv_eps,
        pgd_alpha=pgd_alpha,
        pgd_steps=pgd_steps,
        phys_penalty_lambda_max=phys_penalty_lambda_max,
        phys_penalty_lambda_gamma=phys_penalty_lambda_gamma,
        phys_penalty_use_lambda_schedule=phys_penalty_use_lambda_schedule,
        phys_penalty_w_speed=phys_penalty_w_speed,
        phys_penalty_w_altitude=phys_penalty_w_altitude,
        phys_penalty_w_latlon=phys_penalty_w_latlon,
        phys_penalty_w_heading=phys_penalty_w_heading,
        phys_penalty_use_soft_projection=phys_penalty_use_soft_projection,
        phys_penalty_projection_start_ratio=phys_penalty_projection_start_ratio,
        phys_penalty_final_projection=phys_penalty_final_projection,
        physical_m=physical_m,
        physical_s=physical_s,
    )

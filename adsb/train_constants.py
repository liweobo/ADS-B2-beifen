"""训练 / 验证 / 测试流程共用的数值超参（单一来源，避免魔法数分散）。"""

from __future__ import annotations

# ---- 随机种子与 DataLoader ----
SEED = 42
TRAIN_BATCH_SIZE = 64
EVAL_BATCH_SIZE = 128

# ---- 滑窗（``build_raw_windows`` / ``prepare_train_val_test_loaders``）----
WINDOW_SIZE = 15

# ---- 数据集划分（``train_test_split``）----
TRAIN_VAL_TEST_HOLDOUT_FRACTION = 0.2
TRAIN_VAL_TEST_VAL_FRACTION = 0.125

# ---- 优化器、轮数、早停（与主实验 ``train_common_kwargs`` 一致）----
EPOCHS = 30
LR = 1e-3
USE_AMP = True
EARLY_STOP_PATIENCE = 6
GRAD_CLIP_MAX_NORM = 1.0

# ---- 交叉熵类别权重 (w_normal, w_malicious) ----
BASELINE_CE_CLASS_WEIGHTS = (1.0, 6.0)
ADV_CE_CLASS_WEIGHTS = (1.0, 6.0)

# ---- 对抗训练（penalty-based phys-PGD，主流程第二模型）----
ADV_TRAIN_EPS = 0.1    #对抗训练的epsilon
ADV_TRAIN_LAMBDA = 0.5    #对抗训练的lambda        #物理损失权重
ADV_WARMUP_EPOCHS = 3    #预热轮数
PGD_STEPS = 5    #PGD步数
PGD_ALPHA = 0.03    #PGD步长
ADV_PROJECT_PHYSICAL = True    #Phys-PGD 是否进行物理投影（评价/攻击阶段，不作为训练损失）
USE_PENALTY_PHYS_PGD_TRAIN = True    #对抗训练默认使用 penalty-based phys-PGD 生成扰动样本
PHYS_OUT_LAMBDA = 0.01    #物理一致性：clean/phys-PGD 输出分布 KL 约束权重
PHYS_FEAT_LAMBDA = 0.005    #物理一致性：clean/phys-PGD LSTM 表征 MSE 约束权重
PHYS_TEMPERATURE = 2.0    #输出一致性 KL 蒸馏温度

# ---- 消融里 PGD 训练使用的 L_inf 半径（与主实验 ADV_TRAIN_EPS 区分）----
ADV_TRAIN_EPS_ABLATION = 0.015

# ---- PGD / Phys-PGD 评估与轨迹图 ε ----
EVAL_ATTACK_EPS = 0.1     #评估攻击的epsilon
PHYS_PENALTY_LAMBDA_MAX = 10.0
PHYS_PENALTY_LAMBDA_GAMMA = 2.0
PHYS_PENALTY_USE_LAMBDA_SCHEDULE = True
PHYS_PENALTY_W_SPEED = 1.0
PHYS_PENALTY_W_ALTITUDE = 1.0
PHYS_PENALTY_W_LATLON = 1.0
PHYS_PENALTY_W_HEADING = 10.0
PHYS_PENALTY_USE_SOFT_PROJECTION = False    #关闭 tanh 幅值软限幅；diff_ref 方向对齐约束已关闭
PHYS_PENALTY_PROJECTION_START_RATIO = 0.5
PHYS_PENALTY_FINAL_PROJECTION = True    #结束时执行物理投影；是否软限幅由 PHYS_PENALTY_USE_SOFT_PROJECTION 控制
TRAJECTORY_ADV_EPS_DEFAULT = 0.015     #轨迹图的epsilon

# ---- 阈值搜索（``pick_best_threshold``）----
THRESHOLD_GRID_POINTS = 50

# ---- 鲁棒性曲线 ε 网格 ----
ROBUSTNESS_EPS_MIN = 0.005
ROBUSTNESS_EPS_MAX = 0.06
ROBUSTNESS_EPS_NUM = 13

# ---- 数据注入（与 ``prepare_train_val_test_loaders`` / 消融一致）----
INJECT_RATIO = 0.03
PER_ATTACK_INJECT_RATIO = 0.03

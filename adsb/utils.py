import random

import numpy as np
import torch


def _autocast_disabled_for(X: torch.Tensor):
    # 关闭 PyTorch 自动混合精度，攻击生成使用 Float 32
    return torch.amp.autocast(device_type=("cuda" if X.is_cuda else "cpu"), enabled=False)


def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

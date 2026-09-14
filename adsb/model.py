import torch
import torch.nn as nn


class LSTMDetector(nn.Module):
    def __init__(
        self, input_dim=12, hidden_dim=64, num_layers=2, dropout=0.3, bidirectional=True
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.bidirectional = bidirectional
        self.lstm = nn.LSTM(
            input_dim,
            hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
            bidirectional=bidirectional,
        )
        out_dim = hidden_dim * (2 if bidirectional else 1)
        # Two-class logits: index 0 = normal and index 1 = anomalous,
        # matching the y=0/1 labels used by CrossEntropyLoss.
        self.head = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(out_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 2),
        )

    def forward(self, x, return_features: bool = False):
        o, _ = self.lstm(x)
        if self.bidirectional:
            # The final forward state is at the last time step; the final
            # backward state is at the first time step.
            h_fwd = o[:, -1, : self.hidden_dim]
            h_bwd = o[:, 0, self.hidden_dim :]
            h = torch.cat([h_fwd, h_bwd], dim=-1)
        else:
            h = o[:, -1, :]
        logits = self.head(h)
        if return_features:
            return logits, h
        return logits

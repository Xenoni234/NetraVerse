"""Logistic-regression baseline (FR22, R3): same unified features, same windows, same target.

Input = the L history windows of scaled FEATURE_COLUMNS, flattened (L x F).
Target = attack anywhere in the next K windows (the 300 s forecast target).
"""
from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression

from src.features.schema import FEATURE_COLUMNS


class LogRegBaseline:
    def __init__(self, history: int, C: float = 0.5):
        self.history = history
        self.clf = LogisticRegression(C=C, class_weight="balanced", max_iter=400, solver="lbfgs")

    @staticmethod
    def flatten(x_hist: np.ndarray) -> np.ndarray:
        return x_hist.reshape(len(x_hist), -1)

    def fit(self, x_hist: np.ndarray, y: np.ndarray) -> "LogRegBaseline":
        self.clf.fit(self.flatten(x_hist), y)
        return self

    def predict_proba(self, x_hist: np.ndarray) -> np.ndarray:
        return self.clf.predict_proba(self.flatten(x_hist))[:, 1]

    def feature_names(self) -> list[str]:
        return [f"{c}@t-{self.history - 1 - i}" for i in range(self.history) for c in FEATURE_COLUMNS]

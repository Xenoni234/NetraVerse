"""Leakage-safe forecasting baselines for Phase 5 evaluation.

Every supervised baseline is trained on the training sequence split only. The
functions return one probability column per configured forecast horizon so the
same metric and threshold code can be used for persistence, logistic
regression, tree models and the world model.
"""

from __future__ import annotations

from typing import Any

import numpy as np


def persistence_probabilities(batch: Any) -> np.ndarray:
    """Predict the current origin risk at every future horizon."""
    origin = batch.meta["origin_risk"].to_numpy(dtype="float32")
    return np.repeat(origin[:, None], batch.y_risk.shape[1], axis=1)


def prior_probabilities(train_batch: Any, target_batch: Any) -> np.ndarray:
    """Predict the train-split positive rate independently at each horizon."""
    prior = np.asarray(train_batch.y_risk, dtype="float64").mean(axis=0)
    return np.repeat(prior[None, :], len(target_batch.y_risk), axis=0)


def _flatten(batch: Any, scaler: dict | None = None) -> np.ndarray:
    from src.data.windowing import apply_scaler

    x = batch.x if scaler is None else apply_scaler(batch.x, scaler)
    return np.asarray(x, dtype="float32").reshape(len(x), -1)


def logistic_probabilities(train_batch: Any, target_batch: Any, scaler: dict | None = None,
                           *, random_state: int = 1337) -> np.ndarray:
    """Fit balanced logistic regression per horizon on flattened histories."""
    from sklearn.linear_model import LogisticRegression

    x_train = _flatten(train_batch, scaler)
    x_target = _flatten(target_batch, scaler)
    result = np.zeros((len(target_batch.y_risk), train_batch.y_risk.shape[1]), dtype="float64")
    for h in range(train_batch.y_risk.shape[1]):
        y = np.asarray(train_batch.y_risk[:, h]).astype(int)
        if np.unique(y).size < 2:
            result[:, h] = float(y.mean())
            continue
        model = LogisticRegression(
            max_iter=2000, class_weight="balanced", solver="lbfgs",
            random_state=random_state,
        )
        model.fit(x_train, y)
        result[:, h] = model.predict_proba(x_target)[:, 1]
    return result


def random_forest_probabilities(train_batch: Any, target_batch: Any, scaler: dict | None = None,
                                *, random_state: int = 1337, n_estimators: int = 200) -> np.ndarray:
    """Fit a balanced random-forest history baseline per horizon."""
    from sklearn.ensemble import RandomForestClassifier

    x_train = _flatten(train_batch, scaler)
    x_target = _flatten(target_batch, scaler)
    result = np.zeros((len(target_batch.y_risk), train_batch.y_risk.shape[1]), dtype="float64")
    for h in range(train_batch.y_risk.shape[1]):
        y = np.asarray(train_batch.y_risk[:, h]).astype(int)
        if np.unique(y).size < 2:
            result[:, h] = float(y.mean())
            continue
        model = RandomForestClassifier(
            n_estimators=n_estimators, class_weight="balanced_subsample",
            min_samples_leaf=2, n_jobs=-1, random_state=random_state,
        )
        model.fit(x_train, y)
        result[:, h] = model.predict_proba(x_target)[:, 1]
    return result


__all__ = [
    "persistence_probabilities", "prior_probabilities",
    "logistic_probabilities", "random_forest_probabilities",
]

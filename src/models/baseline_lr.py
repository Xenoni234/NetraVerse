"""Logistic-regression baselines.

Two classes live here, and the distinction matters:

:class:`LogisticRegressionBaseline`
    **Flow-level detection.** One flow in, attack/benign out. This is the
    pipeline smoke test and the classical-ML bar for *detection*. It is what
    ``scripts/train_baseline_lr.py`` trains.

:class:`SequenceLogisticRegressionBaseline`
    **Forecasting.** The flattened ``L x F`` history in, future attack
    probability out. This is the baseline CLAUDE.md section 9 requires the world
    model to beat. Still a scaffold — it needs windowing first.

.. warning::
   **These two numbers are not comparable.** Flow-level detection answers "is
   this completed flow malicious?"; forecasting answers "will an attack occur in
   the next 30-120 s?". The second is strictly harder and will score lower. Do
   not put the flow-level F1 in a results table as the bar the world model must
   clear — that comparison would be meaningless and would make the world model
   look worse than it is.

Why logistic regression, and why scikit-learn: it is fast, its coefficients are
directly readable, and it is a different implementation stack from the torch
code, so a bug shared across the torch paths shows up as a disagreement. If LR
scores near zero, suspect the labelling before blaming any model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np


@dataclass
class LogisticRegressionBaseline:
    """Flow-level logistic regression with standardisation built in.

    Scaling is fitted inside :meth:`fit` on the training data only and reused at
    predict time, so the scaler can never be accidentally refitted on test — a
    mistake that silently inflates results.

    Attributes:
        C: Inverse regularisation strength.
        max_iter: Solver iteration cap. LR on unscaled network features often
            fails to converge; the built-in scaler plus this cap avoids a wall
            of ConvergenceWarnings.
        class_weight: ``"balanced"`` by default — the positive class is a minority.
        feature_names: Recorded at fit time, for :meth:`top_coefficients`.
    """

    C: float = 1.0
    max_iter: int = 2000
    class_weight: str | None = "balanced"
    random_state: int = 1337
    solver: str = "lbfgs"
    feature_names: tuple[str, ...] = ()
    _pipeline: Any = field(default=None, repr=False)

    def fit(
        self, X: np.ndarray, y: np.ndarray, *, feature_names: Sequence[str] | None = None
    ) -> "LogisticRegressionBaseline":
        """Fit the model.

        Args:
            X: ``(n_samples, n_features)`` finite float matrix.
            y: ``(n_samples,)`` binary labels.
            feature_names: Column names, recorded for interpretability output.

        Returns:
            ``self``, for chaining.
        """
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        X = np.asarray(X, dtype="float64")
        y = np.asarray(y).astype(int).ravel()
        self._check_finite(X)

        if len(np.unique(y)) < 2:
            raise ValueError(
                f"Training labels contain a single class ({np.unique(y).tolist()}). "
                "Check the split — a chronological cut can land entirely inside "
                "one label block."
            )

        if feature_names is not None:
            self.feature_names = tuple(feature_names)

        self._pipeline = Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "lr",
                    LogisticRegression(
                        C=self.C,
                        max_iter=self.max_iter,
                        class_weight=self.class_weight,
                        random_state=self.random_state,
                        solver=self.solver,
                        n_jobs=None,
                    ),
                ),
            ]
        )
        self._pipeline.fit(X, y)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return ``(n_samples,)`` probability of the positive (attack) class."""
        self._require_fitted()
        X = np.asarray(X, dtype="float64")
        self._check_finite(X)
        return self._pipeline.predict_proba(X)[:, 1]

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Return ``(n_samples,)`` binary predictions at ``threshold``."""
        return (self.predict_proba(X) >= threshold).astype(int)

    def top_coefficients(self, k: int = 15) -> list[tuple[str, float]]:
        """Largest-magnitude coefficients, signed, most influential first.

        Sanity check: if the top features are not the ones security intuition
        expects (flag counts, rates, IAT), something upstream is wrong.
        """
        self._require_fitted()
        coefs = self._pipeline.named_steps["lr"].coef_.ravel()
        names = self.feature_names or tuple(f"f{i}" for i in range(len(coefs)))
        order = np.argsort(np.abs(coefs))[::-1][:k]
        return [(names[i], float(coefs[i])) for i in order]

    def save(self, path: Path) -> Path:
        """Persist the fitted pipeline with joblib."""
        import joblib

        self._require_fitted()
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"pipeline": self._pipeline, "feature_names": self.feature_names,
             "C": self.C, "class_weight": self.class_weight},
            path,
        )
        return path

    @classmethod
    def load(cls, path: Path) -> "LogisticRegressionBaseline":
        """Load a model written by :meth:`save`."""
        import joblib

        payload = joblib.load(path)
        model = cls(C=payload["C"], class_weight=payload["class_weight"])
        model.feature_names = tuple(payload["feature_names"])
        model._pipeline = payload["pipeline"]
        return model

    # ---- internals ------------------------------------------------------- #

    def _require_fitted(self) -> None:
        if self._pipeline is None:
            raise RuntimeError("Model is not fitted; call fit() first")

    @staticmethod
    def _check_finite(X: np.ndarray) -> None:
        if not np.isfinite(X).all():
            n_bad = int((~np.isfinite(X)).sum())
            raise ValueError(
                f"{n_bad} non-finite value(s) in the feature matrix. "
                "Run unified_schema.clean_features() first — CIC-IDS2018 carries "
                "genuine infinities in the rate columns."
            )


@dataclass
class SequenceLogisticRegressionBaseline:
    """Forecasting LR over the flattened ``L x F`` history.

    The baseline CLAUDE.md section 9 requires the world model to beat. Sees the
    same information as the LSTM but has no notion of sequence.

    TODO
    ----
    * [ ] Implement once windowing lands: one estimator per horizon k.
    * [ ] Reuse ``flatten_history`` so SHAP attributions stay comparable with
          the LSTM's.
    """

    horizons: tuple[int, ...] = (1, 2, 4)
    C: float = 1.0
    models: dict[int, object] = field(default_factory=dict)

    def fit(self, x: np.ndarray, y_risk: np.ndarray) -> "SequenceLogisticRegressionBaseline":
        """Fit one classifier per horizon over ``(N, L, F)`` histories."""
        raise NotImplementedError("TODO: needs src.data.windowing.build_sequences")

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """``(N, |K|)`` predicted attack probability per horizon."""
        raise NotImplementedError("TODO: needs src.data.windowing.build_sequences")


def flatten_history(x: np.ndarray) -> np.ndarray:
    """``(N, L, F)`` -> ``(N, L*F)``, most-recent window last.

    Defined here so the ordering convention lives in one place and
    ``top_coefficients`` can invert it.
    """
    if x.ndim != 3:
        raise ValueError(f"Expected (N, L, F), got shape {x.shape}")
    return x.reshape(x.shape[0], -1)


__all__ = [
    "LogisticRegressionBaseline",
    "SequenceLogisticRegressionBaseline",
    "flatten_history",
]

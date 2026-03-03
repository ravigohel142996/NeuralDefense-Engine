"""
core/anomaly_detector.py – Anomaly detection layer using Isolation Forest.

Trains on normal-baseline samples and flags deviations in live metrics.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import config
from core.environment import NetworkEnvironment, NetworkMetrics


class AnomalyDetector:
    """
    Wraps scikit-learn's :class:`~sklearn.ensemble.IsolationForest` to
    detect anomalous network metrics.

    The detector is trained on *normal* baseline samples so it learns
    the healthy traffic distribution.  Any point that deviates
    significantly is marked as an anomaly.

    Parameters
    ----------
    n_samples : int
        Number of normal samples used to fit the model.
    seed : int | None
        Optional random seed for reproducibility.
    """

    def __init__(
        self,
        n_samples: int = config.TRAINING_SAMPLES,
        seed: int | None = config.RF_RANDOM_STATE,
    ) -> None:
        self._scaler = StandardScaler()
        self._model = IsolationForest(
            n_estimators=config.ISOLATION_FOREST_N_ESTIMATORS,
            contamination=config.ISOLATION_FOREST_CONTAMINATION,
            random_state=seed,
            n_jobs=-1,
        )
        self._fitted = False
        self._seed = seed
        self._n_samples = n_samples

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, env: NetworkEnvironment | None = None) -> "AnomalyDetector":
        """
        Train the Isolation Forest on normal baseline samples.

        Parameters
        ----------
        env : NetworkEnvironment | None
            Environment to sample from.  A fresh one is created if not
            provided.

        Returns
        -------
        AnomalyDetector
            Self (for chaining).
        """
        if env is None:
            env = NetworkEnvironment(seed=self._seed)

        samples = env.bulk_sample(self._n_samples)
        X = np.array([s.to_feature_vector() for s in samples])
        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled)
        self._fitted = True
        return self

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, metrics: NetworkMetrics) -> bool:
        """
        Determine whether *metrics* represent an anomaly.

        Parameters
        ----------
        metrics : NetworkMetrics
            Live snapshot to evaluate.

        Returns
        -------
        bool
            ``True`` if the snapshot is anomalous, ``False`` otherwise.

        Raises
        ------
        RuntimeError
            If the detector has not been trained yet.
        """
        self._require_fitted()
        X = np.array([metrics.to_feature_vector()])
        X_scaled = self._scaler.transform(X)
        # IsolationForest: -1 = anomaly, 1 = normal
        result: int = int(self._model.predict(X_scaled)[0])
        return result == -1

    def anomaly_score(self, metrics: NetworkMetrics) -> float:
        """
        Return a normalised anomaly score in **[0, 1]** (higher = more anomalous).

        Internally uses the raw decision function from Isolation Forest
        (negative decision → anomaly) mapped to [0, 1].

        Parameters
        ----------
        metrics : NetworkMetrics

        Returns
        -------
        float
        """
        self._require_fitted()
        X = np.array([metrics.to_feature_vector()])
        X_scaled = self._scaler.transform(X)
        # decision_function returns negative values for anomalies
        raw: float = float(self._model.decision_function(X_scaled)[0])
        # Map to [0, 1]: lower decision → higher anomaly score
        score = float(np.clip(1.0 - (raw + 0.5), 0.0, 1.0))
        return score

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError(
                "AnomalyDetector has not been trained. Call fit() first."
            )

    @property
    def is_fitted(self) -> bool:
        """Return ``True`` if the model has been trained."""
        return self._fitted

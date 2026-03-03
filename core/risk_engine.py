"""
core/risk_engine.py – Dynamic risk scoring layer.

Computes a weighted risk score in **[0, 100]** by normalising each
network metric against its known danger range and blending the result
with the anomaly score and classifier confidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

import numpy as np

import config
from core.environment import NetworkMetrics


# ---------------------------------------------------------------------------
# Per-metric normalisation: map raw value → [0, 1] danger level
# 0 = safe end of range, 1 = maximum danger
# ---------------------------------------------------------------------------
_DANGER_RANGE: Dict[str, tuple[float, float]] = {
    # (safe_value, max_danger_value) – tightened so mid-severity attacks score > 60
    "traffic_rate":     (config.NORMAL_TRAFFIC_RATE_RANGE[1],     4_000.0),
    "failed_logins":    (config.NORMAL_FAILED_LOGINS_RANGE[1],      200.0),
    "suspicious_ratio": (config.NORMAL_SUSPICIOUS_RATIO_RANGE[1],     1.0),
    "packet_entropy":   (config.NORMAL_PACKET_ENTROPY_RANGE[0],        0.0),   # low entropy = danger
    "ip_reputation":    (config.NORMAL_IP_REPUTATION_RANGE[0],         0.0),   # low rep = danger
    "server_load":      (config.NORMAL_SERVER_LOAD_RANGE[1],         100.0),
    "response_time":    (config.NORMAL_RESPONSE_TIME_RANGE[1],      1_500.0),
}


@dataclass
class RiskReport:
    """Result produced by :class:`RiskEngine`."""

    risk_score: float                   # 0–100
    metric_contributions: Dict[str, float]  # per-metric danger [0–1]
    anomaly_score: float                # raw anomaly component [0–1]
    classifier_confidence: float        # probability of predicted class
    predicted_attack: str
    is_threat: bool                     # True if risk_score > threshold

    @property
    def risk_level(self) -> str:
        """Human-readable risk level string."""
        if self.risk_score < 25:
            return "LOW"
        if self.risk_score < 50:
            return "MEDIUM"
        if self.risk_score < 75:
            return "HIGH"
        return "CRITICAL"

    @property
    def risk_colour(self) -> str:
        """Hex colour associated with the risk level."""
        return {
            "LOW":      "#00c853",
            "MEDIUM":   "#ffd600",
            "HIGH":     "#ff6d00",
            "CRITICAL": "#d50000",
        }[self.risk_level]


class RiskEngine:
    """
    Computes a dynamic risk score that blends:

    * Weighted metric danger levels (70 % of score).
    * Anomaly component (20 % of score).
    * Classifier confidence for a non-Normal prediction (10 % of score).

    Parameters
    ----------
    threshold : float
        Risk score above which a threat is considered active.
        Defaults to :data:`config.RISK_THRESHOLD`.
    """

    _METRIC_WEIGHT = 0.70
    _ANOMALY_WEIGHT = 0.20
    _CLASSIFIER_WEIGHT = 0.10

    def __init__(self, threshold: float = config.RISK_THRESHOLD) -> None:
        self.threshold = threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute(
        self,
        metrics: NetworkMetrics,
        anomaly_score: float,
        predicted_attack: str,
        class_probabilities: Dict[str, float],
    ) -> RiskReport:
        """
        Calculate the risk score for the current network state.

        Parameters
        ----------
        metrics : NetworkMetrics
            Live metric snapshot.
        anomaly_score : float
            Value in [0, 1] from the anomaly detector (1 = most anomalous).
        predicted_attack : str
            Label from the threat classifier.
        class_probabilities : dict[str, float]
            Per-class probability dict from the threat classifier.

        Returns
        -------
        RiskReport
        """
        # 1. Per-metric danger components
        contributions: Dict[str, float] = {}
        metric_dict = metrics.to_dict()
        for name, weight in config.RISK_WEIGHTS.items():
            raw = metric_dict[name]
            contributions[name] = self._normalise_metric(name, raw)

        # 2. Weighted metric score [0, 1]
        weighted_metric = sum(
            contributions[n] * config.RISK_WEIGHTS[n]
            for n in contributions
        )

        # 3. Classifier confidence in a threat (non-Normal) class
        threat_confidence = 1.0 - float(class_probabilities.get("Normal", 1.0))

        # 4. Blend components → [0, 100]
        raw_score = (
            self._METRIC_WEIGHT    * weighted_metric
            + self._ANOMALY_WEIGHT   * float(np.clip(anomaly_score, 0.0, 1.0))
            + self._CLASSIFIER_WEIGHT * float(np.clip(threat_confidence, 0.0, 1.0))
        ) * 100.0

        risk_score = float(np.clip(raw_score, 0.0, 100.0))

        return RiskReport(
            risk_score=risk_score,
            metric_contributions=contributions,
            anomaly_score=float(anomaly_score),
            classifier_confidence=float(class_probabilities.get(predicted_attack, 0.0)),
            predicted_attack=predicted_attack,
            is_threat=risk_score > self.threshold,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_metric(name: str, value: float) -> float:
        """
        Map a raw metric value to a danger level in **[0, 1]**.

        For most metrics higher values → more danger.
        For ``packet_entropy`` and ``ip_reputation`` lower values → more
        danger (ranges are stored reversed in :data:`_DANGER_RANGE`).
        """
        safe, danger = _DANGER_RANGE[name]
        if abs(danger - safe) < 1e-9:
            return 0.0
        # Linear interpolation: safe=0, danger=1
        level = (value - safe) / (danger - safe)
        return float(np.clip(level, 0.0, 1.0))

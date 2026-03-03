"""
core/logger.py – Structured event logging layer.

Maintains a rolling in-memory :class:`pandas.DataFrame` of every
detection cycle and exposes helper queries for the UI.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

import pandas as pd

import config
from core.environment import NetworkMetrics
from core.risk_engine import RiskReport
from core.defense_engine import DefenseAction


class EventLogger:
    """
    Accumulates detection events in a structured :class:`pandas.DataFrame`.

    Each row represents one simulation tick and includes:

    * Raw network metrics
    * Anomaly flag and score
    * Predicted attack type and class probabilities
    * Risk score and level
    * Defense actions taken (if any)

    Parameters
    ----------
    max_rows : int
        Maximum number of rows retained (rolling window).
    """

    _COLUMNS: List[str] = [
        "timestamp",
        # metrics
        "traffic_rate",
        "failed_logins",
        "suspicious_ratio",
        "packet_entropy",
        "ip_reputation",
        "server_load",
        "response_time",
        # detection
        "is_anomaly",
        "anomaly_score",
        # classification
        "predicted_attack",
        "classifier_confidence",
        # risk
        "risk_score",
        "risk_level",
        "is_threat",
        # defense
        "defense_triggered",
        "defense_actions",
    ]

    def __init__(self, max_rows: int = config.HISTORY_SIZE) -> None:
        self._max_rows = max_rows
        self._records: List[Dict[str, Any]] = []
        self._df: pd.DataFrame = pd.DataFrame(columns=self._COLUMNS)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        metrics: NetworkMetrics,
        is_anomaly: bool,
        anomaly_score: float,
        report: RiskReport,
        defense_action: DefenseAction | None,
    ) -> None:
        """
        Append one detection cycle to the event log.

        Parameters
        ----------
        metrics : NetworkMetrics
        is_anomaly : bool
        anomaly_score : float
        report : RiskReport
        defense_action : DefenseAction | None
        """
        row: Dict[str, Any] = {
            "timestamp": datetime.now(tz=timezone.utc),
            **metrics.to_dict(),
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "predicted_attack": report.predicted_attack,
            "classifier_confidence": round(report.classifier_confidence, 4),
            "risk_score": round(report.risk_score, 2),
            "risk_level": report.risk_level,
            "is_threat": report.is_threat,
            "defense_triggered": defense_action is not None,
            "defense_actions": (
                " | ".join(defense_action.actions_taken)
                if defense_action is not None
                else ""
            ),
        }
        self._records.append(row)

        # Rolling window
        if len(self._records) > self._max_rows:
            self._records = self._records[-self._max_rows :]

        self._df = pd.DataFrame(self._records, columns=self._COLUMNS)

    @property
    def dataframe(self) -> pd.DataFrame:
        """Return the current event log as a :class:`pandas.DataFrame`."""
        return self._df.copy()

    @property
    def latest(self) -> Dict[str, Any] | None:
        """Return the most recent event row as a dict, or ``None``."""
        if not self._records:
            return None
        return dict(self._records[-1])

    def threat_summary(self) -> pd.DataFrame:
        """
        Return a summary count of each attack type observed.

        Returns
        -------
        pandas.DataFrame
            Columns: ``attack_type``, ``count``.
        """
        if self._df.empty:
            return pd.DataFrame(columns=["attack_type", "count"])
        counts = (
            self._df["predicted_attack"]
            .value_counts()
            .reset_index()
        )
        # pandas ≥2.0 names columns ('predicted_attack', 'count');
        # older versions name them ('index', 'predicted_attack').
        counts.columns = ["attack_type", "count"]
        return counts

    def recent_threats(self, n: int = 10) -> pd.DataFrame:
        """Return the *n* most recent rows where a threat was detected."""
        if self._df.empty:
            return pd.DataFrame(columns=self._COLUMNS)
        return self._df[self._df["is_threat"]].tail(n)

    def clear(self) -> None:
        """Clear all logged events."""
        self._records.clear()
        self._df = pd.DataFrame(columns=self._COLUMNS)

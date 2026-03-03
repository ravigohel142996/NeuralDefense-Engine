"""
core/defense_engine.py – Autonomous defense action layer.

Determines and executes (simulates) the appropriate countermeasures
when the risk engine triggers a threat alert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

import config
from core.risk_engine import RiskReport


@dataclass
class DefenseAction:
    """Record of a single triggered defense response."""

    timestamp: datetime
    attack_type: str
    risk_score: float
    actions_taken: List[str]
    status: str = "EXECUTED"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "attack_type": self.attack_type,
            "risk_score": round(self.risk_score, 2),
            "actions_taken": " | ".join(self.actions_taken),
            "status": self.status,
        }


class DefenseEngine:
    """
    Evaluates :class:`~core.risk_engine.RiskReport` objects and triggers
    the appropriate countermeasures defined in :data:`config.DEFENSE_ACTIONS`.

    All triggered actions are stored in an internal history for audit.
    """

    def __init__(self) -> None:
        self._history: List[DefenseAction] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, report: RiskReport) -> DefenseAction | None:
        """
        Inspect *report* and trigger defense actions if necessary.

        Parameters
        ----------
        report : RiskReport
            Output from :class:`~core.risk_engine.RiskEngine`.

        Returns
        -------
        DefenseAction | None
            The action record if defenses were triggered, else ``None``.
        """
        if not report.is_threat:
            return None

        actions = config.DEFENSE_ACTIONS.get(
            report.predicted_attack,
            config.DEFENSE_ACTIONS["Normal"],
        )

        da = DefenseAction(
            timestamp=datetime.now(tz=timezone.utc),
            attack_type=report.predicted_attack,
            risk_score=report.risk_score,
            actions_taken=list(actions),
        )
        self._history.append(da)
        return da

    @property
    def history(self) -> List[DefenseAction]:
        """Return the full list of triggered defense actions."""
        return list(self._history)

    def clear_history(self) -> None:
        """Purge the in-memory defense history."""
        self._history.clear()

    def get_actions_for(self, attack_type: str) -> List[str]:
        """
        Retrieve the configured playbook for *attack_type* without
        triggering it.

        Parameters
        ----------
        attack_type : str

        Returns
        -------
        list[str]
        """
        return list(
            config.DEFENSE_ACTIONS.get(attack_type, config.DEFENSE_ACTIONS["Normal"])
        )

"""
core/environment.py – Network environment layer.

Generates realistic baseline network metrics that represent a healthy
infrastructure.  Every call to :meth:`NetworkEnvironment.sample` returns
a fresh snapshot with small Gaussian perturbations around the configured
normal ranges.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict

import numpy as np

import config


@dataclass
class NetworkMetrics:
    """A single snapshot of observed network metrics."""

    traffic_rate: float      # Mbps
    failed_logins: float     # count per minute
    suspicious_ratio: float  # fraction of packets flagged suspicious
    packet_entropy: float    # Shannon entropy (bits)
    ip_reputation: float     # 0 = malicious, 1 = trusted
    server_load: float       # CPU utilisation (%)
    response_time: float     # average response latency (ms)

    def to_dict(self) -> Dict[str, float]:
        """Return metrics as a plain dictionary."""
        return {
            "traffic_rate": self.traffic_rate,
            "failed_logins": self.failed_logins,
            "suspicious_ratio": self.suspicious_ratio,
            "packet_entropy": self.packet_entropy,
            "ip_reputation": self.ip_reputation,
            "server_load": self.server_load,
            "response_time": self.response_time,
        }

    def to_feature_vector(self) -> list[float]:
        """Return ordered list of metric values for ML pipelines."""
        return list(self.to_dict().values())

    @property
    def feature_names(self) -> list[str]:
        """Ordered feature names matching :meth:`to_feature_vector`."""
        return list(self.to_dict().keys())


class NetworkEnvironment:
    """
    Simulates a live network environment by sampling metrics within
    configurable normal ranges.

    Parameters
    ----------
    seed : int | None
        Optional random seed for reproducibility.
    """

    _RANGES: Dict[str, tuple[float, float]] = {
        "traffic_rate":     config.NORMAL_TRAFFIC_RATE_RANGE,
        "failed_logins":    config.NORMAL_FAILED_LOGINS_RANGE,
        "suspicious_ratio": config.NORMAL_SUSPICIOUS_RATIO_RANGE,
        "packet_entropy":   config.NORMAL_PACKET_ENTROPY_RANGE,
        "ip_reputation":    config.NORMAL_IP_REPUTATION_RANGE,
        "server_load":      config.NORMAL_SERVER_LOAD_RANGE,
        "response_time":    config.NORMAL_RESPONSE_TIME_RANGE,
    }

    def __init__(self, seed: int | None = None) -> None:
        self._rng = np.random.default_rng(seed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sample(self) -> NetworkMetrics:
        """
        Generate one baseline (normal) network metrics snapshot.

        Returns
        -------
        NetworkMetrics
            A dataclass with all seven network metric fields populated.
        """
        vals: Dict[str, float] = {}
        for name, (lo, hi) in self._RANGES.items():
            mid = (lo + hi) / 2.0
            std = (hi - lo) / 6.0          # ±3σ fits within [lo, hi]
            raw = float(self._rng.normal(mid, std))
            vals[name] = float(np.clip(raw, lo, hi))

        return NetworkMetrics(**vals)

    def bulk_sample(self, n: int) -> list[NetworkMetrics]:
        """
        Generate *n* independent baseline samples.

        Parameters
        ----------
        n : int
            Number of samples to generate.

        Returns
        -------
        list[NetworkMetrics]
        """
        return [self.sample() for _ in range(n)]

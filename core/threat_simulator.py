"""
core/threat_simulator.py – Attack injection layer.

Overlays attack-specific metric distortions on top of baseline
:class:`NetworkMetrics` to simulate the five threat scenarios defined
in :mod:`config`.
"""

from __future__ import annotations

import random
from typing import Dict, Tuple

import numpy as np

import config
from core.environment import NetworkEnvironment, NetworkMetrics


# Distortion table: for each attack type map each metric to
# (additive_shift, multiplicative_scale) applied *after* clipping
# the base value.  Values tuned so attacks are clearly detectable.
_DISTORTIONS: Dict[str, Dict[str, Tuple[float, float]]] = {
    "Normal": {
        "traffic_rate":     (0.0, 1.0),
        "failed_logins":    (0.0, 1.0),
        "suspicious_ratio": (0.0, 1.0),
        "packet_entropy":   (0.0, 1.0),
        "ip_reputation":    (0.0, 1.0),
        "server_load":      (0.0, 1.0),
        "response_time":    (0.0, 1.0),
    },
    "DDoS": {
        "traffic_rate":     (4_500.0, 1.0),   # massive traffic spike
        "failed_logins":    (0.0,     1.0),
        "suspicious_ratio": (0.7,     1.0),
        "packet_entropy":   (-2.0,    1.0),   # repetitive flood packets → lower entropy
        "ip_reputation":    (-0.6,    1.0),
        "server_load":      (40.0,    1.0),
        "response_time":    (900.0,   1.0),
    },
    "Brute Force": {
        "traffic_rate":     (50.0,   1.0),
        "failed_logins":    (300.0,  1.0),     # hundreds of failed auth attempts
        "suspicious_ratio": (0.5,    1.0),
        "packet_entropy":   (0.0,    1.0),
        "ip_reputation":    (-0.5,   1.0),
        "server_load":      (15.0,   1.0),
        "response_time":    (30.0,   1.0),
    },
    "Data Exfiltration": {
        "traffic_rate":     (300.0,  1.0),    # unusual egress bandwidth
        "failed_logins":    (3.0,    1.0),
        "suspicious_ratio": (0.65,   1.0),
        "packet_entropy":   (2.0,    1.0),    # encrypted payloads → higher entropy
        "ip_reputation":    (-0.5,   1.0),
        "server_load":      (20.0,   1.0),
        "response_time":    (50.0,   1.0),
    },
    "Malware": {
        "traffic_rate":     (150.0,  1.0),
        "failed_logins":    (10.0,   1.0),
        "suspicious_ratio": (0.75,   1.0),
        "packet_entropy":   (1.5,    1.0),
        "ip_reputation":    (-0.55,  1.0),
        "server_load":      (30.0,   1.0),
        "response_time":    (120.0,  1.0),
    },
}

# Hard absolute bounds for clipping after distortion
_BOUNDS: Dict[str, Tuple[float, float]] = {
    "traffic_rate":     (0.0,   10_000.0),
    "failed_logins":    (0.0,    500.0),
    "suspicious_ratio": (0.0,      1.0),
    "packet_entropy":   (0.0,      8.0),
    "ip_reputation":    (0.0,      1.0),
    "server_load":      (0.0,    100.0),
    "response_time":    (1.0,  5_000.0),
}


class ThreatSimulator:
    """
    Injects one of the five attack scenarios into a baseline metrics sample.

    Parameters
    ----------
    env : NetworkEnvironment
        The underlying environment used to generate baseline samples.
    seed : int | None
        Optional random seed.
    """

    def __init__(
        self,
        env: NetworkEnvironment,
        seed: int | None = None,
    ) -> None:
        self._env = env
        self._rng = np.random.default_rng(seed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inject(self, attack_type: str) -> NetworkMetrics:
        """
        Generate a metrics snapshot for the given *attack_type*.

        Parameters
        ----------
        attack_type : str
            One of the values in :data:`config.ATTACK_TYPES`.

        Returns
        -------
        NetworkMetrics
            Distorted metrics snapshot.

        Raises
        ------
        ValueError
            If *attack_type* is not recognised.
        """
        if attack_type not in _DISTORTIONS:
            raise ValueError(
                f"Unknown attack_type '{attack_type}'. "
                f"Choose from: {list(_DISTORTIONS)}"
            )

        base = self._env.sample()
        base_dict = base.to_dict()
        distorted: Dict[str, float] = {}

        for metric, value in base_dict.items():
            shift, scale = _DISTORTIONS[attack_type][metric]
            # add small Gaussian noise on the shift to keep it realistic
            noise = float(self._rng.normal(0, abs(shift) * 0.05 + 0.1))
            new_val = value * scale + shift + noise
            lo, hi = _BOUNDS[metric]
            distorted[metric] = float(np.clip(new_val, lo, hi))

        return NetworkMetrics(**distorted)

    def inject_random(self) -> Tuple[str, NetworkMetrics]:
        """
        Choose a random attack type (weighted toward Normal) and inject it.

        Returns
        -------
        tuple[str, NetworkMetrics]
            ``(attack_type, metrics)``
        """
        weights = [0.50, 0.15, 0.15, 0.10, 0.10]  # Normal, DDoS, BF, Exfil, Malware
        attack_type = random.choices(config.ATTACK_TYPES, weights=weights, k=1)[0]
        return attack_type, self.inject(attack_type)

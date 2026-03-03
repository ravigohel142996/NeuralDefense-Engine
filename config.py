"""
config.py – Global configuration constants for SentinelAI.
"""

# ──────────────────────────────────────────────────────────────
# Simulation settings
# ──────────────────────────────────────────────────────────────
SIMULATION_INTERVAL_SEC: float = 1.0   # seconds between ticks
HISTORY_SIZE: int = 200                 # rolling window kept in memory

# ──────────────────────────────────────────────────────────────
# Network metric ranges (normal baseline)
# ──────────────────────────────────────────────────────────────
NORMAL_TRAFFIC_RATE_RANGE: tuple[float, float] = (100.0, 500.0)   # Mbps
NORMAL_FAILED_LOGINS_RANGE: tuple[float, float] = (0.0, 5.0)       # per minute
NORMAL_SUSPICIOUS_RATIO_RANGE: tuple[float, float] = (0.0, 0.05)   # fraction
NORMAL_PACKET_ENTROPY_RANGE: tuple[float, float] = (3.5, 5.5)      # bits
NORMAL_IP_REPUTATION_RANGE: tuple[float, float] = (0.7, 1.0)       # 0=bad, 1=good
NORMAL_SERVER_LOAD_RANGE: tuple[float, float] = (10.0, 60.0)       # percent CPU
NORMAL_RESPONSE_TIME_RANGE: tuple[float, float] = (5.0, 50.0)      # ms

# ──────────────────────────────────────────────────────────────
# Attack type definitions
# ──────────────────────────────────────────────────────────────
ATTACK_TYPES: list[str] = [
    "Normal",
    "DDoS",
    "Brute Force",
    "Data Exfiltration",
    "Malware",
]

# ──────────────────────────────────────────────────────────────
# Risk engine
# ──────────────────────────────────────────────────────────────
RISK_THRESHOLD: float = 45.0           # trigger defense above this
RISK_WEIGHTS: dict[str, float] = {
    "traffic_rate":      0.20,
    "failed_logins":     0.20,
    "suspicious_ratio":  0.20,
    "packet_entropy":    0.10,
    "ip_reputation":     0.15,
    "server_load":       0.10,
    "response_time":     0.05,
}

# ──────────────────────────────────────────────────────────────
# Anomaly detector
# ──────────────────────────────────────────────────────────────
ISOLATION_FOREST_CONTAMINATION: float = 0.1
ISOLATION_FOREST_N_ESTIMATORS: int = 100

# ──────────────────────────────────────────────────────────────
# Classifier
# ──────────────────────────────────────────────────────────────
RF_N_ESTIMATORS: int = 200
RF_RANDOM_STATE: int = 42
TRAINING_SAMPLES: int = 2_000          # synthetic samples for initial training

# ──────────────────────────────────────────────────────────────
# Defense
# ──────────────────────────────────────────────────────────────
DEFENSE_ACTIONS: dict[str, list[str]] = {
    "Normal":             ["No action required"],
    "DDoS":               ["Rate-limit ingress traffic", "Activate DDoS scrubbing", "Null-route offending IPs"],
    "Brute Force":        ["Block source IPs", "Enforce MFA challenge", "Throttle auth endpoint"],
    "Data Exfiltration":  ["Terminate suspicious sessions", "Block egress to untrusted IPs", "Alert data-loss prevention"],
    "Malware":            ["Quarantine affected hosts", "Isolate network segment", "Trigger IR playbook"],
}

# ──────────────────────────────────────────────────────────────
# Streamlit / UI
# ──────────────────────────────────────────────────────────────
PAGE_TITLE: str = "SentinelAI – Cyber Threat Defense"
PAGE_ICON: str = "🛡️"
REFRESH_INTERVAL_MS: int = 1_500       # autorefresh interval

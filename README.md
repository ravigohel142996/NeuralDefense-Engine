# 🛡️ SentinelAI – NeuralDefense Engine

> **AI-Powered Cyber Threat Detection & Autonomous Defense Engine**

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://streamlit.io/cloud)

---

## Overview

SentinelAI is a production-ready, fully modular cybersecurity monitoring platform that:

- **Simulates** realistic network environments with 7 live metrics
- **Injects** 5 attack scenarios (DDoS, Brute Force, Data Exfiltration, Malware, Normal)
- **Detects anomalies** using an Isolation Forest trained on normal traffic
- **Classifies threats** using a Random Forest multi-class classifier
- **Scores risk dynamically** on a 0–100 scale
- **Triggers autonomous defenses** when the risk threshold is exceeded
- **Logs** all events in a structured DataFrame
- **Visualises** everything on a real-time Streamlit dashboard

---

## Architecture

```
sentinel-ai/
├── app.py                   ← Streamlit entry point (orchestrator)
├── config.py                ← Global constants & thresholds
│
├── core/
│   ├── environment.py       ← Network metrics simulator
│   ├── threat_simulator.py  ← Attack injection layer
│   ├── anomaly_detector.py  ← Isolation Forest wrapper
│   ├── threat_classifier.py ← Random Forest classifier
│   ├── risk_engine.py       ← Dynamic risk scoring (0–100)
│   ├── defense_engine.py    ← Autonomous defense actions
│   └── logger.py            ← Structured event DataFrame logging
│
├── ui/
│   ├── dashboard.py         ← Main layout composer
│   ├── charts.py            ← Plotly chart components
│   └── controls.py          ← Sidebar controls
│
├── requirements.txt
├── README.md
└── .streamlit/
    └── config.toml          ← Dark cyber theme
```

---

## Simulated Network Metrics

| Metric             | Description                           | Normal Range          |
|--------------------|---------------------------------------|-----------------------|
| `traffic_rate`     | Ingress/egress bandwidth (Mbps)       | 100 – 500 Mbps        |
| `failed_logins`    | Failed authentication attempts/min    | 0 – 5 /min            |
| `suspicious_ratio` | Fraction of flagged packets           | 0 – 5 %               |
| `packet_entropy`   | Shannon entropy of packet payloads    | 3.5 – 5.5 bits        |
| `ip_reputation`    | Trust score of source IPs             | 0.7 – 1.0             |
| `server_load`      | Average CPU utilisation               | 10 – 60 %             |
| `response_time`    | Average response latency              | 5 – 50 ms             |

---

## Attack Scenarios

| Attack Type        | Key Indicators                                            |
|--------------------|-----------------------------------------------------------|
| **Normal**         | All metrics within baseline ranges                        |
| **DDoS**           | Massive traffic spike, high server load, slow responses   |
| **Brute Force**    | Hundreds of failed logins, suspicious IP reputation       |
| **Data Exfilt.**   | Elevated egress bandwidth, high packet entropy            |
| **Malware**        | High suspicious ratio, low IP reputation, C2 patterns     |

---

## ML Pipeline

```
NetworkMetrics → [Isolation Forest] → anomaly flag + score
                  ↓
             [Random Forest] → predicted attack + class probabilities
                  ↓
              [Risk Engine]  → risk score (0–100)
                  ↓
           [Defense Engine]  → countermeasures (if risk > threshold)
                  ↓
            [Event Logger]   → structured DataFrame
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the dashboard
streamlit run app.py
```

---

## Deploy on Streamlit Cloud

1. Fork / push this repo to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io) → **New app**.
3. Select this repo, branch `main`, file `app.py`.
4. Click **Deploy** – models train automatically on first boot (~5 s).

---

## Configuration

All thresholds and hyper-parameters are centralised in `config.py`:

| Parameter                        | Default | Description                          |
|----------------------------------|---------|--------------------------------------|
| `RISK_THRESHOLD`                 | 60      | Defense trigger level                |
| `ISOLATION_FOREST_CONTAMINATION` | 0.1     | Expected anomaly fraction            |
| `RF_N_ESTIMATORS`                | 200     | Random Forest trees                  |
| `TRAINING_SAMPLES`               | 2 000   | Synthetic samples for initial train  |
| `HISTORY_SIZE`                   | 200     | Rolling event window                 |
| `REFRESH_INTERVAL_MS`            | 1 500   | Dashboard auto-refresh (ms)          |

---

## License

MIT © 2024 NeuralDefense-Engine contributors

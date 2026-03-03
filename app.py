"""
app.py – SentinelAI Streamlit entry point.

Orchestrates all layers: environment → threat simulator → anomaly
detector → threat classifier → risk engine → defense engine → logger
→ UI dashboard.

Run with:
    streamlit run app.py
"""

from __future__ import annotations

import time

import streamlit as st
from streamlit_autorefresh import st_autorefresh

import config
from core.anomaly_detector import AnomalyDetector
from core.defense_engine import DefenseEngine
from core.environment import NetworkEnvironment
from core.logger import EventLogger
from core.risk_engine import RiskEngine
from core.threat_classifier import ThreatClassifier
from core.threat_simulator import ThreatSimulator
from ui import controls, dashboard

# ──────────────────────────────────────────────────────────────────────────────
# Page configuration
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title=config.PAGE_TITLE,
    page_icon=config.PAGE_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject custom CSS for dark cyber theme
st.markdown(
    """
    <style>
    /* Dark background */
    .stApp { background-color: #0d1117; color: #e0e0e0; }
    /* Metric cards */
    [data-testid="metric-container"] {
        background: #161b22;
        border: 1px solid #21262d;
        border-radius: 8px;
        padding: 12px;
    }
    /* Sidebar */
    [data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #21262d; }
    /* Header divider */
    hr { border-color: #21262d; }
    /* Dataframe */
    .stDataFrame { background: #161b22; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ──────────────────────────────────────────────────────────────────────────────
# Session-state initialisation (runs once per browser session)
# ──────────────────────────────────────────────────────────────────────────────

@st.cache_resource(show_spinner="🧠 Training AI models … this takes a few seconds")
def _build_models() -> tuple[AnomalyDetector, ThreatClassifier]:
    """Train both ML models once and cache them across reruns."""
    env = NetworkEnvironment(seed=config.RF_RANDOM_STATE)
    ad = AnomalyDetector(seed=config.RF_RANDOM_STATE)
    ad.fit(env)
    tc = ThreatClassifier(seed=config.RF_RANDOM_STATE)
    tc.fit(env=env)
    return ad, tc


def _init_session() -> None:
    """Initialise mutable session-state objects."""
    if "env" not in st.session_state:
        st.session_state.env = NetworkEnvironment()
    if "simulator" not in st.session_state:
        st.session_state.simulator = ThreatSimulator(st.session_state.env)
    if "risk_engine" not in st.session_state:
        st.session_state.risk_engine = RiskEngine(threshold=config.RISK_THRESHOLD)
    if "defense_engine" not in st.session_state:
        st.session_state.defense_engine = DefenseEngine()
    if "logger" not in st.session_state:
        st.session_state.logger = EventLogger()
    if "running" not in st.session_state:
        st.session_state.running = True
    if "risk_threshold" not in st.session_state:
        st.session_state.risk_threshold = config.RISK_THRESHOLD


# ──────────────────────────────────────────────────────────────────────────────
# One simulation tick
# ──────────────────────────────────────────────────────────────────────────────

def _run_tick(
    attack_mode: str,
    risk_threshold: float,
    anomaly_detector: AnomalyDetector,
    threat_classifier: ThreatClassifier,
) -> None:
    """Execute one detection cycle and persist results to session state."""
    sim: ThreatSimulator = st.session_state.simulator
    re: RiskEngine = st.session_state.risk_engine
    de: DefenseEngine = st.session_state.defense_engine
    log: EventLogger = st.session_state.logger

    # Update threshold if user changed it
    re.threshold = risk_threshold

    # 1. Sample metrics
    if attack_mode == "Auto (random)":
        _, metrics = sim.inject_random()
    else:
        metrics = sim.inject(attack_mode)

    # 2. Anomaly detection
    is_anomaly = anomaly_detector.predict(metrics)
    anomaly_score = anomaly_detector.anomaly_score(metrics)

    # 3. Threat classification
    predicted_attack = threat_classifier.predict(metrics)
    class_probs = threat_classifier.predict_proba(metrics)

    # 4. Risk scoring
    report = re.compute(metrics, anomaly_score, predicted_attack, class_probs)

    # 5. Defense
    defense_action = de.evaluate(report)

    # 6. Log
    log.log(metrics, is_anomaly, anomaly_score, report, defense_action)

    # Persist report for UI
    st.session_state.last_report = report


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    _init_session()

    # Load (or retrieve from cache) trained models
    anomaly_detector, threat_classifier = _build_models()

    # Sidebar controls
    ctrl = controls.render_sidebar()

    # Handle reset
    if ctrl["reset"]:
        st.session_state.logger.clear()
        st.session_state.defense_engine.clear_history()
        st.session_state.last_report = None
        st.toast("Simulation reset.", icon="🔄")

    # Auto-refresh when running
    if ctrl["running"]:
        st_autorefresh(interval=config.REFRESH_INTERVAL_MS, key="autorefresh")
        _run_tick(
            attack_mode=ctrl["attack_mode"],
            risk_threshold=ctrl["risk_threshold"],
            anomaly_detector=anomaly_detector,
            threat_classifier=threat_classifier,
        )

    # ── Fetch current state for rendering ────────────────────────────
    log: EventLogger = st.session_state.logger
    df = log.dataframe
    summary = log.threat_summary()
    latest = log.latest
    report = st.session_state.get("last_report", None)
    importances = (
        threat_classifier.feature_importances() if threat_classifier.is_fitted else {}
    )

    # ── Render UI ────────────────────────────────────────────────────
    dashboard.render_header(report)
    st.divider()

    dashboard.render_metric_tiles(latest)
    st.divider()

    dashboard.render_risk_section(report, df)
    st.divider()

    dashboard.render_defense_panel(report)
    st.divider()

    dashboard.render_charts_section(df, summary, importances)
    st.divider()

    dashboard.render_event_log(df)


if __name__ == "__main__":
    main()

"""
ui/controls.py – Sidebar controls for the SentinelAI dashboard.
"""

from __future__ import annotations

from typing import Any, Dict

import streamlit as st

import config


def render_sidebar() -> Dict[str, Any]:
    """
    Render the left sidebar with simulation and configuration controls.

    Returns
    -------
    dict[str, Any]
        Dictionary of control values keyed by name:

        * ``running``        – bool, whether simulation is active
        * ``attack_mode``    – str, selected attack type (or "Auto")
        * ``risk_threshold`` – float, configurable risk threshold
        * ``reset``          – bool, whether reset was clicked
    """
    with st.sidebar:
        st.image(
            "https://img.icons8.com/nolan/96/shield.png",
            width=72,
        )
        st.title("SentinelAI")
        st.caption("AI-Powered Cyber Threat Detection & Autonomous Defense Engine")
        st.divider()

        # ── Simulation controls ──────────────────────────────────────
        st.subheader("⚙️ Simulation Controls")

        running = st.toggle(
            "▶ Run Simulation",
            value=st.session_state.get("running", True),
            key="running",
        )

        attack_mode = st.selectbox(
            "Inject Attack Type",
            options=["Auto (random)", *config.ATTACK_TYPES],
            index=0,
            help="Choose 'Auto' to let the simulator pick randomly, or "
                 "select a specific attack to simulate continuously.",
        )

        st.divider()

        # ── Risk threshold ──────────────────────────────────────────
        st.subheader("🎚️ Risk Threshold")
        risk_threshold = st.slider(
            "Defense trigger threshold",
            min_value=10,
            max_value=95,
            value=int(st.session_state.get("risk_threshold", config.RISK_THRESHOLD)),
            step=5,
            help="Autonomous defenses activate when risk score exceeds this value.",
            key="risk_threshold",
        )

        st.divider()

        # ── Reset ────────────────────────────────────────────────────
        reset = st.button("🔄 Reset Simulation", use_container_width=True)

        st.divider()

        # ── Info ─────────────────────────────────────────────────────
        st.subheader("ℹ️ About")
        st.markdown(
            """
            **SentinelAI** uses:
            - 🌲 **Isolation Forest** for anomaly detection
            - 🌳 **Random Forest** for attack classification
            - ⚡ Dynamic risk scoring (0–100)
            - 🛡️ Autonomous defense playbooks
            """
        )

    return {
        "running": running,
        "attack_mode": attack_mode,
        "risk_threshold": float(risk_threshold),
        "reset": reset,
    }

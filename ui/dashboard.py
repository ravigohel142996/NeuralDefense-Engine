"""
ui/dashboard.py – Main Streamlit dashboard layout for SentinelAI.

Composes the header, metric tiles, charts, and event log table into a
cohesive dark-themed dashboard.
"""

from __future__ import annotations

from typing import Any, Dict

import pandas as pd
import streamlit as st

import config
from core.risk_engine import RiskReport
from ui import charts


# ──────────────────────────────────────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────────────────────────────────────

def render_header(report: RiskReport | None = None) -> None:
    """Render the top-of-page title and live status banner."""
    col_title, col_status = st.columns([3, 1])

    with col_title:
        st.markdown(
            "## 🛡️ SentinelAI — Cyber Threat Detection & Defense Engine"
        )

    with col_status:
        if report is not None:
            colour = report.risk_colour
            level = report.risk_level
            threat_label = (
                f"<span style='color:{colour};font-weight:700;font-size:1.1rem'>"
                f"⚠ {level}</span>"
                if report.is_threat
                else f"<span style='color:#00c853;font-weight:700;font-size:1.1rem'>"
                     f"✅ NORMAL</span>"
            )
            st.markdown(threat_label, unsafe_allow_html=True)
            st.caption(f"Attack: **{report.predicted_attack}**")


# ──────────────────────────────────────────────────────────────────────────────
# Metric KPI tiles
# ──────────────────────────────────────────────────────────────────────────────

def render_metric_tiles(latest: Dict[str, Any] | None) -> None:
    """Render seven KPI metric cards from the latest event row."""
    if latest is None:
        st.info("Waiting for first data point …")
        return

    metrics = [
        ("📶 Traffic Rate",      latest.get("traffic_rate",     0.0), "Mbps"),
        ("🔐 Failed Logins",     latest.get("failed_logins",    0.0), "/min"),
        ("🕵️ Suspicious Ratio",  latest.get("suspicious_ratio", 0.0), ""),
        ("🔀 Packet Entropy",    latest.get("packet_entropy",   0.0), "bits"),
        ("🌐 IP Reputation",     latest.get("ip_reputation",    0.0), ""),
        ("💻 Server Load",       latest.get("server_load",      0.0), "%"),
        ("⏱ Response Time",     latest.get("response_time",    0.0), "ms"),
    ]

    cols = st.columns(len(metrics))
    for col, (label, value, unit) in zip(cols, metrics):
        with col:
            display_val = f"{value:.2f}{unit}" if unit else f"{value:.3f}"
            st.metric(label=label, value=display_val)


# ──────────────────────────────────────────────────────────────────────────────
# Risk gauge + recent threat table
# ──────────────────────────────────────────────────────────────────────────────

def render_risk_section(report: RiskReport | None, df: pd.DataFrame) -> None:
    """Render the risk gauge and recent threats table side by side."""
    col_gauge, col_table = st.columns([1, 2])

    with col_gauge:
        if report is not None:
            st.plotly_chart(
                charts.risk_gauge(report.risk_score, report.risk_level),
                use_container_width=True,
            )
        else:
            st.plotly_chart(charts.risk_gauge(0.0, "LOW"), use_container_width=True)

    with col_table:
        st.markdown("#### 🚨 Recent Threat Events")
        if df.empty:
            st.caption("No threats detected yet.")
        else:
            recent = df[df["is_threat"]].tail(8)[
                ["timestamp", "predicted_attack", "risk_score", "risk_level", "defense_actions"]
            ]
            if recent.empty:
                st.caption("No threats in current window.")
            else:
                st.dataframe(
                    recent.sort_values("timestamp", ascending=False),
                    use_container_width=True,
                    hide_index=True,
                )


# ──────────────────────────────────────────────────────────────────────────────
# Charts section
# ──────────────────────────────────────────────────────────────────────────────

def render_charts_section(
    df: pd.DataFrame,
    summary: pd.DataFrame,
    importances: Dict[str, float],
) -> None:
    """Render the main chart grid."""
    col_risk, col_donut = st.columns([2, 1])

    with col_risk:
        st.plotly_chart(
            charts.risk_history_chart(df),
            use_container_width=True,
        )
    with col_donut:
        st.plotly_chart(
            charts.attack_distribution_donut(summary),
            use_container_width=True,
        )

    col_metrics, col_anomaly = st.columns(2)

    with col_metrics:
        st.plotly_chart(
            charts.metrics_sparklines(df),
            use_container_width=True,
        )
    with col_anomaly:
        st.plotly_chart(
            charts.anomaly_score_chart(df),
            use_container_width=True,
        )

    st.plotly_chart(
        charts.feature_importance_chart(importances),
        use_container_width=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Defense actions panel
# ──────────────────────────────────────────────────────────────────────────────

def render_defense_panel(report: RiskReport | None) -> None:
    """Show the active defense playbook for the current threat."""
    st.markdown("#### 🛡️ Active Defense Playbook")
    if report is None or not report.is_threat:
        st.success("✅ No active threat. All systems nominal.")
        return

    actions = config.DEFENSE_ACTIONS.get(
        report.predicted_attack,
        config.DEFENSE_ACTIONS["Normal"],
    )
    st.warning(
        f"**{report.predicted_attack}** detected at risk score "
        f"**{report.risk_score:.1f}** — executing countermeasures:"
    )
    for action in actions:
        st.markdown(f"- 🔴 {action}")


# ──────────────────────────────────────────────────────────────────────────────
# Full event log
# ──────────────────────────────────────────────────────────────────────────────

def render_event_log(df: pd.DataFrame) -> None:
    """Render the scrollable full event log."""
    with st.expander("📋 Full Event Log", expanded=False):
        if df.empty:
            st.caption("No events logged yet.")
        else:
            st.dataframe(
                df.sort_values("timestamp", ascending=False).reset_index(drop=True),
                use_container_width=True,
            )

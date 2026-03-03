"""
ui/charts.py – Reusable Plotly chart components for SentinelAI dashboard.
"""

from __future__ import annotations

from typing import Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import config


# ──────────────────────────────────────────────────────────────────────────────
# Colour palette
# ──────────────────────────────────────────────────────────────────────────────
_ATTACK_COLOURS: Dict[str, str] = {
    "Normal":             "#00c853",
    "DDoS":               "#d50000",
    "Brute Force":        "#ff6d00",
    "Data Exfiltration":  "#aa00ff",
    "Malware":            "#0091ea",
}

_METRIC_COLOURS: List[str] = [
    "#00b0ff", "#00e5ff", "#69ff47", "#ffea00", "#ff9100", "#ff1744", "#d500f9"
]


# ──────────────────────────────────────────────────────────────────────────────
# Risk gauge
# ──────────────────────────────────────────────────────────────────────────────

def risk_gauge(risk_score: float, risk_level: str) -> go.Figure:
    """
    Render an animated gauge showing the current risk score.

    Parameters
    ----------
    risk_score : float
        Value in [0, 100].
    risk_level : str
        ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, or ``"CRITICAL"``.

    Returns
    -------
    plotly.graph_objects.Figure
    """
    colour_map = {
        "LOW":      "#00c853",
        "MEDIUM":   "#ffd600",
        "HIGH":     "#ff6d00",
        "CRITICAL": "#d50000",
    }
    bar_colour = colour_map.get(risk_level, "#00c853")

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=risk_score,
            title={"text": f"Risk Score – <b>{risk_level}</b>", "font": {"size": 18}},
            delta={"reference": config.RISK_THRESHOLD, "increasing": {"color": "#d50000"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar":  {"color": bar_colour},
                "steps": [
                    {"range": [0,  25], "color": "#1b2838"},
                    {"range": [25, 50], "color": "#1f3340"},
                    {"range": [50, 75], "color": "#2a2a2a"},
                    {"range": [75, 100], "color": "#3a1a1a"},
                ],
                "threshold": {
                    "line":  {"color": "#ffffff", "width": 3},
                    "thickness": 0.8,
                    "value": config.RISK_THRESHOLD,
                },
            },
            number={"suffix": " / 100", "font": {"size": 30}},
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e0e0e0",
        margin={"t": 60, "b": 10, "l": 10, "r": 10},
        height=260,
    )
    return fig


# ──────────────────────────────────────────────────────────────────────────────
# Risk history line chart
# ──────────────────────────────────────────────────────────────────────────────

def risk_history_chart(df: pd.DataFrame) -> go.Figure:
    """
    Line chart of risk score over time, colour-coded by risk level.

    Parameters
    ----------
    df : pandas.DataFrame
        Event log from :class:`~core.logger.EventLogger`.

    Returns
    -------
    plotly.graph_objects.Figure
    """
    if df.empty:
        return _empty_figure("No data yet")

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"],
            y=df["risk_score"],
            mode="lines",
            line={"color": "#00b0ff", "width": 2},
            fill="tozeroy",
            fillcolor="rgba(0,176,255,0.1)",
            name="Risk Score",
        )
    )
    # Threshold line
    fig.add_hline(
        y=config.RISK_THRESHOLD,
        line_dash="dash",
        line_color="#ff6d00",
        annotation_text=f"Threshold ({config.RISK_THRESHOLD})",
        annotation_font_color="#ff6d00",
    )
    fig.update_layout(**_dark_layout("Risk Score Over Time", "Time", "Risk Score (0–100)"))
    return fig


# ──────────────────────────────────────────────────────────────────────────────
# Metric sparklines
# ──────────────────────────────────────────────────────────────────────────────

def metrics_sparklines(df: pd.DataFrame) -> go.Figure:
    """
    Multi-line chart showing all seven network metrics over time.

    Parameters
    ----------
    df : pandas.DataFrame

    Returns
    -------
    plotly.graph_objects.Figure
    """
    if df.empty:
        return _empty_figure("No data yet")

    metric_cols = [
        "traffic_rate", "failed_logins", "suspicious_ratio",
        "packet_entropy", "ip_reputation", "server_load", "response_time",
    ]

    fig = go.Figure()
    for i, col in enumerate(metric_cols):
        if col in df.columns:
            # Normalise to [0, 1] for comparable display
            series = df[col]
            rng = series.max() - series.min()
            normalised = (series - series.min()) / (rng if rng > 0 else 1)
            fig.add_trace(
                go.Scatter(
                    x=df["timestamp"],
                    y=normalised,
                    mode="lines",
                    name=col.replace("_", " ").title(),
                    line={"color": _METRIC_COLOURS[i % len(_METRIC_COLOURS)], "width": 1.5},
                )
            )

    fig.update_layout(
        **_dark_layout("Network Metrics (normalised)", "Time", "Normalised Value")
    )
    return fig


# ──────────────────────────────────────────────────────────────────────────────
# Attack distribution donut
# ──────────────────────────────────────────────────────────────────────────────

def attack_distribution_donut(summary: pd.DataFrame) -> go.Figure:
    """
    Donut chart of observed attack type distribution.

    Parameters
    ----------
    summary : pandas.DataFrame
        Output of :meth:`~core.logger.EventLogger.threat_summary`.

    Returns
    -------
    plotly.graph_objects.Figure
    """
    if summary.empty:
        return _empty_figure("No data yet")

    colours = [
        _ATTACK_COLOURS.get(at, "#90a4ae")
        for at in summary["attack_type"]
    ]

    fig = go.Figure(
        go.Pie(
            labels=summary["attack_type"],
            values=summary["count"],
            hole=0.55,
            marker={"colors": colours, "line": {"color": "#0d1117", "width": 2}},
            textfont={"size": 13},
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e0e0e0",
        title={"text": "Attack Type Distribution", "font": {"size": 16}},
        legend={"orientation": "h"},
        margin={"t": 50, "b": 10, "l": 10, "r": 10},
        height=300,
    )
    return fig


# ──────────────────────────────────────────────────────────────────────────────
# Feature importance bar chart
# ──────────────────────────────────────────────────────────────────────────────

def feature_importance_chart(importances: Dict[str, float]) -> go.Figure:
    """
    Horizontal bar chart of Random Forest feature importances.

    Parameters
    ----------
    importances : dict[str, float]

    Returns
    -------
    plotly.graph_objects.Figure
    """
    if not importances:
        return _empty_figure("Model not trained yet")

    sorted_items = sorted(importances.items(), key=lambda x: x[1])
    labels = [k.replace("_", " ").title() for k, _ in sorted_items]
    values = [v for _, v in sorted_items]

    fig = go.Figure(
        go.Bar(
            x=values,
            y=labels,
            orientation="h",
            marker={"color": values, "colorscale": "Teal"},
        )
    )
    fig.update_layout(
        **_dark_layout("Feature Importances (Random Forest)", "Importance", "Feature")
    )
    return fig


# ──────────────────────────────────────────────────────────────────────────────
# Anomaly score over time
# ──────────────────────────────────────────────────────────────────────────────

def anomaly_score_chart(df: pd.DataFrame) -> go.Figure:
    """
    Area chart of anomaly scores over time with anomaly flags highlighted.

    Parameters
    ----------
    df : pandas.DataFrame

    Returns
    -------
    plotly.graph_objects.Figure
    """
    if df.empty:
        return _empty_figure("No data yet")

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["timestamp"],
            y=df["anomaly_score"],
            mode="lines",
            line={"color": "#aa00ff", "width": 2},
            fill="tozeroy",
            fillcolor="rgba(170,0,255,0.1)",
            name="Anomaly Score",
        )
    )

    # Mark anomalies
    anomalies = df[df["is_anomaly"]]
    if not anomalies.empty:
        fig.add_trace(
            go.Scatter(
                x=anomalies["timestamp"],
                y=anomalies["anomaly_score"],
                mode="markers",
                marker={"color": "#ff1744", "size": 8, "symbol": "x"},
                name="Anomaly Detected",
            )
        )

    fig.update_layout(
        **_dark_layout("Anomaly Scores Over Time", "Time", "Score [0–1]")
    )
    return fig


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _empty_figure(message: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 18, "color": "#90a4ae"},
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis={"visible": False},
        yaxis={"visible": False},
        height=250,
    )
    return fig


def _dark_layout(title: str, xlabel: str, ylabel: str) -> dict:
    return {
        "title":           {"text": title, "font": {"size": 16}},
        "xaxis_title":     xlabel,
        "yaxis_title":     ylabel,
        "paper_bgcolor":   "rgba(0,0,0,0)",
        "plot_bgcolor":    "rgba(17,21,28,0.6)",
        "font_color":      "#e0e0e0",
        "xaxis":           {"gridcolor": "#1e2a35", "showgrid": True},
        "yaxis":           {"gridcolor": "#1e2a35", "showgrid": True},
        "legend":          {"bgcolor": "rgba(0,0,0,0)"},
        "margin":          {"t": 50, "b": 40, "l": 60, "r": 20},
        "height":          300,
    }

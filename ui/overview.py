"""
overview.py — Minimal, Clean, and Professional Investigation Dashboard.

Shows:
- Current capture status and source (interface or loaded PCAP file)
- 4 primary telemetry metrics: Total Packets, Observed Bytes, Unique IPs, Active TCP Sessions
- Protocol distribution donut chart
- Traffic arrival timeline over relative seconds
- Clean welcome screen with two primary actions (Start Live Capture, Open PCAP) and Guided Help link
"""

from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import tempfile
import os

from core.protocol_analyzer import analyze_protocols, analyze_top_ips, analyze_traffic_timeline
from core.flow_analyzer import analyze_all_flows
from core.pcap_manager import load_pcap, packets_to_dataframe
from config.settings import PROTOCOL_COLORS
from utils.helpers import format_bytes
from ui.guided_lab import render_contextual_help


def _navigate(page: str):
    """Safely navigate to another workspace, synchronizing sidebar and top-nav."""
    st.session_state["current_page"] = page
    st.session_state["sidebar_workspace_radio"] = page
    st.rerun()


def _apply_dashboard_plotly_layout(fig, height=270):
    """Apply unified clean light styling to Dashboard Plotly figures."""
    fig.update_layout(
        height=height,
        margin=dict(l=14, r=14, t=28, b=14),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        font=dict(family="JetBrains Mono, monospace", size=10, color="#263238"),
        xaxis=dict(
            showgrid=True, gridcolor="#F0F2F5", zeroline=False,
            color="#718096", tickfont=dict(size=10, color="#718096")
        ),
        yaxis=dict(
            showgrid=True, gridcolor="#F0F2F5", zeroline=False,
            color="#718096", tickfont=dict(size=10, color="#718096")
        ),
        legend=dict(
            orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5,
            font=dict(size=10, color="#718096")
        )
    )
    return fig


def render_overview_page():
    """Render the streamlined investigation Dashboard."""
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #E5E9EF; padding-bottom: 10px; margin-bottom: 14px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.1em; text-transform: uppercase;">
                    // EXECUTIVE OVERVIEW // INVESTIGATION DASHBOARD
                </div>
                <div style="font-size: 1.35rem; font-weight: 700; color: #263238; letter-spacing: -0.02em;">
                    Dashboard
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-teal">TELEMETRY</span>
                <span class="soc-badge soc-badge-green">REAL DATA</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    parsed_packets = st.session_state.get("parsed_packets", [])
    raw_packets = st.session_state.get("raw_packets") or st.session_state.get("packets", [])
    is_capturing = st.session_state.get("capture_running", False)
    loaded_source = st.session_state.get("loaded_file") or ("Live Interface" if is_capturing else "None")

    # -----------------------------------------------------------------------
    # Status Banner (Always Visible)
    # -----------------------------------------------------------------------
    status_tag = '<span class="status-badge badge-active">● CAPTURING</span>' if is_capturing else '<span class="status-badge badge-inactive">○ IDLE</span>'
    st.markdown(
        f"""
        <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 6px; padding: 10px 16px; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #718096;">
                CAPTURE STATUS: {status_tag} &nbsp;|&nbsp; SOURCE: <b style="color: #159A91;">{loaded_source}</b>
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #718096;">
                BUFFER: <b style="color: #263238;">{len(parsed_packets):,}</b> FRAMES
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # -----------------------------------------------------------------------
    # Empty State (When no packets in buffer)
    # -----------------------------------------------------------------------
    if not parsed_packets:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px dashed #CBD5E1; border-radius: 8px; padding: 36px 24px; text-align: center; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <div style="font-size: 2.2rem; margin-bottom: 8px;">📊</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #263238; margin-bottom: 6px;">
                    Welcome to Network Forensics Analyzer
                </div>
                <div style="font-size: 0.86rem; color: #718096; max-width: 520px; margin: 0 auto 20px auto; line-height: 1.5;">
                    No capture session is active. Choose an action below to start capturing live network traffic or inspect a pre-recorded PCAP file.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        act1, act2 = st.columns(2)
        with act1:
            st.markdown(
                """
                <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 3px solid #159A91; border-radius: 6px; padding: 16px; min-height: 170px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                    <div style="font-family: JetBrains Mono; font-size: 0.85rem; font-weight: 700; color: #159A91; margin-bottom: 4px;">
                        OPTION 1: LIVE PACKET CAPTURE
                    </div>
                    <div style="font-size: 0.8rem; color: #718096; margin-bottom: 14px; line-height: 1.4;">
                        Sniff real-time traffic from your active Wi-Fi or Ethernet network adapter.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("▶ Open Live Capture Console", key="dash_goto_live_btn", type="primary", use_container_width=True):
                _navigate("📡 Live Capture")

        with act2:
            st.markdown(
                """
                <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 3px solid #0D9488; border-radius: 6px; padding: 16px; min-height: 170px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                    <div style="font-family: JetBrains Mono; font-size: 0.85rem; font-weight: 700; color: #0D9488; margin-bottom: 4px;">
                        OPTION 2: OPEN PCAP FILE
                    </div>
                    <div style="font-size: 0.8rem; color: #718096; margin-bottom: 14px; line-height: 1.4;">
                        Instantly load pre-recorded enterprise baseline traffic or upload a file.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("⚡ Load Benchmark PCAP (21 Frames)", key="dash_load_base_btn", use_container_width=True):
                raw, parsed, err = load_pcap("sample_captures/sample_traffic.pcap")
                if not err:
                    st.session_state["packets"] = raw
                    st.session_state["raw_packets"] = raw
                    st.session_state["parsed_packets"] = parsed
                    st.session_state["loaded_file"] = "sample_traffic.pcap [BASELINE]"
                    st.session_state["selected_packet_idx"] = 0
                    st.session_state["is_synthetic"] = True
                    st.rerun()

        # Quick navigation helpers
        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div style="text-align: center; font-size: 0.82rem; color: #718096;">
                New to packet analysis? Explore step-by-step networking activities in the 
            </div>
            """,
            unsafe_allow_html=True
        )
        _, link_col, _ = st.columns([1.5, 2, 1.5])
        with link_col:
            if st.button("🎓 Open Guided Labs for Beginners", key="dash_goto_help_link", use_container_width=True):
                _navigate("🎓 Guided Labs")
        return

    # -----------------------------------------------------------------------
    # Active Capture Telemetry
    # -----------------------------------------------------------------------
    df = packets_to_dataframe(parsed_packets)
    proto_stats = analyze_protocols(df)
    ip_stats = analyze_top_ips(df, top_n=8)
    flows = analyze_all_flows(parsed_packets)

    total_bytes = df["length"].sum() if "length" in df.columns else 0
    unique_ips = len(ip_stats.get("top_endpoints", {}))
    tcp_sessions = len([f for f in flows if "TCP" in f.get("protocol", "") or f.get("src_port") is not None])

    # Minimal Metrics Chips
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Total Packets", f"{len(df):,} PKTS")
    with m2: st.metric("Observed Volume", format_bytes(total_bytes))
    with m3: st.metric("Unique Endpoints", f"{unique_ips} IPS")
    with m4: st.metric("TCP Sessions", f"{tcp_sessions} FLOWS")

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Telemetry Charts (Protocol Donut & Arrival Timeline)
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>PROTOCOL COMPOSITION</span>", unsafe_allow_html=True)
        counts = proto_stats.get("counts", {})
        if counts:
            fig_p = go.Figure(data=[go.Pie(
                labels=list(counts.keys()),
                values=list(counts.values()),
                hole=0.55,
                marker=dict(
                    colors=[PROTOCOL_COLORS.get(p, "#718096") for p in counts.keys()],
                    line=dict(color="#FFFFFF", width=2)
                ),
                textinfo="label+percent",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#263238")
            )])
            _apply_dashboard_plotly_layout(fig_p, height=270)
            st.plotly_chart(fig_p, use_container_width=True)
        else:
            st.caption("No protocol data available.")

    with c2:
        st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>TRAFFIC OVER TIME</span>", unsafe_allow_html=True)
        timeline_df = analyze_traffic_timeline(df, bins=25)
        if not timeline_df.empty and "bin_mid" in timeline_df.columns:
            fig_t = go.Figure()
            fig_t.add_trace(go.Bar(
                x=timeline_df["bin_mid"],
                y=timeline_df["byte_volume"],
                name="Volume",
                marker_color="#159A91",
                opacity=0.85
            ))
            fig_t.update_layout(xaxis_title="Relative Elapsed (s)", yaxis_title="Bytes")
            _apply_dashboard_plotly_layout(fig_t, height=270)
            st.plotly_chart(fig_t, use_container_width=True)
        else:
            st.caption("Insufficient timestamp spread for timeline calculation.")

    # Workspace Navigation Shortcut
    st.divider()
    nav1, nav2 = st.columns(2)
    with nav1:
        if st.button("📡 Open Live Packet Capture & Ingestion", key="dash_goto_analysis_btn", use_container_width=True, type="primary"):
            _navigate("📡 Live Capture")
    with nav2:
        if st.button("🔗 Open TCP Connections Explorer", key="dash_goto_conn_btn", use_container_width=True):
            _navigate("🔗 TCP Connections")

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    render_contextual_help("overview")

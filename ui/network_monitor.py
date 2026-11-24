"""
network_monitor.py — Consolidated Network Monitor & Telemetry Dashboard.

Combines:
- Host Device & Interface Diagnostics (Hardware adapters, IP/MAC bindings, Gateway, MTU)
- Deep Protocol & Traffic Telemetry (Protocol distribution, timeline, talkers/listeners,
  IANA service ports, TCP flags, DNS query stats, and retransmission analysis).
"""

from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sys
from typing import Dict, Any, List

from core.pcap_manager import packets_to_dataframe, load_pcap
from core.protocol_analyzer import (
    analyze_protocols, analyze_top_ips, analyze_top_ports,
    analyze_tcp_flags, analyze_dns_queries, analyze_traffic_timeline
)
from core.flow_analyzer import analyze_all_flows
from core.capture import get_available_interfaces
from config.settings import PROTOCOL_COLORS
from utils.helpers import format_bytes, format_duration
from ui.guided_lab import render_contextual_help

PORT_SERVICE_MAP = {
    "20": "FTP-Data", "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
    "53": "DNS", "67": "DHCP", "68": "DHCP", "80": "HTTP", "110": "POP3",
    "123": "NTP", "143": "IMAP", "161": "SNMP", "443": "HTTPS", "445": "SMB",
    "993": "IMAPS", "995": "POP3S", "3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL",
    "8080": "HTTP-Alt", "8443": "HTTPS-Alt"
}

TCP_FLAG_COLORS = {
    "SYN": "#159A91",
    "ACK": "#059669",
    "FIN": "#D97706",
    "RST": "#DC2626",
    "PSH": "#8B83C8",
    "URG": "#E11D48",
}


def _apply_light_plotly_layout(fig, height=280):
    """Apply consistent light aesthetic to Plotly figures."""
    fig.update_layout(
        height=height,
        margin=dict(l=15, r=15, t=28, b=15),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        font=dict(family="JetBrains Mono, monospace", size=11, color="#718096"),
        xaxis=dict(
            gridcolor="#F0F2F5",
            zerolinecolor="#E5E9EF",
            tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#718096"),
        ),
        yaxis=dict(
            gridcolor="#F0F2F5",
            zerolinecolor="#E5E9EF",
            tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#718096"),
        ),
        hoverlabel=dict(
            bgcolor="#FFFFFF",
            bordercolor="#159A91",
            font=dict(family="JetBrains Mono, monospace", size=11, color="#263238")
        )
    )
    return fig


def render_network_monitor_page():
    """Render the consolidated Network Monitor & Telemetry workspace."""
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #E5E9EF; padding-bottom: 10px; margin-bottom: 14px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.1em; text-transform: uppercase;">
                    // HOST DIAGNOSTICS & TELEMETRY // L2–L7 MONITORING
                </div>
                <div style="font-size: 1.35rem; font-weight: 700; color: #263238; letter-spacing: -0.02em;">
                    Network Monitor
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-teal">DEVICE DIAGNOSTICS</span>
                <span class="soc-badge soc-badge-green">AGGREGATE TELEMETRY</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    mon_tab_traffic, mon_tab_device = st.tabs([
        "📊 TRAFFIC & PROTOCOL TELEMETRY", "💻 HOST INTERFACES & ADAPTERS"
    ])

    parsed_packets = st.session_state.get("parsed_packets", [])

    # -----------------------------------------------------------------------
    # TAB 1: Traffic & Protocol Telemetry
    # -----------------------------------------------------------------------
    with mon_tab_traffic:
        if not parsed_packets:
            st.markdown(
                """
                <div style="background: #FFFFFF; border: 1px dashed #CBD5E1; border-radius: 8px; padding: 40px; text-align: center; margin-top: 10px;">
                    <div style="font-size: 2rem; margin-bottom: 8px;">📊</div>
                    <div style="font-size: 1.1rem; font-weight: 600; color: #263238; margin-bottom: 6px;">No Capture Traffic Loaded for Telemetry</div>
                    <div style="font-size: 0.85rem; color: #718096; max-width: 480px; margin: 0 auto 16px auto; line-height: 1.5;">
                        Load a PCAP file or start a live sniffing session from Packet Analysis to populate telemetry charts.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            c1, c2, c3 = st.columns([1, 1, 1])
            with c2:
                if st.button("⚡ Load Built-in Sample Capture", key="mon_empty_load_sample_btn", use_container_width=True, type="primary"):
                    raw, parsed, err = load_pcap("sample_captures/sample_traffic.pcap")
                    if not err:
                        st.session_state["packets"] = raw
                        st.session_state["raw_packets"] = raw
                        st.session_state["parsed_packets"] = parsed
                        st.session_state["loaded_file"] = "sample_traffic.pcap [BASELINE]"
                        st.session_state["selected_packet_idx"] = 0
                        st.rerun()
        else:
            df = packets_to_dataframe(parsed_packets)
            flows = analyze_all_flows(parsed_packets)

            proto_stats = analyze_protocols(df)
            unique_protos = len(proto_stats.get("counts", {}))
            total_bytes = df["length"].sum() if "length" in df.columns else 0
            ip_stats = analyze_top_ips(df, top_n=20)
            unique_endpoints = len(ip_stats.get("top_endpoints", {}))
            dns_stats = analyze_dns_queries(df)
            dns_query_count = dns_stats.get("total_queries", 0)
            total_retrans = sum(f.get("potential_retransmissions", 0) for f in flows) if flows else 0

            # Minimal KPI chips
            k1, k2, k3, k4, k5 = st.columns(5)
            with k1: st.metric("Protocols", f"{unique_protos}")
            with k2: st.metric("Observed Bytes", format_bytes(total_bytes))
            with k3: st.metric("Unique IPs", f"{unique_endpoints}")
            with k4: st.metric("DNS Queries", f"{dns_query_count}")
            with k5: st.metric("Retransmissions", f"{total_retrans}")

            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

            # Row 1: Protocol Distribution Donut & Traffic Timeline
            r1c1, r1c2 = st.columns(2)
            with r1c1:
                st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>PROTOCOL BREAKDOWN</span>", unsafe_allow_html=True)
                counts = proto_stats.get("counts", {})
                if counts:
                    fig_p = go.Figure(data=[go.Pie(
                        labels=list(counts.keys()),
                        values=list(counts.values()),
                        hole=0.55,
                        marker=dict(
                            colors=[PROTOCOL_COLORS.get(p, "#94A3B8") for p in counts.keys()],
                            line=dict(color="#FFFFFF", width=2)
                        ),
                        textinfo="label+percent",
                        textfont=dict(family="JetBrains Mono, monospace", size=10, color="#263238")
                    )])
                    _apply_light_plotly_layout(fig_p, height=270)
                    st.plotly_chart(fig_p, use_container_width=True)

            with r1c2:
                st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>TRAFFIC VOLUME OVER TIME</span>", unsafe_allow_html=True)
                timeline_df = analyze_traffic_timeline(df, bins=25)
                if not timeline_df.empty and "bin_mid" in timeline_df.columns:
                    fig_t = go.Figure()
                    fig_t.add_trace(go.Bar(
                        x=timeline_df["bin_mid"],
                        y=timeline_df["byte_volume"],
                        name="Bytes",
                        marker_color="#159A91",
                        opacity=0.85
                    ))
                    fig_t.update_layout(xaxis_title="Relative Seconds", yaxis_title="Bytes")
                    _apply_light_plotly_layout(fig_t, height=270)
                    st.plotly_chart(fig_t, use_container_width=True)

            # Row 2: Top Talkers/Listeners & Active Service Ports
            r2c1, r2c2 = st.columns(2)
            with r2c1:
                st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>TOP TALKERS & LISTENERS</span>", unsafe_allow_html=True)
                top_endpoints = ip_stats.get("top_endpoints", {})
                if top_endpoints:
                    ep_df = pd.DataFrame(list(top_endpoints.items()), columns=["IP Address", "Frames"]).head(8)
                    fig_ep = px.bar(
                        ep_df, x="Frames", y="IP Address", orientation="h",
                        color_discrete_sequence=["#059669"]
                    )
                    fig_ep.update_layout(yaxis=dict(autorange="reversed"))
                    _apply_light_plotly_layout(fig_ep, height=260)
                    st.plotly_chart(fig_ep, use_container_width=True)

            with r2c2:
                st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>ACTIVE SERVICE PORTS</span>", unsafe_allow_html=True)
                port_stats = analyze_top_ports(df, top_n=8)
                ports_dict = port_stats.get("ports", {})
                if ports_dict:
                    port_rows = []
                    for port_str, cnt in ports_dict.items():
                        service_name = PORT_SERVICE_MAP.get(str(port_str), "Dynamic/Private")
                        port_rows.append({"Port": f"{port_str} ({service_name})", "Frames": cnt})
                    port_df = pd.DataFrame(port_rows)
                    fig_prt = px.bar(
                        port_df, x="Frames", y="Port", orientation="h",
                        color_discrete_sequence=["#159A91"]
                    )
                    fig_prt.update_layout(yaxis=dict(autorange="reversed"))
                    _apply_light_plotly_layout(fig_prt, height=260)
                    st.plotly_chart(fig_prt, use_container_width=True)

            # Row 3: TCP Flags & DNS Resolution
            r3c1, r3c2 = st.columns(2)
            with r3c1:
                st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>TCP FLAG BREAKDOWN</span>", unsafe_allow_html=True)
                flags_data = analyze_tcp_flags(df)
                if flags_data:
                    fig_f = go.Figure(data=[go.Bar(
                        x=list(flags_data.keys()),
                        y=list(flags_data.values()),
                        marker_color=[TCP_FLAG_COLORS.get(f, "#94A3B8") for f in flags_data.keys()]
                    )])
                    _apply_light_plotly_layout(fig_f, height=240)
                    st.plotly_chart(fig_f, use_container_width=True)
                else:
                    st.caption("No TCP control flags observed in capture buffer.")

            with r3c2:
                st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>DNS QUERY STATISTICS</span>", unsafe_allow_html=True)
                domains = dns_stats.get("domains", {})
                if domains:
                    dns_df = pd.DataFrame(list(domains.items()), columns=["Domain Name", "Queries"]).head(6)
                    st.dataframe(dns_df, use_container_width=True, hide_index=True)
                else:
                    st.caption("No DNS query activity observed in capture buffer.")

    # -----------------------------------------------------------------------
    # TAB 2: Host Interfaces & Adapters
    # -----------------------------------------------------------------------
    with mon_tab_device:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #263238; margin-bottom: 6px;">
                HOST NETWORK ADAPTERS & OPERATING SYSTEM INTERFACES
            </div>
            <div style="font-size: 0.84rem; color: #718096; margin-bottom: 14px;">
                Enumerate physical and virtual network adapters bound to this machine, including hardware MAC addresses, link GUIDs, and driver statuses.
            </div>
            """,
            unsafe_allow_html=True
        )

        interfaces = get_available_interfaces()
        if interfaces:
            if_rows = []
            for iface in interfaces:
                if_rows.append({
                    "Interface Name": iface.get("name", "Unknown"),
                    "Description": iface.get("description", "—"),
                    "Adapter ID / GUID": iface.get("guid", iface.get("id", "—")),
                })
            if_df = pd.DataFrame(if_rows)
            st.dataframe(if_df, use_container_width=True, hide_index=True)
        else:
            st.warning("No physical or virtual network adapters enumerated.")

        st.divider()
        st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.8rem; font-weight: 700; color: #263238;'>QUICK POWERSHELL HOST DIAGNOSTICS</span>", unsafe_allow_html=True)
        st.caption("Run these native Windows cmdlets in your terminal to inspect hardware link speeds, IP bindings, and gateway routes:")
        st.code("Get-NetIPConfiguration", language="powershell")
        st.code("Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, Status", language="powershell")

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    render_contextual_help("analytics")

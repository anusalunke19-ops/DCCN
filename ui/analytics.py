"""
analytics.py — Deep Network Analytics Dashboard.

Provides:
- Protocol distribution breakdown with SOC color palettes
- Traffic volume and packet arrival rate over relative capture timeline
- Top communicating source & destination endpoints (talkers / listeners)
- Most active service ports with IANA port resolution
- TCP flag telemetry (control vs data transfer signals)
- DNS resolution statistics, queried domains, and record type distribution
- Transport connection health & TCP retransmission heuristic indicators
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from core.pcap_manager import packets_to_dataframe, load_pcap
from core.protocol_analyzer import (
    analyze_protocols, analyze_top_ips, analyze_top_ports,
    analyze_tcp_flags, analyze_dns_queries, analyze_traffic_timeline
)
from core.flow_analyzer import analyze_all_flows
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
    "SYN": "#38BDF8",       # Sky cyan
    "ACK": "#10B981",       # Emerald green
    "FIN": "#F59E0B",       # Amber
    "RST": "#EF4444",       # Crimson
    "PSH": "#A78BFA",       # Violet
    "URG": "#F43F5E",       # Rose
}


def _apply_soc_plotly_layout(fig, height=300):
    """Apply consistent SOC dark aesthetic to Plotly figures."""
    fig.update_layout(
        height=height,
        margin=dict(l=15, r=15, t=28, b=15),
        paper_bgcolor="#11141A",
        plot_bgcolor="#11141A",
        font=dict(family="JetBrains Mono, monospace", size=11, color="#94A3B8"),
        xaxis=dict(
            gridcolor="#1B202A",
            zerolinecolor="#1B202A",
            tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#64748B"),
        ),
        yaxis=dict(
            gridcolor="#1B202A",
            zerolinecolor="#1B202A",
            tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#64748B"),
        ),
        hoverlabel=dict(
            bgcolor="#161A22",
            bordercolor="#00E5FF",
            font=dict(family="JetBrains Mono, monospace", size=11, color="#F1F5F9")
        )
    )
    return fig


def render_analytics_page():
    # Header Banner
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #1F242F; padding-bottom: 12px; margin-bottom: 20px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #00E5FF; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 2px;">
                    // FORENSIC TELEMETRY // DEEP PROTOCOL & TRAFFIC ANALYTICS
                </div>
                <div style="font-size: 1.4rem; font-weight: 700; color: #F1F5F9; letter-spacing: -0.02em;">
                    Network Traffic & Protocol Analytics
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-cyan">L2-L7 ENGINE</span>
                <span class="soc-badge soc-badge-green">AGGREGATE TELEMETRY</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    parsed_packets = st.session_state.get("parsed_packets", [])
    if not parsed_packets:
        st.markdown(
            """
            <div style="background: #11141A; border: 1px dashed #2D3748; border-radius: 8px; padding: 48px; text-align: center; margin-top: 16px;">
                <div style="font-size: 2.2rem; margin-bottom: 12px;">📊</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: #F1F5F9; margin-bottom: 6px;">No Capture Data Available for Analytics</div>
                <div style="font-size: 0.85rem; color: #94A3B8; max-width: 480px; margin: 0 auto 20px auto; line-height: 1.5;">
                    The analytics engine requires parsed packet buffers to compute protocol breakdowns, time series trends, and transport connection health.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("⚡ Load Built-in Sample Capture", key="analytics_empty_load_sample_btn", use_container_width=True, type="primary"):
                raw, parsed, err = load_pcap("sample_captures/sample_traffic.pcap")
                if not err:
                    st.session_state["packets"] = raw
                    st.session_state["raw_packets"] = raw
                    st.session_state["parsed_packets"] = parsed
                    st.session_state["loaded_file"] = "sample_traffic.pcap"
                    st.session_state["capture_source"] = "sample_traffic.pcap"
                    st.session_state["selected_packet_idx"] = 0
                    st.rerun()
        return

    df = packets_to_dataframe(parsed_packets)
    flows = analyze_all_flows(parsed_packets)

    # -----------------------------------------------------------------------
    # Top Telemetry KPI Row
    # -----------------------------------------------------------------------
    proto_stats = analyze_protocols(df)
    unique_protos = len(proto_stats.get("counts", {}))
    total_bytes = df["length"].sum() if "length" in df.columns else 0
    ip_stats = analyze_top_ips(df, top_n=20)
    unique_endpoints = len(ip_stats.get("top_endpoints", {}))
    dns_stats = analyze_dns_queries(df)
    dns_query_count = dns_stats.get("total_queries", 0)
    total_retrans = sum(f.get("potential_retransmissions", 0) for f in flows) if flows else 0

    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">PROTOCOLS</div>
                <div class="kpi-val" style="color: #38BDF8;">{unique_protos}</div>
                <div class="kpi-sub">Observed in buffer</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with kpi2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">TOTAL VOLUME</div>
                <div class="kpi-val" style="color: #00E5FF;">{format_bytes(total_bytes)}</div>
                <div class="kpi-sub">{len(df):,} total frames</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with kpi3:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">ACTIVE ENDPOINTS</div>
                <div class="kpi-val" style="color: #10B981;">{unique_endpoints}</div>
                <div class="kpi-sub">Unique IP addresses</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with kpi4:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">DNS QUERIES</div>
                <div class="kpi-val" style="color: #F59E0B;">{dns_query_count}</div>
                <div class="kpi-sub">{len(dns_stats.get('domains', {}))} unique domains</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with kpi5:
        retrans_color = "#EF4444" if total_retrans > 0 else "#10B981"
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">RETRANSMISSIONS</div>
                <div class="kpi-val" style="color: {retrans_color};">{total_retrans}</div>
                <div class="kpi-sub">{"Flagged anomalies" if total_retrans > 0 else "Clean stream"}</div>
            </div>
            """,
            unsafe_allow_html=True
        )


    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # Row 1: Protocol Breakdown & Traffic Volume Timeline
    # -----------------------------------------------------------------------
    r1c1, r1c2 = st.columns(2)

    with r1c1:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #E2E8F0; margin-bottom: 8px;">
                // PROTOCOL DISTRIBUTION (FRAME VOLUME)
            </div>
            """,
            unsafe_allow_html=True
        )

        counts = proto_stats.get("counts", {})
        if counts:
            pdf = pd.DataFrame(list(counts.items()), columns=["Protocol", "Packets"])
            pdf["Percentage"] = ((pdf["Packets"] / pdf["Packets"].sum()) * 100).round(1)
            pdf = pdf.sort_values("Packets", ascending=True)

            fig_proto = px.bar(
                pdf,
                y="Protocol", x="Packets", orientation="h",
                color="Protocol", color_discrete_map=PROTOCOL_COLORS,
                text="Packets",
                custom_data=["Percentage"]
            )
            fig_proto.update_traces(
                textposition="outside",
                hovertemplate="<b>%{y}</b><br>Frames: %{x:,}<br>Share: %{customdata[0]}%<extra></extra>",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#94A3B8"),
                marker=dict(line=dict(width=0))
            )
            fig_proto.update_layout(
                showlegend=False,
                xaxis_title="Packet Count",
                yaxis_title="",
            )
            _apply_soc_plotly_layout(fig_proto, height=330)
            st.plotly_chart(fig_proto, use_container_width=True)
        else:
            st.caption("No protocol data available.")

    with r1c2:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #E2E8F0; margin-bottom: 8px;">
                // TRAFFIC ARRIVAL DYNAMICS (TIME SERIES)
            </div>
            """,
            unsafe_allow_html=True
        )

        timeline = analyze_traffic_timeline(df, bins=25)
        if not timeline.empty:
            fig_t = go.Figure()
            fig_t.add_trace(go.Scatter(
                x=timeline["bin_mid"],
                y=timeline["packet_count"],
                mode="lines",
                name="Packets / Bin",
                line=dict(color="#00E5FF", width=2),
                fill="tozeroy",
                fillcolor="rgba(0, 229, 255, 0.08)",
                hovertemplate="Time: +%{x:.2f}s<br>Packets: %{y}<extra></extra>"
            ))
            fig_t.update_layout(
                xaxis_title="Relative Capture Time (seconds)",
                yaxis_title="Frames per Interval",
                showlegend=False
            )
            _apply_soc_plotly_layout(fig_t, height=330)
            st.plotly_chart(fig_t, use_container_width=True)
        else:
            st.caption("Single timestamp or insufficient data for timeline rendering.")

    # -----------------------------------------------------------------------
    # Row 2: Top Communicating Endpoints & Most Active Service Ports
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    r2c1, r2c2 = st.columns(2)

    with r2c1:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #E2E8F0; margin-bottom: 8px;">
                // TOP COMMUNICATING IP TALKERS (SOURCE IP)
            </div>
            """,
            unsafe_allow_html=True
        )

        top_src = ip_stats.get("top_src", {})
        if top_src:
            ipdf = pd.DataFrame(list(top_src.items()), columns=["IP", "Packets"]).head(8)
            ipdf = ipdf.sort_values("Packets", ascending=True)

            fig_ip = px.bar(
                ipdf, y="IP", x="Packets", orientation="h",
                text="Packets",
                color_discrete_sequence=["#10B981"]
            )
            fig_ip.update_traces(
                textposition="outside",
                hovertemplate="<b>Host:</b> %{y}<br>Transmitted: %{x:,} packets<extra></extra>",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#94A3B8"),
                marker=dict(line=dict(width=0))
            )
            fig_ip.update_layout(
                showlegend=False,
                xaxis_title="Egress Frame Count",
                yaxis_title="",
            )
            _apply_soc_plotly_layout(fig_ip, height=320)
            st.plotly_chart(fig_ip, use_container_width=True)
        else:
            st.caption("No IP packet sources identified in capture buffer.")

    with r2c2:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #E2E8F0; margin-bottom: 8px;">
                // MOST ACTIVE TRANSPORT PORTS (SERVICES)
            </div>
            """,
            unsafe_allow_html=True
        )

        port_stats = analyze_top_ports(df, top_n=8)
        ports = port_stats.get("ports", {})
        if ports:
            port_items = []
            for p, cnt in ports.items():
                svc = PORT_SERVICE_MAP.get(str(p), "")
                label = f"{p} ({svc})" if svc else str(p)
                port_items.append({"PortLabel": label, "RawPort": p, "Packets": cnt})

            portdf = pd.DataFrame(port_items).sort_values("Packets", ascending=True)
            fig_port = px.bar(
                portdf, y="PortLabel", x="Packets", orientation="h",
                text="Packets",
                color_discrete_sequence=["#38BDF8"]
            )
            fig_port.update_traces(
                textposition="outside",
                hovertemplate="<b>Port:</b> %{y}<br>Hits: %{x:,} packets<extra></extra>",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#94A3B8"),
                marker=dict(line=dict(width=0))
            )
            fig_port.update_layout(
                showlegend=False,
                xaxis_title="Transport Hits",
                yaxis_title="",
            )
            _apply_soc_plotly_layout(fig_port, height=320)
            st.plotly_chart(fig_port, use_container_width=True)
        else:
            st.caption("No transport layer ports present (e.g. ARP or pure ICMP traffic).")

    # -----------------------------------------------------------------------
    # Row 3: TCP Flag Dynamics & DNS Resolution Activity
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    r3c1, r3c2 = st.columns(2)

    with r3c1:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #E2E8F0; margin-bottom: 8px;">
                // TCP CONTROL & DATA FLAGS DISTRIBUTION
            </div>
            """,
            unsafe_allow_html=True
        )

        flags = analyze_tcp_flags(df)
        if flags:
            fdf = pd.DataFrame(list(flags.items()), columns=["Flag", "Count"])
            color_map = [TCP_FLAG_COLORS.get(fl, "#64748B") for fl in fdf["Flag"]]

            fig_f = go.Figure(data=[go.Pie(
                labels=fdf["Flag"],
                values=fdf["Count"],
                hole=0.55,
                marker=dict(colors=color_map, line=dict(color="#0B0D11", width=2)),
                textinfo="label+percent",
                hovertemplate="<b>Flag: %{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
                textfont=dict(family="JetBrains Mono, monospace", size=11, color="#F1F5F9")
            )])
            fig_f.update_layout(
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="top",
                    y=-0.1,
                    xanchor="center",
                    x=0.5,
                    font=dict(family="JetBrains Mono, monospace", size=10, color="#94A3B8")
                )
            )
            _apply_soc_plotly_layout(fig_f, height=330)
            st.plotly_chart(fig_f, use_container_width=True)
        else:
            st.markdown(
                """
                <div style="background: #11141A; border: 1px solid #1F242F; border-radius: 6px; padding: 24px; text-align: center; color: #64748B; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
                    NO TCP SEGMENTS DETECTED IN BUFFER
                </div>
                """,
                unsafe_allow_html=True
            )

    with r3c2:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #E2E8F0; margin-bottom: 8px;">
                // DNS RESOLUTION ACTIVITY & QUERIED DOMAINS
            </div>
            """,
            unsafe_allow_html=True
        )

        domains = dns_stats.get("domains", {})
        if domains:
            ddf = pd.DataFrame(list(domains.items()), columns=["Domain", "Queries"]).head(8)
            ddf = ddf.sort_values("Queries", ascending=True)

            fig_dns = px.bar(
                ddf, y="Domain", x="Queries", orientation="h",
                text="Queries",
                color_discrete_sequence=["#F59E0B"]
            )
            fig_dns.update_traces(
                textposition="outside",
                hovertemplate="<b>Domain:</b> %{y}<br>Queries: %{x}<extra></extra>",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#94A3B8"),
                marker=dict(line=dict(width=0))
            )
            fig_dns.update_layout(
                showlegend=False,
                xaxis_title="Query Hits",
                yaxis_title="",
            )
            _apply_soc_plotly_layout(fig_dns, height=330)
            st.plotly_chart(fig_dns, use_container_width=True)

            qtypes = dns_stats.get("query_types", {})
            if qtypes:
                type_badges = " ".join([f"<span class='soc-badge soc-badge-amber'>{k}: {v}</span>" for k, v in qtypes.items()])
                st.markdown(f"<div style='margin-top: 6px;'>{type_badges}</div>", unsafe_allow_html=True)
        else:
            st.markdown(
                """
                <div style="background: #11141A; border: 1px solid #1F242F; border-radius: 6px; padding: 24px; text-align: center; color: #64748B; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
                    NO PLAINTEXT DNS QUERIES OBSERVED<br>
                    <span style="font-size: 0.75rem; color: #475569;">(Encrypted DoH/DoT queries appear as standard HTTPS/TLS traffic on port 443/853)</span>
                </div>
                """,
                unsafe_allow_html=True
            )

    # -----------------------------------------------------------------------
    # Row 4: Connection Health & TCP Anomaly Deep Telemetry
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #E2E8F0; margin-bottom: 8px;">
            // TRANSPORT SESSION HEALTH & RE-TRANSMISSION HEURISTICS
        </div>
        """,
        unsafe_allow_html=True
    )

    if flows:
        completed = sum(1 for f in flows if "Complete" in f.get("tcp_state", ""))
        established = sum(1 for f in flows if "Established" in f.get("tcp_state", ""))
        refused = sum(1 for f in flows if "Refused" in f.get("tcp_state", ""))
        incomplete = sum(1 for f in flows if "Incomplete" in f.get("tcp_state", ""))
        data_only = sum(1 for f in flows if "Data Only" in f.get("tcp_state", ""))

        health_col1, health_col2 = st.columns([1, 2])

        with health_col1:
            st.markdown(
                f"""
                <div style="background: #11141A; border: 1px solid #1F242F; border-radius: 6px; padding: 16px; font-family: 'JetBrains Mono', monospace;">
                    <div style="font-size: 0.75rem; color: #64748B; text-transform: uppercase; margin-bottom: 8px;">Flow State Inventory</div>
                    <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1B202A; font-size: 0.85rem;">
                        <span style="color: #10B981;">● Completed (FIN/ACK)</span>
                        <span style="font-weight: 600; color: #F1F5F9;">{completed}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1B202A; font-size: 0.85rem;">
                        <span style="color: #00E5FF;">● Established (Open)</span>
                        <span style="font-weight: 600; color: #F1F5F9;">{established}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1B202A; font-size: 0.85rem;">
                        <span style="color: #EF4444;">● Connection Refused</span>
                        <span style="font-weight: 600; color: #F1F5F9;">{refused}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #1B202A; font-size: 0.85rem;">
                        <span style="color: #F59E0B;">● Incomplete Handshake</span>
                        <span style="font-weight: 600; color: #F1F5F9;">{incomplete}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 6px 0; font-size: 0.85rem;">
                        <span style="color: #64748B;">● Mid-Stream Data Only</span>
                        <span style="font-weight: 600; color: #F1F5F9;">{data_only}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with health_col2:
            health_items = {
                "Completed": completed,
                "Established": established,
                "Refused": refused,
                "Incomplete": incomplete,
                "Data Only": data_only,
            }
            health_items = {k: v for k, v in health_items.items() if v > 0}

            if health_items:
                hdf = pd.DataFrame(list(health_items.items()), columns=["State", "Count"])
                state_colors = {
                    "Completed": "#10B981",
                    "Established": "#00E5FF",
                    "Refused": "#EF4444",
                    "Incomplete": "#F59E0B",
                    "Data Only": "#64748B",
                }
                fig_h = go.Figure(data=[go.Pie(
                    labels=hdf["State"],
                    values=hdf["Count"],
                    hole=0.55,
                    marker=dict(
                        colors=[state_colors.get(s, "#64748B") for s in hdf["State"]],
                        line=dict(color="#0B0D11", width=2)
                    ),
                    textinfo="label+value",
                    hovertemplate="<b>%{label}</b><br>Flows: %{value}<br>Share: %{percent}<extra></extra>",
                    textfont=dict(family="JetBrains Mono, monospace", size=11, color="#F1F5F9")
                )])
                fig_h.update_layout(
                    showlegend=True,
                    legend=dict(
                        orientation="h",
                        yanchor="top",
                        y=-0.08,
                        xanchor="center",
                        x=0.5,
                        font=dict(family="JetBrains Mono, monospace", size=10, color="#94A3B8")
                    )
                )
                _apply_soc_plotly_layout(fig_h, height=240)
                st.plotly_chart(fig_h, use_container_width=True)

        if total_retrans > 0:
            st.markdown(
                f"""
                <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid #F59E0B; border-radius: 4px; padding: 12px 16px; margin-top: 12px; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #F1F5F9;">
                    <span style="color: #F59E0B; font-weight: 700;">⚠ FORENSIC ADVISORY:</span>
                    Detected <b>{total_retrans}</b> potential TCP segment retransmissions across 5-tuple streams.
                    <div style="color: #94A3B8; font-size: 0.78rem; margin-top: 4px; line-height: 1.4;">
                        Heuristic criteria: consecutive segments with identical TCP sequence numbers and payload length.
                        Typically correlates with network congestion, link degradation, packet loss, or aggressive client RTO timers.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.markdown(
            """
            <div style="background: #11141A; border: 1px solid #1F242F; border-radius: 6px; padding: 20px; text-align: center; color: #64748B; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
                NO MULTI-PACKET CONVERSATIONAL FLOWS DETECTED
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    render_contextual_help("analytics")


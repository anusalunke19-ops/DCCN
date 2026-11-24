"""
connection_explorer.py — Technical TCP Flow Reconstruction & Handshake Tracker.

Provides:
- Reconstructed bidirectional socket communication flows (5-tuple: IP addresses, ports, protocol)
- IPv4 and IPv6 socket normalization
- State machine tracking (SYN, SYN-ACK, ACK, Data Transfer, FIN, RST)
- Handshake Initial Round-Trip Time (iRTT) measurement
- Data transfer identification distinguishing pure ACKs from payload bytes
- Chronological conversational timeline and Plotly event scatter visualization
- Rigorous distinction between observed packet events and inferred connection states
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from core.flow_analyzer import analyze_all_flows
from utils.helpers import format_bytes, format_duration
from ui.guided_lab import render_contextual_help


def _apply_light_plotly_layout(fig, height=280):
    """Apply unified light aesthetic to connection Plotly charts."""
    fig.update_layout(
        height=height,
        margin=dict(l=15, r=15, t=30, b=15),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        font=dict(family="JetBrains Mono, monospace", size=10, color="#718096"),
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
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="center",
            x=0.5,
            font=dict(family="JetBrains Mono, monospace", size=10, color="#263238")
        ),
        hoverlabel=dict(
            bgcolor="#FFFFFF",
            bordercolor="#159A91",
            font=dict(family="JetBrains Mono, monospace", size=11, color="#263238")
        )
    )
    return fig


def _navigate(page):
    """Navigate to a workspace page with radio sync."""
    st.session_state["current_page"] = page
    st.session_state["sidebar_workspace_radio"] = page
    st.rerun()


def render_connection_explorer_page():
    # Header Banner
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #E5E9EF; padding-bottom: 12px; margin-bottom: 16px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 2px;">
                    // TRANSPORT RECONSTRUCTION // TCP STATE MACHINE ENGINE
                </div>
                <div style="font-size: 1.4rem; font-weight: 700; color: #263238; letter-spacing: -0.02em;">
                    TCP Connection Explorer & Flow Dissector
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-teal">BIDIRECTIONAL 5-TUPLE</span>
                <span class="soc-badge soc-badge-green">STATE MACHINE</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    parsed_packets = st.session_state.get("parsed_packets", [])
    if not parsed_packets:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px dashed #CBD5E1; border-radius: 8px; padding: 48px; text-align: center; margin-top: 16px;">
                <div style="font-size: 2.2rem; margin-bottom: 12px;">🔗</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: #263238; margin-bottom: 6px;">No Conversation Flows Available for Dissection</div>
                <div style="font-size: 0.85rem; color: #718096; max-width: 480px; margin: 0 auto 20px auto; line-height: 1.5;">
                    The Connection Explorer reconstructs conversational sessions across 5-tuple sockets. Please load a capture file or sniff live packets.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("📡 Go to Live Capture Console", key="conn_empty_goto_live_btn", use_container_width=True, type="primary"):
                _navigate("📡 Live Capture")
        return

    flows = analyze_all_flows(parsed_packets)
    if not flows:
        st.info("No multi-packet communication flows identified in the current packet buffer.")
        return

    # -----------------------------------------------------------------------
    # Section 1: Aggregate Telemetry KPI Row
    # -----------------------------------------------------------------------
    total_flows = len(flows)
    complete = sum(1 for f in flows if "Complete" in f.get("tcp_state", ""))
    established = sum(1 for f in flows if "Established" in f.get("tcp_state", ""))
    refused = sum(1 for f in flows if "Refused" in f.get("tcp_state", ""))
    incomplete = sum(1 for f in flows if "Incomplete" in f.get("tcp_state", ""))
    udp_flows = sum(1 for f in flows if "UDP" in f.get("tcp_state", ""))

    mc1, mc2, mc3, mc4, mc5 = st.columns(5)
    with mc1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">TOTAL SESSIONS</div>
                <div class="kpi-val" style="color: #159A91;">{total_flows:,}</div>
                <div class="kpi-sub">Normalized flows</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with mc2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">ESTABLISHED / COMPLETE</div>
                <div class="kpi-val" style="color: #059669;">{complete + established:,}</div>
                <div class="kpi-sub">3-Way Handshake OK</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with mc3:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">CONNECTION REFUSED</div>
                <div class="kpi-val" style="color: #DC2626;">{refused:,}</div>
                <div class="kpi-sub">SYN ➔ RST (Port closed)</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with mc4:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">INCOMPLETE HANDSHAKES</div>
                <div class="kpi-val" style="color: #D97706;">{incomplete:,}</div>
                <div class="kpi-sub">Unanswered / Dropped</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with mc5:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">UDP FLOWS</div>
                <div class="kpi-val" style="color: #8B83C8;">{udp_flows:,}</div>
                <div class="kpi-sub">Connectionless datagrams</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # Section 2: Reconstructed Flow Summary Dissection Table
    # -----------------------------------------------------------------------
    st.markdown(
        """
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #263238; margin-bottom: 8px;">
            // RECONSTRUCTED 5-TUPLE SOCKET SESSIONS
        </div>
        """,
        unsafe_allow_html=True
    )

    flow_table_data = []
    for idx, flow in enumerate(flows):
        state = flow.get("tcp_state", "Unknown")
        flow_table_data.append({
            "ID": f"#{idx + 1:02d}",
            "Client (Initiator) Socket": flow.get("client_socket", f"{flow['src_ip']}:{flow['src_port']}"),
            "Server (Responder) Socket": flow.get("server_socket", f"{flow['dst_ip']}:{flow['dst_port']}"),
            "Proto": flow.get("protocol", "TCP"),
            "Packets": flow["packet_count"],
            "Wire Volume": format_bytes(flow["total_bytes"]),
            "App Payload": format_bytes(flow.get("payload_bytes", 0)),
            "Duration": format_duration(flow["duration_sec"]),
            "Handshake iRTT": f"{flow['rtt_ms']} ms" if flow.get("rtt_ms") is not None else "—",
            "Observed State": state,
            "Retrans": flow.get("potential_retransmissions", 0),
        })

    flow_df = pd.DataFrame(flow_table_data)
    st.dataframe(flow_df, use_container_width=True, hide_index=True)

    # -----------------------------------------------------------------------
    # Section 3: Deep Dissection of Selected Flow
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #263238; margin-bottom: 8px;">
            // INDIVIDUAL CONVERSATION DEEP DIVE & STATE MACHINE
        </div>
        """,
        unsafe_allow_html=True
    )

    flow_options = []
    for i, f in enumerate(flows):
        csock = f.get("client_socket") or f"{f['src_ip']}:{f['src_port']}"
        ssock = f.get("server_socket") or f"{f['dst_ip']}:{f['dst_port']}"
        proto = f.get("protocol", "TCP")
        pkts = f.get("packet_count", 0)
        st_label = f.get("tcp_state", "")[:30]
        flow_options.append(f"Flow #{i+1:02d}: {csock} ↔ {ssock} ({proto}, {pkts} pkts) — {st_label}")

    selected_flow_label = st.selectbox("Select Conversation Flow to Inspect", flow_options, key="conn_flow_select")
    selected_idx = flow_options.index(selected_flow_label)
    selected_flow = flows[selected_idx]

    # Flow Telemetry Strip
    fc1, fc2, fc3, fc4, fc5 = st.columns(5)
    with fc1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">CONVERSATION FRAMES</div>
                <div class="kpi-val" style="color: #159A91;">{selected_flow['packet_count']} PKTS</div>
                <div class="kpi-sub">C➔S: {selected_flow.get('c2s_packets', 0)} | S➔C: {selected_flow.get('s2c_packets', 0)}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with fc2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">APPLICATION PAYLOAD</div>
                <div class="kpi-val" style="color: #059669;">{format_bytes(selected_flow.get('payload_bytes', 0))}</div>
                <div class="kpi-sub">Wire: {format_bytes(selected_flow['total_bytes'])}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with fc3:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">ACTIVE DURATION</div>
                <div class="kpi-val" style="color: #159A91;">{format_duration(selected_flow['duration_sec'])}</div>
                <div class="kpi-sub">First to last packet</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with fc4:
        rtt = selected_flow.get("rtt_ms")
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">HANDSHAKE iRTT</div>
                <div class="kpi-val" style="color: #D97706;">{f"{rtt} ms" if rtt is not None else "N/A"}</div>
                <div class="kpi-sub">SYN to SYN-ACK delta</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with fc5:
        state_str = selected_flow.get("tcp_state", "Unknown")
        state_color = "#059669" if ("Established" in state_str or "Complete" in state_str) else ("#DC2626" if "Refused" in state_str else "#D97706")
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">LIFECYCLE STATUS</div>
                <div class="kpi-val" style="color: {state_color}; font-size: 0.95rem;">{selected_flow.get('handshake_state', 'UNKNOWN')}</div>
                <div class="kpi-sub">{selected_flow.get('stream_status', '')}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # -----------------------------------------------------------------------
    # Handshake Reconstruction Graphic
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    # -----------------------------------------------------------------------
    # Visual TCP 3-Way Handshake Exchange Cards (Interactive & Dynamic)
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    if selected_flow.get("has_syn"):
        syn_pkt = selected_flow.get("syn_pkt") or {}
        syn_ack_pkt = selected_flow.get("syn_ack_pkt") or {}
        final_ack_pkt = selected_flow.get("final_ack_pkt") or {}

        client_isn = selected_flow.get("client_isn")
        server_isn = selected_flow.get("server_isn")
        syn_ack_present = selected_flow.get("has_syn_ack", False)
        final_ack_present = selected_flow.get("has_final_ack", False)
        has_rst = selected_flow.get("has_rst", False)

        # Status badge for the overall handshake
        if final_ack_present:
            hs_badge = '<span class="soc-badge soc-badge-green">● 3-WAY HANDSHAKE ESTABLISHED</span>'
            hs_desc = "Full 3-way handshake verified: bidirectional initial sequence numbers synchronized and acknowledged."
        elif syn_ack_present:
            hs_badge = '<span class="soc-badge soc-badge-amber">⚠ HALF-OPEN (MISSING FINAL ACK)</span>'
            hs_desc = "Client sent SYN and received SYN-ACK, but never transmitted the final ACK. Connection remained half-open."
        elif has_rst:
            hs_badge = '<span class="soc-badge" style="background-color: #FEE2E2; color: #DC2626; border: 1px solid #FECACA;">✕ CONNECTION REFUSED (RST)</span>'
            hs_desc = "Client sent SYN, but the server immediately aborted with RST. The target port is closed or firewalled."
        else:
            hs_badge = '<span class="soc-badge soc-badge-amber">○ UNANSWERED SYN PROBE</span>'
            hs_desc = "Client transmitted initial SYN, but no response was captured from the server (timed out or dropped)."

        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 14px 18px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #159A91;">
                        // VISUAL TCP 3-WAY HANDSHAKE EXCHANGE
                    </span>
                    {hs_badge}
                </div>
                <div style="font-size: 0.82rem; color: #64748B;">
                    {hs_desc}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        h_col1, h_col2, h_col3 = st.columns(3)

        # Card 1: SYN
        syn_num = syn_pkt.get("num", "?")
        syn_win = syn_pkt.get("tcp_window", "N/A")
        with h_col1:
            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-top: 3px solid #159A91; border-radius: 6px; padding: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); height: 100%;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; font-weight: 700; color: #159A91;">
                            1. SYN (STEP 1)
                        </span>
                        <span class="soc-badge soc-badge-teal">FRAME #{syn_num}</span>
                    </div>
                    <div style="font-size: 0.78rem; font-weight: 600; color: #263238; margin-bottom: 8px;">
                        Client ➔ Server [Active Open]
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; line-height: 1.6; color: #1E293B;">
                        <div>Flags: <b style="color: #159A91;">[SYN]</b></div>
                        <div>Seq:   <b>{client_isn}</b> <span style="color: #64748B;">(ISN_c)</span></div>
                        <div>Ack:   <span style="color: #64748B;">0 (None)</span></div>
                        <div>Win:   <b>{syn_win}</b> <span style="color: #64748B;">bytes</span></div>
                    </div>
                    <div style="font-size: 0.73rem; color: #64748B; line-height: 1.45;">
                        Client initiates connection, advertises its Initial Sequence Number (<b style="color: #263238;">ISN_c</b>), and specifies its receive buffer capacity.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Card 2: SYN-ACK
        with h_col2:
            if syn_ack_present:
                sa_num = syn_ack_pkt.get("num", "?")
                sa_ack = syn_ack_pkt.get("tcp_ack", "N/A")
                sa_win = syn_ack_pkt.get("tcp_window", "N/A")
                rtt_str = f"Δ +{rtt} ms" if rtt is not None else ""
                ack_matches = (sa_ack == client_isn + 1) if (isinstance(sa_ack, int) and isinstance(client_isn, int)) else False
                ack_check_html = '<span style="color: #059669; font-weight: 700;">✓ ISN_c + 1 verified</span>' if ack_matches else ""
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-top: 3px solid #059669; border-radius: 6px; padding: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); height: 100%;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; font-weight: 700; color: #059669;">
                                2. SYN-ACK (STEP 2)
                            </span>
                            <span class="soc-badge soc-badge-green">FRAME #{sa_num} {rtt_str}</span>
                        </div>
                        <div style="font-size: 0.78rem; font-weight: 600; color: #263238; margin-bottom: 8px;">
                            Server ➔ Client [Acknowledge & Sync]
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; line-height: 1.6; color: #1E293B;">
                            <div>Flags: <b style="color: #059669;">[SYN, ACK]</b></div>
                            <div>Seq:   <b>{server_isn}</b> <span style="color: #64748B;">(ISN_s)</span></div>
                            <div>Ack:   <b>{sa_ack}</b> {ack_check_html}</div>
                            <div>Win:   <b>{sa_win}</b> <span style="color: #64748B;">bytes</span></div>
                        </div>
                        <div style="font-size: 0.73rem; color: #64748B; line-height: 1.45;">
                            Server agrees to socket connection, confirms client ISN (<b style="color: #263238;">Ack = ISN_c + 1</b>), and sends its own synchronized sequence number (<b style="color: #263238;">ISN_s</b>).
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            elif has_rst:
                st.markdown(
                    """
                    <div style="background: #FFF5F5; border: 1px solid #FED7D7; border-top: 3px solid #DC2626; border-radius: 6px; padding: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); height: 100%;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; font-weight: 700; color: #DC2626;">
                                2. RST REJECTED
                            </span>
                            <span class="soc-badge" style="background-color: #FEE2E2; color: #DC2626;">REFUSED</span>
                        </div>
                        <div style="font-size: 0.78rem; font-weight: 600; color: #991B1B; margin-bottom: 8px;">
                            Server ➔ Client [Reset Connection]
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; background: #FFFFFF; border: 1px solid #FECACA; border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; line-height: 1.6; color: #7F1D1D;">
                            <div>Flags: <b>[RST]</b> or <b>[RST, ACK]</b></div>
                            <div>Status: Destination Port Closed</div>
                        </div>
                        <div style="font-size: 0.73rem; color: #7F1D1D; line-height: 1.45;">
                            The server active operating system or intermediate firewall rejected the connection request immediately.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    """
                    <div style="background: #FFFBEB; border: 1px solid #FDE68A; border-top: 3px solid #D97706; border-radius: 6px; padding: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); height: 100%;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; font-weight: 700; color: #D97706;">
                                2. MISSING SYN-ACK
                            </span>
                            <span class="soc-badge soc-badge-amber">TIMEOUT</span>
                        </div>
                        <div style="font-size: 0.78rem; font-weight: 600; color: #92400E; margin-bottom: 8px;">
                            Server ➔ Client [No Response]
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; background: #FFFFFF; border: 1px solid #FDE68A; border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; line-height: 1.6; color: #78350F;">
                            <div>Status: SYN-ACK Unobserved</div>
                            <div>Cause: Packet Drop / Firewall</div>
                        </div>
                        <div style="font-size: 0.73rem; color: #78350F; line-height: 1.45;">
                            No return SYN-ACK frame was captured. Either the host is unreachable or a firewall silently discarded the SYN packet.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        # Card 3: Final ACK
        with h_col3:
            if final_ack_present:
                fa_num = final_ack_pkt.get("num", "?")
                fa_seq = final_ack_pkt.get("tcp_seq", "N/A")
                fa_ack = final_ack_pkt.get("tcp_ack", "N/A")
                fa_win = final_ack_pkt.get("tcp_window", "N/A")
                ack_matches = (fa_ack == server_isn + 1) if (isinstance(fa_ack, int) and isinstance(server_isn, int)) else False
                ack_check_html = '<span style="color: #059669; font-weight: 700;">✓ ISN_s + 1 verified</span>' if ack_matches else ""
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-top: 3px solid #059669; border-radius: 6px; padding: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); height: 100%;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; font-weight: 700; color: #059669;">
                                3. ACK (STEP 3)
                            </span>
                            <span class="soc-badge soc-badge-green">FRAME #{fa_num}</span>
                        </div>
                        <div style="font-size: 0.78rem; font-weight: 600; color: #263238; margin-bottom: 8px;">
                            Client ➔ Server [Established]
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; line-height: 1.6; color: #1E293B;">
                            <div>Flags: <b style="color: #059669;">[ACK]</b></div>
                            <div>Seq:   <b>{fa_seq}</b></div>
                            <div>Ack:   <b>{fa_ack}</b> {ack_check_html}</div>
                            <div>Win:   <b>{fa_win}</b> <span style="color: #64748B;">bytes</span></div>
                        </div>
                        <div style="font-size: 0.73rem; color: #64748B; line-height: 1.45;">
                            Client confirms server ISN (<b style="color: #263238;">Ack = ISN_s + 1</b>). Connection state transitions to <b style="color: #059669;">ESTABLISHED</b>; bidirectional data transfer can begin.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    """
                    <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-top: 3px solid #94A3B8; border-radius: 6px; padding: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); height: 100%;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; font-weight: 700; color: #64748B;">
                                3. FINAL ACK
                            </span>
                            <span class="soc-badge soc-badge-amber">INCOMPLETE</span>
                        </div>
                        <div style="font-size: 0.78rem; font-weight: 600; color: #475569; margin-bottom: 8px;">
                            Client ➔ Server [Unconfirmed]
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; line-height: 1.6; color: #64748B;">
                            <div>Status: Missing Final ACK</div>
                            <div>State: Half-Open / Dropped</div>
                        </div>
                        <div style="font-size: 0.73rem; color: #64748B; line-height: 1.45;">
                            Client did not transmit the final ACK segment. The socket never reached established state.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
    else:
        st.markdown(
            """
            <div style="background: #FFFBEB; border: 1px solid #FDE68A; border-left: 3px solid #D97706; padding: 10px 14px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #263238;">
                <span style="color: #D97706; font-weight: 700;">⚠ CAPTURE INGESTION NOTE:</span>
                No initial SYN observed for this flow. This indicates mid-stream packet capture (sniffing started after socket establishment) or connectionless UDP traffic.
            </div>
            """,
            unsafe_allow_html=True
        )

    # -----------------------------------------------------------------------
    # Stream Integrity & Retransmission Advisory
    # -----------------------------------------------------------------------
    retrans = selected_flow.get("potential_retransmissions", 0)
    dup_acks = selected_flow.get("duplicate_acks", 0)
    if retrans > 0 or dup_acks > 0:
        st.markdown(
            f"""
            <div style="background: #FFFBEB; border-left: 3px solid #D97706; border: 1px solid #FDE68A; border-radius: 4px; padding: 12px 16px; margin: 12px 0; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #263238;">
                <span style="color: #D97706; font-weight: 700;">⚠ TRANSPORT ANOMALY HEURISTIC:</span>
                Detected <b>{retrans}</b> potential retransmissions and <b>{dup_acks}</b> duplicate ACK events.
                <div style="color: #718096; font-size: 0.75rem; margin-top: 4px; line-height: 1.4;">
                    Duplicate sequence numbers carrying payload in the same direction at a later timestamp indicate dropped segments, network congestion, or receiver timeout.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # -----------------------------------------------------------------------
    # Chronological Conversation Events
    # -----------------------------------------------------------------------
    events = selected_flow.get("events", [])
    if events:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #263238; margin: 16px 0 8px 0;">
                // CHRONOLOGICAL CONVERSATION EVENTS & TIMELINE
            </div>
            """,
            unsafe_allow_html=True
        )

        base_time = events[0]["time"] if events else 0

        # Plotly visual event timeline scatter chart
        if len(events) >= 2:
            chart_data = []
            for ev in events:
                chart_data.append({
                    "Elapsed Time (s)": round(ev["time"] - base_time, 6),
                    "Event Type": ev["event"].split("(")[0].strip(),
                    "Direction": ev.get("dir_label", "Client ➔ Server"),
                    "Detail": ev["detail"],
                    "Flags": ev["flags"]
                })
            chart_df = pd.DataFrame(chart_data)

            fig = px.scatter(
                chart_df,
                x="Elapsed Time (s)",
                y="Event Type",
                color="Direction",
                color_discrete_map={
                    "Client ➔ Server": "#159A91",
                    "Server ➔ Client": "#059669"
                },
                hover_data=["Detail", "Flags"]
            )
            fig.update_traces(marker=dict(size=11, line=dict(width=1, color="#FFFFFF")))
            _apply_light_plotly_layout(fig, height=270)
            st.plotly_chart(fig, use_container_width=True)

        # Tabular Event Dissection
        event_data = []
        for ev in events:
            event_data.append({
                "Offset (s)": f"+{ev['time'] - base_time:.6f}s",
                "Direction": ev["direction"],
                "Flow Orientation": ev.get("dir_label", "Client ➔ Server"),
                "Event Type": ev["event"],
                "Sequence / ACK Detail": ev["detail"],
                "Flags": ev["flags"],
                "Anomaly": "⚠ Anomaly" if ev.get("is_anomaly") else "Normal"
            })

        event_df = pd.DataFrame(event_data)
        st.dataframe(event_df, use_container_width=True, hide_index=True)
    else:
        st.caption("No significant control events recorded for this flow.")

    # -----------------------------------------------------------------------
    # Protocol Reference Expander
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    with st.expander("📘 TCP State Machine & Flow Reconstruction Reference"):
        st.markdown(
            """
            - **Connection Establishment:** Synchronizes 32-bit Sequence Numbers via the 3-Way Handshake ($SYN \\rightarrow SYN-ACK \\rightarrow ACK$). Both hosts exchange Initial Sequence Numbers (ISNs) and advertise initial Flow Control window sizes.
            - **Payload Delivery vs Control ACKs:** Acknowledgment packets with 0 payload confirm receipt of earlier bytes but do not transfer application content. True data transfer occurs when segments carry positive payload octets.
            - **Connection Termination:** Graceful teardown requires mutual exchange of `FIN` flags ($FIN \\rightarrow ACK \\rightarrow FIN \\rightarrow ACK$), transitioning sockets from `ESTABLISHED` to `FIN_WAIT`, `CLOSE_WAIT`, and `TIME_WAIT`. Abrupt termination is executed via the `RST` flag.
            - **Incomplete / Asymmetric Captures:** Network sniffing often observes incomplete handshakes due to asymmetric routing, firewall silent drops (stealth port filtering), or SYN flood attacks.
            """
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    render_contextual_help("connection_explorer")

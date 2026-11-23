"""
capture_comparison.py — Differential Network Forensics & Capture Comparison.

Compares two PCAP/PCAPNG captures (baseline vs impaired/attack):
- Dual-slot ingestion with one-click sample loaders and custom file uploads
- Side-by-side forensic KPIs with automated delta analysis
- Dual-series protocol breakdown grouped bar charts
- TCP control flag dynamics and retransmission differential
- Handshake initial Round Trip Time (iRTT) latency comparison
- DCCN experimental context for network impairment and QoS analysis
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
import tempfile

from core.pcap_manager import load_pcap, packets_to_dataframe
from core.protocol_analyzer import analyze_protocols, analyze_tcp_flags
from core.flow_analyzer import analyze_all_flows
from utils.helpers import format_bytes, format_duration
from ui.guided_lab import render_contextual_help


def _apply_light_plotly_layout(fig, height=320):
    """Apply consistent light aesthetic to comparison Plotly figures."""
    fig.update_layout(
        height=height,
        margin=dict(l=15, r=15, t=35, b=15),
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
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="center",
            x=0.5,
            font=dict(family="JetBrains Mono, monospace", size=11, color="#263238")
        ),
        hoverlabel=dict(
            bgcolor="#FFFFFF",
            bordercolor="#159A91",
            font=dict(family="JetBrains Mono, monospace", size=11, color="#263238")
        )
    )
    return fig


def _load_comparison_slot(slot_label: str, key_prefix: str, default_sample_path: str, badge_color: str):
    """Render an ingestion slot for comparison with upload & sample load options."""
    st.markdown(
        f"""
        <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; font-weight: 700; color: #263238; text-transform: uppercase;">
                    {slot_label}
                </span>
                <span class="soc-badge soc-badge-{badge_color}">SLOT: {key_prefix.upper()}</span>
            </div>
        """,
        unsafe_allow_html=True
    )

    current_name = st.session_state.get(f"{key_prefix}_name")
    current_raw = st.session_state.get(f"{key_prefix}_raw")

    if current_raw:
        st.markdown(
            f"""
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #059669; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
                <span>●</span> <span>ACTIVE: <b>{current_name}</b> ({len(current_raw)} packets)</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    uploaded = st.file_uploader(
        f"Upload {slot_label} PCAP",
        type=["pcap", "pcapng", "cap"],
        key=f"{key_prefix}_upload",
        label_visibility="collapsed"
    )

    if uploaded:
        if st.session_state.get(f"{key_prefix}_uploaded_sig") != (uploaded.name, uploaded.size):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp.write(uploaded.read())
                tmp_path = tmp.name
            raw, parsed, err = load_pcap(tmp_path)
            import gc
            gc.collect()
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            if err:
                st.error(err)
            else:
                st.session_state[f"{key_prefix}_name"] = uploaded.name
                st.session_state[f"{key_prefix}_raw"] = raw
                st.session_state[f"{key_prefix}_parsed"] = parsed
                st.session_state[f"{key_prefix}_uploaded_sig"] = (uploaded.name, uploaded.size)
                st.rerun()

    btn_label = f"⚡ Load Sample: {os.path.basename(default_sample_path)}"
    if st.button(btn_label, key=f"{key_prefix}_sample_btn", use_container_width=True):
        raw, parsed, err = load_pcap(default_sample_path)
        if not err:
            st.session_state[f"{key_prefix}_name"] = os.path.basename(default_sample_path)
            st.session_state[f"{key_prefix}_raw"] = raw
            st.session_state[f"{key_prefix}_parsed"] = parsed
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    return st.session_state.get(f"{key_prefix}_raw"), st.session_state.get(f"{key_prefix}_parsed")


def render_capture_comparison_page():
    # Header Banner
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #E5E9EF; padding-bottom: 12px; margin-bottom: 20px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 2px;">
                    // FORENSIC EXPERIMENTS // DIFFERENTIAL ANALYSIS
                </div>
                <div style="font-size: 1.4rem; font-weight: 700; color: #263238; letter-spacing: -0.02em;">
                    Comparative Packet Capture Analysis
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-teal">BASELINE VS IMPAIRED</span>
                <span class="soc-badge soc-badge-amber">A/B TELEMETRY</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Ingestion Slots
    col_a, col_b = st.columns(2)
    with col_a:
        raw_a, parsed_a = _load_comparison_slot(
            slot_label="Baseline Capture [A] (Healthy / Reference)",
            key_prefix="comp_a",
            default_sample_path="sample_captures/sample_traffic.pcap",
            badge_color="teal"
        )
    with col_b:
        raw_b, parsed_b = _load_comparison_slot(
            slot_label="Comparison Capture [B] (Impaired / Degraded)",
            key_prefix="comp_b",
            default_sample_path="sample_captures/sample_impaired.pcap",
            badge_color="amber"
        )

    # Empty State check
    if not parsed_a or not parsed_b:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px dashed #CBD5E1; border-radius: 8px; padding: 40px; text-align: center; margin-top: 10px; margin-bottom: 20px;">
                <div style="font-size: 2.2rem; margin-bottom: 10px;">⚖️</div>
                <div style="font-size: 1.05rem; font-weight: 600; color: #263238; margin-bottom: 6px;">Differential Analysis Requires Both Ingestion Slots</div>
                <div style="font-size: 0.85rem; color: #718096; max-width: 520px; margin: 0 auto; line-height: 1.5;">
                    Please populate both Slot A (Baseline) and Slot B (Impaired) using the built-in sample buttons above or by uploading custom .pcap / .pcapng files.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        with st.expander("📊 Differential QoS & Network Impairment Analysis Framework", expanded=True):
            st.markdown(
                """
                **Analysis Purpose:**
                Network performance degrades predictably under transmission anomalies (propagation delay, packet loss, queue bufferbloat, and connection resets).
                This differential module measures observable protocol anomalies between two conditions.

                | Condition | Expected Observable Symptom | Detection Metric |
                |---|---|---|
                | **Propagation Latency** | Elongated SYN $\\rightarrow$ SYN-ACK $\\rightarrow$ ACK timing | Initial RTT ($iRTT$) elevation |
                | **Packet Loss** | Duplicate ACKs, Sequence retransmissions | Consecutive identical SEQ/ACK counts |
                | **Window Throttling** | Smaller TCP window advertisements | Reduced throughput & burst size |
                | **Host Unreachable** | Incomplete handshakes or RST generation | Connection state transitions |
                """
            )
        return

    # Process Captures
    df_a = packets_to_dataframe(parsed_a)
    df_b = packets_to_dataframe(parsed_b)
    flows_a = analyze_all_flows(parsed_a)
    flows_b = analyze_all_flows(parsed_b)

    name_a = st.session_state.get("comp_a_name", "Baseline [A]")
    name_b = st.session_state.get("comp_b_name", "Comparison [B]")

    # -----------------------------------------------------------------------
    # Comparative Metric Cards
    # -----------------------------------------------------------------------
    st.markdown(
        """
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #263238; margin: 16px 0 10px 0;">
            // SIDE-BY-SIDE FORENSIC TELEMETRY & DELTA
        </div>
        """,
        unsafe_allow_html=True
    )

    len_a, len_b = len(df_a), len(df_b)
    vol_a = df_a["length"].sum() if "length" in df_a.columns else 0
    vol_b = df_b["length"].sum() if "length" in df_b.columns else 0

    retrans_a = sum(f.get("potential_retransmissions", 0) for f in flows_a)
    retrans_b = sum(f.get("potential_retransmissions", 0) for f in flows_b)

    complete_a = sum(1 for f in flows_a if "Complete" in f.get("tcp_state", "") or "Established" in f.get("tcp_state", ""))
    complete_b = sum(1 for f in flows_b if "Complete" in f.get("tcp_state", "") or "Established" in f.get("tcp_state", ""))

    rtts_a = [f["rtt_ms"] for f in flows_a if f.get("rtt_ms") is not None]
    rtts_b = [f["rtt_ms"] for f in flows_b if f.get("rtt_ms") is not None]
    avg_rtt_a = round(sum(rtts_a) / len(rtts_a), 2) if rtts_a else None
    avg_rtt_b = round(sum(rtts_b) / len(rtts_b), 2) if rtts_b else None

    mc1, mc2, mc3, mc4, mc5 = st.columns(5)

    with mc1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">FRAME COUNT</div>
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-top: 4px;">
                    <div><span style="font-size: 0.72rem; color: #159A91;">A:</span> <b style="color: #263238;">{len_a:,}</b></div>
                    <div><span style="font-size: 0.72rem; color: #D97706;">B:</span> <b style="color: #263238;">{len_b:,}</b></div>
                </div>
                <div class="kpi-sub">Δ: {len_b - len_a:+d} frames</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with mc2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">TOTAL VOLUME</div>
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-top: 4px;">
                    <div><span style="font-size: 0.72rem; color: #159A91;">A:</span> <b style="color: #263238;">{format_bytes(vol_a)}</b></div>
                    <div><span style="font-size: 0.72rem; color: #D97706;">B:</span> <b style="color: #263238;">{format_bytes(vol_b)}</b></div>
                </div>
                <div class="kpi-sub">Δ: {format_bytes(vol_b - vol_a)}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with mc3:
        retrans_delta = retrans_b - retrans_a
        delta_color = "#DC2626" if retrans_delta > 0 else "#059669"
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">RETRANSMISSIONS</div>
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-top: 4px;">
                    <div><span style="font-size: 0.72rem; color: #159A91;">A:</span> <b style="color: #263238;">{retrans_a}</b></div>
                    <div><span style="font-size: 0.72rem; color: #D97706;">B:</span> <b style="color: #263238;">{retrans_b}</b></div>
                </div>
                <div class="kpi-sub" style="color: {delta_color};">Δ: {retrans_delta:+d} anomalies</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with mc4:
        flow_delta = complete_b - complete_a
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">COMPLETED FLOWS</div>
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-top: 4px;">
                    <div><span style="font-size: 0.72rem; color: #159A91;">A:</span> <b style="color: #263238;">{complete_a}</b></div>
                    <div><span style="font-size: 0.72rem; color: #D97706;">B:</span> <b style="color: #263238;">{complete_b}</b></div>
                </div>
                <div class="kpi-sub">Δ: {flow_delta:+d} sessions</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with mc5:
        rtt_str_a = f"{avg_rtt_a} ms" if avg_rtt_a is not None else "—"
        rtt_str_b = f"{avg_rtt_b} ms" if avg_rtt_b is not None else "—"
        if avg_rtt_a is not None and avg_rtt_b is not None:
            rtt_diff = round(avg_rtt_b - avg_rtt_a, 2)
            rtt_diff_str = f"Δ: {rtt_diff:+0.2f} ms"
            diff_color = "#DC2626" if rtt_diff > 0 else "#059669"
        else:
            rtt_diff_str = "Δ: N/A"
            diff_color = "#718096"

        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">AVG HANDSHAKE RTT</div>
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-top: 4px;">
                    <div><span style="font-size: 0.72rem; color: #159A91;">A:</span> <b style="color: #263238;">{rtt_str_a}</b></div>
                    <div><span style="font-size: 0.72rem; color: #D97706;">B:</span> <b style="color: #263238;">{rtt_str_b}</b></div>
                </div>
                <div class="kpi-sub" style="color: {diff_color};">{rtt_diff_str}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # -----------------------------------------------------------------------
    # Comparative Plotly Charts (Grouped Bars)
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)

    with c1:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #263238; margin-bottom: 8px;">
                // PROTOCOL VOLUME COMPARISON
            </div>
            """,
            unsafe_allow_html=True
        )
        proto_a = analyze_protocols(df_a).get("counts", {})
        proto_b = analyze_protocols(df_b).get("counts", {})
        all_protos = sorted(set(list(proto_a.keys()) + list(proto_b.keys())))

        if all_protos:
            comp_data = []
            for p in all_protos:
                comp_data.append({
                    "Protocol": p,
                    f"A: {name_a}": proto_a.get(p, 0),
                    f"B: {name_b}": proto_b.get(p, 0)
                })
            comp_df = pd.DataFrame(comp_data)

            fig_p = go.Figure()
            fig_p.add_trace(go.Bar(
                name=f"A: {name_a}",
                x=comp_df["Protocol"],
                y=comp_df[f"A: {name_a}"],
                marker_color="#159A91",
                text=comp_df[f"A: {name_a}"],
                textposition="outside",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#718096")
            ))
            fig_p.add_trace(go.Bar(
                name=f"B: {name_b}",
                x=comp_df["Protocol"],
                y=comp_df[f"B: {name_b}"],
                marker_color="#D97706",
                text=comp_df[f"B: {name_b}"],
                textposition="outside",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#718096")
            ))
            fig_p.update_layout(
                barmode="group",
                xaxis_title="",
                yaxis_title="Packet Count"
            )
            _apply_light_plotly_layout(fig_p, height=330)
            st.plotly_chart(fig_p, use_container_width=True)

    with c2:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #263238; margin-bottom: 8px;">
                // TCP CONTROL & ANOMALY FLAGS COMPARISON
            </div>
            """,
            unsafe_allow_html=True
        )
        flags_a = analyze_tcp_flags(df_a)
        flags_b = analyze_tcp_flags(df_b)
        all_flags = sorted(set(list(flags_a.keys()) + list(flags_b.keys())))

        if all_flags:
            flag_data = []
            for fl in all_flags:
                flag_data.append({
                    "Flag": fl,
                    f"A: {name_a}": flags_a.get(fl, 0),
                    f"B: {name_b}": flags_b.get(fl, 0)
                })
            flag_df = pd.DataFrame(flag_data)

            fig_f = go.Figure()
            fig_f.add_trace(go.Bar(
                name=f"A: {name_a}",
                x=flag_df["Flag"],
                y=flag_df[f"A: {name_a}"],
                marker_color="#059669",
                text=flag_df[f"A: {name_a}"],
                textposition="outside",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#718096")
            ))
            fig_f.add_trace(go.Bar(
                name=f"B: {name_b}",
                x=flag_df["Flag"],
                y=flag_df[f"B: {name_b}"],
                marker_color="#DC2626",
                text=flag_df[f"B: {name_b}"],
                textposition="outside",
                textfont=dict(family="JetBrains Mono, monospace", size=10, color="#718096")
            ))
            fig_f.update_layout(
                barmode="group",
                xaxis_title="",
                yaxis_title="Flag Count"
            )
            _apply_light_plotly_layout(fig_f, height=330)
            st.plotly_chart(fig_f, use_container_width=True)
        else:
            st.markdown(
                """
                <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 6px; padding: 24px; text-align: center; color: #718096; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
                    NO TCP SEGMENTS IN SELECTED CAPTURES
                </div>
                """,
                unsafe_allow_html=True
            )

    # -----------------------------------------------------------------------
    # DCCN Forensic Conclusion Card
    # -----------------------------------------------------------------------
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    st.markdown(
        f"""
        <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 6px; padding: 14px 18px; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #718096; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
            <div style="color: #159A91; font-weight: 700; margin-bottom: 6px;">// FORENSIC CONCLUSION & TELEMETRY CORRELATION:</div>
            Comparing <b>{name_a}</b> against <b>{name_b}</b> reveals:
            <ul style="margin: 6px 0 6px 18px; padding: 0;">
                <li>Retransmission Differential: <b style="color: {delta_color};">{retrans_delta:+d} anomalous packets</b></li>
                <li>Handshake RTT Latency Shift: <b style="color: #263238;">{rtt_diff_str}</b></li>
                <li>Flow Completion Impact: <b style="color: #263238;">{flow_delta:+d} sessions reached FIN/Established state</b></li>
            </ul>
            <div style="font-size: 0.75rem; color: #94A3B8; margin-top: 6px;">
                Note: In production environments, correlate statistical packet divergence with known test conditions (e.g. simulated delay, loss rate, or firewall dropping) to confirm whether observed deltas stem from network impairment or differing client workload volumes.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    render_contextual_help("comparison")

"""
packet_analysis.py — Unified Wireshark-Inspired 3-Pane Packet Analysis Workspace.

Architecture:
- Top Toolbar: Ingestion controls (Live capture, PCAP/PCAPNG file upload, sample benchmark loader)
  and multi-attribute packet filter matrix (Protocol, IP, Port, Keyword, Time window).
- Pane A (Packet List): Compact, sortable packet table (No., Time, Source, Destination, Protocol, Length, Info).
- Pane B (Packet Details): Real protocol layer hierarchy (Frame → Ethernet II → IPv4/IPv6 → TCP/UDP/ICMP → Application/DNS).
  Expandable per layer, displaying only present fields, with clear technical descriptions and an Advanced Details toggle.
- Pane C (Packet Bytes): Synchronized canonical 16-byte hex dump and ASCII representation.
- Export Toolbar: Export filtered or all captured packets to PCAP.
"""

from __future__ import annotations

import streamlit as st
import pandas as pd
import os
import tempfile
import time
from typing import Dict, Any, List, Optional

from core.pcap_manager import load_pcap, export_pcap, packets_to_dataframe
from core.packet_parser import parse_packet, get_packet_layers
from core.capture import LiveCaptureEngine, is_live_capture_available, get_available_interfaces
from core.explain import explain_packet
from utils.hex_dump import generate_hex_dump, get_raw_bytes
from utils.helpers import format_bytes, format_timestamp
from config.settings import DEFAULT_CAPTURE_LIMIT, MAX_TABLE_DISPLAY_ROWS, CAPTURE_POLL_INTERVAL, PROTOCOL_COLORS
from ui.guided_lab import render_contextual_help


def _get_capture_engine() -> LiveCaptureEngine:
    """Get or create the background capture engine in session state."""
    if "capture_engine" not in st.session_state:
        st.session_state["capture_engine"] = LiveCaptureEngine()
    return st.session_state["capture_engine"]


def render_packet_analysis_page():
    """Render the primary Wireshark-inspired 3-pane packet analysis workspace."""
    engine = _get_capture_engine()

    # Poll live capture if running
    if engine.is_capturing:
        new_pkts = engine.get_new_packets()
        if new_pkts:
            raw_packets = st.session_state.get("packets", [])
            parsed_packets = st.session_state.get("parsed_packets", [])
            start_num = len(parsed_packets) + 1
            for i, pkt in enumerate(new_pkts):
                raw_packets.append(pkt)
                parsed_packets.append(parse_packet(pkt, packet_num=start_num + i))
            st.session_state["packets"] = raw_packets
            st.session_state["raw_packets"] = raw_packets
            st.session_state["parsed_packets"] = parsed_packets

        if engine.error_message:
            st.error(f"Capture Engine Error: {engine.error_message}")
            engine.stop()
            st.session_state["capture_running"] = False

    # Header Bar
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #E5E9EF; padding-bottom: 10px; margin-bottom: 14px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.1em; text-transform: uppercase;">
                    // PRIMARY WORKSPACE // WIRESHARK 3-PANE DISSECTOR
                </div>
                <div style="font-size: 1.35rem; font-weight: 700; color: #263238; letter-spacing: -0.02em;">
                    Packet Analysis
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-teal">LIST • DETAILS • BYTES</span>
                <span class="soc-badge soc-badge-green">PROGRESSIVE DISCLOSURE</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # -----------------------------------------------------------------------
    # Section 1: Capture Ingestion Controls (Collapsible Top Toolbar)
    # -----------------------------------------------------------------------
    with st.expander("📡 Ingestion & Capture Controls", expanded=(len(st.session_state.get("parsed_packets", [])) == 0)):
        source_tab_live, source_tab_file, source_tab_sample = st.tabs([
            "🔴 LIVE SNIFFING", "📂 OPEN PCAP / PCAPNG", "🧪 SAMPLE BENCHMARKS"
        ])

        # --- Subtab A: Live Sniffing ---
        with source_tab_live:
            avail, avail_msg = is_live_capture_available()
            if not avail:
                st.warning(avail_msg)
                st.info("Tip: You can use the 'OPEN PCAP / PCAPNG' or 'SAMPLE BENCHMARKS' tabs to test and analyze full packet traffic offline without Npcap or administrator privileges.")
            else:
                lc1, lc2, lc3 = st.columns([2.5, 1.2, 1.3])
                with lc1:
                    interfaces = get_available_interfaces()
                    if interfaces:
                        iface_options = {iface["description"]: iface["id"] for iface in interfaces}
                        selected_iface_desc = st.selectbox(
                            "Network Interface Adapter",
                            options=list(iface_options.keys()),
                            index=0,
                            key="analysis_iface_select"
                        )
                        selected_iface_id = iface_options[selected_iface_desc]
                    else:
                        st.warning("No physical or virtual network adapters found.")
                        selected_iface_id = None

                with lc2:
                    pkt_limit = st.number_input(
                        "Buffer Limit",
                        min_value=50,
                        max_value=50000,
                        value=DEFAULT_CAPTURE_LIMIT,
                        step=250,
                        key="analysis_limit_input",
                        help="Safety threshold to protect memory"
                    )

                with lc3:
                    bpf_filter = st.text_input(
                        "Driver BPF Filter",
                        placeholder="e.g. tcp port 80 or udp",
                        key="analysis_bpf_input",
                        help="Berkeley Packet Filter applied at driver level"
                    )

                b1, b2, b3 = st.columns([1.2, 1.2, 2.5])
                with b1:
                    if st.button(
                        "▶ START SNIFFING",
                        disabled=engine.is_capturing or selected_iface_id is None,
                        type="primary",
                        use_container_width=True,
                        key="analysis_start_btn"
                    ):
                        st.session_state["packets"] = []
                        st.session_state["raw_packets"] = []
                        st.session_state["parsed_packets"] = []
                        st.session_state["loaded_file"] = None
                        st.session_state["selected_packet_idx"] = 0

                        success, err = engine.start(
                            interface=selected_iface_id,
                            packet_limit=pkt_limit,
                            bpf_filter=bpf_filter
                        )
                        if success:
                            st.session_state["capture_running"] = True
                            st.session_state["loaded_file"] = f"Live Interface ({selected_iface_id})"
                            st.rerun()
                        else:
                            st.error(f"Failed to bind socket: {err}")

                with b2:
                    if st.button(
                        "⏹ STOP SNIFFING",
                        disabled=not engine.is_capturing,
                        use_container_width=True,
                        key="analysis_stop_btn"
                    ):
                        engine.stop()
                        st.session_state["capture_running"] = False
                        st.rerun()

                with b3:
                    curr_count = len(st.session_state.get("parsed_packets", []))
                    status_badge = '<span class="status-badge badge-active">● CAPTURING</span>' if engine.is_capturing else '<span class="status-badge badge-inactive">○ IDLE</span>'
                    st.markdown(
                        f"<div style='padding-top: 6px; font-family: JetBrains Mono; font-size: 0.8rem; color: #718096;'>"
                        f"STATUS: {status_badge} &nbsp;|&nbsp; BUFFER: <span style='color: #159A91; font-weight: 700;'>{curr_count:,}</span> / {engine.packet_limit:,} PKTS"
                        f"</div>",
                        unsafe_allow_html=True
                    )

            if engine.is_capturing:
                time.sleep(CAPTURE_POLL_INTERVAL)
                st.rerun()

        # --- Subtab B: Open PCAP File ---
        with source_tab_file:
            uploaded_file = st.file_uploader(
                "Choose a PCAP / PCAPNG capture file",
                type=["pcap", "pcapng", "cap"],
                label_visibility="collapsed",
                key="analysis_file_uploader"
            )
            if uploaded_file is not None:
                if st.session_state.get("last_uploaded_name") != uploaded_file.name:
                    engine.stop()
                    st.session_state["capture_running"] = False

                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                        tmp.write(uploaded_file.read())
                        tmp_path = tmp.name

                    raw_pkts, parsed_pkts, err = load_pcap(tmp_path)
                    import gc
                    gc.collect()
                    if os.path.exists(tmp_path):
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass

                    if err:
                        st.error(f"PCAP Ingestion Error: {err}")
                    else:
                        st.session_state["packets"] = raw_pkts
                        st.session_state["raw_packets"] = raw_pkts
                        st.session_state["parsed_packets"] = parsed_pkts
                        st.session_state["loaded_file"] = uploaded_file.name
                        st.session_state["last_uploaded_name"] = uploaded_file.name
                        st.session_state["selected_packet_idx"] = 0
                        st.success(f"Loaded {len(raw_pkts):,} frames from {uploaded_file.name}")
                        st.rerun()

        # --- Subtab C: Sample Benchmarks ---
        with source_tab_sample:
            sc1, sc2, sc3 = st.columns(3)
            with sc1:
                if st.button("⚡ Load 7-Protocol Suite", key="analysis_smp_suite_btn", use_container_width=True, type="primary"):
                    engine.stop()
                    st.session_state["capture_running"] = False
                    raw_pkts, parsed_pkts, err = load_pcap("sample_captures/synthetic_protocol_suite.pcap")
                    if not err:
                        st.session_state["packets"] = raw_pkts
                        st.session_state["raw_packets"] = raw_pkts
                        st.session_state["parsed_packets"] = parsed_pkts
                        st.session_state["loaded_file"] = "synthetic_protocol_suite.pcap [7-PROTOCOL SUITE]"
                        st.session_state["selected_packet_idx"] = 0
                        st.session_state["is_synthetic"] = True
                        st.rerun()
                    else:
                        st.error(err)
            with sc2:
                if st.button("📁 Load Enterprise Baseline", key="analysis_smp_base_btn", use_container_width=True):
                    engine.stop()
                    st.session_state["capture_running"] = False
                    raw_pkts, parsed_pkts, err = load_pcap("sample_captures/sample_traffic.pcap")
                    if not err:
                        st.session_state["packets"] = raw_pkts
                        st.session_state["raw_packets"] = raw_pkts
                        st.session_state["parsed_packets"] = parsed_pkts
                        st.session_state["loaded_file"] = "sample_traffic.pcap [BASELINE]"
                        st.session_state["selected_packet_idx"] = 0
                        st.session_state["is_synthetic"] = True
                        st.rerun()
                    else:
                        st.error(err)
            with sc3:
                if st.button("⚠️ Load Impaired Traffic", key="analysis_smp_imp_btn", use_container_width=True):
                    engine.stop()
                    st.session_state["capture_running"] = False
                    raw_pkts, parsed_pkts, err = load_pcap("sample_captures/sample_impaired.pcap")
                    if not err:
                        st.session_state["packets"] = raw_pkts
                        st.session_state["raw_packets"] = raw_pkts
                        st.session_state["parsed_packets"] = parsed_pkts
                        st.session_state["loaded_file"] = "sample_impaired.pcap [IMPAIRED EXPERIMENT]"
                        st.session_state["selected_packet_idx"] = 0
                        st.session_state["is_synthetic"] = True
                        st.rerun()
                    else:
                        st.error(err)

    parsed_packets = st.session_state.get("parsed_packets", [])
    raw_packets = st.session_state.get("raw_packets") or st.session_state.get("packets", [])

    # Empty State
    if not parsed_packets:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px dashed #CBD5E1; border-radius: 8px; padding: 48px; text-align: center; margin-top: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <div style="font-size: 2.2rem; margin-bottom: 10px;">🔍</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #263238; margin-bottom: 6px;">No Packet Capture Loaded</div>
                <div style="font-size: 0.85rem; color: #718096; max-width: 500px; margin: 0 auto 18px auto; line-height: 1.5;">
                    To begin analyzing, open the ingestion toolbar above to sniff live traffic from your network adapter or open a recorded PCAP file.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    df = packets_to_dataframe(parsed_packets)

    # -----------------------------------------------------------------------
    # Section 2: Multi-Parameter Filter Bar
    # -----------------------------------------------------------------------
    st.markdown("<span class='soc-tag'>// DISPLAY FILTER</span>", unsafe_allow_html=True)
    fcol1, fcol2, fcol3, fcol4, fcol5 = st.columns([1.5, 1.4, 1.2, 2.0, 0.9])

    all_protocols = sorted([p for p in df["protocol"].unique() if p != "—"])
    with fcol1:
        selected_protocols = st.multiselect(
            "Protocol Filter", options=all_protocols, default=[], placeholder="All protocols", key="analysis_proto_filter"
        )
    with fcol2:
        ip_query = st.text_input("IP Address Filter", placeholder="e.g. 192.168.1.1", key="analysis_ip_filter").strip()
    with fcol3:
        port_query = st.text_input("Port Filter", placeholder="e.g. 80, 443, 53", key="analysis_port_filter").strip()
    with fcol4:
        keyword = st.text_input("Search Info / Content", placeholder="e.g. SYN, google, GET, RST...", key="analysis_kw_filter").strip()
    with fcol5:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🔄 Reset", key="analysis_reset_filters_btn", use_container_width=True, help="Reset all display filters"):
            st.session_state["analysis_proto_filter"] = []
            st.session_state["analysis_ip_filter"] = ""
            st.session_state["analysis_port_filter"] = ""
            st.session_state["analysis_kw_filter"] = ""
            st.rerun()

    # Time range slider filter
    time_filtered = False
    time_min_val, time_max_val = 0.0, 0.0
    start_ts = 0.0
    if "timestamp" in df.columns and df["timestamp"].dropna().nunique() > 1:
        ts_valid = df["timestamp"].dropna()
        start_ts = float(ts_valid.min())
        end_ts = float(ts_valid.max())
        elapsed_total = round(end_ts - start_ts, 3)
        if elapsed_total > 0.01:
            time_range = st.slider(
                "Time Window Filter (Relative Elapsed Seconds)",
                min_value=0.0,
                max_value=elapsed_total,
                value=(0.0, elapsed_total),
                step=0.01,
                key="analysis_time_filter"
            )
            time_filtered = True
            time_min_val, time_max_val = time_range

    # Apply filters
    filtered_df = df.copy()

    if selected_protocols:
        proto_mask = filtered_df["protocol"].isin(selected_protocols)
        if "TCP" in selected_protocols and "tcp_sport" in filtered_df.columns:
            proto_mask |= filtered_df["tcp_sport"].notna()
        if "UDP" in selected_protocols and "udp_sport" in filtered_df.columns:
            proto_mask |= filtered_df["udp_sport"].notna()
        filtered_df = filtered_df[proto_mask]

    if ip_query:
        filtered_df = filtered_df[
            (filtered_df["src_ip"].astype(str).str.contains(ip_query, case=False, na=False)) |
            (filtered_df["dst_ip"].astype(str).str.contains(ip_query, case=False, na=False))
        ]

    if port_query:
        try:
            target_port = int(port_query)
            filtered_df = filtered_df[
                (pd.to_numeric(filtered_df["src_port"], errors="coerce") == target_port) |
                (pd.to_numeric(filtered_df["dst_port"], errors="coerce") == target_port)
            ]
        except ValueError:
            filtered_df = filtered_df[
                (filtered_df["src_port"].astype(str) == port_query) |
                (filtered_df["dst_port"].astype(str) == port_query)
            ]

    if keyword:
        filtered_df = filtered_df[
            (filtered_df["info"].astype(str).str.contains(keyword, case=False, na=False)) |
            (filtered_df["protocol"].astype(str).str.contains(keyword, case=False, na=False))
        ]

    if time_filtered and "timestamp" in filtered_df.columns:
        ts_series = filtered_df["timestamp"] - start_ts
        filtered_df = filtered_df[(ts_series >= time_min_val) & (ts_series <= time_max_val)]

    # -----------------------------------------------------------------------
    # PANE A: PACKET LIST
    # -----------------------------------------------------------------------
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 8px; margin-bottom: 4px;">
            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #263238;">
                PANE A: PACKET LIST ({len(filtered_df):,} of {len(df):,} frames matching)
            </span>
            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #718096;">
                Click any row or use frame selector to dissect
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

    display_columns = [
        "num", "timestamp_str", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "length",
        "tcp_flags", "info"
    ]
    column_renames = {
        "num": "No.", "timestamp_str": "Time", "src_ip": "Source",
        "dst_ip": "Destination", "src_port": "SPort", "dst_port": "DPort",
        "protocol": "Protocol", "length": "Length", "tcp_flags": "Flags", "info": "Info"
    }

    table_df = filtered_df[display_columns].rename(columns=column_renames).head(MAX_TABLE_DISPLAY_ROWS)
    table_selection = st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
        height=260,
        selection_mode="single-row",
        on_select="rerun",
        key="analysis_packet_table_widget",
        column_config={
            "No.": st.column_config.NumberColumn(width="small"),
            "Time": st.column_config.TextColumn(width="medium"),
            "Source": st.column_config.TextColumn(width="medium"),
            "Destination": st.column_config.TextColumn(width="medium"),
            "SPort": st.column_config.TextColumn(width="small"),
            "DPort": st.column_config.TextColumn(width="small"),
            "Protocol": st.column_config.TextColumn(width="small"),
            "Length": st.column_config.NumberColumn(format="%d B", width="small"),
            "Flags": st.column_config.TextColumn(width="small"),
            "Info": st.column_config.TextColumn(width="large"),
        }
    )

    # -----------------------------------------------------------------------
    # Packet Selection Controller
    # -----------------------------------------------------------------------
    available_nums = filtered_df["num"].tolist() if not filtered_df.empty else []
    if not available_nums:
        st.info("No packets match the current filter criteria.")
        return

    # Check if user clicked a row in the table
    if table_selection and hasattr(table_selection, "selection") and table_selection.selection:
        selected_rows = table_selection.selection.get("rows", [])
        if selected_rows:
            clicked_row_idx = selected_rows[0]
            if 0 <= clicked_row_idx < len(table_df):
                clicked_frame_num = int(table_df.iloc[clicked_row_idx]["No."])
                if clicked_frame_num - 1 != st.session_state.get("selected_packet_idx"):
                    st.session_state["selected_packet_idx"] = clicked_frame_num - 1

    curr_selected_idx = st.session_state.get("selected_packet_idx", 0)
    if curr_selected_idx is None or curr_selected_idx < 0 or curr_selected_idx >= len(parsed_packets):
        curr_selected_idx = 0
        st.session_state["selected_packet_idx"] = 0

    default_sel_num = parsed_packets[curr_selected_idx].get("num")
    if default_sel_num not in available_nums:
        default_sel_num = available_nums[0]
        st.session_state["selected_packet_idx"] = default_sel_num - 1

    sel_col1, sel_col2, sel_col3 = st.columns([2.5, 1.2, 1.3])
    with sel_col1:
        chosen_num = st.selectbox(
            "Selected Frame for Dissection",
            options=available_nums,
            index=available_nums.index(default_sel_num),
            format_func=lambda n: f"Frame #{n:03d} | {df[df['num'] == n]['protocol'].values[0]} | {df[df['num'] == n]['src_ip'].values[0]} → {df[df['num'] == n]['dst_ip'].values[0]} ({df[df['num'] == n]['length'].values[0]} Bytes)",
            key="analysis_frame_selector"
        )
        if chosen_num - 1 != curr_selected_idx:
            st.session_state["selected_packet_idx"] = chosen_num - 1
            st.rerun()

    active_idx = chosen_num - 1
    active_parsed = parsed_packets[active_idx]
    active_raw = raw_packets[active_idx] if active_idx < len(raw_packets) else None

    with sel_col2:
        adv_details_mode = st.toggle("Advanced Details Mode", value=False, key="analysis_adv_toggle", help="Expose raw protocol flags, byte offsets, and checksums")

    with sel_col3:
        matching_indices = [n - 1 for n in available_nums]
        pkts_to_export = [raw_packets[i] for i in matching_indices if i < len(raw_packets)]

        # Prepare in-memory PCAP bytes for direct browser download
        import io
        from scapy.utils import PcapWriter
        buf = io.BytesIO()
        writer = PcapWriter(buf, sync=True)
        for p in pkts_to_export:
            writer.write(p)
        writer.flush()
        pcap_data = buf.getvalue()

        st.download_button(
            label=f"💾 Download PCAP ({len(pkts_to_export)} pkts)",
            data=pcap_data,
            file_name="capture_export.pcap",
            mime="application/vnd.tcpdump.pcap",
            use_container_width=True,
            key="analysis_download_pcap_btn"
        )

    # -----------------------------------------------------------------------
    # Panes B & C: Side-by-Side (Details on Left, Raw Bytes on Right)
    # -----------------------------------------------------------------------
    pane_b_col, pane_c_col = st.columns([1.1, 0.9])

    # --- PANE B: PACKET DETAILS ---
    with pane_b_col:
        st.markdown(
            f"""
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #159A91; margin-bottom: 6px;">
                PANE B: PACKET DETAILS (Frame #{chosen_num:03d} — {active_parsed.get('protocol')})
            </div>
            """,
            unsafe_allow_html=True
        )

        if active_raw is not None:
            layers = get_packet_layers(active_raw)

            # Frame Summary Card
            wire_len = active_parsed.get("length", 0)
            t_curr = active_parsed.get("timestamp")
            t_start = parsed_packets[0].get("timestamp") if parsed_packets else None
            rel_t_str = f"+{(t_curr - t_start):.6f}s" if (t_curr is not None and t_start is not None) else "0.000s"

            with st.expander(f"📦 Frame {chosen_num}: {wire_len} bytes on wire ({wire_len * 8} bits), arrival delta {rel_t_str}", expanded=False):
                st.markdown(
                    f"""
                    - **Arrival Time:** {active_parsed.get('timestamp_str')} (Epoch: `{t_curr}`)
                    - **Frame Number:** #{chosen_num} in capture buffer
                    - **Frame Length on Wire:** {wire_len} bytes ({wire_len * 8} bits)
                    - **Encapsulated Protocol Stack:** {' → '.join([l['name'] for l in layers])}
                    """
                )

            # Render protocol layers in natural top-down encapsulation order (Data Link → Network → Transport → Application)
            for l_idx, layer in enumerate(layers):
                l_name = layer["name"]
                l_pdu = layer.get("pdu_name", "PDU")
                l_color = PROTOCOL_COLORS.get(l_name, "#159A91")
                l_fields = layer.get("fields", {})
                l_highlights = layer.get("highlights", {})

                # Layer header expander
                is_expanded = (l_idx >= len(layers) - 2)  # Expand upper layers by default
                exp_title = f"{layer.get('icon', '📦')} {l_name} [{layer['osi_layer']}] ({layer.get('header_len', 0)} bytes)"

                with st.expander(exp_title, expanded=is_expanded):
                    # Key field badges
                    if l_highlights:
                        badges = [f"<b>{k}:</b> {v}" for k, v in l_highlights.items()]
                        st.markdown(
                            f"<div style='font-family: JetBrains Mono; font-size: 0.78rem; color: #159A91; background: #DDF3ED; padding: 6px 10px; border-left: 3px solid #159A91; border-radius: 4px; margin-bottom: 8px;'>"
                            f"{' &nbsp;•&nbsp; '.join(badges)}"
                            f"</div>",
                            unsafe_allow_html=True
                        )

                    # Fields table
                    field_rows = []
                    for f_name, f_info in l_fields.items():
                        field_rows.append({
                            "Field": f_name,
                            "Captured Value": str(f_info.get("value", "")),
                            "Technical Role": f_info.get("explanation", "")
                        })

                    if field_rows:
                        f_df = pd.DataFrame(field_rows)
                        st.dataframe(f_df, use_container_width=True, hide_index=True)

                    # In Advanced Details mode, expose raw properties
                    if adv_details_mode:
                        st.caption(f"Raw Scapy Object: `{type(active_raw.getlayer(l_idx)).__name__}` | Wire Header Size: {layer.get('header_len', 0)} bytes")

            # Plain-English technical explanation
            exp_data = explain_packet(active_parsed)
            with st.expander("🧠 Plain-English Packet Explanation", expanded=False):
                st.markdown(f"**Forensic Role:** {exp_data.get('summary')}")
                for takeaway in exp_data.get("takeaways", []):
                    st.markdown(f"- <span style='font-size: 0.82rem; color: #263238;'>{takeaway}</span>", unsafe_allow_html=True)
        else:
            st.warning("Raw Scapy packet object unavailable for layer breakdown.")

    # --- PANE C: PACKET BYTES ---
    with pane_c_col:
        st.markdown(
            f"""
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #0D9488; margin-bottom: 6px;">
                PANE C: PACKET BYTES (Canonical Hex & ASCII Dump)
            </div>
            """,
            unsafe_allow_html=True
        )

        if active_raw is not None:
            raw_data = get_raw_bytes(active_raw)
            dump_text = generate_hex_dump(raw_data)
            st.markdown(f"<div class='hex-display' style='max-height: 480px; overflow-y: auto;'><pre>{dump_text}</pre></div>", unsafe_allow_html=True)
            st.markdown(
                f"""
                <div style="display: flex; justify-content: space-between; margin-top: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.74rem; color: #718096;">
                    <span>Size: <b style="color: #159A91;">{len(raw_data)} bytes</b></span>
                    <span>Offsets: <b style="color: #263238;">0x0000 – 0x{len(raw_data)-1:04X}</b></span>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.caption("No raw byte representation available.")

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
    render_contextual_help("packet_inspector")

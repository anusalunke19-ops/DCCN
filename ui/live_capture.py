"""
live_capture.py — Technical Wireshark & SOC-Inspired Live Capture & Packet Explorer.

Provides:
- Interface selection & hardware enumeration
- Start / stop sniffing controls with real-time capture status banner
- Multi-parameter filtering (protocol, IP, numeric port, text, time range)
- Dense, scrollable packet table with interactive row selection
- Direct in-memory PCAP download and seamless Packet Inspector navigation
"""

import streamlit as st
import pandas as pd
import os
import tempfile
import time
import io
from scapy.utils import PcapWriter

from core.pcap_manager import load_pcap, export_pcap, packets_to_dataframe
from core.packet_parser import parse_packet
from core.capture import LiveCaptureEngine, is_live_capture_available, get_available_interfaces
from config.settings import DEFAULT_CAPTURE_LIMIT, MAX_TABLE_DISPLAY_ROWS, CAPTURE_POLL_INTERVAL
from ui.guided_lab import render_contextual_help


def _get_capture_engine() -> LiveCaptureEngine:
    """Get or create the capture engine in session state."""
    if "capture_engine" not in st.session_state:
        st.session_state["capture_engine"] = LiveCaptureEngine()
    return st.session_state["capture_engine"]


def _navigate(page: str):
    """Safely switch workspace and ensure all sidebar and top-nav state stays synchronized."""
    st.session_state["current_page"] = page
    st.session_state["sidebar_workspace_radio"] = page
    st.rerun()


def render_live_capture_page():
    # Header Banner
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #E5E9EF; padding-bottom: 10px; margin-bottom: 14px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.1em; text-transform: uppercase;">
                    // INGESTION ENGINE // PACKET EXPLORER
                </div>
                <div style="font-size: 1.35rem; font-weight: 700; color: #263238; letter-spacing: -0.02em;">
                    Live Packet Capture & Ingestion
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-teal">L2–L7 CAPTURE</span>
                <span class="soc-badge soc-badge-green">BUFFER ENGINE</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    engine = _get_capture_engine()

    # If capture is active, poll for new packets
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

    # -----------------------------------------------------------------------
    # Section 1: Capture Ingestion Source Tabs
    # -----------------------------------------------------------------------
    source_tab_live, source_tab_file, source_tab_sample = st.tabs([
        "🔴 LIVE PACKET CAPTURE", "📂 LOAD PCAP / PCAPNG", "🧪 SAMPLE BENCHMARKS"
    ])

    # --- Live Capture Tab ---
    with source_tab_live:
        avail, avail_msg = is_live_capture_available()

        if not avail:
            st.markdown(
                f"""
                <div style="background: #FFFBEB; border: 1px solid #FDE68A; border-left: 3px solid #D97706; border-radius: 6px; padding: 12px 16px; margin-bottom: 12px;">
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; font-weight: 700; color: #D97706; margin-bottom: 4px;">
                        ⚠️ LIVE SNIFFING RESTRICTED
                    </div>
                    <div style="font-size: 0.82rem; color: #718096; line-height: 1.4;">
                        {avail_msg}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            st.info("Tip: You can use the 'LOAD PCAP / PCAPNG' or 'SAMPLE BENCHMARKS' tabs above to explore all features offline without Npcap or admin rights.")
        else:
            lc1, lc2, lc3 = st.columns([2.5, 1.2, 1.3])

            with lc1:
                interfaces = get_available_interfaces()
                if interfaces:
                    iface_options = {iface["description"]: iface["id"] for iface in interfaces}
                    selected_iface_desc = st.selectbox(
                        "Network Adapter Interface",
                        options=list(iface_options.keys()),
                        index=0,
                        key="live_nic_selector"
                    )
                    selected_iface_id = iface_options[selected_iface_desc]
                else:
                    st.warning("No physical/virtual network adapters found.")
                    selected_iface_id = None

            with lc2:
                pkt_limit = st.number_input(
                    "Buffer Limit",
                    min_value=50,
                    max_value=50000,
                    value=DEFAULT_CAPTURE_LIMIT,
                    step=250,
                    help="Automatic stop threshold to protect system memory",
                    key="live_buffer_limit"
                )

            with lc3:
                bpf_filter = st.text_input(
                    "BPF Filter Expression",
                    placeholder="e.g. tcp port 80 or udp",
                    help="Berkeley Packet Filter syntax applied at driver level",
                    key="live_bpf_filter_input"
                )

            b1, b2, b3 = st.columns([1.2, 1.2, 2.5])

            with b1:
                if st.button(
                    "▶ START SNIFFING",
                    disabled=engine.is_capturing or selected_iface_id is None,
                    type="primary",
                    use_container_width=True,
                    key="live_start_btn"
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
                    key="live_stop_btn"
                ):
                    engine.stop()
                    st.session_state["capture_running"] = False
                    st.rerun()

            with b3:
                curr_count = len(st.session_state.get("parsed_packets", []))
                status_badge = '<span class="status-badge badge-active">● SNIFFING ACTIVE</span>' if engine.is_capturing else '<span class="status-badge badge-inactive">○ IDLE</span>'
                st.markdown(
                    f"<div style='padding-top: 6px; font-family: JetBrains Mono; font-size: 0.8rem; color: #718096;'>"
                    f"STATUS: {status_badge} &nbsp;|&nbsp; BUFFER: <span style='color: #159A91; font-weight: 700;'>{curr_count:,}</span> / {engine.packet_limit:,} PKTS"
                    f"</div>",
                    unsafe_allow_html=True
                )

        if engine.is_capturing:
            time.sleep(CAPTURE_POLL_INTERVAL)
            st.rerun()

    # --- File Upload Tab ---
    with source_tab_file:
        uploaded_file = st.file_uploader(
            "Select PCAP or PCAPNG capture file",
            type=["pcap", "pcapng", "cap"],
            label_visibility="collapsed",
            key="live_file_uploader"
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

    # --- Built-in Samples Tab ---
    with source_tab_sample:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; text-transform: uppercase; margin-bottom: 8px;">
                // REPRODUCIBLE SYNTHETIC CAPTURE BENCHMARKS (NO PRIVILEGES REQUIRED)
            </div>
            """,
            unsafe_allow_html=True
        )
        smp_col1, smp_col2, smp_col3 = st.columns(3)
        with smp_col1:
            st.markdown("""
            <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 3px solid #159A91; padding: 12px; border-radius: 6px; min-height: 140px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <div style="font-family: JetBrains Mono; font-size: 0.8rem; color: #159A91; font-weight: 700;">
                    SYNTHETIC 7-PROTOCOL SUITE
                </div>
                <div style="font-size: 0.75rem; color: #718096; margin: 6px 0 10px 0; line-height: 1.4;">
                    Complete DCCN protocol spectrum: DNS query/response, TCP handshake, data, teardown, UDP, ICMP ping, and native IPv6 traffic.
                </div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("Load 7-Protocol Suite", key="live_load_suite_btn", use_container_width=True, type="primary"):
                engine.stop()
                st.session_state["capture_running"] = False
                raw_pkts, parsed_pkts, err = load_pcap("sample_captures/synthetic_protocol_suite.pcap")
                if not err:
                    st.session_state["packets"] = raw_pkts
                    st.session_state["raw_packets"] = raw_pkts
                    st.session_state["parsed_packets"] = parsed_pkts
                    st.session_state["loaded_file"] = "synthetic_protocol_suite.pcap [SYNTHETIC SUITE]"
                    st.session_state["selected_packet_idx"] = 0
                    st.session_state["is_synthetic"] = True
                    st.rerun()
                else:
                    st.error(err)

        with smp_col2:
            st.markdown("""
            <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 3px solid #059669; padding: 12px; border-radius: 6px; min-height: 140px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <div style="font-family: JetBrains Mono; font-size: 0.8rem; color: #059669; font-weight: 700;">
                    ENTERPRISE BASELINE TRAFFIC
                </div>
                <div style="font-size: 0.75rem; color: #718096; margin: 6px 0 10px 0; line-height: 1.4;">
                    Normal HTTP/HTTPS web sessions, DNS resolutions, NTP synchronization, and TCP RST connection refused.
                </div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("Load Baseline Traffic", key="live_load_base_btn", use_container_width=True):
                engine.stop()
                st.session_state["capture_running"] = False
                raw_pkts, parsed_pkts, err = load_pcap("sample_captures/sample_traffic.pcap")
                if not err:
                    st.session_state["packets"] = raw_pkts
                    st.session_state["raw_packets"] = raw_pkts
                    st.session_state["parsed_packets"] = parsed_pkts
                    st.session_state["loaded_file"] = "sample_traffic.pcap [SYNTHETIC BASELINE]"
                    st.session_state["selected_packet_idx"] = 0
                    st.session_state["is_synthetic"] = True
                    st.rerun()
                else:
                    st.error(err)

        with smp_col3:
            st.markdown("""
            <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 3px solid #D97706; padding: 12px; border-radius: 6px; min-height: 140px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <div style="font-family: JetBrains Mono; font-size: 0.8rem; color: #D97706; font-weight: 700;">
                    IMPAIRED NETWORK CAPTURE
                </div>
                <div style="font-size: 0.75rem; color: #718096; margin: 6px 0 10px 0; line-height: 1.4;">
                    Controlled 220ms latency, TCP retransmissions with exponential backoff, and unacknowledged dropped SYNs.
                </div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("Load Impaired Network", key="live_load_imp_btn", use_container_width=True):
                engine.stop()
                st.session_state["capture_running"] = False
                raw_pkts, parsed_pkts, err = load_pcap("sample_captures/sample_impaired.pcap")
                if not err:
                    st.session_state["packets"] = raw_pkts
                    st.session_state["raw_packets"] = raw_pkts
                    st.session_state["parsed_packets"] = parsed_pkts
                    st.session_state["loaded_file"] = "sample_impaired.pcap [SYNTHETIC IMPAIRED]"
                    st.session_state["selected_packet_idx"] = 0
                    st.session_state["is_synthetic"] = True
                    st.rerun()
                else:
                    st.error(err)

    parsed_packets = st.session_state.get("parsed_packets", [])
    if not parsed_packets:
        st.divider()
        st.info("💡 No packets in memory buffer. Ingest a PCAP file or start a capture session above to view live frames.")
        return

    df = packets_to_dataframe(parsed_packets)

    # -----------------------------------------------------------------------
    # Section 2: Multi-Parameter Filtering Bar
    # -----------------------------------------------------------------------
    st.divider()
    st.markdown("<span class='soc-tag'>// FILTER MATRIX</span>", unsafe_allow_html=True)
    st.markdown("<div style='font-size: 0.95rem; font-weight: 700; color: #263238; margin-bottom: 6px;'>Traffic Slicing & Packet Filters</div>", unsafe_allow_html=True)

    fcol1, fcol2, fcol3, fcol4, fcol5 = st.columns([1.5, 1.3, 1.1, 1.8, 0.9])

    all_protocols = sorted([p for p in df["protocol"].unique() if p != "—"])
    with fcol1:
        selected_protocols = st.multiselect(
            "Protocols", options=all_protocols, default=[], placeholder="All protocols", key="live_filter_proto"
        )
    with fcol2:
        ip_query = st.text_input("IP Address Endpoint", placeholder="e.g. 192.168.1.100", key="live_filter_ip").strip()
    with fcol3:
        port_query = st.text_input("Service Port", placeholder="e.g. 80, 443, 53", key="live_filter_port").strip()
    with fcol4:
        keyword = st.text_input("Payload / Info Match", placeholder="e.g. SYN, google, GET, RST...", key="live_filter_kw").strip()
    with fcol5:
        st.write("")
        st.write("")
        if st.button("Reset Filters", key="live_reset_filters_btn", use_container_width=True):
            st.session_state["live_filter_proto"] = []
            st.session_state["live_filter_ip"] = ""
            st.session_state["live_filter_port"] = ""
            st.session_state["live_filter_kw"] = ""
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
                key="live_time_range_slider"
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

    # Metrics summary bar
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Loaded in Buffer", f"{len(df):,} PKTS")
    with m2: st.metric("Passing Filters", f"{len(filtered_df):,} PKTS")
    with m3:
        total_bytes = filtered_df["length"].sum() if not filtered_df.empty else 0
        st.metric("Filtered Volume", f"{total_bytes:,} B")
    with m4:
        proto_count = filtered_df["protocol"].nunique() if not filtered_df.empty else 0
        st.metric("Protocols Active", f"{proto_count}")

    # -----------------------------------------------------------------------
    # Section 3: Dense Scrollable Packet Table with Interactive Selection
    # -----------------------------------------------------------------------
    st.markdown("<span class='soc-tag'>// FRAME BUFFER</span>", unsafe_allow_html=True)
    st.markdown("<div style='font-size: 0.95rem; font-weight: 700; color: #263238; margin-bottom: 6px;'>Frame Dissection Table (Click a row to select)</div>", unsafe_allow_html=True)

    display_columns = [
        "num", "timestamp_str", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "length",
        "tcp_flags", "info"
    ]
    column_renames = {
        "num": "No.", "timestamp_str": "Timestamp", "src_ip": "Source Address",
        "dst_ip": "Destination Address", "src_port": "SPort", "dst_port": "DPort",
        "protocol": "Proto", "length": "Bytes", "tcp_flags": "Flags", "info": "Forensic Summary / Info"
    }

    table_df = filtered_df[display_columns].rename(columns=column_renames).head(MAX_TABLE_DISPLAY_ROWS)
    table_selection = st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun",
        key="live_packet_table_widget",
        column_config={
            "No.": st.column_config.NumberColumn(width="small"),
            "Timestamp": st.column_config.TextColumn(width="medium"),
            "Source Address": st.column_config.TextColumn(width="medium"),
            "Destination Address": st.column_config.TextColumn(width="medium"),
            "SPort": st.column_config.TextColumn(width="small"),
            "DPort": st.column_config.TextColumn(width="small"),
            "Proto": st.column_config.TextColumn(width="small"),
            "Bytes": st.column_config.NumberColumn(format="%d B", width="small"),
            "Flags": st.column_config.TextColumn(width="small"),
            "Forensic Summary / Info": st.column_config.TextColumn(width="large"),
        }
    )

    # Sync selection from dataframe row click
    if table_selection and hasattr(table_selection, "selection"):
        selected_rows = table_selection.selection.get("rows", [])
        if selected_rows:
            clicked_idx = selected_rows[0]
            if clicked_idx < len(table_df):
                selected_frame_num = int(table_df.iloc[clicked_idx]["No."])
                st.session_state["selected_packet_idx"] = selected_frame_num - 1
                st.session_state["live_frame_select_dropdown"] = selected_frame_num

    # -----------------------------------------------------------------------
    # Section 4: Packet Selection & Export Toolbar
    # -----------------------------------------------------------------------
    st.divider()
    scol1, scol2 = st.columns([3, 2])

    with scol1:
        st.markdown("<span class='soc-tag'>// INSPECT FRAME</span>", unsafe_allow_html=True)
        available_nums = filtered_df["num"].tolist() if not filtered_df.empty else []
        if available_nums:
            curr_selected = st.session_state.get("selected_packet_idx", 0)
            default_index = 0
            if curr_selected is not None and curr_selected < len(parsed_packets):
                pkt_num = parsed_packets[curr_selected].get("num")
                if pkt_num in available_nums:
                    default_index = available_nums.index(pkt_num)

            sel_col1, sel_col2 = st.columns([2.5, 1.5])
            with sel_col1:
                if st.session_state.get("live_frame_select_dropdown") not in available_nums:
                    st.session_state["live_frame_select_dropdown"] = available_nums[default_index]

                def _on_live_dropdown_change():
                    ch = st.session_state.get("live_frame_select_dropdown")
                    if ch is not None:
                        st.session_state["selected_packet_idx"] = ch - 1

                selected_num = st.selectbox(
                    "Selected Frame",
                    options=available_nums,
                    format_func=lambda n: f"Frame #{n:03d} | {df[df['num'] == n]['protocol'].values[0]} | {df[df['num'] == n]['src_ip'].values[0]} → {df[df['num'] == n]['dst_ip'].values[0]}",
                    key="live_frame_select_dropdown",
                    label_visibility="collapsed",
                    on_change=_on_live_dropdown_change
                )

            with sel_col2:
                if st.button("🔬 Open in Packet Inspector", type="primary", use_container_width=True, key="live_goto_inspector_btn"):
                    st.session_state["selected_packet_idx"] = selected_num - 1
                    _navigate("🔍 Packet Inspector")

    with scol2:
        st.markdown("<span class='soc-tag'>// EXPORT ARTIFACT</span>", unsafe_allow_html=True)
        raw_packets = st.session_state.get("packets", [])
        matching_indices = [n - 1 for n in filtered_df["num"].tolist()]
        pkts_to_export = [raw_packets[i] for i in matching_indices if i < len(raw_packets)]

        if pkts_to_export:
            pcap_buffer = io.BytesIO()
            writer = PcapWriter(pcap_buffer, sync=True)
            for pkt in pkts_to_export:
                writer.write(pkt)
            pcap_bytes = pcap_buffer.getvalue()

            st.download_button(
                label=f"💾 Download PCAP ({len(pkts_to_export):,} Packets)",
                data=pcap_bytes,
                file_name="capture_export.pcap",
                mime="application/vnd.tcpdump.pcap",
                use_container_width=True,
                key="live_download_pcap_btn"
            )
        else:
            st.button("💾 Download PCAP (0 Packets)", disabled=True, use_container_width=True, key="live_no_export_btn")

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    render_contextual_help("live_capture")

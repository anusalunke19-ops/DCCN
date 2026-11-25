"""
packet_inspector.py — Technical Wireshark-Style Deep-Dive Packet Dissector & Encapsulation Journey.

Features:
- Vertically arranged interactive protocol stack (Application ↓ Transport ↓ Network ↓ Ethernet)
- Real-time dynamic layer extraction from actual Scapy packet objects (never shows absent layers)
- Highlighted critical fields (IPs, Ports, TTL/Hop Limit, Seq/Ack, Flags, UDP Length, DNS queries)
- Visual packet encapsulation diagram showing nested header wrapping and exact byte boundaries
- Detailed academic comparison: Conceptual 7-Layer OSI Model vs. Actual Captured TCP/IP Reality
- Comprehensive header fields table with educational DCCN explanations
- Wireshark-grade 16-byte offset hexadecimal and printable ASCII wire dump
"""

import streamlit as st
import pandas as pd
from typing import Dict, Any, List

from core.packet_parser import get_packet_layers
from core.explain import explain_packet
from utils.hex_dump import generate_hex_dump, get_raw_bytes
from utils.helpers import format_bytes
from config.settings import PROTOCOL_COLORS
from ui.guided_lab import render_contextual_help


def _navigate(page: str):
    """Safely switch workspace and ensure all sidebar and top-nav state stays synchronized."""
    st.session_state["current_page"] = page
    st.session_state["sidebar_workspace_radio"] = page
    st.rerun()


def _render_layer_highlight_badges(highlights: Dict[str, str], color: str):
    """Render prominent highlighted badges for critical header fields."""
    if not highlights:
        return ""
    
    badge_html_items = []
    for field_name, field_val in highlights.items():
        badge_html_items.append(
            f'<div style="background: #F8FAFC; border: 1px solid #E5E9EF; border-left: 2px solid {color}; border-radius: 4px; padding: 6px 12px; margin: 3px; display: inline-flex; flex-direction: column;">'
            f'<span style="font-family: \'JetBrains Mono\', monospace; font-size: 0.68rem; color: #718096; text-transform: uppercase; letter-spacing: 0.05em;">{field_name}</span>'
            f'<span style="font-family: \'JetBrains Mono\', monospace; font-size: 0.86rem; font-weight: 700; color: #263238; word-break: break-all;">{field_val}</span>'
            f'</div>'
        )
    return f'<div style="display: flex; flex-wrap: wrap; gap: 4px; margin: 10px 0 14px 0;">{"".join(badge_html_items)}</div>'


def _render_encapsulation_diagram(layers: List[Dict[str, Any]], total_wire_bytes: int):
    """
    Render a visual nested container diagram showing how data is wrapped
    inside successive protocol headers with byte offsets and sizes.
    """
    st.markdown(
        """
        <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 8px; padding: 18px 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #159A91; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px;">
                // PROTOCOL ENCAPSULATION WRAPPING ARCHITECTURE
            </div>
            <div style="font-size: 0.95rem; font-weight: 600; color: #263238; margin-bottom: 12px;">
                Visualizing How Layer Data Is Enclosed Inside Successive Headers On The Wire
            </div>
            <div style="font-size: 0.82rem; color: #718096; margin-bottom: 16px; line-height: 1.5;">
                As user data moves down the transmitting stack, each layer prepends a protocol header containing vital addressing, sequencing, and multiplexing metadata before passing the resulting Protocol Data Unit (PDU) to the layer below.
            </div>
        """,
        unsafe_allow_html=True
    )

    # Calculate approximate header offsets
    offset_cursor = 0
    annotated_layers = []
    for l in layers:
        hlen = l.get("header_len", 0)
        start_off = offset_cursor
        end_off = offset_cursor + hlen - 1 if hlen > 0 else offset_cursor
        offset_cursor += hlen
        l_color = PROTOCOL_COLORS.get(l.get("name", ""), "#159A91")
        annotated_layers.append({
            "name": l["name"],
            "pdu": l.get("pdu_name", "PDU"),
            "osi": l["osi_layer"],
            "color": l_color,
            "icon": l.get("icon", "📦"),
            "size": hlen,
            "range": f"Bytes {start_off}–{end_off}" if hlen > 0 else f"Byte {start_off}"
        })

    # Render nested graphical cards (from outer Ethernet down to inner Payload)
    boxes_html = ""
    for idx, al in enumerate(annotated_layers):
        pad_indent = idx * 10
        boxes_html += (
            f'<div style="margin-left: {pad_indent}px; margin-top: 8px; background: #FFFFFF; border: 1px solid #E5E9EF; border-left: 4px solid {al["color"]}; border-radius: 6px; padding: 10px 14px; box-shadow: 0 1px 2px rgba(0,0,0,0.02);">'
            f'<div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">'
            f'<span style="font-family: \'JetBrains Mono\', monospace; font-size: 0.85rem; font-weight: 700; color: #263238;">'
            f'{al["icon"]} {al["name"]} &nbsp;'
            f'<span style="font-size: 0.72rem; color: #718096; font-weight: 500;">[{al["osi"]}]</span>'
            f'</span>'
            f'<span style="font-family: \'JetBrains Mono\', monospace; font-size: 0.75rem; color: #263238; background: #F8FAFC; border: 1px solid #E5E9EF; padding: 2px 8px; border-radius: 4px;">'
            f'{al["pdu"].upper()}: {al["size"]}B ({al["range"]})'
            f'</span>'
            f'</div>'
        )

    for _ in range(len(annotated_layers)):
        boxes_html += "</div>"

    st.markdown(boxes_html, unsafe_allow_html=True)

    # Wire PDU Nomenclature Strip
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; background: #F8FAFC; border: 1px dashed #CBD5E1; border-radius: 4px; padding: 10px 16px; margin-top: 14px; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #718096;">
            <span><b>PHYSICAL WIRE LENGTH:</b> <span style="color: #159A91; font-weight: 700;">{total_wire_bytes} Bytes</span> ({total_wire_bytes * 8:,} bits)</span>
            <span><b>LAYERS ENCAPSULATED:</b> <span style="color: #059669; font-weight: 700;">{len(layers)} Present</span></span>
            <span><b>FCS INTEGRITY:</b> <span style="color: #8B83C8; font-weight: 700;">Verified by NIC</span></span>
        </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def _render_osi_vs_tcpip_explanation(layers: List[Dict[str, Any]]):
    """
    Render a thorough educational section distinguishing the conceptual 7-Layer OSI model
    from actual captured packets in the real-world TCP/IP architecture.
    """
    st.markdown(
        """
        <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #159A91; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px;">
                // ARCHITECTURAL ANALYSIS // PROTOCOL REFERENCE
            </div>
            <div style="font-size: 1.1rem; font-weight: 700; color: #263238; margin-bottom: 8px;">
                Conceptual OSI 7-Layer Model vs. Actual Captured TCP/IP Reality
            </div>
            <div style="font-size: 0.85rem; color: #718096; line-height: 1.6; margin-bottom: 16px;">
                Computer networking textbooks frequently introduce the <b>ISO/IEC 7498-1 Open Systems Interconnection (OSI) 7-Layer Reference Model</b>.
                However, actual network traffic across the global Internet adheres to the <b>IETF TCP/IP Architecture (RFC 1122)</b>.
                Understanding the architectural divergences explains why captured packet headers appear the way they do in forensics tools.
            </div>
        """,
        unsafe_allow_html=True
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            """
            <div style="background: #F8FAFC; border: 1px solid #E5E9EF; border-left: 3px solid #D97706; border-radius: 6px; padding: 14px 16px; margin-bottom: 12px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #D97706; margin-bottom: 6px;">
                    ❓ Why Are Session (L5) & Presentation (L6) Headers Missing?
                </div>
                <div style="font-size: 0.82rem; color: #263238; line-height: 1.5;">
                    The OSI model allocated dedicated layers for Session management (dialogue control, checkpoints) and Presentation (data formatting, compression, encryption).
                    In the TCP/IP stack, these functions are <b>implemented entirely within the Application layer software</b> (e.g. TLS for encryption, JSON/HTTP for presentation, session cookies for session state).
                    Therefore, no standalone "Session" or "Presentation" protocol headers exist in raw packets.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            """
            <div style="background: #F8FAFC; border: 1px solid #E5E9EF; border-left: 3px solid #159A91; border-radius: 6px; padding: 14px 16px; margin-bottom: 12px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #159A91; margin-bottom: 6px;">
                    ❓ What Happened to the Physical Layer (OSI Layer 1)?
                </div>
                <div style="font-size: 0.82rem; color: #263238; line-height: 1.5;">
                    Layer 1 governs raw physical signaling (copper voltages, optical light pulses, radio RF).
                    The Network Interface Card (NIC) hardware transceiver decodes physical signals, validates the 7-byte preamble, 1-byte Start Frame Delimiter (SFD), and 4-byte Frame Check Sequence (FCS/CRC32).
                    The NIC strips the physical framing before handing valid Layer 2 Ethernet frames to OS packet capture drivers (Npcap / libpcap).
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Dynamic OSI Mapping Matrix for THIS packet
    st.markdown(
        """
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 600; color: #263238; margin: 14px 0 8px 0;">
            // DYNAMIC OSI MAPPING FOR SELECTED PACKET:
        </div>
        """,
        unsafe_allow_html=True
    )

    layer_names_lower = [l["name"].lower() for l in layers]
    has_app = any("data" in n or "dns" in n for n in layer_names_lower)
    has_transport = any("tcp" in n or "udp" in n or "icmp" in n for n in layer_names_lower)
    has_network = any("internet protocol" in n or "arp" in n for n in layer_names_lower)
    has_datalink = any("ethernet" in n for n in layer_names_lower)

    matrix_rows = [
        {"OSI Layer": "Layer 7 — Application", "TCP/IP Equivalent": "Application Layer", "Status in Packet": "Captured" if has_app else "Absent", "Observed Protocol Header": next((l['name'] for l in layers if 'dns' in l['name'].lower() or 'payload' in l['name'].lower()), "None")},
        {"OSI Layer": "Layer 6 — Presentation", "TCP/IP Equivalent": "Integrated into Application", "Status in Packet": "Integrated in L7", "Observed Protocol Header": "No distinct header (handled by payload encoding/TLS)"},
        {"OSI Layer": "Layer 5 — Session", "TCP/IP Equivalent": "Integrated into Application/Transport", "Status in Packet": "Integrated in L4/L7", "Observed Protocol Header": "No distinct header (handled by TCP state or App tokens)"},
        {"OSI Layer": "Layer 4 — Transport", "TCP/IP Equivalent": "Transport Layer (Host-to-Host)", "Status in Packet": "Captured" if has_transport else "Absent", "Observed Protocol Header": next((l['name'] for l in layers if 'tcp' in l['name'].lower() or 'udp' in l['name'].lower() or 'icmp' in l['name'].lower()), "None")},
        {"OSI Layer": "Layer 3 — Network", "TCP/IP Equivalent": "Internet Layer", "Status in Packet": "Captured" if has_network else "Absent", "Observed Protocol Header": next((l['name'] for l in layers if 'internet protocol' in l['name'].lower() or 'arp' in l['name'].lower()), "None")},
        {"OSI Layer": "Layer 2 — Data Link", "TCP/IP Equivalent": "Link / Network Access Layer", "Status in Packet": "Captured" if has_datalink else "Absent", "Observed Protocol Header": next((l['name'] for l in layers if 'ethernet' in l['name'].lower()), "None")},
        {"OSI Layer": "Layer 1 — Physical", "TCP/IP Equivalent": "Physical Medium (Bits)", "Status in Packet": "Hardware Handled", "Observed Protocol Header": "Decoded by PHY transceiver; stripped before PCAP capture"}
    ]

    mdf = pd.DataFrame(matrix_rows)
    st.dataframe(mdf, use_container_width=True, hide_index=True)
    st.markdown("</div>", unsafe_allow_html=True)


def render_packet_inspector_page():
    # Header Banner
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #E5E9EF; padding-bottom: 12px; margin-bottom: 16px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 2px;">
                    // FORENSIC DISSECTION ENGINE // PACKET JOURNEY & ENCAPSULATION
                </div>
                <div style="font-size: 1.4rem; font-weight: 700; color: #263238; letter-spacing: -0.02em;">
                    Packet Inspector & Protocol Journey
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-teal">INTERACTIVE STACK</span>
                <span class="soc-badge soc-badge-green">DYNAMIC ENCAPSULATION</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    raw_packets = st.session_state.get("raw_packets") or st.session_state.get("packets", [])
    parsed_packets = st.session_state.get("parsed_packets", [])

    if not parsed_packets:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px dashed #CBD5E1; border-radius: 8px; padding: 48px; text-align: center; margin-top: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                <div style="font-size: 2.2rem; margin-bottom: 12px;">🔬</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: #263238; margin-bottom: 6px;">No Frames Available for Deep Inspection</div>
                <div style="font-size: 0.85rem; color: #718096; max-width: 480px; margin: 0 auto 20px auto; line-height: 1.5;">
                    Please capture live frames or load a PCAP capture file from the Live Capture console to dissect encapsulation layers, header fields, and raw hexadecimal octets.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("📡 Go to Live Capture Console", key="insp_empty_goto_live_btn", use_container_width=True, type="primary"):
                _navigate("📡 Live Capture")
        return

    # -----------------------------------------------------------------------
    # Frame Navigation Toolbar
    # -----------------------------------------------------------------------
    curr_idx = st.session_state.get("selected_packet_idx", 0)
    if curr_idx is None or curr_idx < 0 or curr_idx >= len(parsed_packets):
        curr_idx = 0
        st.session_state["selected_packet_idx"] = 0

    total_pkts = len(parsed_packets)

    if "insp_jump_frame_select" not in st.session_state or st.session_state["insp_jump_frame_select"] != curr_idx + 1:
        st.session_state["insp_jump_frame_select"] = curr_idx + 1

    def _on_prev_frame():
        if st.session_state.get("selected_packet_idx", 0) > 0:
            st.session_state["selected_packet_idx"] -= 1
            st.session_state["insp_jump_frame_select"] = st.session_state["selected_packet_idx"] + 1

    def _on_next_frame():
        curr = st.session_state.get("selected_packet_idx", 0)
        if curr < total_pkts - 1:
            st.session_state["selected_packet_idx"] = curr + 1
            st.session_state["insp_jump_frame_select"] = st.session_state["selected_packet_idx"] + 1

    def _on_jump_frame_change():
        chosen = st.session_state.get("insp_jump_frame_select")
        if chosen is not None:
            st.session_state["selected_packet_idx"] = chosen - 1

    nav1, nav2, nav3, nav4 = st.columns([1, 2.8, 1, 2.2])

    with nav1:
        st.button("⬅ PREV FRAME", key="insp_nav_prev_btn", disabled=(curr_idx <= 0), use_container_width=True, on_click=_on_prev_frame)

    with nav2:
        st.selectbox(
            "Jump to Frame",
            options=range(1, total_pkts + 1),
            format_func=lambda n: f"Frame #{n:03d} — {parsed_packets[n-1]['protocol']} ({parsed_packets[n-1]['length']} Bytes)",
            label_visibility="collapsed",
            key="insp_jump_frame_select",
            on_change=_on_jump_frame_change
        )

    with nav3:
        st.button("NEXT FRAME ➡", key="insp_nav_next_btn", disabled=(curr_idx >= total_pkts - 1), use_container_width=True, on_click=_on_next_frame)

    with nav4:
        st.markdown(
            f"""
            <div style="padding-top: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #718096; text-align: right;">
                FRAME <span style="color: #159A91; font-weight: 700;">{curr_idx + 1}</span> OF {total_pkts:,}
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    active_parsed = parsed_packets[curr_idx]
    active_raw = raw_packets[curr_idx] if curr_idx < len(raw_packets) else None

    # -----------------------------------------------------------------------
    # Frame Header Telemetry Strip
    # -----------------------------------------------------------------------
    wire_len = active_parsed.get("length", 0)
    wire_bits = wire_len * 8
    proto_label = active_parsed.get("protocol", "Unknown")

    t_curr = active_parsed.get("timestamp")
    t_start = parsed_packets[0].get("timestamp") if parsed_packets else None
    rel_time_str = f"+{(t_curr - t_start):.6f}s" if (t_curr is not None and t_start is not None) else "0.000s"

    src_endpoint = active_parsed.get("src_ip") or active_parsed.get("eth_src", "—")
    sport = active_parsed.get("src_port")
    src_socket = f"{src_endpoint}:{sport}" if sport else str(src_endpoint)

    dst_endpoint = active_parsed.get("dst_ip") or active_parsed.get("eth_dst", "—")
    dport = active_parsed.get("dst_port")
    dst_socket = f"{dst_endpoint}:{dport}" if dport else str(dst_endpoint)

    s1, s2, s3, s4, s5 = st.columns(5)
    with s1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">FRAME INDEX</div>
                <div class="kpi-val" style="color: #159A91;">#{active_parsed.get('num', curr_idx + 1):03d}</div>
                <div class="kpi-sub">Buffer position</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with s2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">PROTOCOL</div>
                <div class="kpi-val" style="color: #059669;">{proto_label}</div>
                <div class="kpi-sub">Identified layer</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with s3:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">WIRE LENGTH</div>
                <div class="kpi-val" style="color: #159A91;">{wire_len} B</div>
                <div class="kpi-sub">{wire_bits:,} bits on wire</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with s4:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">ARRIVAL DELTA</div>
                <div class="kpi-val" style="color: #D97706;">{rel_time_str}</div>
                <div class="kpi-sub">{active_parsed.get('timestamp_str', '')}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with s5:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">SOCKET CONVERSATION</div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #263238; margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    {src_socket}
                </div>
                <div class="kpi-sub">➔ {dst_socket}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Dissection Summary Banner
    st.markdown(
        f"""
        <div style="background-color: #FFFFFF; border: 1px solid #E5E9EF; border-left: 3px solid #159A91; padding: 10px 14px; border-radius: 4px; margin: 12px 0 16px 0; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #263238; box-shadow: 0 1px 2px rgba(0,0,0,0.02);">
            <span style="color: #159A91; font-weight: 700;">WIRESHARK DISSECTION SUMMARY:</span> {active_parsed.get('info', 'No summary available')}
        </div>
        """,
        unsafe_allow_html=True
    )

    # -----------------------------------------------------------------------
    # Multi-Dimensional Inspection Tabs
    # -----------------------------------------------------------------------
    tab_stack, tab_diagram, tab_osi, tab_explain, tab_hex = st.tabs([
        "🧬 PROTOCOL STACK (JOURNEY)",
        "📦 ENCAPSULATION DIAGRAM",
        "🏛️ OSI THEORY VS REALITY",
        "🧠 PACKET EXPLANATION & ANALYSIS",
        "💾 HEXADECIMAL & ASCII DUMP"
    ])

    if active_raw is None:
        st.error("Raw Scapy packet object unavailable for full layer-by-layer dissection.")
        return

    # Extract dynamic layers from actual Scapy packet
    layers = get_packet_layers(active_raw)

    # -----------------------------------------------------------------------
    # TAB 1: Vertically Arranged Interactive Protocol Stack
    # -----------------------------------------------------------------------
    with tab_stack:
        st.markdown(
            """
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <div>
                    <span class="soc-tag">// ACTUAL ENCAPSULATION STRUCTURE</span>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #263238; margin-top: 2px;">
                        Interactive Protocol Stack & Header Inspector
                    </div>
                </div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #718096;">
                    Top-down Transmission Encapsulation Order
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Transmission encapsulation order: Application at top, down to Ethernet at bottom
        vertical_stack = list(reversed(layers))

        for idx, layer in enumerate(vertical_stack):
            border_color = PROTOCOL_COLORS.get(layer.get("name", ""), "#159A91")
            layer_icon = layer.get("icon", "📦")
            layer_name = layer["name"]
            osi_desc = layer["osi_layer"]
            pdu_name = layer.get("pdu_name", "PDU")
            header_size = layer.get("header_len", 0)
            highlights = layer.get("highlights", {})

            # Container for the layer
            with st.expander(
                f"{layer_icon}  {layer_name.upper()}  [{osi_desc.upper()}]  —  PDU: {pdu_name.upper()} ({header_size} Bytes)",
                expanded=True
            ):
                # Header meta strip
                st.markdown(
                    f"""
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #E5E9EF; padding-bottom: 8px; margin-bottom: 10px;">
                        <div>
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: {border_color}; font-weight: 700;">
                                {layer_icon} {layer_name}
                            </span>
                            &nbsp;&nbsp;
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #718096;">[{osi_desc}]</span>
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #263238; background: #F8FAFC; border: 1px solid #E5E9EF; padding: 2px 8px; border-radius: 4px;">
                            PDU TYPE: <b style="color: {border_color};">{pdu_name.upper()}</b> | HEADER: <b>{header_size} BYTES</b>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                # Requirement 6: Highlighted Important Fields Strip
                if highlights:
                    st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.72rem; color: #159A91; font-weight: 700;'>⚡ CRITICAL HEADER HIGHLIGHTS:</span>", unsafe_allow_html=True)
                    st.markdown(_render_layer_highlight_badges(highlights, border_color), unsafe_allow_html=True)

                # Header Fields Table
                fields = layer.get("fields", [])
                if fields:
                    field_rows = []
                    for fname, fval, fdesc in fields:
                        field_rows.append({
                            "Header Field": fname,
                            "Captured Value": str(fval) if fval is not None else "—",
                            "DCCN / Educational Significance": fdesc
                        })
                    fdf = pd.DataFrame(field_rows)
                    st.dataframe(fdf, use_container_width=True, hide_index=True)

            # Draw downward arrow between layers if not the bottom layer
            if idx < len(vertical_stack) - 1:
                next_layer_name = vertical_stack[idx + 1]["name"]
                st.markdown(
                    f"""
                    <div style="display: flex; justify-content: center; align-items: center; margin: 6px 0;">
                        <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 20px; padding: 3px 18px; font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #159A91; display: flex; align-items: center; gap: 8px;">
                            <span>↓</span> <span>ENCAPSULATED INTO {next_layer_name.split('(')[0].strip().upper()} PDU</span> <span>↓</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    # -----------------------------------------------------------------------
    # TAB 2: Packet Encapsulation Diagram
    # -----------------------------------------------------------------------
    with tab_diagram:
        _render_encapsulation_diagram(layers, wire_len)

    # -----------------------------------------------------------------------
    # TAB 3: Conceptual OSI vs Reality
    # -----------------------------------------------------------------------
    with tab_osi:
        _render_osi_vs_tcpip_explanation(layers)

    # -----------------------------------------------------------------------
    # TAB 4: Plain-English DCCN Forensic Explanation
    # -----------------------------------------------------------------------
    with tab_explain:
        st.markdown("<span class='soc-tag'>// DCCN FORENSIC DECODING</span>", unsafe_allow_html=True)
        explanation = explain_packet(active_parsed)

        st.markdown(
            f"""
            <div class="tech-panel" style="border-left: 3px solid #059669; margin-bottom: 16px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; font-weight: 700; color: #059669; margin-bottom: 2px;">
                    OPERATIONAL ROLE IN CONVERSATION:
                </div>
                <div style="font-size: 0.95rem; color: #263238; font-weight: 600;">
                    {explanation['summary']}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col_left, col_right = st.columns([3, 2])

        with col_left:
            st.markdown(
                """
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; font-weight: 700; color: #263238; margin-bottom: 8px;">
                    FORENSIC EVIDENCE & KEY TAKEAWAYS
                </div>
                """,
                unsafe_allow_html=True
            )
            for item in explanation.get("takeaways", []):
                st.markdown(f"- <span style='font-size: 0.86rem; color: #263238;'>{item}</span>", unsafe_allow_html=True)

            st.markdown(
                """
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; font-weight: 700; color: #263238; margin-top: 14px; margin-bottom: 8px;">
                    PACKET INFERENCES
                </div>
                """,
                unsafe_allow_html=True
            )
            for note in explanation.get("evidence_notes", []):
                st.markdown(f"ℹ️ <span style='font-size: 0.82rem; color: #718096;'>{note}</span>", unsafe_allow_html=True)

        with col_right:
            st.markdown(
                """
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; font-weight: 700; color: #263238; margin-bottom: 8px;">
                    PROTOCOL & FORENSIC CONCEPTS
                </div>
                """,
                unsafe_allow_html=True
            )
            for concept in explanation.get("dccn_concepts", []):
                st.markdown(
                    f"""
                    <div style="background-color: #FFFFFF; border: 1px solid #E5E9EF; padding: 7px 12px; margin-bottom: 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #159A91; font-weight: 600;">
                        ✓ {concept}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    # -----------------------------------------------------------------------
    # TAB 5: Raw Hexadecimal & ASCII Dissector
    # -----------------------------------------------------------------------
    with tab_hex:
        st.markdown("<span class='soc-tag'>// RAW WIRE OCTET DISSECTION</span>", unsafe_allow_html=True)
        st.caption("Standard 16-byte dual-column display: Left: byte offset (hex), Center: raw hexadecimal octets, Right: printable ASCII.")

        raw_data = get_raw_bytes(active_raw)
        dump_text = generate_hex_dump(raw_data)
        st.markdown(f"<div class='hex-display'><pre>{dump_text}</pre></div>", unsafe_allow_html=True)

        st.markdown(
            f"""
            <div style="display: flex; justify-content: space-between; margin-top: 10px; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #718096;">
                <span>Total Frame Size: <b style="color: #159A91;">{len(raw_data)} bytes</b></span>
                <span>Bit Stream: <b style="color: #059669;">{len(raw_data) * 8:,} bits</b></span>
                <span>Hex Offset Range: <b style="color: #263238;">0x0000 – 0x{len(raw_data)-1:04X}</b></span>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    render_contextual_help("packet_inspector")

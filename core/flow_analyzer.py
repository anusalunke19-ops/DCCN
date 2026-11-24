"""
flow_analyzer.py — TCP/UDP Flow Reconstruction, Handshake Tracking & State Machine.

Groups packets into bidirectional communication flows (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol),
identifies TCP handshake sequences, tracks connection lifecycle states, and calculates per-flow telemetry:
- Bidirectional flow normalization supporting both IPv4 and IPv6
- Initiator (Client) vs Responder (Server) socket resolution
- 3-Way Handshake validation (SYN → SYN-ACK → ACK)
- Handshake Initial Round Trip Time (iRTT) measurement
- Data transfer identification based on actual captured payload bytes
- Connection termination tracking (graceful FIN teardown vs RST abort)
- Incomplete capture detection (mid-stream traffic, SYN flood, unresponded SYN)
- Heuristic retransmission and duplicate ACK tracking
"""

from __future__ import annotations
from typing import Dict, Any, List, Tuple
import pandas as pd

from config.settings import MIN_FLOW_PACKETS


def format_socket(ip: Any, port: Any) -> str:
    """Format an IP and port into a standard socket string with IPv6 bracket support."""
    ip_str = str(ip or "?")
    port_str = str(port if port is not None else 0)
    # Check if IPv6 (contains colons and not already bracketed)
    if ":" in ip_str and not (ip_str.startswith("[") and ip_str.endswith("]")):
        return f"[{ip_str}]:{port_str}"
    return f"{ip_str}:{port_str}"


def make_flow_key(parsed: Dict[str, Any]) -> str | None:
    """
    Generate a normalized bidirectional flow key from a parsed packet.

    Uses sorted endpoints so that packets traveling in both directions
    (Client -> Server and Server -> Client) map to the exact same flow key.
    """
    src_ip = parsed.get("src_ip")
    dst_ip = parsed.get("dst_ip")
    src_port = parsed.get("src_port")
    dst_port = parsed.get("dst_port")

    if not src_ip or not dst_ip:
        return None

    # Determine L4 protocol (TCP, UDP, or other IP protocol)
    if parsed.get("tcp_sport") is not None or parsed.get("protocol") == "TCP":
        proto = "TCP"
    elif parsed.get("udp_sport") is not None or parsed.get("protocol") == "UDP":
        proto = "UDP"
    else:
        proto = parsed.get("ip_proto_str", parsed.get("protocol", "IP"))

    endpoint_a = (str(src_ip), int(src_port) if src_port is not None else 0)
    endpoint_b = (str(dst_ip), int(dst_port) if dst_port is not None else 0)

    # Sort endpoints to ensure bidirectional symmetry
    if endpoint_a > endpoint_b:
        endpoint_a, endpoint_b = endpoint_b, endpoint_a

    sock_a = format_socket(endpoint_a[0], endpoint_a[1])
    sock_b = format_socket(endpoint_b[0], endpoint_b[1])

    return f"{sock_a} <-> {sock_b} [{proto}]"


def group_into_flows(parsed_packets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group parsed packets into bidirectional communication flows.

    Returns:
        Dict mapping flow_key -> list of parsed packet dicts (chronologically sorted).
    """
    flows: Dict[str, List[Dict[str, Any]]] = {}

    for pkt in parsed_packets:
        key = make_flow_key(pkt)
        if key is None:
            continue
        if key not in flows:
            flows[key] = []
        flows[key].append(pkt)

    # Sort each flow chronologically by packet timestamp
    for key in flows:
        flows[key].sort(key=lambda p: float(p.get("timestamp") or 0))

    return flows


def analyze_flow(flow_key: str, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute rigorous transport statistics and reconstruct TCP connection state.

    Distinguishes:
    - Connection attempt vs Established connection
    - Full 3-way handshake vs Incomplete / Refused / Mid-stream
    - Data transfer (actual payload bytes) vs Pure control ACKs
    - Graceful FIN close vs RST abort
    """
    if not packets:
        return {"flow_key": flow_key, "packet_count": 0}

    # 1. Detect Protocol
    is_udp = any(p.get("udp_sport") is not None for p in packets)

    total_wire_bytes = sum(p.get("length", 0) for p in packets)
    timestamps = [float(p["timestamp"]) for p in packets if p.get("timestamp") is not None]
    duration_sec = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0

    # 2. Identify Connection Initiator (Client) vs Responder (Server)
    # Search for initial SYN (SYN=1, ACK=0)
    syn_pkt = None
    for p in packets:
        flags_short = p.get("tcp_flags", "") or ""
        flags_str = p.get("tcp_flags_str", "") or ""
        if ("S" in flags_short and "A" not in flags_short) or ("SYN" in flags_str and "ACK" not in flags_str):
            syn_pkt = p
            break

    first = packets[0]
    if syn_pkt is not None:
        client_ip = syn_pkt.get("src_ip", "?")
        client_port = syn_pkt.get("src_port", 0)
        server_ip = syn_pkt.get("dst_ip", "?")
        server_port = syn_pkt.get("dst_port", 0)
        has_initiator_syn = True
    else:
        # Mid-stream or UDP: infer initiator from first observed frame
        client_ip = first.get("src_ip", "?")
        client_port = first.get("src_port", 0)
        server_ip = first.get("dst_ip", "?")
        server_port = first.get("dst_port", 0)
        has_initiator_syn = False

    client_sock = format_socket(client_ip, client_port)
    server_sock = format_socket(server_ip, server_port)

    # 3. Dissect Events and Connection State Machine
    events: List[Dict[str, Any]] = []

    has_syn = False
    has_syn_ack = False
    has_final_ack = False
    client_fin = False
    server_fin = False
    has_rst = False

    client_isn = None
    server_isn = None
    syn_time = None
    syn_ack_time = None
    syn_pkt = None
    syn_ack_pkt = None
    final_ack_pkt = None

    c2s_packets = 0
    s2c_packets = 0
    c2s_payload_bytes = 0
    s2c_payload_bytes = 0
    data_packet_count = 0

    potential_retransmissions = 0
    duplicate_ack_count = 0

    # Sequence and ACK tracking for heuristic retransmissions and gap detection
    seen_seqs: Dict[str, Dict[int, int]] = {"c2s": {}, "s2c": {}}  # seq -> payload_len
    seen_acks: Dict[str, Dict[int, int]] = {"c2s": {}, "s2c": {}}  # ack -> count

    for pkt in packets:
        pkt_src = str(pkt.get("src_ip", ""))
        pkt_sport = pkt.get("src_port")
        ts = float(pkt.get("timestamp") or 0)
        flags_short = pkt.get("tcp_flags", "") or ""
        flags_str = pkt.get("tcp_flags_str", "") or ""
        seq = pkt.get("tcp_seq")
        ack = pkt.get("tcp_ack")
        payload_len = pkt.get("payload_len", 0) or 0

        # Determine directional orientation relative to initiator
        is_c2s = (pkt_src == str(client_ip) and pkt_sport == client_port)
        dir_key = "c2s" if is_c2s else "s2c"
        dir_arrow = "→" if is_c2s else "←"
        dir_label = "Client ➔ Server" if is_c2s else "Server ➔ Client"

        if is_c2s:
            c2s_packets += 1
            c2s_payload_bytes += payload_len
        else:
            s2c_packets += 1
            s2c_payload_bytes += payload_len

        # Detect TCP Flags
        is_syn_flag = ("S" in flags_short and "A" not in flags_short) or ("SYN" in flags_str and "ACK" not in flags_str)
        is_syn_ack_flag = ("S" in flags_short and "A" in flags_short) or ("SYN" in flags_str and "ACK" in flags_str)
        is_rst_flag = "R" in flags_short or "RST" in flags_str
        is_fin_flag = "F" in flags_short or "FIN" in flags_str
        is_psh_flag = "P" in flags_short or "PSH" in flags_str
        is_ack_flag = "A" in flags_short or "ACK" in flags_str

        # Heuristic Retransmission Tracking
        if seq is not None and not is_udp:
            if seq in seen_seqs[dir_key]:
                prev_len = seen_seqs[dir_key][seq]
                # If segment carried payload or was a SYN, duplicate sequence number indicates retransmission
                if payload_len > 0 or is_syn_flag:
                    potential_retransmissions += 1
                    events.append({
                        "time": ts,
                        "direction": dir_arrow,
                        "dir_label": dir_label,
                        "event": "Potential Retransmission",
                        "detail": f"Duplicate Seq={seq} (Payload={payload_len}B)",
                        "flags": flags_short,
                        "is_anomaly": True
                    })
            else:
                seen_seqs[dir_key][seq] = payload_len

        # Heuristic Duplicate ACK Tracking
        if ack is not None and payload_len == 0 and not (is_syn_flag or is_syn_ack_flag or is_fin_flag or is_rst_flag):
            if ack in seen_acks[dir_key]:
                seen_acks[dir_key][ack] += 1
                if seen_acks[dir_key][ack] >= 3:
                    duplicate_ack_count += 1
            else:
                seen_acks[dir_key][ack] = 1

        # Event Dispatch
        if is_syn_flag:
            has_syn = True
            if syn_time is None:
                syn_time = ts
                client_isn = seq
                syn_pkt = pkt
            events.append({
                "time": ts,
                "direction": dir_arrow,
                "dir_label": dir_label,
                "event": "SYN (Connection Request)",
                "detail": f"Client ISN={seq} (Win={pkt.get('tcp_window', 'N/A')})",
                "flags": flags_short,
                "is_anomaly": False
            })

        elif is_syn_ack_flag:
            has_syn_ack = True
            if syn_ack_time is None:
                syn_ack_time = ts
                server_isn = seq
                syn_ack_pkt = pkt
            events.append({
                "time": ts,
                "direction": dir_arrow,
                "dir_label": dir_label,
                "event": "SYN-ACK (Connection Accepted)",
                "detail": f"Server ISN={seq} Ack={ack}",
                "flags": flags_short,
                "is_anomaly": False
            })

        elif is_rst_flag:
            has_rst = True
            events.append({
                "time": ts,
                "direction": dir_arrow,
                "dir_label": dir_label,
                "event": "RST (Connection Reset)",
                "detail": f"Seq={seq} Ack={ack if ack is not None else '—'}",
                "flags": flags_short,
                "is_anomaly": True
            })

        elif is_fin_flag:
            if is_c2s:
                client_fin = True
            else:
                server_fin = True
            events.append({
                "time": ts,
                "direction": dir_arrow,
                "dir_label": dir_label,
                "event": "FIN (Connection Close Request)",
                "detail": f"Seq={seq} Ack={ack if ack is not None else '—'}",
                "flags": flags_short,
                "is_anomaly": False
            })

        elif payload_len > 0:
            data_packet_count += 1
            push_tag = " [PSH]" if is_psh_flag else ""
            events.append({
                "time": ts,
                "direction": dir_arrow,
                "dir_label": dir_label,
                "event": f"Data Transfer{push_tag}",
                "detail": f"Seq={seq} Payload={payload_len}B",
                "flags": flags_short,
                "is_anomaly": False
            })

        elif is_ack_flag:
            # Check for Handshake Final ACK (Step 3)
            if has_syn and has_syn_ack and not has_final_ack and is_c2s:
                has_final_ack = True
                final_ack_pkt = pkt
                events.append({
                    "time": ts,
                    "direction": dir_arrow,
                    "dir_label": dir_label,
                    "event": "ACK (3-Way Handshake Established)",
                    "detail": f"Seq={seq} Ack={ack}",
                    "flags": flags_short,
                    "is_anomaly": False
                })
            elif client_fin or server_fin:
                events.append({
                    "time": ts,
                    "direction": dir_arrow,
                    "dir_label": dir_label,
                    "event": "ACK (Teardown Acknowledged)",
                    "detail": f"Ack={ack}",
                    "flags": flags_short,
                    "is_anomaly": False
                })

    # 4. Handshake Initial Round-Trip Time (iRTT) calculation
    rtt_ms = None
    if syn_time is not None and syn_ack_time is not None and syn_ack_time >= syn_time:
        rtt_ms = round((syn_ack_time - syn_time) * 1000, 2)

    # 5. Precise Connection & Stream State Deduction
    total_payload_bytes = c2s_payload_bytes + s2c_payload_bytes

    if is_udp:
        tcp_state = "UDP (Connectionless)"
        handshake_state = "NOT_APPLICABLE"
        stream_status = "DATAGRAM_EXCHANGE" if total_payload_bytes > 0 else "DATAGRAM_PROBE"

    elif has_syn and has_syn_ack and has_final_ack:
        handshake_state = "ESTABLISHED"
        if client_fin and server_fin:
            tcp_state = "Complete (Established → Full 4-Way Close)"
            stream_status = "STREAM_COMPLETED_CLEANLY"
        elif client_fin or server_fin:
            tcp_state = "Closing (Established → Half-Closed FIN)"
            stream_status = "STREAM_HALF_CLOSED"
        elif has_rst:
            tcp_state = "Reset (Established → RST Abort)"
            stream_status = "STREAM_ABORTED_BY_RST"
        elif total_payload_bytes > 0:
            tcp_state = "Established (Data Exchanged)"
            stream_status = "STREAM_ACTIVE_DATA"
        else:
            tcp_state = "Established (3-Way Handshake Complete, No Data)"
            stream_status = "STREAM_CONTROL_ONLY"

    elif has_syn and has_rst and not has_syn_ack:
        tcp_state = "Connection Refused (SYN → RST)"
        handshake_state = "REFUSED"
        stream_status = "CONNECTION_REJECTED"

    elif has_syn and has_syn_ack and not has_final_ack:
        tcp_state = "Incomplete (SYN + SYN-ACK, Missing Final ACK)"
        handshake_state = "INCOMPLETE"
        stream_status = "HANDSHAKE_INCOMPLETE"

    elif has_syn and not has_syn_ack:
        tcp_state = "Incomplete (SYN Only, No Server Response)"
        handshake_state = "ATTEMPT_ONLY"
        stream_status = "CONNECTION_ATTEMPT_UNANSWERED"

    elif has_rst:
        tcp_state = "Reset (Mid-Stream RST)"
        handshake_state = "MID_STREAM"
        stream_status = "STREAM_ABORTED"

    elif client_fin or server_fin:
        tcp_state = "Mid-Stream (FIN Teardown Observed)"
        handshake_state = "MID_STREAM"
        stream_status = "TEARDOWN_ONLY"

    elif total_payload_bytes > 0:
        tcp_state = "Data Only (Mid-Stream Traffic, No Handshake)"
        handshake_state = "MID_STREAM"
        stream_status = "MID_STREAM_DATA"

    else:
        tcp_state = "Incomplete / Ambiguous (No Handshake Observed)"
        handshake_state = "MID_STREAM"
        stream_status = "CONTROL_PROBE_ONLY"

    return {
        "flow_key": flow_key,
        "src_ip": client_ip,
        "dst_ip": server_ip,
        "src_port": client_port,
        "dst_port": server_port,
        "client_socket": client_sock,
        "server_socket": server_sock,
        "protocol": "UDP" if is_udp else "TCP",
        "packet_count": len(packets),
        "total_bytes": total_wire_bytes,
        "payload_bytes": total_payload_bytes,
        "duration_sec": round(duration_sec, 6),
        "rtt_ms": rtt_ms,
        "tcp_state": tcp_state,
        "handshake_state": handshake_state,
        "stream_status": stream_status,
        "data_packets": data_packet_count,
        "c2s_packets": c2s_packets,
        "s2c_packets": s2c_packets,
        "c2s_payload_bytes": c2s_payload_bytes,
        "s2c_payload_bytes": s2c_payload_bytes,
        "has_syn": has_syn,
        "has_syn_ack": has_syn_ack,
        "has_final_ack": has_final_ack,
        "has_fin": (client_fin or server_fin),
        "client_fin": client_fin,
        "server_fin": server_fin,
        "has_rst": has_rst,
        "potential_retransmissions": potential_retransmissions,
        "duplicate_acks": duplicate_ack_count,
        "client_isn": client_isn,
        "server_isn": server_isn,
        "syn_pkt": syn_pkt,
        "syn_ack_pkt": syn_ack_pkt,
        "final_ack_pkt": final_ack_pkt,
        "events": events,
    }


def analyze_all_flows(parsed_packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group packets into flows and analyze each one.
    Returns a list of flow analysis dicts sorted by packet count (descending).
    """
    flows = group_into_flows(parsed_packets)
    results = []
    for key, pkts in flows.items():
        if len(pkts) >= MIN_FLOW_PACKETS:
            results.append(analyze_flow(key, pkts))

    results.sort(key=lambda f: f["packet_count"], reverse=True)
    return results

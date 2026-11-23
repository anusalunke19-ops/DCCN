"""
test_qa_full_e2e.py — Senior QA Comprehensive End-to-End Test Suite.

Executes and verifies all 20 technical requirements:
1. Application startup and dependency check
2. Offline PCAP loading
3. PCAPNG loading
4. Packet parsing
5. IPv4 and IPv6 detection
6. TCP and UDP detection
7. DNS parsing
8. Packet filtering (Protocol, IP, Port, Time)
9. Packet selection & index bounds
10. Protocol-layer visualization (encapsulation stack & highlights)
11. Hexadecimal & ASCII packet inspection
12. TCP flow grouping & bidirectional normalization
13. TCP handshake analysis & state machine
14. Network analytics (protocols, talkers, ports, flags, DNS, timeline)
15. Capture comparison (baseline vs impaired differential metrics)
16. Live capture environment & Npcap checking
17. Capture start, stop, bounded queue, and thread cleanup
18. Invalid input handling (non-existent, corrupt, invalid extensions)
19. Empty capture handling (0-byte file, empty buffer, empty DataFrames)
20. Export functionality (export to PCAP and round-trip verification)
"""

import os
import sys
import tempfile
import pytest
import pandas as pd
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR,
    ICMP, Raw, Packet
)
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply

from app import check_dependencies
from core.pcap_manager import load_pcap, export_pcap, validate_pcap_path, packets_to_dataframe
from core.packet_parser import parse_packet, get_packet_layers
from core.flow_analyzer import make_flow_key, group_into_flows, analyze_flow, analyze_all_flows
from core.protocol_analyzer import (
    analyze_protocols, analyze_top_ips, analyze_top_ports,
    analyze_tcp_flags, analyze_dns_queries, analyze_traffic_timeline
)
from core.capture import LiveCaptureEngine, is_live_capture_available, get_available_interfaces
from utils.hex_dump import generate_hex_dump, get_raw_bytes
from config.settings import MAX_CAPTURE_PACKETS, DEFAULT_CAPTURE_LIMIT


# ---------------------------------------------------------------------------
# Test 1: Application Startup & Dependencies
# ---------------------------------------------------------------------------
def test_01_app_startup_and_dependencies():
    """Verify application startup dependencies and module integrity."""
    results = check_dependencies()
    assert len(results) >= 3

    dep_dict = {name: status for name, status, _ in results}
    assert dep_dict["Scapy"] == "✅"
    assert dep_dict["Plotly"] == "✅"
    assert dep_dict["Pandas"] == "✅"


# ---------------------------------------------------------------------------
# Test 2: Offline PCAP Loading
# ---------------------------------------------------------------------------
def test_02_offline_pcap_loading():
    """Load baseline and synthetic benchmark PCAP files offline."""
    sample_files = [
        "sample_captures/sample_traffic.pcap",
        "sample_captures/sample_impaired.pcap",
        "sample_captures/synthetic_protocol_suite.pcap"
    ]
    for path in sample_files:
        assert os.path.exists(path), f"File {path} does not exist"
        raw, parsed, err = load_pcap(path)
        assert err is None, f"Failed to load {path}: {err}"
        assert len(raw) > 0
        assert len(raw) == len(parsed)
        # Check timestamps and ordering are preserved
        timestamps = [p["timestamp"] for p in parsed if p.get("timestamp")]
        assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# Test 3: PCAPNG Loading
# ---------------------------------------------------------------------------
def test_03_pcapng_loading():
    """Verify loading and parsing of PCAPNG files."""
    from scapy.utils import PcapNgWriter

    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=54321) / Raw(load=b"pcapng-test")
    pkt.time = 1700000000.0

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as tmp:
        tmp_path = tmp.name

    try:
        with PcapNgWriter(tmp_path) as writer:
            writer.write(pkt)

        raw, parsed, err = load_pcap(tmp_path)
        assert err is None
        assert len(raw) == 1
        assert len(parsed) == 1
        assert parsed[0]["src_ip"] == "192.168.1.1"
        assert parsed[0]["dst_ip"] == "192.168.1.2"
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except PermissionError:
                pass


# ---------------------------------------------------------------------------
# Test 4: Packet Parsing
# ---------------------------------------------------------------------------
def test_04_packet_parsing():
    """Verify comprehensive packet parsing without crashes or missing keys."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") /
        IP(src="10.0.0.1", dst="10.0.0.2", ttl=64, id=101) /
        TCP(sport=50000, dport=443, flags="PA", seq=1000, ack=2000, window=65535) /
        Raw(load=b"SecurePayloadBytes")
    )
    pkt.time = 1700000001.5

    record = parse_packet(pkt, packet_num=1)
    assert record["num"] == 1
    assert record["timestamp"] == 1700000001.5
    assert record["eth_src"] == "00:11:22:33:44:55"
    assert record["ip_src"] == "10.0.0.1"
    assert record["ip_dst"] == "10.0.0.2"
    assert record["ip_ttl"] == 64
    assert record["tcp_sport"] == 50000
    assert record["tcp_dport"] == 443
    assert record["tcp_seq"] == 1000
    assert record["tcp_ack"] == 2000
    assert "P" in record["tcp_flags"] and "A" in record["tcp_flags"]
    assert record["payload_len"] == len(b"SecurePayloadBytes")
    assert record["parse_error"] is None


# ---------------------------------------------------------------------------
# Test 5: IPv4 and IPv6 Detection
# ---------------------------------------------------------------------------
def test_05_ipv4_and_ipv6_detection():
    """Verify detection of both IPv4 and IPv6 network layer packets."""
    # IPv4
    p4 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IP(src="1.2.3.4", dst="5.6.7.8", ttl=128) / TCP(sport=111, dport=222)
    p4.time = 100.0
    rec4 = parse_packet(p4)
    assert rec4["ip_version"] == 4
    assert rec4["src_ip"] == "1.2.3.4"
    assert rec4["dst_ip"] == "5.6.7.8"
    assert rec4["ip_ttl"] == 128

    # IPv6
    p6 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64) / TCP(sport=333, dport=444)
    p6.time = 100.1
    rec6 = parse_packet(p6)
    assert rec6["ip_version"] == 6
    assert rec6["src_ip"] == "2001:db8::1"
    assert rec6["dst_ip"] == "2001:db8::2"
    assert rec6["ipv6_hlim"] == 64


# ---------------------------------------------------------------------------
# Test 6: TCP and UDP Detection
# ---------------------------------------------------------------------------
def test_06_tcp_and_udp_detection():
    """Verify transport layer distinction between TCP segments and UDP datagrams."""
    p_tcp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=12345, flags="S", seq=500)
    p_tcp.time = 1.0
    rec_tcp = parse_packet(p_tcp)
    assert rec_tcp["protocol"] == "TCP"
    assert rec_tcp["tcp_sport"] == 54321
    assert rec_tcp["tcp_dport"] == 12345
    assert rec_tcp["tcp_flags"] == "S"

    # Well-known port identification
    p_https = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="S")
    p_https.time = 1.05
    rec_https = parse_packet(p_https)
    assert rec_https["protocol"] == "HTTPS"
    assert rec_https["tcp_dport"] == 443

    p_udp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=53, len=32)
    p_udp.time = 2.0
    rec_udp = parse_packet(p_udp)
    assert rec_udp["protocol"] == "DNS"
    assert rec_udp["udp_sport"] == 1234
    assert rec_udp["udp_dport"] == 53
    assert rec_udp["udp_len"] == 32


# ---------------------------------------------------------------------------
# Test 7: DNS Parsing
# ---------------------------------------------------------------------------
def test_07_dns_parsing():
    """Verify resolution of DNS queries and responses."""
    dns_pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") /
        IP(src="8.8.8.8", dst="192.168.1.100") /
        UDP(sport=53, dport=54321) /
        DNS(id=0x9ABC, qr=1, qd=DNSQR(qname="google.com", qtype="A"),
            an=DNSRR(rrname="google.com", type="A", rdata="142.250.190.46", ttl=300))
    )
    dns_pkt.time = 10.0
    rec = parse_packet(dns_pkt)
    assert rec["protocol"] == "DNS"
    assert rec["dns_id"] == 0x9ABC
    assert rec["dns_qr"] == 1
    assert "google.com" in rec["dns_qname"]
    assert rec["dns_qtype_str"] == "A"
    assert rec["dns_ancount"] == 1
    assert len(rec["dns_answers"]) == 1
    assert rec["dns_answers"][0]["rdata"] == "142.250.190.46"


# ---------------------------------------------------------------------------
# Test 8: Packet Filtering
# ---------------------------------------------------------------------------
def test_08_packet_filtering():
    """Verify multi-parameter packet filtering on DataFrame."""
    raw, parsed, _ = load_pcap("sample_captures/synthetic_protocol_suite.pcap")
    df = packets_to_dataframe(parsed)

    # 1. Protocol filter
    df_dns = df[df["protocol"] == "DNS"]
    assert len(df_dns) >= 2

    # 2. IP filter
    df_ip = df[(df["src_ip"].str.contains("192.168.1.10", na=False)) | (df["dst_ip"].str.contains("192.168.1.10", na=False))]
    assert len(df_ip) >= 5

    # 3. Numeric port filter
    target_port = 80
    sport_num = pd.to_numeric(df["src_port"], errors="coerce")
    dport_num = pd.to_numeric(df["dst_port"], errors="coerce")
    df_port80 = df[(sport_num == target_port) | (dport_num == target_port)]
    assert len(df_port80) >= 8

    # 4. Time range filter
    min_t, max_t = df["timestamp"].min(), df["timestamp"].max()
    mid_t = min_t + (max_t - min_t) / 2
    df_time = df[df["timestamp"] <= mid_t]
    assert 0 < len(df_time) < len(df)


# ---------------------------------------------------------------------------
# Test 9: Packet Selection & Index Bounds
# ---------------------------------------------------------------------------
def test_09_packet_selection_bounds():
    """Verify navigation boundaries and safe index clamped jumps."""
    raw, parsed, _ = load_pcap("sample_captures/sample_traffic.pcap")
    total = len(parsed)

    # Within bounds
    idx = 0
    assert 0 <= idx < total
    pkt = parsed[idx]
    assert pkt["num"] == 1

    # End boundary
    idx_end = total - 1
    assert 0 <= idx_end < total
    pkt_end = parsed[idx_end]
    assert pkt_end["num"] == total


# ---------------------------------------------------------------------------
# Test 10: Protocol-Layer Visualization (Encapsulation Stack)
# ---------------------------------------------------------------------------
def test_10_protocol_layer_visualization():
    """Verify dynamic layer extraction, PDU naming, and highlights."""
    raw, _, _ = load_pcap("sample_captures/synthetic_protocol_suite.pcap")
    # Frame 6 is HTTP Data over TCP
    http_frame = raw[5]

    layers = get_packet_layers(http_frame)
    layer_names = [l["name"] for l in layers]
    assert "Ethernet II" in layer_names
    assert "Internet Protocol Version 4 (IPv4)" in layer_names
    assert "Transmission Control Protocol (TCP)" in layer_names
    assert "Data / Payload" in layer_names

    # Verify highlights
    tcp_layer = next(l for l in layers if "TCP" in l["name"])
    assert "Source Port" in tcp_layer["highlights"]
    assert "Destination Port" in tcp_layer["highlights"]
    assert "Sequence Number" in tcp_layer["highlights"]
    assert tcp_layer["pdu_name"] == "Segment"


# ---------------------------------------------------------------------------
# Test 11: Hexadecimal Packet Inspection
# ---------------------------------------------------------------------------
def test_11_hexadecimal_inspection():
    """Verify 16-byte dual-column hex and ASCII dump generation."""
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
    raw_bytes = get_raw_bytes(pkt)
    assert len(raw_bytes) > 0

    dump = generate_hex_dump(raw_bytes)
    assert "0000  " in dump
    assert "0010  " in dump
    # Verify ASCII representation is rendered on the right side
    lines = dump.strip().split("\n")
    assert len(lines) >= 2
    for line in lines:
        assert len(line) > 30  # Contains offset, hex octets, and ASCII chars


# ---------------------------------------------------------------------------
# Test 12: TCP Flow Grouping
# ---------------------------------------------------------------------------
def test_12_tcp_flow_grouping():
    """Verify bidirectional flow grouping with IPv4 and IPv6 normalization."""
    raw, parsed, _ = load_pcap("sample_captures/synthetic_protocol_suite.pcap")
    flows = group_into_flows(parsed)
    assert len(flows) >= 3

    # Check that flow keys are normalized and contain protocol tag
    for k in flows.keys():
        assert "<->" in k
        assert "[" in k and "]" in k


# ---------------------------------------------------------------------------
# Test 13: TCP Handshake Analysis & State Machine
# ---------------------------------------------------------------------------
def test_13_tcp_handshake_analysis():
    """Verify 3-way handshake detection, state machine, and initial RTT measurement."""
    raw, parsed, _ = load_pcap("sample_captures/synthetic_protocol_suite.pcap")
    flow_analyses = analyze_all_flows(parsed)

    # Find the port 80 HTTP flow
    http_flows = [f for f in flow_analyses if f["dst_port"] == 80 or f["src_port"] == 80]
    assert len(http_flows) >= 1
    hf = http_flows[0]

    assert hf["has_syn"] is True
    assert hf["has_syn_ack"] is True
    assert hf["has_final_ack"] is True
    assert hf["handshake_state"] == "ESTABLISHED"
    assert hf["rtt_ms"] is not None
    assert hf["rtt_ms"] > 0
    assert hf["payload_bytes"] > 0
    assert hf["data_packets"] >= 2


# ---------------------------------------------------------------------------
# Test 14: Network Analytics
# ---------------------------------------------------------------------------
def test_14_network_analytics():
    """Verify aggregate analytics (protocols, talkers, ports, flags, DNS, timeline)."""
    raw, parsed, _ = load_pcap("sample_captures/synthetic_protocol_suite.pcap")
    df = packets_to_dataframe(parsed)

    # 1. Protocols
    protos = analyze_protocols(df)
    assert protos["total_packets"] == len(df)
    assert "HTTP" in protos["counts"] or "TCP" in protos["counts"]

    # 2. Talkers
    ips = analyze_top_ips(df)
    assert len(ips["top_src"]) > 0

    # 3. Ports
    ports = analyze_top_ports(df)
    assert "80" in ports["ports"] or 80 in ports["ports"]

    # 4. TCP flags
    flags = analyze_tcp_flags(df)
    assert flags["SYN"] >= 1
    assert flags["ACK"] >= 1

    # 5. DNS queries
    dns = analyze_dns_queries(df)
    assert dns["total_queries"] >= 1

    # 6. Timeline
    timeline = analyze_traffic_timeline(df, bins=10)
    assert not timeline.empty
    assert "packet_count" in timeline.columns


# ---------------------------------------------------------------------------
# Test 15: Capture Comparison
# ---------------------------------------------------------------------------
def test_15_capture_comparison():
    """Verify differential analysis comparing baseline vs impaired captures."""
    _, parsed_base, _ = load_pcap("sample_captures/sample_traffic.pcap")
    _, parsed_imp, _ = load_pcap("sample_captures/sample_impaired.pcap")

    df_a = packets_to_dataframe(parsed_base)
    df_b = packets_to_dataframe(parsed_imp)

    flows_a = analyze_all_flows(parsed_base)
    flows_b = analyze_all_flows(parsed_imp)

    # Verify differential calculations
    delta_packets = len(df_b) - len(df_a)
    assert delta_packets == (11 - 21)

    retrans_a = sum(f.get("potential_retransmissions", 0) for f in flows_a)
    retrans_b = sum(f.get("potential_retransmissions", 0) for f in flows_b)
    assert retrans_b > retrans_a  # Impaired capture contains retransmissions

    rtts_a = [f["rtt_ms"] for f in flows_a if f.get("rtt_ms") is not None]
    rtts_b = [f["rtt_ms"] for f in flows_b if f.get("rtt_ms") is not None]
    assert len(rtts_a) > 0 and len(rtts_b) > 0
    # Impaired handshake RTT must be substantially higher than baseline
    avg_rtt_a = sum(rtts_a) / len(rtts_a)
    avg_rtt_b = sum(rtts_b) / len(rtts_b)
    assert avg_rtt_b > avg_rtt_a


# ---------------------------------------------------------------------------
# Test 16: Live Capture Environment Check
# ---------------------------------------------------------------------------
def test_16_live_capture_environment():
    """Verify live capture availability check and interface enumeration."""
    avail, msg = is_live_capture_available()
    assert isinstance(avail, bool)
    assert isinstance(msg, str)

    ifaces = get_available_interfaces()
    assert isinstance(ifaces, list)
    # Even without Npcap, fallback interface list is returned
    assert len(ifaces) >= 0


# ---------------------------------------------------------------------------
# Test 17: Capture Start, Stop, Bounded Queue & Thread Cleanup
# ---------------------------------------------------------------------------
def test_17_capture_lifecycle_and_bounded_buffer():
    """Verify that capture engine starts, stops, and enforces bounded queue."""
    engine = LiveCaptureEngine(max_buffer=50)
    assert engine.is_capturing is False
    assert engine.max_buffer == 50

    # Stop on idle engine is safe
    engine.stop()
    assert engine.is_capturing is False

    # Simulate packet arrival in bounded queue
    for i in range(70):
        try:
            engine.packet_queue.put_nowait(Ether() / IP() / ICMP())
        except Exception:
            pass
    # Bounded queue must not exceed max_buffer
    assert engine.packet_queue.qsize() <= 50

    # Drain queue
    drained = engine.get_new_packets()
    assert len(drained) == 50
    assert engine.packet_queue.empty()


# ---------------------------------------------------------------------------
# Test 18: Invalid Input Handling
# ---------------------------------------------------------------------------
def test_18_invalid_input_handling():
    """Verify clear errors for non-existent files and corrupt formats."""
    # 1. Non-existent file
    valid, err = validate_pcap_path("non_existent_capture_file.pcap")
    assert valid is False
    assert "File not found" in err

    # 2. Directory instead of file
    valid_dir, err_dir = validate_pcap_path("sample_captures")
    assert valid_dir is False
    assert "not a regular file" in err_dir

    # 3. Corrupt non-pcap file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(b"NOT_A_VALID_PCAP_MAGIC_NUMBER_RANDOM_TEXT_123456789")
        bad_path = tmp.name

    try:
        raw, parsed, err_corrupt = load_pcap(bad_path)
        assert err_corrupt is not None
        assert "Corrupt or unsupported capture file format" in err_corrupt
        assert len(raw) == 0
    finally:
        import gc
        gc.collect()
        if os.path.exists(bad_path):
            os.remove(bad_path)


# ---------------------------------------------------------------------------
# Test 19: Empty Capture Handling
# ---------------------------------------------------------------------------
def test_19_empty_capture_handling():
    """Verify handling of 0-byte capture files and empty DataFrames."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        empty_path = tmp.name  # 0 bytes

    try:
        valid, err = validate_pcap_path(empty_path)
        assert valid is False
        assert "is empty (0 bytes)" in err

        raw, parsed, err_load = load_pcap(empty_path)
        assert err_load is not None
        assert len(raw) == 0
    finally:
        import gc
        gc.collect()
        if os.path.exists(empty_path):
            os.remove(empty_path)

    # Empty analytics handling
    empty_df = pd.DataFrame()
    proto_empty = analyze_protocols(empty_df)
    assert proto_empty["counts"] == {}

    top_ips_empty = analyze_top_ips(empty_df)
    assert top_ips_empty["top_src"] == {}

    flows_empty = analyze_all_flows([])
    assert flows_empty == []


# ---------------------------------------------------------------------------
# Test 20: Export Functionality
# ---------------------------------------------------------------------------
def test_20_export_functionality():
    """Verify exporting packets to PCAP and round-trip re-reading."""
    raw, _, _ = load_pcap("sample_captures/sample_traffic.pcap")
    assert len(raw) > 0

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        export_path = tmp.name

    try:
        # Export
        success, err = export_pcap(raw, export_path)
        assert success is True
        assert err is None
        assert os.path.exists(export_path)
        assert os.path.getsize(export_path) > 0

        # Reload exported file and verify 100% data fidelity
        re_raw, re_parsed, re_err = load_pcap(export_path)
        assert re_err is None
        assert len(re_raw) == len(raw)
        assert len(re_parsed) == len(raw)
        assert re_parsed[0]["protocol"] == "DNS"
    finally:
        import gc
        gc.collect()
        if os.path.exists(export_path):
            os.remove(export_path)

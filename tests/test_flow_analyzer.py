"""
test_flow_analyzer.py — Tests for TCP flow reconstruction and state machine.
"""

from core.flow_analyzer import analyze_all_flows, group_into_flows, make_flow_key, analyze_flow
from core.pcap_manager import load_pcap


def test_flow_grouping_bidirectional():
    """Packets in both directions should map to the exact same flow key."""
    pkt_a = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 100, "dst_port": 200, "protocol": "TCP", "timestamp": 1.0}
    pkt_b = {"src_ip": "2.2.2.2", "dst_ip": "1.1.1.1", "src_port": 200, "dst_port": 100, "protocol": "TCP", "timestamp": 2.0}

    key_a = make_flow_key(pkt_a)
    key_b = make_flow_key(pkt_b)
    assert key_a == key_b
    assert key_a is not None


def test_flow_grouping_ipv6_bidirectional():
    """IPv6 endpoints with colons must be normalized and bracketed bidirectionally."""
    pkt_a = {"src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "src_port": 54321, "dst_port": 80, "protocol": "TCP", "timestamp": 1.0}
    pkt_b = {"src_ip": "2001:db8::2", "dst_ip": "2001:db8::1", "src_port": 80, "dst_port": 54321, "protocol": "TCP", "timestamp": 1.05}

    key_a = make_flow_key(pkt_a)
    key_b = make_flow_key(pkt_b)
    assert key_a == key_b
    assert "[2001:db8::1]:54321" in key_a or "[2001:db8::2]:80" in key_a


def test_flow_grouping_no_ip():
    """Packets without IP should return None flow key."""
    pkt = {"src_ip": None, "dst_ip": None, "protocol": "ARP"}
    assert make_flow_key(pkt) is None


def test_analyze_sample_flows():
    """Test flow analysis with the real sample capture."""
    sample_path = "sample_captures/sample_traffic.pcap"
    _, parsed, err = load_pcap(sample_path)
    assert err is None

    flows = analyze_all_flows(parsed)
    assert len(flows) >= 2

    # Find the HTTP flow (port 80)
    http_flows = [f for f in flows if f.get("dst_port") == 80 or f.get("src_port") == 80]
    assert len(http_flows) >= 1
    http_flow = http_flows[0]

    # Should detect complete TCP handshake and termination
    assert http_flow["has_syn"]
    assert http_flow["has_fin"]
    assert "Complete" in http_flow["tcp_state"] or "Established" in http_flow["tcp_state"]
    assert http_flow["packet_count"] >= 5

    # Find the RST flow (port 8080)
    rst_flows = [f for f in flows if f.get("dst_port") == 8080 or f.get("src_port") == 8080]
    assert len(rst_flows) >= 1
    rst_flow = rst_flows[0]
    assert rst_flow["has_rst"]
    assert "Refused" in rst_flow["tcp_state"]

    # Check events exist
    assert len(http_flow.get("events", [])) >= 3

    # Check RTT calculation
    assert http_flow.get("rtt_ms") is not None
    assert http_flow["rtt_ms"] > 0


def test_udp_flow_state():
    """UDP flows should be identified as UDP (Connectionless)."""
    pkts = [
        {"src_ip": "1.1.1.1", "dst_ip": "8.8.8.8", "src_port": 5000, "dst_port": 53, "udp_sport": 5000, "protocol": "DNS", "timestamp": 1.0, "length": 50},
        {"src_ip": "8.8.8.8", "dst_ip": "1.1.1.1", "src_port": 53, "dst_port": 5000, "udp_sport": 53, "protocol": "DNS", "timestamp": 1.05, "length": 80},
    ]
    flows = analyze_all_flows(pkts)
    assert len(flows) == 1
    assert "UDP (Connectionless)" in flows[0]["tcp_state"]


# ===========================================================================
# Synthetic Test Cases for Handshakes, Teardowns, Resets, and Data Delivery
# ===========================================================================

def test_synthetic_normal_handshake_data_and_termination():
    """
    Test complete lifecycle:
    1. Client SYN
    2. Server SYN-ACK (RTT delta)
    3. Client ACK (Handshake Established)
    4. Client Data Transfer (100 Bytes)
    5. Server ACK
    6. Server Data Transfer (250 Bytes)
    7. Client FIN
    8. Server ACK
    9. Server FIN
    10. Client ACK (Graceful 4-Way Teardown)
    """
    pkts = [
        # Handshake
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000, "dst_port": 80,
         "tcp_flags": "S", "tcp_flags_str": "SYN", "tcp_seq": 1000, "tcp_ack": 0, "timestamp": 1.000, "length": 74, "payload_len": 0},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 40000,
         "tcp_flags": "SA", "tcp_flags_str": "SYN, ACK", "tcp_seq": 5000, "tcp_ack": 1001, "timestamp": 1.025, "length": 74, "payload_len": 0},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000, "dst_port": 80,
         "tcp_flags": "A", "tcp_flags_str": "ACK", "tcp_seq": 1001, "tcp_ack": 5001, "timestamp": 1.026, "length": 66, "payload_len": 0},

        # Data exchange
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000, "dst_port": 80,
         "tcp_flags": "PA", "tcp_flags_str": "PSH, ACK", "tcp_seq": 1001, "tcp_ack": 5001, "timestamp": 1.030, "length": 166, "payload_len": 100},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 40000,
         "tcp_flags": "A", "tcp_flags_str": "ACK", "tcp_seq": 5001, "tcp_ack": 1101, "timestamp": 1.035, "length": 66, "payload_len": 0},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 40000,
         "tcp_flags": "PA", "tcp_flags_str": "PSH, ACK", "tcp_seq": 5001, "tcp_ack": 1101, "timestamp": 1.040, "length": 316, "payload_len": 250},

        # Teardown
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000, "dst_port": 80,
         "tcp_flags": "FA", "tcp_flags_str": "FIN, ACK", "tcp_seq": 1101, "tcp_ack": 5251, "timestamp": 1.050, "length": 66, "payload_len": 0},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 40000,
         "tcp_flags": "A", "tcp_flags_str": "ACK", "tcp_seq": 5251, "tcp_ack": 1102, "timestamp": 1.055, "length": 66, "payload_len": 0},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 40000,
         "tcp_flags": "FA", "tcp_flags_str": "FIN, ACK", "tcp_seq": 5251, "tcp_ack": 1102, "timestamp": 1.060, "length": 66, "payload_len": 0},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000, "dst_port": 80,
         "tcp_flags": "A", "tcp_flags_str": "ACK", "tcp_seq": 1102, "tcp_ack": 5252, "timestamp": 1.065, "length": 66, "payload_len": 0},
    ]

    flows = analyze_all_flows(pkts)
    assert len(flows) == 1
    flow = flows[0]

    assert flow["has_syn"] is True
    assert flow["has_syn_ack"] is True
    assert flow["has_final_ack"] is True
    assert flow["client_fin"] is True
    assert flow["server_fin"] is True
    assert flow["handshake_state"] == "ESTABLISHED"
    assert "Complete" in flow["tcp_state"]
    assert flow["rtt_ms"] == 25.0  # 1.025 - 1.000 = 25ms
    assert flow["payload_bytes"] == 350  # 100B + 250B
    assert flow["data_packets"] == 2
    assert flow["duration_sec"] == 0.065


def test_synthetic_incomplete_handshake_syn_only():
    """Client sends SYN and retransmits SYN; server never responds."""
    pkts = [
        {"src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 49152, "dst_port": 443,
         "tcp_flags": "S", "tcp_flags_str": "SYN", "tcp_seq": 100, "timestamp": 2.0, "length": 74, "payload_len": 0},
        {"src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 49152, "dst_port": 443,
         "tcp_flags": "S", "tcp_flags_str": "SYN", "tcp_seq": 100, "timestamp": 3.0, "length": 74, "payload_len": 0},
    ]
    flows = analyze_all_flows(pkts)
    assert len(flows) == 1
    flow = flows[0]

    assert flow["has_syn"] is True
    assert flow["has_syn_ack"] is False
    assert flow["has_final_ack"] is False
    assert flow["handshake_state"] == "ATTEMPT_ONLY"
    assert "Incomplete (SYN Only" in flow["tcp_state"]
    assert flow["potential_retransmissions"] == 1


def test_synthetic_incomplete_handshake_missing_final_ack():
    """Client sends SYN, Server sends SYN-ACK, but Client never sends 3rd ACK."""
    pkts = [
        {"src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 49152, "dst_port": 80,
         "tcp_flags": "S", "tcp_flags_str": "SYN", "tcp_seq": 200, "timestamp": 1.0, "length": 74, "payload_len": 0},
        {"src_ip": "10.0.0.99", "dst_ip": "192.168.1.50", "src_port": 80, "dst_port": 49152,
         "tcp_flags": "SA", "tcp_flags_str": "SYN, ACK", "tcp_seq": 800, "tcp_ack": 201, "timestamp": 1.015, "length": 74, "payload_len": 0},
    ]
    flows = analyze_all_flows(pkts)
    assert len(flows) == 1
    flow = flows[0]

    assert flow["has_syn"] is True
    assert flow["has_syn_ack"] is True
    assert flow["has_final_ack"] is False
    assert flow["handshake_state"] == "INCOMPLETE"
    assert "Missing Final ACK" in flow["tcp_state"]
    assert flow["rtt_ms"] == 15.0


def test_synthetic_connection_refused_syn_rst():
    """Client sends SYN, Server immediately responds with RST (port closed)."""
    pkts = [
        {"src_ip": "10.1.1.1", "dst_ip": "10.1.1.2", "src_port": 35000, "dst_port": 9999,
         "tcp_flags": "S", "tcp_flags_str": "SYN", "tcp_seq": 500, "timestamp": 10.0, "length": 74, "payload_len": 0},
        {"src_ip": "10.1.1.2", "dst_ip": "10.1.1.1", "src_port": 9999, "dst_port": 35000,
         "tcp_flags": "RA", "tcp_flags_str": "RST, ACK", "tcp_seq": 0, "tcp_ack": 501, "timestamp": 10.002, "length": 60, "payload_len": 0},
    ]
    flows = analyze_all_flows(pkts)
    assert len(flows) == 1
    flow = flows[0]

    assert flow["has_syn"] is True
    assert flow["has_rst"] is True
    assert flow["handshake_state"] == "REFUSED"
    assert "Connection Refused (SYN → RST)" in flow["tcp_state"]


def test_synthetic_established_rst_abort():
    """Connection established via 3-way handshake, then abruptly aborted with RST."""
    pkts = [
        {"src_ip": "10.1.1.1", "dst_ip": "10.1.1.2", "src_port": 35000, "dst_port": 80,
         "tcp_flags": "S", "tcp_flags_str": "SYN", "tcp_seq": 100, "timestamp": 1.0, "length": 74, "payload_len": 0},
        {"src_ip": "10.1.1.2", "dst_ip": "10.1.1.1", "src_port": 80, "dst_port": 35000,
         "tcp_flags": "SA", "tcp_flags_str": "SYN, ACK", "tcp_seq": 200, "tcp_ack": 101, "timestamp": 1.01, "length": 74, "payload_len": 0},
        {"src_ip": "10.1.1.1", "dst_ip": "10.1.1.2", "src_port": 35000, "dst_port": 80,
         "tcp_flags": "A", "tcp_flags_str": "ACK", "tcp_seq": 101, "tcp_ack": 201, "timestamp": 1.011, "length": 66, "payload_len": 0},
        {"src_ip": "10.1.1.2", "dst_ip": "10.1.1.1", "src_port": 80, "dst_port": 35000,
         "tcp_flags": "R", "tcp_flags_str": "RST", "tcp_seq": 201, "timestamp": 1.02, "length": 60, "payload_len": 0},
    ]
    flows = analyze_all_flows(pkts)
    assert len(flows) == 1
    flow = flows[0]

    assert flow["has_syn"] is True
    assert flow["has_final_ack"] is True
    assert flow["has_rst"] is True
    assert "Reset (Established → RST Abort)" in flow["tcp_state"]


def test_synthetic_midstream_capture():
    """Capture begins after connection established; only data & ACKs observed."""
    pkts = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80,
         "tcp_flags": "A", "tcp_flags_str": "ACK", "tcp_seq": 9000, "tcp_ack": 4000, "timestamp": 5.0, "length": 66, "payload_len": 0},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80,
         "tcp_flags": "PA", "tcp_flags_str": "PSH, ACK", "tcp_seq": 9000, "tcp_ack": 4000, "timestamp": 5.01, "length": 266, "payload_len": 200},
    ]
    flows = analyze_all_flows(pkts)
    assert len(flows) == 1
    flow = flows[0]

    assert flow["has_syn"] is False
    assert flow["handshake_state"] == "MID_STREAM"
    assert "Data Only (Mid-Stream" in flow["tcp_state"]
    assert flow["payload_bytes"] == 200

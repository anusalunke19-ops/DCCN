"""
test_protocol_analyzer.py — Unit tests for core/protocol_analyzer.py.
"""

import pandas as pd
from core.protocol_analyzer import (
    analyze_protocols,
    analyze_top_ips,
    analyze_top_ports,
    analyze_tcp_flags,
    analyze_dns_queries,
    analyze_traffic_timeline
)
from core.pcap_manager import load_pcap, packets_to_dataframe


def test_protocol_analyzer_with_sample_capture():
    sample_path = "sample_captures/sample_traffic.pcap"
    _, parsed, err = load_pcap(sample_path)
    assert err is None
    df = packets_to_dataframe(parsed)

    # 1. Protocol analysis
    proto_stats = analyze_protocols(df)
    assert proto_stats["total_packets"] == 21
    assert "DNS" in proto_stats["counts"]
    assert "HTTP" in proto_stats["counts"]

    # 2. Top IPs
    ip_stats = analyze_top_ips(df)
    assert "192.168.1.100" in ip_stats["top_src"]
    assert len(ip_stats["top_endpoints"]) > 0

    # 3. Top Ports
    port_stats = analyze_top_ports(df)
    assert "53" in port_stats["ports"] or "80" in port_stats["ports"]

    # 4. TCP Flags
    flags = analyze_tcp_flags(df)
    assert "SYN" in flags
    assert "ACK" in flags
    assert "FIN" in flags
    assert "RST" in flags

    # 5. DNS Queries
    dns_stats = analyze_dns_queries(df)
    assert dns_stats["total_queries"] >= 2
    assert "example.com" in dns_stats["domains"]

    # 6. Timeline
    timeline = analyze_traffic_timeline(df, bins=5)
    assert not timeline.empty
    assert len(timeline) <= 5

"""
test_explain.py — Unit tests for core/explain.py.
"""

from core.explain import explain_packet


def test_explain_tcp_syn():
    parsed = {
        "protocol": "TCP",
        "tcp_flags_str": "SYN",
        "src_ip": "192.168.1.10",
        "dst_ip": "1.1.1.1",
        "src_port": 50000,
        "dst_port": 80,
        "tcp_seq": 1000,
        "tcp_window": 65535,
        "ip_version": 4,
        "ip_ttl": 64,
        "length": 60
    }
    exp = explain_packet(parsed)
    assert "SYN" in exp["summary"]
    assert any("Three-Way Handshake" in t for t in exp["takeaways"])
    assert "Three-Way Handshake" in exp["dccn_concepts"]


def test_explain_dns():
    parsed = {
        "protocol": "DNS",
        "dns_qr": 0,
        "dns_qname": "google.com",
        "dns_qtype_str": "A",
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "ip_version": 4,
        "ip_ttl": 64,
        "length": 70
    }
    exp = explain_packet(parsed)
    assert "DNS" in exp["summary"]
    assert "google.com" in exp["summary"]
    assert any("Client-Server" in t for t in exp["takeaways"])

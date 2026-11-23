"""
test_pcap_manager.py — Unit tests for core/pcap_manager.py.

Tests loading valid, empty, non-existent, and malformed files,
as well as PCAP exporting and DataFrame conversion.
"""

import os
import tempfile
import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from core.pcap_manager import (
    validate_pcap_path,
    load_pcap,
    export_pcap,
    packets_to_dataframe
)

DUMMY_SRC_MAC = "00:11:22:33:44:55"
DUMMY_DST_MAC = "66:77:88:99:AA:BB"


def test_validate_nonexistent_file():
    is_valid, err = validate_pcap_path("non_existent_file.pcap")
    assert not is_valid
    assert "File not found" in err


def test_validate_empty_file():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        empty_path = tf.name

    try:
        is_valid, err = validate_pcap_path(empty_path)
        assert not is_valid
        assert "empty" in err
    finally:
        if os.path.exists(empty_path):
            os.remove(empty_path)


def test_load_and_export_pcap():
    pkt1 = Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC) / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=100, dport=200, flags="S")
    pkt2 = Ether(src=DUMMY_DST_MAC, dst=DUMMY_SRC_MAC) / IP(src="2.2.2.2", dst="1.1.1.1") / TCP(sport=200, dport=100, flags="SA")

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test.pcap")

        # Export test
        success, err = export_pcap([pkt1, pkt2], test_file)
        assert success
        assert err is None
        assert os.path.exists(test_file)

        # Load test
        raw_pkts, parsed_pkts, err = load_pcap(test_file)
        assert err is None
        assert len(raw_pkts) == 2
        assert len(parsed_pkts) == 2

        # Check DataFrame conversion
        df = packets_to_dataframe(parsed_pkts)
        assert len(df) == 2
        assert "src_ip" in df.columns
        assert df.iloc[0]["src_ip"] == "1.1.1.1"
        assert df.iloc[1]["src_ip"] == "2.2.2.2"


def test_load_sample_capture():
    sample_path = "sample_captures/sample_traffic.pcap"
    assert os.path.exists(sample_path)

    raw, parsed, err = load_pcap(sample_path)
    assert err is None
    assert len(raw) == 21
    assert len(parsed) == 21

    df = packets_to_dataframe(parsed)
    assert not df.empty
    assert len(df) == 21
    assert "DNS" in df["protocol"].values
    assert "HTTP" in df["protocol"].values
    assert "ICMP" in df["protocol"].values


def test_load_synthetic_protocol_suite():
    """Verify the dedicated synthetic benchmark capture contains all required protocol categories."""
    suite_path = "sample_captures/synthetic_protocol_suite.pcap"
    assert os.path.exists(suite_path)

    raw, parsed, err = load_pcap(suite_path)
    assert err is None
    assert len(raw) >= 19

    df = packets_to_dataframe(parsed)
    assert not df.empty

    # 1. DNS query and response
    assert any(p.get("dns_qname") for p in parsed)
    # 2. TCP three-way handshake
    assert any("S" in (p.get("tcp_flags") or "") for p in parsed)
    assert any("SA" in (p.get("tcp_flags") or "") for p in parsed)
    # 3. TCP data exchange
    assert any((p.get("payload_len") or 0) > 0 for p in parsed)
    # 4. TCP connection termination
    assert any("F" in (p.get("tcp_flags") or "") for p in parsed)
    # 5. UDP communication
    assert any(p.get("udp_sport") for p in parsed)
    # 6. ICMP echo request and reply
    assert any(p.get("icmp_type") in (0, 8) for p in parsed)
    # 7. IPv6 traffic
    assert any(p.get("ip_version") == 6 for p in parsed)

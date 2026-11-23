"""
test_packet_parser.py — Unit tests for core/packet_parser.py.

Tests parsing of synthetic IPv4, IPv6, TCP, UDP, DNS, ICMP packets,
as well as packets with missing layers or malformed data.
"""

import pytest
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, ICMP, Raw, ARP
)
from core.packet_parser import parse_packet, get_packet_layers

DUMMY_SRC_MAC = "00:11:22:33:44:55"
DUMMY_DST_MAC = "66:77:88:99:AA:BB"


def test_parse_ipv4_tcp_syn():
    pkt = (
        Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC) /
        IP(src="192.168.1.50", dst="142.250.190.46", ttl=64) /
        TCP(sport=49152, dport=443, flags="S", seq=1000)
    )
    parsed = parse_packet(pkt, packet_num=1)

    assert parsed["num"] == 1
    assert parsed["eth_src"] == DUMMY_SRC_MAC
    assert parsed["src_ip"] == "192.168.1.50"
    assert parsed["dst_ip"] == "142.250.190.46"
    assert parsed["ip_version"] == 4
    assert parsed["ip_ttl"] == 64
    assert parsed["src_port"] == 49152
    assert parsed["dst_port"] == 443
    assert parsed["tcp_seq"] == 1000
    assert "SYN" in parsed["tcp_flags_str"]
    assert parsed["protocol"] == "HTTPS"
    assert "SYN" in parsed["info"]


def test_parse_udp_dns_query():
    pkt = (
        Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC) /
        IP(src="192.168.1.50", dst="8.8.8.8") /
        UDP(sport=53000, dport=53) /
        DNS(id=0x1234, qr=0, qd=DNSQR(qname="google.com", qtype="A"))
    )
    parsed = parse_packet(pkt, packet_num=2)

    assert parsed["src_ip"] == "192.168.1.50"
    assert parsed["dst_ip"] == "8.8.8.8"
    assert parsed["protocol"] == "DNS"
    assert parsed["dns_qname"] == "google.com"
    assert parsed["dns_qtype_str"] == "A"
    assert parsed["dns_qr"] == 0
    assert "google.com" in parsed["info"]


def test_parse_dns_response():
    pkt = (
        Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC) /
        IP(src="8.8.8.8", dst="192.168.1.50") /
        UDP(sport=53, dport=53000) /
        DNS(id=0x1234, qr=1, rcode=0,
            qd=DNSQR(qname="google.com", qtype="A"),
            an=DNSRR(rrname="google.com", type="A", rdata="142.250.190.46", ttl=300))
    )
    parsed = parse_packet(pkt, packet_num=3)

    assert parsed["protocol"] == "DNS"
    assert parsed["dns_qr"] == 1
    assert parsed["dns_rcode"] == 0
    assert parsed["dns_answers"] is not None
    assert len(parsed["dns_answers"]) >= 1
    assert parsed["dns_answers"][0]["rdata"] == "142.250.190.46"


def test_parse_icmp_echo():
    pkt = (
        Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC) /
        IP(src="192.168.1.50", dst="1.1.1.1") /
        ICMP(type=8, code=0, id=0x4321, seq=5) /
        Raw(load=b"pingpayload")
    )
    parsed = parse_packet(pkt, packet_num=4)

    assert parsed["protocol"] == "ICMP"
    assert parsed["icmp_type"] == 8
    assert parsed["icmp_type_str"] == "Echo Request"
    assert parsed["icmp_seq"] == 5
    assert parsed["has_payload"] is True


def test_parse_ipv6():
    pkt = (
        Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC) /
        IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64) /
        UDP(sport=1234, dport=5678)
    )
    parsed = parse_packet(pkt, packet_num=5)

    assert parsed["ip_version"] == 6
    assert parsed["src_ip"] == "2001:db8::1"
    assert parsed["dst_ip"] == "2001:db8::2"
    assert parsed["ipv6_hlim"] == 64
    assert parsed["protocol"] == "UDP"


def test_missing_layers():
    # Only Ethernet, no IP or TCP/UDP
    pkt = Ether(src="AA:BB:CC:DD:EE:01", dst="AA:BB:CC:DD:EE:02", type=0x88F7)
    parsed = parse_packet(pkt, packet_num=6)

    assert parsed["eth_src"] == "AA:BB:CC:DD:EE:01"
    assert parsed["src_ip"] is None
    assert parsed["src_port"] is None
    assert parsed["protocol"] == "Ethernet"


def test_get_packet_layers():
    pkt = (
        Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC) /
        IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=12345, dport=80, flags="PA") /
        Raw(load=b"GET / HTTP/1.1\r\n\r\n")
    )
    layers = get_packet_layers(pkt)

    layer_names = [l["name"] for l in layers]
    assert "Ethernet II" in layer_names
    assert "Internet Protocol Version 4 (IPv4)" in layer_names
    assert "Transmission Control Protocol (TCP)" in layer_names
    assert "Data / Payload" in layer_names

    # Verify enrichment fields for Packet Journey
    tcp_layer = next(l for l in layers if "TCP" in l["name"])
    assert tcp_layer["pdu_name"] == "Segment"
    assert tcp_layer["highlights"]["Source Port"] == "12345"
    assert tcp_layer["highlights"]["Destination Port"] == "80"
    assert "PSH" in tcp_layer["highlights"]["Flags"]

    ip_layer = next(l for l in layers if "IPv4" in l["name"])
    assert ip_layer["pdu_name"] == "Datagram / Packet"
    assert ip_layer["highlights"]["Source IP"] == "10.0.0.1"
    assert ip_layer["highlights"]["Destination IP"] == "10.0.0.2"


def test_get_packet_layers_udp_dns():
    from scapy.all import UDP, DNS, DNSQR
    pkt = (
        Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC) /
        IP(src="192.168.1.10", dst="8.8.8.8", ttl=64) /
        UDP(sport=54321, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="example.com", qtype=1))
    )
    layers = get_packet_layers(pkt)
    layer_names = [l["name"] for l in layers]
    assert "Ethernet II" in layer_names
    assert "Internet Protocol Version 4 (IPv4)" in layer_names
    assert "User Datagram Protocol (UDP)" in layer_names
    assert "Domain Name System (DNS)" in layer_names

    dns_layer = next(l for l in layers if "DNS" in l["name"])
    assert dns_layer["pdu_name"] == "Application Message"
    assert dns_layer["highlights"]["Query Name"] == "example.com"
    assert dns_layer["highlights"]["Query Type"] == "A"
    assert dns_layer["highlights"]["Message Type"] == "Query"

    udp_layer = next(l for l in layers if "UDP" in l["name"])
    assert udp_layer["highlights"]["Source Port"] == "54321"
    assert udp_layer["highlights"]["Destination Port"] == "53"


def test_get_packet_layers_arp():
    pkt = Ether(src=DUMMY_SRC_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=DUMMY_SRC_MAC, psrc="192.168.1.1", pdst="192.168.1.254")
    layers = get_packet_layers(pkt)
    layer_names = [l["name"] for l in layers]
    assert "Ethernet II" in layer_names
    assert "Address Resolution Protocol (ARP)" in layer_names

"""
generate_sample_capture.py — Create a realistic sample PCAP file for demos.

This script builds synthetic packets that simulate a realistic network
session: DNS lookup, TCP handshake, HTTP request/response, and connection
close. These packets are entirely synthetic (no real traffic is captured),
so we can use them without admin privileges for testing and demos.

DCCN concepts demonstrated:
- DNS resolution (application asks "what IP is example.com?")
- TCP three-way handshake (SYN → SYN-ACK → ACK)
- Data transfer over TCP (HTTP GET request)
- TCP connection teardown (FIN → FIN-ACK → ACK)
- Protocol encapsulation (each packet wraps layers)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR,
    ICMP, Raw, wrpcap, ICMPv6EchoRequest
)
import time


def generate_sample_capture(output_path: str = "sample_captures/sample_traffic.pcap"):
    """
    Generate a sample PCAP file with diverse, realistic traffic.

    The capture simulates:
    1. DNS lookup for example.com
    2. TCP handshake to the web server
    3. HTTP GET request
    4. HTTP response
    5. TCP connection close
    6. ICMP ping
    7. Some UDP traffic
    8. A TCP RST (connection reset) example
    9. IPv6 traffic sample
    """
    packets = []
    base_time = 1700000000.0  # Fixed timestamp for reproducibility

    # Common addresses
    client_mac = "00:11:22:33:44:55"
    server_mac = "66:77:88:99:AA:BB"
    gateway_mac = "AA:BB:CC:DD:EE:FF"
    client_ip = "192.168.1.100"
    dns_server = "8.8.8.8"
    web_server = "93.184.216.34"  # example.com's IP

    # ─── 1. DNS Query: "What is the IP of example.com?" ───
    dns_query = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=dns_server, ttl=64, id=1001) /
        UDP(sport=55123, dport=53) /
        DNS(id=0xAAAA, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    dns_query.time = base_time + 0.000
    packets.append(dns_query)

    # ─── 2. DNS Response: "example.com is 93.184.216.34" ───
    dns_response = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=dns_server, dst=client_ip, ttl=56, id=2001) /
        UDP(sport=53, dport=55123) /
        DNS(id=0xAAAA, qr=1, aa=1, qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300))
    )
    dns_response.time = base_time + 0.025
    packets.append(dns_response)

    # ─── 3. TCP Three-Way Handshake ───
    # Step 1: Client → Server: SYN (I want to connect)
    syn = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64, id=1002) /
        TCP(sport=50000, dport=80, flags="S", seq=1000, window=65535,
            options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)])
    )
    syn.time = base_time + 0.030
    packets.append(syn)

    # Step 2: Server → Client: SYN-ACK (I accept, let's connect)
    syn_ack = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=web_server, dst=client_ip, ttl=56, id=2002) /
        TCP(sport=80, dport=50000, flags="SA", seq=5000, ack=1001,
            window=65535, options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)])
    )
    syn_ack.time = base_time + 0.055
    packets.append(syn_ack)

    # Step 3: Client → Server: ACK (Connection established!)
    ack = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64, id=1003) /
        TCP(sport=50000, dport=80, flags="A", seq=1001, ack=5001, window=65535)
    )
    ack.time = base_time + 0.056
    packets.append(ack)

    # ─── 4. HTTP GET Request ───
    http_request = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64, id=1004) /
        TCP(sport=50000, dport=80, flags="PA", seq=1001, ack=5001, window=65535) /
        Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetForensics/1.0\r\n\r\n")
    )
    http_request.time = base_time + 0.060
    packets.append(http_request)

    # ─── 5. Server ACKs the request ───
    server_ack = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=web_server, dst=client_ip, ttl=56, id=2003) /
        TCP(sport=80, dport=50000, flags="A", seq=5001, ack=1070, window=65535)
    )
    server_ack.time = base_time + 0.080
    packets.append(server_ack)

    # ─── 6. HTTP Response ───
    http_body = b"<html><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>"
    http_response_data = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"Content-Length: " + str(len(http_body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + http_body
    )
    http_response = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=web_server, dst=client_ip, ttl=56, id=2004) /
        TCP(sport=80, dport=50000, flags="PA", seq=5001, ack=1070, window=65535) /
        Raw(load=http_response_data)
    )
    http_response.time = base_time + 0.085
    packets.append(http_response)

    # ─── 7. Client ACKs the response ───
    client_ack = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64, id=1005) /
        TCP(sport=50000, dport=80, flags="A", seq=1070,
            ack=5001 + len(http_response_data), window=65535)
    )
    client_ack.time = base_time + 0.086
    packets.append(client_ack)

    # ─── 8. TCP Connection Close (FIN sequence) ───
    # Server initiates close
    server_fin = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=web_server, dst=client_ip, ttl=56, id=2005) /
        TCP(sport=80, dport=50000, flags="FA",
            seq=5001 + len(http_response_data), ack=1070, window=65535)
    )
    server_fin.time = base_time + 0.090
    packets.append(server_fin)

    # Client ACKs FIN
    client_fin_ack = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64, id=1006) /
        TCP(sport=50000, dport=80, flags="FA", seq=1070,
            ack=5002 + len(http_response_data), window=65535)
    )
    client_fin_ack.time = base_time + 0.091
    packets.append(client_fin_ack)

    # Server final ACK
    final_ack = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=web_server, dst=client_ip, ttl=56, id=2006) /
        TCP(sport=80, dport=50000, flags="A",
            seq=5002 + len(http_response_data), ack=1071, window=65535)
    )
    final_ack.time = base_time + 0.115
    packets.append(final_ack)

    # ─── 9. ICMP Ping (Echo Request + Reply) ───
    ping_request = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst="8.8.8.8", ttl=64, id=1007) /
        ICMP(type=8, code=0, id=0x1234, seq=1) /
        Raw(load=b"abcdefghijklmnop")
    )
    ping_request.time = base_time + 0.200
    packets.append(ping_request)

    ping_reply = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src="8.8.8.8", dst=client_ip, ttl=56, id=3001) /
        ICMP(type=0, code=0, id=0x1234, seq=1) /
        Raw(load=b"abcdefghijklmnop")
    )
    ping_reply.time = base_time + 0.230
    packets.append(ping_reply)

    # ─── 10. Additional UDP traffic (NTP-like) ───
    ntp_query = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst="129.6.15.28", ttl=64, id=1008) /
        UDP(sport=55555, dport=123) /
        Raw(load=b"\x1b" + b"\x00" * 47)
    )
    ntp_query.time = base_time + 0.300
    packets.append(ntp_query)

    # ─── 11. TCP RST example (connection refused) ───
    rst_syn = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst="10.0.0.5", ttl=64, id=1009) /
        TCP(sport=50001, dport=8080, flags="S", seq=2000, window=65535)
    )
    rst_syn.time = base_time + 0.400
    packets.append(rst_syn)

    rst_response = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src="10.0.0.5", dst=client_ip, ttl=64, id=4001) /
        TCP(sport=8080, dport=50001, flags="RA", seq=0, ack=2001, window=0)
    )
    rst_response.time = base_time + 0.420
    packets.append(rst_response)

    # ─── 12. Second DNS query (AAAA record for IPv6) ───
    dns_aaaa = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=dns_server, ttl=64, id=1010) /
        UDP(sport=55124, dport=53) /
        DNS(id=0xBBBB, rd=1, qd=DNSQR(qname="example.com", qtype="AAAA"))
    )
    dns_aaaa.time = base_time + 0.500
    packets.append(dns_aaaa)

    # ─── 13. Second TCP connection (to show multiple flows) ───
    syn2 = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst="142.250.80.46", ttl=64, id=1011) /
        TCP(sport=50002, dport=443, flags="S", seq=3000, window=65535)
    )
    syn2.time = base_time + 0.600
    packets.append(syn2)

    syn_ack2 = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src="142.250.80.46", dst=client_ip, ttl=56, id=5001) /
        TCP(sport=443, dport=50002, flags="SA", seq=8000, ack=3001, window=65535)
    )
    syn_ack2.time = base_time + 0.625
    packets.append(syn_ack2)

    ack2 = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst="142.250.80.46", ttl=64, id=1012) /
        TCP(sport=50002, dport=443, flags="A", seq=3001, ack=8001, window=65535)
    )
    ack2.time = base_time + 0.626
    packets.append(ack2)

    # ─── Save to PCAP ───
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wrpcap(output_path, packets)
    print(f"Generated {len(packets)} packets → {output_path}")
    print()
    print("Traffic summary:")
    print(f"  DNS queries/responses:  3 packets")
    print(f"  TCP handshakes:         3 flows")
    print(f"  HTTP request/response:  2 packets")
    print(f"  TCP close (FIN):        3 packets")
    print(f"  ICMP ping:              2 packets")
    print(f"  UDP (NTP-like):         1 packet")
    print(f"  TCP RST:                2 packets")
    print(f"  Total:                  {len(packets)} packets")

    return packets


def generate_impaired_capture(output_path: str = "sample_captures/sample_impaired.pcap"):
    """
    Generate an impaired network capture simulating packet loss, delay, and retransmission.

    Used for Feature F (Controlled Network Experiments & Comparative Analysis).
    """
    packets = []
    base_time = 1700000000.0

    client_mac = "00:11:22:33:44:55"
    gateway_mac = "AA:BB:CC:DD:EE:FF"
    client_ip = "192.168.1.100"
    dns_server = "8.8.8.8"
    web_server = "93.184.216.34"

    # 1. Delayed DNS query & response (+150ms delay)
    dns_q = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=dns_server, ttl=64) /
        UDP(sport=55123, dport=53) /
        DNS(id=0xAAAA, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    dns_q.time = base_time + 0.000
    packets.append(dns_q)

    dns_r = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=dns_server, dst=client_ip, ttl=56) /
        UDP(sport=53, dport=55123) /
        DNS(id=0xAAAA, qr=1, aa=1, qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300))
    )
    dns_r.time = base_time + 0.180  # 180ms delay (vs 25ms baseline)
    packets.append(dns_r)

    # 2. High-latency TCP Handshake (+220ms RTT)
    syn = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64) /
        TCP(sport=50000, dport=80, flags="S", seq=1000, window=65535)
    )
    syn.time = base_time + 0.200
    packets.append(syn)

    syn_ack = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=web_server, dst=client_ip, ttl=56) /
        TCP(sport=80, dport=50000, flags="SA", seq=5000, ack=1001, window=65535)
    )
    syn_ack.time = base_time + 0.420  # 220ms handshake RTT
    packets.append(syn_ack)

    ack = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64) /
        TCP(sport=50000, dport=80, flags="A", seq=1001, ack=5001, window=65535)
    )
    ack.time = base_time + 0.425
    packets.append(ack)

    # 3. HTTP GET Request
    http_req = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64) /
        TCP(sport=50000, dport=80, flags="PA", seq=1001, ack=5001, window=65535) /
        Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    http_req.time = base_time + 0.450
    packets.append(http_req)

    # 4. TCP Retransmissions (Packet Loss simulation: Server ACK was lost, so Client re-transmits!)
    retrans_1 = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64) /
        TCP(sport=50000, dport=80, flags="PA", seq=1001, ack=5001, window=65535) /
        Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    retrans_1.time = base_time + 0.850  # 400ms retransmit timeout
    packets.append(retrans_1)

    retrans_2 = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst=web_server, ttl=64) /
        TCP(sport=50000, dport=80, flags="PA", seq=1001, ack=5001, window=65535) /
        Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    retrans_2.time = base_time + 1.650  # Exponential backoff (800ms)
    packets.append(retrans_2)

    # 5. Server finally ACKs and responds
    http_resp = (
        Ether(src=gateway_mac, dst=client_mac) /
        IP(src=web_server, dst=client_ip, ttl=56) /
        TCP(sport=80, dport=50000, flags="PA", seq=5001, ack=1070, window=65535) /
        Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
    )
    http_resp.time = base_time + 1.700
    packets.append(http_resp)

    # 6. Dropped Connection Simulation (Client sends SYN, but packet is dropped; no SYN-ACK ever returns)
    dropped_syn = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst="10.0.0.99", ttl=64) /
        TCP(sport=50099, dport=80, flags="S", seq=3000, window=65535)
    )
    dropped_syn.time = base_time + 2.000
    packets.append(dropped_syn)

    dropped_syn_retrans = (
        Ether(src=client_mac, dst=gateway_mac) /
        IP(src=client_ip, dst="10.0.0.99", ttl=64) /
        TCP(sport=50099, dport=80, flags="S", seq=3000, window=65535)
    )
    dropped_syn_retrans.time = base_time + 3.000
    packets.append(dropped_syn_retrans)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wrpcap(output_path, packets)
    print(f"Generated {len(packets)} impaired packets → {output_path}")
    return packets


def generate_synthetic_suite(output_path: str = "sample_captures/synthetic_protocol_suite.pcap"):
    """
    Generate an explicitly labeled, reproducible synthetic protocol capture suite.

    Designed for demonstration and testing without requiring administrative privileges or live sniffing.
    Contains the 7 required protocol scenarios in clean sequence:
    1. DNS Query & Response (example.com A record)
    2. TCP Three-Way Handshake (SYN → SYN-ACK → ACK)
    3. TCP Data Exchange (HTTP Request & 200 OK Response)
    4. TCP Connection Termination (FIN-ACK Graceful 4-Way Close)
    5. UDP Communication (DNS & NTP Datagrams)
    6. ICMP Echo Request & Reply (Ping / Pong)
    7. Native IPv6 Traffic (IPv6 Handshake, HTTP Data, and ICMPv6 Ping)
    """
    packets = []
    base_time = 1700000000.0

    c_mac = "00:1A:2B:3C:4D:5E"
    s_mac = "66:77:88:99:AA:BB"
    gw_mac = "AA:BB:CC:DD:EE:FF"

    c_ip4 = "192.168.1.10"
    s_ip4 = "93.184.216.34"
    dns_ip4 = "8.8.8.8"

    c_ip6 = "2001:db8:acad::10"
    s_ip6 = "2001:db8:acad::80"

    # 1. DNS Query & Response
    p1 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst=dns_ip4) / UDP(sport=53000, dport=53) / DNS(id=0x1111, rd=1, qd=DNSQR(qname="synthetic.dccn.internal", qtype="A"))
    p1.time = base_time + 0.000
    packets.append(p1)

    p2 = Ether(src=gw_mac, dst=c_mac) / IP(src=dns_ip4, dst=c_ip4) / UDP(sport=53, dport=53000) / DNS(id=0x1111, qr=1, aa=1, qd=DNSQR(qname="synthetic.dccn.internal", qtype="A"), an=DNSRR(rrname="synthetic.dccn.internal", type="A", rdata=s_ip4, ttl=300))
    p2.time = base_time + 0.020
    packets.append(p2)

    # 2. TCP Three-Way Handshake
    p3 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst=s_ip4) / TCP(sport=45000, dport=80, flags="S", seq=1000, window=65535)
    p3.time = base_time + 0.040
    packets.append(p3)

    p4 = Ether(src=gw_mac, dst=c_mac) / IP(src=s_ip4, dst=c_ip4) / TCP(sport=80, dport=45000, flags="SA", seq=5000, ack=1001, window=65535)
    p4.time = base_time + 0.065
    packets.append(p4)

    p5 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst=s_ip4) / TCP(sport=45000, dport=80, flags="A", seq=1001, ack=5001, window=65535)
    p5.time = base_time + 0.066
    packets.append(p5)

    # 3. TCP Data Exchange
    http_req = b"GET /synthetic-benchmark HTTP/1.1\r\nHost: synthetic.dccn.internal\r\nUser-Agent: NetForensics-Synthetic/1.0\r\n\r\n"
    p6 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst=s_ip4) / TCP(sport=45000, dport=80, flags="PA", seq=1001, ack=5001, window=65535) / Raw(load=http_req)
    p6.time = base_time + 0.080
    packets.append(p6)

    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 28\r\n\r\nSynthetic DCCN Protocol Data"
    p7 = Ether(src=gw_mac, dst=c_mac) / IP(src=s_ip4, dst=c_ip4) / TCP(sport=80, dport=45000, flags="PA", seq=5001, ack=1001 + len(http_req), window=65535) / Raw(load=http_resp)
    p7.time = base_time + 0.105
    packets.append(p7)

    p8 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst=s_ip4) / TCP(sport=45000, dport=80, flags="A", seq=1001 + len(http_req), ack=5001 + len(http_resp), window=65535)
    p8.time = base_time + 0.106
    packets.append(p8)

    # 4. TCP Connection Termination (Graceful 4-Way FIN/ACK)
    p9 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst=s_ip4) / TCP(sport=45000, dport=80, flags="FA", seq=1001 + len(http_req), ack=5001 + len(http_resp), window=65535)
    p9.time = base_time + 0.120
    packets.append(p9)

    p10 = Ether(src=gw_mac, dst=c_mac) / IP(src=s_ip4, dst=c_ip4) / TCP(sport=80, dport=45000, flags="A", seq=5001 + len(http_resp), ack=1002 + len(http_req), window=65535)
    p10.time = base_time + 0.125
    packets.append(p10)

    p11 = Ether(src=gw_mac, dst=c_mac) / IP(src=s_ip4, dst=c_ip4) / TCP(sport=80, dport=45000, flags="FA", seq=5001 + len(http_resp), ack=1002 + len(http_req), window=65535)
    p11.time = base_time + 0.130
    packets.append(p11)

    p12 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst=s_ip4) / TCP(sport=45000, dport=80, flags="A", seq=1002 + len(http_req), ack=5002 + len(http_resp), window=65535)
    p12.time = base_time + 0.135
    packets.append(p12)

    # 5. UDP Communication (NTP-like datagram)
    p13 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst="129.6.15.28") / UDP(sport=56000, dport=123) / Raw(load=b"\x1b" + b"\x00" * 47)
    p13.time = base_time + 0.200
    packets.append(p13)

    # 6. ICMP Echo Request & Reply (Ping/Pong)
    p14 = Ether(src=c_mac, dst=gw_mac) / IP(src=c_ip4, dst="8.8.8.8", ttl=64) / ICMP(type=8, code=0, id=0x4321, seq=1) / Raw(load=b"synthetic-icmp-ping")
    p14.time = base_time + 0.250
    packets.append(p14)

    p15 = Ether(src=gw_mac, dst=c_mac) / IP(src="8.8.8.8", dst=c_ip4, ttl=56) / ICMP(type=0, code=0, id=0x4321, seq=1) / Raw(load=b"synthetic-icmp-ping")
    p15.time = base_time + 0.275
    packets.append(p15)

    # 7. Native IPv6 Traffic (IPv6 TCP Handshake, Data, and ICMPv6)
    p16 = Ether(src=c_mac, dst=gw_mac) / IPv6(src=c_ip6, dst=s_ip6, hlim=64) / TCP(sport=46000, dport=80, flags="S", seq=3000, window=65535)
    p16.time = base_time + 0.300
    packets.append(p16)

    p17 = Ether(src=gw_mac, dst=c_mac) / IPv6(src=s_ip6, dst=c_ip6, hlim=56) / TCP(sport=80, dport=46000, flags="SA", seq=7000, ack=3001, window=65535)
    p17.time = base_time + 0.320
    packets.append(p17)

    p18 = Ether(src=c_mac, dst=gw_mac) / IPv6(src=c_ip6, dst=s_ip6, hlim=64) / TCP(sport=46000, dport=80, flags="A", seq=3001, ack=7001, window=65535)
    p18.time = base_time + 0.321
    packets.append(p18)

    p19 = Ether(src=c_mac, dst=gw_mac) / IPv6(src=c_ip6, dst=s_ip6, hlim=64) / TCP(sport=46000, dport=80, flags="PA", seq=3001, ack=7001, window=65535) / Raw(load=b"GET /ipv6-suite HTTP/1.1\r\n\r\n")
    p19.time = base_time + 0.330
    packets.append(p19)

    try:
        from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply
        p20 = Ether(src=c_mac, dst=gw_mac) / IPv6(src=c_ip6, dst=s_ip6, hlim=64) / ICMPv6EchoRequest(id=0x9999, seq=1, data=b"ping6-suite")
        p20.time = base_time + 0.350
        packets.append(p20)

        p21 = Ether(src=gw_mac, dst=c_mac) / IPv6(src=s_ip6, dst=c_ip6, hlim=56) / ICMPv6EchoReply(id=0x9999, seq=1, data=b"ping6-suite")
        p21.time = base_time + 0.370
        packets.append(p21)
    except Exception as e:
        print(f"Skipping ICMPv6 in suite: {e}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wrpcap(output_path, packets)
    print(f"Generated {len(packets)} synthetic suite packets → {output_path}")
    return packets


if __name__ == "__main__":
    generate_sample_capture()
    generate_impaired_capture()
    generate_synthetic_suite()

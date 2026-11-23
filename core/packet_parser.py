"""
packet_parser.py — Convert a raw Scapy packet into a structured Python dict.

WHY THIS MODULE EXISTS
─────────────────────
Scapy packets are powerful but awkward to work with directly in a UI.
They are layer objects, not plain data. If you try to put them in a Pandas
DataFrame or display them in Streamlit, you run into type issues, missing
attributes, and unpredictable errors.

This module creates a clean interface: given any Scapy packet, it returns
a plain Python dictionary with consistent keys. The UI and analysis modules
never touch raw Scapy packets directly — they always work with these dicts.

DESIGN PRINCIPLES
─────────────────
1. Never crash on a malformed or unusual packet. Every field access is
   wrapped with a safe fallback. If a field is absent, we store None.

2. Never invent data. If we cannot read a field, we store None — not a guess.
   "Unknown" is always better than a wrong value.

3. Only parse layers that are actually present. We check haslayer() before
   accessing any field. A packet without TCP doesn't have TCP fields.

4. We distinguish "this packet has no IP layer" from "IP parsing failed".
   The first is normal (e.g. ARP); the second is an error we log.

DCCN CONNECTION
───────────────
This module directly implements the concept of "protocol encapsulation":
each packet is inspected layer by layer, from the outer Ethernet frame
down to the application payload. This mirrors the OSI/TCP-IP model exactly.

The parsed dict maps to these OSI layers:
  - ethernet_* fields → Layer 2 (Data Link)
  - ip_* / ipv6_* fields → Layer 3 (Network)
  - tcp_* / udp_* fields → Layer 4 (Transport)
  - dns_* / http_* fields → Layer 7 (Application)
"""

from __future__ import annotations

import logging
from typing import Any

# Scapy imports — we import only what we need to keep startup fast
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, DNS, ICMP, Raw,
    ARP, NTPHeader
)

from config.settings import WELL_KNOWN_PORTS, IP_PROTOCOLS, ETHER_TYPES
from utils.helpers import format_timestamp, tcp_flags_to_str, tcp_flags_to_short

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_packet(packet, packet_num: int = 0) -> dict[str, Any]:
    """
    Parse a Scapy packet into a flat dictionary of observed fields.

    This is the single function the rest of the application uses.
    Pass any Scapy packet, get back a dict with consistent keys.

    Args:
        packet: A Scapy packet object (from sniff(), rdpcap(), etc.)
        packet_num: Sequential packet number for display (1-based recommended)

    Returns:
        Dictionary with all extracted fields. Missing fields are None.
        The dict always has the same keys regardless of packet type.
    """
    result = _make_empty_record(packet_num)

    try:
        # Timestamp from the packet capture metadata
        result["timestamp"] = float(packet.time)
        result["timestamp_str"] = format_timestamp(float(packet.time))
        result["length"] = len(packet)

        # Parse each layer in order (outer → inner, like peeling an onion)
        _parse_ethernet(packet, result)
        _parse_network_layer(packet, result)   # IPv4 or IPv6
        _parse_transport_layer(packet, result) # TCP or UDP or ICMP
        _parse_application_layer(packet, result) # DNS, HTTP, etc.
        _parse_raw_payload(packet, result)

        # Determine a human-readable protocol label for display
        result["protocol"] = _identify_protocol(result)
        result["info"] = _build_info_string(result, packet)

    except Exception as e:
        # Log the error but return whatever we have — partial data is
        # better than no data or a crash.
        logger.warning(f"Error parsing packet #{packet_num}: {e}")
        result["parse_error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# Empty record — guarantees consistent keys regardless of packet type
# ---------------------------------------------------------------------------

def _make_empty_record(packet_num: int) -> dict[str, Any]:
    """
    Create a dict with all keys set to None.

    This ensures the DataFrame always has consistent columns even when
    packets are missing layers. Without this, Pandas would have NaN in
    some rows and missing columns in others.
    """
    return {
        # Identity
        "num": packet_num,
        "timestamp": None,
        "timestamp_str": None,
        "length": None,
        "protocol": None,
        "info": None,
        "parse_error": None,

        # Ethernet (Layer 2 — Data Link)
        "eth_src": None,       # Source MAC address
        "eth_dst": None,       # Destination MAC address
        "eth_type": None,      # EtherType value (integer)
        "eth_type_str": None,  # Human-readable EtherType name

        # IPv4 (Layer 3 — Network)
        "ip_version": None,
        "ip_src": None,
        "ip_dst": None,
        "ip_ttl": None,        # Time To Live — decremented at each router
        "ip_proto": None,      # Protocol number (6=TCP, 17=UDP, 1=ICMP)
        "ip_proto_str": None,
        "ip_id": None,         # IP identification field (for fragment reassembly)
        "ip_flags": None,      # DF, MF flags
        "ip_len": None,        # Total length including header
        "ip_tos": None,        # Type of Service (QoS marking)
        "ip_chksum": None,

        # IPv6 (Layer 3 — Network)
        "ipv6_src": None,
        "ipv6_dst": None,
        "ipv6_hlim": None,     # Hop Limit — IPv6 equivalent of TTL
        "ipv6_nh": None,       # Next Header (equivalent to IPv4 proto field)
        "ipv6_nh_str": None,
        "ipv6_fl": None,       # Flow Label
        "ipv6_tc": None,       # Traffic Class

        # Convenience — unified src/dst IP regardless of version
        "src_ip": None,
        "dst_ip": None,

        # TCP (Layer 4 — Transport)
        "tcp_sport": None,
        "tcp_dport": None,
        "tcp_seq": None,       # Sequence number — position in byte stream
        "tcp_ack": None,       # Acknowledgement number
        "tcp_flags": None,     # Short form: "SA", "S", "FA", etc.
        "tcp_flags_str": None, # Readable: "SYN, ACK"
        "tcp_window": None,    # Receiver's advertised window size
        "tcp_chksum": None,
        "tcp_urgptr": None,

        # UDP (Layer 4 — Transport)
        "udp_sport": None,
        "udp_dport": None,
        "udp_len": None,
        "udp_chksum": None,

        # Convenience — unified ports regardless of protocol
        "src_port": None,
        "dst_port": None,

        # ICMP (Layer 3/4 — Network/Transport)
        "icmp_type": None,
        "icmp_type_str": None,
        "icmp_code": None,
        "icmp_id": None,
        "icmp_seq": None,

        # DNS (Layer 7 — Application)
        "dns_id": None,
        "dns_qr": None,        # 0=query, 1=response
        "dns_opcode": None,
        "dns_qname": None,     # The domain name being queried
        "dns_qtype": None,     # Query type: A, AAAA, MX, etc.
        "dns_qtype_str": None,
        "dns_ancount": None,   # Number of answers
        "dns_answers": None,   # List of answer records
        "dns_rcode": None,     # Response code: 0=OK, 3=NXDOMAIN, etc.

        # Raw payload
        "has_payload": False,
        "payload_len": 0,
        "payload_preview": None,  # First 64 bytes as text (if printable)
    }


# ---------------------------------------------------------------------------
# Layer parsers — each handles one protocol layer
# ---------------------------------------------------------------------------

def _parse_ethernet(packet, result: dict) -> None:
    """
    Parse the Ethernet header (Layer 2 — Data Link).

    The Ethernet frame is the outermost wrapper when packets are captured
    at the network interface level. It contains MAC addresses (physical
    hardware addresses, not routable like IP).

    DCCN: Ethernet implements the Data Link layer of the OSI model.
    MAC addresses are unique identifiers burned into network interface cards.
    EtherType tells the receiver what protocol comes next (IPv4=0x0800, etc.)
    """
    if not packet.haslayer(Ether):
        return

    eth = packet[Ether]
    result["eth_src"] = _safe(eth, "src")
    result["eth_dst"] = _safe(eth, "dst")
    result["eth_type"] = _safe(eth, "type")
    eth_type_val = result["eth_type"]
    result["eth_type_str"] = ETHER_TYPES.get(eth_type_val, f"0x{eth_type_val:04X}"
                                               if eth_type_val is not None else "Unknown")


def _parse_network_layer(packet, result: dict) -> None:
    """
    Parse IPv4 or IPv6 header (Layer 3 — Network).

    DCCN — IPv4 key fields:
    - src/dst: Logical IP addresses (routable across the internet)
    - TTL: "Time To Live" — a counter decremented at each router.
      A packet with TTL=1 that reaches a router gets dropped and an
      ICMP "Time Exceeded" is sent back. This prevents routing loops.
    - proto: Tells IPv4 what comes next (6=TCP, 17=UDP, 1=ICMP).
    - id: Used for fragment reassembly when packets are split.

    DCCN — IPv6 key differences from IPv4:
    - 128-bit addresses instead of 32-bit
    - Hop Limit replaces TTL (same concept, different name)
    - Next Header replaces Protocol field
    - No fragmentation at routers — only at source
    - No header checksum (removed for speed; Transport layer handles errors)
    - Flow Label for QoS identification
    """
    if packet.haslayer(IP):
        ip = packet[IP]
        result["ip_version"] = 4
        result["ip_src"] = _safe(ip, "src")
        result["ip_dst"] = _safe(ip, "dst")
        result["ip_ttl"] = _safe(ip, "ttl")
        result["ip_proto"] = _safe(ip, "proto")
        result["ip_id"] = _safe(ip, "id")
        result["ip_len"] = _safe(ip, "len")
        result["ip_tos"] = _safe(ip, "tos")
        result["ip_chksum"] = _safe(ip, "chksum")

        # IP flags: DF (Don't Fragment), MF (More Fragments)
        try:
            flags_int = int(ip.flags)
            flag_parts = []
            if flags_int & 0x2:
                flag_parts.append("DF")
            if flags_int & 0x1:
                flag_parts.append("MF")
            result["ip_flags"] = ",".join(flag_parts) if flag_parts else "None"
        except Exception:
            result["ip_flags"] = None

        proto_num = result["ip_proto"]
        result["ip_proto_str"] = IP_PROTOCOLS.get(proto_num, str(proto_num)
                                                   if proto_num is not None else "Unknown")
        # Unified fields
        result["src_ip"] = result["ip_src"]
        result["dst_ip"] = result["ip_dst"]

    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        result["ip_version"] = 6
        result["ipv6_src"] = _safe(ip6, "src")
        result["ipv6_dst"] = _safe(ip6, "dst")
        result["ipv6_hlim"] = _safe(ip6, "hlim")
        result["ipv6_fl"] = _safe(ip6, "fl")
        result["ipv6_tc"] = _safe(ip6, "tc")
        result["ipv6_nh"] = _safe(ip6, "nh")
        nh_num = result["ipv6_nh"]
        result["ipv6_nh_str"] = IP_PROTOCOLS.get(nh_num, str(nh_num)
                                                  if nh_num is not None else "Unknown")
        # Unified fields
        result["src_ip"] = result["ipv6_src"]
        result["dst_ip"] = result["ipv6_dst"]

    elif packet.haslayer(ARP):
        # ARP doesn't have IP/IPv6 — it IS the protocol for resolving IPs to MACs
        from scapy.all import ARP as ScapyARP
        arp = packet[ScapyARP]
        result["src_ip"] = _safe(arp, "psrc")  # ARP sender IP
        result["dst_ip"] = _safe(arp, "pdst")  # ARP target IP


def _parse_transport_layer(packet, result: dict) -> None:
    """
    Parse TCP, UDP, or ICMP header (Layer 4 — Transport).

    DCCN — TCP key fields:
    - Ports: Identify the application/service (80=HTTP, 443=HTTPS, 53=DNS, etc.)
    - Sequence number: Position of this segment in the byte stream.
      Enables ordered, reliable delivery — the receiver reassembles in order.
    - Acknowledgement number: "I've received everything up to byte N".
    - Flags: Control the connection lifecycle (SYN, ACK, FIN, RST, etc.)
    - Window size: Flow control — how many bytes the receiver can accept.

    DCCN — UDP vs TCP:
    TCP: Connection-oriented (handshake required), reliable, ordered, slower.
    UDP: Connectionless, unreliable (no ACK), unordered, faster.
    UDP is used for DNS, video streaming, gaming — where speed > reliability.

    DCCN — ICMP:
    Not really Layer 4, but encapsulated in IP. Used for diagnostics:
    - Type 8: Echo Request (ping)
    - Type 0: Echo Reply (pong)
    - Type 3: Destination Unreachable (port closed, host down, etc.)
    - Type 11: Time Exceeded (TTL expired — used by traceroute)
    """
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["tcp_sport"] = _safe(tcp, "sport")
        result["tcp_dport"] = _safe(tcp, "dport")
        result["tcp_seq"] = _safe(tcp, "seq")
        result["tcp_ack"] = _safe(tcp, "ack")
        result["tcp_window"] = _safe(tcp, "window")
        result["tcp_chksum"] = _safe(tcp, "chksum")
        result["tcp_urgptr"] = _safe(tcp, "urgptr")

        flags = _safe(tcp, "flags")
        result["tcp_flags"] = tcp_flags_to_short(flags)
        result["tcp_flags_str"] = tcp_flags_to_str(flags)

        result["src_port"] = result["tcp_sport"]
        result["dst_port"] = result["tcp_dport"]

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        result["udp_sport"] = _safe(udp, "sport")
        result["udp_dport"] = _safe(udp, "dport")
        result["udp_len"] = _safe(udp, "len")
        result["udp_chksum"] = _safe(udp, "chksum")

        result["src_port"] = result["udp_sport"]
        result["dst_port"] = result["udp_dport"]

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        result["icmp_type"] = _safe(icmp, "type")
        result["icmp_code"] = _safe(icmp, "code")
        result["icmp_id"] = _safe(icmp, "id")
        result["icmp_seq"] = _safe(icmp, "seq")
        result["icmp_type_str"] = _icmp_type_name(result["icmp_type"])


def _parse_application_layer(packet, result: dict) -> None:
    """
    Parse application-layer protocols where visible (Layer 7).

    IMPORTANT CAVEAT: We can only parse unencrypted application data.
    - DNS over port 53: fully visible → we decode it
    - HTTP over port 80: partially visible → we show the first line
    - HTTPS (TLS): encrypted → we cannot read the payload content
    - Any other protocol: we show it as raw bytes if present

    DCCN — DNS:
    DNS (Domain Name System) is the "phone book" of the internet.
    It translates human-readable names (example.com) into IP addresses.
    A DNS query goes to a resolver (e.g. 8.8.8.8), which returns an answer.
    - qr=0: This is a query (client asking)
    - qr=1: This is a response (server answering)
    - qtype A: Asking for IPv4 address
    - qtype AAAA: Asking for IPv6 address
    - rcode=0: No error (NOERROR)
    - rcode=3: Name does not exist (NXDOMAIN)
    """
    if packet.haslayer(DNS):
        dns = packet[DNS]
        result["dns_id"] = _safe(dns, "id")
        result["dns_qr"] = _safe(dns, "qr")
        result["dns_opcode"] = _safe(dns, "opcode")
        result["dns_ancount"] = _safe(dns, "ancount")
        result["dns_rcode"] = _safe(dns, "rcode")

        # Parse the question section (what was asked)
        try:
            qd = dns.qd
            if qd is not None:
                qname_raw = _safe(qd, "qname")
                # qname comes as bytes like b'example.com.' — decode it
                if isinstance(qname_raw, bytes):
                    result["dns_qname"] = qname_raw.decode("utf-8", errors="replace").rstrip(".")
                else:
                    result["dns_qname"] = str(qname_raw).rstrip(".")

                qtype = _safe(qd, "qtype")
                result["dns_qtype"] = qtype
                result["dns_qtype_str"] = _dns_qtype_name(qtype)
        except Exception:
            pass

        # Parse answer records (if this is a response)
        if result["dns_qr"] == 1:
            try:
                answers = []
                an = dns.an
                while an and hasattr(an, "rrname"):
                    ans_dict = {
                        "name": _decode_dns_name(_safe(an, "rrname")),
                        "type": _dns_qtype_name(_safe(an, "type")),
                        "ttl": _safe(an, "ttl"),
                        "rdata": _safe(an, "rdata"),
                    }
                    answers.append(ans_dict)
                    payload = getattr(an, "payload", None)
                    if not payload or not hasattr(payload, "rrname"):
                        break
                    an = payload
                result["dns_answers"] = answers if answers else None
                if result["dns_ancount"] is None and answers:
                    result["dns_ancount"] = len(answers)
            except Exception:
                pass


def _parse_raw_payload(packet, result: dict) -> None:
    """
    Extract the raw payload (data) if present.

    For application protocols we don't decode, we show the first 64 bytes
    as a text preview (replacing non-printable chars with dots).

    This is similar to the "Follow TCP Stream" feature in Wireshark.
    """
    if not packet.haslayer(Raw):
        return

    raw = packet[Raw]
    payload = bytes(raw)
    result["has_payload"] = True
    result["payload_len"] = len(payload)

    # Show a preview — replace non-printable bytes with dots
    preview_bytes = payload[:64]
    preview = ""
    for b in preview_bytes:
        if 32 <= b <= 126:
            preview += chr(b)
        else:
            preview += "."
    result["payload_preview"] = preview + ("..." if len(payload) > 64 else "")


# ---------------------------------------------------------------------------
# Protocol identification
# ---------------------------------------------------------------------------

def _identify_protocol(result: dict) -> str:
    """
    Determine the best human-readable protocol label for a packet.

    Priority order (most specific → least specific):
    1. Application protocol (DNS, HTTP, HTTPS, SSH, etc.)
    2. Transport protocol (TCP, UDP)
    3. Network protocol (ICMP, ARP)
    4. Data Link protocol (Ethernet)
    5. Unknown

    We use port numbers to guess application protocols because Scapy
    doesn't always decode the application layer automatically.
    """
    # DNS
    if result["dns_qname"] is not None or result["dns_id"] is not None:
        return "DNS"

    # ICMP
    if result["icmp_type"] is not None:
        return "ICMP"

    # ARP
    if result["eth_type"] == 0x0806:
        return "ARP"

    # TCP — check for well-known ports
    if result["tcp_sport"] is not None:
        sport = result["tcp_sport"]
        dport = result["tcp_dport"]
        # Check destination port first (the service being accessed)
        for port in (dport, sport):
            if port in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[port]
        return "TCP"

    # UDP — check for well-known ports
    if result["udp_sport"] is not None:
        sport = result["udp_sport"]
        dport = result["udp_dport"]
        for port in (dport, sport):
            if port in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[port]
        return "UDP"

    # IPv6 with no transport
    if result["ip_version"] == 6:
        return "IPv6"

    # IPv4 with unusual protocol
    if result["ip_proto_str"]:
        return result["ip_proto_str"]

    # Fallback
    if result["eth_src"]:
        return "Ethernet"

    return "Unknown"


def _build_info_string(result: dict, packet) -> str:
    """
    Build a brief one-line summary of what this packet does.

    This fills the "Info" column in the packet table, similar to Wireshark.
    It's a brief human-readable description of the packet's purpose.
    """
    proto = result["protocol"]

    # DNS
    if proto == "DNS":
        qr = result["dns_qr"]
        qname = result["dns_qname"] or "?"
        qtype = result["dns_qtype_str"] or "?"
        if qr == 0:
            return f"Standard query {qtype} {qname}"
        else:
            rcode = result["dns_rcode"]
            rcode_str = {0: "No error", 2: "Server failure", 3: "NXDOMAIN",
                        4: "Not implemented", 5: "Refused"}.get(rcode, f"rcode={rcode}")
            answers = result.get("dns_answers") or []
            if answers:
                first_ans = answers[0]
                return f"Standard query response {rcode_str} {qtype} {qname} → {first_ans.get('rdata', '?')}"
            return f"Standard query response {rcode_str} {qtype} {qname}"

    # ICMP
    if proto == "ICMP":
        type_str = result["icmp_type_str"] or f"type={result['icmp_type']}"
        seq = result["icmp_seq"]
        return f"Echo ({type_str}) seq={seq}" if seq is not None else type_str

    # TCP
    if result["tcp_sport"] is not None:
        sport = result["tcp_sport"]
        dport = result["tcp_dport"]
        flags = result["tcp_flags_str"] or ""
        seq = result["tcp_seq"]
        ack = result["tcp_ack"]
        # Build a Wireshark-style info string
        if "SYN" in flags and "ACK" in flags:
            return f"{sport} → {dport} [SYN, ACK] Seq={seq} Ack={ack}"
        elif "SYN" in flags:
            return f"{sport} → {dport} [SYN] Seq={seq}"
        elif "FIN" in flags and "ACK" in flags:
            return f"{sport} → {dport} [FIN, ACK] Seq={seq} Ack={ack}"
        elif "FIN" in flags:
            return f"{sport} → {dport} [FIN] Seq={seq}"
        elif "RST" in flags and "ACK" in flags:
            return f"{sport} → {dport} [RST, ACK] Seq={seq}"
        elif "RST" in flags:
            return f"{sport} → {dport} [RST] Seq={seq}"
        elif "PSH" in flags and "ACK" in flags:
            payload_len = result["payload_len"]
            return f"{sport} → {dport} [PSH, ACK] Seq={seq} Len={payload_len}"
        elif "ACK" in flags:
            return f"{sport} → {dport} [ACK] Seq={seq} Ack={ack}"
        else:
            return f"{sport} → {dport} [{flags}] Seq={seq}"

    # UDP
    if result["udp_sport"] is not None:
        return f"{result['udp_sport']} → {result['udp_dport']} Len={result['udp_len']}"

    # ARP
    if proto == "ARP":
        return f"ARP: {result['src_ip']} → {result['dst_ip']}"

    return f"{proto} packet ({result['length']} bytes)"


# ---------------------------------------------------------------------------
# Helper: list of layer dicts for the visual packet journey
# ---------------------------------------------------------------------------

def get_packet_layers(packet) -> list[dict]:
    """
    Return an ordered list of layer descriptions for the packet journey view.

    Each dict has:
      - name: Protocol name (e.g. "IPv4", "TCP", "DNS")
      - fields: List of (field_name, value, description) tuples
      - osi_layer: OSI layer number and name

    This is used in the Packet Inspector UI to render the layer-by-layer
    visualization (Feature C). The layers are ordered from outermost (Ethernet)
    to innermost (Application), reflecting encapsulation.
    """
    layers = []

    if packet.haslayer(Ether):
        eth = packet[Ether]
        layers.append({
            "name": "Ethernet II",
            "pdu_name": "Frame",
            "osi_layer": "Layer 2 — Data Link",
            "layer_type": "datalink",
            "color": "#A78BFA",
            "icon": "🔌",
            "header_len": 14,
            "highlights": {
                "Destination MAC": str(_safe(eth, "dst", "—")),
                "Source MAC": str(_safe(eth, "src", "—")),
                "EtherType": f"0x{_safe(eth, 'type', 0):04X} ({ETHER_TYPES.get(_safe(eth, 'type'), 'Unknown')})"
            },
            "fields": [
                ("Destination MAC", _safe(eth, "dst"),
                 "Physical address of receiving network interface card (or broadcast FF:FF:FF:FF:FF:FF)"),
                ("Source MAC", _safe(eth, "src"),
                 "Hardware burning address (OUI + NIC) of transmitting host on local segment"),
                ("EtherType", f"0x{_safe(eth, 'type'):04X} ({ETHER_TYPES.get(_safe(eth,'type'), 'Unknown')})",
                 "Identifies encapsulated Layer 3 protocol (0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP)"),
            ]
        })

    if packet.haslayer(ARP):
        from scapy.all import ARP as ScapyARP
        arp = packet[ScapyARP]
        op_val = _safe(arp, "op")
        op_name = {1: "who-has (Request)", 2: "is-at (Reply)"}.get(op_val, str(op_val))
        layers.append({
            "name": "Address Resolution Protocol (ARP)",
            "pdu_name": "Resolution Message",
            "osi_layer": "Layer 2/3 — Resolution",
            "layer_type": "network",
            "color": "#A78BFA",
            "icon": "🔄",
            "header_len": 28,
            "highlights": {
                "Operation": f"{op_val} ({op_name})",
                "Sender Hardware (MAC)": str(_safe(arp, "hwsrc", "—")),
                "Sender Protocol (IP)": str(_safe(arp, "psrc", "—")),
                "Target Protocol (IP)": str(_safe(arp, "pdst", "—")),
            },
            "fields": [
                ("Operation", f"{op_val} ({op_name})",
                 "1=Request ('Who has IP X? Tell IP Y'), 2=Reply ('IP X is at MAC Z')"),
                ("Sender Hardware Address (MAC)", _safe(arp, "hwsrc"),
                 "Physical hardware address of device originating this ARP packet"),
                ("Sender Protocol Address (IP)", _safe(arp, "psrc"),
                 "IPv4 address of device originating this ARP packet"),
                ("Target Hardware Address (MAC)", _safe(arp, "hwdst"),
                 "Target MAC address (zeros in request probe, resolved in reply)"),
                ("Target Protocol Address (IP)", _safe(arp, "pdst"),
                 "Target IPv4 address being resolved to a hardware MAC"),
            ]
        })

    if packet.haslayer(IP):
        ip = packet[IP]
        flags_int = int(ip.flags) if ip.flags is not None else 0
        flag_parts = []
        if flags_int & 0x2: flag_parts.append("DF (Don't Fragment)")
        if flags_int & 0x1: flag_parts.append("MF (More Fragments)")
        flags_str = ", ".join(flag_parts) if flag_parts else "None"
        ip_hdr_len = int(ip.ihl * 4) if (hasattr(ip, "ihl") and ip.ihl) else 20

        layers.append({
            "name": "Internet Protocol Version 4 (IPv4)",
            "pdu_name": "Datagram / Packet",
            "osi_layer": "Layer 3 — Network",
            "layer_type": "network",
            "color": "#00E5FF",
            "icon": "🌐",
            "header_len": ip_hdr_len,
            "highlights": {
                "Source IP": str(_safe(ip, "src", "—")),
                "Destination IP": str(_safe(ip, "dst", "—")),
                "TTL (Time To Live)": str(_safe(ip, "ttl", "—")),
                "Protocol": f"{_safe(ip, 'proto')} ({IP_PROTOCOLS.get(_safe(ip, 'proto'), 'Unknown')})",
                "Total Length": f"{_safe(ip, 'len')} bytes"
            },
            "fields": [
                ("Version", "4", "IPv4 4-bit version identifier"),
                ("Header Length (IHL)", f"{ip_hdr_len} bytes", "Length of IPv4 header in 32-bit words (minimum 20 bytes without options)"),
                ("Source IP", _safe(ip, "src"),
                 "Logical layer 3 address of transmitting host (globally routable or private RFC 1918)"),
                ("Destination IP", _safe(ip, "dst"),
                 "Logical layer 3 address of final destination host used for routing table lookup"),
                ("TTL (Time To Live)", _safe(ip, "ttl"),
                 "Hop counter decremented by each router; dropped at 0 to avoid infinite loops"),
                ("Protocol", f"{_safe(ip,'proto')} ({IP_PROTOCOLS.get(_safe(ip,'proto'), 'Unknown')})",
                 "Identifies encapsulated Layer 4 protocol (6=TCP, 17=UDP, 1=ICMP)"),
                ("Header Checksum", f"0x{_safe(ip,'chksum'):04X}" if ip.chksum else "N/A",
                 "1's complement checksum verifying IP header integrity"),
                ("Total Length", f"{_safe(ip, 'len')} bytes",
                 "Total datagram size including IP header and encapsulated payload"),
                ("Identification", f"0x{_safe(ip,'id'):04X}" if ip.id else "N/A",
                 "Unique identifier used to reconstruct fragmented IP datagrams"),
                ("Flags", flags_str,
                 "DF (Don't Fragment) prevents MTU splitting; MF (More Fragments) indicates fragments follow"),
            ]
        })

    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        layers.append({
            "name": "Internet Protocol Version 6 (IPv6)",
            "pdu_name": "Datagram / Packet",
            "osi_layer": "Layer 3 — Network",
            "layer_type": "network",
            "color": "#00E5FF",
            "icon": "🌐",
            "header_len": 40,
            "highlights": {
                "Source IP": str(_safe(ip6, "src", "—")),
                "Destination IP": str(_safe(ip6, "dst", "—")),
                "Hop Limit": str(_safe(ip6, "hlim", "—")),
                "Next Header": f"{_safe(ip6, 'nh')} ({IP_PROTOCOLS.get(_safe(ip6, 'nh'), 'Unknown')})"
            },
            "fields": [
                ("Version", "6", "IPv6 128-bit addressing format without NAT fragmentation"),
                ("Source IP", _safe(ip6, "src"),
                 "128-bit IPv6 address of sender formatted as 8 groups of 4 hex digits"),
                ("Destination IP", _safe(ip6, "dst"),
                 "128-bit IPv6 address of destination host"),
                ("Hop Limit", _safe(ip6, "hlim"),
                 "IPv6 equivalent of TTL; decremented by 1 at each hop"),
                ("Next Header", f"{_safe(ip6,'nh')} ({IP_PROTOCOLS.get(_safe(ip6,'nh'), 'Unknown')})",
                 "Specifies next protocol header (TCP, UDP, extension headers)"),
                ("Flow Label", _safe(ip6, "fl"),
                 "20-bit label for QoS multi-packet flow classification"),
                ("Traffic Class", _safe(ip6, "tc"),
                 "DiffServ and Explicit Congestion Notification (ECN) marking"),
            ]
        })

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags_readable = tcp_flags_to_str(tcp.flags)
        tcp_hdr_len = int(tcp.dataofs * 4) if (hasattr(tcp, "dataofs") and tcp.dataofs) else 20
        layers.append({
            "name": "Transmission Control Protocol (TCP)",
            "pdu_name": "Segment",
            "osi_layer": "Layer 4 — Transport",
            "layer_type": "transport",
            "color": "#38BDF8",
            "icon": "🔗",
            "header_len": tcp_hdr_len,
            "highlights": {
                "Source Port": str(_safe(tcp, "sport", "—")),
                "Destination Port": str(_safe(tcp, "dport", "—")),
                "Sequence Number": str(_safe(tcp, "seq", "—")),
                "Acknowledgement Number": str(_safe(tcp, "ack", "—")),
                "Flags": flags_readable if flags_readable else "None",
                "Window Size": f"{_safe(tcp, 'window', 0)} bytes"
            },
            "fields": [
                ("Source Port", _safe(tcp, "sport"),
                 "Ephemeral client port or listening server port originating the transmission"),
                ("Destination Port", _safe(tcp, "dport"),
                 "Target service listening port identifying upper-layer application daemon"),
                ("Sequence Number", _safe(tcp, "seq"),
                 "Byte-stream offset tracking transmitted octets for ordered reassembly"),
                ("Acknowledgement Number", _safe(tcp, "ack"),
                 "Cumulative receipt confirmation: indicates next expected sequence number"),
                ("Flags", flags_readable if flags_readable else "None",
                 "Connection state control: SYN (handshake), ACK (confirm), FIN (teardown), RST (abort), PSH (push), URG (urgent)"),
                ("Window Size", f"{_safe(tcp, 'window')} bytes",
                 "Flow control credit: buffer space currently available at receiver"),
                ("Header Length (Data Offset)", f"{tcp_hdr_len} bytes",
                 "Length of TCP header including optional fields (timestamps, SACK, window scale)"),
                ("Checksum", f"0x{tcp.chksum:04X}" if tcp.chksum else "N/A",
                 "End-to-end pseudo-header checksum verifying payload and header integrity"),
            ]
        })

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        layers.append({
            "name": "User Datagram Protocol (UDP)",
            "pdu_name": "Datagram",
            "osi_layer": "Layer 4 — Transport",
            "layer_type": "transport",
            "color": "#10B981",
            "icon": "📨",
            "header_len": 8,
            "highlights": {
                "Source Port": str(_safe(udp, "sport", "—")),
                "Destination Port": str(_safe(udp, "dport", "—")),
                "UDP Length": f"{_safe(udp, 'len')} bytes",
                "Checksum": f"0x{udp.chksum:04X}" if udp.chksum else "N/A"
            },
            "fields": [
                ("Source Port", _safe(udp, "sport"),
                 "Originating process port for return datagram routing"),
                ("Destination Port", _safe(udp, "dport"),
                 "Destination socket identifying destination service (e.g. 53 for DNS, 123 for NTP)"),
                ("Length", f"{_safe(udp, 'len')} bytes",
                 "Total UDP datagram size (8-byte header + encapsulated payload)"),
                ("Checksum", f"0x{udp.chksum:04X}" if udp.chksum else "N/A",
                 "Optional transport integrity check covering pseudo-header, UDP header, and data"),
            ]
        })

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        type_val = _safe(icmp, "type")
        code_val = _safe(icmp, "code")
        layers.append({
            "name": "Internet Control Message Protocol (ICMP)",
            "pdu_name": "Control Message",
            "osi_layer": "Layer 3 — Network (control)",
            "layer_type": "network_control",
            "color": "#EF4444",
            "icon": "🏓",
            "header_len": 8,
            "highlights": {
                "Type": f"{type_val} ({_icmp_type_name(type_val)})",
                "Code": str(code_val),
                "Identifier": str(_safe(icmp, "id", "—")),
                "Sequence Number": str(_safe(icmp, "seq", "—"))
            },
            "fields": [
                ("Type", f"{type_val} ({_icmp_type_name(type_val)})",
                 "8=Echo Request (ping), 0=Echo Reply, 3=Destination Unreachable, 11=Time Exceeded"),
                ("Code", code_val,
                 "Sub-code qualifier (e.g. Type 3 Code 1 = Host Unreachable, Code 3 = Port Unreachable)"),
                ("Identifier", _safe(icmp, "id"),
                 "Correlation token linking request and response probes across concurrent sessions"),
                ("Sequence Number", _safe(icmp, "seq"),
                 "Monotonically increasing sequence tracking packet loss and round-trip latency"),
            ]
        })

    if packet.haslayer(DNS):
        dns = packet[DNS]
        qr = _safe(dns, "qr")
        qtype = None
        qname = None
        try:
            if dns.qd:
                qtype = _dns_qtype_name(_safe(dns.qd, "qtype"))
                qname_raw = _safe(dns.qd, "qname")
                qname = (qname_raw.decode("utf-8", errors="replace").rstrip(".")
                         if isinstance(qname_raw, bytes) else str(qname_raw).rstrip("."))
        except Exception:
            pass

        rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
                       3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
        rcode = _safe(dns, "rcode")

        dns_fields = [
            ("Transaction ID", f"0x{_safe(dns,'id'):04X}" if dns.id else "N/A",
             "16-bit identifier copied by recursive resolver to match queries to responses"),
            ("Message Type", "Response" if qr else "Query",
             "QR bit: 0=Query (client asking), 1=Response (server answering)"),
            ("Opcode", _safe(dns, "opcode"),
             "0=Standard query (QUERY), 1=Inverse query (IQUERY), 2=Server status (STATUS)"),
        ]
        if qname:
            dns_fields.append(("Query Name", qname,
                                "Fully qualified domain name (FQDN) being queried in DNS namespace"))
        if qtype:
            dns_fields.append(("Query Type", qtype,
                                "Resource record type (A=IPv4, AAAA=IPv6, MX=Mail, CNAME=Alias, PTR=Reverse)"))
        if qr:
            dns_fields.append(("Response Code", f"{rcode} ({rcode_names.get(rcode, 'Unknown')})",
                                "Server resolution status (NOERROR=success, NXDOMAIN=non-existent domain)"))
            dns_fields.append(("Answer Count", _safe(dns, "ancount"),
                                "Number of answer resource records returned"))

        layers.append({
            "name": "Domain Name System (DNS)",
            "pdu_name": "Application Message",
            "osi_layer": "Layer 7 — Application",
            "layer_type": "application",
            "color": "#F59E0B",
            "icon": "📖",
            "header_len": 12,
            "highlights": {
                "Query Name": qname if qname else "—",
                "Query Type": qtype if qtype else "—",
                "Message Type": "Response" if qr else "Query",
                "Transaction ID": f"0x{_safe(dns, 'id', 0):04X}" if dns.id else "N/A"
            },
            "fields": dns_fields
        })

    if packet.haslayer(Raw):
        raw = packet[Raw]
        raw_bytes = bytes(raw)
        preview = ""
        for b in raw_bytes[:32]:
            preview += chr(b) if 32 <= b <= 126 else "."

        layers.append({
            "name": "Data / Payload",
            "pdu_name": "Application Payload",
            "osi_layer": "Layer 7 — Application (raw)",
            "layer_type": "application",
            "color": "#94A3B8",
            "icon": "📄",
            "header_len": len(raw_bytes),
            "highlights": {
                "Payload Length": f"{len(raw_bytes)} bytes",
                "ASCII Preview": preview[:28] + ("..." if len(raw_bytes) > 28 else "")
            },
            "fields": [
                ("Length", f"{len(raw_bytes)} bytes",
                 "Total octets of encapsulated application layer data"),
                ("Preview (ASCII)", preview + ("..." if len(raw_bytes) > 32 else ""),
                 "Leading 32 payload octets mapped to printable ASCII (non-printable shown as '.')"),
            ]
        })

    return layers


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _safe(obj, attr: str, default=None):
    """Safely get an attribute from a Scapy layer object."""
    try:
        val = getattr(obj, attr)
        # Scapy's FlagValue objects need special handling
        if hasattr(val, "__int__"):
            return val
        return val
    except Exception:
        return default


def _icmp_type_name(type_num) -> str:
    """Convert ICMP type number to a human-readable name."""
    names = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect",
        8: "Echo Request",
        9: "Router Advertisement",
        10: "Router Solicitation",
        11: "Time Exceeded",
        12: "Parameter Problem",
        13: "Timestamp",
        14: "Timestamp Reply",
        30: "Traceroute",
    }
    return names.get(type_num, f"Type {type_num}") if type_num is not None else "Unknown"


def _dns_qtype_name(qtype) -> str:
    """Convert DNS query type number to name."""
    names = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }
    return names.get(qtype, f"Type {qtype}") if qtype is not None else "Unknown"


def _decode_dns_name(name) -> str:
    """Decode a DNS name (bytes or string) to a clean string."""
    if name is None:
        return ""
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="replace").rstrip(".")
    return str(name).rstrip(".")

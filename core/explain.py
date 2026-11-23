"""
explain.py — Plain-English technical explanations of observed packets.

Provides technical forensic breakdown of observed network packets:
- Explains the role and purpose of observed fields
- Clarifies protocol mechanics (e.g. 3-way handshake, DNS query resolution)
- Emphasizes the difference between observed evidence and inferences
- Notes encapsulation and OSI/TCP-IP layer mapping
"""

from typing import Dict, Any, List


def explain_packet(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive plain-English explanation of a parsed packet.

    Returns a dictionary containing:
      - 'summary': One-sentence overview of the packet's role.
      - 'key_takeaways': Bullet points explaining key mechanisms.
      - 'dccn_concepts': Mapping to specific DCCN curriculum topics.
      - 'evidence_notes': Clarifications of what is known vs assumed.
    """
    proto = parsed.get("protocol", "Unknown")
    tcp_flags = parsed.get("tcp_flags_str") or ""
    src_ip = parsed.get("src_ip", "Unknown")
    dst_ip = parsed.get("dst_ip", "Unknown")
    src_port = parsed.get("src_port")
    dst_port = parsed.get("dst_port")
    ttl = parsed.get("ip_ttl")
    length = parsed.get("length", 0)

    takeaways: List[str] = []
    dccn_concepts: List[str] = []
    evidence_notes: List[str] = []

    # 1. Base network layer explanation
    if parsed.get("ip_version") == 4:
        dccn_concepts.append("IPv4 Addressing & Header Framing")
        if ttl is not None:
            if ttl > 64:
                hops_note = f"Initial TTL was likely 128 (typical for Windows) or 255; remaining TTL is {ttl}."
            elif ttl > 32:
                hops_note = f"Initial TTL was likely 64 (typical for Linux/macOS); remaining TTL is {ttl} (traversed ~{64 - ttl} router hops)."
            else:
                hops_note = f"TTL is low ({ttl}), indicating packet traversed multiple intermediate routing hops."
            takeaways.append(f"IPv4 Time-To-Live (TTL = {ttl}): {hops_note}")
            evidence_notes.append("Hop counts are estimated based on common default operating system initial TTLs (64, 128, 255).")
    elif parsed.get("ip_version") == 6:
        dccn_concepts.append("IPv6 Addressing & Next-Header Architecture")
        takeaways.append("IPv6: Uses 128-bit hierarchical addressing, eliminating the need for NAT.")

    # 2. Transport & Application layer breakdown
    if "SYN" in tcp_flags and "ACK" not in tcp_flags:
        summary = f"TCP Connection Request (SYN) from {src_ip}:{src_port} to {dst_ip}:{dst_port}."
        takeaways.append("TCP Three-Way Handshake (Step 1): The client initiates a new connection by setting the SYN flag.")
        takeaways.append(f"Initial Sequence Number (ISN = {parsed.get('tcp_seq')}): Randomly chosen by client for synchronization and security.")
        takeaways.append(f"Advertised Window ({parsed.get('tcp_window')} bytes): Indicates the client's receive buffer capacity.")
        dccn_concepts.extend(["TCP Connection Establishment", "Three-Way Handshake", "Flow Control (Window Size)"])

    elif "SYN" in tcp_flags and "ACK" in tcp_flags:
        summary = f"TCP Connection Acknowledged & Response (SYN-ACK) from {src_ip}:{src_port}."
        takeaways.append("TCP Three-Way Handshake (Step 2): The server agrees to connect and acknowledges the client's SYN.")
        takeaways.append(f"Acknowledgement ({parsed.get('tcp_ack')}): Confirms receipt of client's ISN (Client ISN + 1).")
        takeaways.append(f"Server ISN ({parsed.get('tcp_seq')}): Server's own synchronized sequence number.")
        dccn_concepts.extend(["TCP Connection Establishment", "Reliable Transmission (ACK numbering)"])

    elif "FIN" in tcp_flags:
        summary = f"TCP Connection Teardown (FIN) from {src_ip}:{src_port}."
        takeaways.append("TCP Connection Teardown: Sender notifies the other party that it has finished sending data.")
        takeaways.append("Half-Close: The sender can no longer transmit data, but may still receive data until the opposite side sends FIN.")
        dccn_concepts.extend(["TCP Connection Termination", "Stateful Transport Management"])

    elif "RST" in tcp_flags:
        summary = f"TCP Connection Reset (RST) from {src_ip}:{src_port}."
        takeaways.append("TCP Reset: Abrupt connection termination. Usually indicates the destination port is closed or connection was rejected.")
        takeaways.append("Zero Window / Unsynchronized: Unlike FIN, RST does not wait for pending acknowledgements.")
        dccn_concepts.extend(["TCP Error Handling", "Port Scanning / Firewall Behavior"])

    elif "PSH" in tcp_flags:
        summary = f"TCP Data Transfer (PSH-ACK) carrying {parsed.get('payload_len', 0)} bytes of payload."
        takeaways.append("Push Flag (PSH): Instructs the receiver's TCP stack to push incoming data immediately to the application buffer.")
        takeaways.append(f"Sequence ({parsed.get('tcp_seq')}): Byte offset of the transmitted payload.")
        dccn_concepts.extend(["TCP Stream Segmentation", "Application Layer Encapsulation"])

    elif "ACK" in tcp_flags and proto == "TCP":
        summary = f"TCP Acknowledgment (ACK) for byte {parsed.get('tcp_ack')}."
        takeaways.append("Cumulative Acknowledgment: Confirms all contiguous bytes up to this ACK number have been successfully received.")
        dccn_concepts.extend(["TCP Sliding Window", "Cumulative ACKs", "Reliability"])

    elif proto == "DNS":
        qr = parsed.get("dns_qr")
        qname = parsed.get("dns_qname", "unknown")
        qtype = parsed.get("dns_qtype_str", "A")
        if qr == 0:
            summary = f"DNS Resolution Query for '{qname}' ({qtype} record)."
            takeaways.append("Client-Server Architecture: Resolving human-readable hostname to IP address.")
            takeaways.append("Transport: Sent over UDP port 53 for low latency (no handshake overhead).")
        else:
            answers = parsed.get("dns_answers") or []
            ans_str = ", ".join([f"{a.get('rdata')}" for a in answers]) if answers else "No records"
            summary = f"DNS Query Response for '{qname}' -> {ans_str}."
            takeaways.append(f"DNS Resolution complete: Return code {parsed.get('dns_rcode')} with {len(answers)} answer(s).")
            takeaways.append("Caching & TTL: Answer includes TTL specifying how long the client/resolver may cache this record.")
        dccn_concepts.extend(["Domain Name System (DNS)", "UDP Transport Mechanics", "Application Protocol"])

    elif proto == "ICMP":
        icmp_type = parsed.get("icmp_type_str", "Echo")
        summary = f"ICMP Control Message: {icmp_type}."
        takeaways.append("Network Control & Diagnostics: ICMP operates parallel to IP (Protocol 1) without port numbers.")
        takeaways.append("Common utility: Used by ping (Echo Request Type 8 / Echo Reply Type 0) and traceroute (Time Exceeded Type 11).")
        dccn_concepts.extend(["Network Diagnostics", "ICMP Error Reporting", "Round-Trip Time Measurement"])

    elif proto == "ARP":
        summary = f"Address Resolution Protocol (ARP) query/response."
        takeaways.append("Data Link Resolution: Maps IP addresses (Layer 3) to MAC addresses (Layer 2) on local broadcast domain.")
        dccn_concepts.extend(["ARP Protocol", "Layer 2 / Layer 3 Binding", "Ethernet Broadcast"])

    else:
        summary = f"{proto} packet ({length} bytes) between {src_ip} and {dst_ip}."
        takeaways.append(f"Protocol: {proto} encapsulated within {parsed.get('eth_type_str', 'Ethernet')}.")
        dccn_concepts.append("Protocol Encapsulation & Multiplexing")

    # Add general encapsulation takeaway
    takeaways.append(f"Total On-the-Wire Length: {length} bytes (including Layer 2 frame and overhead).")

    return {
        "summary": summary,
        "takeaways": takeaways,
        "dccn_concepts": list(dict.fromkeys(dccn_concepts)),
        "evidence_notes": evidence_notes or ["All statements reflect observable header fields in this captured packet."]
    }

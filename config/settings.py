"""
settings.py — Central configuration for the Network Forensics Analyzer.

This file holds all constants, defaults, and configuration values used
across the application. By keeping them here, we avoid magic numbers
scattered through the codebase and make it easy to tune behavior.
"""

# ---------------------------------------------------------------------------
# Capture settings
# ---------------------------------------------------------------------------

# Maximum number of packets to hold in memory during live capture.
# This prevents unbounded memory growth on busy networks.
# A queue of 10,000 packets ≈ 15–30 MB for typical traffic.
MAX_CAPTURE_PACKETS = 10_000

# Default packet count limit when starting a new capture session.
# The user can change this from the UI.
DEFAULT_CAPTURE_LIMIT = 5_000

# How often (in seconds) the Streamlit UI polls the capture thread
# for new packets. Lower = more responsive, but more CPU usage.
CAPTURE_POLL_INTERVAL = 1.0

# Default BPF (Berkeley Packet Filter) — empty means capture everything.
# Examples: "tcp", "udp port 53", "host 192.168.1.1"
DEFAULT_BPF_FILTER = ""

# Timeout in seconds for each sniff() call inside the capture thread.
# This allows the thread to check the "stop" flag periodically.
SNIFF_TIMEOUT = 2

# ---------------------------------------------------------------------------
# Protocol identification
# ---------------------------------------------------------------------------

# Mapping of well-known port numbers to protocol names.
# Used when Scapy doesn't identify the application-layer protocol.
WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Human-readable names for TCP flags.
# TCP flags are single characters in Scapy: S=SYN, A=ACK, F=FIN, etc.
TCP_FLAGS = {
    "S": "SYN",
    "A": "ACK",
    "F": "FIN",
    "R": "RST",
    "P": "PSH",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

# EtherType values to human-readable names
ETHER_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
}

# IP protocol numbers to names (used in IPv4 header "proto" field)
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-encap",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# ---------------------------------------------------------------------------
# UI theme and display (Clean Modern Light Aesthetic)
# ---------------------------------------------------------------------------

THEME_COLORS = {
    "background": "#F7F8FA",         # Warm off-white
    "card_bg": "#FFFFFF",            # Pure white
    "card_elevated": "#FFFFFF",      # Pure white elevated card
    "accent_primary": "#159A91",     # Muted teal
    "accent_secondary": "#8B83C8",   # Soft lavender
    "accent_highlight": "#DDF3ED",   # Subtle mint
    "accent_warning": "#D97706",     # Soft amber
    "accent_error": "#DC2626",       # Muted red
    "text_primary": "#263238",       # Dark charcoal
    "text_secondary": "#718096",     # Muted grey
    "border": "#E5E9EF",             # Light grey
    "border_hover": "#CBD5E1",       # Slightly darker border on hover
}

# Protocol-to-color mapping optimized for light background readability
PROTOCOL_COLORS = {
    "TCP": "#159A91",       # Muted teal
    "UDP": "#8B83C8",       # Soft lavender
    "DNS": "#D97706",       # Soft amber
    "HTTP": "#EA580C",      # Warm coral
    "HTTPS": "#0D9488",     # Deep teal
    "ICMP": "#DC2626",      # Muted red
    "ICMPv6": "#B91C1C",    # Crimson
    "ARP": "#7C3AED",       # Slate violet
    "SSH": "#4F46E5",       # Indigo
    "Other": "#718096",     # Muted grey
}

# Maximum rows to display in the packet table at once
MAX_TABLE_DISPLAY_ROWS = 1000

# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------

# Default directory for sample captures (relative to project root)
SAMPLE_CAPTURES_DIR = "sample_captures"

# ---------------------------------------------------------------------------
# Analysis settings
# ---------------------------------------------------------------------------

# When detecting potential TCP retransmissions, we look for packets with
# the same (src, dst, sport, dport, seq) seen more than once.
# This is a heuristic — not every duplicate seq is a retransmission.
RETRANSMISSION_LABEL = "Potential Retransmission (same seq number observed earlier)"

# Minimum packets in a TCP flow to consider it for analysis
MIN_FLOW_PACKETS = 2

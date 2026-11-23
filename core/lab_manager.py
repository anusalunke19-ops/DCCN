"""
lab_manager.py — Core engine and data model for Guided Lab Interactive Learning Mode.

Features:
- Local progress persistence (JSON file in config/user_progress.json)
- Tutorial curriculum (Tutorials 1 through 8 with step-by-step cards, diagrams, quizzes)
- Hands-on practical experiments (Experiments A through E with copyable PowerShell commands)
- Searchable networking glossary with practical NetForensics references
- Progress statistics calculation and reset capability
"""

from __future__ import annotations

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

PROGRESS_FILE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "user_progress.json"
)

# ---------------------------------------------------------------------------
# Progress Persistence
# ---------------------------------------------------------------------------

def _get_default_progress() -> Dict[str, Any]:
    return {
        "completed_tutorials": [],
        "completed_experiments": [],
        "quiz_scores": {},
        "created_at": datetime.now().isoformat(),
        "last_updated": datetime.now().isoformat()
    }


def load_progress() -> Dict[str, Any]:
    """Load user learning progress from disk. Returns default state if not found."""
    if not os.path.exists(PROGRESS_FILE_PATH):
        return _get_default_progress()

    try:
        with open(PROGRESS_FILE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Ensure required keys exist
            if "completed_tutorials" not in data:
                data["completed_tutorials"] = []
            if "completed_experiments" not in data:
                data["completed_experiments"] = []
            if "quiz_scores" not in data:
                data["quiz_scores"] = {}
            return data
    except Exception as e:
        logger.warning(f"Failed to load progress file: {e}")
        return _get_default_progress()


def save_progress(progress_data: Dict[str, Any]) -> bool:
    """Save user learning progress to disk."""
    try:
        os.makedirs(os.path.dirname(PROGRESS_FILE_PATH), exist_ok=True)
        progress_data["last_updated"] = datetime.now().isoformat()
        with open(PROGRESS_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(progress_data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save progress file: {e}")
        return False


def mark_tutorial_completed(tutorial_id: str, quiz_score: Optional[int] = None) -> Dict[str, Any]:
    """Mark a tutorial as completed and record quiz score."""
    progress = load_progress()
    if tutorial_id not in progress["completed_tutorials"]:
        progress["completed_tutorials"].append(tutorial_id)
    if quiz_score is not None:
        progress["quiz_scores"][tutorial_id] = quiz_score
    save_progress(progress)
    return progress


def mark_experiment_completed(experiment_id: str) -> Dict[str, Any]:
    """Mark a practical experiment as completed."""
    progress = load_progress()
    if experiment_id not in progress["completed_experiments"]:
        progress["completed_experiments"].append(experiment_id)
    save_progress(progress)
    return progress


def reset_all_progress() -> Dict[str, Any]:
    """Reset all user learning progress."""
    default_data = _get_default_progress()
    save_progress(default_data)
    return default_data


def calculate_progress_stats() -> Dict[str, Any]:
    """Calculate aggregate learning completion percentages."""
    progress = load_progress()
    total_tutorials = len(TUTORIALS)
    total_experiments = len(EXPERIMENTS)
    total_items = total_tutorials + total_experiments

    comp_tut = len(progress.get("completed_tutorials", []))
    comp_exp = len(progress.get("completed_experiments", []))
    comp_total = comp_tut + comp_exp

    pct = round((comp_total / total_items) * 100) if total_items > 0 else 0

    return {
        "total_tutorials": total_tutorials,
        "completed_tutorials_count": comp_tut,
        "completed_tutorials": progress.get("completed_tutorials", []),
        "total_experiments": total_experiments,
        "completed_experiments_count": comp_exp,
        "completed_experiments": progress.get("completed_experiments", []),
        "overall_percentage": pct,
        "quiz_scores": progress.get("quiz_scores", {})
    }


# ---------------------------------------------------------------------------
# Interactive Tutorials Curriculum (8 Comprehensive Modules)
# ---------------------------------------------------------------------------

TUTORIALS: List[Dict[str, Any]] = [
    {
        "id": "tut_1",
        "num": 1,
        "title": "Getting Started with Packet Forensics",
        "level": "Beginner",
        "time": "10 mins",
        "summary": "Understand what network packets are, how packet analysis works, and how to navigate the analyzer.",
        "icon": "🚀",
        "steps": [
            {
                "title": "1. What is Network Packet Analysis?",
                "content": """
When you stream a video, send a message, or load a webpage, your computer does not send that data as one continuous stream. 
Instead, data is chopped into discrete digital envelopes called **packets** (or frames at Layer 2).

Each packet contains:
- **Header**: Addressing and delivery metadata (like the envelope with recipient/sender addresses, postage, and instructions).
- **Payload**: The actual content being transmitted (e.g. text characters, image bytes, audio chunks).

**Packet Forensics** (or packet inspection) is the science of capturing and examining these envelopes to understand network behavior, diagnose bottlenecks, and identify security threats.
""",
                "diagram": """
[ APPLICATION DATA (HTTP / Webpage Content) ]
                    ↓
[ TCP HEADER | Application Data ]              (Transport Segment)
                    ↓
[ IP HEADER | TCP Header | Application Data ]  (Network Datagram)
                    ↓
[ ETHERNET HEADER | IP Header | TCP Header | Application Data | FCS ] (Data Link Frame)
"""
            },
            {
                "title": "2. Dashboard Architecture & Navigation",
                "content": """
The Network Forensics Analyzer is divided into 6 specialized investigation consoles accessible via the sidebar:

1. **🏠 Overview**: Executive telemetry, total observed volume, active endpoints, and protocol distribution.
2. **📡 Live Capture**: Sniff live network adapters or ingest offline PCAP/PCAPNG capture files.
3. **🔍 Packet Inspector**: Deep-dive frame dissector showing vertical encapsulation, header fields, and raw hex octets.
4. **🔗 Connection Explorer**: Stateful TCP flow reconstructor, 3-way handshake visualization, and latency tracking.
5. **📊 Network Analytics**: Deep statistics on active service ports, TCP flag distributions, and DNS queries.
6. **⚖️ Capture Comparison**: Side-by-side differential QoS analytics comparing baseline vs impaired traffic.
"""
            },
            {
                "title": "3. Live Capture vs Offline Analysis",
                "content": """
There are two primary modes of operation in packet analysis:

- **Offline PCAP Ingestion**: Load previously recorded packet files (`.pcap` or `.pcapng`). This mode works on any computer without requiring administrative permissions or special network drivers.
- **Live Packet Capture**: Sniff real-time traffic flowing through your computer's Wi-Fi or Ethernet card. On Windows, this requires the **Npcap driver** installed in WinPcap-compatible mode to allow non-administrative packet reading.

💡 *Tip: If you do not have administrator permissions or Npcap installed, use the **Sample Capture Mode** in the sidebar to explore realistic traffic instantly!*
"""
            }
        ],
        "quiz": [
            {
                "question": "What is the primary role of a packet header?",
                "options": [
                    "(Recommended) It holds addressing, sequencing, and control metadata needed to route and deliver the packet",
                    "It encrypts the payload so that intermediate routers cannot read it",
                    "It compresses the payload to save Internet bandwidth",
                    "It replaces the computer's MAC address with a temporary random ID"
                ],
                "answer_idx": 0,
                "explanation": "A packet header serves as the digital envelope. It contains crucial control metadata including source and destination IP addresses, port numbers, sequence numbers, and protocol types."
            },
            {
                "question": "What is the key difference between live capture and offline PCAP analysis?",
                "options": [
                    "Offline PCAP analysis only works for IPv4, whereas live capture works for IPv6",
                    "(Recommended) Live capture sniffs packets in real time from network adapters, while offline analysis reads pre-recorded capture files without needing special drivers",
                    "Live capture converts packets into text files, while offline capture stores raw electrical signals",
                    "Offline PCAP files cannot be opened in Wireshark"
                ],
                "answer_idx": 1,
                "explanation": "Offline PCAP analysis loads recorded traffic files without driver requirements, making it safe and accessible anywhere. Live capture requires driver hooks (like Npcap on Windows) to sniff adapter traffic in real time."
            },
            {
                "question": "Which section of NetForensics allows you to reconstruct TCP handshakes and examine connection timelines?",
                "options": [
                    "Overview",
                    "Network Analytics",
                    "(Recommended) Connection Explorer",
                    "Packet Table only"
                ],
                "answer_idx": 2,
                "explanation": "The Connection Explorer groups packets into 5-tuple bidirectional flows and reconstructs the TCP 3-way handshake, tracking states such as ESTABLISHED, INCOMPLETE, and REFUSED."
            }
        ]
    },
    {
        "id": "tut_2",
        "num": 2,
        "title": "Device & Network Interface Monitoring",
        "level": "Beginner",
        "time": "12 mins",
        "summary": "Master network adapters, MAC addresses, IP addresses, default gateways, and DNS resolvers.",
        "icon": "💻",
        "steps": [
            {
                "title": "1. What is a Network Interface Card (NIC)?",
                "content": """
Every computer connects to networks via one or more **Network Interfaces** (NICs). These can be:
- **Physical**: Wi-Fi adapter (IEEE 802.11) or Gigabit Ethernet port (IEEE 802.3).
- **Virtual**: VPN tunnels, Loopback adapters (`127.0.0.1`), or container interfaces (Docker/WSL).

In NetForensics' **Live Capture** tab, the interface selector lists all active adapters detected by your operating system.
"""
            },
            {
                "title": "2. MAC Address vs IP Address",
                "content": """
To understand network communication, you must understand the two distinct addresses assigned to your device:

| Property | MAC Address (Layer 2 - Data Link) | IP Address (Layer 3 - Network) |
|---|---|---|
| **Scope** | Local Physical Segment (Same Wi-Fi/Switch) | Global Internet Routing |
| **Format** | 48 bits (6 hex pairs: `00:1A:2B:3C:4D:5E`) | 32 bits (IPv4: `192.168.1.50`) or 128 bits (IPv6) |
| **Permanence** | Burned into hardware by manufacturer | Assigned dynamically by DHCP router |
| **Analogy** | A person's Government ID / Social Security # | A person's current Mailing Postal Address |
"""
            },
            {
                "title": "3. Default Gateway & DNS Servers",
                "content": """
When your computer wants to communicate with another machine:
1. **Local Machine (Same Subnet)**: Communicates directly using the destination's MAC address (resolved via ARP).
2. **Remote Machine (Internet / Different Subnet)**: Forwards the packet to the **Default Gateway** (your local home or office router, e.g., `192.168.1.1`).
3. **DNS Server**: When you type a hostname like `google.com`, your computer queries a DNS resolver (e.g. `8.8.8.8` or `1.1.1.1`) over UDP port 53 to convert the human name into a routable IP address.
"""
            }
        ],
        "quiz": [
            {
                "question": "Why does a computer need both a MAC address and an IP address?",
                "options": [
                    "MAC addresses are only used for Wi-Fi, while IP addresses are only used for Ethernet cables",
                    "(Recommended) MAC addresses identify the physical hardware on the local local link, while IP addresses route data across networks and the global Internet",
                    "IP addresses are permanent hardware IDs, while MAC addresses change every day",
                    "MAC addresses encrypt packet data, while IP addresses decrypt it"
                ],
                "answer_idx": 1,
                "explanation": "MAC addresses (Layer 2) route frames between directly connected devices on a local switch or Wi-Fi network. IP addresses (Layer 3) allow packets to be routed across multiple intermediate routers worldwide."
            },
            {
                "question": "What is the primary role of a Default Gateway?",
                "options": [
                    "It converts domain names like google.com into IP addresses",
                    "It blocks all incoming TCP SYN packets like a firewall",
                    "(Recommended) It acts as the exit router forwarding packets destined for outside the local network",
                    "It assigns MAC addresses to newly plugged-in network cables"
                ],
                "answer_idx": 2,
                "explanation": "The Default Gateway is your local router's IP address. Packets destined for external IP addresses outside your local subnet are forwarded to the gateway."
            },
            {
                "question": "Which protocol does your computer use to translate a domain name into an IP address?",
                "options": [
                    "ARP",
                    "ICMP",
                    "(Recommended) DNS",
                    "DHCP"
                ],
                "answer_idx": 2,
                "explanation": "DNS (Domain Name System) translates human-friendly names (e.g. wikipedia.org) into machine-readable IP addresses."
            }
        ]
    },
    {
        "id": "tut_3",
        "num": 3,
        "title": "Live Packet Capture & Ingestion",
        "level": "Intermediate",
        "time": "15 mins",
        "summary": "Master interface binding, BPF filtering, capture buffers, and Windows Npcap administration.",
        "icon": "📡",
        "steps": [
            {
                "title": "1. Selecting an Adapter & BPF Filters",
                "content": """
In the **Live Capture** console:
1. Select your active network adapter from the dropdown list.
2. Enter a **BPF (Berkeley Packet Filter)** expression if you wish to capture only specific traffic:
   - `tcp`: Sniff only TCP segments.
   - `udp port 53`: Sniff only DNS query and response traffic.
   - `host 192.168.1.1`: Sniff only traffic to/from your router.
   - *Leave empty to capture all visible frames.*
3. Set your **Buffer Limit** (default: 5,000 packets) to safeguard system memory.
"""
            },
            {
                "title": "2. Starting Capture & Generating Traffic",
                "content": """
Click **▶ START SNIFFING**. While the capture status badge pulses green:
- Open a web browser and visit an unencrypted or HTTPS website.
- Open PowerShell or Terminal and run a test command like:
  ```powershell
  ping 8.8.8.8 -n 4
  ```
- Click **⏹ STOP SNIFFING** when finished to freeze the buffer.
"""
            },
            {
                "title": "3. Understanding the Frame Dissection Table",
                "content": """
The capture table organizes frames chronologically:
- **No.**: Sequential frame index.
- **Timestamp**: Time of arrival (with microsecond precision).
- **Source & Destination**: Sender and receiver IP/MAC addresses.
- **SPort & DPort**: Transport port numbers identifying active services.
- **Proto**: Highest recognized protocol layer (e.g. DNS, HTTP, HTTPS, TCP, UDP, ICMP).
- **Bytes**: Physical length of the frame on the wire.
- **Flags**: TCP control flags (SYN, ACK, FIN, RST, PSH).
- **Info**: Human-readable forensic summary of the frame's intent.
"""
            }
        ],
        "quiz": [
            {
                "question": "What is the purpose of setting a BPF (Berkeley Packet Filter) before capturing?",
                "options": [
                    "It speeds up your Internet connection speed",
                    "(Recommended) It instructs the packet capture driver to discard unwanted traffic before passing it to memory",
                    "It changes your public IP address to protect your identity",
                    "It repairs corrupted packets on the wire"
                ],
                "answer_idx": 1,
                "explanation": "BPF filters run directly at kernel/driver level, allowing you to focus on specific protocols (e.g. `udp port 53`) and preventing buffer overflow on busy gigabit networks."
            },
            {
                "question": "What driver is required on Windows to enable live promiscuous packet sniffing?",
                "options": [
                    "DirectX 12",
                    "Hyper-V Driver",
                    "(Recommended) Npcap (in WinPcap API-compatible mode)",
                    "VirtualBox Network Bridge"
                ],
                "answer_idx": 2,
                "explanation": "Npcap is the standard packet capture architecture for Windows, allowing software to capture raw network traffic bypassing normal OS socket restrictions."
            },
            {
                "question": "What happens when the packet capture reaches the configured Buffer Limit?",
                "options": [
                    "The application crashes with an Out-Of-Memory error",
                    "(Recommended) The capture worker automatically sets the stop event and ceases capturing to protect system memory",
                    "All previously captured packets are automatically deleted",
                    "The network adapter is disabled"
                ],
                "answer_idx": 1,
                "explanation": "NetForensics enforces bounded FIFO buffers (`queue.Queue(maxsize=10,000)`) and auto-stops upon reaching your configured packet limit to prevent unbounded memory growth."
            }
        ]
    },
    {
        "id": "tut_4",
        "num": 4,
        "title": "Deep Packet Inspection & Header Dissection",
        "level": "Intermediate",
        "time": "15 mins",
        "summary": "Inspect Ethernet, IPv4/IPv6, TCP/UDP headers, DNS queries, and raw hexadecimal dumps.",
        "icon": "🔍",
        "steps": [
            {
                "title": "1. Selecting a Frame to Inspect",
                "content": """
To dissect a packet in detail:
1. In the **Live Capture** table, select a frame number and click **🔬 Open in Packet Inspector**.
2. Or navigate directly to **🔍 Packet Inspector** and use the **Jump to Frame** dropdown or **PREV / NEXT** buttons.
3. The top telemetry strip immediately displays the frame index, wire length, timestamp delta, and socket pair.
"""
            },
            {
                "title": "2. Inspecting Header Fields Layer-by-Layer",
                "content": """
Click on any layer expander in the **🧬 PROTOCOL STACK** tab to view actual captured fields:
- **Ethernet II**: Destination MAC, Source MAC, EtherType (`0x0800` for IPv4, `0x86DD` for IPv6).
- **IPv4**: Version (4), Header Length (20 bytes), Total Length, TTL, Protocol (6=TCP, 17=UDP, 1=ICMP), Source/Destination IPs.
- **TCP**: Source Port (Client), Destination Port (Server), Sequence Number, Acknowledgment Number, TCP Flags, Advertised Window Size.
- **DNS**: Transaction ID, Query Name (e.g. `google.com`), Record Type (A/AAAA), Response Code.
"""
            },
            {
                "title": "3. Reading Hexadecimal & ASCII Dumps",
                "content": """
Switch to the **💾 HEXADECIMAL & ASCII DUMP** tab to view the true raw wire octets:
- **Left Column**: Byte offset in hexadecimal (e.g., `0000`, `0010`, `0020` = offsets 0, 16, 32 bytes).
- **Center Column**: 16 raw hexadecimal octets (e.g., `45 00 00 3c ...`).
- **Right Column**: Printable ASCII representation. Non-printable control characters are safely replaced with dots (`.`).
"""
            }
        ],
        "quiz": [
            {
                "question": "What EtherType hexadecimal value indicates an IPv4 payload inside an Ethernet frame?",
                "options": [
                    "0x86DD",
                    "(Recommended) 0x0800",
                    "0x0806",
                    "0xFFFF"
                ],
                "answer_idx": 1,
                "explanation": "0x0800 identifies IPv4. In contrast, 0x0806 identifies ARP, and 0x86DD identifies IPv6."
            },
            {
                "question": "In the hex dump view, what does a dot ('.') in the right ASCII column represent?",
                "options": [
                    "A space character (ASCII 32)",
                    "A corrupted bit in the packet",
                    "(Recommended) A non-printable byte (value < 32 or > 126, such as binary numbers or control bytes)",
                    "A DNS query separator"
                ],
                "answer_idx": 2,
                "explanation": "Binary network headers contain numeric values (like IP addresses and checksums) that do not map to printable letters or numbers. Hex viewers display dots for non-printable characters."
            },
            {
                "question": "What does a Time-To-Live (TTL) field of 64 or 128 in an IPv4 header represent?",
                "options": [
                    "The number of milliseconds the packet is allowed to stay in memory",
                    "(Recommended) The maximum number of router hops the packet can traverse before being discarded to prevent infinite routing loops",
                    "The transmission speed of the network interface",
                    "The number of duplicate packets sent"
                ],
                "answer_idx": 1,
                "explanation": "Every intermediate router decrements the TTL field by 1. If TTL hits 0, the router discards the packet and returns an ICMP Time Exceeded message, preventing routing loops."
            }
        ]
    },
    {
        "id": "tut_5",
        "num": 5,
        "title": "Visual Packet Journey & Protocol Encapsulation",
        "level": "Intermediate",
        "time": "12 mins",
        "summary": "Understand nested header wrapping, PDU nomenclature, and conceptual OSI vs real TCP/IP layers.",
        "icon": "📦",
        "steps": [
            {
                "title": "1. What is Protocol Encapsulation?",
                "content": """
Protocol encapsulation is the modular packaging mechanism of computer networks.
Think of sending a letter inside an envelope, which is placed inside a courier pouch, which is loaded into a cargo shipping container.

In computer networks:
1. **User Data** is generated by the application.
2. **Layer 4 (Transport)** adds a TCP/UDP header $\\rightarrow$ creates a **Segment** or **Datagram**.
3. **Layer 3 (Network)** adds an IP header $\\rightarrow$ creates a **Packet / Datagram**.
4. **Layer 2 (Data Link)** adds an Ethernet header & FCS trailer $\\rightarrow$ creates a **Frame**.
"""
            },
            {
                "title": "2. PDU Terminology Across Layers",
                "content": """
Each layer assigns a specific name to its Protocol Data Unit (PDU):

- **Layer 7 (Application)**: *Message / Request / Response* (e.g., HTTP GET, DNS Query).
- **Layer 4 (Transport)**: *Segment* (TCP) or *Datagram* (UDP).
- **Layer 3 (Network)**: *Packet* or *Datagram* (IPv4 / IPv6).
- **Layer 2 (Data Link)**: *Frame* (Ethernet II, Wi-Fi 802.11).
- **Layer 1 (Physical)**: *Bits / Electrical Signals / Optical Photons*.
"""
            },
            {
                "title": "3. Conceptual OSI 7-Layer Model vs Captured TCP/IP Reality",
                "content": """
In textbooks, you learn the **ISO/IEC 7498-1 OSI 7-Layer Reference Model**.
However, actual network traffic across the Internet adheres to the **IETF TCP/IP Architecture (RFC 1122)**:

| OSI 7-Layer Conceptual Model | Real-World Captured TCP/IP Stack | Actual Captured Header |
|---|---|---|
| 7. Application | Application Layer | DNS Query / HTTP / TLS Record |
| 6. Presentation | *(Integrated into Application)* | *(No separate on-the-wire header)* |
| 5. Session | *(Integrated into Application)* | *(No separate on-the-wire header)* |
| 4. Transport | Transport Layer | TCP (20B) or UDP (8B) Header |
| 3. Network | Internet Layer | IPv4 (20B) or IPv6 (40B) Header |
| 2. Data Link | Network Access / Link Layer | Ethernet II Header (14B) + FCS (4B) |
| 1. Physical | Physical Media | Copper RJ45 / Fiber / Radio Waves |
"""
            }
        ],
        "quiz": [
            {
                "question": "What is the correct PDU term for data packaged at the Transport Layer with a TCP header?",
                "options": [
                    "Frame",
                    "(Recommended) Segment",
                    "Packet",
                    "Message"
                ],
                "answer_idx": 1,
                "explanation": "At Layer 4, TCP packages data into 'Segments', while UDP packages data into 'Datagrams'. At Layer 3 it is a 'Packet', and at Layer 2 it is a 'Frame'."
            },
            {
                "question": "Why don't captured packets show separate OSI Presentation and Session layer headers?",
                "options": [
                    "Because Scapy cannot decode those layers",
                    "(Recommended) Because the real Internet uses the TCP/IP model, where encryption, formatting, and session logic reside directly inside the Application layer",
                    "Because Presentation and Session headers are deleted by switches",
                    "Because those layers only exist on satellite networks"
                ],
                "answer_idx": 1,
                "explanation": "The OSI model was a theoretical reference standard. The TCP/IP architecture that powers the real world merged Presentation and Session functionality directly into user-space applications (e.g. TLS inside application streams)."
            },
            {
                "question": "What is the standard minimum header length of an IPv4 packet without optional fields?",
                "options": [
                    "8 bytes",
                    "14 bytes",
                    "(Recommended) 20 bytes",
                    "64 bytes"
                ],
                "answer_idx": 2,
                "explanation": "A standard IPv4 header is 20 bytes long (Header Length = 5 32-bit words). Standard TCP headers are also 20 bytes, while standard UDP headers are 8 bytes."
            }
        ]
    },
    {
        "id": "tut_6",
        "num": 6,
        "title": "TCP Connection Reconstruction & State Machine",
        "level": "Advanced",
        "time": "18 mins",
        "summary": "Master the TCP 3-way handshake, sequence numbers, data transfers, teardowns, and reset anomalies.",
        "icon": "🔗",
        "steps": [
            {
                "title": "1. Why Does TCP Need a 3-Way Handshake?",
                "content": """
Unlike UDP, TCP is a **connection-oriented, reliable, and full-duplex** protocol.
Before a single byte of user data can be sent, both client and server must agree to communicate and synchronize their **Initial Sequence Numbers (ISNs)**:

1. **Step 1: Client SYN ($S$)**: Client sends a SYN packet with random $ISN_c$ (e.g. `seq=1000`).
2. **Step 2: Server SYN-ACK ($SA$)**: Server accepts connection, acknowledges client's ISN (`ack=1001`), and generates its own random $ISN_s$ (e.g. `seq=5000`).
3. **Step 3: Client ACK ($A$)**: Client acknowledges server's ISN (`ack=5001`). The connection is now **ESTABLISHED**!
"""
            },
            {
                "title": "2. Initial Round Trip Time (iRTT)",
                "content": """
The elapsed time between the **Client SYN** and the receiving of the **Server SYN-ACK** represents the network's **Initial Round Trip Time ($iRTT$)**.
In NetForensics' **Connection Explorer**, the engine automatically calculates this latency in milliseconds ($ms$). 

- Low $iRTT$ (< 20ms): Local datacenter or nearby fiber.
- Moderate $iRTT$ (40–100ms): Transcontinental Internet connection.
- High $iRTT$ (> 200ms): Congested or intercontinental satellite connection.
"""
            },
            {
                "title": "3. Termination: Graceful FIN vs Abrupt RST",
                "content": """
- **Graceful Teardown (FIN)**: When one side finishes sending data, it transmits a `FIN` packet. The other side responds with `ACK`, followed by its own `FIN` and `ACK`. This ensures no in-flight data is lost.
- **Connection Reset (RST)**: If a client attempts to connect to a port that has no listening service, or if a firewall blocks the connection, the destination immediately returns an `RST` (Reset) packet, terminating the socket without a graceful teardown.
"""
            }
        ],
        "quiz": [
            {
                "question": "If a client sends SYN with seq=2000, what acknowledgment number must the server return in the SYN-ACK?",
                "options": [
                    "ack=2000",
                    "(Recommended) ack=2001",
                    "ack=0",
                    "ack=2002"
                ],
                "answer_idx": 1,
                "explanation": "The SYN flag consumes one sequence number. The server confirms receipt of the SYN by acknowledging Client ISN + 1 (2000 + 1 = 2001)."
            },
            {
                "question": "What does a TCP RST (Reset) packet signify?",
                "options": [
                    "A request to double the transmission speed",
                    "(Recommended) An abrupt rejection or immediate termination of the connection, typically because the target port is closed",
                    "Confirmation that all data was delivered successfully",
                    "A request to switch from IPv4 to IPv6"
                ],
                "answer_idx": 1,
                "explanation": "RST is sent when an incoming segment does not correspond to an open socket, or when a firewall/host forces an immediate teardown without waiting for pending acknowledgments."
            },
            {
                "question": "Why is an unresponded SYN packet classified as 'Incomplete / Attempt Only' in the Connection Explorer?",
                "options": [
                    "Because the packet was corrupted during transmission",
                    "(Recommended) Because the server never replied with a SYN-ACK, indicating a silent firewall drop, host offline, or SYN port probe",
                    "Because TCP connections can only be established over Wi-Fi",
                    "Because sequence numbers were not enabled"
                ],
                "answer_idx": 1,
                "explanation": "If only the initial SYN is observed without a corresponding SYN-ACK or RST, the connection attempt was never completed, commonly seen during port scans or when a firewall silently drops traffic."
            }
        ]
    },
    {
        "id": "tut_7",
        "num": 7,
        "title": "Network Analytics & Traffic Telemetry",
        "level": "Intermediate",
        "time": "14 mins",
        "summary": "Analyze protocol distribution, traffic bursts, port activity, DNS domains, and TCP retransmissions.",
        "icon": "📊",
        "steps": [
            {
                "title": "1. Protocol Distribution & Traffic Volume",
                "content": """
In the **📊 Network Analytics** dashboard:
- **Protocol Donut Chart**: Visualizes the proportional composition of traffic (TCP, UDP, DNS, ICMP, ARP).
- **Traffic Timeline**: Bins packet counts and byte volume into uniform time slices to reveal burst patterns, DDoS surges, or periods of inactivity.
"""
            },
            {
                "title": "2. Top Endpoints & Active Service Ports",
                "content": """
The analytics engine ranks endpoints and ports:
- **Top Talkers (Source IPs)**: Hosts sending the largest number of packets.
- **Top Listeners (Destination IPs)**: Servers receiving incoming traffic.
- **Service Ports**: Maps numeric port values to standard IANA services (e.g., port 443 $\\rightarrow$ HTTPS, port 80 $\\rightarrow$ HTTP, port 53 $\\rightarrow$ DNS, port 22 $\\rightarrow$ SSH).
"""
            },
            {
                "title": "3. Identifying Anomalies & Retransmissions",
                "content": """
On healthy networks, packet loss should be under 0.5%.
When packets are lost or delayed beyond the retransmission timeout (RTO):
- Sender retransmits the same sequence number with the same payload bytes.
- Receiver sends duplicate ACKs requesting the missing byte offset.
NetForensics flags these duplicate sequences as **Potential Retransmissions**, highlighting network bottlenecks or poor Wi-Fi signal quality.
"""
            }
        ],
        "quiz": [
            {
                "question": "What is the primary indicator of packet loss in a TCP packet capture?",
                "options": [
                    "Packets changing their EtherType value",
                    "(Recommended) Multiple segments observed with identical sequence numbers (retransmissions) and duplicate ACKs",
                    "DNS queries taking longer than 1 second",
                    "Packets having an even number of bytes"
                ],
                "answer_idx": 1,
                "explanation": "When an ACK is not received before the sender's timeout, TCP retransmits the data segment with the same sequence number. Observing identical sequence numbers is a hallmark of network loss."
            },
            {
                "question": "Which well-known port is standard for encrypted web traffic (HTTPS)?",
                "options": [
                    "Port 22",
                    "Port 53",
                    "Port 80",
                    "(Recommended) Port 443"
                ],
                "answer_idx": 3,
                "explanation": "Port 443 is assigned by IANA for HTTPS (HTTP over TLS/SSL). Port 80 is unencrypted HTTP, Port 53 is DNS, and Port 22 is SSH."
            },
            {
                "question": "What does a sudden massive spike on the traffic volume timeline typically signify?",
                "options": [
                    "A DNS server failure",
                    "(Recommended) A high-bandwidth data transfer (e.g. file download/upload) or a traffic burst/denial of service anomaly",
                    "An operating system reboot",
                    "A change in MAC address"
                ],
                "answer_idx": 1,
                "explanation": "Traffic timeline spikes correspond to heavy byte transfers (like streaming or file downloads) or network flooding anomalies."
            }
        ]
    },
    {
        "id": "tut_8",
        "num": 8,
        "title": "Differential Capture Comparison & QoS",
        "level": "Advanced",
        "time": "16 mins",
        "summary": "Compare baseline captures against impaired captures to measure latency shifts, loss, and throughput deltas.",
        "icon": "⚖️",
        "steps": [
            {
                "title": "1. The Scientific A/B Testing Method in Forensics",
                "content": """
To diagnose network degradation, network engineers use **differential analysis**:
1. Record a **Baseline Capture [Slot A]**: Captured when the network is operating normally.
2. Record an **Impaired / Degraded Capture [Slot B]**: Captured when users report lag, high latency, or packet drops.
3. Compare both captures side-by-side to isolate the exact protocol anomalies causing the failure.
"""
            },
            {
                "title": "2. Loading Comparison Slots in NetForensics",
                "content": """
In the **⚖️ Capture Comparison** console:
- Slot A can load your baseline capture (e.g. `sample_traffic.pcap`).
- Slot B can load your impaired experiment (e.g. `sample_impaired.pcap`).
- Or upload your own custom `.pcap` files into each slot.
"""
            },
            {
                "title": "3. Interpreting Comparative Deltas",
                "content": """
The comparison engine automatically computes:
- **Retransmission Differential**: Positive delta indicates severe packet loss in capture B.
- **Handshake $iRTT$ Latency Shift**: Measures added round-trip propagation delay.
- **Protocol Distribution Deltas**: Compares shifts in flag ratios (e.g., higher RST ratios indicate connection resets).
"""
            }
        ],
        "quiz": [
            {
                "question": "In network engineering, what is the primary purpose of capturing a 'baseline'?",
                "options": [
                    "To fill up the hard drive so the system runs faster",
                    "(Recommended) To establish a known-good standard of normal traffic patterns, latency, and flag distributions for future comparison",
                    "To replace the need for firewalls",
                    "To generate random packets for testing"
                ],
                "answer_idx": 1,
                "explanation": "A baseline provides the benchmark of healthy network operation. When issues arise, comparing against the baseline immediately highlights abnormal latency, retransmissions, or error flags."
            },
            {
                "question": "If Capture A has an average iRTT of 12ms and Capture B has an average iRTT of 232ms, what does this indicate?",
                "options": [
                    "Capture B has a smaller packet size",
                    "(Recommended) Capture B suffered an added latency penalty of ~220ms, typical of congested routers, satellite hops, or heavy propagation delay",
                    "Capture B was captured on an IPv6 network",
                    "Capture A had 10 times more packets"
                ],
                "answer_idx": 1,
                "explanation": "Initial Round Trip Time ($iRTT$) reflects path latency. An increase from 12ms to 232ms represents a significant propagation delay."
            },
            {
                "question": "What is the difference between Bandwidth and Throughput?",
                "options": [
                    "Bandwidth is measured in bytes, while Throughput is measured in bits",
                    "(Recommended) Bandwidth is the theoretical maximum capacity of the link, while Throughput is the actual rate of successfully delivered data",
                    "Bandwidth only applies to Wi-Fi, while Throughput only applies to Ethernet",
                    "They are identical terms with no difference"
                ],
                "answer_idx": 1,
                "explanation": "Bandwidth is the maximum theoretical capacity (e.g. 1 Gbps link). Throughput is the actual payload data successfully transferred per second after packet loss, latency, and protocol overhead."
            }
        ]
    }
]


# ---------------------------------------------------------------------------
# Interactive Practical Experiments (5 Hands-On Activities)
# ---------------------------------------------------------------------------

EXPERIMENTS: List[Dict[str, Any]] = [
    {
        "id": "exp_a",
        "num": "A",
        "title": "DNS Investigation & Domain Resolution",
        "icon": "🌐",
        "difficulty": "Beginner",
        "time": "10 mins",
        "summary": "Execute a real DNS resolution query, capture the traffic, and inspect the query name and resolved IP address.",
        "sample_file": "sample_captures/synthetic_protocol_suite.pcap",
        "objective": "Observe how human hostnames are translated into IP addresses over UDP port 53.",
        "steps": [
            {
                "step_num": 1,
                "title": "Execute DNS Query in Terminal",
                "instruction": "Open PowerShell or Command Prompt on your computer and execute the following command:",
                "command": "nslookup google.com",
                "explanation": "The `nslookup` (Name Server Lookup) command sends a DNS query packet to your configured DNS server requesting the IPv4 ('A') and IPv6 ('AAAA') addresses for google.com."
            },
            {
                "step_num": 2,
                "title": "Capture Traffic or Load DNS Learning Fixture",
                "instruction": "If you have live capture enabled, sniff while running the command. Alternatively, load the pre-recorded learning fixture containing this exact DNS interaction:",
                "action_button": "⚡ Load DNS Learning Capture",
                "explanation": "Loading this fixture loads 21 verified protocol frames including the DNS query (frame #1) and response (frame #2)."
            },
            {
                "step_num": 3,
                "title": "Inspect the DNS Query & Response",
                "instruction": "Navigate to 🔍 Packet Inspector and examine Frame #1 and Frame #2:",
                "checklist": [
                    "Frame #1: Notice UDP port 53, qr=0 (Query), and qname='google.com'",
                    "Frame #2: Notice UDP port 53, qr=1 (Response), rcode=0 (NOERROR)",
                    "Examine the Answer Records containing the resolved IP addresses"
                ]
            }
        ]
    },
    {
        "id": "exp_b",
        "num": "B",
        "title": "TCP Three-Way Handshake Reconstruction",
        "icon": "🤝",
        "difficulty": "Intermediate",
        "time": "15 mins",
        "summary": "Reconstruct a complete TCP connection: SYN, SYN-ACK, ACK, data transfer, and 4-way FIN termination.",
        "sample_file": "sample_captures/synthetic_protocol_suite.pcap",
        "objective": "Verify how stateful TCP synchronization operates on real packets.",
        "steps": [
            {
                "step_num": 1,
                "title": "Generate a TCP Web Session",
                "instruction": "In PowerShell, test an HTTP connection using `curl` or `Test-NetConnection`:",
                "command": "curl -I http://example.com",
                "explanation": "This establishes a TCP socket with the remote web server on port 80, requesting HTTP header information."
            },
            {
                "step_num": 2,
                "title": "Load the Verified TCP Handshake Fixture",
                "instruction": "Load the synthetic handshake fixture to analyze clean 3-way synchronization:",
                "action_button": "⚡ Load TCP Handshake Capture",
                "explanation": "Loads the 10-packet TCP flow demonstrating SYN, SYN-ACK, ACK, PSH-ACK payload delivery, and 4-way FIN teardown."
            },
            {
                "step_num": 3,
                "title": "Analyze Connection in Connection Explorer",
                "instruction": "Navigate to 🔗 Connection Explorer:",
                "checklist": [
                    "Confirm the session state is 'Complete (Established → Graceful FIN Close)'",
                    "Inspect the 3-step handshake visual cards (SYN → SYN-ACK → ACK)",
                    "Verify the Initial Round Trip Time (iRTT)",
                    "Check the chronological event scatter chart showing handshake, data, and teardown"
                ]
            }
        ]
    },
    {
        "id": "exp_c",
        "num": "C",
        "title": "ICMP Ping & Time-To-Live (TTL) Investigation",
        "icon": "🏓",
        "difficulty": "Beginner",
        "time": "10 mins",
        "summary": "Generate ICMP Echo Requests and Replies, inspect message types, and analyze TTL hop decrements.",
        "sample_file": "sample_captures/synthetic_protocol_suite.pcap",
        "objective": "Understand how Layer 3 diagnostic tools test reachability and latency without port numbers.",
        "steps": [
            {
                "step_num": 1,
                "title": "Send ICMP Echo Requests",
                "instruction": "In PowerShell, ping a public DNS server with 4 test probes:",
                "command": "ping 8.8.8.8 -n 4",
                "explanation": "`ping` uses the Internet Control Message Protocol (ICMP Type 8) to test end-to-end network reachability and measure round-trip latency."
            },
            {
                "step_num": 2,
                "title": "Load ICMP Learning Capture",
                "instruction": "Load the learning capture to inspect raw ICMP frames:",
                "action_button": "⚡ Load ICMP Learning Capture",
                "explanation": "Contains Frame #15 (ICMP Echo Request) and Frame #16 (ICMP Echo Reply)."
            },
            {
                "step_num": 3,
                "title": "Inspect Type, Code, and TTL Fields",
                "instruction": "Navigate to 🔍 Packet Inspector and inspect Frame #15 and #16:",
                "checklist": [
                    "Notice ICMP has no port numbers (operates directly above IP, Protocol 1)",
                    "Frame #15: Type 8, Code 0 (Echo Request)",
                    "Frame #16: Type 0, Code 0 (Echo Reply)",
                    "Examine the IPv4 header 'TTL' field and notice estimated router hop counts"
                ]
            }
        ]
    },
    {
        "id": "exp_d",
        "num": "D",
        "title": "Protocol Comparison: TCP vs UDP Dissection",
        "icon": "⚖️",
        "difficulty": "Intermediate",
        "time": "12 mins",
        "summary": "Directly compare connection-oriented TCP against lightweight connectionless UDP.",
        "sample_file": "sample_captures/synthetic_protocol_suite.pcap",
        "objective": "Contrast transport header overhead, state management, and speed trade-offs.",
        "steps": [
            {
                "step_num": 1,
                "title": "Understand the Architectural Trade-Offs",
                "instruction": "Review the core differences between the two primary Layer 4 transport protocols:",
                "explanation": """
- **TCP**: 20-byte minimum header. Stateful, requires 3-way handshake, guarantees in-order delivery and retransmission, adds latency. Used for Web, Email, File Transfer.
- **UDP**: 8-byte fixed header. Connectionless, no handshake, no acknowledgments, minimal latency. Used for DNS, Video Streaming, Gaming, VoIP.
"""
            },
            {
                "step_num": 2,
                "title": "Load Multi-Protocol Suite",
                "instruction": "Load the complete 7-protocol suite to inspect both protocols side-by-side:",
                "action_button": "⚡ Load Protocol Suite",
                "explanation": "Contains both UDP datagrams (Frames #1-#2, #13-#14) and TCP streams (Frames #5-#12)."
            },
            {
                "step_num": 3,
                "title": "Dissect Header Differences in Packet Inspector",
                "instruction": "Compare Frame #1 (UDP) vs Frame #5 (TCP):",
                "checklist": [
                    "Inspect Frame #1 (UDP): Notice only 4 header fields (SPort, DPort, Length, Checksum) = 8 bytes total",
                    "Inspect Frame #5 (TCP): Notice SEQ, ACK, Data Offset, Flags, Window Size, Urgent Pointer = 20 bytes minimum",
                    "Check the visual encapsulation diagram in Packet Inspector to see header size differences"
                ]
            }
        ]
    },
    {
        "id": "exp_e",
        "num": "E",
        "title": "Local Host Interface & Gateway Diagnostics",
        "icon": "🔍",
        "difficulty": "Beginner",
        "time": "10 mins",
        "summary": "Inspect your machine's physical network adapters, assigned IP, MAC, Subnet Mask, and Default Gateway.",
        "sample_file": "sample_captures/synthetic_protocol_suite.pcap",
        "objective": "Connect software packet captures with real physical host networking configuration.",
        "steps": [
            {
                "step_num": 1,
                "title": "Run Network Interface Query in PowerShell",
                "instruction": "Execute this command in PowerShell to query your active adapter configuration:",
                "command": "Get-NetIPConfiguration",
                "explanation": "This modern Windows cmdlet retrieves your Interface Alias, IPv4 Address, IPv6 Address, IPv4 Default Gateway, and DNS Servers."
            },
            {
                "step_num": 2,
                "title": "Inspect MAC Address & Physical Link",
                "instruction": "To view your physical MAC hardware addresses and link speeds, execute:",
                "command": "Get-NetAdapter",
                "explanation": "Displays physical adapter names (Wi-Fi, Ethernet), connection status (Up/Disconnected), link speed (e.g. 1000 Mbps), and physical MAC addresses."
            },
            {
                "step_num": 3,
                "title": "Correlate with NetForensics Live Capture",
                "instruction": "Open the 📡 Live Capture tab in this application:",
                "checklist": [
                    "Compare the adapters listed in the 'Network Adapter Interface' dropdown with your PowerShell output",
                    "Notice the human-friendly descriptions and GUIDs",
                    "Verify how your local IP matches the source IP observed in captured outbound traffic"
                ]
            }
        ]
    }
]


# ---------------------------------------------------------------------------
# Searchable Networking Glossary (25 Essential Terms)
# ---------------------------------------------------------------------------

GLOSSARY_ITEMS: List[Dict[str, str]] = [
    {
        "term": "Packet",
        "category": "Network (L3)",
        "definition": "A formatted unit of data transmitted over a network. At Layer 3, it consists of control metadata (IP header) and user payload.",
        "app_example": "In NetForensics, every row in the Frame Dissection Table represents a captured packet."
    },
    {
        "term": "Frame",
        "category": "Data Link (L2)",
        "definition": "The Layer 2 Protocol Data Unit transmitted across a physical wire or Wi-Fi radio. Contains Source/Destination MAC addresses and an EtherType field.",
        "app_example": "Inspected under the 'Ethernet II' header expander in the Packet Inspector."
    },
    {
        "term": "Ethernet",
        "category": "Data Link (L2)",
        "definition": "The most widely used wired local area network (LAN) physical and data-link standard (IEEE 802.3).",
        "app_example": "Shown as the outermost Layer 2 header enclosing IPv4/IPv6 datagrams."
    },
    {
        "term": "MAC Address",
        "category": "Data Link (L2)",
        "definition": "Media Access Control address. A unique 48-bit physical identifier (e.g., 00:1A:2B:3C:4D:5E) assigned to a network interface card by the manufacturer.",
        "app_example": "Displayed in the Packet Table and highlighted in the Packet Inspector header badges."
    },
    {
        "term": "IP Address",
        "category": "Network (L3)",
        "definition": "Internet Protocol address. A logical numerical label (IPv4: 32-bit dotted-decimal, IPv6: 128-bit hexadecimal) used for global routing across networks.",
        "app_example": "Ranked in the 'Top Communicating Endpoints' bar chart in Network Analytics."
    },
    {
        "term": "Subnet Mask",
        "category": "Network (L3)",
        "definition": "A 32-bit number (e.g. 255.255.255.0 or /24) that divides an IP address into its network portion and host portion.",
        "app_example": "Determines whether an IP packet is sent locally via ARP or forwarded to the default gateway."
    },
    {
        "term": "Default Gateway",
        "category": "Network (L3)",
        "definition": "The local router's IP address that forwards outbound packets from your subnet to the wider Internet.",
        "app_example": "Observed as the destination MAC address for all outbound internet-bound packets."
    },
    {
        "term": "Router",
        "category": "Network (L3)",
        "definition": "A Layer 3 networking device that inspects destination IP addresses and forwards packets between different subnets and networks.",
        "app_example": "Decrements the packet's TTL field by 1 on every hop."
    },
    {
        "term": "Switch",
        "category": "Data Link (L2)",
        "definition": "A Layer 2 networking device that forwards Ethernet frames between local ports using a MAC address table.",
        "app_example": "Switches do not modify IP or TCP headers; they only switch frames based on destination MAC."
    },
    {
        "term": "Port",
        "category": "Transport (L4)",
        "definition": "A 16-bit number (0–65535) used by TCP and UDP to multiplex multiple network applications on a single IP address.",
        "app_example": "Analyzed in Network Analytics under 'Top Active Service Ports' (e.g. 80=HTTP, 443=HTTPS)."
    },
    {
        "term": "TCP",
        "category": "Transport (L4)",
        "definition": "Transmission Control Protocol. A reliable, stateful, connection-oriented transport protocol that guarantees ordered data delivery.",
        "app_example": "Dissected in Connection Explorer with complete 3-way handshake and state machine tracking."
    },
    {
        "term": "UDP",
        "category": "Transport (L4)",
        "definition": "User Datagram Protocol. A lightweight, connectionless transport protocol with minimal overhead and no handshake or retransmissions.",
        "app_example": "Classified as 'UDP (Connectionless)' in Connection Explorer and used by DNS traffic."
    },
    {
        "term": "DNS",
        "category": "Application (L7)",
        "definition": "Domain Name System. The hierarchical naming service that translates human-readable hostnames (e.g. google.com) into numerical IP addresses.",
        "app_example": "Analyzed in Network Analytics under 'DNS Resolution Statistics & Queried Domains'."
    },
    {
        "term": "DHCP",
        "category": "Application (L7)",
        "definition": "Dynamic Host Configuration Protocol. Automatically assigns IP addresses, subnet masks, gateways, and DNS servers to network devices.",
        "app_example": "Operates over UDP ports 67 (server) and 68 (client)."
    },
    {
        "term": "ICMP",
        "category": "Network (L3)",
        "definition": "Internet Control Message Protocol. A network diagnostic and error-reporting protocol used by tools like ping and traceroute.",
        "app_example": "Inspected under the ICMP layer in Packet Inspector (Type 8 Echo Request / Type 0 Echo Reply)."
    },
    {
        "term": "TTL",
        "category": "Network (L3)",
        "definition": "Time-To-Live. An 8-bit counter in IPv4 headers that limits packet lifespan. Decremented by 1 at every router hop to prevent infinite routing loops.",
        "app_example": "Highlighted in Packet Inspector with estimated operating system initial TTL and hop counts."
    },
    {
        "term": "MTU",
        "category": "Data Link (L2)",
        "definition": "Maximum Transmission Unit. The largest physical packet size (in bytes) that can be transmitted over a network link without fragmentation (standard Ethernet: 1500 bytes).",
        "app_example": "Observed in packet length metrics to verify frames do not exceed link limits."
    },
    {
        "term": "Bandwidth",
        "category": "Performance",
        "definition": "The theoretical maximum transmission capacity of a network communication link, typically measured in Megabits or Gigabits per second (Mbps / Gbps).",
        "app_example": "Compared with actual observed throughput in Capture Comparison."
    },
    {
        "term": "Throughput",
        "category": "Performance",
        "definition": "The actual rate of successfully delivered application data across a network link per unit of time, accounting for overhead and packet loss.",
        "app_example": "Calculated in Network Analytics as byte volume over elapsed capture seconds."
    },
    {
        "term": "Latency",
        "category": "Performance",
        "definition": "The time delay taken for a packet of data to travel from the sender to the destination across the network.",
        "app_example": "Visualized in the arrival delta and traffic timeline."
    },
    {
        "term": "RTT",
        "category": "Performance",
        "definition": "Round-Trip Time. The total time taken for a data packet to travel from sender to receiver plus the time taken for the acknowledgment to return.",
        "app_example": "Measured precisely in Connection Explorer as Initial RTT (iRTT) from SYN to SYN-ACK."
    },
    {
        "term": "Packet Loss",
        "category": "Performance",
        "definition": "Failure of one or more transmitted packets to reach their destination, caused by network congestion, noise, or queue drops.",
        "app_example": "Diagnosed in Capture Comparison by tracking retransmissions and missing ACKs."
    },
    {
        "term": "Retransmission",
        "category": "Transport (L4)",
        "definition": "A repeated transmission of a previously sent TCP segment after the sender's retransmission timer expires without receiving an ACK.",
        "app_example": "Highlighted in crimson in Connection Explorer and Analytics as potential QoS anomalies."
    },
    {
        "term": "Encapsulation",
        "category": "Architecture",
        "definition": "The process of wrapping higher-layer data inside lower-layer protocol headers as it travels down the communication stack.",
        "app_example": "Rendered interactively in Packet Inspector's 'Visual Encapsulation Wrapping Architecture' diagram."
    },
    {
        "term": "PCAP",
        "category": "Forensics",
        "definition": "Packet Capture. An industry-standard binary file format used to record, store, and exchange network packet streams for offline inspection.",
        "app_example": "NetForensics exports and imports standard .pcap and .pcapng captures compatible with Wireshark."
    }
]

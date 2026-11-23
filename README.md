# 🔬 Network Forensics Analyzer

**Interactive Packet Forensics and Network Behavior Analyzer**

A Python-based network packet analyzer built for DCCN (Data Communication and Computer Networks) coursework. Captures real network traffic, decodes packets, visualizes protocol layers, reconstructs communication flows, and helps users understand what is happening inside a network.

## Quick Start

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate sample capture (optional)
python generate_sample_capture.py

# 3. Run the dashboard
streamlit run app.py
```

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.12+ | Backend and packet processing |
| Scapy | Packet capture and parsing |
| Streamlit | Interactive web dashboard |
| Plotly | Charts and visualizations |
| Pandas | Tabular data and statistics |
| Npcap | Live capture on Windows (optional) |

## Project Structure

```
DCCN/
├── app.py                  # Streamlit entry point
├── requirements.txt        # Python dependencies
├── generate_sample_capture.py  # Create sample PCAP for demos
├── config/
│   └── settings.py         # Constants and configuration
├── core/                   # Packet processing modules
│   ├── capture.py          # Live capture engine
│   ├── packet_parser.py    # Packet → structured data
│   ├── flow_analyzer.py    # TCP flow reconstruction
│   ├── protocol_analyzer.py # Statistics and aggregation
│   ├── lab_manager.py      # Guided Lab curriculum & progress engine
│   └── pcap_manager.py     # PCAP file I/O
├── ui/                     # Streamlit workspace modules
│   ├── overview.py         # Dashboard (Minimal executive overview)
│   ├── packet_analysis.py  # Primary Workspace (Wireshark 3-pane List/Details/Bytes)
│   ├── connection_explorer.py # Connections (TCP Flow Reconstructor & Handshake)
│   ├── network_monitor.py  # Network Monitor (Host Devices & Traffic Telemetry)
│   ├── capture_comparison.py # Capture Comparison (Baseline vs Impaired QoS)
│   └── guided_lab.py       # Guided Help (Interactive Learning Academy)
├── utils/                  # Helpers and utilities
│   ├── helpers.py          # Formatting and conversion
│   └── hex_dump.py         # Hex + ASCII dump renderer
├── tests/                  # Unit tests
└── sample_captures/        # Sample PCAP files for demos
```

## Features

- **Live Packet Capture** — Capture from real network interfaces
- **Packet Table & Filtering** — Browse, search, and filter packets
- **Visual Packet Journey** — See protocol layer encapsulation
- **Hex/ASCII Dump** — Raw packet bytes view
- **TCP Flow Reconstruction** — Handshake visualization
- **Network Analytics** — Protocol distribution, traffic patterns
- **Capture Comparison** — Compare baseline vs impaired traffic
- **Guided Lab (Interactive Learning Mode)** — Cisco Packet Tracer-inspired interactive tutorials, hands-on terminal experiments, quizzes, and 25-term networking glossary with local progress tracking
- **Explain This Packet** — Plain-English packet explanations

## Requirements

- Python 3.12 or later
- Npcap (for live capture only — install from https://npcap.com)
- Administrator privileges (for live capture only)

## DCCN Topics Demonstrated

OSI/TCP-IP models, protocol layers, Ethernet/LAN, IPv4/IPv6, TCP/UDP, DNS, packet framing, bandwidth/throughput, error detection, congestion/QoS, and routing concepts.

## License

Educational project — built for college coursework.

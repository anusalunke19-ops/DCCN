"""
app.py — Main entry point for the Network Forensics Analyzer.

This is the file you run with:  streamlit run app.py

Architecture overview:
─────────────────────
Streamlit works by re-running this entire script on every user interaction
(button click, slider change, etc.). That means:

1. We CANNOT store data in regular Python variables — they reset every rerun.
   Instead, we use st.session_state, which persists across reruns.

2. We CANNOT run long-running tasks (like packet capture) in the main thread.
   They would block the UI. We'll use background threads later (Phase 6).

3. Each "page" of our dashboard is a separate function in the ui/ folder.
   This file just sets up the sidebar navigation and calls the right page.

Dashboard Capabilities:
──────────────────────
This application is a professional network forensics and packet analysis tool.
Each dashboard section covers specific network investigation workflows:

- Overview      → Protocol distribution, traffic volume (bandwidth/throughput)
- Live Capture  → Packet framing, real-time protocol observation
- Inspector     → OSI/TCP-IP layers, header fields, encapsulation
- Connections   → TCP handshake, connection management, reliability
- Analytics     → DNS, traffic patterns, congestion indicators
- Comparison    → Delay, loss, QoS, controlled experiments
"""

import streamlit as st
import sys
import os

# ---------------------------------------------------------------------------
# Page configuration — MUST be the first Streamlit command
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Network Forensics Analyzer",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Ensure our project root is on the Python path so imports work correctly.
# This is needed because Streamlit may run from a different directory.
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ui.overview import render_overview_page
from ui.live_capture import render_live_capture_page
from ui.packet_inspector import render_packet_inspector_page
from ui.packet_analysis import render_packet_analysis_page
from ui.connection_explorer import render_connection_explorer_page
from ui.network_monitor import render_network_monitor_page
from ui.capture_comparison import render_capture_comparison_page
from ui.guided_lab import render_guided_lab_page
from core.packet_parser import parse_packet
from core.pcap_manager import load_pcap


# ---------------------------------------------------------------------------
# Dependency check — give clear errors instead of crashing
# ---------------------------------------------------------------------------
def check_dependencies():
    """
    Verify that all required packages are installed.
    Returns a list of (package_name, status, message) tuples.
    """
    results = []

    # Check Scapy
    try:
        import scapy.all
        results.append(("Scapy", "✅", f"v{scapy.__version__}" if hasattr(scapy, '__version__') else "installed"))
    except ImportError:
        results.append(("Scapy", "❌", "Not installed. Run: pip install scapy"))

    # Check Plotly
    try:
        import plotly
        results.append(("Plotly", "✅", f"v{plotly.__version__}"))
    except ImportError:
        results.append(("Plotly", "❌", "Not installed. Run: pip install plotly"))

    # Check Pandas
    try:
        import pandas
        results.append(("Pandas", "✅", f"v{pandas.__version__}"))
    except ImportError:
        results.append(("Pandas", "❌", "Not installed. Run: pip install pandas"))

    # Check Npcap (Windows only — needed for live capture, not offline analysis)
    if sys.platform == "win32":
        npcap_path = r"C:\Program Files\Npcap"
        if os.path.exists(npcap_path):
            results.append(("Npcap", "✅", "Installed (live capture available)"))
        else:
            results.append(("Npcap", "⚠️",
                "Not found — live capture won't work. "
                "Offline PCAP analysis still works fine. "
                "Install from https://npcap.com if you need live capture."))

    return results


# ---------------------------------------------------------------------------
# Session state initialization
# ---------------------------------------------------------------------------
def init_session_state():
    """
    Initialize all session state variables.

    st.session_state is a dict-like object that persists across Streamlit
    reruns. We use it to store:
    - Captured packets
    - Current page selection
    - Capture thread references (later)
    - Filter state
    """
    defaults = {
        "packets": [],            # List of raw Scapy packet objects
        "raw_packets": [],        # Explicit raw packets mirror
        "parsed_packets": [],     # List of parsed packet dicts
        "current_page": "📊 Overview",
        "capture_running": False,
        "selected_packet_idx": 0,
        "loaded_file": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# ---------------------------------------------------------------------------
# Custom CSS for the clean, professional light theme
# ---------------------------------------------------------------------------
def apply_custom_css():
    """Apply clean, high-contrast light aesthetic with full visibility and readability."""
    st.markdown("""
    <style>
        /* Base typography & backgrounds */
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

        html, body, [class*="css"], .stApp {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
            color: #263238 !important;
            background-color: #F7F8FA !important;
        }

        /* Sidebar styling */
        section[data-testid="stSidebar"] {
            background-color: #FFFFFF !important;
            border-right: 1px solid #E2E8F0 !important;
            padding: 1.5rem 1rem !important;
        }

        section[data-testid="stSidebar"] hr {
            border-color: #E2E8F0 !important;
        }

        section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
        section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] span {
            color: #263238 !important;
        }

        /* Sidebar Radio Navigation (HIGH CONTRAST) */
        div[data-testid="stRadio"] {
            background-color: transparent !important;
        }

        div[data-testid="stRadio"] > label {
            display: none !important;
        }

        div[data-testid="stRadio"] div[role="radiogroup"] {
            gap: 6px !important;
        }

        div[data-testid="stRadio"] label[data-baseweb="radio"] {
            background-color: #FFFFFF !important;
            border: 1px solid #E2E8F0 !important;
            border-radius: 6px !important;
            padding: 9px 12px !important;
            margin-bottom: 2px !important;
            cursor: pointer !important;
            transition: all 0.15s ease !important;
            width: 100% !important;
        }

        div[data-testid="stRadio"] label[data-baseweb="radio"]:hover {
            background-color: #F8FAFC !important;
            border-color: #159A91 !important;
        }

        div[data-testid="stRadio"] label[data-baseweb="radio"] div[data-testid="stMarkdownContainer"] p {
            color: #263238 !important;
            font-weight: 600 !important;
            font-size: 0.85rem !important;
            margin: 0 !important;
        }

        /* Selected Radio Item in Sidebar */
        div[data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) {
            background-color: #DDF3ED !important;
            border: 1px solid #159A91 !important;
            box-shadow: 0 1px 3px rgba(21, 154, 145, 0.15) !important;
        }

        div[data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) div[data-testid="stMarkdownContainer"] p {
            color: #0F766E !important;
            font-weight: 700 !important;
        }

        /* Technical Headers & Badges */
        .soc-tag {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.72rem !important;
            font-weight: 700 !important;
            letter-spacing: 0.08em !important;
            color: #159A91 !important;
            text-transform: uppercase !important;
            margin-bottom: 3px !important;
            display: inline-block !important;
        }

        .main-header {
            font-size: 1.45rem !important;
            font-weight: 700 !important;
            letter-spacing: -0.02em !important;
            color: #263238 !important;
            margin-bottom: 0.25rem !important;
        }

        .sub-header {
            font-size: 0.88rem !important;
            color: #64748B !important;
            margin-bottom: 1.1rem !important;
        }

        /* Metric cards */
        div[data-testid="stMetric"] {
            background-color: #FFFFFF !important;
            border: 1px solid #E2E8F0 !important;
            border-radius: 6px !important;
            padding: 12px 16px !important;
            box-shadow: 0 1px 3px rgba(0,0,0,0.02) !important;
        }

        div[data-testid="stMetric"]:hover {
            border-color: #CBD5E1 !important;
        }

        div[data-testid="stMetric"] label {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.75rem !important;
            font-weight: 600 !important;
            letter-spacing: 0.04em !important;
            color: #64748B !important;
            text-transform: uppercase !important;
        }

        div[data-testid="stMetric"] [data-testid="stMetricValue"] {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 1.35rem !important;
            font-weight: 700 !important;
            color: #263238 !important;
        }

        /* Status & SOC badges */
        .status-badge {
            display: inline-flex !important;
            align-items: center !important;
            padding: 3px 9px !important;
            border-radius: 4px !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.75rem !important;
            font-weight: 600 !important;
            letter-spacing: 0.04em !important;
        }

        .badge-active {
            background-color: #DDF3ED !important;
            color: #0F766E !important;
            border: 1px solid #A7F3D0 !important;
        }

        .badge-inactive {
            background-color: #F1F5F9 !important;
            color: #64748B !important;
            border: 1px solid #E2E8F0 !important;
        }

        .badge-warning {
            background-color: #FEF3C7 !important;
            color: #D97706 !important;
            border: 1px solid #FDE68A !important;
        }

        .soc-badge {
            display: inline-flex !important;
            align-items: center !important;
            padding: 2px 8px !important;
            border-radius: 4px !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.7rem !important;
            font-weight: 600 !important;
            letter-spacing: 0.04em !important;
        }

        .soc-badge-cyan, .soc-badge-teal {
            background-color: #DDF3ED !important;
            color: #0F766E !important;
            border: 1px solid #A7F3D0 !important;
        }

        .soc-badge-green {
            background-color: #ECFDF5 !important;
            color: #059669 !important;
            border: 1px solid #A7F3D0 !important;
        }

        .soc-badge-amber {
            background-color: #FEF3C7 !important;
            color: #D97706 !important;
            border: 1px solid #FDE68A !important;
        }

        .soc-badge-purple {
            background-color: #F3E8FF !important;
            color: #7C3AED !important;
            border: 1px solid #DDD6FE !important;
        }

        /* Monospace Hex Display */
        .hex-display {
            font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace !important;
            font-size: 0.82rem !important;
            line-height: 1.55 !important;
            background-color: #F8FAFC !important;
            color: #1E293B !important;
            padding: 14px 18px !important;
            border-radius: 6px !important;
            border: 1px solid #E2E8F0 !important;
            overflow-x: auto !important;
        }

        .hex-display pre {
            margin: 0 !important;
            font-family: inherit !important;
            color: #1E293B !important;
        }

        /* Technical Info Panel */
        .tech-panel {
            background-color: #FFFFFF !important;
            border: 1px solid #E2E8F0 !important;
            border-radius: 6px !important;
            padding: 14px 18px !important;
            margin: 10px 0 !important;
            box-shadow: 0 1px 3px rgba(0,0,0,0.02) !important;
        }

        /* Clean Streamlit Tab styling (HIGH CONTRAST) */
        .stTabs [data-baseweb="tab-list"] {
            border-bottom: 2px solid #E2E8F0 !important;
            gap: 6px !important;
            background-color: transparent !important;
            padding-bottom: 1px !important;
        }

        .stTabs [data-baseweb="tab"] {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.82rem !important;
            font-weight: 600 !important;
            padding: 8px 16px !important;
            color: #263238 !important;
            background-color: #FFFFFF !important;
            border: 1px solid #E2E8F0 !important;
            border-bottom: none !important;
            border-radius: 6px 6px 0 0 !important;
            transition: all 0.15s ease !important;
        }

        .stTabs [data-baseweb="tab"]:hover {
            color: #159A91 !important;
            background-color: #F8FAFC !important;
        }

        .stTabs [data-baseweb="tab"][aria-selected="true"] {
            color: #0F766E !important;
            border: 1px solid #159A91 !important;
            border-bottom: 2px solid #DDF3ED !important;
            background-color: #DDF3ED !important;
            font-weight: 700 !important;
            margin-bottom: -1px !important;
        }

        .stTabs [data-baseweb="tab"] * {
            color: inherit !important;
        }

        /* Buttons (CLEAN & HIGH CONTRAST) */
        div.stButton > button {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.82rem !important;
            font-weight: 600 !important;
            border-radius: 6px !important;
            border: 1px solid #CBD5E1 !important;
            background-color: #FFFFFF !important;
            color: #263238 !important;
            transition: all 0.15s ease-in-out !important;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03) !important;
            padding: 6px 14px !important;
        }

        div.stButton > button:hover {
            border-color: #159A91 !important;
            color: #159A91 !important;
            background-color: #F8FAFC !important;
        }

        div.stButton > button[kind="primary"] {
            background-color: #159A91 !important;
            color: #FFFFFF !important;
            border: 1px solid #159A91 !important;
            font-weight: 700 !important;
        }

        div.stButton > button[kind="primary"]:hover {
            background-color: #12827A !important;
            border-color: #12827A !important;
            color: #FFFFFF !important;
        }

        /* Dataframe container */
        div[data-testid="stDataFrame"] {
            border: 1px solid #E2E8F0 !important;
            border-radius: 6px !important;
            background-color: #FFFFFF !important;
        }

        /* Expander */
        div[data-testid="stExpander"] {
            background-color: #FFFFFF !important;
            border: 1px solid #E2E8F0 !important;
            border-radius: 6px !important;
            box-shadow: 0 1px 2px rgba(0,0,0,0.02) !important;
        }

        div[data-testid="stExpander"] summary {
            color: #263238 !important;
            font-weight: 600 !important;
        }

        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 7px;
            height: 7px;
        }
        ::-webkit-scrollbar-track {
            background: #F1F5F9;
        }
        ::-webkit-scrollbar-thumb {
            background: #CBD5E1;
            border-radius: 3px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #94A3B8;
        }

        /* KPI Cards (used in Connection Explorer, Network Monitor, Capture Comparison) */
        .kpi-card {
            background: #FFFFFF !important;
            border: 1px solid #E2E8F0 !important;
            border-radius: 6px !important;
            padding: 12px 16px !important;
            box-shadow: 0 1px 3px rgba(0,0,0,0.02) !important;
        }
        .kpi-label {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.72rem !important;
            font-weight: 600 !important;
            color: #64748B !important;
            text-transform: uppercase !important;
            letter-spacing: 0.04em !important;
        }
        .kpi-val {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 1.25rem !important;
            font-weight: 700 !important;
            color: #263238 !important;
            margin: 2px 0 !important;
        }
        .kpi-sub {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.7rem !important;
            color: #64748B !important;
        }

        /* Form Labels & Inputs */
        label, .stTextInput label, .stSelectbox label, .stNumberInput label, .stMultiSelect label {
            color: #263238 !important;
            font-weight: 600 !important;
            font-size: 0.8rem !important;
        }

        div[data-baseweb="select"] {
            border-color: #CBD5E1 !important;
        }

        div[data-baseweb="select"] * {
            color: #263238 !important;
        }

        /* Keep header & sidebar controls visible and clean */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header[data-testid="stHeader"] {
            background-color: transparent !important;
        }
        [data-testid="stSidebarCollapseButton"],
        [data-testid="collapsedControl"] {
            visibility: visible !important;
            display: flex !important;
            color: #159A91 !important;
        }
    </style>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Workspace definitions & Navigation Helper
# ---------------------------------------------------------------------------
WORKSPACE_PAGES = [
    "📊 Overview",
    "📡 Live Capture",
    "🔍 Packet Inspector",
    "🔗 TCP Connections",
    "📈 Network Analytics",
    "⚖️ Capture Comparison",
    "🎓 Guided Labs",
]


def navigate_to(page: str):
    """Safely switch workspace and ensure all sidebar and top-nav state stays synchronized."""
    st.session_state["current_page"] = page
    st.rerun()


# ---------------------------------------------------------------------------
# Top navigation bar (Persistent across all workspaces)
# ---------------------------------------------------------------------------
def render_top_navigation(current_page: str):
    """
    Render a prominent horizontal workspace navigation bar across the top of the main area.
    Guarantees clear, one-click access to all 7 workspaces with live backend status.
    """
    is_capturing = st.session_state.get("capture_running", False)
    loaded_file = st.session_state.get("loaded_file")
    packet_count = len(st.session_state.get("packets", []))

    if is_capturing:
        status_html = '<span class="status-badge badge-active">● CAPTURING LIVE</span>'
    elif packet_count > 0:
        status_html = f'<span class="status-badge badge-active">✓ BUFFER READY ({packet_count:,} PKTS)</span>'
    else:
        status_html = '<span class="status-badge badge-inactive">○ ENGINE: IDLE</span>'

    st.markdown(f"""
    <div class="top-nav-bar">
        <div class="top-nav-brand">
            <span class="top-nav-title">🔬 NetForensics Analyzer</span>
            <span class="top-nav-tag">// WORKSPACES</span>
        </div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; color: #64748B; display: flex; align-items: center; gap: 8px;">
            <span>BACKEND STATUS:</span> {status_html}
        </div>
    </div>
    """, unsafe_allow_html=True)

    def _on_top_nav_click(target_page: str):
        st.session_state["current_page"] = target_page
        st.session_state["sidebar_workspace_radio"] = target_page

    cols = st.columns(len(WORKSPACE_PAGES))
    for i, p in enumerate(WORKSPACE_PAGES):
        is_active = (p == current_page)
        btn_type = "primary" if is_active else "secondary"
        cols[i].button(
            p,
            key=f"top_nav_item_{i}",
            type=btn_type,
            use_container_width=True,
            on_click=_on_top_nav_click,
            args=(p,)
        )


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------
def render_sidebar():
    """Render the sidebar with navigation and project info."""
    with st.sidebar:
        st.markdown('<div class="soc-tag">// NETFORENSICS WORKSTATION</div>', unsafe_allow_html=True)
        st.markdown('<div class="main-header" style="font-size: 1.35rem; margin-bottom: 0;">🔬 NetForensics</div>', unsafe_allow_html=True)
        st.caption("Network Forensics & Behavior Analyzer")

        st.divider()

        # Alias resolution for backward compatibility
        cur = st.session_state.get("current_page", "📊 Overview")
        if cur in ["📊 Dashboard", "🏠 Overview", "Overview", "Dashboard"]:
            cur = "📊 Overview"
        elif cur in ["Live Capture", "🔍 Packet Analysis", "Packet Analysis"]:
            cur = "📡 Live Capture"
        elif cur in ["Packet Inspector"]:
            cur = "🔍 Packet Inspector"
        elif cur in ["🔗 Connections", "Connections", "🔗 Connection Explorer", "TCP Connections"]:
            cur = "🔗 TCP Connections"
        elif cur in ["📡 Network Monitor", "Network Monitor", "📊 Network Analytics", "Network Analytics"]:
            cur = "📈 Network Analytics"
        elif cur in ["Capture Comparison"]:
            cur = "⚖️ Capture Comparison"
        elif cur in ["🎓 Guided Help", "Guided Help", "🎓 Guided Lab", "Guided Lab", "Guided Labs / Learning"]:
            cur = "🎓 Guided Labs"
        if cur not in WORKSPACE_PAGES:
            cur = "📊 Overview"
        st.session_state["current_page"] = cur

        # Synchronize radio key with current page if updated externally
        if st.session_state.get("sidebar_workspace_radio") != cur:
            st.session_state["sidebar_workspace_radio"] = cur

        st.markdown("<div style='font-family: JetBrains Mono; font-size: 0.72rem; font-weight: 600; color: #159A91; text-transform: uppercase; margin-bottom: 6px;'>NAVIGATION</div>", unsafe_allow_html=True)

        def _on_sidebar_radio_change():
            st.session_state["current_page"] = st.session_state["sidebar_workspace_radio"]

        st.radio(
            "Navigation",
            WORKSPACE_PAGES,
            label_visibility="collapsed",
            key="sidebar_workspace_radio",
            on_change=_on_sidebar_radio_change
        )

        st.divider()

        # Status info
        packet_count = len(st.session_state.get("packets", []))
        capture_status = st.session_state.get("capture_running", False)

        st.markdown("<span style='font-family: JetBrains Mono; font-size: 0.72rem; color: #718096; text-transform: uppercase;'>BUFFER STATUS</span>", unsafe_allow_html=True)
        st.markdown(f"<span style='font-family: JetBrains Mono; font-size: 1.15rem; font-weight: 700; color: #263238;'>{packet_count:,} <span style='font-size: 0.8rem; color: #718096;'>PKTS</span></span>", unsafe_allow_html=True)

        status_class = "badge-active" if capture_status else "badge-inactive"
        status_text = "● CAPTURING" if capture_status else "○ IDLE"
        st.markdown(
            f'<div style="margin-top: 6px;"><span class="status-badge {status_class}">{status_text}</span></div>',
            unsafe_allow_html=True,
        )

        if st.session_state.get("loaded_file"):
            st.markdown(f"<div style='margin-top: 10px; font-family: JetBrains Mono; font-size: 0.75rem; color: #718096; word-break: break-all;'>SOURCE: <span style='color: #159A91; font-weight: 600;'>{st.session_state.loaded_file}</span></div>", unsafe_allow_html=True)

        st.divider()

        # -------------------------------------------------------------------
        # Dedicated Sample Capture Mode (Demo without admin/Npcap)
        # -------------------------------------------------------------------
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">
                // SAMPLE CAPTURE MODE
            </div>
            <div style="font-size: 0.75rem; color: #718096; margin-bottom: 10px; line-height: 1.4;">
                Explore all forensic features offline with reproducible synthetic benchmarks (no admin privileges or Npcap required).
            </div>
            """,
            unsafe_allow_html=True
        )

        sample_manifest = {
            "Synthetic 7-Protocol Suite (DNS, TCP, UDP, ICMP, IPv6)": "sample_captures/synthetic_protocol_suite.pcap",
            "Baseline Enterprise Traffic (21 Packets)": "sample_captures/sample_traffic.pcap",
            "Impaired Network Experiment (Delay, Loss, Retrans)": "sample_captures/sample_impaired.pcap"
        }

        selected_sample_label = st.selectbox(
            "Select Sample Capture",
            options=list(sample_manifest.keys()),
            key="sidebar_sample_selector",
            label_visibility="collapsed"
        )

        if st.button("⚡ Load Sample Capture", key="sidebar_load_sample_btn", use_container_width=True, type="primary"):
            target_file = sample_manifest[selected_sample_label]
            raw_smp, parsed_smp, err_smp = load_pcap(target_file)
            if not err_smp:
                st.session_state["packets"] = raw_smp
                st.session_state["raw_packets"] = raw_smp
                st.session_state["parsed_packets"] = parsed_smp
                st.session_state["loaded_file"] = f"{os.path.basename(target_file)} [SYNTHETIC BENCHMARK]"
                st.session_state["selected_packet_idx"] = 0
                st.session_state["is_synthetic"] = True
                st.success(f"Loaded {len(raw_smp)} packets from {os.path.basename(target_file)}")
                st.rerun()
            else:
                st.error(f"Error loading sample: {err_smp}")


# ---------------------------------------------------------------------------
# Page rendering
# ---------------------------------------------------------------------------
def render_page(page_name: str):
    """
    Render the selected workspace.
    Supports 7 primary workspace names and legacy aliases seamlessly.
    """
    if page_name in ["📊 Overview", "Overview", "📊 Dashboard", "Dashboard", "🏠 Overview"]:
        render_overview_page()
    elif page_name in ["📡 Live Capture", "Live Capture"]:
        render_live_capture_page()
    elif page_name in ["🔍 Packet Inspector", "Packet Inspector"]:
        render_packet_inspector_page()
    elif page_name in ["🔍 Packet Analysis", "Packet Analysis"]:
        render_packet_analysis_page()
    elif page_name in ["🔗 TCP Connections", "TCP Connections", "🔗 Connections", "Connections", "🔗 Connection Explorer"]:
        render_connection_explorer_page()
    elif page_name in ["📈 Network Analytics", "Network Analytics", "📡 Network Monitor", "Network Monitor", "📊 Network Analytics"]:
        render_network_monitor_page()
    elif page_name in ["⚖️ Capture Comparison", "Capture Comparison"]:
        render_capture_comparison_page()
    elif page_name in ["🎓 Guided Labs", "Guided Labs", "Guided Labs / Learning", "🎓 Guided Help", "Guided Help", "🎓 Guided Lab"]:
        render_guided_lab_page()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    """Main application entry point."""
    init_session_state()

    # Drain live capture engine globally so packets update regardless of active page
    if "capture_engine" in st.session_state:
        engine = st.session_state["capture_engine"]
        if engine.is_capturing:
            new_pkts = engine.get_new_packets()
            if new_pkts:
                raw_packets = st.session_state.get("packets", [])
                parsed_packets = st.session_state.get("parsed_packets", [])
                start_num = len(parsed_packets) + 1
                for i, pkt in enumerate(new_pkts):
                    raw_packets.append(pkt)
                    parsed_packets.append(parse_packet(pkt, packet_num=start_num + i))
                st.session_state["packets"] = raw_packets
                st.session_state["parsed_packets"] = parsed_packets

    apply_custom_css()
    render_sidebar()
    current_page = st.session_state.get("current_page", "📊 Overview")
    render_top_navigation(current_page)
    render_page(current_page)


if __name__ == "__main__":
    main()

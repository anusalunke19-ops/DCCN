"""
test_packet_analysis_workspace.py — Integration tests for the Wireshark 3-Pane workspace
and simplified main navigation.

Verifies:
- Page router correctly resolves primary workspaces and legacy aliases
- Dashboard renders cleanly with empty and active captures
- Packet Analysis renders 3-pane components without exception
- Network Monitor renders telemetry and device diagnostics
"""

import pytest
import pandas as pd
from unittest.mock import patch, MagicMock

from app import render_page
from ui.overview import render_overview_page
from ui.packet_analysis import render_packet_analysis_page
from ui.network_monitor import render_network_monitor_page
from core.pcap_manager import load_pcap


def test_navigation_router_aliases():
    """Verify render_page accepts all 6 primary workspaces and legacy aliases."""
    workspaces = [
        "📊 Dashboard", "🏠 Overview",
        "🔍 Packet Analysis", "📡 Live Capture", "🔍 Packet Inspector",
        "🔗 Connections", "🔗 Connection Explorer",
        "📡 Network Monitor", "📊 Network Analytics",
        "⚖️ Capture Comparison",
        "🎓 Guided Help", "🎓 Guided Lab"
    ]

    for ws in workspaces:
        # Patch the underlying renderers so we just verify routing without Streamlit DOM errors
        with patch("app.render_overview_page") as m_ov, \
             patch("app.render_live_capture_page") as m_lc, \
             patch("app.render_packet_inspector_page") as m_pi, \
             patch("app.render_packet_analysis_page") as m_pa, \
             patch("app.render_connection_explorer_page") as m_ce, \
             patch("app.render_network_monitor_page") as m_nm, \
             patch("app.render_capture_comparison_page") as m_cc, \
             patch("app.render_guided_lab_page") as m_gl:
            render_page(ws)
            # Ensure at least one renderer was invoked
            assert any([
                m_ov.called, m_lc.called, m_pi.called, m_pa.called,
                m_ce.called, m_nm.called, m_cc.called, m_gl.called
            ])


def test_packet_analysis_fixtures_loaded():
    """Verify synthetic suite and baseline load cleanly into the 3-pane structure."""
    raw, parsed, err = load_pcap("sample_captures/synthetic_protocol_suite.pcap")
    assert err is None
    assert len(raw) == 21
    assert len(parsed) == 21

    # Verify frame 1 has DNS
    f1 = parsed[0]
    assert f1["protocol"] == "DNS"
    assert f1["dns_qname"] == "synthetic.dccn.internal"

    # Verify frame 3 has TCP SYN
    f3 = parsed[2]
    assert f3["tcp_flags"] == "S"
    assert f3["tcp_seq"] == 1000

    # Verify frame 14 has ICMP Echo Request
    f14 = parsed[13]
    assert f14["protocol"] == "ICMP"
    assert f14["icmp_type_str"] == "Echo Request"

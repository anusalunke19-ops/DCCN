"""
guided_lab.py — Guided Lab & Interactive Learning Mode.

Inspired by Cisco Packet Tracer's educational approach, this module provides:
- Welcoming landing page with visual workflow and structured learning paths
- 8 Step-by-step interactive walkthrough tutorials covering every major feature
- 5 Practical hands-on experiments with copyable PowerShell commands & 1-click PCAP loading
- Interactive knowledge checks (quizzes with immediate feedback & detailed explanations)
- Searchable networking glossary with practical application references
- Local progress tracking and completion metrics persisted to disk
"""

import streamlit as st
import pandas as pd
import os
from typing import Dict, Any, List

from core.lab_manager import (
    TUTORIALS, EXPERIMENTS, GLOSSARY_ITEMS,
    load_progress, save_progress, mark_tutorial_completed,
    mark_experiment_completed, reset_all_progress, calculate_progress_stats
)
from core.pcap_manager import load_pcap


def _navigate(page: str):
    """Safely switch workspace and ensure all sidebar and top-nav state stays synchronized."""
    st.session_state["current_page"] = page
    st.rerun()


def render_contextual_help(context_key: str):
    """
    Render persistent contextual help banner on major dashboard pages.
    Links directly to Guided Lab tutorials.
    """
    HELP_TOPICS = {
        "overview": {
            "title": "💡 Need Help Understanding this Dashboard?",
            "summary": "This overview summarizes the entire traffic buffer. Each metric and chart tells a specific story about your network activity.",
            "faq": [
                ("What does 'Total Observed' mean?", "The physical sum of wire bytes across all frames in memory. Useful for calculating network throughput and bandwidth utilization."),
                ("What is an Endpoint?", "A unique IP address participating in the conversation. High unique endpoint counts often reflect broad web browsing or port scanning."),
                ("What does the Protocol Donut chart indicate?", "The breakdown of Layer 3–7 protocols observed. Dominant protocols reveal the primary function of the network traffic (e.g. HTTPS for web, DNS for name lookups).")
            ],
            "tutorial_id": "tut_1",
            "tutorial_name": "Tutorial 1: Getting Started"
        },
        "live_capture": {
            "title": "💡 Need Help with Packet Capturing?",
            "summary": "Sniffing captures real-time packets from your hardware adapter, while offline analysis inspects pre-recorded PCAP files.",
            "faq": [
                ("What am I looking at in the table?", "Each row is a single frame captured on the wire with timestamp, source/destination sockets, protocol, and a forensic summary."),
                ("Why do I see 'Live Sniffing Restricted'?", "Windows requires the Npcap driver in WinPcap-compatible mode for promiscuous sniffing. You can still load and analyze offline PCAP files without it."),
                ("What is a BPF Filter?", "Berkeley Packet Filter syntax (e.g. 'tcp port 80' or 'udp port 53') applied at the driver level to capture only traffic of interest.")
            ],
            "tutorial_id": "tut_3",
            "tutorial_name": "Tutorial 3: Live Packet Capture & Ingestion"
        },
        "packet_inspector": {
            "title": "💡 Need Help Inspecting Packet Headers?",
            "summary": "Packet inspection displays the vertical encapsulation stack from Layer 7 (Application) down to Layer 2 (Ethernet).",
            "faq": [
                ("Why does TTL exist?", "Time-To-Live (TTL) is an 8-bit counter decremented by 1 at every router hop. If it reaches 0, the packet is discarded, preventing infinite routing loops."),
                ("How do I read the Hexadecimal Dump?", "The left column shows byte offsets in hex, the middle shows 16 raw octets, and the right shows printable ASCII characters with unprintable bytes as dots ('.')."),
                ("What is Protocol Encapsulation?", "The process where each protocol layer wraps the higher-layer payload inside its own header, like digital Russian nesting dolls.")
            ],
            "tutorial_id": "tut_4",
            "tutorial_name": "Tutorial 4: Deep Packet Inspection"
        },
        "connection_explorer": {
            "title": "💡 Need Help with TCP Connections & Handshakes?",
            "summary": "The Connection Explorer reconstructs stateful bidirectional sessions across 5-tuple sockets.",
            "faq": [
                ("What does SYN mean?", "Synchronize flag. Sent by the client in Step 1 of the 3-way handshake to establish a new connection and synchronize sequence numbers."),
                ("What is iRTT?", "Initial Round Trip Time: the latency between client SYN and server SYN-ACK. Reflects physical propagation delay between the two hosts."),
                ("What is a TCP Reset (RST)?", "An abrupt termination of a connection, usually sent when connecting to a closed port or when a firewall rejects traffic.")
            ],
            "tutorial_id": "tut_6",
            "tutorial_name": "Tutorial 6: TCP Connection Reconstruction"
        },
        "analytics": {
            "title": "💡 Need Help with Traffic Telemetry?",
            "summary": "Network analytics provides high-level aggregation of ports, IP endpoints, and potential anomalies.",
            "faq": [
                ("What are Service Ports?", "16-bit numbers (e.g. 443 for HTTPS, 80 for HTTP, 53 for DNS) used by transport protocols to direct traffic to the correct application."),
                ("What are Potential Retransmissions?", "Repeated segments observed with identical sequence numbers, typically indicating packet loss or network congestion."),
                ("What do DNS Query statistics show?", "The volume of domain names requested by clients and resolved by DNS servers.")
            ],
            "tutorial_id": "tut_7",
            "tutorial_name": "Tutorial 7: Network Analytics & Traffic Telemetry"
        },
        "comparison": {
            "title": "💡 Need Help with Capture Comparison?",
            "summary": "Differential analysis compares two captures (e.g. healthy baseline vs impaired network) to pinpoint performance bottlenecks.",
            "faq": [
                ("What is a Baseline Capture?", "A capture recorded during normal, healthy network conditions to serve as a benchmark."),
                ("What causes Retransmission Deltas?", "High packet loss or buffer congestion in capture B causes the sender to retransmit segments repeatedly."),
                ("How do I interpret RTT Latency Shifts?", "An elevation in iRTT in capture B indicates increased propagation delay, congested router queues, or slower transmission paths.")
            ],
            "tutorial_id": "tut_8",
            "tutorial_name": "Tutorial 8: Differential Capture Comparison"
        }
    }

    info = HELP_TOPICS.get(context_key)
    if not info:
        return

    with st.expander(info["title"], expanded=False):
        st.markdown(f"<span style='font-size: 0.85rem; color: #718096;'>{info['summary']}</span>", unsafe_allow_html=True)
        st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
        for q, a in info["faq"]:
            st.markdown(f"**Q: {q}**\n\n<span style='color: #159A91;'>{a}</span>", unsafe_allow_html=True)
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        if st.button(f"📖 Open {info['tutorial_name']} in Guided Lab", key=f"help_link_{context_key}", use_container_width=True):
            st.session_state["guided_lab_active_tutorial"] = info["tutorial_id"]
            st.session_state["guided_lab_tab_idx"] = 1  # Switch to Tutorials tab
            _navigate("🎓 Guided Labs")


def render_guided_lab_page():
    """Main renderer for Guided Lab Interactive Learning Mode."""

    # Top Header
    st.markdown(
        """
        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #E5E9EF; padding-bottom: 12px; margin-bottom: 16px;">
            <div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 2px;">
                    // INTERACTIVE LEARNING ENVIRONMENT // CISCO PACKET TRACER INSPIRED
                </div>
                <div style="font-size: 1.45rem; font-weight: 700; color: #263238; letter-spacing: -0.02em;">
                    🎓 Guided Lab: Interactive Networking Academy
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <span class="soc-badge soc-badge-teal">HANDS-ON LABS</span>
                <span class="soc-badge soc-badge-green">PROGRESS TRACKED</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Calculate current progress
    stats = calculate_progress_stats()

    # Progress Summary Strip
    st.markdown(
        f"""
        <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 8px; padding: 14px 18px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; margin-bottom: 8px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; font-weight: 700; color: #263238;">
                    YOUR OVERALL LEARNING JOURNEY: <span style="color: #159A91;">{stats['overall_percentage']}% COMPLETE</span>
                </div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; color: #718096;">
                    Tutorials: <b style="color: #059669;">{stats['completed_tutorials_count']}/{stats['total_tutorials']}</b> &nbsp;|&nbsp; 
                    Experiments: <b style="color: #D97706;">{stats['completed_experiments_count']}/{stats['total_experiments']}</b>
                </div>
            </div>
            <div style="background: #E2E8F0; border-radius: 4px; height: 8px; width: 100%; overflow: hidden;">
                <div style="background: linear-gradient(90deg, #159A91, #059669); height: 100%; width: {stats['overall_percentage']}%; transition: width 0.3s ease;"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Main Navigation Tabs
    tab_overview, tab_tutorials, tab_experiments, tab_glossary, tab_progress = st.tabs([
        "🧭 LEARNING PATHS & OVERVIEW",
        "📖 INTERACTIVE TUTORIALS (8)",
        "🔬 HANDS-ON EXPERIMENTS (5)",
        "📚 NETWORKING GLOSSARY (25)",
        "🏆 MY PROGRESS & BADGES"
    ])

    # -----------------------------------------------------------------------
    # TAB 1: Learning Paths & Overview
    # -----------------------------------------------------------------------
    with tab_overview:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 8px; padding: 22px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
                <div style="font-size: 1.15rem; font-weight: 700; color: #263238; margin-bottom: 8px;">
                    Welcome to the Guided Lab!
                </div>
                <div style="font-size: 0.88rem; color: #718096; line-height: 1.6; margin-bottom: 16px;">
                    Whether you are an aspiring network engineer, cybersecurity student, or curious developer, 
                    this Guided Lab breaks down complex computer networking concepts into clear, step-by-step visual lessons.
                    No prior networking experience is required.
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-top: 14px;">
                    <div style="background: #F8FAFC; border: 1px solid #E5E9EF; border-left: 3px solid #159A91; padding: 12px; border-radius: 4px;">
                        <b style="color: #159A91; font-size: 0.85rem;">1. What is NetForensics?</b>
                        <p style="font-size: 0.78rem; color: #718096; margin-top: 4px; margin-bottom: 0;">
                            A professional, Wireshark-inspired forensic packet analyzer running natively on your workstation.
                        </p>
                    </div>
                    <div style="background: #F8FAFC; border: 1px solid #E5E9EF; border-left: 3px solid #059669; padding: 12px; border-radius: 4px;">
                        <b style="color: #059669; font-size: 0.85rem;">2. What is Packet Analysis?</b>
                        <p style="font-size: 0.78rem; color: #718096; margin-top: 4px; margin-bottom: 0;">
                            Examining real digital envelopes on the wire to understand how devices converse, route, and deliver data.
                        </p>
                    </div>
                    <div style="background: #F8FAFC; border: 1px solid #E5E9EF; border-left: 3px solid #D97706; padding: 12px; border-radius: 4px;">
                        <b style="color: #D97706; font-size: 0.85rem;">3. What will you learn?</b>
                        <p style="font-size: 0.78rem; color: #718096; margin-top: 4px; margin-bottom: 0;">
                            IP routing, MAC addressing, TCP 3-way handshakes, DNS name resolution, ICMP ping, and QoS analysis.
                        </p>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Visual Workflow Architecture
        st.markdown("<span class='soc-tag'>// SYSTEM WORKFLOW ARCHITECTURE</span>", unsafe_allow_html=True)
        st.markdown(
            """
            <div style="background: #F8FAFC; border: 1px dashed #CBD5E1; border-radius: 8px; padding: 18px; margin-bottom: 24px; text-align: center;">
                <div style="display: flex; justify-content: space-around; align-items: center; flex-wrap: wrap; gap: 10px;">
                    <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 2px solid #159A91; border-radius: 6px; padding: 10px 16px; min-width: 140px; box-shadow: 0 1px 2px rgba(0,0,0,0.03);">
                        <div style="font-size: 1.3rem;">📡</div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 700; color: #263238;">1. INGESTION</div>
                        <div style="font-size: 0.7rem; color: #718096;">Sniff NIC or Read PCAP</div>
                    </div>
                    <div style="color: #159A91; font-size: 1.2rem;">➔</div>
                    <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 2px solid #059669; border-radius: 6px; padding: 10px 16px; min-width: 140px; box-shadow: 0 1px 2px rgba(0,0,0,0.03);">
                        <div style="font-size: 1.3rem;">🔍</div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 700; color: #263238;">2. DISSECTION</div>
                        <div style="font-size: 0.7rem; color: #718096;">Layer Encapsulation Stack</div>
                    </div>
                    <div style="color: #059669; font-size: 1.2rem;">➔</div>
                    <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 2px solid #D97706; border-radius: 6px; padding: 10px 16px; min-width: 140px; box-shadow: 0 1px 2px rgba(0,0,0,0.03);">
                        <div style="font-size: 1.3rem;">🔗</div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 700; color: #263238;">3. RECONSTRUCTION</div>
                        <div style="font-size: 0.7rem; color: #718096;">TCP 3-Way Handshake & iRTT</div>
                    </div>
                    <div style="color: #D97706; font-size: 1.2rem;">➔</div>
                    <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 2px solid #8B83C8; border-radius: 6px; padding: 10px 16px; min-width: 140px; box-shadow: 0 1px 2px rgba(0,0,0,0.03);">
                        <div style="font-size: 1.3rem;">📊</div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 700; color: #263238;">4. TELEMETRY</div>
                        <div style="font-size: 0.7rem; color: #718096;">QoS & Forensic Analytics</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Learning Paths
        st.markdown("<span class='soc-tag'>// STRUCTURED LEARNING PATHS</span>", unsafe_allow_html=True)
        lp1, lp2, lp3 = st.columns(3)

        with lp1:
            st.markdown(
                """
                <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 3px solid #059669; border-radius: 6px; padding: 16px; min-height: 240px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #059669; font-weight: 700;">🟢 BEGINNER TRACK</div>
                    <div style="font-size: 1rem; font-weight: 700; color: #263238; margin: 4px 0 8px 0;">Network Fundamentals</div>
                    <div style="font-size: 0.8rem; color: #718096; line-height: 1.5; margin-bottom: 12px;">
                        Start here if you are new to networking. Learn what packets are, identify IP and MAC addresses, and capture your first live traffic.
                    </div>
                    <ul style="font-size: 0.78rem; color: #263238; padding-left: 18px; margin: 0 0 14px 0;">
                        <li>Tutorial 1: Getting Started</li>
                        <li>Tutorial 2: Device & Interface Monitoring</li>
                        <li>Tutorial 3: Live Packet Capture</li>
                        <li>Experiment A: DNS Investigation</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("Start Beginner Track", key="btn_start_beginner", type="primary", use_container_width=True):
                st.session_state["guided_lab_active_tutorial"] = "tut_1"
                st.rerun()

        with lp2:
            st.markdown(
                """
                <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 3px solid #159A91; border-radius: 6px; padding: 16px; min-height: 240px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; font-weight: 700;">🟡 INTERMEDIATE TRACK</div>
                    <div style="font-size: 1rem; font-weight: 700; color: #263238; margin: 4px 0 8px 0;">Packet Dissection & Journey</div>
                    <div style="font-size: 0.8rem; color: #718096; line-height: 1.5; margin-bottom: 12px;">
                        Explore encapsulation and dissect headers layer-by-layer. Master hexadecimal decoding and compare TCP vs UDP.
                    </div>
                    <ul style="font-size: 0.78rem; color: #263238; padding-left: 18px; margin: 0 0 14px 0;">
                        <li>Tutorial 4: Packet Inspection</li>
                        <li>Tutorial 5: Visual Packet Journey</li>
                        <li>Tutorial 7: Network Analytics</li>
                        <li>Experiment C: ICMP Ping & TTL</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("Start Intermediate Track", key="btn_start_intermediate", use_container_width=True):
                st.session_state["guided_lab_active_tutorial"] = "tut_4"
                st.rerun()

        with lp3:
            st.markdown(
                """
                <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-top: 3px solid #D97706; border-radius: 6px; padding: 16px; min-height: 240px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #D97706; font-weight: 700;">🔴 ADVANCED TRACK</div>
                    <div style="font-size: 1rem; font-weight: 700; color: #263238; margin: 4px 0 8px 0;">TCP Flow & QoS Forensics</div>
                    <div style="font-size: 0.8rem; color: #718096; line-height: 1.5; margin-bottom: 12px;">
                        For network engineers and security analysts. Reconstruct stateful TCP streams, calculate iRTT, and analyze network impairment.
                    </div>
                    <ul style="font-size: 0.78rem; color: #263238; padding-left: 18px; margin: 0 0 14px 0;">
                        <li>Tutorial 6: TCP Handshake Reconstruction</li>
                        <li>Tutorial 8: Differential Capture Comparison</li>
                        <li>Experiment B: TCP Three-Way Handshake</li>
                        <li>Experiment D: TCP vs UDP Comparison</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("Start Advanced Track", key="btn_start_advanced", use_container_width=True):
                st.session_state["guided_lab_active_tutorial"] = "tut_6"
                st.rerun()

    # -----------------------------------------------------------------------
    # TAB 2: Interactive Tutorials (8 Modules)
    # -----------------------------------------------------------------------
    with tab_tutorials:
        tut_options = {f"{t['num']}. {t['title']} [{t['level']}]": t["id"] for t in TUTORIALS}
        default_tut_id = st.session_state.get("guided_lab_active_tutorial", "tut_1")

        # Determine index
        id_list = list(tut_options.values())
        sel_idx = id_list.index(default_tut_id) if default_tut_id in id_list else 0

        tcol1, tcol2 = st.columns([3, 1.2])
        with tcol1:
            selected_tut_label = st.selectbox(
                "Select Guided Tutorial Module",
                options=list(tut_options.keys()),
                index=sel_idx,
                key="tut_module_selector"
            )
            active_tut_id = tut_options[selected_tut_label]
            st.session_state["guided_lab_active_tutorial"] = active_tut_id

        active_tut = next(t for t in TUTORIALS if t["id"] == active_tut_id)
        is_completed = active_tut_id in stats["completed_tutorials"]

        with tcol2:
            status_html = '<span class="status-badge badge-active">✓ COMPLETED</span>' if is_completed else '<span class="status-badge badge-inactive">○ IN PROGRESS</span>'
            st.markdown(
                f"""
                <div style="padding-top: 26px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;">
                    STATUS: {status_html}
                </div>
                """,
                unsafe_allow_html=True
            )

        # Tutorial Header Card
        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-left: 4px solid #159A91; border-radius: 6px; padding: 14px 18px; margin: 12px 0 18px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                    <div style="font-size: 1.15rem; font-weight: 700; color: #263238;">
                        {active_tut['icon']} {active_tut['title']}
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <span class="soc-badge soc-badge-teal">{active_tut['level'].upper()}</span>
                        <span class="soc-badge soc-badge-amber">⏱ {active_tut['time']}</span>
                    </div>
                </div>
                <div style="font-size: 0.85rem; color: #718096; margin-top: 6px;">
                    {active_tut['summary']}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Tutorial Steps
        for step in active_tut["steps"]:
            with st.container(border=True):
                st.markdown(
                    f"<div style=\"font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; font-weight: 700; color: #159A91; margin-bottom: 8px;\">{step['title']}</div>",
                    unsafe_allow_html=True
                )
                st.markdown(step["content"].strip())
                if "diagram" in step:
                    st.code(step["diagram"].strip(), language="text")

        # Knowledge Check Quiz
        st.divider()
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 10px;">
                <span class="soc-tag">// KNOWLEDGE CHECK</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; font-weight: 700; color: #263238;">Test Your Understanding</span>
            </div>
            """,
            unsafe_allow_html=True
        )

        quiz_key = f"quiz_{active_tut_id}"
        user_answers = {}
        for q_idx, q in enumerate(active_tut["quiz"]):
            st.markdown(f"**Q{q_idx+1}: {q['question']}**")
            ans = st.radio(
                f"Options for Q{q_idx+1}",
                options=q["options"],
                key=f"{quiz_key}_q_{q_idx}",
                label_visibility="collapsed"
            )
            user_answers[q_idx] = q["options"].index(ans)

        q_btn1, q_btn2 = st.columns([1.5, 2])
        with q_btn1:
            check_quiz = st.button("📝 Submit Knowledge Check", key=f"btn_check_{active_tut_id}", type="primary", use_container_width=True)

        if check_quiz or st.session_state.get(f"{quiz_key}_submitted"):
            st.session_state[f"{quiz_key}_submitted"] = True
            correct_count = 0
            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            for q_idx, q in enumerate(active_tut["quiz"]):
                user_choice = user_answers.get(q_idx)
                is_correct = (user_choice == q["answer_idx"])
                if is_correct:
                    correct_count += 1
                    st.success(f"✅ **Question {q_idx+1}: Correct!**\n\n{q['explanation']}")
                else:
                    st.error(f"❌ **Question {q_idx+1}: Not quite.** Correct answer: *{q['options'][q['answer_idx']]}*\n\n{q['explanation']}")

            with q_btn2:
                mark_tutorial_completed(active_tut_id, quiz_score=correct_count)
                st.success(f"🎉 Tutorial Marked Completed! Score: {correct_count}/{len(active_tut['quiz'])}")

    # -----------------------------------------------------------------------
    # TAB 3: Hands-on Practical Experiments (5 Activities)
    # -----------------------------------------------------------------------
    with tab_experiments:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 8px; padding: 18px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
                <div style="font-size: 1.1rem; font-weight: 700; color: #263238; margin-bottom: 6px;">
                    Practical Network Forensics Lab Activities
                </div>
                <div style="font-size: 0.85rem; color: #718096; line-height: 1.5;">
                    Follow practical instructions using your computer's command terminal, or load pre-recorded verified learning fixtures with 1 click to dissect the resulting wire frames.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        exp_options = {f"Experiment {e['num']}: {e['title']}": e["id"] for e in EXPERIMENTS}
        selected_exp_label = st.selectbox(
            "Select Practical Experiment",
            options=list(exp_options.keys()),
            key="exp_selector"
        )
        active_exp_id = exp_options[selected_exp_label]
        active_exp = next(e for e in EXPERIMENTS if e["id"] == active_exp_id)
        is_exp_done = active_exp_id in stats["completed_experiments"]

        # Experiment Banner
        exp_status_badge = '<span class="status-badge badge-active">✓ LAB COMPLETE</span>' if is_exp_done else '<span class="status-badge badge-inactive">○ PENDING</span>'
        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-left: 4px solid #059669; border-radius: 6px; padding: 14px 18px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                    <div style="font-size: 1.1rem; font-weight: 700; color: #263238;">
                        {active_exp['icon']} Experiment {active_exp['num']}: {active_exp['title']}
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <span class="soc-badge soc-badge-green">{active_exp['difficulty'].upper()}</span>
                        <span class="soc-badge soc-badge-amber">⏱ {active_exp['time']}</span>
                        {exp_status_badge}
                    </div>
                </div>
                <div style="font-size: 0.85rem; color: #718096; margin-top: 6px;">
                    <b>Objective:</b> {active_exp['objective']}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Steps in this experiment
        for st_idx, s in enumerate(active_exp["steps"]):
            st.markdown(
                f"""
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; font-weight: 700; color: #159A91; margin: 14px 0 6px 0;">
                    STEP {s['step_num']}: {s['title']}
                </div>
                <div style="font-size: 0.84rem; color: #263238; margin-bottom: 8px;">
                    {s['instruction']}
                </div>
                """,
                unsafe_allow_html=True
            )

            if "command" in s:
                st.code(s["command"], language="powershell")

            if "action_button" in s:
                if st.button(s["action_button"], key=f"btn_act_{active_exp_id}_{st_idx}", type="primary"):
                    raw, parsed, err = load_pcap(active_exp["sample_file"])
                    if not err:
                        st.session_state["packets"] = raw
                        st.session_state["raw_packets"] = raw
                        st.session_state["parsed_packets"] = parsed
                        st.session_state["loaded_file"] = f"{os.path.basename(active_exp['sample_file'])} [LAB FIXTURE]"
                        st.session_state["selected_packet_idx"] = 0
                        st.session_state["is_synthetic"] = True
                        st.success(f"Loaded {len(raw)} packets! You can now inspect them in Packet Analysis or Connections.")
                    else:
                        st.error(f"Error loading fixture: {err}")

            if "explanation" in s:
                st.markdown(
                    f"""
                    <div style="background: #FFFBEB; border: 1px solid #FDE68A; border-left: 2px solid #D97706; padding: 10px 14px; border-radius: 4px; font-size: 0.82rem; color: #718096; margin: 8px 0;">
                        💡 <b>Explanation:</b> {s['explanation']}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            if "checklist" in s:
                st.markdown("<div style='font-size: 0.8rem; font-weight: 700; color: #263238; margin-top: 6px;'>Verification Tasks:</div>", unsafe_allow_html=True)
                for item in s["checklist"]:
                    st.checkbox(item, key=f"chk_{active_exp_id}_{item[:20]}")

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        eb1, eb2 = st.columns([1.5, 2])
        with eb1:
            if st.button("✅ Mark Experiment as Completed", key=f"btn_done_{active_exp_id}", type="primary", use_container_width=True):
                mark_experiment_completed(active_exp_id)
                st.success("🎉 Experiment marked as completed! Progress recorded.")
                st.rerun()

    # -----------------------------------------------------------------------
    # TAB 4: Searchable Networking Glossary (25 Terms)
    # -----------------------------------------------------------------------
    with tab_glossary:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 4px;">
                // NETWORKING DICTIONARY // SEARCHABLE KNOWLEDGE REPOSITORY
            </div>
            <div style="font-size: 1.1rem; font-weight: 700; color: #263238; margin-bottom: 12px;">
                Essential Network Forensics & Protocol Glossary
            </div>
            """,
            unsafe_allow_html=True
        )

        gcol1, gcol2 = st.columns([2.5, 1.5])
        with gcol1:
            search_query = st.text_input("Search terms, definitions, or protocols...", placeholder="e.g. TCP, MAC, TTL, Handshake, Latency...", key="glossary_search").strip().lower()

        categories = ["All"] + sorted(list(set(g["category"] for g in GLOSSARY_ITEMS)))
        with gcol2:
            sel_category = st.selectbox("Filter Category", options=categories, key="glossary_cat_select")

        # Filter items
        filtered_glossary = GLOSSARY_ITEMS
        if sel_category != "All":
            filtered_glossary = [g for g in filtered_glossary if g["category"] == sel_category]
        if search_query:
            filtered_glossary = [
                g for g in filtered_glossary
                if search_query in g["term"].lower() or search_query in g["definition"].lower() or search_query in g["app_example"].lower()
            ]

        st.caption(f"Showing {len(filtered_glossary)} matching networking terms")

        for item in filtered_glossary:
            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 6px; padding: 14px 18px; margin-bottom: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 1rem; font-weight: 700; color: #159A91;">
                            {item['term']}
                        </span>
                        <span class="soc-badge soc-badge-teal">{item['category']}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #263238; line-height: 1.5; margin-bottom: 8px;">
                        {item['definition']}
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; color: #0F766E; background: #DDF3ED; border-left: 2px solid #159A91; padding: 6px 10px; border-radius: 2px;">
                        📍 <b>In NetForensics:</b> {item['app_example']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    # -----------------------------------------------------------------------
    # TAB 5: My Progress & Badges
    # -----------------------------------------------------------------------
    with tab_progress:
        st.markdown(
            """
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #159A91; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 4px;">
                // LEARNER TELEMETRY // LOCAL PROGRESS TRACKING
            </div>
            <div style="font-size: 1.1rem; font-weight: 700; color: #263238; margin-bottom: 14px;">
                Your Personal Achievement & Mastery Tracker
            </div>
            """,
            unsafe_allow_html=True
        )

        pcol1, pcol2 = st.columns(2)

        with pcol1:
            st.markdown("<div style='font-family: JetBrains Mono; font-size: 0.82rem; font-weight: 700; color: #263238; margin-bottom: 8px;'>TUTORIAL CHECKLIST</div>", unsafe_allow_html=True)
            for tut in TUTORIALS:
                done = tut["id"] in stats["completed_tutorials"]
                icon = "✅" if done else "⬜"
                color = "#059669" if done else "#718096"
                score = stats["quiz_scores"].get(tut["id"])
                score_str = f" (Quiz Score: {score})" if score is not None else ""
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 4px; padding: 8px 12px; margin-bottom: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: {color};">
                        {icon} <b>Tutorial {tut['num']}:</b> {tut['title']}{score_str}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        with pcol2:
            st.markdown("<div style='font-family: JetBrains Mono; font-size: 0.82rem; font-weight: 700; color: #263238; margin-bottom: 8px;'>EXPERIMENT CHECKLIST</div>", unsafe_allow_html=True)
            for exp in EXPERIMENTS:
                done = exp["id"] in stats["completed_experiments"]
                icon = "✅" if done else "⬜"
                color = "#D97706" if done else "#718096"
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E5E9EF; border-radius: 4px; padding: 8px 12px; margin-bottom: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: {color};">
                        {icon} <b>Experiment {exp['num']}:</b> {exp['title']}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.divider()
        st.markdown("<span class='soc-tag'>// PROGRESS MANAGEMENT</span>", unsafe_allow_html=True)
        st.caption("Your progress is stored locally in `config/user_progress.json` without any cloud transmission. No captured packet payloads are stored.")

        if st.button("🔄 Reset All Learning Progress", key="btn_reset_progress"):
            reset_all_progress()
            st.warning("All tutorial and experiment progress has been reset to 0%.")
            st.rerun()

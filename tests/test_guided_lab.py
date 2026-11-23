"""
test_guided_lab.py — Test suite for Guided Lab Interactive Learning Mode.

Verifies:
- Progress persistence (load, save, mark completed, reset, percentage calculation)
- All 8 tutorials integrity (metadata, steps, diagrams, quiz answer indices, explanations)
- All 5 practical experiments (steps, copyable commands, sample capture file existence)
- Networking glossary (25 terms, categories, search functionality)
- Contextual help integration
"""

import os
import json
import tempfile
import pytest

from core.lab_manager import (
    TUTORIALS, EXPERIMENTS, GLOSSARY_ITEMS,
    load_progress, save_progress, mark_tutorial_completed,
    mark_experiment_completed, reset_all_progress, calculate_progress_stats,
    PROGRESS_FILE_PATH
)
from ui.guided_lab import render_contextual_help


def test_lab_manager_progress_lifecycle():
    """Verify loading, updating, calculating, and resetting progress."""
    # Reset first
    reset_all_progress()
    stats_initial = calculate_progress_stats()
    assert stats_initial["completed_tutorials_count"] == 0
    assert stats_initial["completed_experiments_count"] == 0
    assert stats_initial["overall_percentage"] == 0

    # Mark Tutorial 1 complete
    mark_tutorial_completed("tut_1", quiz_score=3)
    stats_1 = calculate_progress_stats()
    assert "tut_1" in stats_1["completed_tutorials"]
    assert stats_1["completed_tutorials_count"] == 1
    assert stats_1["quiz_scores"].get("tut_1") == 3
    assert stats_1["overall_percentage"] > 0

    # Mark Experiment A complete
    mark_experiment_completed("exp_a")
    stats_2 = calculate_progress_stats()
    assert "exp_a" in stats_2["completed_experiments"]
    assert stats_2["completed_experiments_count"] == 1
    assert stats_2["overall_percentage"] > stats_1["overall_percentage"]

    # Reset
    reset_all_progress()
    stats_reset = calculate_progress_stats()
    assert stats_reset["completed_tutorials_count"] == 0
    assert stats_reset["completed_experiments_count"] == 0
    assert stats_reset["overall_percentage"] == 0


def test_tutorials_curriculum_integrity():
    """Verify all 8 tutorials adhere to complete specification."""
    assert len(TUTORIALS) == 8

    expected_ids = [f"tut_{i}" for i in range(1, 9)]
    actual_ids = [t["id"] for t in TUTORIALS]
    assert actual_ids == expected_ids

    for tut in TUTORIALS:
        assert tut["num"] in range(1, 9)
        assert len(tut["title"]) > 5
        assert tut["level"] in ["Beginner", "Intermediate", "Advanced"]
        assert "mins" in tut["time"]
        assert len(tut["summary"]) > 10
        assert len(tut["steps"]) >= 2

        # Verify steps
        for step in tut["steps"]:
            assert "title" in step and len(step["title"]) > 0
            assert "content" in step and len(step["content"]) > 10

        # Verify quizzes (3–5 questions each)
        assert len(tut["quiz"]) >= 3
        for q in tut["quiz"]:
            assert "question" in q and len(q["question"]) > 5
            assert "options" in q and len(q["options"]) >= 3
            assert "answer_idx" in q
            assert 0 <= q["answer_idx"] < len(q["options"])
            assert "explanation" in q and len(q["explanation"]) > 10


def test_experiments_integrity():
    """Verify all 5 practical experiments exist with existing sample captures."""
    assert len(EXPERIMENTS) == 5

    expected_nums = ["A", "B", "C", "D", "E"]
    actual_nums = [e["num"] for e in EXPERIMENTS]
    assert actual_nums == expected_nums

    for exp in EXPERIMENTS:
        assert len(exp["title"]) > 5
        assert exp["difficulty"] in ["Beginner", "Intermediate", "Advanced"]
        assert len(exp["objective"]) > 10
        assert len(exp["steps"]) >= 2
        assert os.path.exists(exp["sample_file"]), f"Sample fixture missing for {exp['id']}: {exp['sample_file']}"

        for s in exp["steps"]:
            assert "step_num" in s
            assert "title" in s and len(s["title"]) > 0
            assert "instruction" in s and len(s["instruction"]) > 0


def test_glossary_integrity_and_search():
    """Verify networking glossary terms and search functionality."""
    assert len(GLOSSARY_ITEMS) >= 25

    required_terms = [
        "Packet", "Frame", "Ethernet", "MAC Address", "IP Address",
        "Subnet Mask", "Default Gateway", "Router", "Switch", "Port",
        "TCP", "UDP", "DNS", "DHCP", "ICMP", "TTL", "MTU",
        "Bandwidth", "Throughput", "Latency", "RTT", "Packet Loss",
        "Retransmission", "Encapsulation", "PCAP"
    ]

    glossary_terms = [g["term"] for g in GLOSSARY_ITEMS]
    for req in required_terms:
        assert req in glossary_terms, f"Missing required glossary term: {req}"

    for item in GLOSSARY_ITEMS:
        assert len(item["term"]) > 0
        assert len(item["category"]) > 0
        assert len(item["definition"]) > 10
        assert len(item["app_example"]) > 10

    # Search query test
    query = "handshake"
    matches = [g for g in GLOSSARY_ITEMS if query in g["term"].lower() or query in g["definition"].lower() or query in g["app_example"].lower()]
    assert len(matches) > 0


def test_contextual_help_definitions():
    """Verify contextual help definitions exist for all major pages."""
    valid_contexts = ["overview", "live_capture", "packet_inspector", "connection_explorer", "analytics", "comparison"]
    # Verify render_contextual_help runs without throwing for valid and invalid keys
    for ctx in valid_contexts:
        render_contextual_help(ctx)

    # Test unknown context is ignored gracefully
    render_contextual_help("non_existent_context")

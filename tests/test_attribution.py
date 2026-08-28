"""
Unit tests for Bayesian attribution engine and Attack Graph clustering.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.services.email_parser import EmailParser
from app.services.bayesian_attribution import BayesianAttributionEngine
from app.services.attack_graph import AttackGraphBuilder


def test_bayesian_attribution_signals():
    engine = BayesianAttributionEngine()
    parser = EmailParser()

    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "phishing.eml")
    with open(sample_path, "r", encoding="utf-8") as f:
        metadata = parser.parse(f.read())

    result = engine.attribute(metadata)

    assert "primary_region" in result
    assert result["confidence"] > 0.0
    assert result["tier_code"] in ["A", "B", "C"]
    assert result["vpn_detected"] is True  # 185.220 is VPN prefix
    assert "coordinates" in result


def test_attack_graph_campaign_clustering():
    graph = AttackGraphBuilder()

    email_1 = {
        "from": "badactor1@sec-update-portal.xyz",
        "subject": "Attack 1",
        "date": "Sun, 24 Aug 2026 02:00:00 +0000",
        "received_chain": [{"ip": "104.244.76.13"}],
        "message_id": "<1@sec-update-portal.xyz>"
    }
    email_2 = {
        "from": "badactor2@sec-update-portal.xyz",
        "subject": "Attack 2",
        "date": "Sun, 24 Aug 2026 02:30:00 +0000",
        "received_chain": [{"ip": "104.244.76.13"}],
        "message_id": "<2@sec-update-portal.xyz>"
    }

    graph.add_email("eml_1", email_1, {"primary_region": "Europe", "confidence": 75.0})
    graph.add_email("eml_2", email_2, {"primary_region": "Europe", "confidence": 75.0})

    campaigns = graph.find_campaigns()
    assert len(campaigns) == 1
    assert campaigns[0]["size"] == 2
    assert "sec-update-portal.xyz" in campaigns[0]["shared_indicators"].get("domain", [])

    vis_data = graph.get_visualization_data()
    assert len(vis_data["nodes"]) >= 3
    assert len(vis_data["edges"]) >= 2

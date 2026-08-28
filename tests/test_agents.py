"""
Unit tests for multi-agent detection, risk scoring, and self-healing.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.services.email_parser import EmailParser
from app.services.digital_twin_builder import DigitalTwinBuilder
from app.services.multi_agent import MultiAgentOrchestrator
from app.services.self_healing import SelfHealingEngine
from app.agents.risk_agent import RiskScoringAgent


def test_risk_scoring_formula():
    risk_agent = RiskScoringAgent()
    detection_res = {"risk_score": 80}
    anomaly_score = 0.5  # 0.5 * 100 = 50

    # 80 * 0.6 = 48, 50 * 0.4 = 20 -> 68
    scored = risk_agent.score(detection_res, anomaly_score)
    assert scored["risk_score"] == 68.0
    assert scored["severity"] == "HIGH"
    assert scored["recommended_action"] == "ALERT"


def test_multi_agent_pipeline_quarantines_phishing():
    parser = EmailParser()
    twin = DigitalTwinBuilder("test_user")
    orchestrator = MultiAgentOrchestrator()

    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "phishing.eml")
    with open(sample_path, "r", encoding="utf-8") as f:
        metadata = parser.parse(f.read())

    anomaly_score = twin.get_anomaly_score(metadata)
    res = orchestrator.analyze(metadata, anomaly_score)

    assert res["risk"]["risk_score"] >= 40.0
    assert res["final_decision"] in ["QUARANTINE", "ALERT"]
    assert len(res["explanation"]) > 20
    assert "adversarial_feedback" in res


def test_self_healing_triggers_policy_update():
    healing = SelfHealingEngine("test_user")
    sample_detection = {
        "risk": {"risk_score": 90.0},
        "anomaly_score": 0.85,
        "adversarial_feedback": {
            "weaknesses_found": ["Timezone manipulation bypass vector", "Domain spoofing vulnerability"]
        }
    }
    sample_email = {
        "from": "badactor@malicious-phish.xyz",
        "x_originating_ip": "185.220.101.5"
    }

    result = healing.heal(sample_detection, sample_email, anomaly_score=0.85)

    assert result["healing_applied"] is True
    assert len(result["updates"]) >= 2
    assert "malicious-phish.xyz" in result["new_policies"]["blocked_domains"]

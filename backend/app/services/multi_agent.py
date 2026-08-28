"""
Multi-Agent Orchestrator — Coordinates all 4 agents in a pipeline.
Based on MultiPhishGuard's cooperative architecture.
"""

from typing import Dict, Any, Optional
import sys
import os

from ..agents.detection_agent import DetectionAgent
from ..agents.risk_agent import RiskScoringAgent
from ..agents.explanation_agent import ExplanationAgent
from ..agents.adversarial_agent import AdversarialAgent


class MultiAgentOrchestrator:
    """Orchestrates detection, risk scoring, user explanation, and adversarial evaluation."""

    AGENT_TYPES = ["detection", "risk_scoring", "explanation", "adversarial"]

    def __init__(self):
        self.detection = DetectionAgent()
        self.risk = RiskScoringAgent()
        self.explanation = ExplanationAgent()
        self.adversarial = AdversarialAgent()

    def analyze(
        self,
        email_data: Dict[str, Any],
        anomaly_score: float,
        attribution: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run full multi-agent analysis pipeline:
        Stage 1: Detection Agent (forensic markers + auth headers)
        Stage 2: Risk Scoring Agent (deterministic fusion: 0.6*detection + 0.4*anomaly)
        Stage 3: Explanation Agent (human-readable explanation)
        Stage 4: Adversarial Agent (red-team evasion & weakness feedback)
        """
        # Stage 1: Detection
        detection_result = self.detection.analyze(email_data)

        # Stage 2: Risk Scoring
        risk_result = self.risk.score(detection_result, anomaly_score)

        # Stage 3: Explanation
        explanation = self.explanation.explain(risk_result, email_data, attribution)

        # Stage 4: Adversarial Red-Team Challenge
        adversarial_feedback = self.adversarial.challenge(detection_result, email_data)

        return {
            "detection": detection_result,
            "risk": risk_result,
            "explanation": explanation,
            "adversarial_feedback": adversarial_feedback,
            "final_decision": risk_result.get("recommended_action", "REVIEW"),
            "agents_used": self.AGENT_TYPES
        }

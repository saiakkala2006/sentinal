"""
Risk Scoring Agent — Calculates overall phishing risk and recommends action.
Deterministic fusion: 0.6 * detection_score + 0.4 * (anomaly_score * 100).
"""

from typing import Dict, Any

try:
    from crewai import Agent, Task, Crew
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False


class RiskScoringAgent:
    """Calculates composite phishing risk and determines mitigation posture."""

    def score(self, detection_result: Dict[str, Any], anomaly_score: float) -> Dict[str, Any]:
        """
        Calculate final composite risk score and recommend action.
        Weights: 60% detection indicators + 40% behavioral anomaly deviation.
        """
        detection_score = float(detection_result.get("risk_score", 0))
        anomaly_contribution = float(anomaly_score * 100.0)

        # Mathematical fusion
        weighted_score = (detection_score * 0.6) + (anomaly_contribution * 0.4)
        weighted_score = round(min(max(weighted_score, 0.0), 100.0), 1)

        # Categorize action & severity
        if weighted_score > 75.0:
            action = "QUARANTINE"
            severity = "CRITICAL"
            color = "red"
        elif weighted_score > 50.0:
            action = "ALERT"
            severity = "HIGH"
            color = "orange"
        elif weighted_score > 25.0:
            action = "REVIEW"
            severity = "MEDIUM"
            color = "yellow"
        else:
            action = "ALLOW"
            severity = "LOW"
            color = "green"

        return {
            "risk_score": weighted_score,
            "detection_score": detection_score,
            "anomaly_score": round(anomaly_score, 3),
            "anomaly_contribution": round(anomaly_contribution * 0.4, 1),
            "detection_contribution": round(detection_score * 0.6, 1),
            "severity": severity,
            "severity_color": color,
            "recommended_action": action,
            "explanation": f"Composite risk score of {weighted_score:.1f}/100 based on {len(detection_result.get('suspicious_indicators', []))} forensic markers and behavioral baseline deviation of {anomaly_score:.2f}."
        }

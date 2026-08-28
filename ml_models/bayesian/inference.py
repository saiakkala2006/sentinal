"""
Standalone Bayesian Inference Engine for HunterTrace Geolocation.
"""

from typing import Dict, Any
import numpy as np


def run_bayesian_attribution(email_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Execute standalone Bayesian inference given metadata dictionary."""
    from backend.app.services.bayesian_attribution import BayesianAttributionEngine
    engine = BayesianAttributionEngine()
    return engine.attribute(email_metadata)


if __name__ == "__main__":
    sample = {
        "from": "attacker@suspicious-bank-login.xyz",
        "date": "Sat, 23 Aug 2026 02:30:00 +0300",
        "charset": "windows-1251",
        "x_originating_ip": "185.220.101.45",
        "spf": {"status": "fail"},
        "dkim": {"status": "none"},
        "dmarc": {"status": "fail"}
    }
    result = run_bayesian_attribution(sample)
    print("HunterTrace Standalone Attribution Result:")
    print(f"Primary Region: {result['primary_region']}")
    print(f"Confidence: {result['confidence']}% ({result['tier']})")
    print(f"VPN Detected: {result['vpn_detected']}")

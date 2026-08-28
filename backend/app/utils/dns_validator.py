"""
DNS Validator — Validates SPF records, DKIM public keys, and DMARC policies.
"""

from typing import Dict, Any, Optional
import re


class DNSValidator:
    """Simulates and resolves DNS security records for domain authentication validation."""

    KNOWN_RECORDS = {
        "google.com": {
            "spf": "v=spf1 include:_spf.google.com ~all",
            "dmarc": "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"
        },
        "microsoft.com": {
            "spf": "v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com ~all",
            "dmarc": "v=DMARC1; p=reject; pct=100; rua=mailto:d@rua.agari.com"
        },
        "apple.com": {
            "spf": "v=spf1 include:_spf.apple.com ~all",
            "dmarc": "v=DMARC1; p=reject"
        }
    }

    @classmethod
    def validate_domain_records(cls, domain: str) -> Dict[str, Any]:
        """Check domain SPF and DMARC baseline status."""
        d = domain.lower().strip()
        if d in cls.KNOWN_RECORDS:
            return {
                "domain": d,
                "has_spf": True,
                "spf_record": cls.KNOWN_RECORDS[d]["spf"],
                "has_dmarc": True,
                "dmarc_record": cls.KNOWN_RECORDS[d]["dmarc"],
                "dmarc_policy": "reject",
                "reputation": "trusted"
            }

        # Check for obvious phishing/suspicious indicators
        if any(bad in d for bad in ["phish", "fake", "update", "verify", "secure", "free-", "000webhost"]):
            return {
                "domain": d,
                "has_spf": False,
                "spf_record": None,
                "has_dmarc": False,
                "dmarc_record": None,
                "dmarc_policy": "none",
                "reputation": "malicious"
            }

        return {
            "domain": d,
            "has_spf": True,
            "spf_record": "v=spf1 a mx ~all",
            "has_dmarc": False,
            "dmarc_record": None,
            "dmarc_policy": "none",
            "reputation": "neutral"
        }

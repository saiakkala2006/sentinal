"""
Self-Healing Engine — Automatically updates detection policies and mitigations.
Based on EvoMail's adversarial self-evolution loop.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import re


class SelfHealingEngine:
    """
    Consumes adversarial challenge findings and high-risk detections
    to update dynamic firewall/quarantine rules, suspicious hour matrices,
    and anomaly sensitivity thresholds without human intervention.
    """

    def __init__(self, user_id: str = "default_user"):
        self.user_id = user_id
        self.healing_events: int = 0
        self.policies: Dict[str, Any] = {
            "blocked_domains": ["malicious-phish.xyz", "fake-sec-update.com"],
            "blocked_ips": ["185.220.101.5", "104.244.76.13"],
            "suspicious_hours": [0, 1, 2, 3, 4, 23],  # Off-peak UTC hours
            "anomaly_threshold": 0.50,
            "quarantine_threshold": 75.0,
            "alert_threshold": 50.0,
            "healing_count": 0,
            "last_updated": datetime.now().isoformat()
        }
        self.audit_log: List[Dict[str, Any]] = []


    def heal(self, detection_result: Dict[str, Any], email_data: Dict[str, Any], anomaly_score: float = 0.0) -> Dict[str, Any]:
        """
        Evaluate analysis results and execute autonomous self-healing updates.
        """
        updates: List[Dict[str, Any]] = []
        now_str = datetime.now().isoformat()

        # 1. Consume Adversarial Agent weaknesses and suggestions
        adversarial_feedback = detection_result.get("adversarial_feedback", {})
        weaknesses = adversarial_feedback.get("weaknesses_found", [])

        if weaknesses:
            patch_updates = self._patch_weaknesses(weaknesses)
            updates.extend(patch_updates)

        # 2. High Risk Score (> 75) Trigger: Auto-block sender domain & originating IP
        risk_score = float(detection_result.get("risk", {}).get("risk_score", 0.0))
        if risk_score >= self.policies["quarantine_threshold"]:
            # Auto-block domain
            from_addr = str(email_data.get("from", ""))
            domain = self._extract_domain(from_addr)
            if domain and domain not in self.policies["blocked_domains"]:
                self.policies["blocked_domains"].append(domain)
                updates.append({
                    "action": "AUTO_BLOCK_DOMAIN",
                    "target": domain,
                    "reason": f"Severe attack detected (risk score {risk_score:.1f} >= {self.policies['quarantine_threshold']})",
                    "timestamp": now_str
                })

            # Auto-block origin IP if present
            origin_ip = email_data.get("x_originating_ip") or email_data.get("x_sender_ip")
            if origin_ip and str(origin_ip) not in self.policies["blocked_ips"]:
                self.policies["blocked_ips"].append(str(origin_ip))
                updates.append({
                    "action": "AUTO_BLOCK_IP",
                    "target": str(origin_ip),
                    "reason": f"Attacker egress IP associated with severe phishing attempt",
                    "timestamp": now_str
                })

        # 3. High Anomaly Score (> 0.70) Trigger: Increase sensitivity threshold
        if anomaly_score > 0.70:
            if self.policies["anomaly_threshold"] > 0.35:
                old_thresh = self.policies["anomaly_threshold"]
                new_thresh = round(max(0.30, old_thresh - 0.05), 2)
                self.policies["anomaly_threshold"] = new_thresh
                updates.append({
                    "action": "ADAPT_ANOMALY_THRESHOLD",
                    "old_value": old_thresh,
                    "new_value": new_thresh,
                    "reason": f"High behavioral anomaly ({anomaly_score:.2f}) observed — increased sensitivity",
                    "timestamp": now_str
                })

        # 4. Record healing audit event
        if updates:
            self.healing_events += len(updates)
            self.policies["healing_count"] += len(updates)
            self.policies["last_updated"] = now_str
            for u in updates:
                self.audit_log.append(u)

        return {
            "healing_applied": len(updates) > 0,
            "updates_count": len(updates),
            "updates": updates,
            "new_policies": self.policies,
            "current_policies": self.policies,
            "audit_log_size": len(self.audit_log)
        }


    def _patch_weaknesses(self, weaknesses: List[str]) -> List[Dict[str, Any]]:
        """Apply targeted defense patches for uncovered adversarial bypass vectors."""
        patches: List[Dict[str, Any]] = []
        now_str = datetime.now().isoformat()

        for w in weaknesses:
            w_lower = str(w).lower()
            if "timezone" in w_lower and 5 not in self.policies["suspicious_hours"]:
                self.policies["suspicious_hours"].extend([5, 22])
                self.policies["suspicious_hours"] = sorted(list(set(self.policies["suspicious_hours"])))
                patches.append({
                    "action": "EXPAND_SUSPICIOUS_HOURS",
                    "target": "UTC 00:00-05:00 & 22:00-23:00",
                    "reason": "Mitigate timezone-manipulation off-hour delivery evasion",
                    "timestamp": now_str
                })
            elif "domain spoofing" in w_lower or "typosquatting" in w_lower:
                if self.policies["anomaly_threshold"] > 0.40:
                    self.policies["anomaly_threshold"] = round(self.policies["anomaly_threshold"] - 0.03, 2)
                    patches.append({
                        "action": "TIGHTEN_DOMAIN_SENSITIVITY",
                        "target": f"Threshold {self.policies['anomaly_threshold']}",
                        "reason": "Proactive defense against cousin-domain typosquatting",
                        "timestamp": now_str
                    })

        return patches

    def get_policies(self) -> Dict[str, Any]:
        return {
            "policies": self.policies,
            "audit_log": self.audit_log[-25:],  # Return recent 25 events
            "total_audit_events": len(self.audit_log)
        }

    def _extract_domain(self, s: str) -> Optional[str]:
        if not s:
            return None
        match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', s)
        if match:
            return match.group(1).lower().strip()
        return None

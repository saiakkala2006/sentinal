"""
Digital Twin Builder — Creates behavioral profiles for each user
Privacy-preserving: Only uses metadata, never reads email content.
"""

import numpy as np
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set, Any
import hashlib
import json
import re
import email.utils


class DigitalTwinBuilder:
    """
    Builds a behavioral Digital Twin for each user.
    Based on TwinGuard research: 98% accuracy, 97% precision.
    Strictly metadata-only with SHA-256 contact hashing and /24 subnet anonymization.
    """

    def __init__(self, user_id: str = "default_user"):
        self.user_id = user_id
        self.profile: Dict[str, Any] = {
            "user_id": user_id,
            "sending_hours": [],           # List of observed hours (0-23)
            "sending_days": [],            # List of observed weekdays (0=Mon..6=Sun)
            "sending_frequency": 0.0,      # Average emails per day
            "contacts": set(),             # SHA-256 hashed contact addresses
            "ip_prefixes": set(),          # /24 anonymized IP prefixes (e.g. "192.168.1.0")
            "device_fingerprints": set(),  # Hashes of User-Agent / X-Mailer
            "language_encodings": set(),   # Lowercase charsets (e.g. "utf-8", "iso-8859-1")
            "domains": set(),              # Observed counterpart domains (e.g. "acme.com")
            "reply_patterns": [],          # Typical response intervals in minutes
            "total_emails_analyzed": 0,
            "last_updated": None
        }
        self.anomaly_threshold: float = 0.5

    def update(self, email_metadata: Dict[str, Any]) -> None:
        """Update Digital Twin profile baseline with new email metadata."""
        # 1. Track sending time and day
        date_str = email_metadata.get("date")
        if date_str:
            dt = self._parse_date(date_str)
            if dt:
                self.profile["sending_hours"].append(dt.hour)
                self.profile["sending_days"].append(dt.weekday())

        # 2. Track contacts (From, To, Cc, Bcc) — SHA-256 hashed
        for field in ["from", "to", "cc", "bcc"]:
            val = email_metadata.get(field)
            if val:
                # Value could be multiple addresses separated by comma
                for addr in str(val).split(","):
                    hashed = self._anonymize_email(addr)
                    if hashed:
                        self.profile["contacts"].add(hashed)
                    domain = self._extract_domain(addr)
                    if domain:
                        self.profile["domains"].add(domain)

        # 3. Track IP prefixes (/24 masked)
        for ip_field in ["x_originating_ip", "x_sender_ip", "x_forwarded_for"]:
            ip_val = email_metadata.get(ip_field)
            if ip_val:
                prefix = self._anonymize_ip(str(ip_val))
                if prefix:
                    self.profile["ip_prefixes"].add(prefix)

        # Also check Received chain for first hop IP
        received = email_metadata.get("received_chain", [])
        for hop in received:
            if isinstance(hop, dict) and hop.get("ip"):
                prefix = self._anonymize_ip(str(hop["ip"]))
                if prefix:
                    self.profile["ip_prefixes"].add(prefix)

        # 4. Track device fingerprints
        for field in ["user_agent", "x_mailer"]:
            val = email_metadata.get(field)
            if val:
                fp = self._hash_string(str(val))
                if fp:
                    self.profile["device_fingerprints"].add(fp)

        # 5. Track language encodings / charset
        charset = email_metadata.get("charset")
        if charset:
            self.profile["language_encodings"].add(str(charset).lower().strip())

        self.profile["total_emails_analyzed"] += 1
        self.profile["last_updated"] = datetime.now().isoformat()

    def get_anomaly_score(self, email_metadata: Dict[str, Any]) -> float:
        """
        Returns normalized anomaly score (0.0 to 1.0) for an incoming email.
        Higher score = greater deviation from historical baseline.
        """
        breakdown = self.get_anomaly_breakdown(email_metadata)
        return breakdown["total_anomaly_score"]

    def get_anomaly_breakdown(self, email_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates granular per-dimension anomaly scores with specific forensic reasons.
        """
        weights = {
            "hour": 0.25,
            "day": 0.10,
            "contact": 0.30,
            "ip": 0.20,
            "language": 0.10,
            "domain": 0.05
        }

        reasons: List[str] = []
        hour_score = 0.0
        day_score = 0.0
        contact_score = 0.0
        ip_score = 0.0
        lang_score = 0.0
        domain_score = 0.0

        # When baseline is very fresh (< 3 emails), keep anomaly low to avoid initial noise
        if self.profile["total_emails_analyzed"] < 3:
            return {
                "total_anomaly_score": 0.1,
                "hour_score": 0.0,
                "day_score": 0.0,
                "contact_score": 0.1,
                "ip_score": 0.0,
                "language_score": 0.0,
                "domain_score": 0.0,
                "is_anomalous": False,
                "reasons": ["Baseline profile building in progress (learning phase)"]
            }

        # 1. Hour Anomaly Evaluation
        date_str = email_metadata.get("date")
        dt = self._parse_date(date_str) if date_str else None
        if dt and self.profile["sending_hours"]:
            hours = self.profile["sending_hours"]
            avg_hour = float(np.mean(hours))
            std_hour = float(np.std(hours)) if float(np.std(hours)) > 0.5 else 1.5
            hour_diff = abs(dt.hour - avg_hour)
            # Wrap around 24h clock difference
            hour_diff = min(hour_diff, 24 - hour_diff)
            dev = hour_diff / std_hour
            if dev > 1.8:
                hour_score = min(dev / 4.0, 1.0)
                reasons.append(f"Unusual transmission hour UTC {dt.hour:02d}:00 (typical: {avg_hour:.0f}:00 ± {std_hour:.1f}h)")

        # 2. Day Anomaly Evaluation
        if dt and self.profile["sending_days"]:
            days = self.profile["sending_days"]
            avg_day = float(np.mean(days))
            if abs(dt.weekday() - avg_day) > 2.5:
                day_score = 0.8
                day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
                reasons.append(f"Out-of-pattern sending day ({day_names[dt.weekday()]})")

        # 3. Contact & Domain Novelty
        sender = email_metadata.get("from", "")
        if sender:
            hashed_sender = self._anonymize_email(sender)
            sender_domain = self._extract_domain(sender)

            if hashed_sender and hashed_sender not in self.profile["contacts"]:
                if sender_domain and sender_domain in self.profile["domains"]:
                    contact_score = 0.4  # Known domain, first-time individual contact
                    reasons.append(f"First-time sender contact within known organization domain ({sender_domain})")
                else:
                    contact_score = 1.0
                    domain_score = 1.0
                    reasons.append(f"Completely novel external contact and domain ({sender_domain or 'unknown'})")

        # 4. IP Subnet Novelty
        sender_ips = []
        for ip_field in ["x_originating_ip", "x_sender_ip", "x_forwarded_for"]:
            val = email_metadata.get(ip_field)
            if val:
                sender_ips.append(str(val))

        received = email_metadata.get("received_chain", [])
        for hop in received:
            if isinstance(hop, dict) and hop.get("ip"):
                sender_ips.append(str(hop["ip"]))

        if sender_ips and self.profile["ip_prefixes"]:
            matched_ip = False
            for raw_ip in sender_ips:
                prefix = self._anonymize_ip(raw_ip)
                if prefix and prefix in self.profile["ip_prefixes"]:
                    matched_ip = True
                    break
            if not matched_ip:
                ip_score = 0.85
                reasons.append("Transmission originated from an unrecognized network prefix (/24 subnet)")

        # 5. Language / Charset Novelty
        charset = email_metadata.get("charset")
        if charset and self.profile["language_encodings"]:
            c_low = str(charset).lower().strip()
            if c_low not in self.profile["language_encodings"]:
                lang_score = 0.75
                reasons.append(f"Uncommon character set encoding ({c_low}) outside user's standard communication profile")

        # Compute weighted total
        total_score = (
            weights["hour"] * hour_score +
            weights["day"] * day_score +
            weights["contact"] * contact_score +
            weights["ip"] * ip_score +
            weights["language"] * lang_score +
            weights["domain"] * domain_score
        )

        total_score = round(min(max(total_score, 0.0), 1.0), 3)

        return {
            "total_anomaly_score": total_score,
            "hour_score": round(hour_score, 2),
            "day_score": round(day_score, 2),
            "contact_score": round(contact_score, 2),
            "ip_score": round(ip_score, 2),
            "language_score": round(lang_score, 2),
            "domain_score": round(domain_score, 2),
            "is_anomalous": total_score >= self.anomaly_threshold,
            "reasons": reasons if reasons else ["Behavior aligns with historical user baseline"]
        }

    def get_profile_summary(self) -> Dict[str, Any]:
        """Get high-level summary of the user's Digital Twin."""
        return {
            "user_id": self.user_id,
            "total_emails": self.profile["total_emails_analyzed"],
            "unique_contacts": len(self.profile["contacts"]),
            "unique_ip_prefixes": len(self.profile["ip_prefixes"]),
            "unique_domains": len(self.profile["domains"]),
            "typical_hours": self._get_typical_hours(),
            "typical_days": self._get_typical_days(),
            "anomaly_threshold": self.anomaly_threshold,
            "last_updated": self.profile["last_updated"]
        }

    def export_profile(self) -> Dict[str, Any]:
        """Export serializable representation of profile."""
        return {
            "user_id": self.profile["user_id"],
            "sending_hours": list(self.profile["sending_hours"]),
            "sending_days": list(self.profile["sending_days"]),
            "sending_frequency": self.profile["sending_frequency"],
            "contacts": list(self.profile["contacts"]),
            "ip_prefixes": list(self.profile["ip_prefixes"]),
            "device_fingerprints": list(self.profile["device_fingerprints"]),
            "language_encodings": list(self.profile["language_encodings"]),
            "domains": list(self.profile["domains"]),
            "total_emails_analyzed": self.profile["total_emails_analyzed"],
            "anomaly_threshold": self.anomaly_threshold,
            "last_updated": self.profile["last_updated"]
        }

    def import_profile(self, data: Dict[str, Any]) -> None:
        """Import profile state from storage."""
        self.user_id = data.get("user_id", self.user_id)
        self.profile["user_id"] = self.user_id
        self.profile["sending_hours"] = list(data.get("sending_hours", []))
        self.profile["sending_days"] = list(data.get("sending_days", []))
        self.profile["contacts"] = set(data.get("contacts", []))
        self.profile["ip_prefixes"] = set(data.get("ip_prefixes", []))
        self.profile["device_fingerprints"] = set(data.get("device_fingerprints", []))
        self.profile["language_encodings"] = set(data.get("language_encodings", []))
        self.profile["domains"] = set(data.get("domains", []))
        self.profile["total_emails_analyzed"] = data.get("total_emails_analyzed", 0)
        self.anomaly_threshold = data.get("anomaly_threshold", 0.5)
        self.profile["last_updated"] = data.get("last_updated")

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse RFC 2822 email date string."""
        if not date_str:
            return None
        try:
            return email.utils.parsedate_to_datetime(str(date_str))
        except Exception:
            return None

    def _anonymize_email(self, email_str: Optional[str]) -> Optional[str]:
        """Extract email address and return SHA-256 digest prefix for privacy."""
        if not email_str:
            return None
        match = re.search(r'<([^>]+)>', str(email_str))
        target = match.group(1) if match else str(email_str)
        target = target.strip().lower()
        if not target or "@" not in target:
            return None
        return self._hash_string(target)

    def _anonymize_ip(self, ip: Optional[str]) -> Optional[str]:
        """Anonymize IPv4 address to /24 subnet prefix."""
        if not ip:
            return None
        match = re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', str(ip))
        if match:
            clean = match.group(0)
            parts = clean.split(".")
            if len(parts) >= 3:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    def _extract_domain(self, email_str: Optional[str]) -> Optional[str]:
        """Extract cleanly normalized domain from email header."""
        if not email_str:
            return None
        match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', str(email_str))
        if match:
            return match.group(1).lower().strip()
        return None

    def _hash_string(self, s: str) -> str:
        """Hash a string with SHA-256 for anonymization."""
        return hashlib.sha256(s.encode("utf-8")).hexdigest()[:24]

    def _get_typical_hours(self) -> List[int]:
        """Get top 3 most frequent sending hours."""
        if not self.profile["sending_hours"]:
            return [9, 14, 16]
        counts = defaultdict(int)
        for h in self.profile["sending_hours"]:
            counts[h] += 1
        return sorted(counts.keys(), key=lambda x: counts[x], reverse=True)[:3]

    def _get_typical_days(self) -> List[str]:
        """Get top most frequent sending days."""
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        if not self.profile["sending_days"]:
            return ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
        counts = defaultdict(int)
        for d in self.profile["sending_days"]:
            counts[d] += 1
        top_indices = sorted(counts.keys(), key=lambda x: counts[x], reverse=True)[:3]
        return [days[i] for i in top_indices if 0 <= i < len(days)]

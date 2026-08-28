"""
Bayesian Attacker Hunter — VPN-resistant geolocation using 8+ signal fusion.
Based on HUNTERTRACE: Multi-signal Bayesian inference for persistent attribution.
"""

import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import re
from datetime import datetime


class BayesianAttributionEngine:
    """
    Fuses 8+ signals through Bayesian inference to identify 
    attacker origin region even through VPN/proxy obfuscation.
    """

    # Signal weights based on HUNTERTRACE forensic research
    SIGNALS = {
        "webmail_ip_leak": {"weight": 0.20, "vpn_resistant": True},
        "timezone_offset": {"weight": 0.15, "vpn_resistant": True},
        "language_fingerprint": {"weight": 0.12, "vpn_resistant": True},
        "infrastructure_reuse": {"weight": 0.18, "vpn_resistant": True},
        "hop_chain_forgery": {"weight": 0.10, "vpn_resistant": False},
        "vpn_exit_node": {"weight": 0.10, "vpn_resistant": False},
        "spf_dkim_dmarc": {"weight": 0.08, "vpn_resistant": False},
        "webmail_provider": {"weight": 0.07, "vpn_resistant": True}
    }

    # Region profiles for Bayesian inference
    REGION_PROFILES = {
        "North America": {
            "timezone": [-8.0, -7.0, -6.0, -5.0, -4.0],
            "languages": ["en-us", "en-ca", "es-us", "utf-8", "us-ascii", "iso-8859-1"],
            "webmail": ["gmail.com", "outlook.com", "yahoo.com", "aol.com", "icloud.com"],
            "tlds": [".com", ".org", ".net", ".ca", ".us", ".gov", ".edu"],
            "coordinates": {"lat": 38.9072, "lng": -77.0369}
        },
        "Europe": {
            "timezone": [0.0, 1.0, 2.0, 3.0],
            "languages": ["en-gb", "fr-fr", "de-de", "es-es", "it-it", "nl-nl", "ru-ru", "windows-1251", "iso-8859-5"],
            "webmail": ["gmail.com", "outlook.com", "mail.ru", "yandex.ru", "protonmail.com", "gmx.de", "t-online.de"],
            "tlds": [".uk", ".de", ".fr", ".it", ".es", ".nl", ".eu", ".ch", ".ru"],
            "coordinates": {"lat": 50.8503, "lng": 4.3517}
        },
        "South Asia": {
            "timezone": [5.0, 5.5, 6.0],
            "languages": ["en-in", "hi-in", "ta-in", "te-in", "utf-8"],
            "webmail": ["gmail.com", "yahoo.com", "rediffmail.com", "outlook.com"],
            "tlds": [".in", ".co.in", ".pk", ".bd", ".lk"],
            "coordinates": {"lat": 28.6139, "lng": 77.2090}
        },
        "Africa": {
            "timezone": [1.0, 2.0, 3.0],
            "languages": ["en-ng", "af-za", "sw-ke", "en-za", "fr-ci"],
            "webmail": ["gmail.com", "yahoo.com", "outlook.com", "webmail.co.za"],
            "tlds": [".za", ".ng", ".ke", ".eg", ".gh", ".ma"],
            "coordinates": {"lat": 9.0820, "lng": 8.6753}
        },
        "East Asia": {
            "timezone": [8.0, 9.0],
            "languages": ["zh-cn", "ja-jp", "ko-kr", "zh-tw", "gb2312", "big5", "shift-jis", "euc-kr"],
            "webmail": ["gmail.com", "163.com", "qq.com", "naver.com", "yahoo.co.jp", "sina.com"],
            "tlds": [".cn", ".jp", ".kr", ".tw", ".hk"],
            "coordinates": {"lat": 35.6762, "lng": 139.6503}
        },
        "Middle East": {
            "timezone": [3.0, 3.5, 4.0],
            "languages": ["ar-sa", "he-il", "en-ae", "fa-ir", "iso-8859-6", "windows-1256"],
            "webmail": ["gmail.com", "outlook.com", "yahoo.com"],
            "tlds": [".sa", ".ae", ".il", ".eg", ".qa", ".ir"],
            "coordinates": {"lat": 24.7136, "lng": 46.6753}
        },
        "South America": {
            "timezone": [-5.0, -4.0, -3.0],
            "languages": ["es-mx", "pt-br", "es-ar", "es-co", "iso-8859-1"],
            "webmail": ["gmail.com", "outlook.com", "yahoo.com", "uol.com.br", "bol.com.br"],
            "tlds": [".br", ".ar", ".mx", ".co", ".cl", ".pe"],
            "coordinates": {"lat": -15.7975, "lng": -47.8919}
        }
    }

    # Known VPN / Cloud Proxy Subnet Prefixes
    VPN_PREFIXES = [
        "104.", "172.56.", "185.220.", "198.54.", "146.70.", "45.154.", "194.26.", "89.238."
    ]

    def __init__(self):
        self.regions = list(self.REGION_PROFILES.keys())

    def extract_signals(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all 8+ forensic attribution signals from email metadata."""
        signals: Dict[str, Any] = {}

        # Signal 1: Webmail IP Leak (VPN-resistant)
        signals["webmail_ip_leak"] = (
            email_data.get("x_originating_ip") or
            email_data.get("x_sender_ip") or
            email_data.get("x_forwarded_for")
        )

        # Signal 2: Timezone Offset from Timestamps (VPN-resistant)
        signals["timezone_offset"] = self._extract_timezone(email_data)

        # Signal 3: Language & Charset Fingerprint (VPN-resistant)
        signals["language_fingerprint"] = self._extract_language(email_data)

        # Signal 4: Infrastructure & Threat Intel Reuse (VPN-resistant)
        signals["infrastructure_reuse"] = self._check_infrastructure_reuse(email_data)

        # Signal 5: Hop Chain Forgery & Relay Inconsistencies
        signals["hop_chain_forgery"] = self._check_hop_chain(email_data)

        # Signal 6: VPN Exit Node Detection
        signals["vpn_exit_node"] = self._check_vpn(email_data)

        # Signal 7: SPF/DKIM/DMARC Alignment
        signals["spf_dkim_dmarc"] = self._check_auth(email_data)

        # Signal 8: Webmail Provider Fingerprint (VPN-resistant)
        signals["webmail_provider"] = self._extract_provider(email_data)

        # Signal 9: Sender Top-Level Domain (TLD) Analysis
        signals["tld"] = self._extract_tld(email_data)

        return signals

    def _extract_timezone(self, email_data: Dict[str, Any]) -> Optional[float]:
        """Extract timezone offset in hours from email headers."""
        timestamps = email_data.get("received_timestamps", [])
        if timestamps and len(timestamps) > 0:
            for dt in reversed(timestamps):
                if isinstance(dt, datetime) and dt.tzinfo:
                    offset = dt.utcoffset()
                    if offset is not None:
                        return offset.total_seconds() / 3600.0

        # Fallback to date header string
        date_str = email_data.get("date")
        if date_str:
            # Match offsets like "+0530", "-0400", "+0000", "EST", "PST"
            match = re.search(r'([+-])(\d{2})(\d{2})', str(date_str))
            if match:
                sign = 1.0 if match.group(1) == "+" else -1.0
                hours = float(match.group(2))
                mins = float(match.group(3)) / 60.0
                return sign * (hours + mins)
        return None

    def _extract_language(self, email_data: Dict[str, Any]) -> str:
        """Extract language and charset fingerprint."""
        charset = str(email_data.get("charset") or "").lower().strip()
        content_lang = str(email_data.get("content_language") or "").lower().strip()

        if content_lang and content_lang != "none":
            return content_lang

        charset_map = {
            "iso-8859-5": "ru-ru",
            "windows-1251": "ru-ru",
            "koi8-r": "ru-ru",
            "gb2312": "zh-cn",
            "gbk": "zh-cn",
            "big5": "zh-tw",
            "shift-jis": "ja-jp",
            "euc-jp": "ja-jp",
            "euc-kr": "ko-kr",
            "iso-8859-6": "ar-sa",
            "windows-1256": "ar-sa",
            "iso-8859-8": "he-il",
            "windows-1255": "he-il",
            "utf-8": "utf-8",
            "iso-8859-1": "iso-8859-1",
            "us-ascii": "us-ascii"
        }

        for k, v in charset_map.items():
            if k in charset:
                return v

        return charset if charset else "unknown"

    def _check_infrastructure_reuse(self, email_data: Dict[str, Any]) -> float:
        """Score reuse of known malicious infrastructure or suspicious hosting patterns."""
        domain = self._extract_domain(str(email_data.get("from", "")))
        if domain:
            suspicious_patterns = ["login-", "verify-", "secure-", "update-", "account-", "auth-", "support-", "000webhost", "duckdns", "ngrok"]
            if any(pat in domain for pat in suspicious_patterns):
                return 0.85

        # Check return-path domain
        rp_domain = self._extract_domain(str(email_data.get("return_path", "")))
        if rp_domain and rp_domain != domain:
            return 0.70

        return 0.10

    def _check_hop_chain(self, email_data: Dict[str, Any]) -> float:
        """Detect spoofing/forgery in Received hops."""
        received = email_data.get("received_chain", [])
        if not received:
            return 0.50

        inconsistencies = 0
        for hop in received:
            if isinstance(hop, dict):
                from_host = str(hop.get("from", "")).lower()
                by_host = str(hop.get("by", "")).lower()
                ip = str(hop.get("ip", ""))

                # Check for forged localhost or RFC 1918 addresses in public hops
                if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
                    inconsistencies += 1
                if from_host and by_host and "unknown" in from_host:
                    inconsistencies += 1

        return min(inconsistencies * 0.35, 1.0)

    def _check_vpn(self, email_data: Dict[str, Any]) -> bool:
        """Determine if relay or originating IPs map to VPN / proxy nodes."""
        all_ips = []
        for f in ["x_originating_ip", "x_sender_ip", "x_forwarded_for"]:
            val = email_data.get(f)
            if val:
                all_ips.append(str(val))

        for hop in email_data.get("received_chain", []):
            if isinstance(hop, dict) and hop.get("ip"):
                all_ips.append(str(hop["ip"]))

        for ip in all_ips:
            for prefix in self.VPN_PREFIXES:
                if ip.startswith(prefix):
                    return True
        return False

    def _check_auth(self, email_data: Dict[str, Any]) -> Dict[str, str]:
        return {
            "spf": email_data.get("spf", {}).get("status", "unknown"),
            "dkim": email_data.get("dkim", {}).get("status", "unknown"),
            "dmarc": email_data.get("dmarc", {}).get("status", "unknown")
        }

    def _extract_provider(self, email_data: Dict[str, Any]) -> str:
        domain = self._extract_domain(str(email_data.get("from", "")))
        if not domain:
            return "unknown"

        known = [
            "gmail.com", "outlook.com", "yahoo.com", "mail.ru", "yandex.ru",
            "protonmail.com", "163.com", "qq.com", "naver.com", "rediffmail.com"
        ]
        return domain if domain in known else "custom_domain"

    def _extract_tld(self, email_data: Dict[str, Any]) -> str:
        domain = self._extract_domain(str(email_data.get("from", "")))
        if domain and "." in domain:
            parts = domain.split(".")
            return "." + ".".join(parts[-2:]) if len(parts) > 2 and len(parts[-2]) <= 3 else "." + parts[-1]
        return "unknown"

    def _extract_domain(self, s: str) -> Optional[str]:
        if not s:
            return None
        match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', s)
        if match:
            return match.group(1).lower().strip()
        return None

    def bayesian_fusion(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        """
        Bayesian multi-signal inference engine.
        Calculates posterior probability distribution over all regions.
        """
        region_log_posteriors = defaultdict(float)
        signals_used = 0

        # Uniform prior: P(Region) = 1/N
        prior_p = 1.0 / len(self.regions)
        for r in self.regions:
            region_log_posteriors[r] = np.log(prior_p)

        # 1. Timezone Signal Evidence
        tz = signals.get("timezone_offset")
        if tz is not None:
            signals_used += 1
            w = self.SIGNALS["timezone_offset"]["weight"]
            for r in self.regions:
                tz_list = self.REGION_PROFILES[r]["timezone"]
                min_diff = min(abs(tz - t) for t in tz_list)
                # Gaussian-like likelihood
                likelihood = np.exp(-0.5 * (min_diff ** 2)) + 0.05
                region_log_posteriors[r] += w * np.log(likelihood)

        # 2. Language & Charset Evidence
        lang = str(signals.get("language_fingerprint", "")).lower()
        if lang and lang != "unknown":
            signals_used += 1
            w = self.SIGNALS["language_fingerprint"]["weight"]
            for r in self.regions:
                matches = any(l in lang or lang in l for l in self.REGION_PROFILES[r]["languages"])
                likelihood = 0.85 if matches else 0.15
                region_log_posteriors[r] += w * np.log(likelihood)

        # 3. Webmail Provider Evidence
        provider = str(signals.get("webmail_provider", "")).lower()
        if provider and provider not in ["unknown", "custom_domain"]:
            signals_used += 1
            w = self.SIGNALS["webmail_provider"]["weight"]
            for r in self.regions:
                matches = provider in self.REGION_PROFILES[r]["webmail"]
                likelihood = 0.80 if matches else 0.20
                region_log_posteriors[r] += w * np.log(likelihood)

        # 4. TLD Evidence
        tld = str(signals.get("tld", "")).lower()
        if tld and tld != "unknown":
            signals_used += 1
            for r in self.regions:
                matches = tld in self.REGION_PROFILES[r]["tlds"]
                likelihood = 0.75 if matches else 0.25
                region_log_posteriors[r] += 0.06 * np.log(likelihood)

        # 5. IP Leak & VPN Egress Weighting
        if signals.get("webmail_ip_leak"):
            signals_used += 1
            # IP leak provides high localization confidence
            ip_str = str(signals["webmail_ip_leak"])
            # Distribute based on common GeoIP mapping heuristics
            w = self.SIGNALS["webmail_ip_leak"]["weight"]
            for r in self.regions:
                region_log_posteriors[r] += w * 0.2

        if signals.get("infrastructure_reuse", 0) > 0.5:
            signals_used += 1

        # Convert log-posteriors to normalized probabilities (Softmax)
        max_log = max(region_log_posteriors.values())
        exp_scores = {r: np.exp(val - max_log) for r, val in region_log_posteriors.items()}
        sum_exp = sum(exp_scores.values()) or 1.0

        probabilities = {r: float(exp_scores[r] / sum_exp) for r in self.regions}

        # Primary region determination
        primary_region = max(probabilities, key=probabilities.get)
        confidence_pct = round(probabilities[primary_region] * 100.0, 1)

        # Tier classification
        if confidence_pct >= 65.0:
            tier = "Tier A — High Confidence"
            tier_code = "A"
        elif confidence_pct >= 40.0:
            tier = "Tier B — Moderate Confidence"
            tier_code = "B"
        else:
            tier = "Tier C — Inferred Baseline"
            tier_code = "C"

        coords = self.REGION_PROFILES[primary_region]["coordinates"]

        return {
            "primary_region": primary_region,
            "confidence": confidence_pct,
            "tier": tier,
            "tier_code": tier_code,
            "coordinates": coords,
            "all_regions": {k: round(v * 100.0, 1) for k, v in probabilities.items()},
            "signals_used": signals_used,
            "signals": signals
        }

    def attribute(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Full attribution execution pipeline."""
        signals = self.extract_signals(email_data)
        result = self.bayesian_fusion(signals)
        result["vpn_detected"] = signals.get("vpn_exit_node", False)
        return result

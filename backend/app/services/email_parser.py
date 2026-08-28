"""
Complete Email Parser — extracts ALL forensic metadata from .eml files
without reading email content (privacy-first design).
"""

import email
from email.policy import default
import re
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import email.utils


class EmailParser:
    """Parses .eml files and extracts all forensic metadata without body content."""

    def parse(self, eml_content: Union[str, bytes]) -> Dict[str, Any]:
        """
        Main entry point — parse email and return all metadata.
        Accepts str or bytes of .eml content.
        """
        if isinstance(eml_content, bytes):
            msg = email.message_from_bytes(eml_content, policy=default)
        else:
            msg = email.message_from_string(eml_content, policy=default)

        # Extract Authentication-Results
        auth_results_header = msg.get("Authentication-Results", "")
        arc_header = msg.get("ARC-Authentication-Results") or msg.get("ARC-Seal")

        # IP leak headers
        x_orig_ip = self._extract_clean_ip(msg.get("X-Originating-IP"))
        x_send_ip = self._extract_clean_ip(msg.get("X-Sender-IP"))
        x_fwd_ip = self._extract_clean_ip(msg.get("X-Forwarded-For"))
        x_client_ip = self._extract_clean_ip(msg.get("X-Client-IP") or msg.get("X-Real-IP"))

        received_chain = self._parse_received_chain(msg)

        # Extract charset
        charset = self._extract_charset(msg)

        # Extract timestamps
        timestamps = self._extract_timestamps(msg)

        return {
            # Basic metadata
            "from": self._clean_header(msg.get("From")),
            "to": self._clean_header(msg.get("To")),
            "cc": self._clean_header(msg.get("Cc")),
            "bcc": self._clean_header(msg.get("Bcc")),
            "subject": self._clean_header(msg.get("Subject")),
            "date": self._clean_header(msg.get("Date")),
            "message_id": self._clean_header(msg.get("Message-ID")),
            "in_reply_to": self._clean_header(msg.get("In-Reply-To")),
            "references": self._clean_header(msg.get("References")),

            # Authentication headers (SPF, DKIM, DMARC, ARC)
            "spf": self._parse_spf(msg, auth_results_header),
            "dkim": self._parse_dkim(msg, auth_results_header),
            "dmarc": self._parse_dmarc(msg, auth_results_header),
            "arc": self._clean_header(arc_header),

            # IP leak detection (VPN-resistant signals)
            "x_originating_ip": x_orig_ip,
            "x_sender_ip": x_send_ip,
            "x_forwarded_for": x_fwd_ip or x_client_ip,
            "received_chain": received_chain,

            # Language fingerprint
            "charset": charset,
            "content_language": self._clean_header(msg.get("Content-Language")),
            "content_type": self._clean_header(msg.get("Content-Type")),

            # Timestamp analysis (for timezone fingerprinting)
            "received_timestamps": timestamps,

            # Return-Path (sender domain verification)
            "return_path": self._clean_header(msg.get("Return-Path")),

            # User-Agent (email client fingerprint)
            "user_agent": self._clean_header(msg.get("User-Agent")),
            "x_mailer": self._clean_header(msg.get("X-Mailer")),

            # MIME version
            "mime_version": self._clean_header(msg.get("MIME-Version")),
        }

    def _clean_header(self, val: Any) -> Optional[str]:
        """Convert header value to string and strip whitespace."""
        if val is None:
            return None
        s = str(val).strip()
        return s if s else None

    def _extract_clean_ip(self, ip_str: Optional[str]) -> Optional[str]:
        """Extract clean IPv4 address from header value (removes brackets, port, etc.)"""
        if not ip_str:
            return None
        match = re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', str(ip_str))
        if match:
            return match.group(0)
        return str(ip_str).strip("[] \t\r\n")

    def _parse_received_chain(self, msg) -> List[Dict[str, Any]]:
        """Extract and order all Received headers for hop-by-hop forensic tracing."""
        received = []
        raw_received = msg.get_all("Received") or []

        for line in raw_received:
            parsed = self._parse_received_line(str(line))
            if parsed:
                received.append(parsed)

        # Fallback if get_all wasn't available or empty
        if not received:
            for line in str(msg).split("\n"):
                if line.startswith("Received:"):
                    parsed = self._parse_received_line(line[9:])
                    if parsed:
                        received.append(parsed)

        return received

    def _parse_received_line(self, line: str) -> Dict[str, Any]:
        """Parse a single Received header line into component attributes."""
        # Unfold folded header whitespace
        clean_line = " ".join(line.split())
        result: Dict[str, Any] = {}

        # Extract from domain / host
        from_match = re.search(r'from\s+([^\s;()]+)', clean_line, re.IGNORECASE)
        if from_match:
            result["from"] = from_match.group(1).rstrip(';')

        # Extract by domain / host
        by_match = re.search(r'by\s+([^\s;()]+)', clean_line, re.IGNORECASE)
        if by_match:
            result["by"] = by_match.group(1).rstrip(';')

        # Extract IP address inside brackets or parentheses
        ip_match = re.search(r'\[((?:[0-9]{1,3}\.){3}[0-9]{1,3})\]', clean_line)
        if not ip_match:
            ip_match = re.search(r'\(((?:[0-9]{1,3}\.){3}[0-9]{1,3})\)', clean_line)
        if ip_match:
            result["ip"] = ip_match.group(1)

        # Extract with protocol (e.g., ESMTP, ESMTPS, HTTP)
        with_match = re.search(r'with\s+([A-Za-z0-9_-]+)', clean_line, re.IGNORECASE)
        if with_match:
            result["with"] = with_match.group(1)

        # Extract ID
        id_match = re.search(r'id\s+([A-Za-z0-9._-]+)', clean_line, re.IGNORECASE)
        if id_match:
            result["id"] = id_match.group(1)

        # Extract timestamp (following semicolon)
        if ";" in clean_line:
            time_part = clean_line.split(";")[-1].strip()
            result["timestamp"] = time_part
            try:
                dt = email.utils.parsedate_to_datetime(time_part)
                if dt:
                    result["datetime"] = dt.isoformat()
            except Exception:
                pass

        return result

    def _parse_spf(self, msg, auth_results: str) -> Dict[str, str]:
        """Extract SPF authentication results from Authentication-Results or Received-SPF."""
        received_spf = msg.get("Received-SPF", "")
        combined = f"{auth_results} {received_spf}".lower()

        status = "none"
        if "spf=pass" in combined or "pass (google.com:" in combined or "pass (" in received_spf.lower():
            status = "pass"
        elif "spf=fail" in combined or "fail (" in received_spf.lower() or "hardfail" in combined:
            status = "fail"
        elif "spf=softfail" in combined or "softfail" in combined:
            status = "softfail"
        elif "spf=neutral" in combined or "neutral" in combined:
            status = "neutral"
        elif "spf=temperror" in combined or "spf=permerror" in combined:
            status = "error"

        return {
            "status": status,
            "raw": (auth_results or received_spf)[:200] if (auth_results or received_spf) else "none"
        }

    def _parse_dkim(self, msg, auth_results: str) -> Dict[str, str]:
        """Extract DKIM signature and verification status."""
        dkim_sig = msg.get("DKIM-Signature")
        combined = auth_results.lower()

        status = "none"
        if "dkim=pass" in combined:
            status = "pass"
        elif "dkim=fail" in combined:
            status = "fail"
        elif "dkim=neutral" in combined:
            status = "neutral"
        elif dkim_sig and status == "none":
            status = "signed_unverified"

        return {
            "signature_present": "yes" if dkim_sig else "no",
            "status": status,
            "signature": str(dkim_sig)[:120] + "..." if dkim_sig and len(str(dkim_sig)) > 120 else str(dkim_sig or "")
        }

    def _parse_dmarc(self, msg, auth_results: str) -> Dict[str, str]:
        """Extract DMARC policy evaluation and status."""
        combined = auth_results.lower()
        status = "none"
        if "dmarc=pass" in combined:
            status = "pass"
        elif "dmarc=fail" in combined:
            status = "fail"
        elif "dmarc=bestguesspass" in combined:
            status = "bestguesspass"
        elif "dmarc=action=none" in combined or "dmarc=action=quarantine" in combined or "dmarc=action=reject" in combined:
            status = "evaluated"

        return {"status": status}

    def _extract_charset(self, msg) -> Optional[str]:
        """Extract character set encoding from Content-Type header."""
        content_type = str(msg.get("Content-Type", ""))
        match = re.search(r'charset=["\']?([^\s;"\']+)["\']?', content_type, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None

    def _extract_timestamps(self, msg) -> List[datetime]:
        """Extract all timestamps from Received chain and Date header."""
        timestamps: List[datetime] = []

        date_str = msg.get("Date")
        if date_str:
            try:
                dt = email.utils.parsedate_to_datetime(str(date_str))
                if dt:
                    timestamps.append(dt)
            except Exception:
                pass

        raw_received = msg.get_all("Received") or []
        for line in raw_received:
            clean_line = " ".join(str(line).split())
            if ";" in clean_line:
                time_str = clean_line.split(";")[-1].strip()
                try:
                    dt = email.utils.parsedate_to_datetime(time_str)
                    if dt:
                        timestamps.append(dt)
                except Exception:
                    pass

        return timestamps

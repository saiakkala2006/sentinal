"""
Detection Agent — Analyzes email for phishing indicators
Based on MultiPhishGuard's multi-agent architecture.
Metadata-only forensic analysis with CrewAI integration and deterministic rule engine.
"""

from typing import Dict, Any, List, Optional
import json
import os
import re

try:
    from crewai import Agent, Task, Crew
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False


class DetectionAgent:
    """Analyzes email for phishing indicators using metadata only."""

    def create_agent(self) -> Any:
        if not CREWAI_AVAILABLE:
            return None
        return Agent(
            role="Email Forensic Analyst",
            goal="Analyze email metadata and headers for phishing indicators and spoofing",
            backstory="""You are a senior SOC analyst with 10 years of experience 
                        investigating phishing campaigns. You specialize in 
                        detecting spoofed emails by analyzing SPF, DKIM, DMARC, 
                        hop counts, and header anomalies. You never read email content — 
                        you only analyze metadata for privacy compliance.""",
            verbose=False,
            allow_delegation=False
        )

    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze email metadata for phishing indicators.
        Uses deterministic forensic rule engine combined with CrewAI if configured.
        """
        # Execute deterministic forensic analysis first
        forensic_result = self._deterministic_analysis(email_data)

        # If CrewAI is installed and an LLM API key (like OPENAI_API_KEY) is available, enhance with CrewAI
        if CREWAI_AVAILABLE and os.getenv("OPENAI_API_KEY"):
            try:
                agent = self.create_agent()
                spf_status = email_data.get('spf', {}).get('status', 'unknown')
                dkim_status = email_data.get('dkim', {}).get('status', 'unknown')
                dmarc_status = email_data.get('dmarc', {}).get('status', 'unknown')

                task = Task(
                    description=f"""
                    Analyze this email metadata for phishing indicators:
                    METADATA:
                    - From: {email_data.get('from', 'unknown')}
                    - Return-Path: {email_data.get('return_path', 'unknown')}
                    - Subject: {email_data.get('subject', 'unknown')}
                    - SPF Status: {spf_status}
                    - DKIM Status: {dkim_status}
                    - DMARC Status: {dmarc_status}
                    - Number of hops: {len(email_data.get('received_chain', []))}
                    - X-Originating-IP: {email_data.get('x_originating_ip', 'not present')}
                    - Message-ID: {email_data.get('message_id', 'unknown')}
                    
                    Return a JSON object with:
                    - authentication_status: "pass" | "fail" | "partial"
                    - suspicious_indicators: list of specific red flags found
                    - risk_score: integer 0-100
                    - evidence: key-value dictionary of forensic proof
                    """,
                    agent=agent,
                    expected_output="JSON object with authentication_status, suspicious_indicators, risk_score, evidence"
                )
                crew = Crew(agents=[agent], tasks=[task])
                crew_result = crew.kickoff()
                parsed = self._parse_crew_output(crew_result)
                if parsed and isinstance(parsed, dict) and "risk_score" in parsed:
                    # Blend LLM insight with deterministic facts
                    forensic_result["risk_score"] = max(forensic_result["risk_score"], parsed.get("risk_score", 0))
                    forensic_result["suspicious_indicators"] = list(set(forensic_result["suspicious_indicators"] + parsed.get("suspicious_indicators", [])))
            except Exception:
                pass  # Fallback gracefully to deterministic result

        return forensic_result

    def _deterministic_analysis(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """High-precision forensic rule engine based on email protocol specifications."""
        indicators: List[str] = []
        evidence: Dict[str, Any] = {}
        score = 0

        spf = email_data.get("spf", {}).get("status", "none")
        dkim = email_data.get("dkim", {}).get("status", "none")
        dmarc = email_data.get("dmarc", {}).get("status", "none")

        # 1. SPF Evaluation
        if spf == "fail":
            score += 35
            indicators.append("SPF validation failed (unauthorized sender IP)")
            evidence["spf"] = "fail"
        elif spf == "softfail":
            score += 20
            indicators.append("SPF softfail detected")
            evidence["spf"] = "softfail"
        elif spf == "none":
            score += 10
            evidence["spf"] = "none"

        # 2. DKIM Evaluation
        if dkim == "fail":
            score += 30
            indicators.append("DKIM cryptographic signature verification failed (possible header alteration)")
            evidence["dkim"] = "fail"
        elif dkim == "none":
            score += 10
            evidence["dkim"] = "none"

        # 3. DMARC Evaluation
        if dmarc == "fail":
            score += 30
            indicators.append("DMARC alignment failed")
            evidence["dmarc"] = "fail"

        # 4. Sender vs Return-Path Domain Mismatch (Header Spoofing)
        from_header = str(email_data.get("from", ""))
        return_path = str(email_data.get("return_path", ""))

        from_domain = self._extract_domain(from_header)
        rp_domain = self._extract_domain(return_path)

        if from_domain and rp_domain and from_domain != rp_domain:
            # Common in spoofing & phishing
            score += 25
            indicators.append(f"Domain mismatch between From (@{from_domain}) and Return-Path (@{rp_domain})")
            evidence["domain_alignment"] = f"mismatch: {from_domain} vs {rp_domain}"

        # 5. Received Chain Hop Count & Forgery
        received = email_data.get("received_chain", [])
        if len(received) > 7:
            score += 15
            indicators.append(f"Excessive relay hop count ({len(received)} hops) indicating multi-hop proxying")
            evidence["hop_count"] = len(received)
        elif len(received) == 0:
            score += 20
            indicators.append("Missing Received headers (forged or stripped trace)")
            evidence["hop_count"] = 0

        # 6. Direct IP Leaks / VPN indicators
        if email_data.get("x_originating_ip"):
            ip = str(email_data["x_originating_ip"])
            evidence["x_originating_ip"] = ip
            if ip.startswith("104.") or ip.startswith("172.") or ip.startswith("185."):
                score += 15
                indicators.append(f"Originating IP ({ip}) is within high-risk cloud/VPN hosting range")

        # 7. Urgent / Suspicious Subject Keywords (Metadata keyword scan)
        subject = str(email_data.get("subject", "")).lower()
        phish_keywords = ["urgent", "password reset", "account suspended", "verify your identity", "invoice overdue", "wire transfer", "action required", "login attempt", "security alert"]
        matched_keywords = [kw for kw in phish_keywords if kw in subject]
        if matched_keywords:
            score += 15
            indicators.append(f"High-urgency social engineering markers in subject: {', '.join(matched_keywords)}")
            evidence["subject_keywords"] = matched_keywords

        # 8. User-Agent / Mailer anomalies
        x_mailer = str(email_data.get("x_mailer", "")).lower()
        if any(tool in x_mailer for tool in ["phpmailer", "massmailer", "darkmailer", "sendgrid"]):
            if "phpmailer" in x_mailer or "darkmailer" in x_mailer:
                score += 20
                indicators.append(f"Suspicious automated bulk mailer software detected: {x_mailer}")

        final_score = min(score, 100)

        # Determine overall authentication status
        if spf == "pass" and dkim == "pass" and dmarc == "pass":
            auth_status = "pass"
        elif spf == "fail" or dkim == "fail" or dmarc == "fail":
            auth_status = "fail"
        else:
            auth_status = "partial"

        return {
            "authentication_status": auth_status,
            "suspicious_indicators": indicators if indicators else ["No explicit phishing markers detected"],
            "risk_score": final_score,
            "evidence": evidence
        }

    def _extract_domain(self, s: str) -> Optional[str]:
        if not s:
            return None
        match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', s)
        if match:
            return match.group(1).lower().strip()
        return None

    def _parse_crew_output(self, result: Any) -> Optional[Dict[str, Any]]:
        try:
            raw = str(result).strip()
            if "```json" in raw:
                raw = raw.split("```json")[1].split("```")[0].strip()
            elif "```" in raw:
                raw = raw.split("```")[1].split("```")[0].strip()
            return json.loads(raw)
        except Exception:
            return None

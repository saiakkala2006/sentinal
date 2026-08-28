"""
Adversarial Agent — 'Red team' agent that challenges detection decisions.
Enables self-healing through adversarial co-evolution.
Based on EvoMail's adversarial self-evolution loop.
"""

from typing import Dict, Any, List, Optional
import json
import os

try:
    from crewai import Agent, Task, Crew
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False


class AdversarialAgent:
    """
    Simulates red-team evasion techniques against current detection results
    to trigger proactive self-healing defense policies.
    """

    def challenge(self, detection_result: Dict[str, Any], email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Challenge detection findings to uncover evasion vectors.
        Feeds actionable weakness detections directly into the Self-Healing Engine.
        """
        # Run heuristic red-team challenge
        red_team_analysis = self._simulate_adversarial_evasion(detection_result, email_data)

        # Enhance with CrewAI if LLM available
        if CREWAI_AVAILABLE and os.getenv("OPENAI_API_KEY"):
            try:
                agent = Agent(
                    role="Red Team Hacker",
                    goal="Find ways an attacker could bypass detection and suggest defense improvements",
                    backstory="""You are an elite ethical red-teamer. You analyze 
                                email security detections to identify bypass blindspots.""",
                    verbose=False,
                    allow_delegation=False
                )
                task = Task(
                    description=f"""
                    Analyze this detection result:
                    - Indicators: {detection_result.get('suspicious_indicators', [])}
                    - Evidence: {detection_result.get('evidence', {})}
                    
                    Identify possible evasion techniques (e.g. timezone manipulation, domain spoofing, IP rotation).
                    Return JSON:
                    {{
                        "evasion_techniques": ["list", "of", "techniques"],
                        "weaknesses_found": ["list", "of", "weaknesses"],
                        "suggestions": ["list", "of", "mitigations"]
                    }}
                    """,
                    agent=agent,
                    expected_output="JSON with evasion_techniques, weaknesses_found, suggestions"
                )
                crew = Crew(agents=[agent], tasks=[task])
                res = crew.kickoff()
                parsed = self._parse_crew_output(res)
                if parsed and isinstance(parsed, dict) and "weaknesses_found" in parsed:
                    red_team_analysis["weaknesses_found"].extend(parsed.get("weaknesses_found", []))
                    red_team_analysis["evasion_techniques"].extend(parsed.get("evasion_techniques", []))
                    red_team_analysis["suggestions"].extend(parsed.get("suggestions", []))
            except Exception:
                pass

        return red_team_analysis

    def _simulate_adversarial_evasion(self, detection_result: Dict[str, Any], email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic adversarial scenario simulator."""
        evasion_techniques: List[str] = []
        weaknesses_found: List[str] = []
        suggestions: List[str] = []

        auth_status = detection_result.get("authentication_status", "pass")
        score = detection_result.get("risk_score", 0)

        # 1. Timezone manipulation vector
        evasion_techniques.append("Attacker adjusts sending SMTP timestamps to mimic victim business hours")
        weaknesses_found.append("Timezone-manipulation risk: Off-hours or weekend delivery evasion")
        suggestions.append("Apply dynamic off-hours Bayesian scoring and adjust suspicious hour matrix")

        # 2. Domain Lookalike / Typosquatting vector
        from_header = str(email_data.get("from", "")).lower()
        if "@" in from_header:
            domain = from_header.split("@")[1]
            if any(char.isdigit() for char in domain) or "-" in domain:
                evasion_techniques.append(f"Cousin domain / typosquatting camouflage: @{domain}")
                weaknesses_found.append(f"Domain spoofing vulnerability: {domain}")
                suggestions.append(f"Auto-blacklist compromised domain: {domain}")

        # 3. IP Rotation & Residential Proxying vector
        if email_data.get("x_originating_ip"):
            ip = str(email_data["x_originating_ip"])
            evasion_techniques.append(f"Residential proxy rotation across subnet {ip.rsplit('.', 1)[0]}.0/24")
            weaknesses_found.append("IP rotation bypass vector across residential egress")
            suggestions.append("Enforce strict subnet anomaly penalties for untrusted /24 prefixes")

        # 4. Hop Chain Stripping
        received = email_data.get("received_chain", [])
        if len(received) < 2:
            evasion_techniques.append("Stripped intermediate Received headers to conceal origin relay")
            weaknesses_found.append("Hop-chain forgery / header stripping vulnerability")
            suggestions.append("Penalize truncated relay headers with reduced baseline trust")

        # If high risk was detected, formulate direct patching cues
        if score > 50:
            weaknesses_found.append(f"Confirmed high-risk attack signature (score {score}) requiring domain quarantine")
            suggestions.append("Initiate autonomous self-healing policy update")

        return {
            "evasion_techniques": evasion_techniques,
            "weaknesses_found": weaknesses_found,
            "suggestions": suggestions
        }

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

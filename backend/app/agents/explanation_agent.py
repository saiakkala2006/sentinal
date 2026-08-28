"""
Explanation Agent — Generates concise, human-readable explanations for end users.
2-3 sentences max, zero technical jargon, clear actionable guidance.
"""

from typing import Dict, Any
import os

try:
    from crewai import Agent, Task, Crew
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False


class ExplanationAgent:
    """Translates forensic and behavioral findings into plain English."""

    def create_agent(self) -> Any:
        if not CREWAI_AVAILABLE:
            return None
        return Agent(
            role="Security Translator",
            goal="Explain technical email security findings in plain, actionable English",
            backstory="""You translate complex cybersecurity telemetry into 
                        simple, reassuring, and actionable language for business users.
                        You never use technical jargon. You tell users exactly 
                        why an email was flagged and what action is being taken.""",
            verbose=False,
            allow_delegation=False
        )

    def explain(self, risk_result: Dict[str, Any], email_data: Dict[str, Any], attribution: Dict[str, Any] = None) -> str:
        """Generate 2-3 sentence plain English explanation."""
        risk_score = risk_result.get("risk_score", 0)
        action = risk_result.get("recommended_action", "ALLOW")
        sender = email_data.get("from", "Unknown sender")
        subject = email_data.get("subject", "No subject")
        region = attribution.get("primary_region") if attribution else None

        # If CrewAI + API Key available, generate dynamic summary
        if CREWAI_AVAILABLE and os.getenv("OPENAI_API_KEY"):
            try:
                agent = self.create_agent()
                task = Task(
                    description=f"""
                    Explain this email threat in plain, actionable English:
                    - Risk Score: {risk_score}/100
                    - Action: {action}
                    - Sender: {sender}
                    - Subject: {subject}
                    - Attributed Origin: {region or 'Unknown'}
                    
                    Requirements:
                    1. 2 to 3 sentences MAXIMUM.
                    2. No technical acronyms (do not say SPF/DKIM/DMARC).
                    3. Clearly explain what Sentinel did and what the user should do.
                    """,
                    agent=agent,
                    expected_output="2-3 sentence plain English explanation"
                )
                crew = Crew(agents=[agent], tasks=[task])
                res = crew.kickoff()
                if res and len(str(res).strip()) > 10:
                    return str(res).strip()
            except Exception:
                pass

        # High-quality templated plain-English explanations
        if action == "QUARANTINE":
            region_str = f" originating from {region}" if region else ""
            return (
                f"Sentinel isolated this message from {sender}{region_str} because its sender identity could not be verified and shows high indicators of an imposter attack. "
                f"It has been quarantined safely away from your inbox. No action is required from you unless you wish to submit an admin release request."
            )
        elif action == "ALERT":
            return (
                f"This email from {sender} contains unusual transmission markers and deviates significantly from your normal communication patterns. "
                f"Sentinel has marked it with an alert banner. Please double-check the sender's identity before opening attachments or clicking links."
            )
        elif action == "REVIEW":
            return (
                f"We noticed this is a first-time sender or was sent at an atypical hour compared to your normal schedule. "
                f"The message is available in your inbox, but take a quick look to ensure the request is legitimate."
            )
        else:
            return (
                f"This email from {sender} matches your trusted behavioral profile and passed all security verification checks. "
                f"It has been delivered safely to your inbox."
            )

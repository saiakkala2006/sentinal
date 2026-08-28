"""
Pydantic models for email metadata and analysis results.
Strictly metadata-only — never contains email body or message payload.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class ReceivedHop(BaseModel):
    """Forensic breakdown of a single hop in the email's Received chain"""
    from_host: Optional[str] = Field(None, alias="from")
    by_host: Optional[str] = Field(None, alias="by")
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    with_protocol: Optional[str] = None
    id_header: Optional[str] = None

    class Config:
        populate_by_name = True


class AuthResults(BaseModel):
    """Authentication header results (SPF, DKIM, DMARC, ARC)"""
    spf: Dict[str, str] = Field(default_factory=dict)
    dkim: Dict[str, str] = Field(default_factory=dict)
    dmarc: Dict[str, str] = Field(default_factory=dict)
    arc: Optional[str] = None


class EmailMetadata(BaseModel):
    """Complete email forensic metadata (body-free)"""
    from_addr: Optional[str] = Field(None, alias="from")
    to: Optional[str] = None
    cc: Optional[str] = None
    bcc: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    in_reply_to: Optional[str] = None
    references: Optional[str] = None
    spf: Dict[str, str] = Field(default_factory=dict)
    dkim: Dict[str, str] = Field(default_factory=dict)
    dmarc: Dict[str, str] = Field(default_factory=dict)
    arc: Optional[str] = None
    x_originating_ip: Optional[str] = None
    x_sender_ip: Optional[str] = None
    x_forwarded_for: Optional[str] = None
    received_chain: List[Dict[str, Any]] = Field(default_factory=list)
    charset: Optional[str] = None
    content_language: Optional[str] = None
    content_type: Optional[str] = None
    received_timestamps: List[datetime] = Field(default_factory=list)
    return_path: Optional[str] = None
    user_agent: Optional[str] = None
    x_mailer: Optional[str] = None
    mime_version: Optional[str] = None

    class Config:
        populate_by_name = True


class AnalysisResult(BaseModel):
    """Complete multi-signal email security analysis result"""
    email_id: str
    filename: Optional[str] = None
    metadata: EmailMetadata
    anomaly_score: float = Field(..., description="Behavioral anomaly score (0.0 to 1.0)")
    detection_score: float = Field(..., description="Multi-agent detection score (0 to 100)")
    risk_score: float = Field(..., description="Weighted composite risk score (0 to 100)")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    severity_color: str = Field(..., description="red, orange, yellow, green")
    recommended_action: str = Field(..., description="QUARANTINE, ALERT, REVIEW, ALLOW")
    explanation: str
    attribution: Dict[str, Any]
    adversarial_feedback: Optional[Dict[str, Any]] = None
    healing_applied: bool = False
    healing_updates: List[Dict[str, Any]] = Field(default_factory=list)
    campaign_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class BatchAnalysisResult(BaseModel):
    """Batch analysis summary and list of results"""
    total_analyzed: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    quarantined_count: int
    campaigns_detected: int
    results: List[AnalysisResult]

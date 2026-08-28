"""
Pydantic models for the Digital Twin behavioral profile.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Set, Any
from datetime import datetime


class DigitalTwinProfile(BaseModel):
    """Behavioral profile for an individual user (privacy-preserving)"""
    user_id: str
    sending_hours: List[int] = Field(default_factory=list)
    sending_days: List[int] = Field(default_factory=list)
    sending_frequency: float = 0.0
    contacts: List[str] = Field(default_factory=list, description="SHA-256 hashed contact identifiers")
    ip_prefixes: List[str] = Field(default_factory=list, description="/24 masked anonymized IP prefixes")
    device_fingerprints: List[str] = Field(default_factory=list, description="Hashed User-Agent / X-Mailer")
    language_encodings: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    reply_patterns: List[float] = Field(default_factory=list)
    total_emails_analyzed: int = 0
    last_updated: Optional[str] = None
    anomaly_threshold: float = 0.5


class DigitalTwinSummary(BaseModel):
    """Summary of user's behavioral baseline for UI rendering"""
    user_id: str
    total_emails: int
    unique_contacts: int
    unique_ip_prefixes: int
    unique_domains: int
    typical_hours: List[int]
    typical_days: List[str]
    anomaly_threshold: float
    last_updated: Optional[str] = None


class AnomalyScoreResult(BaseModel):
    """Detailed dimension-by-dimension anomaly breakdown"""
    total_anomaly_score: float
    hour_score: float
    day_score: float
    contact_score: float
    ip_score: float
    language_score: float
    domain_score: float
    is_anomalous: bool
    reasons: List[str] = Field(default_factory=list)

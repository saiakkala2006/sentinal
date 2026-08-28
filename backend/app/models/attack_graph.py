"""
Pydantic models for Attack Graph and Threat Campaign correlation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class GraphNode(BaseModel):
    """Node in the D3 / NetworkX attack graph"""
    id: str
    type: str  # email, domain, ip, message_id_domain, return_path_domain
    label: str
    color: str
    size: int
    data: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Edge connecting email to indicator or indicator to indicator"""
    source: str
    target: str
    relationship: str = "uses"


class GraphVisualizationData(BaseModel):
    """Complete graph visualization data for D3.js frontend"""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    total_nodes: int
    total_edges: int


class CampaignInfo(BaseModel):
    """Coordinated phishing campaign cluster"""
    id: str
    name: Optional[str] = None
    emails: List[str]
    size: int
    shared_indicators: Dict[str, List[str]]
    primary_region: str
    confidence: float
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

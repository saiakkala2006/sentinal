"""
FastAPI Main Application — Project Sentinel Security Command API.
Integrates all 8 forensic, behavioral, multi-agent, Bayesian, attack graph, and self-healing pipelines.
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional, Dict, Any
import uuid
import json
import asyncio
from datetime import datetime

from .config import settings
from .models.email import EmailMetadata, AnalysisResult, BatchAnalysisResult
from .models.digital_twin import DigitalTwinSummary, AnomalyScoreResult
from .models.attack_graph import GraphVisualizationData, CampaignInfo

from .services.email_parser import EmailParser
from .services.digital_twin_builder import DigitalTwinBuilder
from .services.bayesian_attribution import BayesianAttributionEngine
from .services.attack_graph import AttackGraphBuilder
from .services.self_healing import SelfHealingEngine
from .services.multi_agent import MultiAgentOrchestrator

# Initialize FastAPI App
app = FastAPI(
    title="Sentinel — The Self-Healing Email Immune System",
    description="Privacy-preserving behavioral profiling, multi-agent detection, Bayesian attribution, and autonomous defense API",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-Memory State Engines (Global Singletons)
parser = EmailParser()
twin_builder = DigitalTwinBuilder(user_id="secops_admin")
attribution_engine = BayesianAttributionEngine()
graph_builder = AttackGraphBuilder()
self_healing = SelfHealingEngine(user_id="secops_admin")
multi_agent = MultiAgentOrchestrator()

# Store analyzed results in memory
analysis_history: List[Dict[str, Any]] = []

# WebSocket Connection Manager for Real-Time Streaming
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()


# Health Check & Root
@app.get("/")
async def root():
    return {
        "system": "Project Sentinel",
        "tagline": "The Self-Healing Email Immune System",
        "status": "OPERATIONAL",
        "version": settings.VERSION,
        "privacy": "Strictly Metadata-Only (Zero Body Access)"
    }


# Phase 7 & 1: POST /analyze — Single EML Upload
@app.post("/analyze", response_model=Dict[str, Any])
async def analyze_email(
    file: UploadFile = File(...),
    user_id: str = Form("secops_admin"),
    update_twin: bool = Form(True)
):
    """
    Analyze a single .eml file through the complete Sentinel pipeline:
    1. Parse headers (privacy-first, no body parsing)
    2. Compute Digital Twin behavioral anomaly score
    3. Run Bayesian multi-signal geolocation attribution
    4. Multi-agent detection, risk scoring, and explanation
    5. Ingest into NetworkX attack graph
    6. Autonomous self-healing policy update
    """
    try:
        content_bytes = await file.read()
        email_metadata = parser.parse(content_bytes)

        # 1. Digital Twin behavioral evaluation
        anomaly_breakdown = twin_builder.get_anomaly_breakdown(email_metadata)
        anomaly_score = anomaly_breakdown["total_anomaly_score"]

        # 2. Bayesian Attribution
        attribution = attribution_engine.attribute(email_metadata)

        # 3. Multi-Agent Orchestration
        agent_result = multi_agent.analyze(
            email_data=email_metadata,
            anomaly_score=anomaly_score,
            attribution=attribution
        )

        risk_data = agent_result["risk"]
        detection_data = agent_result["detection"]
        explanation = agent_result["explanation"]
        adversarial_feedback = agent_result["adversarial_feedback"]

        # 4. Ingest into behavioral twin baseline if marked or if safe
        if update_twin and risk_data["recommended_action"] == "ALLOW":
            twin_builder.update(email_metadata)

        # 5. Attack Graph Ingestion
        email_id = f"eml_{uuid.uuid4().hex[:10]}"
        graph_builder.add_email(
            email_id=email_id,
            email_data=email_metadata,
            attribution=attribution,
            risk_data=risk_data
        )

        # Check if email is part of a newly correlated campaign
        campaigns = graph_builder.find_campaigns()
        matched_campaign_id = None
        for camp in campaigns:
            if email_id in camp["emails"]:
                matched_campaign_id = camp["id"]
                break

        # 6. Autonomous Self-Healing Check
        healing_result = self_healing.heal(
            detection_result={
                "risk": risk_data,
                "anomaly_score": anomaly_score,
                "adversarial_feedback": adversarial_feedback
            },
            email_data=email_metadata,
            anomaly_score=anomaly_score
        )

        result_payload = {
            "email_id": email_id,
            "filename": file.filename,
            "metadata": email_metadata,
            "anomaly_score": anomaly_score,
            "anomaly_breakdown": anomaly_breakdown,
            "detection_score": detection_data.get("risk_score", 0),
            "risk_score": risk_data.get("risk_score", 0),
            "severity": risk_data.get("severity", "LOW"),
            "severity_color": risk_data.get("severity_color", "green"),
            "recommended_action": risk_data.get("recommended_action", "ALLOW"),
            "explanation": explanation,
            "attribution": attribution,
            "adversarial_feedback": adversarial_feedback,
            "healing_applied": healing_result.get("healing_applied", False),
            "healing_updates": healing_result.get("updates", []),
            "campaign_id": matched_campaign_id,
            "timestamp": datetime.now().isoformat()
        }

        # Store in historical log
        analysis_history.insert(0, result_payload)

        # Broadcast event to WebSocket subscribers
        await ws_manager.broadcast({
            "event": "NEW_ANALYSIS",
            "data": result_payload
        })

        return result_payload

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze email: {str(e)}")


# POST /analyze/batch — Multiple EML Uploads
@app.post("/analyze/batch", response_model=Dict[str, Any])
async def analyze_batch(
    files: List[UploadFile] = File(...),
    user_id: str = Form("secops_admin")
):
    """Batch analysis of multiple .eml files with campaign correlation."""
    results = []
    quarantined = 0
    critical = 0
    high = 0
    medium = 0
    low = 0

    for file in files:
        content = await file.read()
        email_metadata = parser.parse(content)
        anomaly_breakdown = twin_builder.get_anomaly_breakdown(email_metadata)
        anomaly_score = anomaly_breakdown["total_anomaly_score"]
        attribution = attribution_engine.attribute(email_metadata)

        agent_result = multi_agent.analyze(
            email_data=email_metadata,
            anomaly_score=anomaly_score,
            attribution=attribution
        )

        risk_data = agent_result["risk"]
        detection_data = agent_result["detection"]
        explanation = agent_result["explanation"]
        adversarial_feedback = agent_result["adversarial_feedback"]

        email_id = f"eml_{uuid.uuid4().hex[:10]}"
        graph_builder.add_email(
            email_id=email_id,
            email_data=email_metadata,
            attribution=attribution,
            risk_data=risk_data
        )

        healing_result = self_healing.heal(
            detection_result={
                "risk": risk_data,
                "anomaly_score": anomaly_score,
                "adversarial_feedback": adversarial_feedback
            },
            email_data=email_metadata,
            anomaly_score=anomaly_score
        )

        severity = risk_data.get("severity", "LOW")
        action = risk_data.get("recommended_action", "ALLOW")

        if severity == "CRITICAL":
            critical += 1
        elif severity == "HIGH":
            high += 1
        elif severity == "MEDIUM":
            medium += 1
        else:
            low += 1

        if action == "QUARANTINE":
            quarantined += 1

        res = {
            "email_id": email_id,
            "filename": file.filename,
            "metadata": email_metadata,
            "anomaly_score": anomaly_score,
            "anomaly_breakdown": anomaly_breakdown,
            "detection_score": detection_data.get("risk_score", 0),
            "risk_score": risk_data.get("risk_score", 0),
            "severity": severity,
            "severity_color": risk_data.get("severity_color", "green"),
            "recommended_action": action,
            "explanation": explanation,
            "attribution": attribution,
            "adversarial_feedback": adversarial_feedback,
            "healing_applied": healing_result.get("healing_applied", False),
            "healing_updates": healing_result.get("updates", []),
            "campaign_id": None,
            "timestamp": datetime.now().isoformat()
        }

        results.append(res)
        analysis_history.insert(0, res)

    # Re-evaluate campaign IDs
    campaigns = graph_builder.find_campaigns()
    for item in results:
        for camp in campaigns:
            if item["email_id"] in camp["emails"]:
                item["campaign_id"] = camp["id"]
                break

    batch_response = {
        "total_analyzed": len(results),
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "quarantined_count": quarantined,
        "campaigns_detected": len(campaigns),
        "results": results
    }

    await ws_manager.broadcast({
        "event": "BATCH_ANALYSIS_COMPLETE",
        "data": batch_response
    })

    return batch_response


# GET /dashboard/stats — High Level Metrics & Telemetry
@app.get("/dashboard/stats")
async def get_dashboard_stats():
    """Retrieve operational telemetry and detection statistics."""
    total = len(analysis_history)
    quarantined = sum(1 for item in analysis_history if item.get("recommended_action") == "QUARANTINE")
    alerts = sum(1 for item in analysis_history if item.get("recommended_action") == "ALERT")
    allowed = sum(1 for item in analysis_history if item.get("recommended_action") == "ALLOW")

    campaigns = graph_builder.find_campaigns()
    policies_data = self_healing.get_policies()

    # Region breakdown
    region_counts = {}
    for item in analysis_history:
        reg = item.get("attribution", {}).get("primary_region", "Unknown")
        region_counts[reg] = region_counts.get(reg, 0) + 1

    return {
        "total_emails_analyzed": total,
        "quarantined_count": quarantined,
        "alert_count": alerts,
        "allowed_count": allowed,
        "active_campaigns_count": len(campaigns),
        "self_healing_events_count": policies_data["policies"]["healing_count"],
        "blocked_domains_count": len(policies_data["policies"]["blocked_domains"]),
        "region_distribution": region_counts,
        "recent_results": analysis_history[:10],
        "top_campaigns": campaigns[:5]
    }


# GET /dashboard/graph — D3 Force-Directed Graph Data
@app.get("/dashboard/graph")
async def get_dashboard_graph():
    """Returns nodes and edges formatted for D3.js force-directed graph."""
    return graph_builder.get_visualization_data()


# GET /dashboard/campaigns — Full Campaign Clusters List
@app.get("/dashboard/campaigns")
async def get_dashboard_campaigns():
    """Returns all identified coordinated phishing campaigns."""
    return graph_builder.get_campaign_summary()


# GET /policies — Current Self-Healing Policies
@app.get("/policies")
async def get_policies():
    """Returns current active self-healing policies and audit trail."""
    return self_healing.get_policies()


# POST /digital-twin/train-seed — Seed Baseline Profile
@app.post("/digital-twin/train-seed")
async def seed_digital_twin():
    """Seed sample normal enterprise communication baseline into Digital Twin."""
    sample_seeds = [
        {"from": "colleague@acme.com", "to": "user@acme.com", "date": "Mon, 18 Aug 2026 09:30:00 +0000", "charset": "utf-8", "x_originating_ip": "192.168.1.50"},
        {"from": "manager@acme.com", "to": "user@acme.com", "date": "Tue, 19 Aug 2026 14:15:00 +0000", "charset": "utf-8", "x_originating_ip": "192.168.1.52"},
        {"from": "hr@acme.com", "to": "user@acme.com", "date": "Wed, 20 Aug 2026 11:00:00 +0000", "charset": "utf-8", "x_originating_ip": "192.168.1.55"},
        {"from": "client@partner.org", "to": "user@acme.com", "date": "Thu, 21 Aug 2026 16:45:00 +0000", "charset": "utf-8", "x_originating_ip": "10.0.5.20"},
        {"from": "finance@acme.com", "to": "user@acme.com", "date": "Fri, 22 Aug 2026 10:20:00 +0000", "charset": "utf-8", "x_originating_ip": "192.168.1.58"},
        {"from": "support@saas-tool.io", "to": "user@acme.com", "date": "Mon, 25 Aug 2026 15:10:00 +0000", "charset": "utf-8", "x_originating_ip": "172.16.0.10"}
    ]
    for s in sample_seeds:
        twin_builder.update(s)

    return {
        "status": "SEEDED",
        "summary": twin_builder.get_profile_summary()
    }


# GET /digital-twin/{user_id} — Behavioral Profile Summary
@app.get("/digital-twin/{user_id}")
async def get_digital_twin_profile(user_id: str):
    """Retrieve summary of user's behavioral digital twin baseline."""
    return twin_builder.get_profile_summary()


# WS /ws — Real-time stream for Dashboard
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial status
        await websocket.send_json({
            "event": "CONNECTED",
            "message": "Connected to Sentinel Real-Time Telemetry Stream",
            "active_nodes": len(graph_builder.graph.nodes),
            "healing_events": self_healing.healing_events
        })
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"event": "PONG"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

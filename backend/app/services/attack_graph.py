"""
Attack Graph Correlator — Links multiple emails to coordinated threat campaigns.
Uses NetworkX for graph centrality, connected components, and D3 force-graph formatting.
"""

import networkx as nx
from typing import Dict, Any, List, Set, Optional
from collections import defaultdict
import hashlib
import re


class AttackGraphBuilder:
    """
    Builds and queries an in-memory threat correlation graph.
    Identifies multi-vector phishing campaigns via shared infrastructure clustering.
    """

    def __init__(self):
        self.graph = nx.Graph()
        self.email_nodes: Set[str] = set()
        self.indicator_nodes: Set[str] = set()

    def add_email(self, email_id: str, email_data: Dict[str, Any], attribution: Dict[str, Any], risk_data: Optional[Dict[str, Any]] = None) -> None:
        """Add an email and its infrastructure nodes to the attack graph."""
        severity = risk_data.get("severity", "LOW") if risk_data else "LOW"
        risk_score = risk_data.get("risk_score", 0.0) if risk_data else 0.0

        # 1. Add Email Node
        self.graph.add_node(
            email_id,
            type="email",
            label=f"Email: {email_data.get('subject', 'No Subject')[:24]}",
            from_addr=email_data.get("from", "unknown"),
            subject=email_data.get("subject", ""),
            region=attribution.get("primary_region", "Unknown"),
            confidence=attribution.get("confidence", 0),
            severity=severity,
            risk_score=risk_score,
            timestamp=email_data.get("date", "")
        )
        self.email_nodes.add(email_id)

        # 2. Extract Infrastructure Indicators
        indicators = self._extract_indicators(email_data)

        # 3. Add Indicator Nodes & Link Edges
        for ind_type, value in indicators.items():
            if value:
                node_id = f"{ind_type}:{self._hash_string(value)}"
                if not self.graph.has_node(node_id):
                    self.graph.add_node(
                        node_id,
                        type=ind_type,
                        value=value,
                        label=f"{ind_type.replace('_', ' ').title()}: {value[:28]}"
                    )
                    self.indicator_nodes.add(node_id)
                self.graph.add_edge(email_id, node_id, relationship="uses")

    def _extract_indicators(self, email_data: Dict[str, Any]) -> Dict[str, str]:
        """Extract domain, IP, message-id domain, and return-path domain."""
        indicators: Dict[str, str] = {}

        # Sender domain
        from_addr = str(email_data.get("from", ""))
        from_dom = self._extract_domain(from_addr)
        if from_dom:
            indicators["domain"] = from_dom

        # Origin IP (from leaks or first hop)
        for ip_field in ["x_originating_ip", "x_sender_ip", "x_forwarded_for"]:
            ip_val = email_data.get(ip_field)
            if ip_val:
                indicators["ip"] = str(ip_val)
                break

        if "ip" not in indicators:
            received = email_data.get("received_chain", [])
            for hop in received:
                if isinstance(hop, dict) and hop.get("ip"):
                    indicators["ip"] = str(hop["ip"])
                    break

        # Message-ID domain
        msg_id = str(email_data.get("message_id", ""))
        if "@" in msg_id:
            parts = msg_id.split("@")
            if len(parts) > 1:
                indicators["message_id_domain"] = parts[1].replace(">", "").strip().lower()

        # Return-Path domain
        rp = str(email_data.get("return_path", ""))
        rp_dom = self._extract_domain(rp)
        if rp_dom:
            indicators["return_path_domain"] = rp_dom

        return indicators

    def find_campaigns(self) -> List[Dict[str, Any]]:
        """
        Identify clusters of emails sharing common infrastructure.
        Uses NetworkX connected components.
        """
        campaigns: List[Dict[str, Any]] = []
        if len(self.graph.nodes) == 0:
            return campaigns

        components = list(nx.connected_components(self.graph))

        for idx, component in enumerate(components):
            email_members = [
                n for n in component
                if self.graph.nodes[n].get("type") == "email"
            ]

            if len(email_members) >= 2:
                shared_inds = self._find_shared_indicators(email_members)
                primary_region = self._majority_region(email_members)
                conf = self._campaign_confidence(email_members, shared_inds)
                first_seen = self._get_first_seen(email_members)
                last_seen = self._get_last_seen(email_members)
                campaign_id = f"CAMP-{self._hash_string(str(sorted(email_members)))[:8].upper()}"

                campaigns.append({
                    "id": campaign_id,
                    "name": f"Campaign {primary_region} #{idx+1}",
                    "emails": email_members,
                    "size": len(email_members),
                    "shared_indicators": shared_inds,
                    "primary_region": primary_region,
                    "confidence": conf,
                    "first_seen": first_seen,
                    "last_seen": last_seen
                })

        campaigns.sort(key=lambda c: (c["size"], c["confidence"]), reverse=True)
        return campaigns

    def _find_shared_indicators(self, emails: List[str]) -> Dict[str, List[str]]:
        """Identify infrastructure nodes connected to 2 or more emails."""
        shared = defaultdict(set)
        counts = defaultdict(int)

        for email_id in emails:
            if not self.graph.has_node(email_id):
                continue
            neighbors = list(self.graph.neighbors(email_id))
            for nbr in neighbors:
                ntype = self.graph.nodes[nbr].get("type")
                val = self.graph.nodes[nbr].get("value")
                if ntype and ntype != "email" and val:
                    shared[ntype].add(val)
                    counts[(ntype, val)] += 1

        result: Dict[str, List[str]] = {}
        for ind_type, vals in shared.items():
            common_vals = [v for v in vals if counts[(ind_type, v)] >= 2]
            if common_vals:
                result[ind_type] = common_vals

        return result

    def _majority_region(self, emails: List[str]) -> str:
        regions = []
        for e in emails:
            r = self.graph.nodes[e].get("region", "Unknown")
            if r and r != "Unknown":
                regions.append(r)
        if regions:
            return max(set(regions), key=regions.count)
        return "Unknown"

    def _campaign_confidence(self, emails: List[str], shared_indicators: Dict[str, List[str]]) -> float:
        email_factor = min(len(emails) / 5.0, 1.0) * 45.0
        total_shared = sum(len(v) for v in shared_indicators.values())
        indicator_factor = min(total_shared / 3.0, 1.0) * 55.0
        return round(min(email_factor + indicator_factor, 99.0), 1)

    def _get_first_seen(self, emails: List[str]) -> Optional[str]:
        ts = [self.graph.nodes[e].get("timestamp") for e in emails if self.graph.nodes[e].get("timestamp")]
        return min(ts) if ts else None

    def _get_last_seen(self, emails: List[str]) -> Optional[str]:
        ts = [self.graph.nodes[e].get("timestamp") for e in emails if self.graph.nodes[e].get("timestamp")]
        return max(ts) if ts else None

    def get_visualization_data(self) -> Dict[str, Any]:
        """Format nodes and edges for D3.js force-directed graph."""
        nodes = []
        edges = []

        colors = {
            "email": "#38BDF8",              # Sky blue
            "domain": "#34D399",             # Emerald green
            "ip": "#FBBF24",                 # Amber
            "message_id_domain": "#A78BFA",  # Purple
            "return_path_domain": "#F87171"  # Coral red
        }

        sizes = {
            "email": 14,
            "domain": 10,
            "ip": 10,
            "message_id_domain": 8,
            "return_path_domain": 8
        }

        for node in self.graph.nodes():
            nd = self.graph.nodes[node]
            ntype = nd.get("type", "unknown")
            nodes.append({
                "id": str(node),
                "type": ntype,
                "label": nd.get("label", str(node)[:20]),
                "color": colors.get(ntype, "#94A3B8"),
                "size": sizes.get(ntype, 8),
                "data": {
                    "subject": nd.get("subject", ""),
                    "from": nd.get("from_addr", ""),
                    "region": nd.get("region", ""),
                    "severity": nd.get("severity", ""),
                    "risk_score": nd.get("risk_score", 0.0),
                    "value": nd.get("value", "")
                }
            })

        for u, v, d in self.graph.edges(data=True):
            edges.append({
                "source": str(u),
                "target": str(v),
                "relationship": d.get("relationship", "uses")
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }

    def get_campaign_summary(self) -> Dict[str, Any]:
        campaigns = self.find_campaigns()
        return {
            "total_campaigns": len(campaigns),
            "total_emails_analyzed": len(self.email_nodes),
            "total_indicators": len(self.indicator_nodes),
            "campaigns": campaigns
        }

    def _extract_domain(self, s: str) -> Optional[str]:
        if not s:
            return None
        match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', s)
        if match:
            return match.group(1).lower().strip()
        return None

    def _hash_string(self, s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]

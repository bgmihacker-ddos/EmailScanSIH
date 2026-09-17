"""
Phase 11: Evidence Graph Service.

Builds a relationship graph connecting all entities observed in an email
analysis: sender, domains, IPs, URLs, attachments, and their relationships.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from datetime import datetime, timezone


class EvidenceGraphBuilder:
    """Builds an evidence relationship graph from analysis results."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[Dict[str, Any]] = []
        self._node_counter = 0

    def _add_node(self, node_type: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Add a node to the graph, return its ID."""
        key = f"{node_type}:{value.lower()}"
        if key in self._nodes:
            return self._nodes[key]["id"]

        self._node_counter += 1
        node_id = f"node_{self._node_counter:04d}"

        self._nodes[key] = {
            "id": node_id,
            "type": node_type,
            "value": value,
            "metadata": metadata or {},
            "added_at": datetime.now(timezone.utc).isoformat(),
        }
        return node_id

    def _add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        confidence: int = 50,
        source: Optional[str] = None,
    ) -> None:
        """Add an edge (relationship) between two nodes."""
        edge_id = hashlib.sha256(
            f"{source_id}:{target_id}:{relationship}".encode()
        ).hexdigest()[:12]

        self._edges.append({
            "id": edge_id,
            "source": source_id,
            "target": target_id,
            "relationship": relationship,
            "confidence": confidence,
            "provenance": source or "evidence_graph",
            "added_at": datetime.now(timezone.utc).isoformat(),
        })

    def build_from_analysis(
        self,
        addresses: Dict[str, Any],
        header_forensics: Dict[str, Any],
        authentication: Dict[str, Any],
        iocs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build evidence graph from analysis results."""
        # 1. Add sender nodes
        from_addr = addresses.get("from")
        if from_addr:
            if isinstance(from_addr, list) and from_addr:
                from_addr = from_addr[0]
            if isinstance(from_addr, dict):
                display = from_addr.get("display_name")
                addr = from_addr.get("address")
                domain = from_addr.get("domain")

                if display:
                    self._add_node("display_name", display, {"original": display})

                if addr:
                    node_id = self._add_node("email_address", addr, {"category": "from"})
                    if domain:
                        self._add_node("domain", domain, {"category": "sender"})

                if domain:
                    from_node = self._add_node("domain", domain, {"category": "sender"})
                    if addr:
                        self._add_edge(
                            from_node,
                            self._add_node("email_address", addr),
                            "owns",
                            confidence=80,
                            source="addresses",
                        )

        # 2. Add Reply-To relationships
        reply_to_list = addresses.get("reply_to", [])
        if reply_to_list:
            if isinstance(reply_to_list, list) and reply_to_list:
                first_reply = reply_to_list[0]
                if isinstance(first_reply, dict):
                    reply_addr = first_reply.get("address")
                    reply_domain = first_reply.get("domain")
                    if reply_addr:
                        self._add_node("email_address", reply_addr, {"category": "reply_to"})
                    if reply_domain:
                        reply_node = self._add_node("domain", reply_domain, {"category": "reply"})
                        if reply_addr:
                            self._add_edge(
                                reply_node,
                                self._add_node("email_address", reply_addr),
                                "owns",
                                confidence=80,
                                source="addresses",
                            )
                        if from_domain := (addresses.get("from") or {}).get("domain"):
                            self._add_edge(
                                self._add_node("domain", from_domain),
                                reply_node,
                                "divergent_from",
                                confidence=95 if from_domain != reply_domain else 50,
                                source="domain_relationships",
                            )

        # 3. Add Return-Path relationship
        return_path = addresses.get("return_path")
        if return_path:
            if isinstance(return_path, dict):
                rp_addr = return_path.get("address")
                rp_domain = return_path.get("domain")
                if rp_domain:
                    rp_node = self._add_node("domain", rp_domain, {"category": "return_path"})
                    if rp_addr:
                        self._add_edge(
                            rp_node,
                            self._add_node("email_address", rp_addr),
                            "owns",
                            confidence=85,
                            source="addresses",
                        )
                if from_domain := (addresses.get("from") or {}).get("domain"):
                    if rp_domain and rp_domain != from_domain:
                        self._add_edge(
                            self._add_node("domain", from_domain),
                            rp_node,
                            "divergent_from",
                            confidence=80,
                            source="domain_relationships",
                        )

        # 4. Add IP addresses from mail flow
        ip_classifications = header_forensics.get("ip_classifications", [])
        for ip_entry in ip_classifications:
            if isinstance(ip_entry, dict):
                ip_value = ip_entry.get("ip")
                if ip_value:
                    self._add_node(
                        "ip_address",
                        ip_value,
                        {
                            "classification": ip_entry.get("classification"),
                            "version": ip_entry.get("version"),
                        },
                    )

        # 5. Add URL nodes
        extracted_iocs = iocs.get("iocs", [])
        for ioc in extracted_iocs:
            if isinstance(ioc, dict):
                ioc_type = ioc.get("type")
                ioc_value = ioc.get("value")

                if ioc_type == "url" and ioc_value:
                    url_node = self._add_node("url", ioc_value)
                    if domain := ioc.get("domain"):
                        dom_node = self._add_node("domain", domain)
                        self._add_edge(
                            url_node,
                            dom_node,
                            "hosts_on",
                            confidence=95,
                            source="url_analysis",
                        )
                    ip = ioc.get("ip")
                    if ip:
                        self._add_edge(
                            url_node,
                            self._add_node("ip_address", ip),
                            "resolves_to",
                            confidence=85,
                            source="url_analysis",
                        )

                elif ioc_type == "domain" and ioc_value:
                    self._add_node("domain", ioc_value)

                elif ioc_type == "ip" and ioc_value:
                    self._add_node("ip_address", ioc_value)

        # 6. Add attachment hashes
        attachment_analysis = iocs.get("attachments", {})
        for att in attachment_analysis.get("attachments", []):
            if isinstance(att, dict):
                sha256 = att.get("sha256")
                if sha256:
                    self._add_node(
                        "file_hash",
                        sha256,
                        {"type": "sha256", "category": "attachment"},
                    )
                filename = att.get("filename") or att.get("name")
                if filename:
                    self._add_node("filename", filename, {"category": "attachment"})

        # 7. Build result
        return {
            "nodes": list(self._nodes.values()),
            "edges": self._edges,
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "summary": self._generate_summary(),
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate graph summary statistics."""
        by_type: Dict[str, int] = {}
        for node in self._nodes.values():
            node_type = node.get("type", "unknown")
            by_type[node_type] = by_type.get(node_type, 0) + 1

        by_relationship: Dict[str, int] = {}
        for edge in self._edges:
            rel = edge.get("relationship", "unknown")
            by_relationship[rel] = by_relationship.get(rel, 0) + 1

        return {
            "node_types": by_type,
            "relationship_types": by_relationship,
            "graph_density": (
                len(self._edges) / max(1, len(self._nodes) * (len(self._nodes) - 1) / 2)
                if len(self._nodes) > 1
                else 0
            ),
        }


def build_evidence_graph(
    addresses: Dict[str, Any],
    header_forensics: Dict[str, Any],
    authentication: Dict[str, Any],
    iocs: Dict[str, Any],
) -> Dict[str, Any]:
    """Convenience function to build evidence graph."""
    builder = EvidenceGraphBuilder()
    return builder.build_from_analysis(addresses, header_forensics, authentication, iocs)
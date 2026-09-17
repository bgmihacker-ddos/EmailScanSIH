# AUDIT SCRIPT: Timeline & Correlation Engine
# Importers/Callers: backend/app/api/routes/investigation.py, backend/tests/test_timeline_correlation.py
# Affected API: /api/v1/investigation/*
# Data schemas: TimelineEvent, ForensicRelationship, InvestigationPath
# Verbatim instruction: "Turn the P11 Forensic Evidence Graph + Chain of Custody into a deterministic investigator-oriented timeline and correlation engine."

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from app.schemas.evidence import EvidenceManifest, EvidenceNode
from app.schemas.timeline import (
    TimelineEvent, TimelineEventType, TimestampPrecision,
    ForensicRelationship, RelationshipType, InvestigationTimeline, InvestigationCorrelations, InvestigationPath
)
from app.services.evidence_canonicalizer import EvidenceCanonicalizer

logger = logging.getLogger(__name__)

class TimelineCorrelationEngine:
    def __init__(self, manifest: EvidenceManifest):
        self.manifest = manifest
        self.case_id = manifest.case_id

    def build_timeline(self) -> InvestigationTimeline:
        events = []
        from email.utils import parsedate_to_datetime
        from datetime import timezone

        for custody_event in self.manifest.chain_of_custody:
            evidence_node = self.manifest.nodes.get(custody_event.evidence_id)
            if not evidence_node:
                continue

            # 1. Inject physical forensic timeline events (if discovery/parsed)
            if custody_event.event_type.value in ("ACQUIRED", "PARSED"):
                if evidence_node.evidence_type.value == "RELAY_HOP":
                    hop_ts = evidence_node.attributes.get("timestamp_utc") or evidence_node.attributes.get("timestamp")
                    if hop_ts:
                        try:
                            ts = datetime.fromisoformat(str(hop_ts).replace("Z", "+00:00"))
                            if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
                            events.append(TimelineEvent(
                                event_id=EvidenceCanonicalizer.compute_sha256({"hop_ts": ts.isoformat(), "node": evidence_node.node_id}),
                                case_id=self.case_id,
                                evidence_id=evidence_node.node_id,
                                event_type=TimelineEventType.RECEIVED_HOP_OBSERVED,
                                timestamp=ts,
                                timestamp_precision=TimestampPrecision.SECOND,
                                title=f"Relay Hop: {evidence_node.attributes.get('from_server', '')} -> {evidence_node.attributes.get('by_server', '')}",
                                description=f"Email traversed network hop",
                                source="received_chain",
                                provenance_class=evidence_node.provenance,
                                actor=custody_event.actor,
                                event_hash=EvidenceCanonicalizer.compute_sha256({"ts": ts.isoformat(), "source": "hop"})
                            ))
                        except Exception: pass
                elif evidence_node.evidence_type.value == "EMAIL":
                    email_ts = evidence_node.attributes.get("date")
                    if email_ts:
                        try:
                            ts = parsedate_to_datetime(email_ts)
                            if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
                            events.append(TimelineEvent(
                                event_id=EvidenceCanonicalizer.compute_sha256({"email_ts": ts.isoformat(), "node": evidence_node.node_id}),
                                case_id=self.case_id,
                                evidence_id=evidence_node.node_id,
                                event_type=TimelineEventType.EMAIL_ACQUIRED,
                                timestamp=ts,
                                timestamp_precision=TimestampPrecision.MINUTE,
                                title=f"Email Sent: {evidence_node.attributes.get('subject', 'No Subject')}",
                                description=f"Sender-reported send time",
                                source="email_header",
                                provenance_class=evidence_node.provenance,
                                actor=custody_event.actor,
                                event_hash=EvidenceCanonicalizer.compute_sha256({"ts": ts.isoformat(), "source": "email_header"})
                            ))
                        except Exception: pass

            # 2. Add analysis event
            event_type = self._map_custody_to_timeline(custody_event.event_type, evidence_node)
            events.append(TimelineEvent(
                event_id=EvidenceCanonicalizer.compute_sha256({"custody_id": custody_event.event_id}),
                case_id=self.case_id,
                evidence_id=custody_event.evidence_id,
                event_type=event_type,
                timestamp=custody_event.timestamp,
                timestamp_precision=TimestampPrecision.EXACT,
                title=f"Analysis: {evidence_node.evidence_type.value} {custody_event.event_type.value}",
                description=str(custody_event.details.get("value", "No description"))[:200],
                source=evidence_node.source,
                provenance_class=evidence_node.provenance,
                actor=custody_event.actor,
                event_hash=EvidenceCanonicalizer.compute_sha256(custody_event.model_dump())
            ))

        # Sort chronologically, then by type, then by id for determinism
        events.sort(key=lambda e: (e.timestamp, e.event_type, e.event_id))

        return InvestigationTimeline(case_id=self.case_id, events=events)

    def build_correlations(self) -> InvestigationCorrelations:
        from app.schemas.evidence import EvidenceType
        relationships = []
        seen = set()

        def add_relationship(rel_type: RelationshipType, source_id: str, target_id: str, provenance):
            sig = f"{source_id}-{rel_type.value}-{target_id}"
            if sig in seen:
                return
            seen.add(sig)
            relationships.append(ForensicRelationship(
                relationship_id=EvidenceCanonicalizer.compute_sha256(sig),
                source_evidence_id=source_id,
                target_evidence_id=target_id,
                relationship_type=rel_type,
                provenance=provenance
            ))

        # Forensic Correlation Mapping
        for node_id, node in self.manifest.nodes.items():
            if node.parent_id:
                add_relationship(RelationshipType.DERIVED_FROM, node.parent_id, node.node_id, node.provenance)

            # Additional forensic correlations (e.g., threat intel -> findings)
            if node.evidence_type == EvidenceType.THREAT_INTEL_RESULT:
                # Correlate with associated IP/URL if present in attributes
                attrs = node.attributes
                if "indicator" in attrs:
                    indicator = attrs["indicator"]
                    for other_id, other_node in self.manifest.nodes.items():
                        if other_node.value == indicator and other_id != node_id:
                            add_relationship(RelationshipType.INDICATES, node.node_id, other_id, node.provenance)

        return InvestigationCorrelations(case_id=self.case_id, relationships=relationships)

    def build_attack_path(self, correlations: InvestigationCorrelations) -> InvestigationPath:
        from app.schemas.timeline import InvestigationStep
        # Build directed adjacency list from correlations
        adj: Dict[str, List[ForensicRelationship]] = {}
        for rel in correlations.relationships:
            adj.setdefault(rel.source_evidence_id, []).append(rel)
            # Also consider reverse traversal for some relationships if desired, but DFS typically follows directed edges

        steps = {}
        visited = set()

        def dfs(node_id: str, depth: int = 0):
            if node_id in visited or depth > 100:
                return
            visited.add(node_id)
            node = self.manifest.nodes.get(node_id)
            if not node:
                return

            next_steps = []
            for rel in adj.get(node_id, []):
                next_steps.append(rel.target_evidence_id)
                dfs(rel.target_evidence_id, depth + 1)

            # For simplicity, represent each path step as the node
            steps[node_id] = InvestigationStep(
                step_id=node_id,
                evidence_id=node_id,
                description=f"{node.evidence_type.value}: {node.value}",
                next_steps=next_steps,
                metadata=node.attributes
            )

        # Start traversal from root evidence nodes (i.e. EMAIL)
        for root_id in self.manifest.root_evidence_ids:
            dfs(root_id)

        # Reverse edges (e.g. DERIVED_FROM points from child to parent, so we traverse backwards)
        # Actually our DERIVED_FROM is target = child, source = parent. Wait:
        # source_evidence_id=node.parent_id, target_evidence_id=node.node_id
        # Yes, so root -> children traversal works natively.

        root_node_id = self.manifest.root_evidence_ids[0] if self.manifest.root_evidence_ids else None

        return InvestigationPath(case_id=self.case_id, root_step_id=root_node_id, steps=steps)

    def _map_custody_to_timeline(self, custody_type: Any, node: EvidenceNode) -> TimelineEventType:
        from app.schemas.evidence import EvidenceType
        mapping = {
            EvidenceType.EMAIL: TimelineEventType.EMAIL_PARSED,
            EvidenceType.RELAY_HOP: TimelineEventType.RECEIVED_HOP_OBSERVED,
            EvidenceType.AUTHENTICATION_RESULT: TimelineEventType.AUTHENTICATION_ANALYZED,
            EvidenceType.IP: TimelineEventType.ORIGIN_IP_IDENTIFIED,
            EvidenceType.URL: TimelineEventType.URL_EXTRACTED,
            EvidenceType.DOMAIN: TimelineEventType.DOMAIN_ANALYZED,
            EvidenceType.THREAT_INTEL_RESULT: TimelineEventType.THREAT_INTEL_ENRICHED,
            EvidenceType.ATTACHMENT: TimelineEventType.ATTACHMENT_IDENTIFIED,
            EvidenceType.STATIC_ATTACHMENT_FINDING: TimelineEventType.ATTACHMENT_STATIC_ANALYZED,
            EvidenceType.ML_FINDING: TimelineEventType.ML_ANALYZED,
            EvidenceType.BEC_FINDING: TimelineEventType.BEC_ANALYZED,
            EvidenceType.RISK_FINDING: TimelineEventType.RISK_FUSED,
        }
        return mapping.get(node.evidence_type, TimelineEventType.EVIDENCE_VERIFIED)

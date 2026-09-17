# AUDIT SCRIPT: Evidence Graph V2 & Chain of Custody Service
# Importers/Callers: backend/app/api/routes/analysis.py, backend/app/services/case_service.py, tests/test_evidence_custody.py
# Affected API: /api/v1/evidence/manifest, /api/v1/evidence/validate, Case Evidence Graph endpoints
# Data schemas: EvidenceNode, CustodyEvent, EvidenceManifest
# Verbatim instruction: "Standardize EvidenceNode abstractions across defined evidence types... Implement deterministic cryptographic SHA-256 serialization... Implement append-only cryptographic Chain of Custody event chaining... Implement tamper detection and validation APIs, Case & Timeline integration, and deterministic Case Evidence Manifest generation."

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.evidence import (
    EvidenceNode,
    CustodyEvent,
    EvidenceManifest,
    EvidenceType,
    ProvenanceClass,
    CustodyEventType,
)
from app.services.evidence_canonicalizer import EvidenceCanonicalizer

logger = logging.getLogger(__name__)

class EvidenceGraphV2Builder:
    """
    Builds a deterministic, cryptographically verifiable forensic evidence graph,
    lineage tree, and append-only chain of custody.
    """

    def __init__(self, case_id: str, actor: str = "system:pipeline"):
        self.case_id = case_id
        self.actor = actor
        self.nodes: Dict[str, EvidenceNode] = {}
        self.chain_of_custody: List[CustodyEvent] = []
        self._last_event_hash_by_evidence: Dict[str, str] = {}
        self.root_evidence_ids: List[str] = []

    def add_evidence(
        self,
        evidence_type: EvidenceType,
        value: str,
        provenance: ProvenanceClass,
        source: str,
        parent_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        confidence: Optional[int] = None
    ) -> EvidenceNode:
        """
        Creates or retrieves an EvidenceNode, computes its canonical node_id,
        and appends ACQUIRED / PARSED custody events.
        """
        attributes_clean = attributes or {}
        node_id = EvidenceCanonicalizer.compute_node_id(
            evidence_type=evidence_type,
            value=value,
            source=source,
            provenance=provenance,
            parent_id=parent_id,
            attributes=attributes_clean
        )

        if node_id in self.nodes:
            return self.nodes[node_id]

        node = EvidenceNode(
            node_id=node_id,
            parent_id=parent_id,
            evidence_type=evidence_type,
            provenance=provenance,
            value=str(value),
            attributes=attributes_clean,
            source=source,
            confidence=confidence
        )
        self.nodes[node_id] = node

        if not parent_id and node_id not in self.root_evidence_ids:
            self.root_evidence_ids.append(node_id)

        # Record initial ACQUIRED/PARSED custody event
        ev_type = CustodyEventType.ACQUIRED if not parent_id else CustodyEventType.PARSED
        self._append_custody_event(
            evidence_id=node_id,
            event_type=ev_type,
            details={"value": value, "source": source, "provenance": provenance}
        )

        return node

    def _append_custody_event(
        self,
        evidence_id: str,
        event_type: CustodyEventType,
        details: Optional[Dict[str, Any]] = None
    ) -> CustodyEvent:
        prev_hash = self._last_event_hash_by_evidence.get(evidence_id)
        event = EvidenceCanonicalizer.create_custody_event(
            evidence_id=evidence_id,
            event_type=event_type,
            actor=self.actor,
            previous_event_hash=prev_hash,
            details=details
        )
        self.chain_of_custody.append(event)
        self._last_event_hash_by_evidence[evidence_id] = event.event_id
        return event

    def enrich_evidence(
        self,
        evidence_id: str,
        enrichment_source: str,
        details: Dict[str, Any]
    ) -> Optional[CustodyEvent]:
        """
        Appends an ENRICHED or ANALYZED custody event to an existing evidence node.
        """
        if evidence_id not in self.nodes:
            logger.warning(f"Attempted to enrich non-existent evidence node {evidence_id}")
            return None
        return self._append_custody_event(
            evidence_id=evidence_id,
            event_type=CustodyEventType.ENRICHED,
            details={"source": enrichment_source, **details}
        )

    def build_from_full_analysis(self, raw_email_content: str, analysis_result: Dict[str, Any]) -> EvidenceManifest:
        """
        Builds the complete evidence lineage and custody graph from a processed email analysis result.
        """
        # 1. Root Email Node
        email_meta = analysis_result.get("email", {})
        email_subject = email_meta.get("subject", "Unknown Subject")
        email_sender = email_meta.get("sender", "unknown@domain.com")

        email_node = self.add_evidence(
            evidence_type=EvidenceType.EMAIL,
            value=email_sender,
            provenance=ProvenanceClass.OBSERVED,
            source="email_parser",
            attributes={
                "subject": email_subject,
                "message_id": email_meta.get("message_id"),
                "raw_size": len(raw_email_content)
            }
        )
        email_id = email_node.node_id

        # Hashed custody event for raw email
        raw_hash = EvidenceCanonicalizer.compute_sha256(raw_email_content)
        self._append_custody_event(
            evidence_id=email_id,
            event_type=CustodyEventType.HASHED,
            details={"raw_sha256": raw_hash}
        )

        # 2. Headers & Relay Hops (P7 Integration)
        header_forensics = analysis_result.get("header_forensics", {})
        relay_path = analysis_result.get("relay_path", header_forensics.get("relay_path", []))

        for idx, hop in enumerate(relay_path):
            hop_id = hop.get("hop_id") or f"hop_{idx+1}"
            hop_val = hop.get("ip") or hop.get("by") or f"hop_{idx}"
            self.add_evidence(
                evidence_type=EvidenceType.RELAY_HOP,
                value=str(hop_val),
                provenance=ProvenanceClass.OBSERVED,
                source="header_forensics_p7",
                parent_id=email_id,
                attributes={"hop_id": hop_id, "hop_index": idx, **hop}
            )

        # 3. Authentication Results (SPF/DKIM/DMARC)
        auth_data = analysis_result.get("authentication", {})
        for auth_key, auth_val in auth_data.items():
            if auth_val:
                self.add_evidence(
                    evidence_type=EvidenceType.AUTHENTICATION_RESULT,
                    value=f"{auth_key.upper()}: {auth_val}",
                    provenance=ProvenanceClass.OBSERVED,
                    source="auth_verification",
                    parent_id=email_id,
                    attributes={"protocol": auth_key, "result": auth_val}
                )

        # 4. Attachments & Static Forensics (P9 Integration)
        att_analysis = analysis_result.get("attachment_analysis", {})
        attachments = att_analysis.get("attachments", [])
        for att in attachments:
            filename = att.get("filename") or att.get("name") or "attachment.bin"
            sha256 = att.get("sha256") or att.get("hash")
            att_node = self.add_evidence(
                evidence_type=EvidenceType.ATTACHMENT,
                value=filename,
                provenance=ProvenanceClass.OBSERVED,
                source="attachment_parser",
                parent_id=email_id,
                attributes={"filename": filename, "size": att.get("size", 0), "sha256": sha256}
            )
            if sha256:
                self.add_evidence(
                    evidence_type=EvidenceType.HASH,
                    value=sha256,
                    provenance=ProvenanceClass.OBSERVED,
                    source="attachment_forensics_p9",
                    parent_id=att_node.node_id,
                    attributes={"hash_type": "sha256", "target": "attachment"}
                )
            # Static findings if any
            for finding in att.get("findings", []):
                self.add_evidence(
                    evidence_type=EvidenceType.STATIC_ATTACHMENT_FINDING,
                    value=str(finding.get("description") or finding),
                    provenance=ProvenanceClass.HEURISTIC,
                    source="attachment_forensics_p9",
                    parent_id=att_node.node_id,
                    attributes=finding if isinstance(finding, dict) else {"finding": finding}
                )

        # 5. IOCs (URLs, Domains, IPs)
        iocs_data = analysis_result.get("iocs", {})
        urls = iocs_data.get("urls", [])
        for url_item in urls:
            url_val = url_item.get("url") if isinstance(url_item, dict) else str(url_item)
            if url_val:
                self.add_evidence(
                    evidence_type=EvidenceType.URL,
                    value=url_val,
                    provenance=ProvenanceClass.DERIVED,
                    source="ioc_extractor",
                    parent_id=email_id,
                    attributes=url_item if isinstance(url_item, dict) else {}
                )

        domains = iocs_data.get("domains", [])
        for dom_item in domains:
            dom_val = dom_item.get("domain") if isinstance(dom_item, dict) else str(dom_item)
            if dom_val:
                self.add_evidence(
                    evidence_type=EvidenceType.DOMAIN,
                    value=dom_val,
                    provenance=ProvenanceClass.DERIVED,
                    source="ioc_extractor",
                    parent_id=email_id,
                    attributes=dom_item if isinstance(dom_item, dict) else {}
                )

        ips = iocs_data.get("ips", [])
        for ip_item in ips:
            ip_val = ip_item.get("ip") if isinstance(ip_item, dict) else str(ip_item)
            if ip_val:
                self.add_evidence(
                    evidence_type=EvidenceType.IP,
                    value=ip_val,
                    provenance=ProvenanceClass.DERIVED,
                    source="ioc_extractor",
                    parent_id=email_id,
                    attributes=ip_item if isinstance(ip_item, dict) else {}
                )

        # 6. Threat Intelligence Fusion (P10 Integration)
        ti_list = analysis_result.get("threat_intelligence", [])
        for ti in ti_list:
            if isinstance(ti, dict):
                indicator = ti.get("indicator") or ti.get("query")
                provider = ti.get("provider") or "unknown_provider"
                severity = ti.get("severity") or "unknown"
                if indicator:
                    self.add_evidence(
                        evidence_type=EvidenceType.THREAT_INTEL_RESULT,
                        value=f"{provider}: {indicator} ({severity})",
                        provenance=ProvenanceClass.ENRICHED,
                        source=f"provider:{provider}",
                        parent_id=email_id,
                        attributes=ti,
                        confidence=ti.get("confidence")
                    )

        # 7. Machine Learning Findings (P8 Integration)
        ml_data = analysis_result.get("ml_analysis", {})
        if ml_data:
            ml_prob = ml_data.get("phishing_probability") or ml_data.get("probability", 0.0)
            self.add_evidence(
                evidence_type=EvidenceType.ML_FINDING,
                value=f"ML Phishing Probability: {ml_prob:.4f}",
                provenance=ProvenanceClass.MODEL,
                source="ml_classifier_p8",
                parent_id=email_id,
                attributes=ml_data,
                confidence=int(ml_prob * 100) if ml_prob <= 1.0 else int(ml_prob)
            )

        # 8. BEC / Impersonation Findings
        bec_data = analysis_result.get("bec_analysis", {})
        if bec_data and bec_data.get("is_bec"):
            self.add_evidence(
                evidence_type=EvidenceType.BEC_FINDING,
                value=f"BEC Detected: {bec_data.get('reasoning', 'Executive impersonation detected')}",
                provenance=ProvenanceClass.HEURISTIC,
                source="bec_detector",
                parent_id=email_id,
                attributes=bec_data,
                confidence=bec_data.get("confidence", 90)
            )

        # 9. Risk Findings & Verdict Report
        verdict = analysis_result.get("verdict", "UNKNOWN")
        risk_score = analysis_result.get("risk_score", 0)
        self.add_evidence(
            evidence_type=EvidenceType.REPORT,
            value=f"Final Verdict: {verdict} (Risk Score: {risk_score}/100)",
            provenance=ProvenanceClass.ANALYST,
            source="pipeline_orchestrator",
            parent_id=email_id,
            attributes={
                "verdict": verdict,
                "risk_score": risk_score,
                "summary": analysis_result.get("summary")
            }
        )

        # 10. Compute Manifest ID
        manifest_id = EvidenceCanonicalizer.compute_manifest_id(
            case_id=self.case_id,
            nodes=self.nodes,
            chain_of_custody=self.chain_of_custody
        )

        return EvidenceManifest(
            case_id=self.case_id,
            manifest_id=manifest_id,
            root_evidence_ids=self.root_evidence_ids,
            nodes=self.nodes,
            chain_of_custody=self.chain_of_custody,
            generated_by=self.actor,
            generated_at=datetime.now(timezone.utc)
        )

# AUDIT SCRIPT: Forensic Intelligence Engine
# Importers/Callers: backend/app/api/routes/intelligence.py, backend/tests/test_forensic_intelligence.py
# Affected API: /api/v1/intelligence/{case_id}
# Data schemas: ForensicIntelligence
# Verbatim instruction: "Build a backend Forensic Intelligence layer that converts the existing forensic evidence, threat-intelligence, ML/BEC, timeline, and correlation data into a structured investigator-oriented intelligence result."

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from app.schemas.evidence import EvidenceManifest, EvidenceNode, EvidenceType, ProvenanceClass
from app.schemas.intelligence import ForensicIntelligence, Verdict, Severity
from app.services.evidence_canonicalizer import EvidenceCanonicalizer

logger = logging.getLogger(__name__)

class ForensicIntelligenceEngine:
    def __init__(self, manifest: EvidenceManifest):
        self.manifest = manifest
        self.case_id = manifest.case_id

    def build_intelligence(self) -> ForensicIntelligence:
        # Trace all nodes
        nodes = list(self.manifest.nodes.values())

        # 1. Suspicious Indicators & Prioritization
        suspicious_indicators = []
        for n in nodes:
            if n.evidence_type in (EvidenceType.IP, EvidenceType.DOMAIN, EvidenceType.URL, EvidenceType.HASH, EvidenceType.IOC):
                suspicious_indicators.append({
                    "evidence_id": n.node_id,
                    "type": n.evidence_type.value,
                    "value": n.value,
                    "provenance": n.provenance.value,
                    "attributes": n.attributes
                })

        # Sort indicators deterministically
        suspicious_indicators.sort(key=lambda x: (x["type"], x["value"], x["evidence_id"]))

        # 2. Origin & Infrastructure Assessment
        origin_assessment = {
            "origin_status": "observed origin",
            "first_hop": None,
            "origin_ip": None,
            "provenance": ProvenanceClass.OBSERVED.value
        }
        infrastructure_assessment = {
            "relays": [],
            "domains": []
        }

        for n in nodes:
            if n.evidence_type == EvidenceType.RELAY_HOP:
                infrastructure_assessment["relays"].append(n.value)
                if not origin_assessment["first_hop"]:
                    origin_assessment["first_hop"] = n.attributes.get("from_server") or n.value
            elif n.evidence_type == EvidenceType.IP:
                if not origin_assessment["origin_ip"]:
                    origin_assessment["origin_ip"] = n.value
            elif n.evidence_type == EvidenceType.DOMAIN:
                infrastructure_assessment["domains"].append(n.value)

        # 3. MITRE ATT&CK Mapping
        attack_techniques = []
        for n in nodes:
            if n.evidence_type == EvidenceType.ATTACHMENT:
                attack_techniques.append({
                    "technique_id": "T1566.001",
                    "technique_name": "Spearphishing Attachment",
                    "supporting_evidence_ids": [n.node_id],
                    "confidence": 90
                })
            elif n.evidence_type == EvidenceType.URL:
                attack_techniques.append({
                    "technique_id": "T1566.002",
                    "technique_name": "Spearphishing Link",
                    "supporting_evidence_ids": [n.node_id],
                    "confidence": 85
                })
            elif n.evidence_type == EvidenceType.BEC_FINDING:
                attack_techniques.append({
                    "technique_id": "T1534",
                    "technique_name": "Internal Spearphishing / Impersonation",
                    "supporting_evidence_ids": [n.node_id],
                    "confidence": 80
                })

        # Deduplicate techniques
        unique_techniques = []
        seen_t = set()
        for t in attack_techniques:
            if t["technique_id"] not in seen_t:
                seen_t.add(t["technique_id"])
                unique_techniques.append(t)

        # 4. Attack Narrative
        narrative_parts = ["Email investigation initiated."]
        if origin_assessment["origin_ip"]:
            narrative_parts.append(f"Observed origin IP {origin_assessment['origin_ip']}.")
        if infrastructure_assessment["relays"]:
            narrative_parts.append(f"Traversed {len(infrastructure_assessment['relays'])} relay hop(s).")
        if suspicious_indicators:
            narrative_parts.append(f"Extracted {len(suspicious_indicators)} indicator(s).")
        attack_narrative = " ".join(narrative_parts)

        # 5. Contributing findings
        contributing_findings = []
        for n in nodes:
            if n.evidence_type in (EvidenceType.ML_FINDING, EvidenceType.BEC_FINDING, EvidenceType.STATIC_ATTACHMENT_FINDING, EvidenceType.THREAT_INTEL_RESULT):
                contributing_findings.append({
                    "evidence_id": n.node_id,
                    "type": n.evidence_type.value,
                    "value": n.value,
                    "attributes": n.attributes
                })

        # 6. Uncertainties and Contradictions
        uncertainties = []
        contradictions = []
        ti_nodes = [n for n in nodes if n.evidence_type == EvidenceType.THREAT_INTEL_RESULT]
        ml_nodes = [n for n in nodes if n.evidence_type == EvidenceType.ML_FINDING]

        # Simple contradiction rule: TI malicious vs ML benign
        for ti in ti_nodes:
            if "malicious" in ti.value.lower():
                for ml in ml_nodes:
                    if "benign" in ml.value.lower() or "0.0" in ml.value:
                        contradictions.append(f"Contradiction: Threat intel reports malicious ({ti.node_id}) while ML reports benign ({ml.node_id})")

        # 7. Recommendations
        recommended_actions = []
        if any(n.evidence_type == EvidenceType.ATTACHMENT for n in nodes):
            recommended_actions.append("Inspect attachment manually in isolated sandbox.")
        if any(n.evidence_type == EvidenceType.URL for n in nodes):
            recommended_actions.append("Block identified suspicious URL domains on gateway proxy.")
        if origin_assessment["origin_ip"]:
            recommended_actions.append(f"Review perimeter logs for traffic to {origin_assessment['origin_ip']}.")

        if not recommended_actions:
            recommended_actions.append("No immediate containment action needed. Archive investigation.")

        # Determine Verdict and Severity
        verdict = Verdict.BENIGN
        severity = Severity.SAFE
        if any(n.evidence_type == EvidenceType.THREAT_INTEL_RESULT and "malicious" in n.value.lower() for n in nodes):
            verdict = Verdict.MALICIOUS
            severity = Severity.HIGH
        elif any(n.evidence_type in (EvidenceType.BEC_FINDING, EvidenceType.STATIC_ATTACHMENT_FINDING) for n in nodes):
            verdict = Verdict.SUSPICIOUS
            severity = Severity.MEDIUM

        confidence = 85 if len(nodes) > 3 else 50

        return ForensicIntelligence(
            case_id=self.case_id,
            executive_summary=f"Automated intelligence summary for case {self.case_id}. Verdict: {verdict.value}.",
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            attack_narrative=attack_narrative,
            origin_assessment=origin_assessment,
            infrastructure_assessment=infrastructure_assessment,
            suspicious_indicators=suspicious_indicators,
            evidence_summary=[f"{n.evidence_type.value}: {n.value}" for n in nodes],
            contributing_findings=contributing_findings,
            attack_techniques=unique_techniques,
            recommended_actions=recommended_actions,
            uncertainties=uncertainties,
            contradictions=contradictions,
            reference_evidence_ids=[n.node_id for n in nodes]
        )

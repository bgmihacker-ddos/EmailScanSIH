# AUDIT SCRIPT: Evidence Schema
# Importers/Callers: backend/app/services/evidence_canonicalizer.py, backend/app/services/evidence_graph_v2.py
# Affected API: Evidence Graph and Chain of Custody feature
# Data schemas: EvidenceNode, CustodyEvent, EvidenceManifest
# Verbatim instruction: "Standardize EvidenceNode abstractions across defined evidence types... Model strict provenance classes... Implement append-only cryptographic Chain of Custody event chaining"

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime, timezone

class EvidenceType(str, Enum):
    EMAIL = "EMAIL"
    HEADER = "HEADER"
    RELAY_HOP = "RELAY_HOP"
    ATTACHMENT = "ATTACHMENT"
    IOC = "IOC"
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"
    HASH = "HASH"
    AUTHENTICATION_RESULT = "AUTHENTICATION_RESULT"
    THREAT_INTEL_RESULT = "THREAT_INTEL_RESULT"
    ML_FINDING = "ML_FINDING"
    BEC_FINDING = "BEC_FINDING"
    STATIC_ATTACHMENT_FINDING = "STATIC_ATTACHMENT_FINDING"
    RISK_FINDING = "RISK_FINDING"
    TIMELINE_EVENT = "TIMELINE_EVENT"
    REPORT = "REPORT"

class ProvenanceClass(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    ENRICHED = "ENRICHED"
    MODEL = "MODEL"
    HEURISTIC = "HEURISTIC"
    ANALYST = "ANALYST"

class CustodyEventType(str, Enum):
    ACQUIRED = "ACQUIRED"
    HASHED = "HASHED"
    PARSED = "PARSED"
    EXTRACTED = "EXTRACTED"
    ANALYZED = "ANALYZED"
    ENRICHED = "ENRICHED"
    CORRELATED = "CORRELATED"
    EXPORTED = "EXPORTED"
    VERIFIED = "VERIFIED"

def default_utcnow() -> datetime:
    return datetime.now(timezone.utc)

class EvidenceNode(BaseModel):
    node_id: str = Field(..., description="Canonical SHA-256 hash identity of this exact evidence state")
    parent_id: Optional[str] = Field(None, description="SHA-256 node_id of the origin evidence (e.g., EMAIL root for a parsed URL)")
    evidence_type: EvidenceType
    provenance: ProvenanceClass
    value: str = Field(..., description="Core value or summary of the evidence, usually standardized")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Detailed attributes, must be serializable")
    timestamp: datetime = Field(default_factory=default_utcnow)
    source: str = Field(..., description="System module or external provider origin")
    confidence: Optional[int] = Field(None, ge=0, le=100)

class CustodyEvent(BaseModel):
    event_id: str = Field(..., description="Canonical SHA-256 of the event properties")
    evidence_id: str = Field(..., description="Matches EvidenceNode.node_id")
    event_type: CustodyEventType
    previous_event_hash: Optional[str] = Field(None, description="Cryptographic link to prior event for this evidence_id")
    actor: str = Field(..., description="System, analyst, or component performing action")
    timestamp: datetime = Field(default_factory=default_utcnow)
    details: Dict[str, Any] = Field(default_factory=dict)

class EvidenceManifest(BaseModel):
    case_id: str
    manifest_id: str = Field(..., description="Cryptographic hash spanning all included nodes and events")
    root_evidence_ids: List[str]
    nodes: Dict[str, EvidenceNode] = Field(default_factory=dict)
    chain_of_custody: List[CustodyEvent] = Field(default_factory=list)
    generated_by: str
    generated_at: datetime = Field(default_factory=default_utcnow)

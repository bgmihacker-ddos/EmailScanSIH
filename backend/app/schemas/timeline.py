# AUDIT SCRIPT: Timeline & Correlation Schema
# Importers/Callers: backend/app/services/timeline_correlation_engine.py, backend/app/api/routes/investigation.py
# Affected API: /api/v1/investigation/*
# Data schemas: TimelineEvent, ForensicRelationship, InvestigationPath
# Verbatim instruction: "Implement strongly typed backend timeline model: event_id ... timestamp_precision... Explicit multi-stage evidence correlation preserving source, target, relationship type... Deterministically build linear/graph investigation path representation"

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime, timezone

from app.schemas.evidence import ProvenanceClass

class TimestampPrecision(str, Enum):
    EXACT = "EXACT"
    SECOND = "SECOND"
    MINUTE = "MINUTE"
    UNKNOWN = "UNKNOWN"

class TimelineEventType(str, Enum):
    EMAIL_ACQUIRED = "EMAIL_ACQUIRED"
    EMAIL_PARSED = "EMAIL_PARSED"
    AUTHENTICATION_ANALYZED = "AUTHENTICATION_ANALYZED"
    RECEIVED_HOP_OBSERVED = "RECEIVED_HOP_OBSERVED"
    ORIGIN_IP_IDENTIFIED = "ORIGIN_IP_IDENTIFIED"
    GEOLOCATION_ENRICHED = "GEOLOCATION_ENRICHED"
    ASN_ENRICHED = "ASN_ENRICHED"
    URL_EXTRACTED = "URL_EXTRACTED"
    DOMAIN_ANALYZED = "DOMAIN_ANALYZED"
    IOC_IDENTIFIED = "IOC_IDENTIFIED"
    THREAT_INTEL_ENRICHED = "THREAT_INTEL_ENRICHED"
    ATTACHMENT_IDENTIFIED = "ATTACHMENT_IDENTIFIED"
    ATTACHMENT_STATIC_ANALYZED = "ATTACHMENT_STATIC_ANALYZED"
    ML_ANALYZED = "ML_ANALYZED"
    BEC_ANALYZED = "BEC_ANALYZED"
    RISK_FUSED = "RISK_FUSED"
    VERDICT_GENERATED = "VERDICT_GENERATED"
    CASE_CREATED = "CASE_CREATED"
    REPORT_GENERATED = "REPORT_GENERATED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    TIMING_GAP = "TIMING_GAP"


class RelationshipType(str, Enum):
    DERIVED_FROM = "DERIVED_FROM"
    CONTAINS = "CONTAINS"
    OBSERVED_IN = "OBSERVED_IN"
    ORIGINATED_FROM = "ORIGINATED_FROM"
    RESOLVES_TO = "RESOLVES_TO"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    ENRICHED_BY = "ENRICHED_BY"
    INDICATES = "INDICATES"
    CONTRIBUTES_TO = "CONTRIBUTES_TO"
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    GENERATED_FROM = "GENERATED_FROM"

def default_utcnow() -> datetime:
    return datetime.now(timezone.utc)

class TimelineEvent(BaseModel):
    event_id: str = Field(..., description="Deterministic hash of the event properties")
    case_id: Optional[str] = Field(None)
    evidence_id: Optional[str] = Field(None, description="Reference to P11 EvidenceNode ID")
    event_type: TimelineEventType
    timestamp: datetime = Field(..., description="Timezone-aware UTC normalized timestamp")
    timestamp_precision: TimestampPrecision
    title: str = Field(...)
    description: str = Field(...)
    source: str = Field(...)
    provenance_class: ProvenanceClass
    severity: Optional[str] = Field(None, description="info, low, medium, high, critical")
    actor: Optional[str] = Field(None)
    related_evidence_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    event_hash: str = Field(..., description="Deterministic hash verifying the core values of this event")


class ForensicRelationship(BaseModel):
    relationship_id: str = Field(..., description="Deterministic hash of source + target + relationship_type")
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: RelationshipType
    provenance: ProvenanceClass
    confidence: Optional[int] = Field(None, ge=0, le=100)
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InvestigationTimeline(BaseModel):
    case_id: str
    events: List[TimelineEvent] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=default_utcnow)


class InvestigationCorrelations(BaseModel):
    case_id: str
    relationships: List[ForensicRelationship] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=default_utcnow)


class InvestigationStep(BaseModel):
    step_id: str = Field(...)
    evidence_id: str = Field(...)
    description: str = Field(...)
    next_steps: List[str] = Field(default_factory=list, description="List of step_ids")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InvestigationPath(BaseModel):
    case_id: str
    root_step_id: Optional[str] = None
    steps: Dict[str, InvestigationStep] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=default_utcnow)

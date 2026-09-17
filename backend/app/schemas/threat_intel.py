# AUDIT SCRIPT: Unified Threat Intelligence Data Models
# Importers/Callers: app.services.threat_intelligence, app.detection.threat_fusion
# Affected API: app.schemas.threat_intel
# Data schemas: Pydantic models for Normalized IOCs, Provider Results, and Consensus Results
# Verbatim instruction: "Transform the existing standalone threat-intelligence integrations into one resilient, normalized, evidence-aware IOC intelligence layer."

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

class IOCStatus(str, Enum):
    FRESH = "fresh"
    CACHED = "cached"
    STALE = "stale"
    FAILED = "failed"
    PARTIAL = "partial"
    NOT_CONFIGURED = "not_configured"

class NormalizedIOC(BaseModel):
    ioc_type: str  # ip|domain|url|hash|email
    raw_value: str
    normalized_value: str
    source_location: str
    context: Dict[str, Any] = Field(default_factory=dict)
    confidence: int
    provenance: str = "ENRICHED"
    freshness: IOCStatus = IOCStatus.FRESH

class ProviderResult(BaseModel):
    provider: str
    indicator: str
    indicator_type: str
    status: str
    reputation: str
    detections: int
    confidence: int
    categories: List[str] = []
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    references: List[str] = []
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    fallback_used: bool = False

class ConsensusResult(BaseModel):
    severity: str
    confidence: int
    sources: List[str]
    evidence: List[str]
    reasoning: str
    has_disagreement: bool = False
    provider_results: List[ProviderResult] = []

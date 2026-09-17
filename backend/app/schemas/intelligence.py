# AUDIT SCRIPT: Intelligence Schema
# Importers/Callers: backend/app/services/forensic_intelligence_engine.py, backend/app/api/routes/intelligence.py
# Affected API: /api/v1/intelligence/{case_id}
# Data schemas: ForensicIntelligence
# Verbatim instruction: "Create strongly typed backend schemas for ForensicIntelligence result..."

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime, timezone

class Verdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"

class ForensicIntelligence(BaseModel):
    case_id: str
    executive_summary: str
    verdict: Verdict
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    attack_narrative: str
    origin_assessment: Dict[str, Any]
    infrastructure_assessment: Dict[str, Any]
    suspicious_indicators: List[Dict[str, Any]]
    evidence_summary: List[str]
    contributing_findings: List[Dict[str, Any]]
    attack_techniques: List[Dict[str, Any]]
    recommended_actions: List[str]
    uncertainties: List[str]
    contradictions: List[str]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reference_evidence_ids: List[str]

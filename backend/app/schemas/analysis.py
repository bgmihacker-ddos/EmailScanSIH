from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class EmailAnalysisSchema(BaseModel):
    analysis_id: str
    verdict: str
    risk_score: int
    severity: str
    confidence: int
    summary: str
    reasons: List[str] = []
    evidence: List[str] = []
    detections: List[str] = []
    forensic_findings: List[Dict[str, Any]] = []
    threat_reasoning: List[str] = []
    attack_chain_steps: List[Dict[str, Any]] = []  # new richer format
    attack_chain: List[str] = [] # backward compat
    email: Dict[str, Any]
    authentication: Dict[str, Any] = {} # expanded to Any for dict logic
    live_authentication: Dict[str, Any] = {}
    iocs: Dict[str, Any] = {"urls": [], "domains": [], "ips": [], "attachments": []}
    extracted_iocs: Dict[str, Any] = {}
    threat_intelligence: List[Dict[str, Any]] = []
    recommendations: List[str] = []
    header_forensics: Dict[str, Any] = {}
    url_analysis: List[Dict[str, Any]] = []
    domain_analysis: Dict[str, Any] = {}
    ip_enrichment: List[Dict[str, Any]] = []
    relay_path: List[Dict[str, Any]] = []
    attachment_analysis: Dict[str, Any] = {}
    content_analysis: Dict[str, Any] = {}
    india_threat_intel: Dict[str, Any] = {}
    ml_analysis: Dict[str, Any] = {}
    risk_breakdown: List[Dict[str, Any]] = []
    evidence_ledger: List[Dict[str, Any]] = []
    evidence_integrity: Dict[str, Any] = {}
    alert: Dict[str, Any] = {}
    extended_reasoning: Dict[str, Any] = {}
    sender_intelligence: Dict[str, Any] = {}
    evidence_graph: Dict[str, Any] = {}
    timeline: Dict[str, Any] = {}
    mitre_techniques: List[Dict[str, Any]] = []
    related_investigations: List[Dict[str, Any]] = []
    stage_timings: List[Dict[str, Any]] = []
    anomaly_analysis: Dict[str, Any] = {}
    impersonation_analysis: Dict[str, Any] = {}
    bec_analysis: Dict[str, Any] = {}

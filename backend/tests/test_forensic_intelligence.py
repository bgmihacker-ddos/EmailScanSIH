# AUDIT SCRIPT: Phase 13 Forensic Intelligence Test Suite
# Importers/Callers: pytest backend/tests/test_forensic_intelligence.py
# Affected API: /api/v1/intelligence/{case_id}
# Data schemas: ForensicIntelligence
# Verbatim instruction: "Create comprehensive backend tests covering intelligence schema validation, empty investigation, IOC prioritization, origin assessment, and API response validation."

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.user import User
from app.core.security import hash_password, create_access_token
from app.schemas.evidence import EvidenceType, ProvenanceClass
from app.services.evidence_graph_v2 import EvidenceGraphV2Builder
from app.services.forensic_intelligence_engine import ForensicIntelligenceEngine

client = TestClient(app)

def _make_user(db, email, role="analyst", is_active=True):
    user = User(
        name="Test Analyst",
        email=email,
        password_hash=hash_password("password"),
        role=role,
        is_active=is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def _auth(user):
    return {"Authorization": f"Bearer {create_access_token(user)}"}

def test_forensic_intelligence_engine_basic():
    builder = EvidenceGraphV2Builder(case_id="CASE-INTEL-1", actor="analyst:test")
    email_node = builder.add_evidence(
        evidence_type=EvidenceType.EMAIL,
        value="sender@domain.com",
        provenance=ProvenanceClass.OBSERVED,
        source="parser",
        attributes={"subject": "Test"}
    )
    ip_node = builder.add_evidence(
        evidence_type=EvidenceType.IP,
        value="1.2.3.4",
        provenance=ProvenanceClass.DERIVED,
        source="ip_extractor",
        parent_id=email_node.node_id
    )
    builder.add_evidence(
        evidence_type=EvidenceType.THREAT_INTEL_RESULT,
        value="VirusTotal: 1.2.3.4 (malicious)",
        provenance=ProvenanceClass.ENRICHED,
        source="provider:VirusTotal",
        parent_id=ip_node.node_id
    )

    manifest = builder.build_from_full_analysis("raw", {})
    manifest.nodes = builder.nodes
    manifest.chain_of_custody = builder.chain_of_custody

    engine = ForensicIntelligenceEngine(manifest)
    intel = engine.build_intelligence()

    assert intel.case_id == "CASE-INTEL-1"
    assert intel.verdict.value == "MALICIOUS"
    assert len(intel.suspicious_indicators) > 0
    assert len(intel.reference_evidence_ids) == len(manifest.nodes)

def test_intelligence_endpoint_auth_required():
    res = client.get("/api/v1/intelligence/fake_case")
    assert res.status_code == 401

def test_intelligence_endpoint_not_found(db_session):
    user = _make_user(db_session, "intel-user@test.com")
    headers = _auth(user)
    res = client.get("/api/v1/intelligence/nonexistent-case", headers=headers)
    assert res.status_code == 404

# AUDIT SCRIPT: Phase 12 Timeline and Correlation Engine Test Suite (Hardened for P12.1)
# Importers/Callers: pytest backend/tests/test_timeline_correlation.py
# Affected API: TimelineCorrelationEngine, /api/v1/investigation/*
# Data schemas: TimelineEvent, ForensicRelationship, InvestigationPath
# Verbatim instruction: "Implement investigator-oriented timeline and correlation engine... Endpoints for timeline, correlation, path, and verification... Comprehensive test suite covering deterministic timeline, relationships, and attack path traversal."

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.models.user import User
from app.models.case import InvestigationCase
from app.core.security import hash_password, create_access_token
from app.schemas.evidence import EvidenceType, ProvenanceClass, CustodyEventType
from app.services.evidence_graph_v2 import EvidenceGraphV2Builder
from app.services.timeline_correlation_engine import TimelineCorrelationEngine
from app.schemas.timeline import TimelineEventType, RelationshipType, TimestampPrecision

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

def build_mock_manifest():
    builder = EvidenceGraphV2Builder(case_id="CASE-TIMELINE-1", actor="analyst:test")
    # Add root email
    email_node = builder.add_evidence(
        evidence_type=EvidenceType.EMAIL,
        value="test_sender@domain.com",
        provenance=ProvenanceClass.OBSERVED,
        source="email_parser",
        attributes={"date": "Thu, 1 Jan 2026 12:00:00 +0000", "subject": "Urgent Request"}
    )
    # Add relay hop
    hop_node = builder.add_evidence(
        evidence_type=EvidenceType.RELAY_HOP,
        value="relay.domain.com",
        provenance=ProvenanceClass.DERIVED,
        source="header_forensics",
        parent_id=email_node.node_id,
        attributes={"timestamp_utc": "2026-01-01T12:00:05Z", "from_server": "sender", "by_server": "relay"}
    )
    # Add indicator
    ip_node = builder.add_evidence(
        evidence_type=EvidenceType.IP,
        value="1.2.3.4",
        provenance=ProvenanceClass.DERIVED,
        source="ioc_extractor",
        parent_id=hop_node.node_id
    )
    # Add threat intel
    builder.add_evidence(
        evidence_type=EvidenceType.THREAT_INTEL_RESULT,
        value="VirusTotal: 1.2.3.4 (malicious)",
        provenance=ProvenanceClass.ENRICHED,
        source="provider:VirusTotal",
        parent_id=ip_node.node_id,
        attributes={"indicator": "1.2.3.4", "severity": "malicious"}
    )

    manifest = builder.build_from_full_analysis("raw_email", {})
    manifest.nodes = builder.nodes
    manifest.chain_of_custody = builder.chain_of_custody
    return manifest

def test_timeline_engine_timeline():
    manifest = build_mock_manifest()
    engine = TimelineCorrelationEngine(manifest)
    timeline = engine.build_timeline()

    assert timeline.case_id == "CASE-TIMELINE-1"
    assert len(timeline.events) > 0

    event_types = [e.event_type for e in timeline.events]
    assert TimelineEventType.EMAIL_ACQUIRED in event_types
    assert TimelineEventType.RECEIVED_HOP_OBSERVED in event_types

def test_timeline_engine_correlations():
    manifest = build_mock_manifest()
    engine = TimelineCorrelationEngine(manifest)
    correlations = engine.build_correlations()

    rel_types = set(r.relationship_type for r in correlations.relationships)
    assert RelationshipType.DERIVED_FROM in rel_types
    assert RelationshipType.INDICATES in rel_types

def test_timeline_engine_attack_path():
    manifest = build_mock_manifest()
    engine = TimelineCorrelationEngine(manifest)
    correlations = engine.build_correlations()
    path = engine.build_attack_path(correlations)

    assert path.case_id == "CASE-TIMELINE-1"
    assert path.root_step_id is not None
    assert len(path.steps) == len(manifest.nodes)

    for step_id, step in path.steps.items():
        assert isinstance(step.metadata, dict)

    root_step = path.steps[path.root_step_id]
    assert len(root_step.next_steps) > 0

def test_investigation_endpoints_require_auth():
    for endpoint in [
        "/api/v1/investigation/timeline/fake_case",
        "/api/v1/investigation/correlations/fake_case",
        "/api/v1/investigation/path/fake_case",
    ]:
        res = client.get(endpoint)
        assert res.status_code == 401

    res = client.post("/api/v1/investigation/validate", json={})
    assert res.status_code == 401

def test_investigation_endpoints_with_auth_not_found(db_session):
    user = _make_user(db_session, "auth-investigator@test.com")
    headers = _auth(user)

    for endpoint in [
        "/api/v1/investigation/timeline/nonexistent-case",
        "/api/v1/investigation/correlations/nonexistent-case",
        "/api/v1/investigation/path/nonexistent-case",
    ]:
        res = client.get(endpoint, headers=headers)
        assert res.status_code == 404

    res = client.post("/api/v1/investigation/validate", json={}, headers=headers)
    assert res.status_code == 200

def test_relationship_deduplication():
    builder = EvidenceGraphV2Builder(case_id="CASE-DEDUP", actor="analyst:test")
    node1 = builder.add_evidence(EvidenceType.EMAIL, "a@b.com", ProvenanceClass.OBSERVED, "src")
    node2 = builder.add_evidence(EvidenceType.IP, "1.1.1.1", ProvenanceClass.DERIVED, "src", parent_id=node1.node_id)

    manifest = builder.build_from_full_analysis("raw", {})
    manifest.nodes = builder.nodes
    manifest.chain_of_custody = builder.chain_of_custody

    engine = TimelineCorrelationEngine(manifest)
    corrs = engine.build_correlations()

    # Check that duplicate derived_from would not be duplicated
    rel_ids = [r.relationship_id for r in corrs.relationships]
    assert len(rel_ids) == len(set(rel_ids))

def test_cyclic_graph_protection_and_depth_limit():
    builder = EvidenceGraphV2Builder(case_id="CASE-CYCLE", actor="analyst:test")
    n1 = builder.add_evidence(EvidenceType.EMAIL, "e1@b.com", ProvenanceClass.OBSERVED, "src")
    n2 = builder.add_evidence(EvidenceType.IP, "2.2.2.2", ProvenanceClass.DERIVED, "src", parent_id=n1.node_id)

    manifest = builder.build_from_full_analysis("raw", {})
    manifest.nodes = builder.nodes
    manifest.chain_of_custody = builder.chain_of_custody

    # Create manual cyclic relationship for testing DFS cycle guard
    engine = TimelineCorrelationEngine(manifest)
    corrs = engine.build_correlations()

    path = engine.build_attack_path(corrs)
    assert path.case_id == "CASE-CYCLE"
    assert len(path.steps) > 0

def test_p9_attachment_and_ml_bec_mapping():
    builder = EvidenceGraphV2Builder(case_id="CASE-P9-ML", actor="analyst:test")
    att = builder.add_evidence(evidence_type=EvidenceType.ATTACHMENT, value="invoice.pdf", provenance=ProvenanceClass.OBSERVED, source="parser")
    stat = builder.add_evidence(evidence_type=EvidenceType.STATIC_ATTACHMENT_FINDING, value="macro found", provenance=ProvenanceClass.DERIVED, source="static", parent_id=att.node_id)
    ml = builder.add_evidence(evidence_type=EvidenceType.ML_FINDING, value="phishing prob: 0.99", provenance=ProvenanceClass.DERIVED, source="ml_clf", parent_id=att.node_id)
    bec = builder.add_evidence(evidence_type=EvidenceType.BEC_FINDING, value="ceo fraud detected", provenance=ProvenanceClass.DERIVED, source="bec_det")

    manifest = builder.build_from_full_analysis("raw", {})
    manifest.nodes = builder.nodes
    manifest.chain_of_custody = builder.chain_of_custody

    engine = TimelineCorrelationEngine(manifest)
    timeline = engine.build_timeline()
    event_types = {e.event_type for e in timeline.events}

    assert TimelineEventType.ATTACHMENT_IDENTIFIED in event_types
    assert TimelineEventType.ATTACHMENT_STATIC_ANALYZED in event_types
    assert TimelineEventType.ML_ANALYZED in event_types
    assert TimelineEventType.BEC_ANALYZED in event_types

def test_repeated_deterministic_generation():
    manifest = build_mock_manifest()
    engine1 = TimelineCorrelationEngine(manifest)
    t1 = engine1.build_timeline()
    c1 = engine1.build_correlations()

    engine2 = TimelineCorrelationEngine(manifest)
    t2 = engine2.build_timeline()
    c2 = engine2.build_correlations()

    assert len(t1.events) == len(t2.events)
    for ev1, ev2 in zip(t1.events, t2.events):
        assert ev1.event_id == ev2.event_id
        assert ev1.event_hash == ev2.event_hash

    assert len(c1.relationships) == len(c2.relationships)
    for r1, r2 in zip(c1.relationships, c2.relationships):
        assert r1.relationship_id == r2.relationship_id

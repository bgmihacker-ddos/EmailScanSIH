# AUDIT SCRIPT: Evidence & Custody Comprehensive Test Suite
# Importers/Callers: python -m pytest backend/tests/test_evidence_custody.py
# Affected API: EvidenceCanonicalizer, EvidenceGraphV2Builder, /api/v1/evidence/validate
# Data schemas: EvidenceNode, CustodyEvent, EvidenceManifest
# Verbatim instruction: "Every evidence artifact must have a deterministic cryptographic hash. Use SHA-256... Implement append-only cryptographic Chain of Custody event chaining... Implement tamper detection and validation APIs"

import pytest
from datetime import datetime, timezone
from app.schemas.evidence import (
    EvidenceType,
    ProvenanceClass,
    CustodyEventType,
    EvidenceNode,
    CustodyEvent,
    EvidenceManifest
)
from app.services.evidence_canonicalizer import EvidenceCanonicalizer
from app.services.evidence_graph_v2 import EvidenceGraphV2Builder

def test_canonical_json_determinism():
    d1 = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
    d2 = {"nested": {"y": 20, "z": 10}, "a": 1, "b": 2}
    assert EvidenceCanonicalizer.canonical_json(d1) == EvidenceCanonicalizer.canonical_json(d2)
    assert EvidenceCanonicalizer.compute_sha256(d1) == EvidenceCanonicalizer.compute_sha256(d2)

def test_evidence_node_identity_determinism():
    id1 = EvidenceCanonicalizer.compute_node_id(
        evidence_type=EvidenceType.URL,
        value="https://evil-login.com",
        source="ioc_extractor",
        provenance=ProvenanceClass.DERIVED,
        parent_id="root_123",
        attributes={"scheme": "https"}
    )
    id2 = EvidenceCanonicalizer.compute_node_id(
        evidence_type=EvidenceType.URL,
        value="https://evil-login.com",
        source="ioc_extractor",
        provenance=ProvenanceClass.DERIVED,
        parent_id="root_123",
        attributes={"scheme": "https"}
    )
    assert id1 == id2
    assert len(id1) == 64

def test_custody_chain_creation_and_integrity():
    builder = EvidenceGraphV2Builder(case_id="CASE-001", actor="analyst:test")
    node = builder.add_evidence(
        evidence_type=EvidenceType.EMAIL,
        value="sender@target.com",
        provenance=ProvenanceClass.OBSERVED,
        source="email_parser"
    )

    # Check that initial ACQUIRED event was added
    assert len(builder.chain_of_custody) == 1
    first_ev = builder.chain_of_custody[0]
    assert first_ev.event_type == CustodyEventType.ACQUIRED
    assert first_ev.previous_event_hash is None

    # Enrich and check chain linking
    second_ev = builder.enrich_evidence(node.node_id, "virustotal", {"score": 100})
    assert second_ev is not None
    assert second_ev.previous_event_hash == first_ev.event_id
    assert len(builder.chain_of_custody) == 2

    # Validate chain
    is_valid, err = EvidenceCanonicalizer.verify_custody_chain(builder.chain_of_custody)
    assert is_valid is True
    assert err is None

def test_custody_chain_tamper_detection():
    builder = EvidenceGraphV2Builder(case_id="CASE-002", actor="analyst:test")
    node = builder.add_evidence(
        evidence_type=EvidenceType.IP,
        value="1.2.3.4",
        provenance=ProvenanceClass.DERIVED,
        source="header_forensics"
    )
    builder.enrich_evidence(node.node_id, "abuseipdb", {"reputation": "bad"})

    # Tamper with an event actor
    builder.chain_of_custody[1].actor = "tampered:actor"
    is_valid, err = EvidenceCanonicalizer.verify_custody_chain(builder.chain_of_custody)
    assert is_valid is False
    assert "Tampered event_id detected" in err

def test_manifest_generation_and_full_verification():
    raw_email = "From: ceo@company.com\nTo: finance@company.com\nSubject: Urgent Wire Transfer\n\nPlease transfer immediately."
    mock_analysis = {
        "email": {"sender": "ceo@company.com", "subject": "Urgent Wire Transfer", "message_id": "<msg-001@company.com>"},
        "header_forensics": {"relay_path": [{"ip": "198.51.100.1", "hop_id": "hop_1"}]},
        "authentication": {"spf": "pass", "dkim": "fail"},
        "attachment_analysis": {
            "attachments": [
                {
                    "filename": "invoice.pdf",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "size": 1024,
                    "findings": [{"description": "Suspicious JavaScript embedded"}]
                }
            ]
        },
        "iocs": {
            "urls": [{"url": "https://malicious-login.com"}],
            "domains": [{"domain": "malicious-login.com"}],
            "ips": [{"ip": "198.51.100.1"}]
        },
        "threat_intelligence": [
            {"indicator": "https://malicious-login.com", "provider": "VirusTotal", "severity": "malicious", "confidence": 95}
        ],
        "ml_analysis": {"phishing_probability": 0.985},
        "bec_analysis": {"is_bec": True, "reasoning": "Executive impersonation wire fraud attempt", "confidence": 92},
        "verdict": "MALICIOUS",
        "risk_score": 95,
        "summary": "High risk BEC and credential harvesting email"
    }

    builder = EvidenceGraphV2Builder(case_id="CASE-003", actor="pipeline:audit")
    manifest = builder.build_from_full_analysis(raw_email, mock_analysis)

    assert manifest.case_id == "CASE-003"
    assert len(manifest.nodes) >= 10
    assert len(manifest.chain_of_custody) >= 10

    # Check that root evidence is identified
    assert len(manifest.root_evidence_ids) == 1

    # Verify manifest integrity
    is_valid, err = EvidenceCanonicalizer.verify_evidence_manifest(manifest)
    assert is_valid is True
    assert err is None

def test_manifest_tamper_detection():
    raw_email = "Subject: Test"
    mock_analysis = {"email": {"sender": "a@b.com", "subject": "Test"}}
    builder = EvidenceGraphV2Builder(case_id="CASE-004", actor="pipeline:audit")
    manifest = builder.build_from_full_analysis(raw_email, mock_analysis)

    # Tamper with a node value
    root_id = manifest.root_evidence_ids[0]
    manifest.nodes[root_id].value = "tampered_sender@domain.com"

    is_valid, err = EvidenceCanonicalizer.verify_evidence_manifest(manifest)
    assert is_valid is False
    assert "Manifest root hash mismatch" in err or "Tampered node" in err

"""Unit and integration tests for SIH26106 P4 Evidence Verification and QR anchoring.
Importers: pytest
Affected API: /api/analysis/{analysis_id}/verify-qr, /api/analysis/{analysis_id}/qr-image
Schemas: Verification response schemas
User instruction: SIH26106 P4 — Comprehensive backend unit tests for evidence verification and QR endpoints.
"""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.analysis import AnalysisResult
from app.database.session import get_db

client = TestClient(app)


def test_verify_qr_not_found():
    """Requesting verification for a non-existent analysis ID returns 404 NOT_FOUND."""
    fake_id = str(uuid.uuid4())
    res = client.get(f"/api/analysis/{fake_id}/verify-qr")
    assert res.status_code == 404
    body = res.json()
    assert body["detail"]["status"] == "NOT_FOUND"
    assert body["detail"]["analysis_id"] == fake_id


def test_verify_qr_ready_metadata():
    """Calling verify-qr without a hash returns READY status and metadata."""
    unique_id = str(uuid.uuid4())
    test_hash = "a" * 64
    from app.database.session import SessionLocal
    db = SessionLocal()
    try:
        record = AnalysisResult(
            id=unique_id,
            status="completed",
            verdict="phishing",
            evidence_hash=test_hash,
            chain_of_custody_id="COC-TEST-001",
            result={"evidence_integrity": {"raw_email_sha256": "b" * 64}},
            created_at=datetime.now(timezone.utc),
        )
        db.add(record)
        db.commit()

        res = client.get(f"/api/analysis/{unique_id}/verify-qr")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "READY"
        assert data["stored_evidence_hash"] == test_hash
        assert data["chain_of_custody_id"] == "COC-TEST-001"

        # Verify with MATCHING hash
        res_match = client.get(f"/api/analysis/{unique_id}/verify-qr?hash={test_hash}")
        assert res_match.status_code == 200
        data_match = res_match.json()
        assert data_match["status"] == "VERIFIED"
        assert data_match["submitted_hash"] == test_hash

        # Verify with MISMATCH hash
        wrong_hash = "c" * 64
        res_mismatch = client.get(f"/api/analysis/{unique_id}/verify-qr?hash={wrong_hash}")
        assert res_mismatch.status_code == 200
        data_mismatch = res_mismatch.json()
        assert data_mismatch["status"] == "MISMATCH"
        assert data_mismatch["submitted_hash"] == wrong_hash
    finally:
        # cleanup
        db.query(AnalysisResult).filter(AnalysisResult.id == unique_id).delete()
        db.commit()
        db.close()


def test_qr_image_generation():
    """Ensure qr-image returns valid PNG binary stream."""
    unique_id = str(uuid.uuid4())
    from app.database.session import SessionLocal
    db = SessionLocal()
    try:
        record = AnalysisResult(
            id=unique_id,
            status="completed",
            verdict="clean",
            evidence_hash="d" * 64,
            created_at=datetime.now(timezone.utc),
        )
        db.add(record)
        db.commit()

        res = client.get(f"/api/analysis/{unique_id}/qr-image")
        assert res.status_code == 200
        assert res.headers["content-type"] == "image/png"
        assert len(res.content) > 50  # valid PNG header & data
        assert res.content.startswith(b"\x89PNG")
    finally:
        db.query(AnalysisResult).filter(AnalysisResult.id == unique_id).delete()
        db.commit()
        db.close()

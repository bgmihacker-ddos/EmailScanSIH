"""Evidence verification endpoint and QR generator.
Importers: backend/app/main.py
Affected API: /api/analysis/{analysis_id}/verify-qr, /api/analysis/{analysis_id}/qr-image
Schemas: Verification response JSON schema with status (VERIFIED, MISMATCH, NOT_FOUND, READY).
User instruction: SIH26106 P4 — Evidence verification / QR code anchoring.
"""

from __future__ import annotations

import io
import hashlib
import json
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.analysis import AnalysisResult

router = APIRouter(prefix="/api/analysis", tags=["verification"])


def generate_qr_code_image(data: str) -> bytes:
    """Generate a PNG QR code for verification URL/hash data."""
    try:
        import qrcode
        img = qrcode.make(data)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        # Fallback tiny 1x1 transparent PNG if qrcode fails or PIL missing
        return b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc````\x00\x00\x00\x04\x00\x01\xf6(kR\x00\x00\x00\x00IEND\xaeB`\x82"


@router.get("/{analysis_id}/verify-qr")
def verify_analysis_evidence(
    analysis_id: str,
    hash: Optional[str] = Query(None, description="SHA-256 hash to verify against stored evidence"),
    db: Session = Depends(get_db),
):
    """Verify evidence integrity and cryptographic hash matching stored record.

    Returns:
    - VERIFIED: If hash matches exactly.
    - MISMATCH: If hash is provided but does not match.
    - NOT_FOUND: If analysis record does not exist.
    """
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "NOT_FOUND",
                "analysis_id": analysis_id,
                "message": "Analysis record not found in forensic ledger.",
            },
        )

    stored_hash = record.evidence_hash
    res_data = record.result or {}
    integrity = res_data.get("evidence_integrity") or {}
    raw_sha256 = integrity.get("raw_email_sha256")

    # If no hash query param supplied, return current verification metadata and QR
    if not hash:
        return {
            "status": "READY",
            "analysis_id": analysis_id,
            "stored_evidence_hash": stored_hash,
            "raw_email_sha256": raw_sha256,
            "chain_of_custody_id": record.chain_of_custody_id,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "message": "Provide ?hash=<sha256> to verify evidence integrity.",
        }

    # Compare supplied hash with stored_hash or raw_sha256
    clean_hash = hash.strip().lower()
    matches = (stored_hash and clean_hash == stored_hash.lower()) or (raw_sha256 and clean_hash == raw_sha256.lower())

    if matches:
        return {
            "status": "VERIFIED",
            "analysis_id": analysis_id,
            "submitted_hash": clean_hash,
            "stored_hash": stored_hash or raw_sha256,
            "verified_at": record.updated_at.isoformat() if record.updated_at else None,
            "chain_of_custody_id": record.chain_of_custody_id,
            "message": "Cryptographic evidence integrity verified successfully against forensic ledger.",
        }
    else:
        return {
            "status": "MISMATCH",
            "analysis_id": analysis_id,
            "submitted_hash": clean_hash,
            "stored_hash": stored_hash or raw_sha256,
            "message": "Evidence hash mismatch! Submitted hash does not match forensic ledger record.",
        }


@router.get("/{analysis_id}/qr-image")
def get_analysis_qr_code(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """Return a PNG QR code image encoding verification URL for this analysis."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    verify_url = f"/api/analysis/{analysis_id}/verify-qr"
    png_bytes = generate_qr_code_image(verify_url)
    return Response(content=png_bytes, media_type="image/png")

# AUDIT SCRIPT: Evidence API Endpoints
# Importers/Callers: backend/app/main.py
# Affected API: /api/v1/evidence/manifest, /api/v1/evidence/validate
# Data schemas: EvidenceManifest
# Verbatim instruction: "Implement tamper detection and validation APIs... and deterministic Case Evidence Manifest generation"

import json
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.case import InvestigationCase
from app.models.analysis import AnalysisResult
from app.schemas.evidence import EvidenceManifest, CustodyEvent
from app.services.evidence_canonicalizer import EvidenceCanonicalizer
from app.services.evidence_graph_v2 import EvidenceGraphV2Builder

router = APIRouter(prefix="/api/v1/evidence", tags=["Evidence"])

@router.get("/manifest/{case_id}", response_model=EvidenceManifest)
def get_case_evidence_manifest(case_id: str, db: Session = Depends(get_db)):
    """
    Generates a deterministic EvidenceManifest for all analyses linked to a case.
    """
    case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    builder = EvidenceGraphV2Builder(case_id=case_id, actor="system:api")

    # Check linked analyses
    analysis_ids = case.analysis_ids or []
    analyses = db.query(AnalysisResult).filter(AnalysisResult.id.in_(analysis_ids)).all()

    for analysis_record in analyses:
        if not analysis_record.result or not isinstance(analysis_record.result, dict):
            continue

        # Get raw email for raw hashing (best effort)
        email_dict = analysis_record.result.get("email", {})
        raw_email_placeholder = email_dict.get("raw_email", "")

        builder.build_from_full_analysis(raw_email_content=raw_email_placeholder, analysis_result=analysis_record.result)

    manifest_id = EvidenceCanonicalizer.compute_manifest_id(
        case_id=builder.case_id,
        nodes=builder.nodes,
        chain_of_custody=builder.chain_of_custody
    )

    manifest = EvidenceManifest(
        case_id=builder.case_id,
        manifest_id=manifest_id,
        root_evidence_ids=builder.root_evidence_ids,
        nodes=builder.nodes,
        chain_of_custody=builder.chain_of_custody,
        generated_by=builder.actor
    )

    return manifest

@router.post("/validate")
def validate_evidence_manifest(payload: EvidenceManifest):
    """
    Validates a previously exported EvidenceManifest for tampering or drift.
    """
    is_valid, err = EvidenceCanonicalizer.verify_evidence_manifest(payload)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={
                "valid": False,
                "error": err,
                "message": "Manifest integrity check failed."
            }
        )
    return {"valid": True, "message": "Manifest is fully verified and matches cryptographic hashes."}

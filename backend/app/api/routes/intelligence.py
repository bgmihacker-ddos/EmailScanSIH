# AUDIT SCRIPT: Intelligence API Endpoints
# Importers/Callers: backend/app/main.py
# Affected API: /api/v1/intelligence/{case_id}
# Data schemas: ForensicIntelligence
# Verbatim instruction: "Add backend API(s) following existing conventions... GET /api/v1/intelligence/{case_id}..."

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.api.dependencies import get_current_user
from app.api.routes.evidence import get_case_evidence_manifest
from app.schemas.intelligence import ForensicIntelligence
from app.services.forensic_intelligence_engine import ForensicIntelligenceEngine

router = APIRouter(prefix="/api/v1/intelligence", tags=["Intelligence"])

@router.get("/{case_id}", response_model=ForensicIntelligence)
def get_forensic_intelligence(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    manifest = get_case_evidence_manifest(case_id, db)
    engine = ForensicIntelligenceEngine(manifest)
    return engine.build_intelligence()

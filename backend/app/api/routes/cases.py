from __future__ import annotations

from datetime import timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.analysis import AnalysisResult
from app.models.case import InvestigationCase

router = APIRouter()


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=2000)
    severity: str = Field(default="medium", pattern="^(info|low|medium|high|critical)$")


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: Optional[str] = Field(default=None, pattern="^(open|investigating|closed)$")
    severity: Optional[str] = Field(default=None, pattern="^(info|low|medium|high|critical)$")


class LinkAnalysis(BaseModel):
    analysis_id: str = Field(min_length=1, max_length=36)


class CaseNote(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


def _serialize(case: InvestigationCase) -> Dict[str, Any]:
    return {
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "severity": case.severity,
        "analysis_ids": case.analysis_ids or [],
        "notes": case.notes or [],
        "created_at": case.created_at.replace(tzinfo=timezone.utc).isoformat() if case.created_at.tzinfo is None else case.created_at.isoformat(),
        "updated_at": case.updated_at.replace(tzinfo=timezone.utc).isoformat() if case.updated_at.tzinfo is None else case.updated_at.isoformat(),
    }


@router.post("/cases", status_code=201)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)):
    case = InvestigationCase(title=payload.title, description=payload.description, severity=payload.severity, analysis_ids=[], notes=[])
    db.add(case)
    db.commit()
    db.refresh(case)
    return _serialize(case)


@router.get("/cases")
def list_cases(status: Optional[str] = Query(None), severity: Optional[str] = Query(None), db: Session = Depends(get_db)):
    statement = db.query(InvestigationCase)
    if status:
        statement = statement.filter(InvestigationCase.status == status)
    if severity:
        statement = statement.filter(InvestigationCase.severity == severity)
    return {"data": [_serialize(case) for case in statement.order_by(InvestigationCase.updated_at.desc()).limit(250).all()]}


@router.get("/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return _serialize(case)


@router.patch("/cases/{case_id}")
def update_case(case_id: str, payload: CaseUpdate, db: Session = Depends(get_db)):
    case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(case, key, value)
    db.commit()
    db.refresh(case)
    return _serialize(case)


@router.post("/cases/{case_id}/analyses")
def link_analysis(case_id: str, payload: LinkAnalysis, db: Session = Depends(get_db)):
    case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    analysis = db.query(AnalysisResult).filter(AnalysisResult.id == payload.analysis_id).first()
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    ids = list(case.analysis_ids or [])
    if payload.analysis_id not in ids:
        ids.append(payload.analysis_id)
        case.analysis_ids = ids
        db.commit()
        db.refresh(case)
    return _serialize(case)


@router.post("/cases/{case_id}/notes")
def add_note(case_id: str, payload: CaseNote, db: Session = Depends(get_db)):
    case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    notes = list(case.notes or [])
    notes.append({"text": payload.text, "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()})
    case.notes = notes
    db.commit()
    db.refresh(case)
    return _serialize(case)

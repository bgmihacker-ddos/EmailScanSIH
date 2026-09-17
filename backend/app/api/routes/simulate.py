import os
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any, List

from app.database import get_db
from app.api.routes.analysis import _execute_analysis_pipeline
from app.services.certin_reporter import generate_certin_report
from app.services.blockchain_ledger import anchor_analysis, compute_evidence_hash

router = APIRouter(tags=["simulation & exports"])

class SimulateRequest(BaseModel):
    subject: Optional[str] = Field(default="Urgent: Verify Your SBI Account KYC Now")
    sender: Optional[str] = Field(default="support@sbi-yono-update.co.in")
    body: Optional[str] = Field(default="Dear Customer, Your SBI account will be blocked today due to pending KYC verification. Click here to update immediately: https://sbi-kyc-update-verify.com/login")
    spf_result: Optional[str] = Field(default="fail")
    dkim_result: Optional[str] = Field(default="fail")

@router.post("/simulate")
async def simulate_attack(payload: SimulateRequest, db: Session = Depends(get_db)):
    """Run synthetic attack payload through the full analysis pipeline."""
    raw_eml = f"""From: {payload.sender}
To: victim@target.org
Subject: {payload.subject}
Date: Mon, 13 Sep 2026 10:00:00 +0530
Authentication-Results: spf={payload.spf_result} dkim={payload.dkim_result} dmarc=fail

{payload.body}
"""
    analysis_id = f"sim-{os.urandom(4).hex()}"
    try:
        result = await _execute_analysis_pipeline(raw_eml.encode("utf-8"), analysis_id, db)
        return {
            "status": "success",
            "analysis_id": analysis_id,
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "severity": result.severity,
            "summary": result.summary,
            "recommendations": result.recommendations,
            "analysis": result.model_dump(mode="json"),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/analyze/{analysis_id}/certin-report")
async def get_certin_report(analysis_id: str, db: Session = Depends(get_db)):
    """Export one-click CERT-In compliant incident report."""
    from app.models.analysis import AnalysisResult as AnalysisResultModel
    record = db.query(AnalysisResultModel).filter(AnalysisResultModel.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis_data = record.result if isinstance(record.result, dict) else {}
    report = generate_certin_report(analysis_data)
    return report

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any

from app.database import get_db
from app.models.analysis import AnalysisResult as AnalysisResultModel

router = APIRouter(prefix="/iocs", tags=["iocs"])

@router.get("/pivot")
async def pivot_ioc(value: str = Query(..., description="IOC value (domain, IP, URL, email, hash)"), db: Session = Depends(get_db)):
    """Global search across all analyses to pivot on an IOC and find related threat campaigns."""
    needle = value.strip().lower()
    records = db.query(AnalysisResultModel).order_by(AnalysisResultModel.created_at.desc()).limit(1000).all()

    matches = []
    for rec in records:
        data = rec.result if isinstance(rec.result, dict) else {}
        if needle not in str(data).lower():
            continue
        matches.append({
            "analysis_id": rec.id,
            "subject": data.get("email", {}).get("subject") or data.get("subject", "Untitled"),
            "verdict": rec.verdict,
            "risk_score": rec.risk_score,
            "severity": rec.severity,
            "created_at": rec.created_at.isoformat() if rec.created_at else None,
        })
    return {
        "ioc": value,
        "total_matches": len(matches),
        "analyses": matches,
    }

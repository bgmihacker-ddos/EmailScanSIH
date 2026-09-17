from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.database import get_db
from app.models.audit import AuditLog

router = APIRouter(prefix="/audit-logs", tags=["audit"])

@router.get("")
async def list_audit_logs(limit: int = Query(50, le=200), offset: int = Query(0), db: Session = Depends(get_db)):
    """List system and security audit logs."""
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    total = db.query(AuditLog).count()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "data": [
            {
                "id": log.id,
                "timestamp": log.created_at.isoformat() if log.created_at else None,
                "created_at": log.created_at.isoformat() if log.created_at else None,
                "actor_user_id": log.actor_user_id,
                "action": log.action,
                "target_user_id": log.target_user_id,
                "metadata": log.metadata_json,
            }
            for log in logs
        ]
    }

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.analysis_worker import get_worker_health_snapshot

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok"}


@router.get("/worker/health")
def worker_health(db: Session = Depends(get_db)):
    return get_worker_health_snapshot(db)

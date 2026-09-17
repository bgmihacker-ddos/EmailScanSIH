"""Scheduled deletion of expired analysis data."""

from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.analysis import AnalysisResult
from app.models.analysis_job import AnalysisIndicator, AnalysisJob


def purge_expired_analyses() -> dict[str, int]:
    """Delete expired results, indicators, and queued payloads in bounded batches."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.RETENTION_DAYS)
    db = SessionLocal()
    try:
        result_ids = [
            row[0]
            for row in (
                db.query(AnalysisResult.id)
                .filter(AnalysisResult.created_at < cutoff)
                .limit(settings.ANALYSIS_RETENTION_SWEEP_BATCH)
                .all()
            )
        ]
        if not result_ids:
            return {"analyses": 0, "indicators": 0, "jobs": 0}

        indicators = db.query(AnalysisIndicator).filter(AnalysisIndicator.analysis_id.in_(result_ids)).delete(synchronize_session=False)
        jobs = db.query(AnalysisJob).filter(AnalysisJob.analysis_id.in_(result_ids)).delete(synchronize_session=False)
        analyses = db.query(AnalysisResult).filter(AnalysisResult.id.in_(result_ids)).delete(synchronize_session=False)
        db.commit()
        return {"analyses": analyses, "indicators": indicators, "jobs": jobs}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print(purge_expired_analyses())

"""Database-backed analysis worker entry point.

Run one bounded pass with ``python -m app.services.analysis_worker`` from the
backend directory, or use ``--loop`` under a process manager.
"""

import asyncio
import argparse
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.routes.analysis import _execute_analysis_pipeline
from app.core.config import settings
from app.database.session import SessionLocal
from app.models.analysis import AnalysisResult
from app.models.analysis_job import AnalysisJob


def _update_job_status(db, analysis_id: str, status: str, stage: str, pct: int, error: str | None = None):
    """Accept only safe lifecycle transitions for persisted analysis records."""
    db_rec = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    terminal_statuses = {"completed", "failed", "cancelled"}
    if db_rec and db_rec.status in terminal_statuses and status != db_rec.status:
        return
    if not db_rec:
        db_rec = AnalysisResult(
            id=analysis_id,
            status=status,
            current_stage=stage,
            progress_percent=pct,
            error_message=error,
            started_at=datetime.now(timezone.utc),
        )
        db.add(db_rec)
    else:
        db_rec.status = status
        db_rec.current_stage = stage
        db_rec.progress_percent = pct
        db_rec.error_message = error
        db_rec.updated_at = datetime.now(timezone.utc)
        if status in terminal_statuses:
            db_rec.completed_at = datetime.now(timezone.utc)
    db.commit()


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def get_worker_health_snapshot(db: Session | None = None):
    """Return a compact worker health snapshot with queue, worker, and stale-job counts."""
    session = db or SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        queue_jobs = session.query(AnalysisJob).filter(AnalysisJob.status == "queued").all()
        processing_jobs = session.query(AnalysisJob).filter(AnalysisJob.status == "processing").all()
        stale_jobs = []
        for job in processing_jobs:
            locked_at = _as_utc(job.locked_at)
            lease_expires_at = _as_utc(job.lease_expires_at)
            if (lease_expires_at is not None and lease_expires_at <= now) or (
                locked_at is not None and locked_at < (now - timedelta(minutes=settings.ANALYSIS_STALE_MINUTES))
            ):
                stale_jobs.append(job)
        worker_ids = {job.worker_id for job in processing_jobs if job.worker_id}
        oldest_job_age_seconds = 0
        if queue_jobs:
            created_values = [_as_utc(job.created_at) for job in queue_jobs if job.created_at is not None]
            if created_values:
                oldest_created = min(created_values)
                oldest_job_age_seconds = max(0, int((now - oldest_created).total_seconds()))
        return {
            "queue_depth": len(queue_jobs),
            "processing_jobs": len(processing_jobs),
            "stale_jobs": len(stale_jobs),
            "active_workers": len(worker_ids),
            "oldest_job_age_seconds": oldest_job_age_seconds,
            "lease_seconds": settings.ANALYSIS_LEASE_SECONDS,
            "max_attempts": settings.ANALYSIS_MAX_ATTEMPTS,
        }
    finally:
        if db is None:
            session.close()


def _claim_job(worker_id: str | None = None):
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=settings.ANALYSIS_STALE_MINUTES)
        candidate = db.execute(
            text(
                """
                SELECT analysis_id, payload, attempts
                FROM analysis_jobs
                WHERE status IN ('queued', 'processing')
                  AND (
                    locked_at IS NULL
                    OR locked_at < :cutoff
                    OR (lease_expires_at IS NOT NULL AND lease_expires_at <= :now)
                  )
                ORDER BY created_at ASC
                LIMIT 1
                """
            ),
            {"cutoff": cutoff, "now": now},
        ).first()
        if not candidate:
            return None

        analysis_id, payload, attempts = candidate
        result = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
        if not result or result.status in {"completed", "failed", "cancelled"}:
            db.execute(text("DELETE FROM analysis_jobs WHERE analysis_id = :analysis_id"), {"analysis_id": analysis_id})
            db.commit()
            return None

        if (attempts or 0) >= settings.ANALYSIS_MAX_ATTEMPTS:
            result.status = "failed"
            result.current_stage = "Analysis retry limit reached"
            result.error_message = "Analysis worker retry limit reached."
            result.completed_at = now
            db.execute(text("DELETE FROM analysis_jobs WHERE analysis_id = :analysis_id"), {"analysis_id": analysis_id})
            db.commit()
            return None

        resolved_worker_id = worker_id or "analysis-worker"
        next_attempts = (attempts or 0) + 1
        claim_result = db.execute(
            text(
                """
                UPDATE analysis_jobs
                SET status = 'processing',
                    locked_at = :now,
                    worker_id = :worker_id,
                    lease_expires_at = :lease_expires_at,
                    heartbeat_at = :now,
                    attempts = :next_attempts
                WHERE analysis_id = :analysis_id
                  AND status IN ('queued', 'processing')
                  AND (
                    locked_at IS NULL
                    OR locked_at < :cutoff
                    OR (lease_expires_at IS NOT NULL AND lease_expires_at <= :now)
                  )
                """
            ),
            {
                "analysis_id": analysis_id,
                "now": now,
                "worker_id": resolved_worker_id,
                "lease_expires_at": now + timedelta(seconds=settings.ANALYSIS_LEASE_SECONDS),
                "next_attempts": next_attempts,
                "cutoff": cutoff,
            },
        )
        if claim_result.rowcount != 1:
            db.rollback()
            return None
        db.commit()
        return analysis_id, payload
    finally:
        db.close()


async def run_once() -> bool:
    claimed = _claim_job()
    if not claimed:
        return False
    analysis_id, payload = claimed
    if isinstance(payload, memoryview):
        payload = payload.tobytes()
    elif isinstance(payload, bytearray):
        payload = bytes(payload)
    db = SessionLocal()
    try:
        await _execute_analysis_pipeline(payload, analysis_id, db)
        db.query(AnalysisJob).filter(AnalysisJob.analysis_id == analysis_id).delete()
        db.commit()
    except Exception as exc:
        db.rollback()
        result = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
        job = db.query(AnalysisJob).filter(AnalysisJob.analysis_id == analysis_id).first()
        if result and job and job.attempts >= settings.ANALYSIS_MAX_ATTEMPTS:
            result.status = "failed"
            result.current_stage = "Analysis failed after retries"
            result.error_message = "Analysis worker failed after the configured retry limit."
            result.completed_at = datetime.now(timezone.utc)
            db.delete(job)
        elif job:
            job.status = "queued"
            job.locked_at = None
            job.worker_id = None
            job.lease_expires_at = None
            job.heartbeat_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()
    return True


async def run_loop() -> None:
    while True:
        processed = await run_once()
        if not processed:
            await asyncio.sleep(settings.ANALYSIS_WORKER_POLL_SECONDS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the database-backed email analysis worker")
    parser.add_argument("--loop", action="store_true", help="Poll continuously instead of processing one job")
    args = parser.parse_args()
    asyncio.run(run_loop() if args.loop else run_once())


if __name__ == "__main__":
    main()
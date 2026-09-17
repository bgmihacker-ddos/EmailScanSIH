from datetime import datetime, timedelta, timezone

from app.models.analysis import AnalysisResult
from app.models.analysis_job import AnalysisJob
from app.services import analysis_worker


def test_claim_job_marks_exhausted_job_failed(db_session, monkeypatch):
    analysis_id = "worker-exhausted-job"
    db_session.add(AnalysisResult(id=analysis_id, status="queued"))
    db_session.add(AnalysisJob(
        analysis_id=analysis_id,
        payload=b"From: sender@example.com\n\nTest",
        attempts=3,
        locked_at=datetime.now(timezone.utc) - timedelta(hours=1),
    ))
    db_session.commit()
    monkeypatch.setattr(analysis_worker, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(analysis_worker.settings, "ANALYSIS_MAX_ATTEMPTS", 3)

    assert analysis_worker._claim_job() is None
    result = db_session.query(AnalysisResult).filter_by(id=analysis_id).one()
    assert result.status == "failed"
    assert "retry limit" in result.error_message.lower()
    assert db_session.query(AnalysisJob).filter_by(analysis_id=analysis_id).first() is None


def test_claim_job_reclaims_stale_lock(db_session, monkeypatch):
    analysis_id = "worker-stale-job"
    db_session.add(AnalysisResult(id=analysis_id, status="queued"))
    db_session.add(AnalysisJob(
        analysis_id=analysis_id,
        payload=b"From: sender@example.com\n\nTest",
        attempts=1,
        locked_at=datetime.now(timezone.utc) - timedelta(hours=1),
    ))
    db_session.commit()
    monkeypatch.setattr(analysis_worker, "SessionLocal", lambda: db_session)

    claimed = analysis_worker._claim_job()
    assert claimed[0] == analysis_id
    job = db_session.query(AnalysisJob).filter_by(analysis_id=analysis_id).one()
    assert job.attempts == 2
    assert job.locked_at is not None


def test_claim_job_sets_lease_metadata(db_session, monkeypatch):
    analysis_id = "worker-lease-metadata"
    db_session.add(AnalysisResult(id=analysis_id, status="queued"))
    db_session.add(AnalysisJob(
        analysis_id=analysis_id,
        payload=b"From: sender@example.com\n\nTest",
        status="queued",
        locked_at=None,
    ))
    db_session.commit()
    monkeypatch.setattr(analysis_worker, "SessionLocal", lambda: db_session)

    claimed = analysis_worker._claim_job(worker_id="worker-1")
    assert claimed[0] == analysis_id
    job = db_session.query(AnalysisJob).filter_by(analysis_id=analysis_id).one()
    assert job.status == "processing"
    assert job.worker_id == "worker-1"
    assert job.lease_expires_at is not None
    assert job.heartbeat_at is not None


def test_claim_job_reclaims_expired_lease(db_session, monkeypatch):
    analysis_id = "worker-expired-lease"
    db_session.add(AnalysisResult(id=analysis_id, status="queued"))
    db_session.add(AnalysisJob(
        analysis_id=analysis_id,
        payload=b"From: sender@example.com\n\nTest",
        status="processing",
        attempts=1,
        worker_id="worker-old",
        locked_at=datetime.now(timezone.utc) - timedelta(hours=1),
        lease_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        heartbeat_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    ))
    db_session.commit()
    monkeypatch.setattr(analysis_worker, "SessionLocal", lambda: db_session)

    claimed = analysis_worker._claim_job(worker_id="worker-new")
    assert claimed[0] == analysis_id
    job = db_session.query(AnalysisJob).filter_by(analysis_id=analysis_id).one()
    assert job.worker_id == "worker-new"
    assert job.attempts == 2
    assert job.lease_expires_at is not None


def test_update_job_status_rejects_invalid_terminal_transition(db_session):
    analysis_id = "worker-invalid-transition"
    db_session.add(AnalysisResult(id=analysis_id, status="completed"))
    db_session.commit()

    analysis_worker._update_job_status(db_session, analysis_id, "processing", "should-not-overwrite", 42)

    result = db_session.query(AnalysisResult).filter_by(id=analysis_id).one()
    assert result.status == "completed"
    assert result.current_stage != "should-not-overwrite"


def test_claim_job_is_atomic_for_parallel_workers(db_session, monkeypatch):
    analysis_id = "worker-parallel-claim"
    db_session.add(AnalysisResult(id=analysis_id, status="queued"))
    db_session.add(AnalysisJob(
        analysis_id=analysis_id,
        payload=b"From: sender@example.com\n\nTest",
        status="queued",
        attempts=0,
        locked_at=None,
        lease_expires_at=None,
    ))
    db_session.commit()
    monkeypatch.setattr(analysis_worker, "SessionLocal", lambda: db_session)

    first = analysis_worker._claim_job(worker_id="worker-a")
    second = analysis_worker._claim_job(worker_id="worker-b")

    assert first[0] == analysis_id
    assert second is None
    job = db_session.query(AnalysisJob).filter_by(analysis_id=analysis_id).one()
    assert job.worker_id == "worker-a"
    assert job.attempts == 1
    assert job.status == "processing"


def test_worker_health_summary_reports_queue_and_stale_jobs(db_session):
    now = datetime.now(timezone.utc)
    db_session.add(AnalysisResult(id="health-queued", status="queued"))
    db_session.add(AnalysisResult(id="health-processing", status="processing"))
    db_session.add(AnalysisResult(id="health-stale", status="processing"))
    db_session.add(AnalysisJob(
        analysis_id="health-queued",
        payload=b"queued",
        status="queued",
        created_at=now - timedelta(minutes=5),
        worker_id=None,
    ))
    db_session.add(AnalysisJob(
        analysis_id="health-processing",
        payload=b"processing",
        status="processing",
        worker_id="worker-1",
        locked_at=now - timedelta(minutes=1),
        lease_expires_at=now + timedelta(minutes=10),
        heartbeat_at=now - timedelta(seconds=30),
        created_at=now - timedelta(minutes=3),
    ))
    db_session.add(AnalysisJob(
        analysis_id="health-stale",
        payload=b"stale",
        status="processing",
        worker_id="worker-2",
        locked_at=now - timedelta(minutes=20),
        lease_expires_at=now - timedelta(minutes=2),
        heartbeat_at=now - timedelta(minutes=5),
        created_at=now - timedelta(minutes=25),
    ))
    db_session.commit()

    health = analysis_worker.get_worker_health_snapshot(db_session)

    assert health["queue_depth"] == 1
    assert health["processing_jobs"] == 2
    assert health["stale_jobs"] == 1
    assert health["active_workers"] == 2
    assert health["oldest_job_age_seconds"] >= 300

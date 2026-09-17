from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, LargeBinary, String

from app.database.base import Base


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    analysis_id = Column(String(36), primary_key=True)
    batch_id = Column(String(36), nullable=True, index=True)
    payload = Column(LargeBinary, nullable=False)
    status = Column(String(32), nullable=False, default="queued", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    heartbeat_at = Column(DateTime(timezone=True), nullable=True, index=True)
    worker_id = Column(String(128), nullable=True, index=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class AnalysisIndicator(Base):
    __tablename__ = "analysis_indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(36), nullable=False, index=True)
    indicator_type = Column(String(32), nullable=False, index=True)
    normalized_value = Column(String(2048), nullable=False, index=True)
    source = Column(String(64), nullable=False, default="ioc_extractor")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

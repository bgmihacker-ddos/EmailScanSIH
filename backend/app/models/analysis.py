import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, JSON, String

from app.database.base import Base


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    batch_id = Column(String(36), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="processing", index=True)
    current_stage = Column(String(255), nullable=True)
    progress_percent = Column(Integer, nullable=False, default=0)
    error_message = Column(String(1000), nullable=True)

    verdict = Column(String(32), nullable=True, index=True)
    risk_score = Column(Integer, nullable=True, index=True)
    severity = Column(String(32), nullable=True, index=True)
    confidence = Column(Integer, nullable=True)
    summary = Column(String(1000), nullable=True)
    evidence_hash = Column(String(128), nullable=True, index=True)
    chain_of_custody_id = Column(String(128), nullable=True, index=True)
    hash_manifest = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)

    started_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

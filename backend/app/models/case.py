import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, JSON, String

from app.database.base import Base


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    description = Column(String(2000), nullable=True)
    status = Column(String(32), nullable=False, default="open", index=True)
    severity = Column(String(32), nullable=False, default="medium", index=True)
    analysis_ids = Column(JSON, nullable=False, default=list)
    notes = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

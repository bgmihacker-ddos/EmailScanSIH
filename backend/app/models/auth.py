import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database.base import Base

class AuthAccount(Base):
    __tablename__ = "auth_accounts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    provider = Column(String(50), nullable=False)  # 'local', 'google'
    provider_account_id = Column(String(255), nullable=False)
    access_token_encrypted = Column(String(4096), nullable=True)
    refresh_token_encrypted = Column(String(4096), nullable=True)
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    token_scope = Column(String(2048), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("provider", "provider_account_id", name="uq_auth_provider_id"),
    )

    user = relationship("User", back_populates="auth_accounts")

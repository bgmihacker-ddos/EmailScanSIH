from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from app.api.dependencies import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.models.password_reset import PasswordResetToken
from app.core.security import hash_password, verify_password
from app.services.audit import log_action
import secrets
import uuid

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ... change_password code ...

@router.post("/forgot-password")
def forgot_password(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email.lower().strip()).first()
    if user:
        token_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        # Store the hash of the secret, and keep the ID as public lookup
        reset = PasswordResetToken(
            id=token_id,
            user_id=user.id,
            token_hash=hash_password(secret),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(reset)
        db.commit()
        log_action(db, user.id, "password_reset_requested")
    return {"detail": "If an account exists, a reset link will be sent."}

from app.schemas.password_reset import PasswordResetRequest

# ...

@router.post("/reset-password")
def reset_password(payload: PasswordResetRequest, db: Session = Depends(get_db)):
    token = payload.token
    new_password = payload.new_password
    if "." not in token:
        raise HTTPException(status_code=400, detail="Invalid token format.")
    token_id, secret = token.split(".", 1)
    reset = db.query(PasswordResetToken).filter(PasswordResetToken.id == token_id).first()

    if not reset:
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    # Ensure we use UTC for comparison
    now = datetime.now(timezone.utc)
    expires_at = reset.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < now:
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    if not verify_password(secret, reset.token_hash):
        raise HTTPException(status_code=400, detail="Invalid token.")

    user = db.query(User).filter(User.id == reset.user_id).first()
    if user:
        user.password_hash = hash_password(new_password)
        db.delete(reset) # Single use
        db.commit()
        log_action(db, user.id, "password_reset_success")

    return {"detail": "Password reset successfully."}

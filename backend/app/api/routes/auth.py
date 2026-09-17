from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.core.security import create_access_token, hash_password, verify_password
from app.database.session import get_db
from app.models.user import User
from app.models.email_verification import EmailVerificationToken
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.schemas.user import UserResponse
from app.services.audit import log_action
from app.services.email import get_email_provider

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: RegisterRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        name=payload.name.strip(),
        email=email,
        password_hash=hash_password(payload.password),
        role="user",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login_user(payload: LoginRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    user = db.query(User).filter(User.email == email).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenResponse(
        access_token=create_access_token(user),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    if "." not in token:
        raise HTTPException(status_code=400, detail="Invalid token format.")
    token_id, secret = token.split(".", 1)
    verification = db.query(EmailVerificationToken).filter(EmailVerificationToken.id == token_id).first()

    if not verification:
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    # Check expiration
    expires_at = verification.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        db.delete(verification)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    # Verify secret
    if not verify_password(secret, verification.token_hash):
        raise HTTPException(status_code=400, detail="Invalid token.")

    user = db.query(User).filter(User.id == verification.user_id).first()
    if user:
        user.is_verified = True
        db.delete(verification)
        db.commit()
        log_action(db, user.id, "email_verified")

    return {"detail": "Email verified successfully."}


@router.post("/resend-verification")
def resend_verification(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email.lower().strip()).first()
    if user and not user.is_verified:
        # Invalidate old tokens
        db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).delete()

        token_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        verification = EmailVerificationToken(
            id=token_id,
            user_id=user.id,
            token_hash=hash_password(secret),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.add(verification)
        db.commit()

        # Email abstraction
        email_provider = get_email_provider()
        email_provider.send_email(user.email, "Verify your email", f"Token: {token_id}.{secret}")
        log_action(db, user.id, "verification_resent")

    return {"detail": "If the account exists and is unverified, a verification link will be sent."}

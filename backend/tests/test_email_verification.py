import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.models.user import User
from app.models.email_verification import EmailVerificationToken
from app.core.security import hash_password

client = TestClient(app)

def test_email_verification_flow(db_session):
    # Setup unverified test user
    user = User(
        name="Verify Test",
        email="verify@example.com",
        password_hash=hash_password("password"),
        role="user",
        is_active=True,
        is_verified=False
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # 1. Resend Verification
    response = client.post("/api/auth/resend-verification", params={"email": "verify@example.com"})
    assert response.status_code == 200

    token = db_session.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).first()
    assert token is not None

    # Manually set a known secret in DB
    token.token_hash = hash_password("test-secret")
    db_session.commit()

    verification_token_str = f"{token.id}.test-secret"

    # 2. Verify Email
    response = client.post(f"/api/auth/verify-email?token={verification_token_str}")
    assert response.status_code == 200

    db_session.refresh(user)
    assert user.is_verified is True

    # 3. Verify single-use
    response = client.post(f"/api/auth/verify-email?token={verification_token_str}")
    assert response.status_code == 400

def test_email_verification_invalid_token(db_session):
    response = client.post("/api/auth/verify-email?token=invalid.token")
    assert response.status_code == 400

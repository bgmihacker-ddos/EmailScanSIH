import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.models.user import User
from app.models.password_reset import PasswordResetToken
from app.core.security import hash_password

client = TestClient(app)

def test_password_reset_flow(db_session):
    # Setup test user
    user = User(
        name="Reset Test",
        email="reset@example.com",
        password_hash=hash_password("old-password"),
        role="user",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # 1. Forgotten Password
    response = client.post("/api/auth/forgot-password", params={"email": "reset@example.com"})
    assert response.status_code == 200

    # Get the token hash from DB (manual way for test)
    token = db_session.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).first()
    assert token is not None

    # We can't know the plain token, so we have to manually set one in DB
    # Or mock the secret generation
    # Let's override the token in the DB to known test token: "test-token"
    token.token_hash = hash_password("test-token")
    token.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    db_session.commit()

    reset_token_str = f"{token.id}.test-token"

    # 2. Reset Password
    response = client.post("/api/auth/reset-password", json={
        "token": reset_token_str,
        "new_password": "new-secure-password"
    })
    assert response.status_code == 200

    # Verify new password works
    login_response = client.post("/api/auth/login", json={
        "email": "reset@example.com",
        "password": "new-secure-password"
    })
    assert login_response.status_code == 200

    # Verify token is single-use
    response = client.post("/api/auth/reset-password", json={
        "token": reset_token_str,
        "new_password": "newer-secure-password"
    })
    assert response.status_code == 400

def test_password_reset_invalid_token(db_session):
    response = client.post("/api/auth/reset-password", json={
        "token": "invalid.token",
        "new_password": "new-secure-password"
    })
    assert response.status_code == 400

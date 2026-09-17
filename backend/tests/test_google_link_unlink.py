import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app
from app.models.user import User
from app.models.auth import AuthAccount
from app.core.security import hash_password, create_access_token
import uuid

@pytest.fixture
def test_client():
    return TestClient(app)

@pytest.fixture
def auth_header(db_session):
    user = User(
        name="Test User",
        email="test@example.com",
        password_hash=hash_password("password"),
        role="user",
        is_active=True,
        is_verified=True
    )
    db_session.add(user)
    db_session.commit()
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}

@patch("authlib.integrations.starlette_client.StarletteOAuth2App.authorize_access_token")
def test_google_link_success(mock_authorize_access_token, test_client, auth_header, db_session):
    mock_authorize_access_token.return_value = {
        "userinfo": {
            "sub": "google-new-id",
        }
    }

    response = test_client.get("/api/auth/google/link-callback", headers=auth_header, follow_redirects=False)

    assert response.status_code == 200
    assert "successfully" in response.json()["detail"]

    # Check database
    link = db_session.query(AuthAccount).filter(AuthAccount.provider_account_id == "google-new-id").first()
    assert link is not None

@patch("authlib.integrations.starlette_client.StarletteOAuth2App.authorize_access_token")
def test_google_unlink_success(mock_authorize_access_token, test_client, auth_header, db_session):
    # Setup link first
    user = db_session.query(User).filter(User.email == "test@example.com").first()
    link1 = AuthAccount(user_id=user.id, provider="google", provider_account_id="g1")
    link2 = AuthAccount(user_id=user.id, provider="google", provider_account_id="g2")
    db_session.add(link1)
    db_session.add(link2)
    db_session.commit()

    response = test_client.delete("/api/auth/google/link", headers=auth_header)
    assert response.status_code == 200

    # Verify all Google links are gone
    remaining = db_session.query(AuthAccount).filter(AuthAccount.user_id == user.id).all()
    assert len(remaining) == 0

def test_google_unlink_lockout(test_client, auth_header, db_session):
    # Setup one link only
    user = db_session.query(User).filter(User.email == "test@example.com").first()
    link = AuthAccount(user_id=user.id, provider="google", provider_account_id="g1")
    db_session.add(link)
    db_session.commit()

    # Try unlink
    response = test_client.delete("/api/auth/google/link", headers=auth_header)
    assert response.status_code == 400
    assert "last authentication provider" in response.json()["detail"]

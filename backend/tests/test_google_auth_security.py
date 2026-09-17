import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app
from app.models.user import User
from app.core.security import hash_password

@pytest.fixture
def test_client():
    return TestClient(app)

@patch("authlib.integrations.starlette_client.StarletteOAuth2App.authorize_access_token")
def test_google_callback_email_collision(mock_authorize_access_token, test_client, db_session):
    # Setup local user
    user = User(
        name="Local User",
        email="collision@example.com",
        password_hash=hash_password("password"),
    )
    db_session.add(user)
    db_session.commit()

    # Mock Google returning same email
    mock_authorize_access_token.return_value = {
        "userinfo": {
            "email": "collision@example.com",
            "sub": "google-collision-id",
            "name": "Google User",
            "email_verified": True
        }
    }

    # Attempt OAuth callback
    response = test_client.get("/api/auth/google/callback", follow_redirects=False)

    # Assert conflict/error, NOT link
    assert response.status_code == 400
    assert "already exists locally" in response.json()["detail"]

from datetime import timedelta

from fastapi.testclient import TestClient

from app.core.security import create_access_token, hash_password
from app.database.session import get_db
from app.main import app
from app.models.user import User

client = TestClient(app)


def register_user(email="Test@Example.COM", password="secure-password", **extra_payload):
    payload = {
        "name": "Test User",
        "email": email,
        "password": password,
        **extra_payload,
    }
    return client.post("/api/auth/register", json=payload)


def login_user(email="test@example.com", password="secure-password"):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def create_user(db_session, email="analyst@example.com", role="user", is_active=True):
    user = User(
        name="Role User",
        email=email,
        password_hash=hash_password("secure-password"),
        role=role,
        is_active=is_active,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_registration_success_returns_safe_user():
    response = register_user()

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test User"
    assert data["email"] == "test@example.com"
    assert data["role"] == "user"
    assert data["is_active"] is True
    assert "id" in data
    assert "password" not in data
    assert "password_hash" not in data


def test_duplicate_email_rejected():
    assert register_user().status_code == 201

    response = register_user(email="test@example.com")

    assert response.status_code == 409


def test_email_normalized(db_session):
    response = register_user(email="  Mixed@Example.COM  ")

    assert response.status_code == 201
    assert response.json()["email"] == "mixed@example.com"
    stored_user = db_session.query(User).filter(User.email == "mixed@example.com").first()
    assert stored_user is not None


def test_password_hashed_and_plaintext_not_stored(db_session):
    password = "secure-password"
    register_user(password=password)

    stored_user = db_session.query(User).filter(User.email == "test@example.com").first()
    assert stored_user.password_hash != password
    assert password not in stored_user.password_hash


def test_correct_login_works():
    register_user()

    response = login_user()

    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 3600
    assert data["access_token"]


def test_wrong_password_rejected():
    register_user()

    response = login_user(password="wrong-password")

    assert response.status_code == 401


def test_unknown_user_rejected():
    response = login_user(email="missing@example.com")

    assert response.status_code == 401


def test_me_works():
    register_user()
    token = login_user().json()["access_token"]

    response = client.get("/api/auth/me", headers=auth_header(token))

    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"


def test_missing_token_rejected():
    response = client.get("/api/auth/me")

    assert response.status_code == 401


def test_invalid_token_rejected():
    response = client.get("/api/auth/me", headers=auth_header("not-a-token"))

    assert response.status_code == 401


def test_expired_token_rejected(db_session):
    user = create_user(db_session, email="expired@example.com")
    token = create_access_token(user, expires_delta=timedelta(seconds=-1))

    response = client.get("/api/auth/me", headers=auth_header(token))

    assert response.status_code == 401


def test_inactive_user_rejected(db_session):
    user = create_user(db_session, email="inactive@example.com", is_active=False)
    token = create_access_token(user)

    response = client.get("/api/auth/me", headers=auth_header(token))

    assert response.status_code == 401


def test_public_registration_cannot_create_admin():
    response = register_user(role="admin")

    assert response.status_code == 201
    assert response.json()["role"] == "user"


def test_public_registration_cannot_create_analyst():
    response = register_user(role="analyst")

    assert response.status_code == 201
    assert response.json()["role"] == "user"


def test_user_cannot_access_admin(db_session):
    user = create_user(db_session, email="user@example.com", role="user")
    token = create_access_token(user)

    response = client.get("/api/test/admin-only", headers=auth_header(token))

    assert response.status_code == 403


def test_analyst_can_access_analyst(db_session):
    user = create_user(db_session, email="analyst@example.com", role="analyst")
    token = create_access_token(user)

    response = client.get("/api/test/analyst-only", headers=auth_header(token))

    assert response.status_code == 200
    assert response.json()["role"] == "analyst"


def test_admin_can_access_admin(db_session):
    user = create_user(db_session, email="admin@example.com", role="admin")
    token = create_access_token(user)

    response = client.get("/api/test/admin-only", headers=auth_header(token))

    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_database_dependency_works():
    db = next(app.dependency_overrides[get_db]())
    try:
        assert db.query(User).count() == 0
    finally:
        db.close()

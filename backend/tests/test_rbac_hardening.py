import pytest
from fastapi.testclient import TestClient
from jose import jwt
from datetime import datetime, timedelta, timezone
from app.main import app
from app.models.user import User
from app.models.audit import AuditLog
from app.core.security import hash_password, create_access_token
from app.core.config import settings

client = TestClient(app)


def _make_user(db, email, role="user", is_active=True):
    user = User(
        name="Test",
        email=email,
        password_hash=hash_password("password"),
        role=role,
        is_active=is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _auth(user):
    return {"Authorization": f"Bearer {create_access_token(user)}"}


# ==== TEST A: Demoted admin old JWT ====
def test_demoted_admin_old_jwt_rejected(db_session):
    admin = _make_user(db_session, "admin-demote@test.com", role="admin")
    headers = _auth(admin)

    # Verify admin access works
    res = client.get("/api/admin/users", headers=headers)
    assert res.status_code == 200

    # Demote to user in DB
    admin.role = "user"
    db_session.commit()

    # Old JWT must be rejected for admin endpoint
    res = client.get("/api/admin/users", headers=headers)
    assert res.status_code == 403


# ==== TEST B: Deactivated user old JWT ====
def test_deactivated_user_old_jwt_rejected(db_session):
    user = _make_user(db_session, "deact@test.com")
    headers = _auth(user)

    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 200

    user.is_active = False
    db_session.commit()

    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 401


# ==== TEST C: Deactivated admin old JWT ====
def test_deactivated_admin_old_jwt_rejected(db_session):
    admin = _make_user(db_session, "admin-deact@test.com", role="admin")
    headers = _auth(admin)

    res = client.get("/api/admin/users", headers=headers)
    assert res.status_code == 200

    admin.is_active = False
    db_session.commit()

    res = client.get("/api/admin/users", headers=headers)
    assert res.status_code == 401


# ==== JWT security ====
def test_missing_jwt_returns_401(db_session):
    res = client.get("/api/auth/me")
    assert res.status_code == 401


def test_malformed_jwt_returns_401(db_session):
    res = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert res.status_code == 401


def test_wrong_signature_jwt_returns_401(db_session):
    user = _make_user(db_session, "sig@test.com")
    payload = {"sub": user.id, "email": user.email, "role": user.role,
               "exp": datetime.now(timezone.utc) + timedelta(hours=1)}
    bad_token = jwt.encode(payload, "wrong-secret-key", algorithm="HS256")
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {bad_token}"})
    assert res.status_code == 401


def test_expired_jwt_returns_401(db_session):
    user = _make_user(db_session, "exp@test.com")
    payload = {"sub": user.id, "email": user.email, "role": user.role,
               "exp": datetime.now(timezone.utc) - timedelta(hours=1)}
    expired_token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401


# ==== RBAC ====
def test_normal_user_cannot_access_admin(db_session):
    user = _make_user(db_session, "normuser@test.com")
    res = client.get("/api/admin/users", headers=_auth(user))
    assert res.status_code == 403


def test_admin_can_access_admin(db_session):
    admin = _make_user(db_session, "admin@test.com", role="admin")
    res = client.get("/api/admin/users", headers=_auth(admin))
    assert res.status_code == 200


def test_unauthenticated_cannot_access_admin(db_session):
    res = client.get("/api/admin/users")
    assert res.status_code == 401


# ==== Last-admin protection ====
def test_cannot_delete_last_admin(db_session):
    admin = _make_user(db_session, "lastadmin-del@test.com", role="admin")
    headers = _auth(admin)
    res = client.delete(f"/api/admin/users/{admin.id}", headers=headers)
    assert res.status_code == 403


def test_cannot_deactivate_last_admin(db_session):
    admin = _make_user(db_session, "lastadmin-deact@test.com", role="admin")
    headers = _auth(admin)
    res = client.patch(f"/api/admin/users/{admin.id}/deactivate", headers=headers)
    assert res.status_code == 403


def test_cannot_demote_last_admin(db_session):
    admin = _make_user(db_session, "lastadmin-demote@test.com", role="admin")
    headers = _auth(admin)
    res = client.patch(f"/api/admin/users/{admin.id}/role", headers=headers, json={"role": "user"})
    assert res.status_code == 403


def test_can_demote_admin_when_two_exist(db_session):
    admin1 = _make_user(db_session, "admin1@test.com", role="admin")
    admin2 = _make_user(db_session, "admin2@test.com", role="admin")
    headers = _auth(admin1)
    res = client.patch(f"/api/admin/users/{admin2.id}/role", headers=headers, json={"role": "user"})
    assert res.status_code == 200
    assert res.json()["role"] == "user"


def test_can_delete_admin_when_two_exist(db_session):
    admin1 = _make_user(db_session, "admindel1@test.com", role="admin")
    admin2 = _make_user(db_session, "admindel2@test.com", role="admin")
    headers = _auth(admin1)
    res = client.delete(f"/api/admin/users/{admin2.id}", headers=headers)
    assert res.status_code == 204


# ==== Password/hash leakage ====
def test_password_hash_not_in_response(db_session):
    user = _make_user(db_session, "nohash@test.com")
    headers = _auth(user)
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert "password_hash" not in body
    assert "password" not in body


def test_admin_list_no_password_hash(db_session):
    admin = _make_user(db_session, "adminhash@test.com", role="admin")
    headers = _auth(admin)
    res = client.get("/api/admin/users", headers=headers)
    assert res.status_code == 200
    for u in res.json():
        assert "password_hash" not in u
        assert "password" not in u


# ==== Audit logging ====
def test_role_change_audited(db_session):
    admin1 = _make_user(db_session, "auditadm1@test.com", role="admin")
    admin2 = _make_user(db_session, "auditadm2@test.com", role="admin")
    headers = _auth(admin1)
    client.patch(f"/api/admin/users/{admin2.id}/role", headers=headers, json={"role": "user"})
    log = db_session.query(AuditLog).filter(AuditLog.action == "role_changed").first()
    assert log is not None
    assert log.target_user_id == admin2.id
    # Verify no secrets in metadata
    if log.metadata_json:
        meta_str = str(log.metadata_json)
        assert "password" not in meta_str.lower()
        assert "secret" not in meta_str.lower()
        assert "token" not in meta_str.lower()


def test_deactivation_audited(db_session):
    admin = _make_user(db_session, "auditdeact-adm@test.com", role="admin")
    user = _make_user(db_session, "auditdeact-usr@test.com")
    headers = _auth(admin)
    client.patch(f"/api/admin/users/{user.id}/deactivate", headers=headers)
    log = db_session.query(AuditLog).filter(AuditLog.action == "deactivate_user").first()
    assert log is not None
    assert log.target_user_id == user.id

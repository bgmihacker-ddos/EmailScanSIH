import os
import sys
from pathlib import Path

import pytest
from fastapi import Depends
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JWT_SECRET"] = "test-jwt-secret"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "60"

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

import app.database.session as app_session
import app.database.connection as app_connection
app_session.SessionLocal = TestingSessionLocal
app_connection.engine = engine

import app.api.routes.analysis as app_analysis_route
app_analysis_route.SessionLocal = TestingSessionLocal

from app.api.dependencies import require_admin, require_analyst  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.database.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app import models  # noqa: E402,F401
from app.models.user import User  # noqa: E402,F401


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/api/test/analyst-only", include_in_schema=False)
def analyst_only(current_user: User = Depends(require_analyst)):
    return {"role": current_user.role}


@app.get("/api/test/admin-only", include_in_schema=False)
def admin_only(current_user: User = Depends(require_admin)):
    return {"role": current_user.role}


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

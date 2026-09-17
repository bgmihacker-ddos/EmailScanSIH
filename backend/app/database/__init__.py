from app.database.base import Base
from app.database.connection import engine
from app.database.session import SessionLocal, get_db


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


__all__ = ["Base", "SessionLocal", "engine", "get_db", "init_db"]

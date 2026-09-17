from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database.session import get_db
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)

ROLE_RANK = {
    "user": 1,
    "analyst": 2,
    "admin": 3,
}


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError:
        raise unauthorized

    user = db.query(User).filter(User.id == payload["sub"]).first()
    if user is None or user.email != payload.get("email"):
        raise unauthorized
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(required_role: str) -> Callable[[User], User]:
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        user_rank = ROLE_RANK.get(current_user.role, 0)
        required_rank = ROLE_RANK[required_role]
        if user_rank < required_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions.",
            )
        return current_user

    return dependency


def require_user(current_user: User = Depends(require_role("user"))) -> User:
    return current_user


def require_analyst(current_user: User = Depends(require_role("analyst"))) -> User:
    return current_user


def require_admin(current_user: User = Depends(require_role("admin"))) -> User:
    return current_user

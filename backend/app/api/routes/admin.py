from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel, Field

from app.api.dependencies import require_admin
from app.database.session import get_db
from app.models.user import User
from app.schemas.user import UserResponse
from app.services.audit import log_action

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users", response_model=List[UserResponse])
def get_users(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    return db.query(User).all()


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: str, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


@router.patch("/users/{user_id}/activate", response_model=UserResponse)
def activate_user(user_id: str, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_active = True
    db.commit()
    db.refresh(user)
    log_action(db, current_user.id, "activate_user", target_user_id=user_id)
    return user


@router.patch("/users/{user_id}/deactivate", response_model=UserResponse)
def deactivate_user(user_id: str, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.role == 'admin':
        admin_count = db.query(User).filter(User.role == 'admin', User.is_active == True).count()
        if admin_count <= 1:
            raise HTTPException(status_code=403, detail="Cannot deactivate the last active admin.")

    user.is_active = False
    db.commit()
    db.refresh(user)
    log_action(db, current_user.id, "deactivate_user", target_user_id=user_id)
    return user


class RoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(user|analyst|admin)$")


@router.patch("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(user_id: str, payload: RoleUpdateRequest, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    old_role = user.role
    new_role = payload.role

    # Prevent demoting the last active admin
    if old_role == 'admin' and new_role != 'admin':
        admin_count = db.query(User).filter(User.role == 'admin', User.is_active == True).count()
        if admin_count <= 1:
            raise HTTPException(status_code=403, detail="Cannot demote the last active admin.")

    user.role = new_role
    db.commit()
    db.refresh(user)
    log_action(db, current_user.id, "role_changed", target_user_id=user_id,
               metadata={"old_role": old_role, "new_role": new_role})
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: str, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.role == 'admin':
        admin_count = db.query(User).filter(User.role == 'admin', User.is_active == True).count()
        if admin_count <= 1:
            raise HTTPException(status_code=403, detail="Cannot delete the last active admin.")

    db.delete(user)
    db.commit()
    log_action(db, current_user.id, "delete_user", target_user_id=user_id)
    return None

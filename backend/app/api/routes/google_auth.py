from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from starlette.requests import Request
from sqlalchemy.orm import Session
import uuid
import secrets
from datetime import datetime, timedelta, timezone

from app.database.session import get_db
from app.models.user import User
from app.models.auth import AuthAccount
from app.models.oauth_handoff import OAuthHandoffCode
from app.api.dependencies import get_current_user
from app.core.google_oauth import get_google_oauth_settings
from app.core.security import create_access_token, hash_password, verify_password
from app.core.inbox_tokens import encrypt_token
from app.services.audit import log_action
from app.core.config import settings
from app.schemas.auth import TokenResponse

router = APIRouter(prefix="/auth/google", tags=["Authentication"])

oauth = OAuth()
conf = get_google_oauth_settings()
oauth.register(
    name='google',
    client_id=conf['client_id'],
    client_secret=conf['client_secret'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile https://www.googleapis.com/auth/gmail.readonly'}
)

@router.get("/login")
async def google_login(request: Request):
    return await oauth.google.authorize_redirect(
        request,
        conf['redirect_uri'],
        prompt='consent',
        access_type='offline',
    )

@router.get("/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    user_info = token.get('userinfo')
    if not user_info:
        raise HTTPException(status_code=400, detail="Failed to get user info from Google")

    email = user_info.get('email').lower().strip()
    google_id = user_info.get('sub')

    # 1. Check if AuthAccount exists
    auth_account = db.query(AuthAccount).filter(
        AuthAccount.provider == 'google',
        AuthAccount.provider_account_id == google_id
    ).first()

    user = auth_account.user if auth_account else None

    # 2. Account linking policy
    if not user:
        user = db.query(User).filter(User.email == email).first()
        if user:
            log_action(db, user.id, "google_login_blocked_email_collision", metadata={"google_id": google_id})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account with this email already exists locally. Please login with password."
            )

        # 3. Create new user
        user = User(
            name=user_info.get('name'),
            email=email,
            password_hash=hash_password(str(uuid.uuid4())),
            role="user",
            is_active=True,
            is_verified=user_info.get('email_verified', False)
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        new_auth_account = AuthAccount(
            user_id=user.id,
            provider='google',
            provider_account_id=google_id
        )
        db.add(new_auth_account)
        db.commit()
        auth_account = new_auth_account
        log_action(db, user.id, "google_login_new_user")

    auth_account.access_token_encrypted = encrypt_token(token.get('access_token'))
    if token.get('refresh_token'):
        auth_account.refresh_token_encrypted = encrypt_token(token.get('refresh_token'))
    auth_account.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(token.get('expires_in') or 3600))
    auth_account.token_scope = token.get('scope')
    db.commit()

    # Generate handoff code
    raw_code = secrets.token_urlsafe(32)
    handoff_code = OAuthHandoffCode(
        user_id=user.id,
        code_hash=hash_password(raw_code),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=2)
    )
    db.add(handoff_code)
    db.commit()

    return RedirectResponse(url=f"{settings.FRONTEND_URL}/auth/callback?code={raw_code}")

@router.post("/exchange", response_model=TokenResponse)
def google_exchange(payload: dict, db: Session = Depends(get_db)):
    code = payload.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")

    # Find active codes
    # Since we can't easily query hashed code, we have to fetch potentially all recent codes
    # and verify. This is a bit inefficient but necessary given hashed storage.
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=2)
    handoff_codes = db.query(OAuthHandoffCode).filter(
        OAuthHandoffCode.consumed_at == None,
        OAuthHandoffCode.expires_at > datetime.now(timezone.utc),
        OAuthHandoffCode.created_at >= cutoff
    ).all()

    for hc in handoff_codes:
        if verify_password(code, hc.code_hash):
            # Consume
            hc.consumed_at = datetime.now(timezone.utc)
            db.commit()

            user = db.query(User).filter(User.id == hc.user_id).first()
            log_action(db, user.id, "google_exchange_success")

            return TokenResponse(
                access_token=create_access_token(user),
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            )

    raise HTTPException(status_code=401, detail="Invalid or expired code")


@router.post("/link")
async def google_link_initiation(request: Request, current_user: User = Depends(get_current_user)):
    # Redirect with callback changed back to link-callback
    return await oauth.google.authorize_redirect(request, conf['redirect_uri'].replace("/callback", "/link-callback"))

@router.get("/link-callback")
async def google_link_callback(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    token = await oauth.google.authorize_access_token(request)
    user_info = token.get('userinfo')
    if not user_info:
        raise HTTPException(status_code=400, detail="Failed to get user info from Google")

    google_id = user_info.get('sub')

    # 1. Check if identity already linked to another user
    existing_link = db.query(AuthAccount).filter(
        AuthAccount.provider == 'google',
        AuthAccount.provider_account_id == google_id
    ).first()

    if existing_link:
        if existing_link.user_id != current_user.id:
            log_action(db, current_user.id, "google_link_rejected_already_linked")
            raise HTTPException(status_code=400, detail="This Google account is already linked to another user.")
        return {"detail": "Already linked."}

    # 2. Link account
    new_auth_account = AuthAccount(
        user_id=current_user.id,
        provider='google',
        provider_account_id=google_id
    )
    db.add(new_auth_account)
    db.commit()
    new_auth_account.access_token_encrypted = encrypt_token(token.get('access_token'))
    if token.get('refresh_token'):
        new_auth_account.refresh_token_encrypted = encrypt_token(token.get('refresh_token'))
    new_auth_account.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(token.get('expires_in') or 3600))
    new_auth_account.token_scope = token.get('scope')
    db.commit()
    log_action(db, current_user.id, "google_account_linked")
    return {"detail": "Google account linked successfully."}

@router.delete("/link")
async def google_unlink(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # 1. Check if it's the only AuthAccount
    linked_accounts = db.query(AuthAccount).filter(AuthAccount.user_id == current_user.id).all()
    if len(linked_accounts) <= 1:
        log_action(db, current_user.id, "google_unlink_blocked_lockout")
        raise HTTPException(status_code=400, detail="Cannot unlink last authentication provider.")

    # 2. Unlink
    db.query(AuthAccount).filter(
        AuthAccount.user_id == current_user.id,
        AuthAccount.provider == 'google'
    ).delete()
    db.commit()
    log_action(db, current_user.id, "google_account_unlinked")
    return {"detail": "Google account unlinked successfully."}

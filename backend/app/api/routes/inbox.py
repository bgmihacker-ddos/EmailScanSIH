"""Read-only Gmail inbox synchronization into the forensic queue."""

from __future__ import annotations

import asyncio
import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.api.routes.analysis import _background_analysis_task
from app.core.google_oauth import get_google_oauth_settings
from app.core.inbox_tokens import decrypt_token, encrypt_token
from app.database.session import get_db
from app.models.analysis import AnalysisResult
from app.models.analysis_batch import AnalysisBatch
from app.models.analysis_job import AnalysisJob
from app.models.auth import AuthAccount
from app.models.user import User

router = APIRouter(prefix="/inbox", tags=["Inbox"])
GMAIL_READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def _require_gmail_scope(account: AuthAccount) -> None:
    if GMAIL_READ_SCOPE not in (account.token_scope or ""):
        raise HTTPException(
            status_code=409,
            detail="Gmail read permission is missing. Click Connect Google & Gmail and approve the Gmail read-only permission.",
        )


def _raise_gmail_api_error(response: httpx.Response, action: str) -> None:
    if response.status_code == 401:
        raise HTTPException(status_code=409, detail="Gmail authorization is no longer valid. Reconnect the mailbox.")
    try:
        payload = response.json()
        reason = payload.get("error", {}).get("message") or payload.get("error_description")
    except ValueError:
        reason = None
    detail = f"Gmail {action} failed"
    if reason:
        detail += f": {reason}"
    raise HTTPException(status_code=502, detail=detail)


async def _get_access_token(account: AuthAccount, db: Session) -> str:
    try:
        access_token = decrypt_token(account.access_token_encrypted)
        refresh_token = decrypt_token(account.refresh_token_encrypted)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Stored Gmail credentials could not be decrypted.") from exc

    if access_token and (not account.token_expires_at or account.token_expires_at > datetime.now(timezone.utc)):
        return access_token
    if not refresh_token:
        raise HTTPException(status_code=409, detail="Gmail authorization has expired. Reconnect the mailbox.")

    conf = get_google_oauth_settings()
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post("https://oauth2.googleapis.com/token", data={
            "client_id": conf["client_id"],
            "client_secret": conf["client_secret"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        })
    if response.status_code != 200:
        raise HTTPException(status_code=409, detail="Gmail authorization refresh failed. Reconnect the mailbox.")
    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=409, detail="Gmail did not return a refreshed access token.")
    account.access_token_encrypted = encrypt_token(access_token)
    account.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(payload.get("expires_in") or 3600))
    db.commit()
    return access_token


async def _gmail_raw_messages(access_token: str, limit: int) -> list[bytes]:
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        listing = await client.get("https://gmail.googleapis.com/gmail/v1/users/me/messages", headers=headers, params={"labelIds": "UNREAD", "maxResults": limit})
        if listing.status_code != 200:
            _raise_gmail_api_error(listing, "message listing")
        message_ids = [item.get("id") for item in (listing.json().get("messages") or []) if item.get("id")]
        raw_messages: list[bytes] = []
        for message_id in message_ids:
            response = await client.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}", headers=headers, params={"format": "raw"})
            if response.status_code != 200:
                continue
            raw_value = response.json().get("raw")
            if raw_value:
                raw_messages.append(base64.urlsafe_b64decode(raw_value + "=" * (-len(raw_value) % 4)))
        return raw_messages


async def _gmail_message_ids(access_token: str, limit: int) -> list[str]:
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        listing = await client.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers=headers,
            params={"labelIds": "INBOX", "maxResults": limit},
        )
    if listing.status_code != 200:
        _raise_gmail_api_error(listing, "message listing")
    return [item["id"] for item in listing.json().get("messages", []) if item.get("id")]


async def _gmail_message(access_token: str, message_id: str, format_name: str = "raw") -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
            headers=headers,
            params={"format": format_name, "metadataHeaders": ["Subject", "From", "Date"]},
        )
    if response.status_code == 404:
        raise HTTPException(status_code=404, detail="Gmail message was not found.")
    if response.status_code != 200:
        _raise_gmail_api_error(response, "message retrieval")
    return response.json()


def _message_headers(message: dict[str, Any]) -> dict[str, str]:
    return {
        str(header.get("name", "")).lower(): str(header.get("value", ""))
        for header in message.get("payload", {}).get("headers", [])
    }


@router.get("/gmail/status")
def gmail_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    account = db.query(AuthAccount).filter(AuthAccount.user_id == current_user.id, AuthAccount.provider == "google").first()
    return {"connected": bool(account and account.access_token_encrypted), "gmail_readonly": bool(account and GMAIL_READ_SCOPE in (account.token_scope or "")), "provider": "gmail", "scope": account.token_scope if account else None, "expires_at": account.token_expires_at.isoformat() if account and account.token_expires_at else None}


@router.get("/gmail/messages")
async def gmail_messages(limit: int = Query(10, ge=1, le=25), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    account = db.query(AuthAccount).filter(AuthAccount.user_id == current_user.id, AuthAccount.provider == "google").first()
    if not account or not account.access_token_encrypted:
        raise HTTPException(status_code=409, detail="Connect a Gmail account before browsing messages.")
    _require_gmail_scope(account)
    access_token = await _get_access_token(account, db)
    message_ids = await _gmail_message_ids(access_token, limit)
    message_payloads = await asyncio.gather(*[
        _gmail_message(access_token, message_id, "metadata")
        for message_id in message_ids
    ])
    messages: list[dict[str, Any]] = []
    for message_id, message in zip(message_ids, message_payloads):
        headers = _message_headers(message)
        messages.append({
            "id": message_id,
            "thread_id": message.get("threadId"),
            "subject": headers.get("subject") or "(no subject)",
            "sender": headers.get("from") or "(unknown sender)",
            "date": headers.get("date"),
            "snippet": message.get("snippet") or "",
        })
    return {"messages": messages, "total": len(messages)}


@router.post("/gmail/messages/{message_id}/scan")
async def scan_gmail_message(message_id: str, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    account = db.query(AuthAccount).filter(AuthAccount.user_id == current_user.id, AuthAccount.provider == "google").first()
    if not account or not account.access_token_encrypted:
        raise HTTPException(status_code=409, detail="Connect a Gmail account before scanning messages.")
    _require_gmail_scope(account)
    access_token = await _get_access_token(account, db)
    message = await _gmail_message(access_token, message_id)
    raw_value = message.get("raw")
    if not raw_value:
        raise HTTPException(status_code=422, detail="Gmail did not return the message source.")
    raw_email = base64.urlsafe_b64decode(raw_value + "=" * (-len(raw_value) % 4))
    analysis_id = str(uuid.uuid4())
    db.add(AnalysisResult(id=analysis_id, status="queued", current_stage="Queued from Gmail message", progress_percent=5))
    db.add(AnalysisJob(analysis_id=analysis_id, payload=raw_email))
    db.commit()
    background_tasks.add_task(_background_analysis_task, analysis_id)
    return {"analysis_id": analysis_id, "status": "queued", "message_id": message_id}


@router.post("/gmail/sync")
async def gmail_sync(limit: int = Query(10, ge=1, le=25), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    account = db.query(AuthAccount).filter(AuthAccount.user_id == current_user.id, AuthAccount.provider == "google").first()
    if not account or not account.access_token_encrypted:
        raise HTTPException(status_code=409, detail="Connect a Gmail account before syncing unread messages.")
    access_token = await _get_access_token(account, db)
    raw_messages = await _gmail_raw_messages(access_token, limit)
    batch_id = str(uuid.uuid4())
    batch = AnalysisBatch(id=batch_id, status="queued", total=len(raw_messages))
    db.add(batch)
    queued: list[dict[str, Any]] = []
    for raw_email in raw_messages:
        analysis_id = str(uuid.uuid4())
        db.add(AnalysisResult(id=analysis_id, batch_id=batch_id, status="queued", current_stage="Queued from Gmail inbox", progress_percent=5))
        db.add(AnalysisJob(analysis_id=analysis_id, batch_id=batch_id, payload=raw_email))
        queued.append({"analysis_id": analysis_id, "status": "queued"})
    if not queued:
        batch.status = "completed"
    db.commit()
    for item in queued:
        asyncio.create_task(_background_analysis_task(item["analysis_id"]))
    return {"batch_id": batch_id, "provider": "gmail", "total": len(queued), "queued": queued}

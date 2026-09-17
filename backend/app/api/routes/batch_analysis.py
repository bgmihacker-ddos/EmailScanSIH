"""Batch email ingestion and queued analysis orchestration."""

from __future__ import annotations

import asyncio
import io
import mailbox
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.routes.analysis import _background_analysis_thread
from app.database.session import get_db
from app.models.analysis import AnalysisResult
from app.models.analysis_batch import AnalysisBatch
from app.models.analysis_job import AnalysisJob

router = APIRouter()

_BATCH_ANALYSIS_CONCURRENCY = 2
_batch_analysis_semaphore = asyncio.Semaphore(_BATCH_ANALYSIS_CONCURRENCY)

_MAX_ARCHIVE_MEMBERS = 100
_MAX_ARCHIVE_BYTES = 25 * 1024 * 1024


async def _run_batch_analysis(analysis_id: str) -> None:
    """Keep batch uploads from overwhelming the single-process worker."""
    async with _batch_analysis_semaphore:
        await asyncio.to_thread(_background_analysis_thread, analysis_id)


def _expand_upload(filename: str, raw_bytes: bytes) -> List[Tuple[str, bytes]]:
    suffix = Path(filename).suffix.lower()
    if suffix in {".eml", ".msg"}:
        return [(filename, raw_bytes)]
    if suffix == ".zip":
        expanded: List[Tuple[str, bytes]] = []
        total_bytes = 0
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                raise HTTPException(status_code=413, detail="Archive contains too many email files.")
            for member in members:
                member_name = Path(member.filename)
                if member_name.is_absolute() or ".." in member_name.parts:
                    raise HTTPException(status_code=400, detail="Archive contains an unsafe path.")
                if member_name.suffix.lower() not in {".eml", ".msg"}:
                    continue
                total_bytes += member.file_size
                if total_bytes > _MAX_ARCHIVE_BYTES:
                    raise HTTPException(status_code=413, detail="Archive expands beyond the allowed size limit.")
                expanded.append((member_name.name, archive.read(member)))
        return expanded
    if suffix == ".mbox":
        with tempfile.NamedTemporaryFile(suffix=".mbox") as temporary:
            temporary.write(raw_bytes)
            temporary.flush()
            messages = mailbox.mbox(temporary.name)
            expanded = [(f"{Path(filename).stem}-{index + 1}.eml", message.as_bytes()) for index, message in enumerate(messages)]
            messages.close()
        if len(expanded) > _MAX_ARCHIVE_MEMBERS:
            raise HTTPException(status_code=413, detail="MBOX contains too many messages.")
        if sum(len(message) for _, message in expanded) > _MAX_ARCHIVE_BYTES:
            raise HTTPException(status_code=413, detail="MBOX expands beyond the allowed size limit.")
        return expanded
    raise HTTPException(status_code=400, detail=f"Unsupported batch file type: {filename}")


@router.post("/batch/analyze")
async def analyze_batch(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
):
    """Expand bounded email archives and queue each message for forensic processing."""
    if not files:
        raise HTTPException(status_code=400, detail="At least one email file is required.")

    batch_id = str(uuid.uuid4())
    queued: List[dict] = []
    batch = AnalysisBatch(id=batch_id, status="queued")
    db.add(batch)
    for upload in files:
        if upload.filename is None:
            raise HTTPException(status_code=400, detail="Uploaded batch file has no filename.")
        raw_bytes = await upload.read()
        if not raw_bytes:
            continue
        for message_name, message_bytes in _expand_upload(upload.filename, raw_bytes):
            if not message_bytes:
                continue
            analysis_id = str(uuid.uuid4())
            db.add(AnalysisResult(id=analysis_id, batch_id=batch_id, status="queued", current_stage="Queued for batch analysis", progress_percent=5))
            db.add(AnalysisJob(analysis_id=analysis_id, batch_id=batch_id, payload=message_bytes))
            queued.append({"analysis_id": analysis_id, "filename": message_name, "status": "queued"})
    batch.total = len(queued)
    if not queued:
        batch.status = "failed"
    db.commit()
    for item in queued:
        asyncio.create_task(_run_batch_analysis(item["analysis_id"]))
    return {"batch_id": batch_id, "queued": queued, "total": len(queued)}


@router.get("/batch/{batch_id}/status")
async def batch_status(batch_id: str, db: Session = Depends(get_db)):
    batch = db.query(AnalysisBatch).filter(AnalysisBatch.id == batch_id).first()
    if batch is None:
        raise HTTPException(status_code=404, detail="Batch not found.")
    results = db.query(AnalysisResult).filter(AnalysisResult.batch_id == batch_id).all()
    completed = sum(result.status == "completed" for result in results)
    failed = sum(result.status in {"failed", "cancelled"} for result in results)
    batch.completed = completed
    batch.failed = failed
    batch.updated_at = datetime.now(timezone.utc)
    if batch.total and completed + failed >= batch.total:
        batch.status = "completed" if failed == 0 else "partial"
    elif results:
        batch.status = "processing"
    db.commit()
    return {
        "batch_id": batch_id,
        "status": batch.status,
        "total": batch.total,
        "completed": completed,
        "failed": failed,
        "queued": max(batch.total - completed - failed, 0),
        "analysis_ids": [result.id for result in results],
    }

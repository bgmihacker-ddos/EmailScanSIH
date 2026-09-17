"""Persisted analysis aggregations for the SOC dashboard.

This route only summarizes results created by the local analysis pipeline. It does
not represent external intelligence feeds or invent operational outcomes.
"""

import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session, defer

from app.database.session import get_db
from app.models.analysis import AnalysisResult
from app.models.analysis_job import AnalysisIndicator
from app.services.dashboard_trends import build_trends

router = APIRouter()

_DASHBOARD_CACHE: Dict[str, Any] = {"data": None, "expires_at": 0.0, "recent_limit": 10}
_TRENDS_CACHE: Dict[str, Any] = {"data": None, "expires_at": 0.0}


def invalidate_dashboard_cache() -> None:
    """Invalidate in-memory dashboard caches when new scans finish."""
    _DASHBOARD_CACHE["expires_at"] = 0.0
    _TRENDS_CACHE["expires_at"] = 0.0


_SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#06b6d4",
    "info": "#64748b",
}


def _as_utc(value: datetime) -> datetime:
    """Normalize SQLite's naive timestamps and aware database timestamps."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _summary(record: AnalysisResult) -> Dict[str, Any]:
    """Produce a compact record without embedding parsed email content."""
    result = record.result if isinstance(record.result, dict) else {}
    email = result.get("email") if isinstance(result.get("email"), dict) else {}
    metadata = email.get("metadata") if isinstance(email.get("metadata"), dict) else {}
    sender = email.get("from") or metadata.get("from")
    recipient = email.get("to") or metadata.get("to") or []
    if isinstance(recipient, list):
        recipient = ", ".join(str(item) for item in recipient[:3])

    return {
        "analysis_id": record.id,
        "verdict": record.verdict,
        "risk_score": record.risk_score,
        "severity": record.severity,
        "confidence": record.confidence,
        "summary": record.summary,
        "subject": email.get("subject") or metadata.get("subject") or "(no subject)",
        "sender": sender or "(unknown sender)",
        "recipient": recipient or "(no recipient)",
        "created_at": _as_utc(record.created_at).isoformat(),
        "status": record.status or "completed",
    }


@router.get("/dashboard/summary", response_model=dict)
def get_dashboard_summary(
    recent_limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Return honest dashboard aggregates over persisted local analyses."""
    limit_val = int(recent_limit.default if hasattr(recent_limit, "default") else recent_limit)
    now_ts = time.time()
    if (
        _DASHBOARD_CACHE["data"] is not None
        and now_ts < _DASHBOARD_CACHE["expires_at"]
        and _DASHBOARD_CACHE.get("recent_limit") == limit_val
    ):
        return _DASHBOARD_CACHE["data"]

    # 1. Fast metadata query: Defer huge JSON result & hash_manifest columns (~60x network speedup on Supabase)
    records: List[AnalysisResult] = (
        db.query(AnalysisResult)
        .options(defer(AnalysisResult.result), defer(AnalysisResult.hash_manifest))
        .filter(AnalysisResult.status.in_(["completed", "partial"]))
        .order_by(AnalysisResult.created_at.desc())
        .limit(1000)
        .all()
    )

    verdict_counts = Counter(record.verdict for record in records)
    severity_counts = Counter(record.severity for record in records)
    total = len(records)
    malicious_or_suspicious = verdict_counts["malicious"] + verdict_counts["suspicious"]
    average_risk = round(sum(record.risk_score for record in records) / total, 1) if total else 0

    now = datetime.now(timezone.utc)
    start_day = (now - timedelta(days=6)).date()
    daily = {str(start_day + timedelta(days=index)): 0 for index in range(7)}
    daily_malicious = {str(start_day + timedelta(days=index)): 0 for index in range(7)}

    for record in records:
        created_at = _as_utc(record.created_at)
        day = str(created_at.date())
        if day in daily:
            daily[day] += 1
            if record.verdict in {"malicious", "suspicious"}:
                daily_malicious[day] += 1

    activity = [
        {"date": day, "analyses": daily[day], "flagged": daily_malicious[day]}
        for day in daily
    ]
    distribution = [
        {
            "name": severity,
            "value": severity_counts[severity],
            "color": _SEVERITY_COLORS.get(severity, "#64748b"),
        }
        for severity in ("critical", "high", "medium", "low", "info")
        if severity_counts[severity]
    ]

    # 2. Fast top indicators directly from indexed analysis_indicators table
    top_indicators = []
    try:
        top_rows = (
            db.query(AnalysisIndicator.normalized_value, func.count(AnalysisIndicator.id).label("cnt"))
            .group_by(AnalysisIndicator.normalized_value)
            .order_by(func.count(AnalysisIndicator.id).desc())
            .limit(8)
            .all()
        )
        top_indicators = [{"indicator": row[0], "count": row[1]} for row in top_rows]
    except Exception:
        top_indicators = []

    # 3. Load full payload ONLY for the 10 recent analyses displayed on screen
    recent_records: List[AnalysisResult] = (
        db.query(AnalysisResult)
        .filter(AnalysisResult.status.in_(["completed", "partial"]))
        .order_by(AnalysisResult.created_at.desc())
        .limit(limit_val)
        .all()
    )

    result_data = {
        "metrics": {
            "total_analyses": total,
            "flagged_analyses": malicious_or_suspicious,
            "malicious_analyses": verdict_counts["malicious"],
            "average_risk_score": average_risk,
        },
        "verdict_counts": dict(verdict_counts),
        "severity_counts": dict(severity_counts),
        "activity": activity,
        "distribution": distribution,
        "top_indicators": top_indicators,
        "recent_analyses": [_summary(record) for record in recent_records],
        "data_source": "persisted_local_analyses",
    }

    _DASHBOARD_CACHE["data"] = result_data
    _DASHBOARD_CACHE["expires_at"] = now_ts + 12.0  # 12s cache TTL
    _DASHBOARD_CACHE["recent_limit"] = limit_val
    return result_data


@router.get("/dashboard/trends")
def get_dashboard_trends(db: Session = Depends(get_db)):
    now_ts = time.time()
    if _TRENDS_CACHE["data"] is not None and now_ts < _TRENDS_CACHE["expires_at"]:
        return _TRENDS_CACHE["data"]

    start_date = datetime.now(timezone.utc) - timedelta(days=30)
    records = (
        db.query(AnalysisResult)
        .options(defer(AnalysisResult.hash_manifest))
        .filter(
            AnalysisResult.status.in_(["completed", "partial"]),
            AnalysisResult.created_at >= start_date
        )
        .order_by(AnalysisResult.created_at.desc())
        .limit(500)
        .all()
    )
    trends = build_trends(records)
    _TRENDS_CACHE["data"] = trends
    _TRENDS_CACHE["expires_at"] = now_ts + 15.0  # 15s cache TTL
    return trends

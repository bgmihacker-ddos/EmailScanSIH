"""Reusable, analysis-scoped timing records for forensic pipeline stages."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, Iterator, Optional


def summarize_stage_timings(stage_timings: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a compact summary with slowest stage, total duration, provider success, and fallback usage."""
    valid = [item for item in stage_timings if isinstance(item, dict)]
    if not valid:
        return {
            "stage_latency_ms": {},
            "slowest_stage": None,
            "slowest_stage_ms": 0,
            "total_duration_ms": 0,
            "provider_success_rate": 0.0,
            "fallback_used": False,
        }

    stage_latency_ms = {}
    for item in valid:
        stage_name = str(item.get("stage") or "unknown")
        if stage_name.lower() == "total":
            continue
        duration_ms = item.get("duration_ms")
        if isinstance(duration_ms, (int, float)):
            stage_latency_ms[stage_name] = int(duration_ms)

    total_duration = 0
    total_duration_item = next((item for item in reversed(valid) if str(item.get("stage") or "").lower() == "total"), None)
    if isinstance(total_duration_item, dict):
        total_duration = int(total_duration_item.get("duration_ms") or 0)
    if total_duration == 0:
        total_duration = sum(stage_latency_ms.values())

    slowest_stage = None
    slowest_stage_ms = 0
    if stage_latency_ms:
        slowest_stage, slowest_stage_ms = max(stage_latency_ms.items(), key=lambda entry: entry[1])

    provider_results = [
        str(item.get("status") or "").lower()
        for item in valid
        if str(item.get("stage") or "").lower() != "total"
    ]
    provider_count = len(provider_results) or 1
    successful = sum(1 for status in provider_results if status in {"completed", "ok", "success", "not_found"})
    provider_success_rate = round(successful / provider_count, 2) if provider_count else 0.0

    fallback_used = any(
        bool(item.get("metadata", {}).get("fallback_used"))
        for item in valid
        if isinstance(item, dict) and isinstance(item.get("metadata"), dict)
    )

    return {
        "stage_latency_ms": stage_latency_ms,
        "slowest_stage": slowest_stage,
        "slowest_stage_ms": slowest_stage_ms,
        "total_duration_ms": total_duration,
        "provider_success_rate": provider_success_rate,
        "fallback_used": fallback_used,
    }


class StageTimer:
    """Measure one pipeline stage without hiding stage failures."""

    def __init__(self, analysis_id: str, stage: str, item_count: Optional[int] = None):
        self.analysis_id = analysis_id
        self.stage = stage
        self.item_count = item_count
        self.started_at = datetime.now(timezone.utc)
        self._started = perf_counter()
        self.status = "running"
        self.error: Optional[str] = None
        self.duration_ms: Optional[int] = None

    def complete(self, status: str = "completed", error: Optional[str] = None) -> Dict[str, Any]:
        """Finish the timer and return a JSON-safe timing record."""
        self.status = status
        self.error = error
        self.duration_ms = max(0, round((perf_counter() - self._started) * 1000))
        return self.as_dict()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "stage": self.stage,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "duration_ms": self.duration_ms,
            "item_count": self.item_count,
            "error": self.error,
        }


@contextmanager
def timed_stage(
    analysis_id: str,
    stage: str,
    item_count: Optional[int] = None,
) -> Iterator[StageTimer]:
    """Yield a timer and finalize it as completed or failed on exit."""
    timer = StageTimer(analysis_id, stage, item_count)
    try:
        yield timer
    except Exception as exc:
        timer.complete("failed", type(exc).__name__)
        raise
    else:
        timer.complete()

"""Bounded, privacy-aware alert delivery for high-risk analyses."""

from typing import Any, Dict

import httpx

from app.core.config import settings
from app.realtime import alert_manager


async def dispatch_analysis_alert(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Send a sanitized alert webhook when configured; never include raw email."""
    webhook_url = (settings.ALERT_WEBHOOK_URL or "").strip()
    if not webhook_url:
        return {"status": "not_configured", "provider": "webhook"}

    if str(analysis.get("verdict", "")).lower() == "benign":
        return {"status": "not_required", "provider": "webhook"}

    payload = {
        "analysis_id": analysis.get("analysis_id"),
        "verdict": analysis.get("verdict"),
        "risk_score": analysis.get("risk_score"),
        "severity": analysis.get("severity"),
        "confidence": analysis.get("confidence"),
        "summary": analysis.get("summary"),
        "evidence_count": len(analysis.get("evidence_ledger") or []),
    }
    await alert_manager.broadcast(payload)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0, connect=1.0)) as client:
            response = await client.post(webhook_url, json=payload)
        if 200 <= response.status_code < 300:
            return {"status": "delivered", "provider": "webhook"}
        return {"status": "error", "provider": "webhook", "error": f"Webhook returned HTTP {response.status_code}."}
    except httpx.TimeoutException:
        return {"status": "timeout", "provider": "webhook", "error": "Webhook delivery timed out."}
    except httpx.HTTPError:
        return {"status": "error", "provider": "webhook", "error": "Webhook delivery failed."}

"""Public Feodo Tracker C2 feed adapter (no API key required)."""

import httpx
import logging
from typing import Any

from app.schemas.indicator import ThreatIndicator

logger = logging.getLogger(__name__)


class FeodoTrackerService:
    def __init__(self) -> None:
        self.url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        self.timeout = httpx.Timeout(8.0, connect=3.0)

    async def get_recent_ioc(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(self.url)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                return {"data": [], "status": "error", "error_message": "Feodo Tracker returned an unexpected payload."}

            indicators = []
            for item in payload:
                if not isinstance(item, dict) or not item.get("ip_address"):
                    continue
                tags = [str(item["malware"])] if item.get("malware") else ["botnet", "c2"]
                indicators.append(ThreatIndicator(
                    id=str(item.get("id") or item["ip_address"]),
                    indicator=str(item["ip_address"]),
                    indicator_type="ip",
                    severity="high",
                    confidence=95,
                    source="Feodo Tracker",
                    country=item.get("country") or item.get("country_iso_code"),
                    country_code=item.get("country_iso_code"),
                    latitude=_float(item.get("latitude")),
                    longitude=_float(item.get("longitude")),
                    first_seen=item.get("first_seen"),
                    last_seen=item.get("last_online") or item.get("last_seen"),
                    status="active" if item.get("status") in {"online", "active"} else "inactive",
                    malware=item.get("malware"),
                    tags=tags,
                    reference_url="https://feodotracker.abuse.ch/browse/",
                    reporter="abuse.ch",
                    threat_type="botnet C2",
                ))
            return {"data": indicators, "status": "ok", "error_message": None}
        except httpx.TimeoutException:
            return {"data": [], "status": "timeout", "error_message": "Feodo Tracker request timed out."}
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("Feodo Tracker feed unavailable: %s", exc)
            return {"data": [], "status": "error", "error_message": "Feodo Tracker feed was unavailable."}


def _float(value: object) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None

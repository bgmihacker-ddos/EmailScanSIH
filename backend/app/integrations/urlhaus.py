import httpx
import logging
from typing import List, Optional
from app.schemas.provider import ProviderResponse
from app.schemas.indicator import ThreatIndicator
from app.core.config import settings

logger = logging.getLogger(__name__)

class URLhausService:
    def __init__(self):
        self.base_url = "https://urlhaus-api.abuse.ch/v1/"
        self.timeout = httpx.Timeout(5.0, connect=2.0)

    async def get_recent_urls(self) -> ProviderResponse:
        key = settings.URLHAUS_API_KEY
        if not (key and key.strip()):
            return {"data": [], "status": "not_configured", "error_message": "Provider API key is not configured."}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                headers = {"Auth-Key": key}
                response = await client.get(self.base_url + "urls/recent/", headers=headers)

            if response.status_code == 429:
                return {"data": [], "status": "rate_limited", "error_message": "Provider rate limit reached."}
            if response.status_code in {401, 403}:
                return {"data": [], "status": "unavailable", "error_message": "Provider authorization failed."}
            if response.status_code == 404:
                return {"data": [], "status": "not_found", "error_message": "No results found."}
            response.raise_for_status()

            data = response.json()
            if data.get("query_status") != "ok":
                logger.error(f"URLhaus API Error: {data.get('query_status')}")
                return {"data": [], "status": "error", "error_message": data.get('query_status')}

            indicators = []
            for item in data.get("urls", []):
                if not isinstance(item, dict) or not item.get("id") or not item.get("url"):
                    continue

                tags = item.get("tags") or []
                if not isinstance(tags, list):
                    tags = [str(tags)]

                indicators.append(ThreatIndicator(
                    id=str(item["id"]),
                    indicator=str(item["url"]),
                    indicator_type="url",
                    severity=self._map_severity(item.get("threat")),
                    confidence=self._confidence(item),
                    source="URLhaus",
                    status=str(item.get("url_status")) if item.get("url_status") else "unknown",
                    tags=[str(tag) for tag in tags],
                    reference_url=item.get("urlhaus_reference"),
                    first_seen=item.get("date_added"),
                    last_seen=item.get("last_online"),
                    reporter=item.get("reporter"),
                    threat_type=item.get("threat"),
                ))
            return {"data": indicators, "status": "ok", "error_message": None}
        except httpx.TimeoutException:
            return {"data": [], "status": "timeout", "error_message": "Provider request timed out."}
        except httpx.HTTPError as e:
            logger.error(f"URLhaus HTTP Error: {e}")
            return {"data": [], "status": "error", "error_message": str(e)}
        except Exception as e:
            logger.error(f"URLhaus Unexpected Error: {e}")
            return {"data": [], "status": "error", "error_message": "Provider response was malformed."}

    @staticmethod
    def _map_severity(threat: Optional[str]) -> str:
        value = (threat or "").lower()
        return "high" if value in {"malware", "phishing"} else "medium"

    @staticmethod
    def _confidence(item: dict) -> int:
        blacklists = item.get("blacklists") or {}
        if not isinstance(blacklists, dict):
            return 80
        listed = sum(1 for value in blacklists.values() if value)
        return min(100, 80 + listed * 5)

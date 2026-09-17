import httpx
import logging
from typing import List, Optional
from app.schemas.provider import ProviderResponse
from app.schemas.indicator import ThreatIndicator
from app.core.config import settings

logger = logging.getLogger(__name__)

class ThreatFoxService:
    def __init__(self):
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.timeout = httpx.Timeout(5.0, connect=2.0)

    async def get_recent_ioc(self) -> ProviderResponse:
        key = settings.THREATFOX_API_KEY
        if not (key and key.strip()):
            return {"data": [], "status": "not_configured", "error_message": "Provider API key is not configured."}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                headers = {"Auth-Key": key}
                response = await client.post(self.base_url, json={"query": "get_iocs", "days": 1}, headers=headers)

            if response.status_code == 429:
                return {"data": [], "status": "rate_limited", "error_message": "Provider rate limit reached."}
            if response.status_code in {401, 403}:
                return {"data": [], "status": "unavailable", "error_message": "Provider authorization failed."}
            if response.status_code == 404:
                return {"data": [], "status": "not_found", "error_message": "No results found."}
            response.raise_for_status()

            data = response.json()
            if data.get("query_status") != "ok":
                logger.error(f"ThreatFox API Error: {data.get('query_status')}")
                return {"data": [], "status": "error", "error_message": data.get('query_status')}

            indicators = []
            for item in data.get("data", []):
                if not isinstance(item, dict):
                    continue

                indicator_id = item.get("id") or item.get("ioc_id")
                indicator = item.get("ioc")
                if not indicator_id or not indicator:
                    continue

                tags = item.get("tags") or []
                if not isinstance(tags, list):
                    tags = [str(tags)]

                indicators.append(ThreatIndicator(
                    id=str(indicator_id),
                    indicator=str(indicator),
                    indicator_type=self._map_indicator_type(item.get("ioc_type")),
                    severity=self._map_severity(item.get("threat_type")),
                    confidence=int(item.get("confidence_level") or 0),
                    source="ThreatFox",
                    status=self._map_status(item.get("status")),
                    malware=item.get("malware_printable") or item.get("malware"),
                    tags=[str(tag) for tag in tags],
                    reference_url=item.get("reference"),
                    latitude=self._optional_float(item.get("geo_lat")),
                    longitude=self._optional_float(item.get("geo_long")),
                    country=item.get("country"),
                    country_code=item.get("country_code"),
                    first_seen=item.get("first_seen"),
                    last_seen=item.get("last_seen"),
                    reporter=item.get("reporter"),
                    threat_type=item.get("threat_type"),
                ))
            return {"data": indicators, "status": "ok", "error_message": None}
        except httpx.TimeoutException:
            return {"data": [], "status": "timeout", "error_message": "Provider request timed out."}
        except httpx.HTTPError as e:
            logger.error(f"ThreatFox HTTP Error: {e}")
            return {"data": [], "status": "error", "error_message": str(e)}
        except Exception as e:
            logger.error(f"ThreatFox Unexpected Error: {e}")
            return {"data": [], "status": "error", "error_message": "Provider response was malformed."}

    def _map_severity(self, threat_type: Optional[str]) -> str:
        threat = (threat_type or "").lower()
        if any(term in threat for term in ("phishing", "botnet", "ransomware")):
            return "high"
        if threat:
            return "medium"
        return "low"

    @staticmethod
    def _map_indicator_type(indicator_type: Optional[str]) -> str:
        value = (indicator_type or "").lower()
        if "ipv6" in value:
            return "ip"
        if "ip" in value:
            return "ip"
        if "domain" in value:
            return "domain"
        if "url" in value:
            return "url"
        if "hash" in value or "md5" in value or "sha" in value:
            return "hash"
        return "hash"

    @staticmethod
    def _map_status(status: Optional[str]) -> str:
        if status in {"online", "active"}:
            return "active"
        if status in {"offline", "inactive"}:
            return "inactive"
        return "unknown"

    @staticmethod
    def _optional_float(value: object) -> Optional[float]:
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

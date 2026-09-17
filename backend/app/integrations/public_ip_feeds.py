"""No-key public IP abuse lists used as live telemetry sources."""

from datetime import datetime, timezone
from typing import Any
import ipaddress
import asyncio
import httpx
import logging

from app.schemas.indicator import ThreatIndicator

logger = logging.getLogger(__name__)


class PublicIpFeedService:
    FEEDS = {
        "CINS Army": "https://cinsscore.com/list/ci-badguys.txt",
        "Blocklist.de SSH": "https://lists.blocklist.de/lists/ssh.txt",
    }

    async def get_recent_ioc(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0), follow_redirects=True) as client:
            results = await self._fetch_all(client)
        indicators = [item for result in results for item in result["data"]]
        errors = [result["error_message"] for result in results if result["error_message"]]
        status = "ok" if indicators else ("error" if errors else "not_found")
        return {"data": indicators, "status": status, "error_message": "; ".join(errors) if errors else None}

    async def _fetch_all(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        responses = await asyncio.gather(*(self._fetch_one(client, source, url) for source, url in self.FEEDS.items()), return_exceptions=False)
        return list(responses)

    async def _fetch_one(self, client: httpx.AsyncClient, source: str, url: str) -> dict[str, Any]:
        collected_at = datetime.now(timezone.utc).isoformat()
        try:
            response = await client.get(url)
            response.raise_for_status()
            indicators = []
            for line in response.text.splitlines():
                value = line.strip().split()[0] if line.strip() else ""
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                indicators.append(ThreatIndicator(
                    id=f"{source}-{value}",
                    indicator=value,
                    indicator_type="ip",
                    severity="high" if source == "CINS Army" else "medium",
                    confidence=90,
                    source=source,
                    status="active",
                    first_seen=collected_at,
                    last_seen=collected_at,
                    tags=["public-feed", "ip-abuse"],
                    reference_url=url,
                    reporter=source,
                    threat_type="abusive SSH/scanning IP",
                ))
            return {"data": indicators, "error_message": None}
        except (httpx.HTTPError, ValueError, IndexError) as exc:
            logger.warning("%s feed unavailable: %s", source, exc)
            return {"data": [], "error_message": f"{source} feed unavailable."}

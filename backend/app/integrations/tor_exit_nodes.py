import logging
import time
from typing import Dict, Set

import httpx

logger = logging.getLogger(__name__)


class TorExitNodeChecker:
    """Check whether the IP belongs to a known TOR exit node."""

    TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
    _cache: Set[str] = set()
    _cache_time: float = 0.0
    CACHE_TTL = 3600

    @classmethod
    async def _refresh_cache(cls) -> None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(cls.TOR_LIST_URL)
                if response.status_code != 200:
                    return
                lines = response.text.strip().splitlines()
                cls._cache = {
                    line.strip() for line in lines if line.strip() and not line.startswith("#")
                }
                cls._cache_time = time.monotonic()
                logger.info("TOR exit node list refreshed: %s nodes", len(cls._cache))
        except Exception as exc:  # pragma: no cover - network dependent
            logger.warning("Failed to refresh TOR exit node list: %s", exc)

    @classmethod
    async def is_tor_exit(cls, ip: str) -> bool:
        candidate = (ip or "").strip()
        if not candidate:
            return False
        if candidate in cls._cache:
            return True
        if not cls._cache or time.monotonic() - cls._cache_time > cls.CACHE_TTL:
            await cls._refresh_cache()
        return candidate in cls._cache

    @classmethod
    async def check_ip(cls, ip: str) -> Dict[str, bool | str | int]:
        is_tor = await cls.is_tor_exit(ip)
        return {
            "ip": ip,
            "is_tor_exit_node": is_tor,
            "source": "torproject.org/torbulkexitlist",
            "cache_size": len(cls._cache),
        }

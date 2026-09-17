"""WHOIS intelligence lookup service."""

import logging
import asyncio
import time
from typing import Any, Dict, Optional
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

class WHOISIntelligenceService:
    """Offline-friendly / Cached WHOIS enrichment via whoisxmlapi or similar provider."""

    _TIMEOUT = httpx.Timeout(5.0, connect=2.0)
    _CACHE_TTL = 300.0
    _cache: Dict[str, Dict[str, Any]] = {}
    _unavailable_until: Optional[float] = None
    _unavailable_status: Optional[str] = None
    _unavailable_error: Optional[str] = None
    _provider_available = False
    _health_probe_lock: Optional[asyncio.Lock] = None

    @classmethod
    def clear_cache(cls) -> None:
        """Clear cached records and provider health state for tests or revalidation."""
        cls._cache.clear()
        cls._unavailable_until = None
        cls._unavailable_status = None
        cls._unavailable_error = None
        cls._provider_available = False
        cls._health_probe_lock = None

    @classmethod
    def _cached(cls, domain: str) -> Optional[Dict[str, Any]]:
        cached = cls._cache.get(domain)
        if cached and time.monotonic() - cached["created_at"] < cls._CACHE_TTL:
            return cached["data"]
        if cached:
            cls._cache.pop(domain, None)
        return None

    @classmethod
    def _store(cls, domain: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cls._cache[domain] = {"created_at": time.monotonic(), "data": data}
        return data

    @classmethod
    def _unavailable_result(cls, domain: str) -> Dict[str, Any]:
        return cls._store(domain, {
            "status": cls._unavailable_status or "error",
            "error": cls._unavailable_error or "WHOIS provider is temporarily unavailable.",
        })

    @classmethod
    async def lookup_domain(cls, domain: str) -> Dict[str, Any]:
        """Fetch WHOIS data with one cold-start provider health probe."""
        domain = str(domain or "").strip().lower().rstrip(".")
        cached = cls._cached(domain)
        if cached is not None:
            return cached

        if not settings.WHOIS_ENABLED:
            return cls._store(domain, {
                "status": "disabled",
                "provider": "WHOIS",
                "error": "WHOIS enrichment is disabled until a valid subscription is configured.",
            })

        if not settings.WHOIS_API_KEY:
            return cls._store(domain, {"status": "not_configured"})

        if cls._unavailable_until and time.monotonic() < cls._unavailable_until:
            return cls._unavailable_result(domain)

        if cls._provider_available:
            return await cls._lookup_uncached(domain)

        if cls._health_probe_lock is None:
            cls._health_probe_lock = asyncio.Lock()
        async with cls._health_probe_lock:
            if cls._unavailable_until and time.monotonic() < cls._unavailable_until:
                return cls._unavailable_result(domain)
            if cls._provider_available:
                return await cls._lookup_uncached(domain)

            result = await cls._lookup_uncached(domain)
            if result.get("status") in {"unauthorized", "timeout", "error"}:
                cls._unavailable_until = time.monotonic() + cls._CACHE_TTL
                cls._unavailable_status = result["status"]
                cls._unavailable_error = result.get("error")
            else:
                cls._provider_available = True
            return result

    @classmethod
    async def _lookup_uncached(cls, domain: str) -> Dict[str, Any]:
        """Perform one WHOIS request after cache and health checks."""

        try:
            # Assuming whoisxmlapi for the structure based on common WHOIS_API_KEY env setups
            # adjust if a different provider was intended.
            async with httpx.AsyncClient(timeout=cls._TIMEOUT) as client:
                response = await client.get(
                    "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                    params={
                        "apiKey": settings.WHOIS_API_KEY,
                        "domainName": domain,
                        "outputFormat": "JSON"
                    }
                )

            if response.status_code != 200:
                logger.warning(f"WHOIS lookup failed with status {response.status_code}")
                if response.status_code in (401, 403):
                    cls._unavailable_until = time.monotonic() + cls._CACHE_TTL
                    cls._unavailable_status = "unauthorized"
                    cls._unavailable_error = "WHOIS provider authorization failed."
                    return cls._store(domain, {"status": "unauthorized", "error": "WHOIS provider authorization failed."})
                return cls._store(domain, {"status": "error", "error": f"HTTP {response.status_code}"})

            data = response.json()
            whr = data.get("WhoisRecord", {})

            registry_data = whr.get("registryData", {})
            created = registry_data.get("createdDate") or whr.get("createdDate")
            expires = registry_data.get("expiresDate") or whr.get("expiresDate")
            registrar = whr.get("registrarName")

            return cls._store(domain, {
                "status": "ok",
                "domain": domain,
                "created_date": created,
                "expires_date": expires,
                "registrar": registrar,
                "raw_record": data
            })
        except httpx.TimeoutException:
            result = {"status": "timeout", "error": "Provider request timed out."}
            cls._unavailable_until = time.monotonic() + cls._CACHE_TTL
            cls._unavailable_status = "timeout"
            cls._unavailable_error = result["error"]
            return cls._store(domain, result)
        except Exception as e:
            logger.warning(f"WHOIS lookup exception: {e}")
            result = {"status": "error", "error": str(e)}
            cls._unavailable_until = time.monotonic() + cls._CACHE_TTL
            cls._unavailable_status = "error"
            cls._unavailable_error = result["error"]
            return cls._store(domain, result)

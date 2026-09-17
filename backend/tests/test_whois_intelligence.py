from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.core.config import settings
from app.services.whois_intelligence import WHOISIntelligenceService


@pytest.mark.asyncio
async def test_unauthorized_whois_is_cached_as_provider_state(monkeypatch):
    WHOISIntelligenceService.clear_cache()
    monkeypatch.setattr(settings, "WHOIS_ENABLED", True)
    monkeypatch.setattr(settings, "WHOIS_API_KEY", "configured")
    response = httpx.Response(401, request=httpx.Request("GET", "https://whois.test"))
    client = AsyncMock()
    client.get.return_value = response

    class ClientContext:
        async def __aenter__(self):
            return client

        async def __aexit__(self, *args):
            return False

    with patch("app.services.whois_intelligence.httpx.AsyncClient", return_value=ClientContext()):
        first = await WHOISIntelligenceService.lookup_domain("Example.COM")
        second = await WHOISIntelligenceService.lookup_domain("other.example")

    assert first["status"] == "unauthorized"
    assert second["status"] == "unauthorized"
    assert client.get.await_count == 1
    WHOISIntelligenceService.clear_cache()


@pytest.mark.asyncio
async def test_timeout_whois_is_cached_as_timeout_state(monkeypatch):
    WHOISIntelligenceService.clear_cache()
    monkeypatch.setattr(settings, "WHOIS_ENABLED", True)
    monkeypatch.setattr(settings, "WHOIS_API_KEY", "configured")
    client = AsyncMock()
    client.get.side_effect = httpx.TimeoutException("slow provider")

    class ClientContext:
        async def __aenter__(self):
            return client

        async def __aexit__(self, *args):
            return False

    with patch("app.services.whois_intelligence.httpx.AsyncClient", return_value=ClientContext()):
        first = await WHOISIntelligenceService.lookup_domain("first.example")
        second = await WHOISIntelligenceService.lookup_domain("second.example")

    assert first["status"] == "timeout"
    assert second["status"] == "timeout"
    assert client.get.await_count == 1
    WHOISIntelligenceService.clear_cache()
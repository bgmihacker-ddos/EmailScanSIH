"""Offline regression tests for the authenticated live threat feed."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.api.routes import live_threats
from app.main import app
from app.schemas.indicator import ThreatIndicator


client = TestClient(app)


def _indicator(**overrides):
    values = {
        "id": "ioc-1",
        "indicator": "evil.example",
        "indicator_type": "domain",
        "severity": "high",
        "confidence": 90,
        "source": "ThreatFox",
        "status": "active",
    }
    values.update(overrides)
    return ThreatIndicator(**values)


def test_live_threats_route_keeps_non_geolocated_events():
    threatfox = {
        "data": [_indicator()],
        "status": "ok",
        "error_message": None,
    }
    urlhaus = {
        "data": [_indicator(id="uh-1", indicator="https://evil.example/a", indicator_type="url", source="URLhaus", latitude=12.5, longitude=77.6)],
        "status": "ok",
        "error_message": None,
    }

    with patch.object(live_threats.ThreatFoxService, "get_recent_ioc", new=AsyncMock(return_value=threatfox)), \
            patch.object(live_threats.URLhausService, "get_recent_urls", new=AsyncMock(return_value=urlhaus)), \
             patch.object(live_threats.FeodoTrackerService, "get_recent_ioc", new=AsyncMock(return_value={"data": [], "status": "ok", "error_message": None})), \
             patch.object(live_threats.PublicIpFeedService, "get_recent_ioc", new=AsyncMock(return_value={"data": [], "status": "ok", "error_message": None})):
        response = client.get("/api/live-threats")

    assert response.status_code == 200
    payload = response.json()
    assert payload["meta"]["count"] == 2
    assert {item["source"] for item in payload["data"]} == {"ThreatFox", "URLhaus"}
    no_geo = next(item for item in payload["data"] if item["source"] == "ThreatFox")
    assert no_geo["latitude"] is None
    assert no_geo["longitude"] is None
    geo = next(item for item in payload["data"] if item["source"] == "URLhaus")
    assert geo["latitude"] == 12.5
    assert geo["longitude"] == 77.6
    assert payload["meta"]["providers"][0]["status"] == "ok"


def test_threatfox_live_adapter_normalizes_current_fields():
    response = type("Response", (), {
        "status_code": 200,
        "json": lambda self: {
            "query_status": "ok",
            "data": [{
                "id": 42,
                "ioc": "evil.example",
                "ioc_type": "domain",
                "threat_type": "botnet_cc",
                "confidence_level": 88,
                "first_seen": "2026-09-07",
                "tags": None,
            }],
        },
        "raise_for_status": lambda self: None,
    })()

    async def fake_post(*args, **kwargs):
        assert kwargs["headers"] == {"Auth-Key": "test-key"}
        assert kwargs["json"] == {"query": "get_iocs", "days": 1}
        return response

    with patch("app.integrations.threatfox.settings.THREATFOX_API_KEY", "test-key"), \
         patch("httpx.AsyncClient.post", new=fake_post):
        from app.integrations.threatfox import ThreatFoxService
        import asyncio

        result = asyncio.run(ThreatFoxService().get_recent_ioc())

    assert result["status"] == "ok"
    assert result["data"][0].id == "42"
    assert result["data"][0].tags == []
    assert result["data"][0].status == "unknown"


def test_urlhaus_live_adapter_uses_get_and_handles_null_tags():
    response = type("Response", (), {
        "status_code": 200,
        "json": lambda self: {
            "query_status": "ok",
            "urls": [{
                "id": 7,
                "url": "https://evil.example/a",
                "url_status": "online",
                "threat": "malware",
                "tags": None,
                "date_added": "2026-09-07",
            }],
        },
        "raise_for_status": lambda self: None,
    })()

    async def fake_get(*args, **kwargs):
        assert kwargs["headers"] == {"Auth-Key": "test-key"}
        return response

    with patch("app.integrations.urlhaus.settings.URLHAUS_API_KEY", "test-key"), \
         patch("httpx.AsyncClient.get", new=fake_get):
        from app.integrations.urlhaus import URLhausService
        import asyncio

        result = asyncio.run(URLhausService().get_recent_urls())

    assert result["status"] == "ok"
    assert result["data"][0].id == "7"
    assert result["data"][0].tags == []
    assert result["data"][0].first_seen == "2026-09-07"


def test_live_threats_enriches_public_ips():
    from app.services.geo_enricher import GeoEnricher
    GeoEnricher._cache.clear()

    threatfox = {
        "data": [
            _indicator(id="tf-ip-1", indicator="8.8.8.8:8080", indicator_type="ip", source="ThreatFox"),
            _indicator(id="tf-dom-1", indicator="evil.example", indicator_type="domain", source="ThreatFox"),
        ],
        "status": "ok",
        "error_message": None,
    }
    urlhaus = {
        "data": [],
        "status": "ok",
        "error_message": None,
    }

    geo_data = {
        "latitude": 37.751,
        "longitude": -97.822,
        "country": "United States",
        "country_code": "US",
        "city": "Ashburn",
        "geo_source": "https://ipapi.co",
    }

    with patch.object(live_threats.ThreatFoxService, "get_recent_ioc", new=AsyncMock(return_value=threatfox)), \
            patch.object(live_threats.URLhausService, "get_recent_urls", new=AsyncMock(return_value=urlhaus)), \
            patch.object(live_threats.FeodoTrackerService, "get_recent_ioc", new=AsyncMock(return_value={"data": [], "status": "ok", "error_message": None})), \
             patch.object(live_threats.PublicIpFeedService, "get_recent_ioc", new=AsyncMock(return_value={"data": [], "status": "ok", "error_message": None})), \
         patch.object(live_threats.GeoEnricher, "enrich_ip", new=AsyncMock(return_value=geo_data)) as mock_enrich:
        # Pre-seed or let it enrich
        GeoEnricher._cache["8.8.8.8"] = geo_data
        response = client.get("/api/live-threats")

    assert response.status_code == 200
    payload = response.json()
    assert payload["meta"]["count"] == 2

    enriched_event = next(e for e in payload["data"] if e["id"] == "TF-tf-ip-1")
    assert enriched_event["latitude"] == 37.751
    assert enriched_event["longitude"] == -97.822
    assert enriched_event["country"] == "United States"
    assert enriched_event["geo_source"] == "https://ipapi.co"

    domain_event = next(e for e in payload["data"] if e["id"] == "TF-tf-dom-1")
    assert domain_event["latitude"] is None
    assert domain_event["longitude"] is None
    assert domain_event["geo_source"] is None

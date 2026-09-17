"""Unit tests for GeoEnricher IP geolocation service."""

import pytest
from unittest.mock import AsyncMock, patch
from app.services.geo_enricher import GeoEnricher


def test_extract_ip():
    assert GeoEnricher.extract_ip("8.8.8.8") == "8.8.8.8"
    assert GeoEnricher.extract_ip("8.8.8.8:8080") == "8.8.8.8"
    assert GeoEnricher.extract_ip("[2001:4860:4860::8888]:443") == "2001:4860:4860::8888"
    assert GeoEnricher.extract_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"
    assert GeoEnricher.extract_ip("example.com") is None
    assert GeoEnricher.extract_ip("http://8.8.8.8/malware.exe") == "8.8.8.8"
    assert GeoEnricher.extract_ip("https://8.8.8.8:8080/path") == "8.8.8.8"
    assert GeoEnricher.extract_ip("http://example.com/malware.exe") is None
    assert GeoEnricher.extract_ip("192.168.1.1:8080") is None  # Private IP

def test_is_public_ip():
    # Public IPs
    assert GeoEnricher.is_public_ip("8.8.8.8") is True
    assert GeoEnricher.is_public_ip("1.1.1.1") is True

    # Private / Reserved / Loopback
    assert GeoEnricher.is_public_ip("192.168.1.1") is False
    assert GeoEnricher.is_public_ip("10.0.0.1") is False
    assert GeoEnricher.is_public_ip("127.0.0.1") is False
    assert GeoEnricher.is_public_ip("169.254.1.1") is False

    # Invalid
    assert GeoEnricher.is_public_ip("not-an-ip") is False
    assert GeoEnricher.is_public_ip("") is False


@pytest.mark.asyncio
async def test_enrich_ip_private_ignored():
    GeoEnricher._cache.clear()
    res = await GeoEnricher.enrich_ip("192.168.1.1")
    assert res is None


@pytest.mark.asyncio
async def test_enrich_ip_success():
    GeoEnricher._cache.clear()
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "latitude": 37.751,
        "longitude": -97.822,
        "country_name": "United States",
        "country_code": "US",
        "city": "Washington",
        "proxy": True,
        "hosting": True,
        "mobile": False,
        "isp": "Google LLC",
        "org": "Google Cloud",
        "as": "AS15169 Google LLC"
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
         patch("app.services.geo_enricher.settings.GEOLOCATION_API_URL", "https://ipapi.co"):
        mock_get.return_value = mock_response
        res = await GeoEnricher.enrich_ip("8.8.8.8")

        assert res is not None
        assert res["latitude"] == 37.751
        assert res["longitude"] == -97.822
        assert res["country"] == "United States"
        assert res["geo_source"] == "https://ipapi.co"
        assert res["is_proxy"] is True
        assert res["is_hosting"] is True
        assert res["is_mobile"] is False
        assert res["isp"] == "Google LLC"
        assert res["org"] == "Google Cloud"
        assert res["asn"] == "AS15169 Google LLC"


@pytest.mark.asyncio
async def test_enrich_ip_caching():
    GeoEnricher._cache.clear()
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "latitude": 51.5,
        "longitude": -0.12,
        "country_name": "United Kingdom",
        "country_code": "GB",
        "city": "London"
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
         patch("app.services.geo_enricher.settings.GEOLOCATION_API_URL", "https://ipapi.co"):
        mock_get.return_value = mock_response

        # First call hits the network
        res1 = await GeoEnricher.enrich_ip("1.1.1.1")
        assert res1 is not None
        assert mock_get.call_count == 1

        # Second call should use cache, not calling get again
        res2 = await GeoEnricher.enrich_ip("1.1.1.1")
        assert res2 == res1
        assert mock_get.call_count == 1



@pytest.mark.asyncio
async def test_enrich_ip_ipinfo_format():
    GeoEnricher._cache.clear()
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "ip": "8.8.8.8",
        "loc": "37.4056,-122.0775",
        "country": "US",
        "city": "Mountain View"
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        res = await GeoEnricher.enrich_ip("8.8.8.8")

        assert res is not None
        assert res["latitude"] == 37.4056
        assert res["longitude"] == -122.0775
        assert res["country"] == "US"
        assert res["country_code"] == "US"
        assert res["city"] == "Mountain View"


@pytest.mark.asyncio
async def test_enrich_ip_failure_non_fatal():
    GeoEnricher._cache.clear()
    with patch("httpx.AsyncClient.get", side_effect=Exception("Network timeout")):
        res = await GeoEnricher.enrich_ip("8.8.8.8")
        assert res is None


@pytest.mark.asyncio
async def test_reverse_lookup_reports_not_found_without_blocking():
    with patch("socket.gethostbyaddr", side_effect=__import__("socket").herror()):
        result = await GeoEnricher.reverse_lookup("8.8.8.8")

    assert result["status"] == "not_found"
    assert result["source"] == "reverse_dns_ptr"

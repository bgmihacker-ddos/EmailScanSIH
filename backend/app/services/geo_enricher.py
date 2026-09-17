"""IP Geolocation Enrichment Service.

Enriches public/routable IP addresses with real geolocation data using a public lookup
API (ipapi.co) with strict private IP exclusion, in-memory caching, and non-fatal failure handling.
"""

import ipaddress
import logging
import asyncio
import socket
from typing import Any, Dict, Optional
from urllib.parse import urlparse
import httpx
from app.core.config import settings

logger = logging.getLogger(__name__)


class GeoEnricher:
    _cache: Dict[str, Optional[Dict[str, Any]]] = {}

    @classmethod
    def extract_ip(cls, indicator: str) -> Optional[str]:
        """Extract valid public IP from raw indicator string (e.g. ip:port, URL, or pure IP)."""
        if not indicator:
            return None
        candidate = indicator.strip()

        # Handle URLs (e.g. http://194.26.192.12/malware.exe)
        lower_cand = candidate.lower()
        if lower_cand.startswith("http://") or lower_cand.startswith("https://") or lower_cand.startswith("ftp://"):
            try:
                parsed = urlparse(candidate)
                if parsed.hostname:
                    candidate = parsed.hostname
            except Exception:
                pass

        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1:candidate.index("]")]
        elif candidate.count(":") == 1:
            host, port = candidate.rsplit(":", 1)
            if port.isdigit():
                candidate = host

        if cls.is_public_ip(candidate):
            return candidate
        return None

    @classmethod
    def is_public_ip(cls, ip_str: str) -> bool:
        """Return True if the string is a valid public, routable IP address."""
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            return not (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
                or addr.is_unspecified
            )
        except ValueError:
            return False

    @classmethod
    async def enrich_ip(cls, ip_str: str, client: Optional[httpx.AsyncClient] = None) -> Optional[Dict[str, Any]]:
        """Geolocate a public IP address with caching, multi-provider format handling, and fallback."""
        if not ip_str or not cls.is_public_ip(ip_str):
            return None

        clean_ip = ip_str.strip()
        if clean_ip in cls._cache:
            return cls._cache[clean_ip]

        # Determine configured lookup URL
        raw_geo_setting = (settings.GEOLOCATION_API_URL or "").strip()

        # If user passed a bare token (e.g. 14-char ipinfo token)
        if raw_geo_setting and not (raw_geo_setting.startswith("http://") or raw_geo_setting.startswith("https://")):
            primary_url = f"https://ipinfo.io/{clean_ip}/json?token={raw_geo_setting}"
            primary_source = "https://ipinfo.io"
        elif "ipinfo.io" in raw_geo_setting:
            primary_url = f"{raw_geo_setting.rstrip('/')}/{clean_ip}/json"
            primary_source = raw_geo_setting.rstrip("/")
        elif "ip-api.com" in raw_geo_setting:
            primary_url = f"{raw_geo_setting.rstrip('/')}/json/{clean_ip}"
            primary_source = raw_geo_setting.rstrip("/")
        else:
            base = raw_geo_setting.rstrip("/") if raw_geo_setting else "https://ipapi.co"
            primary_url = f"{base}/{clean_ip}/json/"
            primary_source = base

        candidate_endpoints = [
            (primary_url, primary_source),
            (f"http://ip-api.com/json/{clean_ip}", "http://ip-api.com")
        ]

        # Deduplicate if fallback is already primary
        seen_urls = set()
        endpoints = []
        for u, s in candidate_endpoints:
            if u not in seen_urls:
                seen_urls.add(u)
                endpoints.append((u, s))

        headers = {"User-Agent": "EmailThreatDetection-GeoEnricher/1.0"}

        async def _do_lookup(http_client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
            for url, source_label in endpoints:
                try:
                    response = await http_client.get(url, headers=headers)
                    if response.status_code != 200:
                        continue

                    data = response.json()
                    if hasattr(data, "__await__"):
                        data = await data

                    if not isinstance(data, dict) or data.get("error") or data.get("status") == "fail":
                        continue

                    # Standard latitude / longitude
                    lat = data.get("latitude")
                    lon = data.get("longitude")

                    # ipinfo.io 'loc': 'lat,lon' format
                    if (lat is None or lon is None) and "loc" in data:
                        parts = str(data["loc"]).split(",")
                        if len(parts) == 2:
                            try:
                                lat, lon = float(parts[0]), float(parts[1])
                            except ValueError:
                                pass

                    # ip-api.com 'lat' and 'lon'
                    if (lat is None or lon is None) and "lat" in data and "lon" in data:
                        try:
                            lat, lon = float(data["lat"]), float(data["lon"])
                        except ValueError:
                            pass

                    if lat is not None and lon is not None:
                        country = data.get("country_name") or data.get("country") or "Unknown"
                        country_code = data.get("country_code") or data.get("countryCode")
                        if not country_code and len(str(country)) == 2:
                            country_code = country

                        result = {
                            "latitude": float(lat),
                            "longitude": float(lon),
                            "country": str(country),
                            "country_code": str(country_code) if country_code else None,
                            "city": data.get("city"),
                            "geo_source": source_label,
                            "is_proxy": bool(data.get("proxy", False)),
                            "is_hosting": bool(data.get("hosting", False)),
                            "is_mobile": bool(data.get("mobile", False)),
                            "isp": data.get("isp") or data.get("org") or data.get("as") or None,
                            "org": data.get("org") or None,
                            "asn": data.get("as") or None,
                        }
                        cls._cache[clean_ip] = result
                        return result
                except Exception as exc:
                    logger.debug(f"Geolocation attempt failed for {clean_ip} on {url}: {exc}")
                    continue
            return None

        try:
            if client is not None:
                return await _do_lookup(client)
            else:
                async with httpx.AsyncClient(timeout=settings.GEOLOCATION_API_TIMEOUT_SECONDS) as new_client:
                    return await _do_lookup(new_client)
        except Exception as exc:
            logger.debug(f"Geolocation client failed for {clean_ip}: {exc}")

        cls._cache[clean_ip] = None
        return None

    @classmethod
    async def reverse_lookup(cls, ip_str: str, timeout_seconds: float = 2.0) -> Dict[str, Any]:
        """Resolve a public IP to a PTR name without blocking the event loop."""
        if not cls.is_public_ip(ip_str):
            return {"status": "not_applicable", "hostname": None}

        clean_ip = ip_str.strip()

        def _lookup() -> str:
            return socket.gethostbyaddr(clean_ip)[0]

        try:
            hostname = await asyncio.wait_for(asyncio.to_thread(_lookup), timeout_seconds)
            return {"status": "ok", "hostname": hostname, "source": "reverse_dns_ptr"}
        except socket.herror:
            return {"status": "not_found", "hostname": None, "source": "reverse_dns_ptr"}
        except (socket.gaierror, asyncio.TimeoutError, OSError):
            return {"status": "unavailable", "hostname": None, "source": "reverse_dns_ptr"}



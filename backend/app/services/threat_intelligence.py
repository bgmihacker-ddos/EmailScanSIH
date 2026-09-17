"""Credential-gated threat-intelligence lookups with normalized results."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set
from urllib.parse import urlparse

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

ProviderResult = Dict[str, Any]
_TIMEOUT = httpx.Timeout(5.0, connect=2.0)
_PUBLIC_LOOKUP_TIMEOUT = httpx.Timeout(8.0, connect=2.0)
_MAX_INDICATOR_LENGTH = 2048


def _configured(value: Optional[str]) -> bool:
    return bool(value and value.strip())


# AUDIT SCRIPT: Threat Intelligence Normalization & SSRF Defense
# Importers/Callers: app.services.threat_intelligence internal usage
# Affected API: app.services.threat_intelligence._normalize_indicator
# Data schemas: normalizes ip, ipv6, url, domain, hash
# Verbatim instruction: "Transform the existing standalone threat-intelligence integrations into one resilient, normalized, evidence-aware IOC intelligence layer."

def _normalize_indicator(indicator_type: str, indicator: str) -> Optional[str]:
    value = str(indicator or "").strip()
    if not value or len(value) > _MAX_INDICATOR_LENGTH:
        return None
    kind = indicator_type.lower().strip()
    if kind in {"ip", "ipv6"}:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return None
        if kind == "ip" and parsed.version != 4:
            return None
        if kind == "ipv6" and parsed.version != 6:
            return None
        # SSRF protection: reject loopback, link-local, unspecified, multicast, and RFC 1918 private ranges
        if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified or parsed.is_multicast:
            return None
        if isinstance(parsed, ipaddress.IPv4Address):
            if parsed in ipaddress.IPv4Network("10.0.0.0/8") or parsed in ipaddress.IPv4Network("172.16.0.0/12") or parsed in ipaddress.IPv4Network("192.168.0.0/16"):
                return None
        elif isinstance(parsed, ipaddress.IPv6Address):
            if parsed.is_site_local:
                return None
        return str(parsed)
    if kind == "url":
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        try:
            host_ip = ipaddress.ip_address(parsed.hostname)
            if host_ip.is_loopback or host_ip.is_link_local or host_ip.is_unspecified or host_ip.is_multicast:
                return None
            if isinstance(host_ip, ipaddress.IPv4Address):
                if host_ip in ipaddress.IPv4Network("10.0.0.0/8") or host_ip in ipaddress.IPv4Network("172.16.0.0/12") or host_ip in ipaddress.IPv4Network("192.168.0.0/16"):
                    return None
        except (ValueError, TypeError):
            pass
        return value
    if kind in {"domain", "hash"}:
        return value.lower()
    return None


@dataclass
class ThreatIntelProvider:
    name: str
    api_key: Optional[str]
    _circuit_breaker_until: float = 0.0
    supported_indicator_types: Set[str] = field(default_factory=lambda: {"url", "domain", "ip", "ipv6", "hash"})

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        raise NotImplementedError

    def is_healthy(self) -> bool:
        if not _configured(self.api_key):
            return False
        return time.monotonic() >= self._circuit_breaker_until

    def trip_circuit_breaker(self, duration: float = 300.0) -> None:
        """Trip circuit breaker for providers on unauthorized or persistent errors."""
        self._circuit_breaker_until = time.monotonic() + duration
        logger.warning(f"Circuit breaker tripped for provider {self.name} due to auth/persistent error.")

    def unavailability_reason(self) -> str:
        if not _configured(self.api_key):
            return "not_configured"
        if time.monotonic() < self._circuit_breaker_until:
            return "circuit_broken"
        return "available"

    def unavailable_result(self, indicator_type: str, indicator: str) -> ProviderResult:
        reason = self.unavailability_reason()
        error_msg = f"{self.name} API key is not configured." if reason == "not_configured" else f"{self.name} is temporarily disabled (unauthorized/rate-limited)."
        status = "not_configured" if reason == "not_configured" else "skipped"
        return _result(self.name, indicator, indicator_type, status, error=error_msg)

    def invalid_result(self, indicator_type: str, indicator: str) -> ProviderResult:
        return _result(self.name, indicator, indicator_type, "error", error="Unsupported or malformed indicator.")


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal v3 object lookup; this never submits or uploads an indicator."""

    def __init__(self) -> None:
        super().__init__("VirusTotal", settings.VIRUSTOTAL_API_KEY)

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        endpoint_type = {"url": "urls", "domain": "domains", "ip": "ip_addresses", "ipv6": "ip_addresses", "hash": "files"}.get(indicator_type)
        if not value or not endpoint_type:
            return self.invalid_result(indicator_type, indicator)
        target = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if indicator_type == "url" else value

        if client is not None:
            result = await _get_object(self, value, indicator_type, f"https://www.virustotal.com/api/v3/{endpoint_type}/{target}", {"x-apikey": self.api_key}, client)
        else:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as local_client:
                result = await _get_object(self, value, indicator_type, f"https://www.virustotal.com/api/v3/{endpoint_type}/{target}", {"x-apikey": self.api_key}, local_client)

        if result["status"] in {"unavailable", "rate_limited"}:
            self.trip_circuit_breaker()
        return result


class URLhausProvider(ThreatIntelProvider):
    """URLhaus URL lookup using the abuse.ch Auth-Key header."""

    def __init__(self) -> None:
        super().__init__("URLhaus", settings.URLHAUS_API_KEY)
        self.supported_indicator_types = {"url"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        if indicator_type != "url" or not value:
            return self.invalid_result(indicator_type, indicator)
        try:
            if client is not None:
                response = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": value}, headers={"Auth-Key": self.api_key})
            else:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as local_client:
                    response = await local_client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": value}, headers={"Auth-Key": self.api_key})
            result = _urlhaus_result(self.name, value, indicator_type, response)
            if result["status"] in {"unauthorized", "rate_limited"}:
                self.trip_circuit_breaker()
            return result
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="Provider request timed out.")
        except httpx.HTTPError:
            return _result(self.name, value, indicator_type, "error", error="Provider request failed.")


class ThreatFoxProvider(ThreatIntelProvider):
    """ThreatFox IOC lookup using the abuse.ch Auth-Key header."""

    def __init__(self) -> None:
        super().__init__("ThreatFox", settings.THREATFOX_API_KEY)

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        if indicator_type not in {"url", "domain", "ip", "ipv6", "hash"} or not value:
            return self.invalid_result(indicator_type, indicator)
        try:
            if client is not None:
                response = await client.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": value}, headers={"Auth-Key": self.api_key})
            else:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as local_client:
                    response = await local_client.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": value}, headers={"Auth-Key": self.api_key})
            result = _threatfox_result(self.name, value, indicator_type, response)
            if result["status"] in {"unauthorized", "rate_limited"}:
                self.trip_circuit_breaker()
            return result
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="Provider request timed out.")
        except httpx.HTTPError:
            return _result(self.name, value, indicator_type, "error", error="Provider request failed.")


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB v2 IP reputation lookup."""

    def __init__(self) -> None:
        super().__init__("AbuseIPDB", settings.ABUSEIPDB_API_KEY)
        self.supported_indicator_types = {"ip", "ipv6"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        if indicator_type not in {"ip", "ipv6"} or not value:
            return self.invalid_result(indicator_type, indicator)
        try:
            if client is not None:
                response = await client.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": self.api_key, "Accept": "application/json"}, params={"ipAddress": value, "maxAgeInDays": 90})
            else:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as local_client:
                    response = await local_client.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": self.api_key, "Accept": "application/json"}, params={"ipAddress": value, "maxAgeInDays": 90})
            result = _abuse_result(self.name, value, indicator_type, response)
            if result["status"] in {"unauthorized", "rate_limited"}:
                self.trip_circuit_breaker()
            return result
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="Provider request timed out.")
        except httpx.HTTPError:
            return _result(self.name, value, indicator_type, "error", error="Provider request failed.")


class PhishTankProvider(ThreatIntelProvider):
    """PhishTank verified phishing URL lookup."""

    def __init__(self) -> None:
        super().__init__("PhishTank", settings.PHISHTANK_API_KEY)
        self.supported_indicator_types = {"url"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        if indicator_type != "url" or not value:
            return self.invalid_result(indicator_type, indicator)
        payload = {"url": value, "format": "json", "app_key": self.api_key}
        try:
            if client is not None:
                response = await client.post("https://checkurl.phishtank.com/checkurl/", data=payload)
            else:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as local_client:
                    response = await local_client.post("https://checkurl.phishtank.com/checkurl/", data=payload)
            if response.status_code != 200:
                return _result(self.name, value, indicator_type, "error", error="PhishTank request failed.")
            data = response.json()
            results = data.get("results") if isinstance(data, dict) else {}
            is_phish = bool(results.get("in_database") and results.get("valid"))
            reference = results.get("phish_detail_page") if isinstance(results, dict) else None
            return _result(
                self.name,
                value,
                indicator_type,
                "ok",
                "malicious" if is_phish else "unknown",
                1 if is_phish else 0,
                95 if is_phish else 0,
                ["phishing"] if is_phish else [],
                references=[str(reference)] if reference else [],
            )
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="PhishTank lookup timed out.")
        except (httpx.HTTPError, ValueError, TypeError):
            return _result(self.name, value, indicator_type, "error", error="PhishTank response was unavailable or malformed.")


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    """Google Safe Browsing v4 URL match lookup."""

    def __init__(self) -> None:
        super().__init__("Google Safe Browsing", settings.GOOGLE_SAFE_BROWSING_API_KEY)
        self.supported_indicator_types = {"url"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        if not value:
            return self.invalid_result(indicator_type, indicator)
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "email-threat-detection", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": value}],
            },
        }
        try:
            if client is not None:
                response = await client.post(endpoint, params={"key": self.api_key}, json=payload)
            else:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as local_client:
                    response = await local_client.post(endpoint, params={"key": self.api_key}, json=payload)
            status = _http_status(self.name, value, indicator_type, response)
            if status:
                if status["status"] in {"unavailable", "rate_limited"}:
                    self.trip_circuit_breaker()
                return status
            matches = response.json().get("matches") or []
            categories = list(dict.fromkeys(str(item.get("threatType")) for item in matches if item.get("threatType")))
            if matches:
                return _result(self.name, value, indicator_type, "ok", "malicious", len(matches), 95, categories, references=[endpoint])
            return _result(self.name, value, indicator_type, "ok", "unknown", references=[endpoint])
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="Safe Browsing lookup timed out.")
        except (httpx.HTTPError, ValueError, TypeError):
            return _result(self.name, value, indicator_type, "error", error="Safe Browsing response was unavailable or malformed.")


class AlienVaultOTXProvider(ThreatIntelProvider):
    """AlienVault OTX pulse lookup for URL, domain, IP, and file hash context."""

    def __init__(self) -> None:
        super().__init__("AlienVault OTX", settings.OTX_API_KEY)
        self.supported_indicator_types = {"url", "domain", "ip", "ipv6", "hash"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        if not value:
            return self.invalid_result(indicator_type, indicator)
        section = {"ip": "IPv4", "ipv6": "IPv6", "hash": "file", "domain": "domain", "url": "url"}[indicator_type]
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general"
        headers = {"X-OTX-API-KEY": self.api_key or ""}
        try:
            if client is not None:
                response = await client.get(endpoint, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as local_client:
                    response = await local_client.get(endpoint, headers=headers)
            status = _http_status(self.name, value, indicator_type, response)
            if status:
                if status["status"] in {"unavailable", "rate_limited"}:
                    self.trip_circuit_breaker()
                return status
            payload = response.json()
            pulse_info = payload.get("pulse_info") or {}
            pulse_count = int(pulse_info.get("count") or 0)
            references = [str(item.get("name")) for item in (pulse_info.get("pulses") or []) if item.get("name")][:10]
            return _result(
                self.name,
                value,
                indicator_type,
                "ok",
                "suspicious" if pulse_count else "unknown",
                pulse_count,
                min(80, pulse_count * 10),
                ["otx_pulse"] if pulse_count else [],
                references=references + [endpoint],
                metadata={"pulse_count": pulse_count},
            )
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="OTX lookup timed out.")
        except (httpx.HTTPError, ValueError, TypeError):
            return _result(self.name, value, indicator_type, "error", error="OTX response was unavailable or malformed.")


class RDAPProvider(ThreatIntelProvider):
    """Keyless registration and network allocation lookup via RDAP."""

    def __init__(self) -> None:
        super().__init__("RDAP", "public")
        self.supported_indicator_types = {"domain", "ip", "ipv6"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        value = _normalize_indicator(indicator_type, indicator)
        if not value:
            return self.invalid_result(indicator_type, indicator)
        endpoint = f"https://rdap.org/{'domain' if indicator_type == 'domain' else 'ip'}/{value}"
        try:
            if client is not None:
                response = await client.get(endpoint)
            else:
                async with httpx.AsyncClient(timeout=_PUBLIC_LOOKUP_TIMEOUT, follow_redirects=True) as local_client:
                    response = await local_client.get(endpoint)
            status = _http_status(self.name, value, indicator_type, response)
            if status:
                return status
            payload = response.json()
            events = payload.get("events") or []
            registration_date = None
            domain_age_days = None
            for item in events:
                if str(item.get("eventAction") or "").lower() == "registration":
                    registration_date = item.get("eventDate")
                    try:
                        from datetime import datetime, timezone
                        if registration_date:
                            parsed = datetime.fromisoformat(str(registration_date).replace("Z", "+00:00"))
                            domain_age_days = (datetime.now(timezone.utc) - parsed).days
                    except (TypeError, ValueError):
                        domain_age_days = None
                    break

            return _result(self.name, value, indicator_type, "ok", categories=["registration"], references=[endpoint], metadata={
                "name": payload.get("name"),
                "ldh_name": payload.get("ldhName"),
                "status": payload.get("status", []),
                "events": events,
                "registration_date": registration_date,
                "domain_age_days": domain_age_days,
                "is_newly_registered": bool(domain_age_days is not None and domain_age_days < 30),
            })
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="RDAP lookup timed out.")
        except (httpx.HTTPError, ValueError, TypeError):
            return _result(self.name, value, indicator_type, "error", error="RDAP response was unavailable or malformed.")


class HaveIBeenPwnedProvider(ThreatIntelProvider):
    """Optional Have I Been Pwned domain breach lookup."""

    def __init__(self) -> None:
        super().__init__("HaveIBeenPwned", settings.HIBP_API_KEY)
        self.supported_indicator_types = {"domain"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        if indicator_type != "domain" or not value:
            return self.invalid_result(indicator_type, indicator)
        endpoint = f"https://haveibeenpwned.com/api/v3/breachedomain/{value}"
        headers = {"hibp-api-key": str(self.api_key), "user-agent": "email-threat-detection"}
        try:
            if client is not None:
                response = await client.get(endpoint, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=_PUBLIC_LOOKUP_TIMEOUT) as local_client:
                    response = await local_client.get(endpoint, headers=headers)
            if response.status_code == 404:
                return _result(self.name, value, indicator_type, "not_found", references=[endpoint])
            if response.status_code in {401, 403, 429}:
                self.trip_circuit_breaker()
                return _result(self.name, value, indicator_type, "rate_limited" if response.status_code == 429 else "unauthorized", references=[endpoint], error="HIBP access was rejected or rate limited.")
            if response.status_code != 200:
                return _result(self.name, value, indicator_type, "error", references=[endpoint], error="HIBP response was unavailable.")
            breaches = response.json()
            if not isinstance(breaches, list):
                return _result(self.name, value, indicator_type, "error", references=[endpoint], error="HIBP response was malformed.")
            names = [str(item.get("Name")) for item in breaches if item.get("Name")]
            return _result(self.name, value, indicator_type, "ok", "suspicious" if names else "unknown", len(names), min(100, len(names) * 20), ["domain_breach"] if names else [], references=[endpoint], metadata={"breach_names": names[:20], "breach_count": len(names)})
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", references=[endpoint], error="HIBP lookup timed out.")
        except (httpx.HTTPError, ValueError, TypeError):
            return _result(self.name, value, indicator_type, "error", references=[endpoint], error="HIBP response was unavailable or malformed.")


class CertificateTransparencyProvider(ThreatIntelProvider):
    """Keyless certificate history lookup through crt.sh."""

    def __init__(self) -> None:
        super().__init__("crt.sh", "public")
        self.supported_indicator_types = {"domain"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        value = _normalize_indicator(indicator_type, indicator)
        if not value:
            return self.invalid_result(indicator_type, indicator)
        endpoint = f"https://crt.sh/?q={value}&output=json"
        try:
            if client is not None:
                response = await client.get(endpoint)
            else:
                async with httpx.AsyncClient(timeout=_PUBLIC_LOOKUP_TIMEOUT, follow_redirects=True) as local_client:
                    response = await local_client.get(endpoint)
            status = _http_status(self.name, value, indicator_type, response)
            if status:
                return status
            records = response.json()
            if not isinstance(records, list) or not records:
                return _result(self.name, value, indicator_type, "not_found")
            return _result(self.name, value, indicator_type, "ok", detections=len(records), categories=["certificate_transparency"], references=[endpoint], metadata={
                "issuers": list(dict.fromkeys(str(item.get("issuer_name")) for item in records if item.get("issuer_name")))[:10],
                "latest_names": list(dict.fromkeys(str(item.get("name_value")) for item in records if item.get("name_value")))[:10],
            })
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="Certificate transparency lookup timed out.")
        except (httpx.HTTPError, ValueError, TypeError):
            return _result(self.name, value, indicator_type, "error", error="Certificate transparency response was unavailable or malformed.")


class CIRCLHashlookupProvider(ThreatIntelProvider):
    """Keyless known-file lookup through CIRCL Hashlookup."""

    def __init__(self) -> None:
        super().__init__("CIRCL Hashlookup", "public")
        self.supported_indicator_types = {"hash"}

    async def lookup(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        value = _normalize_indicator(indicator_type, indicator)
        if not value:
            return self.invalid_result(indicator_type, indicator)
        endpoint = f"https://hashlookup.circl.lu/lookup/{value}"
        try:
            if client is not None:
                response = await client.get(endpoint)
            else:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as local_client:
                    response = await local_client.get(endpoint)
            status = _http_status(self.name, value, indicator_type, response)
            if status:
                return status
            payload = response.json()
            return _result(self.name, value, indicator_type, "ok", categories=["known_file"], references=[endpoint], metadata={
                "sha256": payload.get("SHA-256") or payload.get("sha256"),
                "product": payload.get("Product") or payload.get("product"),
                "file_name": payload.get("FileName") or payload.get("file_name"),
            })
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout", error="Hashlookup timed out.")
        except (httpx.HTTPError, ValueError, TypeError):
            return _result(self.name, value, indicator_type, "error", error="Hashlookup response was unavailable or malformed.")


async def _get_object(provider_obj: ThreatIntelProvider, indicator: str, kind: str, endpoint: str, headers: Dict[str, str], client: httpx.AsyncClient) -> ProviderResult:
    provider = provider_obj.name
    try:
        response = await client.get(endpoint, headers=headers)
        status = _http_status(provider, indicator, kind, response)
        if status:
            return status
        payload = response.json()
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = _int(stats.get("malicious")); suspicious = _int(stats.get("suspicious"))
        detections = malicious + suspicious
        return _result(provider, indicator, kind, "ok", "malicious" if malicious else ("suspicious" if suspicious else "unknown"), detections, min(100, detections * 10), [str(k) for k, v in stats.items() if _int(v)])
    except (httpx.TimeoutException, httpx.ReadTimeout):
        return _result(provider, indicator, kind, "timeout", error="Provider request timed out.")
    except (httpx.HTTPError, ValueError, TypeError, AttributeError):
        return _result(provider, indicator, kind, "error", error="Provider response was unavailable or malformed.")


def _http_status(provider: str, indicator: str, kind: str, response: httpx.Response) -> Optional[ProviderResult]:
    if response.status_code == 404: return _result(provider, indicator, kind, "not_found")
    if response.status_code in {401, 403}: return _result(provider, indicator, kind, "unavailable", error="Provider authorization failed.")
    if response.status_code == 429: return _result(provider, indicator, kind, "rate_limited", error="Provider rate limit reached.")
    if response.status_code >= 400: return _result(provider, indicator, kind, "error", error="Provider request failed.")
    return None


def _urlhaus_result(provider: str, indicator: str, kind: str, response: httpx.Response) -> ProviderResult:
    status = _http_status(provider, indicator, kind, response)
    if status: return status
    try:
        payload = response.json()
        if payload.get("query_status") != "ok": return _result(provider, indicator, kind, "not_found")
        tags = [str(x) for x in (payload.get("tags") or [])]
        return _result(provider, indicator, kind, "ok", "malicious", 1, 90, tags, payload.get("date_added"), payload.get("last_online"), [payload["urlhaus_reference"]] if payload.get("urlhaus_reference") else [])
    except (ValueError, TypeError, AttributeError):
        return _result(provider, indicator, kind, "error", error="Provider response was malformed.")
    except Exception as e:
        return _result(provider, indicator, kind, "error", error=f"Provider response error {str(e)}")

def _threatfox_result(provider: str, indicator: str, kind: str, response: httpx.Response) -> ProviderResult:
    status = _http_status(provider, indicator, kind, response)
    if status: return status
    try:
        payload = response.json(); records = payload.get("data") if payload.get("query_status") == "ok" else []
        if not records: return _result(provider, indicator, kind, "not_found")
        records = records if isinstance(records, list) else [records]; record = records[0]
        return _result(provider, indicator, kind, "ok", "malicious", len(records), max(0, min(100, _int(record.get("confidence_level")))), [str(record["threat_type"])] if record.get("threat_type") else [], record.get("first_seen"), record.get("last_seen"), [record["reference"]] if record.get("reference") else [])
    except (ValueError, TypeError, AttributeError):
        return _result(provider, indicator, kind, "error", error="Provider response was malformed.")


def _abuse_result(provider: str, indicator: str, kind: str, response: httpx.Response) -> ProviderResult:
    status = _http_status(provider, indicator, kind, response)
    if status: return status
    try:
        score = max(0, min(100, _int(response.json().get("data", {}).get("abuseConfidenceScore"))))
        return _result(provider, indicator, kind, "ok", "malicious" if score >= 50 else ("suspicious" if score else "unknown"), score, score, ["reported_abuse"] if score else [])
    except (ValueError, TypeError, AttributeError):
        return _result(provider, indicator, kind, "error", error="Provider response was malformed.")


def _int(value: Any) -> int:
    try: return max(0, int(value or 0))
    except (TypeError, ValueError): return 0


def _result(provider: str, indicator: str, indicator_type: str, status: str, reputation: str = "unknown", detections: int = 0, confidence: int = 0, categories: Optional[List[str]] = None, first_seen: Optional[str] = None, last_seen: Optional[str] = None, references: Optional[List[str]] = None, error: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None, fallback_used: bool = False) -> ProviderResult:
    metadata = dict(metadata or {})
    metadata.setdefault("provider_state", status)
    metadata.setdefault("fallback_used", fallback_used)
    return {"provider": provider, "indicator": indicator, "indicator_type": indicator_type, "status": status, "reputation": reputation, "detections": detections, "confidence": confidence, "categories": categories or [], "first_seen": first_seen, "last_seen": last_seen, "references": references or [], "error": error, "metadata": metadata, "fallback_used": fallback_used}


class ThreatIntelligenceService:
    """Bounded, deduplicated provider enrichment with TTL caching and Connection Pooling."""

    _cache: Dict[Tuple[str, str], Tuple[float, List[ProviderResult]]] = {}
    _CACHE_TTL_SECONDS = 300
    _CACHE_MAX_ENTRIES = 512

    # Global list of provider instances to preserve circuit breaker states across requests
    _ALL_PROVIDERS = [VirusTotalProvider(), URLhausProvider(), ThreatFoxProvider(), AbuseIPDBProvider(), RDAPProvider(), HaveIBeenPwnedProvider(), CertificateTransparencyProvider(), CIRCLHashlookupProvider(), GoogleSafeBrowsingProvider(), AlienVaultOTXProvider(), PhishTankProvider()]
    _GLOBAL_PROVIDERS = [
        provider for provider in _ALL_PROVIDERS
        if provider.name not in settings.DISABLED_THREAT_PROVIDERS
    ]

    def __init__(self, providers: Optional[Iterable[ThreatIntelProvider]] = None) -> None:
        self.providers = list(providers) if providers is not None else self._GLOBAL_PROVIDERS

    @staticmethod
    def _ioc_priority(ioc: Dict[str, Any]) -> int:
        """Prioritize high-value external lookups without changing local extraction."""
        kind = str(ioc.get("type") or "")
        source = str(ioc.get("source") or "")
        context = str(ioc.get("context") or "").lower()
        priority = {"url": 100, "ip": 90, "ipv6": 90, "hash": 85, "domain": 70}.get(kind, 0)
        if source == "received_chain":
            priority += 15
        if source == "attachment" or context.startswith("attachment"):
            priority += 10
        if "suspicious" in context or "credential" in context or "imperson" in context:
            priority += 10
        return priority + min(9, int(ioc.get("confidence") or 0) // 10)

    async def enrich_ioc(self, indicator_type: str, indicator: str, client: Optional[httpx.AsyncClient] = None) -> List[ProviderResult]:
        key = (indicator_type.lower(), indicator.lower())
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached and now - cached[0] < self._CACHE_TTL_SECONDS: return cached[1]

        if cached: self._cache.pop(key, None)

        active_providers = [
            provider for provider in self.providers
            if indicator_type.lower() in provider.supported_indicator_types
            and _configured(getattr(provider, "api_key", None))
            and provider.is_healthy()
        ]
        skipped_providers = [provider for provider in self.providers if provider not in active_providers]

        def skipped_result(provider: ThreatIntelProvider) -> ProviderResult:
            configured = _configured(getattr(provider, "api_key", None))
            if not configured:
                return _result(
                    provider.name,
                    indicator,
                    indicator_type,
                    "not_configured",
                    error=f"{provider.name} API key is not configured.",
                )
            if indicator_type.lower() not in provider.supported_indicator_types:
                return _result(
                    provider.name,
                    indicator,
                    indicator_type,
                    "skipped",
                    error=f"{provider.name} does not support {indicator_type} lookups.",
                )
            return _result(
                provider.name,
                indicator,
                indicator_type,
                "not_configured" if not configured else "skipped",
                error=(
                    f"{provider.name} API key is not configured."
                    if not configured
                    else f"{provider.name} is temporarily disabled (unauthorized/rate-limited)."
                ),
            )

        if not active_providers:
            result = [skipped_result(provider) for provider in self.providers]
            self._cache[key] = (now, result)
            return result

        # Bounded concurrency across healthy, configured providers only.
        results = await asyncio.gather(*(p.lookup(indicator_type, indicator, client) for p in active_providers), return_exceptions=True)
        normalized = [r if isinstance(r, dict) else _result(p.name, indicator, indicator_type, "error", error=f"Unhandled exception: {str(r)}") for r, p in zip(results, active_providers)]

        normalized.extend(skipped_result(provider) for provider in skipped_providers)

        if len(self._cache) >= self._CACHE_MAX_ENTRIES:
            oldest = min(self._cache, key=lambda item: self._cache[item][0]); self._cache.pop(oldest, None)

        self._cache[key] = (now, normalized)
        return normalized

    async def enrich_all(self, iocs: List[Dict[str, Any]]) -> List[ProviderResult]:
        supported = {"url", "domain", "ip", "ipv6", "hash"}
        unique = []
        seen = set()

        prioritized_iocs = sorted(enumerate(iocs), key=lambda item: (-ThreatIntelligenceService._ioc_priority(item[1]), item[0]))
        for _, ioc in prioritized_iocs:
            kind = str(ioc.get("type") or "")
            value = str(ioc.get("normalized_value") or ioc.get("value") or "")
            key = (kind, value.lower())
            if kind in supported and value and key not in seen:
                seen.add(key)
                unique.append((kind, value, ioc))

            if len(unique) == 12:  # Bounded item count to prevent abuse
                break

        # Connection pooling via a shared AsyncClient
        limits = httpx.Limits(max_connections=12, max_keepalive_connections=8)
        async with httpx.AsyncClient(timeout=_TIMEOUT, limits=limits, follow_redirects=True) as client:
            batches = await asyncio.gather(*(self.enrich_ioc(kind, val, client) for kind, val, _ in unique))

        annotated = []
        for batch, (kind, value, ioc) in zip(batches, unique):
            source = str(ioc.get("source") or "unknown")
            context = str(ioc.get("context") or "")
            for item in batch:
                result = dict(item)
                metadata = dict(result.get("metadata") or {})
                metadata.update({
                    "ioc_source": source,
                    "ioc_context": context,
                    "ioc_confidence": int(ioc.get("confidence") or 0),
                    "ti_scoring_eligible": not (
                        kind == "domain"
                        and source in {"header", "authentication", "received_chain"}
                    ),
                })
                result["metadata"] = metadata
                result.setdefault("indicator", value)
                annotated.append(result)

        return annotated

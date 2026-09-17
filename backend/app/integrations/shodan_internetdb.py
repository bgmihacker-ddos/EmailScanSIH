import logging
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class ShodanInternetDBService:
    """Free Shodan InternetDB lookup without requiring an API key."""

    BASE_URL = "https://internetdb.shodan.io"

    async def lookup(self, ip: str) -> Dict[str, Any]:
        if not ip or not ip.strip():
            return {"status": "invalid", "ip": ip, "ports": [], "hostnames": [], "vulns": [], "tags": [], "cpes": [], "has_smtp": False, "vuln_count": 0}
        clean_ip = ip.strip()
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.BASE_URL}/{clean_ip}")
                if response.status_code == 404:
                    return {"status": "not_found", "ip": clean_ip, "ports": [], "hostnames": [], "vulns": [], "tags": [], "cpes": [], "has_smtp": False, "vuln_count": 0}
                if response.status_code != 200:
                    return {"status": "error", "ip": clean_ip, "ports": [], "hostnames": [], "vulns": [], "tags": [], "cpes": [], "has_smtp": False, "vuln_count": 0}
                data = response.json()
                ports = list(data.get("ports") or [])
                hostnames = list(data.get("hostnames") or [])
                vulns = list(data.get("vulns") or [])
                tags = list(data.get("tags") or [])
                cpes = list(data.get("cpes") or [])
                result = {
                    "status": "ok",
                    "ip": clean_ip,
                    "ports": ports,
                    "hostnames": hostnames,
                    "vulns": vulns,
                    "tags": tags,
                    "cpes": cpes,
                    "has_smtp": 25 in ports or 587 in ports,
                    "vuln_count": len(vulns),
                }
                return result
        except (httpx.TimeoutException, httpx.HTTPError, ValueError, TypeError) as exc:
            logger.debug("Shodan InternetDB lookup failed for %s: %s", clean_ip, exc)
            return {"status": "error", "ip": clean_ip, "ports": [], "hostnames": [], "vulns": [], "tags": [], "cpes": [], "has_smtp": False, "vuln_count": 0}

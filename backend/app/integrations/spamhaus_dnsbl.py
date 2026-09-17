import logging
from typing import Any, Dict, List

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)


class SpamhausDNSBLService:
    """Check if an IP is listed in common DNS-based blocklists."""

    DNSBL_ZONES = [
        ("zen.spamhaus.org", "Spamhaus ZEN"),
        ("bl.spamcop.net", "SpamCop"),
        ("dnsbl.sorbs.net", "SORBS"),
    ]

    SPAMHAUS_CODES = {
        "127.0.0.2": "SBL (direct spam source)",
        "127.0.0.3": "SBL CSS (spam domain)",
        "127.0.0.4": "XBL (exploited host)",
        "127.0.0.9": "DROP (hijacked netblock)",
        "127.0.0.10": "PBL (end-user IP, should not send mail)",
        "127.0.0.11": "PBL (ISP policy block)",
    }

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        clean_ip = ip.strip()
        reversed_ip = ".".join(reversed(clean_ip.split(".")))
        listings: List[Dict[str, Any]] = []

        for zone, zone_name in self.DNSBL_ZONES:
            query = f"{reversed_ip}.{zone}"
            try:
                answers = dns.resolver.resolve(query, "A")
                for rdata in answers:
                    code = str(rdata)
                    listings.append({
                        "zone": zone_name,
                        "code": code,
                        "reason": self.SPAMHAUS_CODES.get(code, "Listed"),
                    })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except Exception as exc:
                logger.debug("DNSBL lookup failed for %s on %s: %s", clean_ip, zone, exc)
                continue

        unique_codes = {item["code"] for item in listings}
        return {
            "ip": clean_ip,
            "is_blacklisted": bool(listings),
            "blacklist_count": len(unique_codes),
            "listings": listings,
        }

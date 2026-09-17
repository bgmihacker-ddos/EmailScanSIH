"""SSRF Protection and Private IP Guard.

Prevents Server-Side Request Forgery by rejecting localhost, loopback, link-local,
private RFC1918, RFC4193, and cloud metadata network ranges.
"""

import ipaddress
from typing import Optional, Union


def is_ssrf_safe_ip(ip_str: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Validate whether an IP address is safe for outbound queries.

    Rejects:
    - Loopback (127.0.0.0/8, ::1)
    - Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Multicast & Reserved
    - Cloud metadata (169.254.169.254, etc.)
    """
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
        # Specific metadata endpoint check
        if str(ip) in ("169.254.169.254", "100.100.100.200"):
            return False
        return True
    except (ValueError, AttributeError):
        return False


def validate_outbound_url_ssrf(url_str: str) -> bool:
    """Check if a URL destination is safe from SSRF."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url_str)
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"):
            return False
        # If hostname is an IP, check directly
        try:
            return is_ssrf_safe_ip(hostname)
        except Exception:
            pass
        return True
    except Exception:
        return False

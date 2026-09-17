"""Phase 6D: IOC Extraction Service.

Extracts Indicators of Compromise from parsed email data without
contacting external services.
"""

import hashlib
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]*(?![0-9A-Fa-f:.])"
)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_AUTH_FIELD_LABELS = {"smtp.mailfrom", "header.from", "header.i", "header.d"}
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _validate_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


class IOCExtractor:
    @staticmethod
    def extract(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and deduplicate IOCs from all email components."""
        iocs: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def _add(ioc_type: str, value: str, source: str, context: str = "",
                 confidence: int = 80):
            normalized = value.strip().lower()
            key = f"{ioc_type}:{normalized}"
            if key in seen:
                return
            seen.add(key)
            iocs.append({
                "type": ioc_type,
                "value": value.strip(),
                "normalized_value": normalized,
                "source": source,
                "context": context,
                "confidence": confidence,
            })

        # --- Extract from headers ---
        IOCExtractor._from_received_chain(parsed_email, _add)
        IOCExtractor._from_addresses(parsed_email, _add)
        IOCExtractor._from_message_id(parsed_email, _add)

        # --- Extract from body ---
        plain_text = parsed_email.get("plain_text", "")
        html_body = parsed_email.get("html_body", "")
        IOCExtractor._from_text(plain_text, "body", _add)
        IOCExtractor._from_text(html_body, "html", _add)

        # --- Extract from URLs ---
        for url in parsed_email.get("urls", []):
            _add("url", url, "body", "Extracted URL", 80)
            IOCExtractor._domain_from_url(url, "body", _add)
            IOCExtractor._ip_from_url(url, "body", _add)

        # --- Extract from attachments ---
        IOCExtractor._from_attachments(parsed_email, _add)

        # --- Extract from authentication ---
        IOCExtractor._from_authentication(parsed_email, _add)

        return {
            "iocs": iocs,
            "summary": {
                "total": len(iocs),
                "by_type": IOCExtractor._count_by_type(iocs),
                "by_source": IOCExtractor._count_by_source(iocs),
            },
        }

    @staticmethod
    def _from_received_chain(data: Dict, _add):
        for hop in data.get("received_chain", []):
            if not isinstance(hop, dict):
                continue
            for ip in hop.get("ips", []):
                validated = _validate_ip(ip)
                if validated:
                    version = ipaddress.ip_address(validated).version
                    _add("ipv6" if version == 6 else "ip", validated,
                         "received_chain", f"From Received hop", 90)
            for field in ("from_server", "by_server"):
                server = hop.get(field)
                if server and _DOMAIN_RE.match(server):
                    _add("domain", server, "received_chain",
                         f"Received {field}", 70)

    @staticmethod
    def _from_addresses(data: Dict, _add):
        addresses = data.get("addresses", {})
        if not isinstance(addresses, dict):
            return
        for field in ("from", "to", "cc", "bcc", "reply_to", "return_path"):
            value = addresses.get(field)
            if value is None:
                continue
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                if isinstance(entry, dict):
                    addr = entry.get("address")
                    domain = entry.get("domain")
                    if addr:
                        _add("email", addr, "header",
                             f"Address field: {field}", 90)
                    if domain:
                        _add("domain", domain, "header",
                             f"Domain from {field}", 70)

    @staticmethod
    def _from_message_id(data: Dict, _add):
        mid = data.get("message_id")
        if mid:
            _add("message_id", mid, "header", "Message-ID header", 90)

    @staticmethod
    def _from_text(text: str, source: str, _add):
        if not text:
            return
        for ip in _IPV4_RE.findall(text):
            if _validate_ip(ip):
                _add("ip", ip, source, "IP in text", 60)
        for ip in _IPV6_RE.findall(text):
            if _validate_ip(ip):
                _add("ipv6", ip, source, "IPv6 in text", 60)
        for url in _URL_RE.findall(text):
            url = url.rstrip(".,;:!?\"')>")
            _add("url", url, source, "URL in text", 70)
            IOCExtractor._domain_from_url(url, source, _add)
        for email in _EMAIL_RE.findall(text):
            _add("email", email, source, "Email in text", 60)

    @staticmethod
    def _domain_from_url(url: str, source: str, _add):
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if host:
                if _validate_ip(host):
                    _add("ip", host, source, "IP-hosted URL", 80)
                else:
                    _add("domain", host, source, "Domain from URL", 75)
        except Exception:
            pass

    @staticmethod
    def _ip_from_url(url: str, source: str, _add):
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if host and _validate_ip(host):
                _add("ip", host, source, "IP from URL", 80)
        except Exception:
            pass

    @staticmethod
    def _from_attachments(data: Dict, _add):
        for att in data.get("attachments", []):
            filename = att.get("filename") or att.get("name")
            if filename:
                _add("filename", filename, "attachment",
                     f"Attachment: {filename}", 90)

    @staticmethod
    def _from_authentication(data: Dict, _add):
        auth = data.get("authentication_headers", {})
        if not isinstance(auth, dict):
            return
        for key, value in auth.items():
            values = value if isinstance(value, list) else [value]
            for v in values:
                for domain in _DOMAIN_RE.findall(str(v)):
                    if domain.lower() in _AUTH_FIELD_LABELS:
                        continue
                    _add("domain", domain, "authentication",
                         f"Domain in {key}", 60)

    @staticmethod
    def _count_by_type(iocs: List[Dict]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for ioc in iocs:
            t = ioc["type"]
            counts[t] = counts.get(t, 0) + 1
        return counts

    @staticmethod
    def _count_by_source(iocs: List[Dict]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for ioc in iocs:
            s = ioc["source"]
            counts[s] = counts.get(s, 0) + 1
        return counts


def compute_hash(data: bytes) -> Dict[str, str]:
    """Compute MD5, SHA1, SHA256 for attachment bytes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

"""
email_parser.py — Phase 6A: RFC/MIME forensic email parser.

Extracts a structured forensic representation of an email while preserving
backward compatibility with the existing RuleEngine interface.
"""

import logging
import re
from email import policy
from email.headerregistry import Address
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

# Maximum raw email size logged in debug messages (chars) — avoid leaking content.
_LOG_PREVIEW_LEN = 80


# ---------------------------------------------------------------------------
# Helper: link extractor from HTML
# ---------------------------------------------------------------------------

class _HrefExtractor(HTMLParser):
    """Collect href values from <a> tags in HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs: List) -> None:
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.hrefs.append(value)


def _extract_hrefs(html: str) -> List[str]:
    parser = _HrefExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.hrefs


# ---------------------------------------------------------------------------
# Helper: URL extraction from plain text
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _extract_urls_from_text(text: str) -> List[str]:
    return _URL_RE.findall(text)


# ---------------------------------------------------------------------------
# Helper: URL normalization / dedup
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Minimal normalization: strip trailing punctuation that is unlikely to be
    part of the URL (common in plain-text prose)."""
    return url.rstrip(".,;:!?\"')")


def _dedup_urls(urls: List[str]) -> List[str]:
    seen: Dict[str, None] = {}
    result = []
    for u in urls:
        n = _normalize_url(u)
        if n not in seen:
            seen[n] = None
            result.append(n)
    return result


# ---------------------------------------------------------------------------
# Helper: address parsing
# ---------------------------------------------------------------------------

def _parse_address(raw: str) -> Optional[Dict[str, Optional[str]]]:
    """Parse a single 'Name <addr>' string into its components."""
    if not raw:
        return None
    display, addr = parseaddr(raw)
    if not addr and not display:
        return None
    domain = addr.split("@", 1)[1] if "@" in addr else None
    return {
        "display_name": display or None,
        "address": addr or None,
        "domain": domain,
    }


def _parse_address_list(raw_header_values: List[str]) -> List[Dict[str, Optional[str]]]:
    """Parse a list of raw header values into structured address objects.

    Handles comma-separated addresses within each header value and skips entries
    that cannot be parsed rather than raising.
    """
    result = []
    try:
        pairs = getaddresses(raw_header_values)
        for display, addr in pairs:
            if not addr and not display:
                continue
            domain = addr.split("@", 1)[1] if "@" in addr else None
            result.append({
                "display_name": display or None,
                "address": addr or None,
                "domain": domain,
            })
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Helper: Received header parsing
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_DATE_IN_RECEIVED_RE = re.compile(r";\s*(.+)$")


def _parse_received_header(raw: str) -> Dict[str, Any]:
    """Extract deterministic, text-only details from one ``Received`` hop.

    Header values are untrusted input.  The parser keeps the original value,
    captures useful relay metadata when the syntax is recognizable, and never
    performs DNS/IP attribution or treats a malformed hop as malicious.
    """
    raw_value = str(raw or "")
    entry: Dict[str, Any] = {
        "raw": raw_value,
        "from_server": None,
        "by_server": None,
        "from_host": None,
        "by_host": None,
        "source_ip": None,
        "destination_ip": None,
        "ips": [],
        "protocol": None,
        "timestamp": None,
        "timestamp_iso": None,
        "parse_status": "ok",
    }

    entry["ips"] = list(dict.fromkeys(_IP_RE.findall(raw_value)))

    from_match = re.search(r"\bfrom\s+([^;\s(]+)", raw_value, re.IGNORECASE)
    by_match = re.search(r"\bby\s+([^;\s(]+)", raw_value, re.IGNORECASE)
    if from_match:
        entry["from_server"] = from_match.group(1).rstrip(";,")
        entry["from_host"] = entry["from_server"]
    if by_match:
        entry["by_server"] = by_match.group(1).rstrip(";,")
        entry["by_host"] = entry["by_server"]

    # The first bracketed/parenthesized address is normally the source relay;
    # preserve all values in ``ips`` because Received syntax varies by MTA.
    if entry["ips"]:
        entry["source_ip"] = entry["ips"][0]
        if len(entry["ips"]) > 1:
            entry["destination_ip"] = entry["ips"][1]

    protocol_match = re.search(r"\b(?:with|via)\s+([A-Za-z0-9._/-]+)", raw_value, re.IGNORECASE)
    if protocol_match:
        entry["protocol"] = protocol_match.group(1).lower()

    date_match = _DATE_IN_RECEIVED_RE.search(raw_value)
    if date_match:
        timestamp = date_match.group(1).strip()
        entry["timestamp"] = timestamp
        try:
            parsed = parsedate_to_datetime(timestamp)
            entry["timestamp_iso"] = parsed.isoformat() if parsed else None
        except (TypeError, ValueError, OverflowError):
            entry["parse_status"] = "invalid_timestamp"
    elif raw_value:
        entry["parse_status"] = "missing_timestamp"
    else:
        entry["parse_status"] = "empty"

    return entry


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class EmailParser:
    """RFC/MIME forensic email parser.

    Callable interface is the existing ``parse_raw(raw_email: bytes) -> dict``.
    The returned dict maintains all existing keys consumed by ``RuleEngine``
    and extends them with structured forensic fields.
    """

    # Headers that carry authentication evidence.
    _AUTH_HEADERS = (
        "authentication-results",
        "received-spf",
        "dkim-signature",
        "arc-seal",
        "arc-message-signature",
        "arc-authentication-results",
    )

    @staticmethod
    def parse_raw(raw_email: bytes) -> Dict[str, Any]:
        """Parse an RFC/MIME email message.

        Args:
            raw_email: Raw email bytes.

        Returns:
            Structured dictionary containing forensic and backward-compat fields.

        Raises:
            ValueError: If ``raw_email`` is empty or None.
        """
        if not raw_email:
            raise ValueError("Empty email content provided.")
        if len(raw_email) > settings.MAX_EMAIL_BYTES:
            raise ValueError(
                f"Email exceeds the maximum supported size of {settings.MAX_EMAIL_BYTES} bytes."
            )

        try:
            return EmailParser._parse(raw_email)
        except ValueError:
            raise
        except Exception as exc:
            # Return a controlled partial result so the analysis pipeline can
            # continue with whatever could be extracted.
            logger.warning("Email parsing error: %s", str(exc))
            return EmailParser._empty_result(
                raw_email=raw_email,
                error=str(exc),
            )

    @staticmethod
    def _parse(raw_email: bytes) -> Dict[str, Any]:
        # policy=default gives us modern string-based header values.
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)

        # ------------------------------------------------------------------
        # 1. Metadata (standard headers)
        # ------------------------------------------------------------------
        raw_from = msg.get("from") or ""
        raw_to = msg.get_all("to") or []
        raw_cc = msg.get_all("cc") or []
        raw_bcc = msg.get_all("bcc") or []
        raw_reply_to = msg.get_all("reply-to") or []
        raw_sender = msg.get("sender") or ""
        raw_return_path = msg.get("return-path")
        subject = msg.get("subject")
        date = msg.get("date")
        message_id = msg.get("message-id")
        in_reply_to = msg.get("in-reply-to")
        references = msg.get_all("references") or []
        mime_version = msg.get("mime-version")
        content_type_header = msg.get("content-type")
        content_transfer_encoding = msg.get("content-transfer-encoding")

        metadata = {
            "from": raw_from or None,
            "to": raw_to,
            "cc": raw_cc,
            "bcc": raw_bcc,
            "reply_to": raw_reply_to,
            "sender": raw_sender or None,
            "return_path": raw_return_path,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "in_reply_to": in_reply_to,
            "references": references,
            "mime_version": mime_version,
            "content_type": content_type_header,
            "content_transfer_encoding": content_transfer_encoding,
        }

        # ------------------------------------------------------------------
        # 2. Parsed address structures
        # ------------------------------------------------------------------
        addresses = {
            "from": _parse_address(raw_from),
            "to": _parse_address_list(raw_to),
            "cc": _parse_address_list(raw_cc),
            "bcc": _parse_address_list(raw_bcc),
            "reply_to": _parse_address_list(raw_reply_to),
            "sender": _parse_address(raw_sender),
            "return_path": _parse_address(raw_return_path or ""),
        }

        # ------------------------------------------------------------------
        # 3. All headers (preserve duplicate headers as lists)
        # ------------------------------------------------------------------
        all_headers: Dict[str, Any] = {}
        for key, value in msg.items():
            k_lower = key.lower()
            if k_lower in all_headers:
                existing = all_headers[k_lower]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    all_headers[k_lower] = [existing, value]
            else:
                all_headers[k_lower] = value

        # ------------------------------------------------------------------
        # 4. Received chain
        # ------------------------------------------------------------------
        raw_received = msg.get_all("received") or []
        received_chain = [_parse_received_header(r) for r in raw_received]

        # ------------------------------------------------------------------
        # 5. Authentication headers (extraction only — no pass/fail judgment)
        # ------------------------------------------------------------------
        authentication_headers: Dict[str, Any] = {}
        for h in EmailParser._AUTH_HEADERS:
            values = msg.get_all(h) or []
            if values:
                authentication_headers[h] = values if len(values) > 1 else values[0]

        # ------------------------------------------------------------------
        # 6. Body extraction
        # ------------------------------------------------------------------
        plain_text, html_body = EmailParser._extract_bodies(msg)

        # ------------------------------------------------------------------
        # 7. URL extraction
        # ------------------------------------------------------------------
        text_urls = _extract_urls_from_text(plain_text)
        html_text_urls = _extract_urls_from_text(html_body)
        html_href_urls = _extract_hrefs(html_body)
        all_urls = _dedup_urls(text_urls + html_text_urls + html_href_urls)

        # ------------------------------------------------------------------
        # 8. Attachments and MIME tree summary
        # ------------------------------------------------------------------
        attachments = EmailParser._extract_attachments(msg)
        mime_summary = EmailParser._summarize_mime_tree(msg)

        # ------------------------------------------------------------------
        # 9. Derive simple RuleEngine compat values from auth headers
        # ------------------------------------------------------------------
        spf_raw = authentication_headers.get("received-spf")
        if isinstance(spf_raw, list):
            spf_raw = spf_raw[0]

        dkim_raw = authentication_headers.get("dkim-signature")
        if isinstance(dkim_raw, list):
            dkim_raw = dkim_raw[0]

        # Leave dmarc as None — we don't have a dedicated header for it before
        # forensic analysis phase; the RuleEngine tolerates None gracefully.
        dmarc_raw = None

        # Derive friendly from address string for RuleEngine.
        from_str = addresses["from"]["address"] if addresses["from"] and addresses["from"].get("address") else raw_from

        # Derive reply_to string for RuleEngine mismatch check.
        reply_to_str = None
        if addresses["reply_to"]:
            first = addresses["reply_to"][0]
            reply_to_str = first.get("address") if first else None

        # ------------------------------------------------------------------
        # 10. Raw email (avoid logging)
        # ------------------------------------------------------------------
        try:
            raw_email_str = raw_email.decode("utf-8", errors="replace")
        except Exception:
            raw_email_str = repr(raw_email)

        # ------------------------------------------------------------------
        # Build result — new forensic fields + all existing RuleEngine fields.
        # ------------------------------------------------------------------
        result: Dict[str, Any] = {
            # ---- Forensic fields (Phase 6A) ----
            "metadata": metadata,
            "addresses": addresses,
            "headers": all_headers,
            "received_chain": received_chain,
            "authentication_headers": authentication_headers,
            "mime_summary": mime_summary,
            "message_id": message_id,
            "in_reply_to": in_reply_to,
            "references": references,
            "urls": all_urls,
            "raw_email": raw_email_str,
            # ---- Backward-compat RuleEngine fields ----
            "from": from_str,
            "to": raw_to,
            "reply_to": reply_to_str,
            "sender": raw_sender or None,
            "return_path": raw_return_path,
            "in_reply_to": in_reply_to,
            "references": references,
            "subject": subject,
            "date": date,
            "authentication_results": authentication_headers.get("authentication-results"),
            "received": raw_received,
            "spf": spf_raw,
            "dkim": dkim_raw,
            "dmarc": dmarc_raw,
            "plain_text": plain_text,
            "html_body": html_body,
            "attachments": attachments,
        }

        return result

    # ------------------------------------------------------------------
    # Body extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_bodies(msg: Any) -> tuple:
        """Walk the MIME tree and collect plain_text and html_body.

        Handles:
        - text/plain, text/html
        - multipart/alternative, multipart/mixed
        - base64, quoted-printable (handled by Python email library)
        - malformed parts (skipped with a log warning)
        """
        plain_text = ""
        html_body = ""

        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = (part.get("content-disposition") or "").lower()

            # Skip attachments.
            if "attachment" in disposition:
                continue
            # Skip multipart containers — they are not body content themselves.
            if content_type.startswith("multipart/"):
                continue

            if content_type == "text/plain" and not plain_text:
                try:
                    plain_text = part.get_content()
                    if plain_text:
                        plain_text = plain_text.strip()
                except Exception as exc:
                    logger.warning("Could not decode text/plain part: %s", exc)

            elif content_type == "text/html" and not html_body:
                try:
                    html_body = part.get_content()
                    if html_body:
                        html_body = html_body.strip()
                except Exception as exc:
                    logger.warning("Could not decode text/html part: %s", exc)

        return plain_text or "", html_body or ""

    # ------------------------------------------------------------------
    # MIME tree summary
    # ------------------------------------------------------------------

    @staticmethod
    def _summarize_mime_tree(msg: Any) -> Dict[str, Any]:
        """Summarize MIME parts without exposing decoded content."""
        parts: List[Dict[str, Any]] = []
        max_depth = 0
        truncated = False
        def visit(part: Any, depth: int) -> None:
            nonlocal truncated
            if len(parts) >= settings.MAX_MIME_PARTS:
                truncated = True
                return
            nonlocal max_depth
            max_depth = max(max_depth, depth)
            parts.append({
                "content_type": part.get_content_type(),
                "content_disposition": part.get("content-disposition"),
                "filename": part.get_filename(),
                "is_multipart": part.is_multipart(),
                "depth": depth,
            })
            if part.is_multipart():
                for child in part.iter_parts():
                    visit(child, depth + 1)

        visit(msg, 0)
        return {
            "part_count": len(parts),
            "max_depth": max_depth,
            "truncated": truncated,
            "content_types": [item["content_type"] for item in parts],
            "parts": parts,
        }

    # ------------------------------------------------------------------
    # Attachment extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_attachments(msg: Any) -> List[Dict[str, Any]]:
        """Return a list of attachment metadata dicts.

        Does not decode or store attachment content.
        """
        attachments = []
        for part in msg.walk():
            filename = part.get_filename()
            disposition = (part.get("content-disposition") or "").lower()
            content_type = part.get_content_type()

            # Include parts that are explicitly marked as attachments OR have a
            # filename but are not inline text parts.
            is_attachment = "attachment" in disposition or (
                filename
                and content_type not in ("text/plain", "text/html")
            )
            if not is_attachment:
                continue
            if len(attachments) >= settings.MAX_ATTACHMENTS:
                break

            extension = ""
            if filename and "." in filename:
                extension = filename.rsplit(".", 1)[-1].lower()

            # Size: attempt to measure without decoding full content.
            size: Optional[int] = None
            sha256: Optional[str] = None
            md5: Optional[str] = None
            magic_bytes: Optional[str] = None

            try:
                payload = part.get_payload(decode=True)
                if payload is not None:
                    size = len(payload)

                    import hashlib
                    if size <= settings.MAX_ATTACHMENT_BYTES:
                        sha256 = hashlib.sha256(payload).hexdigest()
                        md5 = hashlib.md5(payload).hexdigest()
                        magic_bytes_raw = payload[:4]
                        magic_bytes = magic_bytes_raw.hex()
            except Exception:
                pass

            attachments.append({
                # Keep 'name' for RuleEngine backward compat.
                "name": filename or "",
                "filename": filename or "",
                "content_type": content_type,
                # Keep 'type' for RuleEngine backward compat.
                "type": content_type,
                "extension": extension,
                # Keep 'size' for RuleEngine backward compat.
                "size": size,
                "sha256": sha256,
                "md5": md5,
                "magic_bytes": magic_bytes,
                "content_disposition": disposition,
                "content_id": part.get("content-id"),
                "hashing_status": "complete" if sha256 else "skipped_size_limit" if size is not None else "unavailable",
            })

        return attachments

    # ------------------------------------------------------------------
    # Empty/error result
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_result(raw_email: bytes, error: str) -> Dict[str, Any]:
        """Return a minimal, safe result when parsing fails."""
        try:
            raw_email_str = raw_email.decode("utf-8", errors="replace")
        except Exception:
            raw_email_str = ""

        return {
            "metadata": {},
            "addresses": {
                "from": None,
                "to": [],
                "cc": [],
                "bcc": [],
                "reply_to": [],
                "sender": None,
                "return_path": None,
            },
            "headers": {},
            "mime_summary": {"part_count": 0, "max_depth": 0, "content_types": [], "parts": []},
            "received_chain": [],
            "authentication_headers": {},
            "message_id": None,
            "in_reply_to": None,
            "references": [],
            "urls": [],
            "raw_email": raw_email_str,
            "parse_error": error,
            # Backward-compat
            "from": None,
            "to": [],
            "reply_to": None,
            "return_path": None,
            "subject": None,
            "date": None,
            "authentication_results": None,
            "received": [],
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "plain_text": "",
            "html_body": "",
            "attachments": [],
        }

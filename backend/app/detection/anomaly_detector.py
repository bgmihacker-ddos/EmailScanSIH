"""Rule-based anomaly detection for novel email threats.

Catches statistical and structural anomalies the ML classifier hasn't seen.
Pure stdlib — no external dependencies.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse


_CORPORATE_RE = re.compile(
    r"\b(Inc|Corp|Ltd|Bank|Ministry|Government|Pvt|Limited)\b", re.IGNORECASE
)
_FREE_PROVIDERS = {"gmail", "yahoo", "hotmail", "outlook", "rediffmail", "ymail", "protonmail"}


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits) of *text*."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_domain(address: str) -> str:
    """Return the domain part of an email address, lowercased."""
    if "@" in address:
        return address.rsplit("@", 1)[1].strip().lower()
    return ""


def _extract_url_domains(text: str) -> list[str]:
    """Pull unique domains from URLs found in *text*."""
    domains: set[str] = set()
    for match in re.finditer(r"https?://[^\s\"'<>]+", text):
        try:
            host = urlparse(match.group()).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass
    return list(domains)


class AnomalyDetector:
    """Stateless, rule-based anomaly detector."""

    @staticmethod
    def analyze(email: dict, header_forensics: dict | None = None) -> dict:
        """Scan *email* for structural/statistical anomalies.

        Returns a dict with ``anomalies``, ``anomaly_count``,
        ``max_severity``, and ``status``.
        """
        anomalies: List[Dict[str, Any]] = []
        addresses = email.get("addresses") or {}
        from_addr = ""
        display_name = ""

        # Parse from field
        raw_from = email.get("from", "")
        if isinstance(raw_from, str) and raw_from:
            # "Display Name <addr>" format
            m = re.match(r"^(.+?)\s*<([^>]+)>", raw_from)
            if m:
                display_name, from_addr = m.group(1).strip(), m.group(2).strip()
            elif "@" in raw_from:
                from_addr = raw_from.strip()
        # Fallback to addresses dict
        if not from_addr:
            from_info = addresses.get("from", {})
            if isinstance(from_info, dict):
                from_addr = from_info.get("address", "")
                display_name = display_name or from_info.get("name", "")

        from_domain = _extract_domain(from_addr)

        # ── 2a. Sender frequency / display-name mismatch ──────────────
        provider_name = from_domain.split(".")[0] if from_domain else ""
        if provider_name in _FREE_PROVIDERS and _CORPORATE_RE.search(display_name):
            anomalies.append({
                "anomaly_type": "display_name_organization_mismatch",
                "description": (
                    f"Display name '{display_name}' claims corporate identity "
                    f"but sender uses free provider '{from_domain}'"
                ),
                "severity": "high",
                "confidence": 80,
                "evidence": f"from={from_addr}, display_name={display_name}",
            })

        # ── 2b. Header entropy (Message-ID) ───────────────────────────
        hf = header_forensics or {}
        message_id = hf.get("message_id") or email.get("message_id", "")
        if message_id:
            entropy = _shannon_entropy(message_id)
            bad_format = "@" not in message_id
            if entropy < 2.0 or bad_format:
                anomalies.append({
                    "anomaly_type": "anomalous_message_id",
                    "description": (
                        f"Message-ID has {'low entropy ({:.2f} bits)'.format(entropy) if entropy < 2.0 else 'missing @ separator'}"
                    ),
                    "severity": "medium",
                    "confidence": 65,
                    "evidence": f"message_id={message_id}, entropy={entropy:.2f}",
                })

        # ── 2c. Temporal anomaly ──────────────────────────────────────
        date_str = email.get("date") or hf.get("date", "")
        if date_str:
            parsed_date = _try_parse_date(date_str)
            if parsed_date is not None:
                now = datetime.now(timezone.utc)
                if parsed_date > now + timedelta(hours=24):
                    anomalies.append({
                        "anomaly_type": "timestamp_anomaly",
                        "description": "Email Date header is more than 24 hours in the future",
                        "severity": "medium",
                        "confidence": 75,
                        "evidence": f"date={date_str}",
                    })
                elif parsed_date < now - timedelta(days=30):
                    anomalies.append({
                        "anomaly_type": "timestamp_anomaly",
                        "description": "Email Date header is more than 30 days in the past",
                        "severity": "medium",
                        "confidence": 70,
                        "evidence": f"date={date_str}",
                    })

        # Timezone inconsistency (IST vs. relay headers)
        received_headers = hf.get("received_headers") or email.get("received_headers") or []
        if date_str and received_headers:
            _check_timezone_inconsistency(date_str, received_headers, anomalies)

        # ── 2d. Structural anomalies ──────────────────────────────────
        plain_text = email.get("plain_text", "") or ""
        html_body = email.get("html_body", "") or ""

        if not plain_text.strip() and len(html_body) > 2000:
            anomalies.append({
                "anomaly_type": "html_only_body",
                "description": "Email has no plain-text body but HTML body exceeds 2000 chars",
                "severity": "low",
                "confidence": 50,
                "evidence": f"plain_text_len=0, html_len={len(html_body)}",
            })

        # High domain diversity
        body_text = f"{plain_text} {html_body}"
        url_domains = _extract_url_domains(body_text)
        if len(url_domains) > 5:
            anomalies.append({
                "anomaly_type": "high_domain_diversity",
                "description": f"Email body references {len(url_domains)} different URL domains",
                "severity": "medium",
                "confidence": 60,
                "evidence": f"domains={url_domains[:8]}",
            })

        # Reply-to mismatch (redundant signal with unique evidence ID)
        reply_to_list = addresses.get("reply_to") or []
        reply_to_addr = ""
        if reply_to_list and isinstance(reply_to_list, list):
            first = reply_to_list[0] if reply_to_list else {}
            if isinstance(first, dict):
                reply_to_addr = first.get("address", "")
            elif isinstance(first, str):
                reply_to_addr = first
        reply_to_domain = _extract_domain(reply_to_addr)
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            anomalies.append({
                "anomaly_type": "reply_to_domain_mismatch",
                "description": (
                    f"Reply-To domain '{reply_to_domain}' differs from "
                    f"sender domain '{from_domain}'"
                ),
                "severity": "high",
                "confidence": 85,
                "evidence": f"from_domain={from_domain}, reply_to_domain={reply_to_domain}",
            })

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = max(
            (a["severity"] for a in anomalies),
            key=lambda s: severity_order.get(s, 0),
            default="info",
        )

        return {
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "max_severity": max_severity,
            "status": "available",
        }


def _try_parse_date(date_str: str) -> datetime | None:
    """Best-effort parse of an email Date header string."""
    import email.utils
    try:
        tup = email.utils.parsedate_to_datetime(date_str)
        if tup.tzinfo is None:
            tup = tup.replace(tzinfo=timezone.utc)
        return tup
    except Exception:
        pass
    # Fallback: ISO format
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _check_timezone_inconsistency(
    date_str: str,
    received_headers: list,
    anomalies: List[Dict[str, Any]],
) -> None:
    """Flag when Date header timezone drastically differs from relay timestamps."""
    # Check if Date claims IST (+0530)
    ist_match = re.search(r"[+-]0530\b", date_str)
    if not ist_match:
        return
    # Look for relay timezone offsets in Received headers
    for hdr in received_headers:
        hdr_str = str(hdr)
        tz_matches = re.findall(r"([+-]\d{4})\b", hdr_str)
        for tz in tz_matches:
            if tz == "+0530":
                continue
            try:
                offset_hours = int(tz[:3]) + int(tz[0] + tz[3:]) / 60
                ist_offset = 5.5
                if abs(offset_hours - ist_offset) > 4:
                    anomalies.append({
                        "anomaly_type": "timezone_inconsistency",
                        "description": (
                            f"Date header claims IST (+0530) but relay header "
                            f"shows timezone {tz}"
                        ),
                        "severity": "high",
                        "confidence": 70,
                        "evidence": f"date_tz=+0530, relay_tz={tz}",
                    })
                    return  # one finding is enough
            except ValueError:
                continue

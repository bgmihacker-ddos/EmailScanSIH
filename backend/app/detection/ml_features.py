"""Shared, non-circular feature preparation for the email ML classifier.

The feature builder intentionally accepts parsed email evidence only.  It never
consumes a risk score, final verdict, threat-intelligence result, or any other
output produced later in the detection pipeline.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping


TEXT_FEATURE_FAMILY = "subject_body_tfidf"
STRUCTURAL_FEATURE_FAMILY = "email_structure"

# Regex patterns for social engineering detection
_URGENCY_RE = re.compile(r"\b(urgent|immediate|action required|now|immediately)\b", re.IGNORECASE)
_CRED_RE = re.compile(r"\b(login|password|verify|account|security)\b", re.IGNORECASE)
_FINANCIAL_RE = re.compile(r"\b(wire|transfer|payment|invoice|bank)\b", re.IGNORECASE)

# India-specific threat patterns
_UPI_HANDLE_RE = re.compile(
    r"@(okaxis|okhdfcbank|ybl|paytm|upi|okicici|oksbi|ikwik|apl|rbl|barodampay)",
    re.IGNORECASE,
)
_GOV_BRAND_RE = re.compile(
    r"\b(ministry\s+of|government\s+of\s+india|govt\.?\s*of\s*india|uidai|aadhaar|aadhar"
    r"|pan\s+card|income\s+tax\s+department|epfo|provident\s+fund|gst\s+notice"
    r"|rbi\s+governor|reserve\s+bank|sarkari|digilocker)\b",
    re.IGNORECASE,
)
_HINDI_URGENCY_RE = re.compile(
    r"\b(turant|jaldi|abhi|khata\s*band|otp\s*bhej|kripya|aapka\s*khata"
    r"|rupaye|paisa\s*transfer|naukri|lottery\s*jeet)\b",
    re.IGNORECASE,
)
_FREE_PROVIDER_RE = re.compile(
    r"@(gmail|yahoo|hotmail|outlook|rediffmail|ymail|protonmail)\.com",
    re.IGNORECASE,
)


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else "" if value is None else str(value)


def _get_html_text_ratio(plain: str, html: str) -> float:
    if not html:
        return 0.0
    text_len = len(plain)
    html_len = len(html)
    return text_len / html_len if html_len > 0 else 0.0


def email_to_features(email: Mapping[str, Any] | None) -> Dict[str, Any]:
    """Convert parsed email fields into deterministic model input.

    ``email`` may be a production parser result or a compact training record.
    Only content and observable message structure are used.
    """
    message = email or {}
    subject = _as_text(message.get("subject"))
    plain_text = _as_text(message.get("plain_text"))
    html_body = _as_text(message.get("html_body"))
    body = f"{plain_text} {html_body}".strip()

    urls = message.get("urls") or []
    attachments = message.get("attachments") or []
    addresses = message.get("addresses") or {}
    authentication_headers = message.get("authentication_results") or message.get("authentication_headers") or ""
    if isinstance(authentication_headers, Mapping):
        authentication_headers = " ".join(_as_text(value) for value in authentication_headers.values())
    if not authentication_headers:
        headers = message.get("headers") or {}
        authentication_headers = headers.get("authentication-results", "")
    authentication_headers = _as_text(authentication_headers)

    subject_clean = subject.strip()
    body_clean = body.strip()
    combined_text = f"subject: {subject_clean} body: {body_clean}".strip() if (subject_clean or body_clean) else ""

    # Calculate additional features
    unique_urls = set(urls)

    # Simple sender/reply-to mismatch check
    sender = addresses.get("from", {}).get("address") if addresses else None
    reply_to = addresses.get("reply_to", [])
    reply_to_addr = reply_to[0].get("address") if reply_to and reply_to[0] else None

    mismatch = 0
    if sender and reply_to_addr and sender.lower() != reply_to_addr.lower():
        mismatch = 1

    return {
        "text": combined_text,
        "authentication_headers": authentication_headers,
        "structure": {
            "has_html": int(bool(html_body.strip())),
            "url_count": min(len(urls), 20),
            "unique_url_count": min(len(unique_urls), 20),
            "html_text_ratio": min(_get_html_text_ratio(plain_text, html_body), 1.0),
            "attachment_count": min(len(attachments), 20),
            "subject_length_bucket": min(len(subject) // 20, 10),
            "body_length_bucket": min(len(body) // 200, 25),
            "has_urgency": int(bool(_URGENCY_RE.search(body))),
            "has_cred": int(bool(_CRED_RE.search(body))),
            "has_financial": int(bool(_FINANCIAL_RE.search(body))),
            "reply_to_mismatch": mismatch,
            "has_upi_spoof": int(bool(_UPI_HANDLE_RE.search(body + " " + subject))),
            "has_gov_brand": int(bool(_GOV_BRAND_RE.search(body + " " + subject))),
            "has_hindi_urgency": int(bool(_HINDI_URGENCY_RE.search(body + " " + subject))),
            "from_free_provider": int(bool(_FREE_PROVIDER_RE.search(
                str(addresses.get("from", {}).get("address", "") if addresses else "")))),
        },
    }


def text_to_features(text: str | None) -> Dict[str, Any]:
    """Build compatible input for legacy ``predict(text)`` callers."""
    value = _as_text(text)
    return {
        "text": value,
        "structure": {
            "has_html": 0,
            "url_count": 0,
            "attachment_count": 0,
            "subject_length_bucket": 0,
            "body_length_bucket": min(len(value) // 200, 25),
        },
    }

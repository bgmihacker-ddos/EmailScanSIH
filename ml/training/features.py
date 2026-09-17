"""Training-side feature helpers shared conceptually with backend inference."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Dict, Mapping

# Make the repository's backend package importable when this module is run from
# the repository root. Production inference never imports the training package.
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.detection.ml_features import email_to_features  # noqa: E402


STRUCTURAL_NAMES = (
    "has_html",
    "url_count",
    "unique_url_count",
    "html_text_ratio",
    "attachment_count",
    "subject_length_bucket",
    "body_length_bucket",
    "has_urgency",
    "has_cred",
    "has_financial",
    "reply_to_mismatch",
    "has_upi_spoof",
    "has_gov_brand",
    "has_hindi_urgency",
    "from_free_provider",
)


def record_to_features(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize a controlled JSONL record to the inference feature contract."""
    # Maps training records to the expected EmailParser structure needed by email_to_features

    # Defaults for new features that might not exist in controlled emails
    parsed_email = {
        "subject": record.get("subject", ""),
        "plain_text": str(record.get("body", ""))[:12000],
        "html_body": "<body>controlled</body>" if record.get("has_html") else "",
        "urls": ["controlled-url"] * int(record.get("url_count", 0) or 0),
        "attachments": [{}] * int(record.get("attachment_count", 0) or 0),
        # Addresses not typically in controlled.jsonl, assume no mismatch
        "addresses": {"from": {"address": "a@b.c"}, "reply_to": [{"address": "a@b.c"}]}
    }

    return email_to_features(parsed_email)

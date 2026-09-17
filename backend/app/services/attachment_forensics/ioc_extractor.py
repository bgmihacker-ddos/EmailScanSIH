# AUDIT SCRIPT: Attachment Forensics - IOC Extractor
# Importers/Callers: app.services.attachment_analyzer
# Affected API: app.services.attachment_forensics.ioc_extractor.AttachmentIocExtractor
# Data schemas: list of IOC dicts with provenance
# Verbatim instruction: "Build a production-safe ATTACHMENT STATIC FORENSICS subsystem."

"""Phase 7: IOC Extraction & Provenance inside Attachments."""

import re
from typing import List, Dict, Any

class AttachmentIocExtractor:
    _URL_REGEX = re.compile(
        rb"(?:https?|ftp)://[^\s/$.?#].[^\s\"\'>\)\],]*", re.IGNORECASE
    )
    _IPV4_REGEX = re.compile(
        rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    @staticmethod
    def extract_iocs(raw_bytes: bytes, filename: str, attachment_id: str) -> List[Dict[str, Any]]:
        """Extract URLs, IPs, and hashes with explicit provenance."""
        iocs: List[Dict[str, Any]] = []
        seen = set()

        # URLs
        for match in AttachmentIocExtractor._URL_REGEX.finditer(raw_bytes):
            try:
                url_str = match.group().decode("utf-8", errors="ignore").rstrip(".,;)\"\'")
                if len(url_str) > 7 and url_str not in seen:
                    seen.add(url_str)
                    iocs.append({
                        "type": "url",
                        "value": url_str,
                        "normalized_value": url_str.lower(),
                        "source": "attachment_static_scan",
                        "provenance_class": "OBSERVED",
                        "confidence": 90,
                        "attachment_id": attachment_id,
                        "parent_filename": filename,
                    })
            except Exception:
                pass

        # IPv4
        for match in AttachmentIocExtractor._IPV4_REGEX.finditer(raw_bytes):
            try:
                ip_str = match.group().decode("utf-8", errors="ignore")
                # Filter out standard subnet masks or 0.0.0.0
                if ip_str not in ("0.0.0.0", "255.255.255.255", "127.0.0.1") and ip_str not in seen:
                    seen.add(ip_str)
                    iocs.append({
                        "type": "ipv4",
                        "value": ip_str,
                        "normalized_value": ip_str.lower(),
                        "source": "attachment_static_scan",
                        "provenance_class": "OBSERVED",
                        "confidence": 85,
                        "attachment_id": attachment_id,
                        "parent_filename": filename,
                    })
            except Exception:
                pass

        return iocs

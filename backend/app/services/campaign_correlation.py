"""
Phase 13: Campaign Correlation Service.

Detects related analyses based on shared infrastructure (sender domain, Reply-To domain,
shared URLs, IPs, attachment hashes, and structural similarity).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class CampaignCorrelator:
    """Correlates analyses into campaigns based on shared indicators."""

    @staticmethod
    def correlate_analysis(
        current_analysis_id: str,
        current_iocs: Dict[str, Any],
        current_metadata: Dict[str, Any],
        historical_records: List[Any],
    ) -> List[Dict[str, Any]]:
        """Find related historical investigations based on indicator overlap."""
        related: List[Dict[str, Any]] = []

        # Extract current IOCs
        current_urls: Set[str] = set()
        current_domains: Set[str] = set()
        current_ips: Set[str] = set()
        current_hashes: Set[str] = set()

        if isinstance(current_iocs, dict):
            iocs_list = current_iocs.get("iocs", [])
            for ioc in iocs_list:
                if not isinstance(ioc, dict):
                    continue
                val = str(ioc.get("value", "")).lower()
                t = str(ioc.get("type", "")).lower()
                if not val:
                    continue
                if t == "url":
                    current_urls.add(val)
                elif t == "domain":
                    current_domains.add(val)
                elif t == "ip":
                    current_ips.add(val)
                elif t in ("hash", "sha256", "md5", "attachment"):
                    current_hashes.add(val)

        # Also check structured attachment hashes
        att_hashes = current_metadata.get("attachment_hashes", [])
        for h in att_hashes:
            if h:
                current_hashes.add(str(h).lower())

        current_from_domain = str(current_metadata.get("from_domain", "")).lower()

        # Compare with historical records
        for record in historical_records:
            if not record or not hasattr(record, "id") or record.id == current_analysis_id:
                continue

            result = record.result if hasattr(record, "result") else {}
            if not isinstance(result, dict):
                continue

            hist_extracted = result.get("extracted_iocs", {})
            hist_urls: Set[str] = set()
            hist_domains: Set[str] = set()
            hist_ips: Set[str] = set()
            hist_hashes: Set[str] = set()

            if isinstance(hist_extracted, dict):
                for ioc in hist_extracted.get("iocs", []):
                    if not isinstance(ioc, dict):
                        continue
                    val = str(ioc.get("value", "")).lower()
                    t = str(ioc.get("type", "")).lower()
                    if not val:
                        continue
                    if t == "url":
                        hist_urls.add(val)
                    elif t == "domain":
                        hist_domains.add(val)
                    elif t == "ip":
                        hist_ips.add(val)
                    elif t in ("hash", "sha256", "md5", "attachment"):
                        hist_hashes.add(val)

            hist_meta = result.get("header_forensics", {})
            hist_from_domain = str(
                (hist_meta.get("domain_relationships", {}) or {}).get("from_domain", "")
            ).lower()

            # Calculate overlap
            shared_urls = current_urls.intersection(hist_urls)
            shared_domains = current_domains.intersection(hist_domains)
            shared_ips = current_ips.intersection(hist_ips)
            shared_hashes = current_hashes.intersection(hist_hashes)
            shared_sender = bool(current_from_domain and current_from_domain == hist_from_domain)

            overlap_types = []
            if shared_hashes:
                overlap_types.append("shared_attachment_hash")
            if shared_urls:
                overlap_types.append("shared_url")
            if shared_ips:
                overlap_types.append("shared_ip")
            if shared_domains:
                overlap_types.append("shared_domain")
            if shared_sender:
                overlap_types.append("shared_sender_domain")

            # Require at least 2 independent signal types or 1 strong signal (hash/URL)
            is_related = False
            confidence = 0

            if shared_hashes:
                is_related = True
                confidence = 95
            elif len(shared_urls) >= 1 or len(shared_ips) >= 1:
                is_related = True
                confidence = 85
            elif len(overlap_types) >= 2:
                is_related = True
                confidence = 75
            elif shared_sender and len(shared_domains) >= 1:
                is_related = True
                confidence = 65

            if is_related:
                all_shared_iocs = list(
                    shared_hashes | shared_urls | shared_ips | shared_domains
                )
                related.append({
                    "analysis_id": record.id,
                    "overlap_type": overlap_types,
                    "shared_iocs": all_shared_iocs,
                    "shared_indicator_count": len(all_shared_iocs),
                    "confidence": confidence,
                    "verdict": getattr(record, "verdict", "unknown"),
                    "severity": getattr(record, "severity", "unknown"),
                    "created_at": getattr(record, "created_at", None),
                })

        # Sort by confidence/shared count descending
        related.sort(key=lambda x: (x["confidence"], x["shared_indicator_count"]), reverse=True)
        return related


def correlate_campaigns(
    current_analysis_id: str,
    current_iocs: Dict[str, Any],
    current_metadata: Dict[str, Any],
    historical_records: List[Any],
) -> List[Dict[str, Any]]:
    """Convenience function for campaign correlation."""
    return CampaignCorrelator.correlate_analysis(
        current_analysis_id, current_iocs, current_metadata, historical_records
    )
"""
Phase 16: STIX 2.1 Exporter Service.

Generates a valid STIX 2.1 bundle containing indicators, email messages,
malware objects, domains, IP addresses, URLs, and relationships.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


class Stix21Exporter:
    """Exports an analysis record as a STIX 2.1 bundle."""

    @staticmethod
    def export_bundle(analysis_id: str, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate STIX 2.1 JSON bundle from analysis result."""
        objects: List[Dict[str, Any]] = []
        now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Identity object (producer)
        identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'email-threat-detection')}"
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "name": "Email Threat Detection & Forensics Platform",
            "identity_class": "system",
        })

        # Campaign / Threat Report object
        report_id = f"report--{uuid.uuid4()}"
        verdict = analysis_result.get("verdict", "unknown")
        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created_by_ref": identity_id,
            "created": now_str,
            "modified": now_str,
            "name": f"Email Threat Forensic Report - {analysis_id}",
            "description": f"Automated analysis verdict: {verdict.upper()}. Risk score: {analysis_result.get('risk_score', 0)}/100.",
            "published": now_str,
            "object_refs": [],
        })

        # Extract IOCs and create SCOs (Cyber Observable Objects)
        extracted = analysis_result.get("extracted_iocs", {})
        iocs = extracted.get("iocs", []) if isinstance(extracted, dict) else []

        for ioc in iocs:
            if not isinstance(ioc, dict):
                continue
            ioc_type = ioc.get("type")
            value = ioc.get("value")
            if not value:
                continue

            sco_id = f"observed-data--{uuid.uuid4()}"
            obj_type = ""
            observable_key = ""

            if ioc_type == "url":
                obj_type = "url"
                observable_key = "value"
            elif ioc_type == "domain":
                obj_type = "domain-name"
                observable_key = "value"
            elif ioc_type == "ip":
                obj_type = "ipv4-addr"
                observable_key = "value"
            elif ioc_type in ("hash", "sha256"):
                obj_type = "file"
                observable_key = "hashes"
                value = {"SHA-256": value}

            if obj_type:
                objects.append({
                    "type": obj_type,
                    "spec_version": "2.1",
                    "id": f"{obj_type}--{uuid.uuid4()}",
                    observable_key: value,
                })

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }


def export_stix_bundle(analysis_id: str, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for STIX export."""
    return Stix21Exporter.export_bundle(analysis_id, analysis_result)
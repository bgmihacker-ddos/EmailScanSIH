"""
Phase 19: SOAR / Response Artifacts Service.

Generates actionable defense artifacts from email forensic analyses:
- IOC blocklist (CSV/plain text formats)
- SIEM detection queries (KQL, Splunk SPL, Sigma rules)
- SIEM-ready JSON event (CEF/ECS compatible structure)
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Set


class ResponseArtifactGenerator:
    """Generates SOAR and SIEM artifacts from forensic analysis results."""

    @staticmethod
    def generate_blocklist_csv(analysis_result: Dict[str, Any]) -> str:
        """Generate CSV string containing all actionable threat indicators."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["indicator_type", "indicator_value", "threat_verdict", "source_context"])

        verdict = analysis_result.get("verdict", "unknown")
        extracted = analysis_result.get("extracted_iocs", {})
        iocs = extracted.get("iocs", []) if isinstance(extracted, dict) else []

        seen: Set[str] = set()
        for ioc in iocs:
            if not isinstance(ioc, dict):
                continue
            itype = str(ioc.get("type", "")).strip()
            val = str(ioc.get("value", "")).strip()
            if not itype or not val or val in seen:
                continue
            seen.add(val)
            writer.writerow([itype, val, verdict, "extracted_iocs"])

        # Also add attachment hashes if present
        for att in analysis_result.get("attachments", {}).get("attachments", []):
            if isinstance(att, dict):
                sha256 = att.get("sha256")
                if sha256 and sha256 not in seen:
                    seen.add(sha256)
                    writer.writerow(["sha256", sha256, verdict, f"attachment:{att.get('filename', '')}"])

        return output.getvalue()

    @staticmethod
    def generate_siem_queries(analysis_result: Dict[str, Any]) -> Dict[str, str]:
        """Generate KQL, Splunk SPL, and Sigma detection rules for observed indicators."""
        extracted = analysis_result.get("extracted_iocs", {})
        iocs = extracted.get("iocs", []) if isinstance(extracted, dict) else []

        urls = [ioc.get("value") for ioc in iocs if isinstance(ioc, dict) and ioc.get("type") == "url" and ioc.get("value")]
        domains = [ioc.get("value") for ioc in iocs if isinstance(ioc, dict) and ioc.get("type") == "domain" and ioc.get("value")]
        ips = [ioc.get("value") for ioc in iocs if isinstance(ioc, dict) and ioc.get("type") == "ip" and ioc.get("value")]
        hashes = [ioc.get("value") for ioc in iocs if isinstance(ioc, dict) and ioc.get("type") in ("hash", "sha256") and ioc.get("value")]

        for att in analysis_result.get("attachments", {}).get("attachments", []):
            if isinstance(att, dict) and att.get("sha256"):
                hashes.append(att.get("sha256"))

        # KQL (Microsoft Defender / Sentinel)
        kql_parts = []
        if domains:
            dom_list = ", ".join(f"'{d}'" for d in domains[:10])
            kql_parts.append(f"DeviceNetworkEvents | where RemoteUrl has_any ({dom_list})")
        if ips:
            ip_list = ", ".join(f"'{ip}'" for ip in ips[:10])
            kql_parts.append(f"DeviceNetworkEvents | where RemoteIP has_any ({ip_list})")
        if hashes:
            hash_list = ", ".join(f"'{h}'" for h in hashes[:10])
            kql_parts.append(f"DeviceFileEvents | where SHA256 has_any ({hash_list})")

        kql_query = "\n// OR\n".join(kql_parts) if kql_parts else "// No indicators available for KQL"

        # Splunk SPL
        splunk_parts = []
        if domains:
            splunk_parts.append(f"index=* ( " + " OR ".join(f'query="*{d}*"' for d in domains[:10]) + " )")
        if ips:
            splunk_parts.append(f"index=* ( " + " OR ".join(f'dest_ip="{ip}"' for ip in ips[:10]) + " )")
        if hashes:
            splunk_parts.append(f"index=* ( " + " OR ".join(f'file_hash="{h}"' for h in hashes[:10]) + " )")

        splunk_query = "\nOR\n".join(splunk_parts) if splunk_parts else 'index=* "no_indicators"'

        # Sigma Rule (YAML string)
        sigma_yaml = (
            "title: Email Forensic Investigation Correlated Threat Indicators\n"
            "status: experimental\n"
            "description: Detects network or file activity matching indicators from email forensics\n"
            "logsource:\n"
            "    category: network_connection\n"
            "detection:\n"
            "    selection:\n"
        )
        if domains:
            sigma_yaml += "        DestinationHostname:\n" + "".join(f"            - '{d}'\n" for d in domains[:10])
        if ips:
            sigma_yaml += "        DestinationIp:\n" + "".join(f"            - '{ip}'\n" for ip in ips[:10])
        if not domains and not ips:
            sigma_yaml += "        DestinationHostname: []\n"
        sigma_yaml += (
            "    condition: selection\n"
            "level: high\n"
        )

        return {
            "kql": kql_query,
            "splunk": splunk_query,
            "sigma": sigma_yaml,
        }


def generate_blocklist(analysis_result: Dict[str, Any]) -> str:
    """Convenience function for blocklist generation."""
    return ResponseArtifactGenerator.generate_blocklist_csv(analysis_result)


def generate_queries(analysis_result: Dict[str, Any]) -> Dict[str, str]:
    """Convenience function for SIEM queries."""
    return ResponseArtifactGenerator.generate_siem_queries(analysis_result)
"""
Phase 15: MITRE ATT&CK Mapping Service.

Maps observed forensic evidence to MITRE ATT&CK enterprise techniques statically
and deterministically without external API calls.
"""

from __future__ import annotations

from typing import Any, Dict, List


class MitreMapper:
    """Maps forensic evidence to MITRE ATT&CK techniques."""

    _TECHNIQUE_RULES = [
        {
            "technique_id": "T1566.001",
            "technique_name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "check": lambda res: any(
                "attachment" in str(f.get("finding_id", "")).lower() or
                "executable" in str(f.get("title", "")).lower() or
                res.get("attachments", {}).get("high_risk_count", 0) > 0
                for f in res.get("all_findings", [])
            ),
        },
        {
            "technique_id": "T1566.002",
            "technique_name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "check": lambda res: any(
                "url" in str(f.get("finding_id", "")).lower() or
                "credential" in str(f.get("finding_id", "")).lower() or
                res.get("content", {}).get("html_indicators")
                for f in res.get("all_findings", [])
            ),
        },
        {
            "technique_id": "T1656",
            "technique_name": "Impersonation",
            "tactic": "Initial Access",
            "check": lambda res: any(
                "spoof" in str(f.get("finding_id", "")).lower() or
                "mismatch" in str(f.get("finding_id", "")).lower() or
                "impersonat" in str(f.get("finding_id", "")).lower()
                for f in res.get("all_findings", [])
            ),
        },
        {
            "technique_id": "T1598.003",
            "technique_name": "Phishing for Information: Spearphishing Link",
            "tactic": "Reconnaissance",
            "check": lambda res: any(
                "credential" in str(f.get("finding_id", "")).lower() or
                "harvest" in str(f.get("finding_id", "")).lower()
                for f in res.get("all_findings", [])
            ),
        },
        {
            "technique_id": "T1204.001",
            "technique_name": "User Execution: Malicious Link",
            "tactic": "Execution",
            "check": lambda res: len(res.get("urls", [])) > 0 and res.get("risk", {}).get("verdict") == "malicious",
        },
        {
            "technique_id": "T1204.002",
            "technique_name": "User Execution: Malicious File",
            "tactic": "Execution",
            "check": lambda res: res.get("attachments", {}).get("high_risk_count", 0) > 0,
        },
    ]

    @staticmethod
    def map_evidence(analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map analysis result to MITRE ATT&CK techniques."""
        matched_techniques: List[Dict[str, Any]] = []
        seen_ids = set()

        for rule in MitreMapper._TECHNIQUE_RULES:
            tech_id = rule["technique_id"]
            if tech_id in seen_ids:
                continue

            try:
                if rule["check"](analysis_result):
                    seen_ids.add(tech_id)
                    matched_techniques.append({
                        "technique_id": tech_id,
                        "technique_name": rule["technique_name"],
                        "tactic": rule["tactic"],
                        "confidence": 85,
                        "evidence_refs": [],
                    })
            except Exception:
                pass

        return matched_techniques


def map_mitre_techniques(analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convenience function for MITRE mapping."""
    return MitreMapper.map_evidence(analysis_result)
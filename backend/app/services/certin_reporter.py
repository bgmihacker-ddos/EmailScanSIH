"""CERT-In incident report formatter.

Generates a structured incident report following Indian CERT-In reporting guidelines.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_certin_report(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Format analysis data into a CERT-In compliant incident report."""
    now = datetime.now(timezone.utc).isoformat()
    findings = analysis.get("findings") or []
    iocs = analysis.get("ioc_extraction") or analysis.get("iocs") or {}
    header_analysis = analysis.get("header_analysis") or analysis.get("header_forensics") or {}
    auth = analysis.get("authentication_results") or analysis.get("authentication") or {}
    verdict = analysis.get("verdict", "unknown")
    risk_score = analysis.get("risk_score", 0)

    # Classify incident type
    incident_type = _classify_incident(findings, analysis)

    # Extract IOC summary
    urls = iocs.get("urls") or []
    domains = iocs.get("domains") or []
    ips = iocs.get("ip_addresses") or iocs.get("ips") or []
    emails_found = iocs.get("email_addresses") or []
    hashes = iocs.get("file_hashes") or []

    india_data = analysis.get("india_threat_intel") or {}

    report = {
        "report_type": "CERT-In Incident Report",
        "report_version": "2.0",
        "generated_at": now,
        "classification": "TLP:AMBER",

        "section_1_incident_identification": {
            "incident_id": analysis.get("analysis_id", "N/A"),
            "incident_type": incident_type,
            "severity": analysis.get("severity", "medium"),
            "date_detected": now,
            "reporting_organization": "Email Threat Detection Platform",
            "contact_email": "security@organization.gov.in",
        },

        "section_2_incident_description": {
            "summary": f"Automated analysis detected a {verdict} email (risk score: {risk_score}/100).",
            "verdict": verdict,
            "risk_score": risk_score,
            "attack_vector": "Email / Phishing",
            "findings_count": len(findings),
            "key_findings": [
                {"title": f.get("title", ""), "severity": f.get("severity", ""), "confidence": f.get("confidence", 0)}
                for f in findings[:15]
            ],
        },

        "section_3_technical_details": {
            "email_subject": analysis.get("subject", "N/A"),
            "sender_address": analysis.get("sender", {}).get("address", "N/A") if isinstance(analysis.get("sender"), dict) else analysis.get("from", "N/A"),
            "authentication": {
                "spf": auth.get("spf", {}).get("result", "none") if isinstance(auth.get("spf"), dict) else str(auth.get("spf", "none")),
                "dkim": auth.get("dkim", {}).get("result", "none") if isinstance(auth.get("dkim"), dict) else str(auth.get("dkim", "none")),
                "dmarc": auth.get("dmarc", {}).get("result", "none") if isinstance(auth.get("dmarc"), dict) else str(auth.get("dmarc", "none")),
            },
            "mitre_techniques": [
                t.get("technique_id", "") for t in (analysis.get("mitre_mapping") or analysis.get("mitre_techniques") or [])
            ],
        },

        "section_4_indicators_of_compromise": {
            "malicious_urls": urls[:20],
            "suspicious_domains": domains[:20],
            "ip_addresses": ips[:20],
            "email_addresses": emails_found[:10],
            "file_hashes": hashes[:10],
        },

        "section_5_india_specific": {
            "impersonated_brands": india_data.get("impersonated_brands", []),
            "scam_patterns": india_data.get("scam_patterns", []),
            "ist_anomaly": india_data.get("ist_timezone_anomaly", False),
        },

        "section_6_evidence_integrity": {
            "analysis_hash": analysis.get("evidence_integrity", {}).get("result_sha256", "N/A"),
            "raw_email_hash": analysis.get("evidence_integrity", {}).get("raw_email_sha256", "N/A"),
            "blockchain_anchor": analysis.get("blockchain_anchor", None),
        },

        "section_7_recommendations": _generate_recommendations(findings, verdict, risk_score),
    }
    return report


def _classify_incident(findings: List[Dict], analysis: Dict) -> str:
    titles = " ".join(f.get("title", "").lower() for f in findings)
    if "credential" in titles or "password" in titles:
        return "Phishing – Credential Harvesting"
    if "bec" in titles or "wire fraud" in titles:
        return "Business Email Compromise (BEC)"
    if "malware" in titles or "attachment" in titles:
        return "Malware Distribution via Email"
    if "impersonation" in titles or "spoof" in titles:
        return "Email Spoofing / Impersonation"
    verdict = analysis.get("verdict", "")
    if verdict in ("malicious", "phishing"):
        return "Phishing – General"
    return "Suspicious Email Activity"


def _generate_recommendations(findings: List[Dict], verdict: str, risk_score: int) -> List[str]:
    recs = []
    if risk_score >= 70:
        recs.append("IMMEDIATE: Block sender domain and quarantine similar emails.")
        recs.append("Add extracted IOCs to organizational blocklists.")
    if any("credential" in f.get("title", "").lower() for f in findings):
        recs.append("Force password reset for any users who may have interacted with this email.")
    if any("bec" in f.get("title", "").lower() for f in findings):
        recs.append("Verify any financial requests through out-of-band communication channels.")
    recs.append("Report to CERT-In via incident@cert-in.org.in with this report attached.")
    recs.append("Preserve original email headers and attachments as evidence.")
    return recs

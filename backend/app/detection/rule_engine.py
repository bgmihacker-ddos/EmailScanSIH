import re
from typing import Any, Dict, List


class RuleEngine:
    @staticmethod
    def analyze(email_data: Dict[str, Any]) -> Dict[str, Any]:
        results = {
            "verdict": "benign",
            "risk_score": 0,
            "confidence": 100,
            "summary": "Email passed basic security checks.",
            "reasons": [],
            "evidence": [],
            "detections": [],
            "authentication": {
                "spf": str(email_data.get("spf") or "missing"),
                "dkim": str(email_data.get("dkim") or "missing"),
                "dmarc": str(email_data.get("dmarc") or "missing"),
            },
            "forensic_findings": [],
            "threat_reasoning": [],
            "attack_chain": [],
            "iocs": {"urls": [], "domains": [], "ips": [], "attachments": []},
            "threat_intelligence": [],
            "recommendations": [],
        }

        text = (email_data.get("plain_text", "") + " " + email_data.get("html_body", "")).lower()
        from_addr = (email_data.get("from") or "").lower()

        # Urgency and social engineering
        urgency_keywords = [
            "urgent",
            "immediate",
            "action required",
            "verify account",
            "confirm identity",
            "click here",
            "urgent action",
            "asap",
            "time-sensitive",
            "act now",
        ]
        if any(kw in text for kw in urgency_keywords):
            results["risk_score"] += 20
            results["reasons"].append("Contains high-urgency language typical of phishing.")
            results["detections"].append("Urgency/Social Engineering")
            results["threat_reasoning"].append("Artificial urgency is a common social engineering tactic.")

        # Financial/credential requests
        credential_keywords = [
            "password",
            "confirm password",
            "verify credentials",
            "credit card",
            "bank account",
            "ssn",
            "social security",
            "atm pin",
            "verify payment",
            "billing information",
        ]
        if any(kw in text for kw in credential_keywords):
            results["risk_score"] += 25
            results["reasons"].append("Contains requests for sensitive credentials or financial information.")
            results["detections"].append("Credential Harvesting")
            results["threat_reasoning"].append("Legitimate companies never request credentials via email.")

        # Authentication checks
        spf_status = email_data.get("spf", "").lower() if email_data.get("spf") else "unknown"
        if not email_data.get("spf") or "fail" in spf_status:
            results["risk_score"] += 15
            results["reasons"].append("SPF validation failed or missing.")
            results["detections"].append("Authentication Failure")
            results["threat_reasoning"].append("Missing or failed SPF record increases spoofing risk.")

        dkim_status = email_data.get("dkim", "").lower() if email_data.get("dkim") else "unknown"
        if not email_data.get("dkim") or "fail" in dkim_status:
            results["risk_score"] += 10
            results["reasons"].append("DKIM validation failed or missing.")
            results["detections"].append("Authentication Failure")
            results["threat_reasoning"].append("Missing or failed DKIM signature allows message tampering.")

        # Reply-to mismatch
        reply_to = (email_data.get("reply_to") or "").lower()
        if from_addr and reply_to and from_addr != reply_to and "@" in from_addr and "@" in reply_to:
            from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
            reply_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
            if from_domain and reply_domain and from_domain != reply_domain:
                results["risk_score"] += 20
                results["reasons"].append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}).")
                results["detections"].append("Reply-To Mismatch")
                results["threat_reasoning"].append("Domain mismatch between From and Reply-To suggests spoofing.")

        # Suspicious attachments
        attachments = email_data.get("attachments", [])
        dangerous_extensions = [
            "exe",
            "bat",
            "cmd",
            "scr",
            "vbs",
            "js",
            "jar",
            "zip",
            "rar",
            "7z",
            "dll",
            "msi",
            "ps1",
            "psm1",
        ]
        for att in attachments:
            ext = att.get("extension", "").lower()
            if ext in dangerous_extensions:
                results["risk_score"] += 15
                results["reasons"].append(f"Suspicious attachment extension: .{ext}")
                results["detections"].append("Suspicious Attachment")
                results["threat_reasoning"].append(f".{ext} files are commonly used in malware delivery.")
                results["iocs"]["attachments"].append(att.get("name", "unknown"))

        # Suspicious URLs
        url_pattern = r"https?://[^\s]+"
        urls = re.findall(url_pattern, text)
        suspicious_url_keywords = ["bit.ly", "tinyurl", "short.link", "update", "verify", "confirm", "urgent"]
        for url in urls:
            url_lower = url.lower()
            if any(kw in url_lower for kw in suspicious_url_keywords):
                results["risk_score"] += 10
                results["reasons"].append(f"Suspicious URL pattern detected: {url[:50]}...")
                results["detections"].append("Suspicious URL")
                results["threat_reasoning"].append("Short or obfuscated URLs are commonly used in phishing.")
                results["iocs"]["urls"].append(url)

        # Determine severity and final verdict
        if results["risk_score"] >= 50:
            results["verdict"] = "malicious"
            results["severity"] = "high"
            results["confidence"] = min(100, 60 + (results["risk_score"] - 50))
            results["summary"] = "Email is likely malicious. Immediate action recommended."
            results["recommendations"].append("Delete this email immediately.")
            results["recommendations"].append("Do not click links or download attachments.")
            results["recommendations"].append("Report this email to your IT security team.")
        elif results["risk_score"] >= 25:
            results["verdict"] = "suspicious"
            results["severity"] = "medium"
            results["confidence"] = min(100, 50 + results["risk_score"])
            results["summary"] = "Email exhibits suspicious characteristics. Caution advised."
            results["recommendations"].append("Exercise caution with this email.")
            results["recommendations"].append("Verify sender through an independent channel.")
            results["recommendations"].append("Do not click external links without verifying.")
        else:
            results["verdict"] = "benign"
            results["severity"] = "low"
            results["confidence"] = 100
            results["summary"] = "Email appears legitimate based on basic checks."
            results["recommendations"].append("Standard email precautions apply.")

        # Forensic findings
        results["forensic_findings"] = [
            {"type": "Header Analysis", "detail": f"From: {from_addr}, Subject: {(email_data.get('subject') or 'N/A')[:50]}"},
            {
                "type": "Authentication Status",
                "detail": f"SPF: {results['authentication']['spf']}, DKIM: {results['authentication']['dkim']}, DMARC: {results['authentication'].get('dmarc', 'missing')}",
            },
            {"type": "Body Analysis", "detail": f"Plain text: {len(email_data.get('plain_text', ''))} chars, HTML: {len(email_data.get('html_body', ''))} chars"},
            {"type": "Attachments", "detail": f"Count: {len(attachments)}, Types: {', '.join([a.get('type', 'unknown') for a in attachments]) if attachments else 'None'}"},
        ]

        # Attack chain (simplified)
        if results["detections"]:
            results["attack_chain"] = [
                f"Initial detection: {results['detections'][0]}",
                f"Risk assessment: Risk score {results['risk_score']}/100",
                "Recommended action: Follow recommendations above.",
            ]
        else:
            results["attack_chain"] = ["No threats detected.", "Email appears safe.", "Standard precautions apply."]

        results["evidence"] = results["reasons"]

        return results

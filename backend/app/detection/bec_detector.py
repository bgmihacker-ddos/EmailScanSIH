"""Phase 12: Business Email Compromise (BEC) & Executive Impersonation Detector.

Performs deterministic analysis for:
- Executive / VIP impersonation
- Urgent wire transfers & financial transaction requests
- Payroll / direct deposit alteration requests
- Secrecy & out-of-band communication requests
- Gift card and vendor payment diversion scams
"""

import re
from typing import Any, Dict, List, Optional


class BECDetector:
    # Common executive / VIP titles
    EXECUTIVE_TITLES = [
        r"\bceo\b", r"\bcfo\b", r"\bcto\b", r"\bcoo\b", r"\bpresident\b",
        r"\bexecutive\s+director\b", r"\bmanaging\s+director\b", r"\bboard\s+member\b",
        r"\bvice\s+president\b", r"\bvp\b", r"\bhead\s+of\s+finance\b", r"\bpayroll\b",
        r"\bhuman\s+resources\b", r"\bhr\s+director\b", r"\bfinance\s+controller\b"
    ]

    # Urgent financial transactions
    FINANCIAL_PATTERNS = [
        (r"\b(?:wire|bank)\s+(?:transfer|payment)\b", "Wire transfer request", 25),
        (r"\b(?:update|change|switch)\s+(?:our\s+|my\s+|the\s+)?(?:banking|bank|direct\s+deposit|payroll|ach|routing|remittance)\s+(?:details?|info|information|account)\b", "Direct deposit / Bank account change request", 30),
        (r"\b(?:new|updated)\s+(?:invoice|banking|bank\s+account)\b", "Vendor invoice diversion", 25),
        (r"\b(?:purchase|buy|get)\s+(?:[a-z]+\s+)*(?:apple|google\s+play|steam|amazon|gift|itunes|target)\s+cards?\b", "Gift card purchase solicitation", 35),
        (r"\b(?:overdue|urgent|pending)\s+(?:payment|invoice|remittance)\b", "Urgent payment solicitation", 20),
        (r"\b(?:swift|iban|routing\s+number|account\s+number)\b", "Banking routing identifier solicitation", 20),
        (r"\bdirect\s+deposit\b", "Direct deposit modification reference", 20),
    ]

    # Urgency & Secrecy patterns
    SECRECY_PATTERNS = [
        (r"\b(?:keep\s+this\s+confidential|strictly\s+confidential|between\s+you\s+and\s+me|do\s+not\s+(?:call|discuss|tell)|keep\s+it\s+quiet)\b", "Explicit secrecy / out-of-band restriction", 20),
        (r"\b(?:available\s+right\s+now|in\s+a\s+meeting|cannot\s+take\s+calls?|reach\s+me\s+only\s+via\s+email|working\s+remotely)\b", "Executive unavailability pretense", 15),
        (r"\b(?:asap|urgently|urgent\s+attention|immediate\s+attention|immediately|before\s+end\s+of\s+day|within\s+the\s+hour|time[- ]sensitive)\b", "High urgency pressure", 15),
    ]

    # Free email provider domains commonly used for lookalike executive emails
    FREEMAIL_PROVIDERS = {
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
        "mail.com", "proton.me", "protonmail.com", "aol.com", "zoho.com"
    }

    @classmethod
    def analyze(cls, parsed_email: Dict[str, Any], header_forensics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze an email for Business Email Compromise (BEC) patterns."""
        findings: List[Dict[str, Any]] = []
        risk_score_delta = 0
        detected_types: List[str] = []

        if not parsed_email or not isinstance(parsed_email, dict):
            return {
                "status": "completed",
                "is_bec": False,
                "confidence": 0,
                "bec_score": 0,
                "detected_types": [],
                "findings": [],
            }

        # 1. Extract addresses
        addresses = parsed_email.get("addresses", {}) or {}
        from_info = addresses.get("from") or {}
        display_name = str(from_info.get("display_name") or "")
        from_address = str(from_info.get("address") or parsed_email.get("from") or "").lower()
        from_domain = from_address.split("@")[-1] if "@" in from_address else ""

        reply_to_list = addresses.get("reply_to") or []
        reply_to_address = ""
        reply_to_domain = ""
        if reply_to_list and isinstance(reply_to_list[0], dict):
            reply_to_address = str(reply_to_list[0].get("address") or "").lower()
            reply_to_domain = reply_to_address.split("@")[-1] if "@" in reply_to_address else ""

        # 2. Extract content
        subject = str(parsed_email.get("subject") or "")
        body_text = str(parsed_email.get("plain_text") or "")
        full_content = f"{subject}\n{body_text}".lower()

        # Check for Executive display name on generic freemail provider
        has_exec_title = any(re.search(pat, display_name, re.IGNORECASE) for pat in cls.EXECUTIVE_TITLES)
        if has_exec_title and from_domain in cls.FREEMAIL_PROVIDERS:
            findings.append({
                "type": "executive_freemail_impersonation",
                "title": f"Executive title '{display_name}' sent from free webmail ({from_domain})",
                "severity": "high",
                "points": 35,
                "evidence": f"From: {display_name} <{from_address}>",
                "evidence_class": "strong_risk_signal",
            })
            risk_score_delta += 35
            detected_types.append("executive_freemail_impersonation")

        # Reply-To / From Domain Mismatch in BEC Context
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            findings.append({
                "type": "bec_reply_to_divergence",
                "title": f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})",
                "severity": "medium",
                "points": 20,
                "evidence": f"From: {from_address} | Reply-To: {reply_to_address}",
                "evidence_class": "contextual_anomaly",
            })
            risk_score_delta += 20
            detected_types.append("bec_reply_to_divergence")

        # Check Financial solicitation patterns
        for pattern, label, points in cls.FINANCIAL_PATTERNS:
            match = re.search(pattern, full_content, re.IGNORECASE)
            if match:
                findings.append({
                    "type": "financial_solicitation",
                    "title": label,
                    "severity": "high" if points >= 25 else "medium",
                    "points": points,
                    "evidence": match.group(0),
                    "evidence_class": "strong_risk_signal",
                })
                risk_score_delta += points
                detected_types.append("financial_solicitation")
                break  # Cap at highest financial match to avoid duplicate stacking

        # Check Urgency & Secrecy patterns
        for pattern, label, points in cls.SECRECY_PATTERNS:
            match = re.search(pattern, full_content, re.IGNORECASE)
            if match:
                findings.append({
                    "type": "urgency_secrecy_pretense",
                    "title": label,
                    "severity": "medium",
                    "points": points,
                    "evidence": match.group(0),
                    "evidence_class": "contextual_anomaly",
                })
                risk_score_delta += points
                detected_types.append("urgency_secrecy_pretense")
                break

        # Compound BEC Multiplier: If financial request + (urgency OR reply-to mismatch OR exec freemail)
        is_compound_bec = ("financial_solicitation" in detected_types) and (
            "executive_freemail_impersonation" in detected_types
            or "bec_reply_to_divergence" in detected_types
            or "urgency_secrecy_pretense" in detected_types
        )

        if is_compound_bec:
            findings.append({
                "type": "compound_bec_attack",
                "title": "High-confidence Business Email Compromise (BEC) attack vector identified",
                "severity": "critical",
                "points": 25,
                "evidence": f"Compound signals: {', '.join(detected_types)}",
                "evidence_class": "strong_risk_signal",
            })
            risk_score_delta += 25
            detected_types.append("compound_bec_attack")

        bec_score = min(100, max(0, risk_score_delta))
        is_bec = bec_score >= 35

        return {
            "status": "completed",
            "is_bec": is_bec,
            "confidence": min(95, 50 + len(findings) * 15) if findings else 0,
            "bec_score": bec_score,
            "detected_types": list(set(detected_types)),
            "findings": findings,
        }

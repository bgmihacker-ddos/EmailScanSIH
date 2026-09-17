"""India-specific threat intelligence: brand impersonation, UPI/KYC scams, IST anomalies."""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List

_INDIAN_BRANDS = {
    "banks": ["sbi", "state bank", "hdfc", "icici", "axis bank", "pnb", "punjab national",
              "bank of baroda", "canara bank", "kotak", "yes bank", "idbi", "indian bank",
              "union bank", "bob", "rbi", "reserve bank"],
    "upi": ["paytm", "phonepe", "google pay", "gpay", "bhim", "upi", "bharat pay",
            "amazon pay", "cred", "mobikwik", "freecharge"],
    "govt": ["aadhaar", "aadhar", "pan card", "income tax", "gst", "epfo", "provident fund",
             "digilocker", "umang", "cowin", "rti", "nrega", "pmjay", "ayushman",
             "ministry of", "govt of india", "government of india", "mygov"],
    "ecommerce": ["flipkart", "myntra", "meesho", "snapdeal", "jiomart", "bigbasket",
                  "swiggy", "zomato", "dunzo", "blinkit", "nykaa"],
    "telecom": ["jio", "airtel", "vi ", "vodafone", "idea ", "bsnl", "trai"],
}
_FLAT = {brand: cat for cat, brands in _INDIAN_BRANDS.items() for brand in brands}

_INDIA_SCAM_PATTERNS = [
    r"kyc\s*(update|verify|expir|mandatory|pending|suspend)",
    r"(aadhaar|aadhar|pan)\s*(link|verify|update|expir|mismatch)",
    r"upi\s*(id|pin|verify|block|suspend|limit)",
    r"(refund|cashback)\s*(of|worth)?\s*₹?\s*[\d,]+",
    r"(dear\s+customer|valued\s+customer)",
    r"(sbi|hdfc|icici|axis)\s*(yono|net\s*banking|alert)",
    r"electricity\s*(bill|disconnect|payment)",
    r"sim\s*(card|swap|block|deactivat)",
    r"(lucky\s*draw|lottery)\s*(winner|prize|selected)",
    r"(customs|courier)\s*(held|seized|parcel|package)",
    r"(whatsapp|telegram)\s*(job|earn|part.time|work.from.home)",
]
_INDIA_SCAM_RE = [re.compile(p, re.IGNORECASE) for p in _INDIA_SCAM_PATTERNS]

_HINDI_THREAT_KEYWORDS = [
    "turant", "jaldi", "khata band", "kyc", "aadhar", "paisa", "rupaye",
    "account block", "sim block", "otp bheje", "bhejein", "kripya",
    "sarkari", "naukri", "lottery jeetein",
]

_INDIA_CAUSES = {
    "trusted_brand_impersonation": {
        "title": "Trusted Indian brand impersonation",
        "description": "The message borrows trust from a bank, payment app, government service, telecom provider, or major Indian consumer brand.",
        "response": "Open the service from its official app or a manually typed website, not from the email.",
    },
    "kyc_identity_pressure": {
        "title": "KYC or identity pressure",
        "description": "KYC, Aadhaar, PAN, GST, or account-verification language creates fear of suspension and pushes the recipient toward disclosure.",
        "response": "Never send Aadhaar, PAN, passwords, or OTPs by email. Verify the request with the institution using an official channel.",
    },
    "upi_payment_social_engineering": {
        "title": "UPI or payment social engineering",
        "description": "UPI, PIN, refund, cashback, or payment language can be used to make a victim approve a transaction or reveal payment credentials.",
        "response": "Never share a UPI PIN or OTP. A UPI PIN is used to authorize payments, not to receive a refund.",
    },
    "urgency_and_fear": {
        "title": "Urgency and fear conditioning",
        "description": "Threats of blocking, expiry, disconnection, penalties, or short deadlines reduce time for independent verification.",
        "response": "Pause and verify the request independently before clicking, replying, paying, or calling a number in the message.",
    },
    "credential_or_otp_harvesting": {
        "title": "Credential or OTP harvesting",
        "description": "The message asks for a login, password, OTP, PIN, or verification step that could enable account takeover or payment fraud.",
        "response": "Do not enter credentials from an email link. Go directly to the official service and review account activity there.",
    },
    "regional_language_targeting": {
        "title": "Regional-language social engineering",
        "description": "Hindi or regional-language cues may increase familiarity and urgency for a targeted audience; language alone is not proof of fraud.",
        "response": "Treat familiar language as a delivery tactic, then validate the sender, domain, authentication, and requested action.",
    },
    "telecom_or_sim_swap": {
        "title": "Telecom or SIM-swap pretext",
        "description": "SIM deactivation, mobile verification, or telecom-account language can precede account takeover and OTP interception.",
        "response": "Contact the mobile operator through its official support channel and never share an OTP or remote-access code.",
    },
    "delivery_or_refund_lure": {
        "title": "Delivery, customs, refund, or lottery lure",
        "description": "Small fees, held parcels, refunds, cashback, and prizes create a low-friction reason to click or pay immediately.",
        "response": "Track parcels and refunds only through the official merchant or courier app; do not pay through an email link.",
    },
}

_INDIA_RESEARCH_SOURCES = [
    {"name": "CERT-In", "url": "https://www.cert-in.org.in/", "use": "Indian national cyber-incident response and reporting guidance."},
    {"name": "NPCI UPI safety", "url": "https://www.npci.org.in/product/upi/safety-features", "use": "UPI safety and fraud-awareness guidance."},
    {"name": "National Cyber Crime Reporting Portal", "url": "https://www.cybercrime.gov.in/", "use": "Report suspected cybercrime in India."},
    {"name": "RBI Sachet", "url": "https://sachet.rbi.org.in/", "use": "Report certain financial fraud and unauthorized activity concerns."},
]


class IndiaThreatIntel:
    @staticmethod
    def analyze(email_data: Dict[str, Any]) -> Dict[str, Any]:
        plain = str(email_data.get("plain_text") or "")
        html = str(email_data.get("html_body") or "")
        subject = str(email_data.get("subject") or "")
        full_text = (subject + " " + plain + " " + html).lower()
        headers = email_data.get("headers") or {}

        # Brand impersonation
        impersonated: List[Dict[str, str]] = []
        government_action = re.search(
            r"\b(verify|update|expire|expired|pending|refund|notice|tax|registration|account|login|click|link|document|submit)\b",
            full_text,
            re.IGNORECASE,
        )
        for brand, category in _FLAT.items():
            brand_pattern = rf"(?<!\w){re.escape(brand.strip())}(?!\w)"
            if brand in {"gst", "rti"} and not government_action:
                continue
            if re.search(brand_pattern, full_text, re.IGNORECASE):
                impersonated.append({"brand": brand, "category": category})

        # Scam pattern matches
        scam_hits: List[str] = []
        for rx in _INDIA_SCAM_RE:
            m = rx.search(full_text)
            if m:
                scam_hits.append(m.group(0))

        # Hindi/regional keywords
        hindi_hits = [k for k in _HINDI_THREAT_KEYWORDS if k in full_text]

        india_anchor = bool(impersonated or hindi_hits or re.search(
            r"\b(india|indian|inr|upi|aadhaar|aadhar|pan\s*card|kyc|gst|digilocker)\b|₹",
            full_text,
            re.IGNORECASE,
        ))

        if not india_anchor:
            return {
                "impersonated_brands": [],
                "scam_patterns": [],
                "hindi_keywords": [],
                "ist_timezone_anomaly": False,
                "likely_causes": [],
                "research_sources": [],
                "findings": [],
            }

        # IST timezone anomaly: if claimed sender is Indian but Date header offset isn't +0530
        ist_anomaly = False
        date_header = headers.get("Date") or headers.get("date") or ""
        if impersonated and date_header:
            ist_anomaly = _check_ist_anomaly(date_header)

        # Build findings
        findings: List[Dict[str, Any]] = []
        causes: List[Dict[str, Any]] = []

        def add_cause(cause_id: str, evidence: List[str], confidence: int) -> None:
            cause = _INDIA_CAUSES[cause_id]
            causes.append({
                "cause_id": cause_id,
                "title": cause["title"],
                "description": cause["description"],
                "evidence": evidence[:8],
                "confidence": confidence,
                "response": cause["response"],
            })

        if impersonated:
            add_cause("trusted_brand_impersonation", [f"{b['brand']} ({b['category']})" for b in impersonated], 88)
        identity_signal = re.search(r"kyc|aadhaar|aadhar|pan\s*card|identity", full_text, re.IGNORECASE)
        gst_signal = re.search(r"\bgst\b", full_text, re.IGNORECASE) and government_action
        if any(re.search(r"kyc|aadhaar|aadhar|pan\s*card|gst|identity", value, re.IGNORECASE) for value in scam_hits) or identity_signal or gst_signal:
            add_cause("kyc_identity_pressure", scam_hits or ["KYC/identity language"], 86)
        if re.search(r"upi|pin|refund|cashback|payment|transaction", full_text, re.IGNORECASE):
            add_cause("upi_payment_social_engineering", ["UPI/payment/refund language"], 82)
        if re.search(r"urgent|immediately|within\s+\d+\s*(hour|minute)|suspend|block|expire|disconnect|penalt", full_text, re.IGNORECASE):
            add_cause("urgency_and_fear", ["Urgency, blocking, expiry, or disconnection language"], 80)
        if re.search(r"otp|one[- ]time password|password|passcode|login|sign[- ]?in|verify your", full_text, re.IGNORECASE):
            add_cause("credential_or_otp_harvesting", ["Credential or verification language"], 84)
        if hindi_hits:
            add_cause("regional_language_targeting", hindi_hits, 68)
        if re.search(r"sim|mobile number|telecom|deactivat", full_text, re.IGNORECASE):
            add_cause("telecom_or_sim_swap", ["Telecom or SIM language"], 78)
        if re.search(r"customs|courier|parcel|package|refund|cashback|lottery|prize", full_text, re.IGNORECASE):
            add_cause("delivery_or_refund_lure", ["Delivery, refund, lottery, or prize language"], 76)

        if impersonated:
            findings.append({
                "finding_id": "india.brand_impersonation",
                "category": "india_specific",
                "title": "Indian Brand Impersonation Detected",
                "description": f"Email references {len(impersonated)} Indian brand(s) which may indicate targeted impersonation.",
                "severity": "high" if len(impersonated) >= 2 else "medium",
                "confidence": min(90, 70 + len(impersonated) * 10),
                "evidence": [f"{b['brand']} ({b['category']})" for b in impersonated[:10]],
                "related_iocs": [],
                "evidence_class": "strong_risk_signal" if scam_hits else "contextual_anomaly",
                "risk_relevance": "risk_contributing" if scam_hits else "contextual",
            })

        if scam_hits:
            findings.append({
                "finding_id": "india.scam_pattern",
                "category": "india_specific",
                "title": "India-Specific Scam Pattern Detected",
                "description": "Email matches known Indian scam patterns (KYC fraud, UPI scams, fake refunds).",
                "severity": "high", "confidence": 88,
                "evidence": scam_hits[:10], "related_iocs": [],
                "evidence_class": "strong_risk_signal", "risk_relevance": "risk_contributing",
            })

        if hindi_hits:
            findings.append({
                "finding_id": "india.hindi_threat_keywords",
                "category": "india_specific",
                "title": "Hindi/Regional Threat Keywords",
                "description": "Email contains Hindi keywords commonly used in social engineering targeting Indian users.",
                "severity": "low", "confidence": 65,
                "evidence": hindi_hits[:10], "related_iocs": [],
                "evidence_class": "contextual_anomaly", "risk_relevance": "contextual",
            })

        if ist_anomaly:
            findings.append({
                "finding_id": "india.timezone_anomaly",
                "category": "india_specific",
                "title": "IST Timezone Mismatch",
                "description": "Email claims Indian origin but Date header timezone is not IST (+0530).",
                "severity": "medium", "confidence": 75,
                "evidence": [f"Date header: {date_header}"], "related_iocs": [],
                "evidence_class": "contextual_anomaly", "risk_relevance": "contextual",
            })

        return {
            "impersonated_brands": impersonated,
            "scam_patterns": scam_hits,
            "hindi_keywords": hindi_hits,
            "ist_timezone_anomaly": ist_anomaly,
            "likely_causes": causes,
            "research_sources": _INDIA_RESEARCH_SOURCES if causes else [],
            "findings": findings,
        }


def _check_ist_anomaly(date_str: str) -> bool:
    """Returns True if date header exists but offset is NOT +0530."""
    try:
        # Check for +0530 or +05:30 in the raw header
        if "+0530" in date_str or "+05:30" in date_str:
            return False
        # If there's any timezone offset, it's not IST
        if re.search(r"[+-]\d{4}", date_str):
            return True
    except Exception:
        pass
    return False

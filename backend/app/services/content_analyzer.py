"""Phase 6H & Phase 8: Safe Content, NLP, and HTML Forensics Analysis.

Inspects text and HTML structurally without executing JavaScript, loading remote
resources, or submitting embedded forms.
"""

import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

_URGENCY_KEYWORDS = [
    "urgent", "immediate action", "act now", "critical update", "within 24 hours",
    "account suspended", "limited time", "verify now", "final notice",
    "immediate response required", "deadline", "suspended", "expire in 24 hours",
    "locked", "restriction", "action required",
]
_CREDENTIAL_KEYWORDS = [
    "password", "verify credentials", "login to continue", "reset password",
    "confirm identity", "security alert", "unauthorized access", "update security",
    "two-factor", "2fa code", "otp", "mfa", "confirm account", "security confirmation",
]
_FINANCIAL_KEYWORDS = [
    "invoice", "wire transfer", "payment overdue", "bank details", "remittance",
    "gift card", "direct deposit", "payroll", "purchase order", "beneficiary",
    "account change", "payment deadline", "routing number",
]
_AUTHORITY_KEYWORDS = [
    "ceo", "chief executive", "director", "human resources", "it department",
    "help desk", "administrator", "legal department", "executive", "president",
    "chief financial officer", "cfo", "head of department",
]
_SECRECY_KEYWORDS = [
    "strictly confidential", "keep this private", "do not call", "discrete",
    "handle this privately", "urgent and confidential",
]
_BIDI_CHARS = {"‮", "‭", "‬", "‎", "‏"}


class _HTMLDeceptionParser(HTMLParser):
    """Safely extracts potentially deceptive HTML; it never executes content."""

    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.password_inputs = 0
        self.iframes = 0
        self.javascript_references = 0
        self.hidden_tags: List[str] = []
        self.links: List[Tuple[str, str]] = []
        self.external_form_actions: List[str] = []
        self.external_resources: List[str] = []
        self.tracking_pixels = 0
        self._current_tag: Optional[str] = None
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []

    @staticmethod
    def _is_external(value: str) -> bool:
        return bool(urlparse(value).scheme in ("http", "https"))

    @staticmethod
    def _is_hidden(style: str, attrs: Dict[str, str]) -> bool:
        compact = style.replace(" ", "")
        return (
            "display:none" in compact
            or "visibility:hidden" in compact
            or "font-size:0" in compact
            or "opacity:0" in compact
            or "width:0" in compact
            or "height:0" in compact
            or attrs.get("hidden", "").lower() in ("", "hidden", "true") and "hidden" in attrs
        )

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        style = attr_dict.get("style", "").lower()

        if self._is_hidden(style, attr_dict):
            self.hidden_tags.append(tag_lower)

        if tag_lower == "form":
            self.forms += 1
            action = attr_dict.get("action", "")
            if self._is_external(action):
                self.external_form_actions.append(action)
        elif tag_lower in ("iframe", "object", "embed"):
            self.iframes += 1
        elif tag_lower == "input" and attr_dict.get("type", "").lower() == "password":
            self.password_inputs += 1

        if tag_lower in ("script", "noscript") or attr_dict.get("href", "").lower().startswith("javascript:"):
            self.javascript_references += 1

        resource_attr = "src" if tag_lower in ("img", "script", "iframe", "audio", "video", "source") else "href" if tag_lower in ("link",) else ""
        resource = attr_dict.get(resource_attr, "") if resource_attr else ""
        if self._is_external(resource):
            self.external_resources.append(resource)
            if tag_lower == "img":
                width = attr_dict.get("width", "").strip().lower()
                height = attr_dict.get("height", "").strip().lower()
                if width in ("1", "1px") and height in ("1", "1px"):
                    self.tracking_pixels += 1

        if tag_lower == "a":
            self._current_tag = "a"
            self._current_href = attr_dict.get("href", "")
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_tag == "a":
            self._current_text.append(data.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_tag == "a":
            visible_text = " ".join(self._current_text).strip()
            if self._current_href:
                self.links.append((self._current_href, visible_text))
            self._current_tag = None
            self._current_href = None
            self._current_text = []


class ContentAnalyzer:
    @staticmethod
    def analyze(email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform lexical, psychological, and safe structural HTML analysis."""
        plain_text = str(email_data.get("plain_text") or "")
        html_body = str(email_data.get("html_body") or "")
        subject = str(email_data.get("subject") or "")
        full_text = (subject + " " + plain_text + " " + html_body).lower()

        urgency_hits = [k for k in _URGENCY_KEYWORDS if k in full_text]
        credential_hits = [k for k in _CREDENTIAL_KEYWORDS if k in full_text]
        financial_hits = [k for k in _FINANCIAL_KEYWORDS if k in full_text]
        authority_hits = [k for k in _AUTHORITY_KEYWORDS if k in full_text]
        secrecy_hits = [k for k in _SECRECY_KEYWORDS if k in full_text]

        findings: List[Dict[str, Any]] = []
        html_indicators: List[str] = []
        html_forensics: Dict[str, Any] = {
            "hidden_elements": 0,
            "tracking_pixels": 0,
            "external_resources": 0,
            "link_text_mismatches": [],
            "external_form_actions": [],
            "iframes": 0,
            "javascript_references": 0,
            "bidi_controls": any(char in html_body for char in _BIDI_CHARS),
            "password_inputs": 0,
        }

        if html_body:
            parser = _HTMLDeceptionParser()
            try:
                parser.feed(html_body)
                parser.close()
            except Exception:
                pass

            html_forensics.update({
                "hidden_elements": len(parser.hidden_tags),
                "tracking_pixels": parser.tracking_pixels,
                "external_resources": len(parser.external_resources),
                "external_form_actions": parser.external_form_actions[:20],
                "iframes": parser.iframes,
                "javascript_references": parser.javascript_references,
                "password_inputs": parser.password_inputs,
            })

            if parser.forms:
                html_indicators.append("embedded_form")
            if parser.password_inputs:
                html_indicators.append("password_input")
            if parser.hidden_tags:
                html_indicators.append("hidden_elements")
            if parser.iframes:
                html_indicators.append("iframe_or_embedded_object")
            if parser.javascript_references:
                html_indicators.append("javascript_reference")
            if parser.external_form_actions:
                html_indicators.append("external_form_action")
            if html_forensics["bidi_controls"]:
                html_indicators.append("bidi_control_character")

            for href, text in parser.links:
                if re.match(r"^https?://", text, re.IGNORECASE) or ("." in text and " " not in text):
                    visible_text = text.strip().rstrip(".,;:!?)]}")
                    text_host = urlparse("http://" + visible_text if not visible_text.startswith("http") else visible_text).hostname
                    href_host = urlparse(href).hostname
                    has_domain_like_text = bool(text_host and "." in text_host and re.search(r"\.[a-z]{2,}$", text_host, re.IGNORECASE))
                    if has_domain_like_text and href_host and text_host.lower() != href_host.lower():
                        mismatch = {"visible_host": text_host, "destination_host": href_host, "href": href}
                        html_forensics["link_text_mismatches"].append(mismatch)
                        html_indicators.append("deceptive_hyperlink")

            if parser.password_inputs or parser.external_form_actions:
                findings.append({
                    "finding_id": "content.html.credential_collection",
                    "category": "content",
                    "title": "Potential Credential Collection Form",
                    "description": "Email HTML contains a password field or posts form data to an external destination.",
                    "severity": "high", "confidence": 95,
                    "evidence": [f"Password inputs: {parser.password_inputs}", f"External form actions: {len(parser.external_form_actions)}"],
                    "related_iocs": parser.external_form_actions[:10],
                    "evidence_class": "strong_risk_signal", "risk_relevance": "risk_contributing",
                })
            if html_forensics["link_text_mismatches"]:
                mismatch = html_forensics["link_text_mismatches"][0]
                findings.append({
                    "finding_id": "content.html.link_mismatch", "category": "content",
                    "title": "Deceptive Hyperlink Text vs Destination Mismatch",
                    "description": "Visible URL-like link text does not match its click destination.",
                    "severity": "high", "confidence": 98,
                    "evidence": [f"Visible host: {mismatch['visible_host']}", f"Destination host: {mismatch['destination_host']}"],
                    "related_iocs": [mismatch["destination_host"]],
                    "evidence_class": "strong_risk_signal", "risk_relevance": "risk_contributing",
                })
            if parser.hidden_tags:
                findings.append({
                    "finding_id": "content.html.hidden_text", "category": "content",
                    "title": "Hidden HTML Elements Detected",
                    "description": "Email HTML uses hiding techniques; this is an anomaly, not standalone proof of maliciousness.",
                    "severity": "medium", "confidence": 85,
                    "evidence": [f"Hidden element count: {len(parser.hidden_tags)}"], "related_iocs": [],
                    "evidence_class": "contextual_anomaly", "risk_relevance": "contextual",
                })

        is_bec = bool((authority_hits or secrecy_hits or urgency_hits) and financial_hits)
        if is_bec:
            evidence_bec = []
            if authority_hits:
                evidence_bec.append(f"Authority cues: {', '.join(authority_hits)}")
            if financial_hits:
                evidence_bec.append(f"Financial requests: {', '.join(financial_hits)}")
            if secrecy_hits:
                evidence_bec.append(f"Secrecy/Urgency: {', '.join(secrecy_hits)}")
            findings.append({
                "finding_id": "content.social_engineering.bec", "category": "content",
                "title": "Business Email Compromise (BEC) / Wire Fraud Patterns",
                "description": "Email combines executive authority, urgent/confidential pressure, and payment language.",
                "severity": "high", "confidence": 88, "evidence": evidence_bec, "related_iocs": [],
                "evidence_class": "strong_risk_signal", "risk_relevance": "risk_contributing",
            })

        if credential_hits:
            form_supported = "embedded_form" in html_indicators or "external_form_action" in html_indicators
            findings.append({
                "finding_id": "content.social_engineering.credential_harvesting", "category": "content",
                "title": "Credential Harvesting Cues Detected",
                "description": "Email contains credential-related language; it is contextual unless corroborated by structural deception.",
                "severity": "medium", "confidence": 80, "evidence": credential_hits, "related_iocs": [],
                "evidence_class": "strong_risk_signal" if (form_supported or urgency_hits) else "contextual_anomaly",
                "risk_relevance": "risk_contributing" if (form_supported or urgency_hits) else "contextual",
            })

        if urgency_hits and not is_bec:
            findings.append({
                "finding_id": "content.social_engineering.urgency", "category": "content",
                "title": "Urggency / Coercive Language", "description": "Email contains language intended to prompt a fast response.",
                "severity": "low", "confidence": 75, "evidence": urgency_hits, "related_iocs": [],
                "evidence_class": "contextual_anomaly", "risk_relevance": "contextual",
            })

        return {
            "urgency_keywords": urgency_hits, "credential_keywords": credential_hits,
            "financial_keywords": financial_hits, "authority_keywords": authority_hits,
            "secrecy_keywords": secrecy_hits, "is_bec_indicator": is_bec,
            "html_indicators": list(dict.fromkeys(html_indicators)), "html_forensics": html_forensics,
            "findings": findings,
        }

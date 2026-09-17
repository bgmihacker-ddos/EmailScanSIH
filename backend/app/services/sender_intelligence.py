"""
Phase 10: Sender Identity Intelligence Service.

Analyzes sender identity relationships, detects impersonation patterns,
and recognizes legitimate ESP infrastructure for false-positive reduction.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Known legitimate ESP bounce/feedback domains
_LEGITIMATE_ESP_PATTERNS: Dict[str, List[str]] = {
    "amazon_ses": ["amazonses.com", "bounce.amazonses.com", "mail.amazonses.com"],
    "sendgrid": ["sendgrid.net", "bounce.sendgrid.net", "mx.sendgrid.net"],
    "mailgun": ["mailgun.org", ["bounces", "mailgun"], "mg.mailgun.org"],
    "mailchimp": ["mcsv.net", "mailchimp.com", "mandrillapp.com"],
    "postmark": ["postmarkapp.com", "mail.postmarkapp.com"],
    "sparkpost": ["sparkpostmail.com", "sparkpost.com"],
    "zoho": ["zoho.com", "zohomail.com", "mail.zoho.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "microsoft": ["outlook.com", "office365.com", "microsoft.com", "hotmail.com"],
    "yahoo": ["yahoo.com", "ymail.com"],
}

# High-risk display name patterns
_SPOOFING_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "display_name_contains_email",
        "pattern": r"[\w\s\.-]*[<][^>]+@[^>]+[>]",  # "Name <email@domain>"
        "risk": "high",
        "description": "Display name contains embedded email address",
    },
    {
        "id": "trusted_brand_in_display",
        "patterns": [r"\bPayPal\b", r"\bApple\b", r"\bMicrosoft\b", r"\bGoogle\b",
                     r"\bAmazon\b", r"\bBank of America\b", r"\bChase\b",
                     r"\bWells Fargo\b", r"\bIRS\b", r"\bSocial Security\b"],
        "risk": "medium",
        "description": "Trusted brand name in display name",
    },
]


def _normalize_domain(domain: Optional[str]) -> Optional[str]:
    """Normalize domain for comparison."""
    if not domain:
        return None
    d = str(domain).strip().lower()
    d = re.sub(r"^\\.", "", d)  # Remove leading dots
    d = re.sub(r"\\.$", "", d)  # Remove trailing dots
    if not d or " " in d or "@" in d:
        return None
    return d


def _domain_matches_pattern(domain: str, pattern_list: List[str]) -> bool:
    """Check if domain matches any pattern in list."""
    if not domain:
        return False
    d = domain.lower()
    for pattern in pattern_list:
        if isinstance(pattern, str):
            if d == pattern or d.endswith("." + pattern):
                return True
        elif isinstance(pattern, list):
            # List pattern like ["bounces", "mailgun"] - check subdomain parts
            for part in pattern:
                if part in d:
                    return True
    return False


class SenderIntelligenceAnalyzer:
    """Analyze sender identity, detect impersonation, recognize legitimate ESP."""

    @staticmethod
    def analyze(
        addresses: Dict[str, Any],
        header_forensics: Dict[str, Any],
        authentication: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Perform comprehensive sender identity analysis."""
        findings: List[Dict[str, Any]] = []
        identity_relationships: Dict[str, Any] = {}

        # Extract domains from addresses
        from_domain = SenderIntelligenceAnalyzer._extract_domain(addresses.get("from"))
        reply_to_domain = SenderIntelligenceAnalyzer._extract_domain_from_list(
            addresses.get("reply_to", [])
        )
        return_path_domain = SenderIntelligenceAnalyzer._extract_domain(addresses.get("return_path"))
        sender_domain = SenderIntelligenceAnalyzer._extract_domain(addresses.get("sender"))

        # 1. Identity Relationship Analysis
        identity_relationships = SenderIntelligenceAnalyzer._analyze_relationships(
            from_domain, reply_to_domain, return_path_domain, sender_domain, findings
        )

        # 2. Display Name Analysis
        SenderIntelligenceAnalyzer._analyze_display_name(
            addresses.get("from"), from_domain, findings
        )

        # 3. ESP Recognition
        recognized_esp = SenderIntelligenceAnalyzer._recognize_esp(
            from_domain, return_path_domain, authentication
        )

        # 4. Identity Divergence Scoring
        divergence_score = SenderIntelligenceAnalyzer._calculate_divergence(
            from_domain, reply_to_domain, return_path_domain, sender_domain,
            identity_relationships, recognized_esp, findings
        )

        return {
            "findings": findings,
            "identity_relationships": identity_relationships,
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "sender_domain": sender_domain,
            "recognized_esp": recognized_esp,
            "divergence_score": divergence_score,
            "impersonation_risk": SenderIntelligenceAnalyzer._assess_impersonation_risk(findings),
        }

    @staticmethod
    def _extract_domain(address: Any) -> Optional[str]:
        """Extract domain from address structure."""
        if not address:
            return None
        if isinstance(address, dict):
            addr = address.get("address") or ""
            if "@" in addr:
                return _normalize_domain(addr.rsplit("@", 1)[1])
            return _normalize_domain(address.get("domain"))
        if isinstance(address, str) and "@" in address:
            return _normalize_domain(address.rsplit("@", 1)[1])
        return None

    @staticmethod
    def _extract_domain_from_list(address_list: Any) -> Optional[str]:
        """Extract domain from list of addresses."""
        if not address_list:
            return None
        if isinstance(address_list, list):
            for addr in address_list:
                domain = SenderIntelligenceAnalyzer._extract_domain(addr)
                if domain:
                    return domain
        return SenderIntelligenceAnalyzer._extract_domain(address_list)

    @staticmethod
    def _analyze_relationships(
        from_domain: Optional[str],
        reply_to_domain: Optional[str],
        return_path_domain: Optional[str],
        sender_domain: Optional[str],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Analyze relationships between sender identity fields."""
        relationships = {}
        all_domains = [d for d in [from_domain, reply_to_domain, return_path_domain, sender_domain] if d]

        # From -> Reply-To
        if from_domain and reply_to_domain:
            if from_domain == reply_to_domain:
                relationships["from_to_reply_to"] = "aligned"
            else:
                relationships["from_to_reply_to"] = "divergent"
                findings.append({
                    "finding_id": "identity.reply_to_divergence",
                    "category": "identity",
                    "title": "Reply-To Domain Different from From",
                    "description": f"Reply-To ({reply_to_domain}) routes to different domain than From ({from_domain}).",
                    "severity": "low",
                    "confidence": 85,
                    "evidence": [f"From: {from_domain}", f"Reply-To: {reply_to_domain}"],
                    "related_iocs": [from_domain, reply_to_domain],
                    "evidence_class": "contextual_anomaly",
                    "risk_relevance": "contextual",
                })
        else:
            relationships["from_to_reply_to"] = "unknown"

        # From -> Return-Path
        if from_domain and return_path_domain:
            if from_domain == return_path_domain:
                relationships["from_to_return_path"] = "aligned"
            else:
                relationships["from_to_return_path"] = "divergent"
                findings.append({
                    "finding_id": "identity.return_path_divergence",
                    "category": "identity",
                    "title": "Return-Path Domain Different from From",
                    "description": f"Return-Path ({return_path_domain}) differs from From domain ({from_domain}). Common for mailing lists.",
                    "severity": "info",
                    "confidence": 90,
                    "evidence": [f"From: {from_domain}", f"Return-Path: {return_path_domain}"],
                    "related_iocs": [from_domain, return_path_domain],
                    "evidence_class": "informational",
                    "risk_relevance": "informational",
                })
        else:
            relationships["from_to_return_path"] = "unknown"

        # From -> Sender
        if from_domain and sender_domain:
            relationships["from_to_sender"] = "aligned" if from_domain == sender_domain else "divergent"
        else:
            relationships["from_to_sender"] = "unknown"

        # Overall alignment score
        if all_domains:
            aligned_count = sum(
                1 for d in all_domains if d == from_domain
            )
            relationships["alignment_ratio"] = aligned_count / len(all_domains)
        else:
            relationships["alignment_ratio"] = None

        return relationships

    @staticmethod
    def _analyze_display_name(
        from_address: Any, from_domain: Optional[str], findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze display name for spoofing indicators."""
        if not from_address:
            return

        if isinstance(from_address, list) and from_address:
            from_address = from_address[0]
        if not isinstance(from_address, dict):
            return

        display_name = str(from_address.get("display_name") or "").strip()
        if not display_name:
            return

        # Check for embedded email in display name
        embedded_match = re.search(r"<([^>]+@[^>]+)>", display_name)
        if embedded_match:
            embedded_email = embedded_match.group(1)
            embedded_domain = _normalize_domain(embedded_email.split("@")[1]) if "@" in embedded_email else None
            if embedded_domain and from_domain and embedded_domain != from_domain:
                findings.append({
                    "finding_id": "identity.display_name_email_spoof",
                    "category": "identity",
                    "title": "Display Name Contains Conflicting Email",
                    "description": f"Display name '{display_name}' embeds email at '{embedded_domain}' while From domain is '{from_domain}'.",
                    "severity": "high",
                    "confidence": 95,
                    "evidence": [f"Display Name: {display_name}", f"From Domain: {from_domain}"],
                    "related_iocs": [from_domain, embedded_domain],
                    "evidence_class": "strong_risk_signal",
                    "risk_relevance": "risk_contributing",
                })

        # Check for trusted brand impersonation
        for pattern_info in _SPOOFING_PATTERNS:
            if pattern_info["id"] != "trusted_brand_in_display":
                continue
            for pattern in pattern_info["patterns"]:
                if re.search(pattern, display_name, re.IGNORECASE):
                    findings.append({
                        "finding_id": "identity.brand_imitation",
                        "category": "identity",
                        "title": f"Trusted Brand Reference in Display Name",
                        "description": f"Display name references '{pattern.replace(chr(92), '')}' which may indicate impersonation.",
                        "severity": pattern_info["risk"],
                        "confidence": 70,
                        "evidence": [f"Display Name: {display_name}"],
                        "related_iocs": [from_domain] if from_domain else [],
                        "evidence_class": "contextual_anomaly",
                        "risk_relevance": "contextual",
                    })
                    break

    @staticmethod
    def _recognize_esp(
        from_domain: Optional[str],
        return_path_domain: Optional[str],
        authentication: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Recognize legitimate ESP infrastructure."""
        recognized: Dict[str, Any] = {
            "is_legitimate_esp": False,
            "esp_name": None,
            "esp_confidence": 0,
            "details": [],
        }

        candidates: Set[str] = set()
        if from_domain:
            candidates.add(from_domain)
        if return_path_domain:
            candidates.add(return_path_domain)

        # Check Authentication-Results for ESP signatures
        auth_headers = authentication.get("headers", {}) if isinstance(authentication, dict) else {}
        if isinstance(auth_headers, dict):
            auth_results = str(auth_headers.get("authentication-results", "")).lower()
            for esp, patterns in _LEGITIMATE_ESP_PATTERNS.items():
                for pattern in patterns:
                    if isinstance(pattern, str) and pattern in auth_results:
                        recognized["is_legitimate_esp"] = True
                        recognized["esp_name"] = esp
                        recognized["esp_confidence"] = 95
                        recognized["details"].append(f"Found '{pattern}' in Authentication-Results")
                        break

        # Check domains against known ESP patterns
        for esp, patterns in _LEGITIMATE_ESP_PATTERNS.items():
            if recognized["esp_name"]:
                break
            for candidate in candidates:
                if _domain_matches_pattern(candidate, patterns):
                    recognized["is_legitimate_esp"] = True
                    recognized["esp_name"] = esp
                    recognized["esp_confidence"] = 80
                    recognized["details"].append(f"Domain '{candidate}' matches {esp} patterns")
                    break

        return recognized

    @staticmethod
    def _calculate_divergence(
        from_domain: Optional[str],
        reply_to_domain: Optional[str],
        return_path_domain: Optional[str],
        sender_domain: Optional[str],
        relationships: Dict[str, Any],
        esp_recognition: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Calculate identity divergence score."""
        # High divergence score = more suspicious
        divergence_factors = []

        if relationships.get("from_to_reply_to") == "divergent":
            divergence_factors.append(("reply_to_divergence", 15))
        if relationships.get("from_to_return_path") == "divergent":
            # Return-path divergence is less suspicious for ESP
            if not esp_recognition.get("is_legitimate_esp"):
                divergence_factors.append(("return_path_divergence", 10))

        # Check for display name spoofing findings
        spoofing_findings = [f for f in findings if "spoof" in f.get("finding_id", "").lower()]
        for _ in spoofing_findings:
            divergence_factors.append(("display_name_spoof", 25))

        # Check for brand impersonation
        brand_findings = [f for f in findings if "brand" in f.get("finding_id", "").lower()]
        for _ in brand_findings:
            divergence_factors.append(("brand_imitation", 20))

        total_divergence = sum(score for _, score in divergence_factors)

        return {
            "score": min(100, total_divergence),
            "factors": dict(divergence_factors),
            "is_suspicious": total_divergence >= 25,
            "requires_verification": total_divergence >= 40,
        }

    @staticmethod
    def _assess_impersonation_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall impersonation risk level."""
        high_risk_count = sum(1 for f in findings if f.get("severity") == "high" and
                            f.get("evidence_class") == "strong_risk_signal")
        medium_risk_count = sum(1 for f in findings if f.get("severity") == "medium")

        if high_risk_count >= 2:
            risk_level = "critical"
        elif high_risk_count >= 1:
            risk_level = "high"
        elif medium_risk_count >= 2:
            risk_level = "medium"
        elif medium_risk_count >= 1:
            risk_level = "low"
        else:
            risk_level = "minimal"

        return {
            "level": risk_level,
            "high_risk_signals": high_risk_count,
            "medium_risk_signals": medium_risk_count,
            "requires_manual_review": risk_level in ("high", "critical"),
        }
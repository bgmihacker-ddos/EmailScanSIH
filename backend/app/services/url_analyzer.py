"""Phase 6E: URL Intelligence — offline URL analysis and enrichment."""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, unquote
import unicodedata

import ipaddress

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "short.link", "rb.gy", "cutt.ly", "tiny.cc", "rebrand.ly",
}

_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "club",
    "work", "click", "link", "info", "online", "site", "icu", "zip"
}

_CREDENTIAL_KEYWORDS = {
    "login", "signin", "verify", "account", "password", "secure",
    "authentication", "wallet", "banking", "reset", "recovery",
    "auth", "confirm", "update", "credential", "mfa", "otp",
}

_KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "wells", "bankofamerica", "citi", "yahoo", "facebook",
    "instagram", "linkedin", "dropbox", "docusign", "adobe",
    "github", "slack", "stripe", "coinbase", "binance", "metamask",
]

_SUSPICIOUS_PORTS = {21, 22, 23, 25, 3389, 8080, 8443, 6667}

def _get_org_domain(host: str) -> str:
    """Extract registrable domain (best effort)."""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


class URLIntelligence:
    @staticmethod
    def analyze(url: str) -> Dict[str, Any]:
        """Analyze a single URL for suspicious characteristics deterministically."""
        result: Dict[str, Any] = {
            "url": url,
            "normalized": url.strip().rstrip("/"),
            "scheme": None,
            "hostname": None,
            "port": None,
            "path": None,
            "query": None,
            "fragment": None,
            "registrable_domain": None,
            "indicators": [],
            "risk_indicators": 0,
            "findings": [],
        }

        try:
            parsed = urlparse(url)
        except Exception:
            result["indicators"].append("malformed_url")
            result["risk_indicators"] = 1
            result["findings"].append(URLIntelligence._finding(
                "url.malformed",
                "malformed_url",
                "Malformed URL Structure",
                "The URL structure could not be parsed by standard libraries, which may indicate deliberate malformation designed to break parsers.",
                "low",
                100,
                [url],
                "contextual_anomaly"
            ))
            return result

        result["scheme"] = parsed.scheme.lower() if parsed.scheme else None
        host = (parsed.hostname or "").lower()
        result["hostname"] = host
        result["port"] = parsed.port
        result["path"] = parsed.path
        result["query"] = parsed.query or None
        result["fragment"] = parsed.fragment or None

        # Basic Protocol checks
        if result["scheme"] == "http":
            result["indicators"].append("insecure_protocol")

        # IP-hosted URL vs Domain
        is_ip = False
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
            result["indicators"].append("ip_hosted_url")
            result["findings"].append(URLIntelligence._finding(
                "url.ip_hosted",
                "suspicious_host",
                "URL Hosted on IP Address",
                "The URL uses a raw IP address instead of a domain name. Legitimate services rarely do this in emails.",
                "medium",
                95,
                [host],
                "strong_risk_signal"
            ))
        except ValueError:
            pass

        # Credential in URL
        if parsed.username or parsed.password or ("@" in (parsed.netloc or "") and not is_ip):
            result["indicators"].append("credential_url")
            result["findings"].append(URLIntelligence._finding(
                "url.credential_embedded",
                "credential_harvesting",
                "Credentials Embedded in URL",
                "The URL contains embedded username/password structures (e.g. user:pass@host), a common trick to obfuscate the true destination.",
                "high",
                100,
                [parsed.netloc],
                "strong_risk_signal"
            ))

        # Port and encoding anomalies
        if result["port"] in _SUSPICIOUS_PORTS:
            result["indicators"].append("suspicious_port")

        # Check excessive URL encoding
        unquoted = unquote(url)
        if len(url) - len(unquoted) > 10:
            result["indicators"].append("excessive_encoding")

        if not is_ip and host:
            # Punycode / IDNA spoofing
            if host.startswith("xn--") or ".xn--" in host:
                result["indicators"].append("punycode_domain")
                # Attempt to decode punycode to find homoglyphs
                decoded_host = host
                try:
                    decoded_host = host.encode('ascii').decode('idna')
                except Exception:
                    pass
                
                result["findings"].append(URLIntelligence._finding(
                    "url.punycode",
                    "domain_impersonation",
                    "Punycode/IDNA Domain Detected",
                    f"The URL uses internationalized domain encoding (Punycode). Decoded: {decoded_host}",
                    "medium",
                    90,
                    [host, decoded_host],
                    "strong_risk_signal"
                ))

            # Unicode Homoglyph check
            # Look for non-ASCII characters that might be confusingly similar
            unquoted_host = unquote(host)
            normalized_host = unicodedata.normalize('NFKC', unquoted_host)
            is_homoglyph_likely = any(ord(c) > 127 for c in unquoted_host)
            if is_homoglyph_likely:
                result["indicators"].append("unicode_homoglyph")
                result["findings"].append(URLIntelligence._finding(
                    "url.unicode_homoglyph",
                    "domain_impersonation",
                    "Unicode Homoglyph / Confusable Characters Detected",
                    f"The URL contains Unicode characters that may be visually confusing. Normalized: {normalized_host}",
                    "high",
                    95,
                    [unquoted_host, normalized_host],
                    "strong_risk_signal"
                ))

            # URL Shortener
            org_domain = _get_org_domain(host)
            result["registrable_domain"] = org_domain

            if org_domain in _SHORTENERS:
                result["indicators"].append("url_shortener")
                result["findings"].append(URLIntelligence._finding(
                    "url.shortener",
                    "obfuscation",
                    "URL Shortener Used",
                    "A URL shortener service obscures the true destination of the link.",
                    "low",
                    90,
                    [host],
                    "contextual_anomaly"
                ))

            # Suspicious TLD
            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            if tld in _SUSPICIOUS_TLDS:
                result["indicators"].append("suspicious_tld")
                result["findings"].append(URLIntelligence._finding(
                    "url.suspicious_tld",
                    "suspicious_host",
                    "Suspicious Top-Level Domain",
                    f"The TLD '.{tld}' is frequently associated with disposable or malicious infrastructure.",
                    "low",
                    85,
                    [tld],
                    "contextual_anomaly"
                ))

            # Excessive subdomains
            if host.count(".") >= 4:
                result["indicators"].append("excessive_subdomains")

            # Brand Tokens (Typosquatting/Subdomain trickery)
            detected_brands = []
            for brand in _KNOWN_BRANDS:
                if brand in host and brand not in org_domain:
                    detected_brands.append(brand)
            if detected_brands:
                result["indicators"].append("brand_impersonation")
                result["findings"].append(URLIntelligence._finding(
                    "url.brand_impersonation",
                    "domain_impersonation",
                    "Brand Name Abuse in Subdomain",
                    f"The URL contains trusted brand names ({', '.join(detected_brands)}) in a subdomain, but the actual destination domain ({org_domain}) does not own the brand.",
                    "high",
                    95,
                    [host],
                    "strong_risk_signal"
                ))

        # Content/Path Credential Harvesting check
        path_query_lower = f"{result['path'] or ''} {result['query'] or ''}".lower()
        found_cred_kws = [kw for kw in _CREDENTIAL_KEYWORDS if kw in path_query_lower]
        if found_cred_kws:
            result["indicators"].append("credential_keywords_in_url")
            result["findings"].append(URLIntelligence._finding(
                "url.credential_keywords",
                "credential_harvesting",
                "Credential & Security Keywords in URL Path",
                "The URL path or query parameters contain terms commonly used in phishing login pages to mimic security or authentication flows.",
                "low",
                80,
                found_cred_kws,
                "contextual_anomaly"
            ))

        result["risk_indicators"] = len(result["indicators"])
        return result

    @staticmethod
    def _finding(
        finding_id: str,
        category: str,
        title: str,
        description: str,
        severity: str,
        confidence: int,
        evidence: List[str],
        evidence_class: str
    ) -> Dict[str, Any]:
        return {
            "finding_id": finding_id,
            "category": category,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "evidence_class": evidence_class,
            "risk_relevance": "risk_contributing" if evidence_class == "strong_risk_signal" else "contextual"
        }

    @classmethod
    def analyze_batch(cls, urls: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Analyze a batch of URLs without crashing on empty or bound-call usage."""
        if not urls:
            return []
        return [cls.analyze(url) for url in urls]

"""Phase 6E: Domain Intelligence — lexical and offline domain analysis."""

import math
from typing import Any, Dict, List

# This analyzer is intentionally offline. DNS enrichment belongs to the
# credential-gated threat-intelligence pipeline, not deterministic lexical analysis.
DNS_AVAILABLE = False


_SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking",
    "signin", "support", "service", "auth", "confirm", "security"
]

_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "club",
    "work", "click", "link", "info", "online", "site", "icu", "zip"
}

_KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "wells", "bankofamerica", "citi", "yahoo", "facebook",
    "instagram", "linkedin", "dropbox", "docusign", "adobe",
    "github", "slack", "stripe", "coinbase", "binance", "metamask",
]


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def _get_org_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


class DomainIntelligence:
    @staticmethod
    def analyze(domain: str) -> Dict[str, Any]:
        """Analyze a domain name lexically and query optional DNS records safely."""
        domain_clean = domain.strip().lower().strip(".<>[]()\"'")
        parts = domain_clean.split(".") if domain_clean else []
        tld = parts[-1] if len(parts) > 1 else ""
        org_domain = _get_org_domain(domain_clean)
        subdomains = parts[:-2] if len(parts) > 2 else []

        entropy = _shannon_entropy(domain_clean)

        result: Dict[str, Any] = {
            "domain": domain_clean,
            "registrable_domain": org_domain,
            "tld": tld,
            "length": len(domain_clean),
            "subdomain_count": len(subdomains),
            "punycode": domain_clean.startswith("xn--") or ".xn--" in domain_clean,
            "entropy": round(entropy, 2),
            "suspicious_keywords_found": [],
            "brand_impersonation_detected": False,
            "findings": [],
            "dns": {
                "available": DNS_AVAILABLE,
                "a": [],
                "mx": [],
                "txt": [],
            }
        }

        # Check suspicious keywords
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in domain_clean:
                result["suspicious_keywords_found"].append(kw)

        if result["suspicious_keywords_found"]:
            result["findings"].append({
                "finding_id": "domain.keywords.security",
                "category": "domain",
                "title": "Security-Themed Keyword in Domain",
                "description": f"Domain contains security or authentication terms ({', '.join(result['suspicious_keywords_found'])}) commonly seen in phishing destinations.",
                "severity": "low",
                "confidence": 80,
                "evidence": result["suspicious_keywords_found"],
                "evidence_class": "contextual_anomaly",
                "risk_relevance": "contextual"
            })

        # Punycode / Homoglyph check
        if result["punycode"]:
            result["findings"].append({
                "finding_id": "domain.punycode",
                "category": "domain",
                "title": "Internationalized / Punycode Domain",
                "description": "Domain utilizes Punycode (IDNA) encoding, often employed in homograph spoofing attacks.",
                "severity": "medium",
                "confidence": 90,
                "evidence": [domain_clean],
                "evidence_class": "strong_risk_signal",
                "risk_relevance": "risk_contributing"
            })

        # High entropy (DGA / random string indicator)
        if entropy > 3.8 and len(domain_clean) > 15:
            result["findings"].append({
                "finding_id": "domain.high_entropy",
                "category": "domain",
                "title": "High Entropy / Randomized Domain Name",
                "description": f"Domain has high character entropy ({round(entropy, 2)}), suggesting algorithmically generated (DGA) or disposable registration.",
                "severity": "low",
                "confidence": 80,
                "evidence": [f"Entropy: {round(entropy, 2)}", domain_clean],
                "evidence_class": "contextual_anomaly",
                "risk_relevance": "contextual"
            })

        # Suspicious TLD
        if tld in _SUSPICIOUS_TLDS:
            result["findings"].append({
                "finding_id": "domain.suspicious_tld",
                "category": "domain",
                "title": "High-Risk Top Level Domain",
                "description": f"The top-level domain '.{tld}' is disproportionately abused for spam and short-lived phishing campaigns.",
                "severity": "low",
                "confidence": 85,
                "evidence": [tld],
                "evidence_class": "contextual_anomaly",
                "risk_relevance": "contextual"
            })

        # Brand impersonation in subdomains (e.g. paypal.com.attacker.com)
        impersonated_brands = []
        for brand in _KNOWN_BRANDS:
            if brand in domain_clean and brand not in org_domain:
                impersonated_brands.append(brand)
        if impersonated_brands:
            result["brand_impersonation_detected"] = True
            result["findings"].append({
                "finding_id": "domain.brand_impersonation",
                "category": "domain",
                "title": "Suspected Brand Domain Impersonation",
                "description": f"Domain uses brand name ({', '.join(impersonated_brands)}) in its subdomain structure, but the registered domain is '{org_domain}'.",
                "severity": "high",
                "confidence": 95,
                "evidence": [domain_clean, f"Target brand: {', '.join(impersonated_brands)}"],
                "evidence_class": "strong_risk_signal",
                "risk_relevance": "risk_contributing"
            })

        # Homoglyphs and Typosquatting (Levenshtein distance)
        org_base = org_domain.split(".")[0] if "." in org_domain else org_domain
        if org_base not in _KNOWN_BRANDS:
            # Check for close matches against known brands (edit distance 1 or 2 depending on length)
            for brand in _KNOWN_BRANDS:
                if len(brand) < 4:
                    continue
                dist = _levenshtein_distance(org_base, brand)
                threshold = 1 if len(brand) <= 6 else 2
                if 0 < dist <= threshold:
                    result["brand_impersonation_detected"] = True
                    result["findings"].append({
                        "finding_id": "domain.typosquatting",
                        "category": "domain",
                        "title": "Suspected Typosquatting / Homoglyph",
                        "description": f"The domain '{org_base}' is visually or structurally very similar to trusted brand '{brand}' (edit distance {dist}).",
                        "severity": "high",
                        "confidence": 90,
                        "evidence": [domain_clean, f"Target brand: {brand}", f"Edit distance: {dist}"],
                        "evidence_class": "strong_risk_signal",
                        "risk_relevance": "risk_contributing"
                    })
                    break

        # Optional DNS resolution if available
        if DNS_AVAILABLE and domain_clean:
            try:
                answers = dns.resolver.resolve(domain_clean, 'A', lifetime=1.5)
                result["dns"]["a"] = [r.address for r in answers]
            except Exception:
                pass

            try:
                answers = dns.resolver.resolve(domain_clean, 'MX', lifetime=1.5)
                result["dns"]["mx"] = [str(r.exchange) for r in answers]
            except Exception:
                pass

            try:
                answers = dns.resolver.resolve(domain_clean, 'TXT', lifetime=1.5)
                result["dns"]["txt"] = [b"".join(r.strings).decode("utf-8") for r in answers]
            except Exception:
                pass

        return result

"""Brand impersonation detection via Levenshtein distance, homoglyph
normalization, punycode/IDN decoding, and subdomain abuse detection.

Pure-stdlib implementation — no external dependencies.
"""

from __future__ import annotations

import encodings.idna  # noqa: F401 — stdlib punycode codec
import re
from typing import Any, Dict, List

# ── Protected domains (top 30 Indian + global brands) ──────────────────────
PROTECTED_INDIAN_DOMAINS: list[str] = [
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "paytm.com", "phonepe.com", "googlepay.com",
    "uidai.gov.in", "incometax.gov.in", "rbi.org.in", "irctc.co.in",
    "amazon.in", "flipkart.com", "infosys.com", "tcs.com", "wipro.com",
    "paypal.com", "microsoft.com", "apple.com", "google.com",
    "facebook.com", "linkedin.com", "netflix.com", "amazon.com",
    "dhl.com", "fedex.com", "ups.com", "wellsfargo.com", "chase.com",
]

# ── Homoglyph map (Cyrillic, Greek, other Unicode → Latin) ─────────────────
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s",
    # Greek
    "α": "a", "ε": "e", "ο": "o",
    # Other visually-similar
    "ℓ": "l",  # ℓ
    "ⅰ": "i",  # ⅰ
    "Ο": "O",  # Greek capital omicron
}

_HOMOGLYPH_RE = re.compile("|".join(re.escape(ch) for ch in HOMOGLYPH_MAP))

# Pre-compute hyphenated forms of protected domains for brand-squatting detection
_PROTECTED_HYPHENATED = {d.replace(".", "-"): d for d in PROTECTED_INDIAN_DOMAINS}
# Also extract short brand names (first label) for substring matching
_PROTECTED_BRANDS = {d.split(".")[0]: d for d in PROTECTED_INDIAN_DOMAINS if len(d.split(".")[0]) >= 3}


def _normalize_homoglyphs(domain: str) -> str:
    """Replace known homoglyph characters with their Latin equivalents."""
    return _HOMOGLYPH_RE.sub(lambda m: HOMOGLYPH_MAP[m.group()], domain)


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between *a* and *b* (DP, O(mn))."""
    n, m = len(a), len(b)
    if n == 0:
        return m
    if m == 0:
        return n
    # Single-row DP
    prev = list(range(m + 1))
    for i in range(1, n + 1):
        curr = [i] + [0] * m
        for j in range(1, m + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[m]


def _decode_punycode(domain: str) -> str | None:
    """Attempt to decode a punycode (xn--) domain. Returns None on failure."""
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return None


class ImpersonationAnalyzer:
    """Detect brand impersonation via domain similarity analysis."""

    @staticmethod
    def analyze(sender_domain: str, url_domains: list[str]) -> dict:
        """Analyze sender and URL domains for impersonation signals.

        Returns a dict with ``lookalike_findings``, ``impersonation_detected``,
        ``max_severity``, and ``summary``.
        """
        findings: List[Dict[str, Any]] = []
        all_domains = [sender_domain] + (url_domains or [])

        for raw_domain in all_domains:
            if not raw_domain:
                continue
            domain = raw_domain.lower().strip()

            # ── 1c. Punycode / IDN detection ───────────────────────────
            decoded_domain: str | None = None
            if domain.startswith("xn--") or ".xn--" in domain:
                findings.append({
                    "type": "punycode_domain",
                    "observed_domain": raw_domain,
                    "protected_domain": "",
                    "distance": 0,
                    "severity": "high",
                    "confidence": 80,
                    "description": f"Domain uses punycode/IDN encoding: {raw_domain}",
                })
                decoded_domain = _decode_punycode(domain)

            # ── 1b. Homoglyph normalization ────────────────────────────
            normalized = _normalize_homoglyphs(domain)

            # ── 1d. Subdomain abuse detection ──────────────────────────
            for protected in PROTECTED_INDIAN_DOMAINS:
                if domain != protected and domain.startswith(protected + "."):
                    # e.g. sbi.co.in.phisher.com — protected is a prefix
                    findings.append({
                        "type": "subdomain_abuse",
                        "observed_domain": raw_domain,
                        "protected_domain": protected,
                        "distance": 0,
                        "severity": "critical",
                        "confidence": 95,
                        "description": (
                            f"Protected domain '{protected}' used as subdomain "
                            f"prefix in '{raw_domain}'"
                        ),
                    })

            # ── 1d-ext. Hyphenated brand-squatting ────────────────────
            #   e.g. sbi-co-in-update.net  contains "sbi-co-in" ≡ "sbi.co.in"
            domain_base = domain.rsplit(".", 1)[0] if "." in domain else domain
            for hyp, protected in _PROTECTED_HYPHENATED.items():
                if hyp in domain_base and domain != protected:
                    findings.append({
                        "type": "levenshtein_lookalike",
                        "observed_domain": raw_domain,
                        "protected_domain": protected,
                        "distance": 1,
                        "severity": "critical",
                        "confidence": 90,
                        "description": (
                            f"Domain '{raw_domain}' embeds hyphenated form of "
                            f"protected domain '{protected}'"
                        ),
                    })
            # Brand-name substring in domain (e.g. "sbi-kyc-verify.net" contains "sbi")
            for brand, protected in _PROTECTED_BRANDS.items():
                is_trusted_subdomain = domain.endswith("." + protected)
                if brand in domain_base and domain != protected and not is_trusted_subdomain:
                    # Only flag if the brand name is a distinct segment
                    segments = re.split(r"[-.]", domain_base)
                    if brand in segments:
                        dist = _levenshtein(domain, protected)
                        if dist > 2:  # not already caught by Levenshtein
                            findings.append({
                                "type": "levenshtein_lookalike",
                                "observed_domain": raw_domain,
                                "protected_domain": protected,
                                "distance": dist,
                                "severity": "high",
                                "confidence": 70,
                                "description": (
                                    f"Domain '{raw_domain}' contains brand name "
                                    f"'{brand}' from protected domain '{protected}'"
                                ),
                            })

            # ── 1b + 1a. Homoglyph then Levenshtein ───────────────────
            variants = [normalized]
            if decoded_domain:
                variants.append(_normalize_homoglyphs(decoded_domain.lower()))

            for variant in variants:
                # Exact homoglyph spoof (normalizes to protected but raw differs)
                for protected in PROTECTED_INDIAN_DOMAINS:
                    if variant == protected and domain != protected:
                        findings.append({
                            "type": "homoglyph_spoof",
                            "observed_domain": raw_domain,
                            "protected_domain": protected,
                            "distance": 0,
                            "severity": "critical",
                            "confidence": 98,
                            "description": (
                                f"Domain '{raw_domain}' uses homoglyph characters "
                                f"to impersonate '{protected}'"
                            ),
                        })

                # Levenshtein lookalike (distance 1-2, not exact match)
                for protected in PROTECTED_INDIAN_DOMAINS:
                    if variant == protected:
                        continue  # exact match → not a lookalike
                    dist = _levenshtein(variant, protected)
                    if dist <= 2:
                        severity = "critical" if dist == 1 else "high"
                        findings.append({
                            "type": "levenshtein_lookalike",
                            "observed_domain": raw_domain,
                            "protected_domain": protected,
                            "distance": dist,
                            "severity": severity,
                            "confidence": 95 if dist == 1 else 85,
                            "description": (
                                f"Domain '{raw_domain}' is {dist} edit(s) away "
                                f"from protected domain '{protected}'"
                            ),
                        })

        # ── Deduplicate findings by (type, observed, protected) ────────
        seen: set[tuple[str, str, str]] = set()
        unique: List[Dict[str, Any]] = []
        for f in findings:
            key = (f["type"], f["observed_domain"], f["protected_domain"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        findings = unique

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = max(
            (f["severity"] for f in findings),
            key=lambda s: severity_order.get(s, 0),
            default="info",
        )
        detected = len(findings) > 0

        summary_parts = []
        if detected:
            summary_parts.append(
                f"{len(findings)} impersonation signal(s) detected "
                f"(max severity: {max_severity})"
            )
            types_found = sorted({f["type"] for f in findings})
            summary_parts.append(f"Types: {', '.join(types_found)}")
        else:
            summary_parts.append("No impersonation signals detected")

        return {
            "lookalike_findings": findings,
            "impersonation_detected": detected,
            "max_severity": max_severity,
            "summary": ". ".join(summary_parts),
        }

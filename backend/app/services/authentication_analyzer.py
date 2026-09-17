"""Phase 6C: Authentication Analysis Engine."""

import logging
import re
from typing import Any, Dict, List, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

logger = logging.getLogger(__name__)


def _get_org_domain(domain: Optional[str]) -> Optional[str]:
    """Extract organizational domain (last two labels) safely."""
    if not domain:
        return None
    cleaned = domain.strip().lower().strip(".<>[]()\"'")
    parts = cleaned.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return cleaned


class AuthenticationAnalyzer:
    @staticmethod
    def analyze(header_forensics: Dict[str, Any], email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize authentication evidence, calculate SPF/DKIM alignment, and produce an auth matrix."""

        result: Dict[str, Any] = {
            "spf": {"status": "missing", "verified": False, "details": {}},
            "dkim": {"status": "missing", "verified": False, "details": {}, "signatures": []},
            "dmarc": {"status": "missing", "verified": False, "details": {}},
            "arc": {"status": "missing", "verified": False, "details": {}},
            "alignment": {
                "spf_aligned": False,
                "dkim_aligned": False,
                "dmarc_pass": False,
                "alignment_type": "none",
            },
            "auth_matrix": {},
            "findings": [],
        }

        auth_evidence = header_forensics.get("authentication_evidence", {})
        domains = header_forensics.get("domain_relationships", {})

        from_domain = domains.get("from_domain")
        from_org = _get_org_domain(from_domain)
        return_path_domain = domains.get("return_path_domain")
        return_path_org = _get_org_domain(return_path_domain)

        # 1. Seed from reported header evidence
        AuthenticationAnalyzer._extract_reported(result, auth_evidence)

        # 2. Extract DKIM signature details from headers
        AuthenticationAnalyzer._extract_dkim_signatures(result, email_data, from_domain, from_org)

        # 3. Extract ARC details
        AuthenticationAnalyzer._extract_arc(result, email_data)

        # 4. Compute SPF alignment
        spf_status = result["spf"]["status"].lower() if result["spf"].get("status") else "missing"
        spf_aligned = False
        if spf_status == "pass" and from_org:
            eval_domain = result["spf"]["details"].get("domain") or return_path_domain
            eval_org = _get_org_domain(eval_domain)
            if eval_org and eval_org == from_org:
                spf_aligned = True

        # 5. Compute DKIM alignment
        dkim_status = result["dkim"]["status"].lower() if result["dkim"].get("status") else "missing"
        dkim_aligned = False
        for sig in result["dkim"]["signatures"]:
            sig_domain = sig.get("domain")
            sig_org = _get_org_domain(sig_domain)
            if sig_org and from_org and sig_org == from_org:
                sig["aligned"] = True
                if dkim_status == "pass":
                    dkim_aligned = True
            else:
                sig["aligned"] = False

        # 6. Evaluate DMARC alignment & pass
        dmarc_pass = (spf_status == "pass" and spf_aligned) or (dkim_status == "pass" and dkim_aligned)
        alignment_type = "strict" if (spf_aligned and dkim_aligned) else ("relaxed" if (spf_aligned or dkim_aligned) else "none")

        result["alignment"] = {
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "dmarc_pass": dmarc_pass,
            "alignment_type": alignment_type,
            "from_domain": from_domain,
        }

        # 7. Attempt safe DNS-based policy verification if DNS is available
        if DNS_AVAILABLE and from_domain:
            AuthenticationAnalyzer._verify_spf(result, from_domain)
            AuthenticationAnalyzer._verify_dmarc(result, from_domain)

        # 8. Build structured Authentication Matrix
        AuthenticationAnalyzer._build_auth_matrix(result)

        # 9. Generate forensic findings with clear evidence classification
        AuthenticationAnalyzer._generate_findings(result, from_domain)

        return result

    @staticmethod
    def _extract_reported(result: Dict[str, Any], auth_evidence: Dict[str, Any]):
        for mech in ["spf", "dkim", "dmarc", "arc"]:
            reported = auth_evidence.get(mech, {})
            if reported and reported.get("available"):
                status = reported.get("status")
                if status:
                    result[mech]["status"] = status
                result[mech]["details"]["reported_sources"] = reported.get("sources", [])
                result[mech]["details"]["reported_headers"] = reported.get("reported_by_header", [])

    @staticmethod
    def _fetch_txt(domain: str, prefix: str) -> Optional[str]:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=2.0)
            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8")
                if txt.lower().startswith(prefix.lower()):
                    return txt
        except Exception:
            pass
        return None

    @staticmethod
    def _verify_spf(result: Dict[str, Any], domain: str):
        record = AuthenticationAnalyzer._fetch_txt(domain, "v=spf1")
        if record:
            result["spf"]["details"]["record"] = record
            result["spf"]["details"]["domain"] = domain
            result["spf"]["verified"] = True

            policy = "neutral"
            if "-all" in record:
                policy = "hardfail"
            elif "~all" in record:
                policy = "softfail"
            elif "+all" in record:
                policy = "pass_all"
            result["spf"]["details"]["policy"] = policy

    @staticmethod
    def _verify_dmarc(result: Dict[str, Any], domain: str):
        dmarc_domain = f"_dmarc.{domain}"
        record = AuthenticationAnalyzer._fetch_txt(dmarc_domain, "v=DMARC1")
        if record:
            result["dmarc"]["details"]["record"] = record
            result["dmarc"]["details"]["domain"] = domain
            result["dmarc"]["verified"] = True

            parts = [p.strip() for p in record.split(";")]
            policy = "none"
            for p in parts:
                if p.startswith("p="):
                    policy = p.split("=")[1].lower()
            result["dmarc"]["details"]["policy"] = policy

    @staticmethod
    def _extract_dkim_signatures(
        result: Dict[str, Any],
        email_data: Dict[str, Any],
        from_domain: Optional[str],
        from_org: Optional[str],
    ):
        headers = email_data.get("headers", {}) if isinstance(email_data.get("headers"), dict) else {}
        dkim_headers = headers.get("dkim-signature", [])
        if isinstance(dkim_headers, str):
            dkim_headers = [dkim_headers]

        for dkim in dkim_headers:
            sig = {"domain": None, "selector": None, "algorithm": None, "aligned": False}
            d_match = re.search(r"\bd=([^;\s]+)", dkim)
            s_match = re.search(r"\bs=([^;\s]+)", dkim)
            a_match = re.search(r"\ba=([^;\s]+)", dkim)

            if d_match:
                sig["domain"] = d_match.group(1).lower()
            if s_match:
                sig["selector"] = s_match.group(1)
            if a_match:
                sig["algorithm"] = a_match.group(1)

            if sig["domain"] and from_org:
                sig_org = _get_org_domain(sig["domain"])
                sig["aligned"] = (sig_org == from_org)

            if DNS_AVAILABLE and sig["domain"] and sig["selector"]:
                dkim_domain = f"{sig['selector']}._domainkey.{sig['domain']}"
                record = AuthenticationAnalyzer._fetch_txt(dkim_domain, "v=DKIM1")
                sig["record_found"] = bool(record)

            result["dkim"]["signatures"].append(sig)

    @staticmethod
    def _extract_arc(result: Dict[str, Any], email_data: Dict[str, Any]):
        headers = email_data.get("headers", {}) if isinstance(email_data.get("headers"), dict) else {}
        arc_seals = headers.get("arc-seal", [])
        if isinstance(arc_seals, str):
            arc_seals = [arc_seals]

        result["arc"]["details"]["seal_count"] = len(arc_seals)
        result["arc"]["details"]["chain_present"] = len(arc_seals) > 0

    @staticmethod
    def _build_auth_matrix(result: Dict[str, Any]):
        spf = result["spf"].get("status") or "missing"
        dkim = result["dkim"].get("status") or "missing"
        dmarc = result["dmarc"].get("status") or "missing"
        arc = result["arc"].get("status") or "missing"
        alignment = result["alignment"].get("alignment_type", "none")

        if spf == "pass" and dkim == "pass" and dmarc == "pass":
            interpretation = "Fully authenticated message with aligned SPF and DKIM signatures."
        elif dmarc in ["fail", "failed"]:
            interpretation = "DMARC validation failed. Message sender identity is unauthenticated or spoofed."
        elif spf in ["fail", "failed"] and dkim in ["fail", "failed"]:
            interpretation = "Both SPF and DKIM validation failed."
        elif spf == "pass" and not result["alignment"]["spf_aligned"]:
            interpretation = "SPF passed for sending host but is not aligned with From header domain."
        elif dkim == "pass" and not result["alignment"]["dkim_aligned"]:
            interpretation = "DKIM signature is valid but signed under a third-party domain."
        else:
            interpretation = f"SPF={spf}, DKIM={dkim}, DMARC={dmarc}, ARC={arc} ({alignment} alignment)."

        result["auth_matrix"] = {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "arc": arc,
            "alignment": alignment,
            "interpretation": interpretation,
        }

    @staticmethod
    def _generate_findings(result: Dict[str, Any], from_domain: Optional[str]):
        findings = result["findings"]

        # Weak DMARC
        if result["dmarc"]["verified"]:
            policy = result["dmarc"]["details"].get("policy")
            if policy == "none":
                findings.append({
                    "finding_id": "auth.dmarc.weak_policy",
                    "category": "authentication",
                    "title": "Weak DMARC Policy",
                    "description": f"Domain {from_domain} uses a 'none' DMARC policy, which monitors but does not enforce blocking of spoofed mail.",
                    "severity": "low",
                    "confidence": 100,
                    "evidence": [result["dmarc"]["details"].get("record")],
                    "related_iocs": [from_domain] if from_domain else [],
                    "evidence_class": "contextual_anomaly",
                    "risk_relevance": "contextual",
                })

        if from_domain and not result["dmarc"]["verified"] and result["dmarc"]["status"] == "missing":
            findings.append({
                "finding_id": "auth.dmarc.missing",
                "category": "authentication",
                "title": "Missing DMARC Record",
                "description": f"Domain {from_domain} lacks an explicit DMARC record, reducing defense against email spoofing.",
                "severity": "medium",
                "confidence": 90,
                "evidence": [f"Domain: {from_domain}"],
                "related_iocs": [from_domain],
                "evidence_class": "contextual_anomaly",
                "risk_relevance": "contextual",
            })

        if result["spf"]["verified"]:
            policy = result["spf"]["details"].get("policy")
            if policy == "pass_all":
                findings.append({
                    "finding_id": "auth.spf.permissive",
                    "category": "authentication",
                    "title": "Permissive SPF Policy",
                    "description": f"Domain {from_domain} uses '+all' in its SPF record, explicitly permitting any server to send mail.",
                    "severity": "high",
                    "confidence": 100,
                    "evidence": [result["spf"]["details"].get("record")],
                    "related_iocs": [from_domain] if from_domain else [],
                    "evidence_class": "strong_risk_signal",
                    "risk_relevance": "risk_contributing",
                })

        # Failed DMARC reported
        if result["dmarc"]["status"] in ["fail", "failed"]:
            findings.append({
                "finding_id": "auth.dmarc.fail",
                "category": "authentication",
                "title": "DMARC Validation Failed",
                "description": "Upstream MTA reported a DMARC failure, indicating unaligned or unverified sender identity.",
                "severity": "high",
                "confidence": 100,
                "evidence": result["dmarc"]["details"].get("reported_headers", []),
                "related_iocs": [from_domain] if from_domain else [],
                "evidence_class": "strong_risk_signal",
                "risk_relevance": "risk_contributing",
            })

        # SPF unaligned warning
        if result["spf"]["status"] == "pass" and not result["alignment"]["spf_aligned"]:
            findings.append({
                "finding_id": "auth.spf.unaligned",
                "category": "authentication",
                "title": "SPF Valid but Unaligned",
                "description": "SPF validation passed for the envelope return-path, but the envelope domain differs from the visible From header domain.",
                "severity": "low",
                "confidence": 90,
                "evidence": [f"From domain: {from_domain}"],
                "related_iocs": [from_domain] if from_domain else [],
                "evidence_class": "contextual_anomaly",
                "risk_relevance": "contextual",
            })

        # DKIM unaligned warning
        if result["dkim"]["status"] == "pass" and not result["alignment"]["dkim_aligned"]:
            findings.append({
                "finding_id": "auth.dkim.unaligned",
                "category": "authentication",
                "title": "DKIM Signed by Third-Party Domain",
                "description": "DKIM signature passed but was signed by a third-party domain rather than the visible From header domain.",
                "severity": "low",
                "confidence": 85,
                "evidence": [f"From domain: {from_domain}"],
                "related_iocs": [from_domain] if from_domain else [],
                "evidence_class": "contextual_anomaly",
                "risk_relevance": "contextual",
            })

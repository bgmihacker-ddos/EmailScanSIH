"""Phase 6L: Attack Chain Reconstruction Engine.

Reconstructs evidence-bounded execution stages aligned with observable attack lifecycles.
Does not fabricate stages without empirical forensic support.
"""

from typing import Any, Dict, List


class AttackChainReconstruction:
    @staticmethod
    def reconstruct(
        header_forensics: Dict[str, Any],
        authentication: Dict[str, Any],
        url_intel: List[Dict[str, Any]],
        attachments: Dict[str, Any],
        content: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Reconstruct observable threat execution stages with clear evidence attribution."""
        chain: List[Dict[str, Any]] = []

        # Stage 1: Initial Ingestion / Transport
        mail_flow = header_forensics.get("mail_flow", {})
        hops = mail_flow.get("hop_count", 0)
        origin_ip = mail_flow.get("origin_ip") or "unknown"
        provider = mail_flow.get("origin_provider")
        prov_text = f" via {provider}" if provider else ""

        chain.append({
            "stage": "initial_delivery",
            "title": "1. Ingestion & Mail Transport",
            "status": "observed" if hops else "not_observed",
            "confidence": 100 if hops else 0,
            "evidence": [
                f"Processed {hops} hop(s). Origin IP: {origin_ip}{prov_text}"
                if hops else "No Received headers were supplied; transport path was not observed."
            ],
            "why_inferred": "MTA Received hop headers reconstructed chronologically." if hops else "No transport evidence was available."
        })

        # Stage 2: Identity Deception / Spoofing
        sender_findings = [
            f for f in header_forensics.get("forensic_findings", [])
            if f.get("category") == "identity" or "spoof" in f.get("finding_id", "")
        ]
        if sender_findings:
            chain.append({
                "stage": "sender_impersonation",
                "title": "2. Sender Deception / Identity Divergence",
                "status": "observed",
                "confidence": max(f.get("confidence", 90) for f in sender_findings),
                "evidence": [f.get("title") for f in sender_findings],
                "related_iocs": [ioc for f in sender_findings for ioc in f.get("related_iocs", [])],
                "why_inferred": "Divergence between display name, envelope From, Sender, or Reply-To identities."
            })

        # Stage 3: Authentication Bypass / Policy Anomaly
        auth_findings = [
            f for f in authentication.get("findings", [])
            if f.get("severity") in ("high", "medium") or "fail" in f.get("finding_id", "")
        ]
        if auth_findings:
            chain.append({
                "stage": "authentication_anomaly",
                "title": "3. Security Policy / Authentication Failure",
                "status": "observed",
                "confidence": max(f.get("confidence", 90) for f in auth_findings),
                "evidence": [f.get("title") for f in auth_findings],
                "related_iocs": [ioc for f in auth_findings for ioc in f.get("related_iocs", [])],
                "why_inferred": "Sender domain failed SPF/DKIM cryptographic or policy verification."
            })

        # Stage 4: Social Engineering / Psychological Framing
        content_findings = [
            f for f in content.get("findings", [])
            if "urgency" in f.get("finding_id", "") or "bec" in f.get("finding_id", "")
        ]
        if content_findings or content.get("is_bec_indicator"):
            ev = [f.get("title") for f in content_findings] or ["Urgency & financial authority language detected"]
            chain.append({
                "stage": "social_engineering",
                "title": "4. Social Engineering / Psychological Pressure",
                "status": "observed",
                "confidence": 85,
                "evidence": ev,
                "why_inferred": "Heuristic and lexical pattern correlation for coercive language."
            })

        # Stage 5: Malicious Infrastructure / Hyperlink Delivery
        suspicious_urls = [u for u in url_intel if u.get("risk_indicators", 0) > 0 or u.get("findings")]
        if suspicious_urls:
            ev_list = []
            related_urls = []
            for u in suspicious_urls:
                norm = u.get("normalized", u.get("url", ""))
                related_urls.append(norm)
                inds = u.get("indicators", [])
                ev_list.append(f"URL: {norm} ({', '.join(inds) if inds else 'flagged findings'})")

            chain.append({
                "stage": "suspicious_url",
                "title": "5. Deceptive Link / Malicious Infrastructure",
                "status": "observed",
                "confidence": 95,
                "evidence": ev_list[:5],
                "related_iocs": related_urls[:5],
                "why_inferred": "URL structural anomalies, homoglyphs, or brand token spoofing."
            })

        # Stage 6: Credential Harvesting Action
        cred_findings = [
            f for f in content.get("findings", [])
            if "credential" in f.get("finding_id", "") or "form" in f.get("finding_id", "")
        ]
        if cred_findings or "embedded_form" in content.get("html_indicators", []):
            chain.append({
                "stage": "credential_harvesting",
                "title": "6. Credential Interception Technique",
                "status": "observed",
                "confidence": 95,
                "evidence": [f.get("title") for f in cred_findings] or ["Interactive form / password input detected"],
                "why_inferred": "Direct interactive HTML forms or credential soliciting cues."
            })

        # Stage 7: Weaponized Attachment Delivery
        att_findings = attachments.get("findings", [])
        if att_findings:
            chain.append({
                "stage": "malware_attachment",
                "title": "7. Dangerous Attachment Delivery",
                "status": "observed",
                "confidence": max(f.get("confidence", 90) for f in att_findings),
                "evidence": [f.get("title") for f in att_findings],
                "related_iocs": [ioc for f in att_findings for ioc in f.get("related_iocs", [])],
                "why_inferred": "File extensions, MIME types, or magic headers associated with executable payloads."
            })

        return chain

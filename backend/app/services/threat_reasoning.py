"""Phase 6K: Threat Reasoning Engine.

Produces traceable, deterministic, SOC-grade explanations for the final threat verdict.
Separates primary risk factors from contextual indicators and positive/benign signals.
"""

from typing import Any, Dict, List, Optional


class ThreatReasoningEngine:
    @staticmethod
    def generate_reasoning(
        verdict: str,
        risk_score: int,
        score_breakdown: List[Dict[str, Any]],
        all_findings: List[Dict[str, Any]],
        benign_signals: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Synthesize decision path, executive narrative, and structured reasoning from forensic evidence."""
        primary_reasons: List[str] = []
        supporting_evidence: List[str] = []
        decision_path: List[str] = []
        recommendations: List[str] = []

        categorized_factors: Dict[str, List[str]] = {
            "critical_threats": [],
            "strong_indicators": [],
            "contextual_anomalies": [],
            "positive_authentication": benign_signals or []
        }

        decision_path.append("Forensic pipeline initialized. Ingesting multi-layer forensic evidence.")

        for item in score_breakdown:
            src = str(item.get("source") or "Unknown")
            reason = str(item.get("reason") or "")
            pts = int(item.get("points") or 0)
            e_class = str(item.get("evidence_class") or "informational")
            confidence = item.get("confidence", 90)

            supporting_evidence.append(f"[{src}] {reason}")

            if e_class == "confirmed_malicious" or pts >= 30:
                primary_reasons.append(f"[{src}] {reason}")
                categorized_factors["critical_threats"].append(f"{reason} (+{pts} pts, {confidence}% conf)")
                decision_path.append(f"Critical risk escalation (+{pts} pts): {reason} [{src}]")
            elif e_class == "strong_risk_signal" or pts >= 15:
                primary_reasons.append(f"[{src}] {reason}")
                categorized_factors["strong_indicators"].append(f"{reason} (+{pts} pts)")
                decision_path.append(f"Strong indicator observed (+{pts} pts): {reason} [{src}]")
            elif pts > 0:
                categorized_factors["contextual_anomalies"].append(f"{reason} (+{pts} pts)")
                decision_path.append(f"Contextual anomaly logged (+{pts} pts): {reason} [{src}]")

        # Hypotheses based on evidence
        attack_hypotheses: List[str] = []
        if any("bec" in r.lower() or "wire" in r.lower() for r in primary_reasons):
            attack_hypotheses.append("Business Email Compromise (BEC) targeting financial transfers or confidential actions.")
        if any("credential" in r.lower() or "password" in r.lower() or "form" in r.lower() for r in primary_reasons):
            attack_hypotheses.append("Credential harvesting campaign mimicking trusted authentication portal.")
        if any("attachment" in r.lower() or "executable" in r.lower() or "macro" in r.lower() for r in primary_reasons):
            attack_hypotheses.append("Malware delivery attempt via weaponized or deceptive email attachment.")
        if any("impersonat" in r.lower() or "spoof" in r.lower() for r in primary_reasons):
            attack_hypotheses.append("Identity spoofing / brand impersonation designed to bypass user trust.")

        decision_path.append(
            f"Calculated aggregate risk score {risk_score}/100 with {len(primary_reasons)} primary threat driver(s). "
            f"Verdict determined as {verdict.upper()}."
        )

        # Summary Generation
        if verdict == "malicious":
            summary = (
                f"Email classified as MALICIOUS (Risk: {risk_score}/100). "
                f"Definitive high-confidence threat signals identified: {'; '.join(primary_reasons[:2])}."
            )
            recommendations.extend([
                "Block sender domain and associated threat infrastructure immediately.",
                "Purge message from all recipient mailboxes to prevent user interaction.",
                "Review logs for any recipient interactions or URL clicks."
            ])
        elif verdict == "suspicious":
            summary = (
                f"Email classified as SUSPICIOUS (Risk: {risk_score}/100). "
                f"Unusual indicators detected: {'; '.join(primary_reasons[:2]) if primary_reasons else 'Multiple contextual anomalies'}."
            )
            recommendations.extend([
                "Exercise caution before following links or opening attachments.",
                "Verify sender authenticity through out-of-band communication."
            ])
        else:
            summary = (
                f"Email classified as BENIGN (Risk: {risk_score}/100). "
                "Core security checks and authentication policies verified without high-risk indicators."
            )
            recommendations.append("Standard security policies apply. No immediate mitigation required.")

        return {
            "summary": summary,
            "primary_reasons": primary_reasons,
            "supporting_evidence": supporting_evidence,
            "decision_path": decision_path,
            "risk_narrative": summary,
            "categorized_factors": categorized_factors,
            "attack_hypotheses": attack_hypotheses,
            "recommendations": recommendations,
        }

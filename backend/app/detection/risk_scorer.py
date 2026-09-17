"""Phase 6J/Phase 2: Hybrid Risk Scoring & Threat Fusion Engine.

Deduplicated, correlated evidence aggregation via EvidenceCorrelator.
"""

import os
from typing import Any, Dict, List

from app.detection.bert_classifier import get_bert_classifier
from app.detection.evidence_correlation import EvidenceCorrelator


class RiskEngine:
    @staticmethod
    def calculate_risk(
        header_forensics: Dict[str, Any],
        authentication: Dict[str, Any],
        iocs: Dict[str, Any],
        url_intel: List[Dict[str, Any]],
        domain_intel: Dict[str, Any],
        threat_intel: List[Dict[str, Any]],
        attachments: Dict[str, Any],
        content: Dict[str, Any],
        ml_res: Dict[str, Any],
        rule_res: Dict[str, Any],
        email: Dict[str, Any] | None = None,
        detector_findings: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        """Aggregate evidence via EvidenceCorrelator for consistent scoring."""

        # --- Optional BERT ensemble ---
        _BERT_ENABLED = os.getenv("BERT_ENSEMBLE_ENABLED", "false").lower() == "true"
        if _BERT_ENABLED and email is not None and ml_res.get("status") == "available":
            try:
                bert_res = get_bert_classifier().predict_email(email)
                if bert_res.get("status") == "available":
                    ml_prob = ml_res.get("probabilities", {}).get("phishing", 0.0)
                    bert_prob = bert_res.get("probability", 0.0)
                    # Soft-vote: 55% TF-IDF weight, 45% BERT weight
                    ensemble_prob = round(0.55 * ml_prob + 0.45 * bert_prob, 6)
                    THREAT_THRESHOLD = 0.40
                    ensemble_label = "phishing" if ensemble_prob >= THREAT_THRESHOLD else "benign"
                    ml_res = {
                        **ml_res,
                        "probability": ensemble_prob,
                        "label": ensemble_label,
                        "confidence": ensemble_prob if ensemble_label == "phishing" else (1.0 - ensemble_prob),
                        "probabilities": {**ml_res.get("probabilities", {}), "phishing": ensemble_prob},
                        "model_version": "ensemble-tfidf55-bert45-v1",
                        "bert_probability": bert_prob,
                        "ensemble_weights": {"tfidf": 0.55, "bert": 0.45},
                    }
            except Exception:
                pass  # BERT failure must never block the pipeline
        # --- End ensemble ---

        # 1. Correlate all findings
        correlation = EvidenceCorrelator.correlate(
            header_forensics=header_forensics,
            authentication=authentication,
            extracted_iocs=iocs,
            url_intelligence={"urls": url_intel},
            domain_intelligence=domain_intel,
            threat_intelligence={f"ti_{ti.get('provider', 'unknown')}": ti for ti in threat_intel},
            attachment_analysis=attachments,
            content_analysis=content,
            ml_prediction=ml_res,
            rule_detections=rule_res.get("rules", []) if isinstance(rule_res, dict) else [],
            detector_findings=detector_findings or [],
        )

        score_breakdown: List[Dict[str, Any]] = []
        total_score = 0
        evidence_ledger: List[Dict[str, Any]] = []

        # 2. Translate correlated records into score_breakdown format
        source_labels = {
            "ml_classifier": "ML Classifier",
            "authentication_analyzer": "Authentication",
            "header_forensics": "Header Forensics",
            "url_intelligence": "URL Analysis",
            "domain_intelligence": "Domain Analysis",
            "attachment_analyzer": "Attachment Analysis",
            "content_analyzer": "Content Analysis",
        }

        for rec in correlation.scoring_records:
            total_score += rec.base_points
            reason = rec.title
            if rec.source_family == "model":
                label = rec.title.removeprefix("ML classified as ").split("(")[0].strip().lower()
                reason = f"Model classified as {label}"
            item = {
                "analysis_id": None,
                "source": source_labels.get(rec.source, rec.source),
                "reason": reason,
                "points": rec.base_points,
                "confidence": rec.confidence,
                "signal": rec.finding_id,
                "evidence_class": rec.evidence_class,
                "risk_relevance": "risk_contributing",
                "evidence_refs": rec.evidence_refs
            }
            score_breakdown.append(item)
            evidence_ledger.append(item)

        # 3. Handle Mitigating records (negative impact)
        for rec in correlation.mitigating_records:
            total_score += rec.base_points
            item = {
                "analysis_id": None,
                "source": source_labels.get(rec.source, rec.source),
                "reason": rec.title,
                "points": rec.base_points,
                "confidence": rec.confidence,
                "signal": rec.finding_id,
                "evidence_class": rec.evidence_class,
                "risk_relevance": "mitigating",
                "evidence_refs": rec.evidence_refs
            }
            score_breakdown.append(item)
            evidence_ledger.append(item)

        total_score = sum(item["points"] for item in evidence_ledger)

        # Clamp total score
        final_score = min(100, max(0, total_score))

        # Determine verdict & severity
        if final_score >= 50:
            verdict = "malicious"
            severity = "critical" if final_score >= 80 else "high"
        elif final_score >= 25:
            verdict = "suspicious"
            severity = "medium"
        else:
            verdict = "benign"
            severity = "low" if final_score > 0 else "info"

        return {
            "verdict": verdict,
            "risk_score": final_score,
            "severity": severity,
            "confidence": correlation.confidence,
            "score_breakdown": score_breakdown,
            "evidence_ledger": evidence_ledger,
            "correlation_summary": correlation.summary_notes,
            "correlation_clusters": correlation.clusters,
            "evidence_count": len(correlation.evidence_records),
            "suppressed_count": len(correlation.suppressed_records),
        }

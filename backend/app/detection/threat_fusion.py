# AUDIT SCRIPT: Unified Threat Fusion Service
# Importers/Callers: app.api.routes.analysis, tests.test_fusion
# Affected API: app.detection.threat_fusion.ThreatFusionService
# Data schemas: Dict or ConsensusResult
# Verbatim instruction: "Transform the existing standalone threat-intelligence integrations into one resilient, normalized, evidence-aware IOC intelligence layer."

from typing import List, Optional, Dict, Any, Union
from app.schemas.indicator import ThreatIndicator

class ThreatFusionService:
    @staticmethod
    def fuse(indicators: List[Union[ThreatIndicator, Dict[str, Any]]]) -> Dict[str, Any]:
        if not indicators:
            return {
                "severity": "safe",
                "confidence": 0,
                "sources": [],
                "evidence": ["No intelligence available"],
                "reasoning": "Insufficient data available",
                "has_disagreement": False
            }

        # Rule-based fusion
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0, "malicious": 4, "suspicious": 2, "unknown": 0}

        # Normalize indicators
        norm_indicators = []
        for i in indicators:
            if isinstance(i, ThreatIndicator):
                norm_indicators.append({
                    "source": i.source,
                    "type": i.indicator_type,
                    "severity": i.severity.lower(),
                    "confidence": i.confidence
                })
            elif isinstance(i, dict):
                norm_indicators.append({
                    "source": i.get("provider", i.get("source", "unknown")),
                    "type": i.get("indicator_type", i.get("type", "unknown")),
                    "severity": i.get("reputation", i.get("severity", "unknown")).lower(),
                    "confidence": int(i.get("confidence", 0))
                })

        sources = list(set([i["source"] for i in norm_indicators]))
        evidence = []
        for i in norm_indicators:
            evidence.append(f"{i['source']} reports {i['type']} as {i['severity']} (confidence: {i['confidence']})")

        # Determine highest severity
        max_severity_val = max([severity_map.get(i["severity"], 0) for i in norm_indicators])

        # Base confidence on source agreement and provider confidence
        conf_values = [i["confidence"] for i in norm_indicators]
        confidence = sum(conf_values) // len(conf_values) if conf_values else 0
        if len(norm_indicators) > 1:
            confidence = min(100, confidence + 10)

        # Detect dissent
        severities = [i["severity"] for i in norm_indicators]
        has_disagreement = ("malicious" in severities or "critical" in severities or "high" in severities) and ("safe" in severities or "low" in severities)

        reasoning = f"Fusion of {len(norm_indicators)} independent sources: {', '.join(sources)}."
        if has_disagreement:
            reasoning += " Warning: High provider dissent detected."

        # Map back to severity string
        inv_severity_map = {4: "high", 3: "high", 2: "medium", 1: "low", 0: "safe"}
        severity = inv_severity_map.get(max_severity_val, "safe")

        return {
            "severity": severity,
            "confidence": confidence,
            "sources": sources,
            "evidence": evidence,
            "reasoning": reasoning,
            "has_disagreement": has_disagreement
        }


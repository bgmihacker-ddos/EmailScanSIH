# AUDIT SCRIPT: Threat Fusion Test Suite
# Importers/Callers: pytest backend/tests/test_fusion.py
# Affected API: app.detection.threat_fusion.ThreatFusionService
# Data schemas: ConsensusResult and legacy dictionaries
# Verbatim instruction: "Transform the existing standalone threat-intelligence integrations into one resilient, normalized, evidence-aware IOC intelligence layer."

import pytest
from app.detection.threat_fusion import ThreatFusionService
from app.schemas.indicator import ThreatIndicator

def test_fusion_empty():
    res = ThreatFusionService.fuse([])
    assert res["severity"] == "safe"
    assert res["confidence"] == 0
    assert res["has_disagreement"] is False

def test_fusion_high_severity():
    i1 = ThreatIndicator(id="1", indicator="a.com", indicator_type="domain", severity="high", confidence=80, source="T", status="active")
    i2 = ThreatIndicator(id="2", indicator="b.com", indicator_type="domain", severity="low", confidence=50, source="U", status="active")
    result = ThreatFusionService.fuse([i1, i2])
    assert result["severity"] == "high"
    assert result["has_disagreement"] is True
    assert "Warning: High provider dissent detected." in result["reasoning"]

def test_fusion_dict_provider_results():
    providers = [
        {"provider": "VirusTotal", "type": "url", "severity": "malicious", "confidence": 90},
        {"provider": "GoogleSafeBrowsing", "type": "url", "severity": "safe", "confidence": 85},
    ]
    result = ThreatFusionService.fuse(providers)
    assert result["severity"] == "high"
    assert result["has_disagreement"] is True
    assert len(result["evidence"]) == 2
    assert "VirusTotal reports url as malicious (confidence: 90)" in result["evidence"]


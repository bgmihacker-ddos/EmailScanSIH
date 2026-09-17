"""
test_evidence_correlation.py — Tests for Evidence Correlation & Normalization Engine (Phase 2).
"""

import pytest
from app.detection.evidence_correlation import (
    EvidenceCorrelator,
    EvidenceRecord,
    CorrelationResult,
)


def test_empty_inputs():
    res = EvidenceCorrelator.correlate()
    assert isinstance(res, CorrelationResult)
    assert len(res.evidence_records) == 0
    assert len(res.scoring_records) == 0
    assert res.confidence == 30


def test_authentication_normalization_and_clustering():
    auth_data = {
        "spf": {"result": "fail", "domain": "example.com"},
        "dkim": {"result": "fail", "domain": "example.com"},
        "dmarc": {"result": "reject", "domain": "example.com"},
    }
    res = EvidenceCorrelator.correlate(authentication=auth_data)
    assert len(res.evidence_records) >= 3
    # Verify DMARC fail is in scoring records
    scoring_ids = [r.finding_id for r in res.scoring_records]
    assert "auth_dmarc_fail" in scoring_ids
    # Verify MITRE technique attached
    dmarc_record = next(r for r in res.scoring_records if r.finding_id == "auth_dmarc_fail")
    assert "T1566.002" in dmarc_record.mitre_techniques


def test_authentication_pass_mitigation():
    auth_data = {
        "spf": {"result": "pass", "domain": "trusted.com"},
        "dkim": {"result": "pass", "domain": "trusted.com"},
        "dmarc": {"result": "pass", "domain": "trusted.com"},
    }
    res = EvidenceCorrelator.correlate(authentication=auth_data)
    assert len(res.mitigating_records) >= 1
    assert any(r.finding_id == "auth_dmarc_pass" for r in res.mitigating_records)
    # High confidence for clean verified email
    assert res.confidence >= 75


def test_url_and_domain_host_clustering():
    url_intel = {
        "urls": [
            {
                "url": "http://evil-bank.com/login",
                "domain": "evil-bank.com",
                "risk_score": 90,
                "threat_types": ["credential_phishing"],
            },
            {
                "url": "http://evil-bank.com/reset-password",
                "domain": "evil-bank.com",
                "risk_score": 85,
                "threat_types": ["credential_phishing"],
            },
        ]
    }
    domain_intel = {
        "evil-bank.com": {
            "impersonated_brand": "Bank of America",
            "risk_score": 95,
        }
    }
    res = EvidenceCorrelator.correlate(url_intelligence=url_intel, domain_intelligence=domain_intel)
    # Both URLs and domain share cluster_key "host_cluster_evil-bank.com"
    cluster_records = [r for r in res.evidence_records if r.cluster_key == "host_cluster_evil-bank.com"]
    assert len(cluster_records) >= 3
    # Exactly one primary scoring record from that host cluster
    scoring_cluster_records = [r for r in res.scoring_records if r.cluster_key == "host_cluster_evil-bank.com"]
    assert len(scoring_cluster_records) == 1
    # Other records in the cluster are suppressed from duplicate scoring
    assert len(res.suppressed_records) >= 2


def test_threat_intel_corroboration_priority():
    url_intel = {
        "urls": [
            {
                "url": "http://known-c2.com/payload.exe",
                "domain": "known-c2.com",
                "risk_score": 80,
            }
        ]
    }
    ti_data = {
        "urlhaus": {
            "status": "ok",
            "is_malicious": True,
            "target": "http://known-c2.com/payload.exe",
            "positives": 15,
        }
    }
    res = EvidenceCorrelator.correlate(url_intelligence=url_intel, threat_intelligence=ti_data)
    ti_hits = [r for r in res.scoring_records if r.evidence_class == "confirmed_malicious"]
    assert len(ti_hits) == 1
    assert ti_hits[0].source == "ti_urlhaus"
    assert res.confidence >= 80


def test_ti_non_scoring_states():
    ti_data = {
        "virustotal": {"status": "not_configured", "target": "domain.com"},
        "urlhaus": {"status": "timeout", "target": "domain.com"},
        "abuseipdb": {"status": "rate_limited", "target": "1.2.3.4"},
    }
    res = EvidenceCorrelator.correlate(threat_intelligence=ti_data)
    # None of these should score
    assert len(res.scoring_records) == 0
    # They should be recorded with non-scoring reasons
    assert len(res.evidence_records) == 3
    for r in res.evidence_records:
        assert r.scoring_eligible is False
        assert r.non_scoring_reason is not None


def test_header_domain_threat_intel_is_context_only():
    res = EvidenceCorrelator.correlate(threat_intelligence={
        "threatfox": {
            "status": "ok",
            "reputation": "malicious",
            "confidence": 75,
            "indicator": "example.com",
            "metadata": {"ti_scoring_eligible": False, "ioc_source": "header"},
        }
    })

    assert res.scoring_records == []
    assert res.evidence_records[0].non_scoring_reason == "header_domain_context"


def test_low_confidence_provider_report_is_not_confirmed():
    res = EvidenceCorrelator.correlate(threat_intelligence={
        "threatfox": {
            "status": "ok",
            "reputation": "malicious",
            "confidence": 75,
            "indicator": "https://evil.test/login",
        }
    })

    record = res.scoring_records[0]
    assert record.base_points == 10
    assert record.title == "threatfox reported malicious"
    assert record.evidence_class == "strong_risk_signal"
    assert record.confidence == 75


def test_ml_signal_bounded_and_penalty():
    ml_data = {
        "prediction": "phishing",
        "probability": 0.98,
    }
    res = EvidenceCorrelator.correlate(ml_prediction=ml_data)
    assert len(res.scoring_records) == 1
    ml_rec = res.scoring_records[0]
    assert ml_rec.base_points <= 15
    assert ml_rec.source_family == "model"
    # When ML is the only signal, confidence should be appropriately low/penalized
    assert res.confidence <= 60


def test_unavailable_ml_does_not_create_unknown_risk_signal():
    res = EvidenceCorrelator.correlate(
        ml_prediction={
            "status": "unavailable",
            "label": "unknown",
            "confidence": 0.0,
        }
    )

    assert res.scoring_records == []


def test_attachment_weaponization():
    att_data = {
        "attachments": [
            {
                "filename": "invoice_urgent.exe",
                "sha256": "abc123def456",
                "is_executable": True,
                "has_double_extension": True,
                "is_malicious": True,
            }
        ]
    }
    res = EvidenceCorrelator.correlate(attachment_analysis=att_data)
    assert len(res.scoring_records) == 1
    att_rec = res.scoring_records[0]
    assert att_rec.severity == "critical"
    assert "T1566.001" in att_rec.mitre_techniques


def test_multi_source_corroboration_confidence_boost():
    auth_data = {"dmarc": {"result": "reject", "domain": "spoofed.com"}}
    url_data = {"urls": [{"url": "http://spoofed.com/phish", "domain": "spoofed.com", "risk_score": 90}]}
    att_data = {"attachments": [{"filename": "macro.docm", "has_macro": True, "is_malicious": True}]}
    content_data = {"intent": {"primary_intent": "credential_phishing"}}
    ti_data = {"virustotal": {"status": "ok", "is_malicious": True, "target": "spoofed.com", "positives": 10}}

    res = EvidenceCorrelator.correlate(
        authentication=auth_data,
        url_intelligence=url_data,
        attachment_analysis=att_data,
        content_analysis=content_data,
        threat_intelligence=ti_data,
    )
    # Multi-family corroboration + confirmed TI
    assert res.confidence >= 90
    assert len(res.evidence_families_present) >= 4

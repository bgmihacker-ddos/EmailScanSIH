"""Comprehensive unit tests for Phases 6C through 6L.

Tests authentication analysis, IOC extraction, URL/domain intelligence,
threat intelligence providers (mocked), attachment analysis, content analysis,
ML classification fallback, hybrid risk fusion, threat reasoning, and attack chain reconstruction.
"""

import pytest
from app.services.authentication_analyzer import AuthenticationAnalyzer
from app.services.ioc_extractor import IOCExtractor, compute_hash
from app.services.url_analyzer import URLIntelligence
from app.services.domain_analyzer import DomainIntelligence
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.content_analyzer import ContentAnalyzer
from app.ml.classifier import MLClassifier
from app.detection.risk_scorer import RiskEngine
from app.services.threat_reasoning import ThreatReasoningEngine
from app.services.attack_chain import AttackChainReconstruction


def test_authentication_analyzer_basic():
    header_forensics = {
        "authentication_evidence": {
            "spf": {"available": True, "status": "pass", "sources": ["received-spf"], "reported_by_header": ["pass"]},
            "dmarc": {"available": True, "status": "fail", "sources": ["authentication-results"], "reported_by_header": ["fail"]}
        },
        "domain_relationships": {"from_domain": "example.com"}
    }
    email_data = {"headers": {"dkim-signature": ["v=1; d=example.com; s=sel1; a=rsa-sha256;"]}}
    res = AuthenticationAnalyzer.analyze(header_forensics, email_data)
    assert res["spf"]["status"] == "pass"
    assert res["dmarc"]["status"] == "fail"
    assert len(res["dkim"]["signatures"]) == 1
    assert any(f["finding_id"] == "auth.dmarc.fail" for f in res["findings"])


def test_ioc_extractor_comprehensive():
    parsed_email = {
        "received_chain": [{"ips": ["192.168.1.1", "8.8.8.8"], "from_server": "mail.test.com"}],
        "addresses": {"from": {"address": "sender@test.com", "domain": "test.com"}},
        "message_id": "12345@test.com",
        "plain_text": "Hello, visit https://evil.com/login or contact test@example.com or IP 10.0.0.1",
        "html_body": "<a href='http://phish.com'>Click</a>",
        "urls": ["https://evil.com/login", "http://phish.com"],
        "attachments": [{"filename": "invoice.pdf.exe", "content_type": "application/x-msdownload", "size": 1024}]
    }
    extracted = IOCExtractor.extract(parsed_email)
    iocs = extracted["iocs"]
    types = [i["type"] for i in iocs]
    assert "url" in types
    assert "domain" in types
    assert "email" in types
    assert "ip" in types or "ipv6" in types
    assert "filename" in types


def test_url_intelligence():
    url = "https://admin:pass@xn--pple-43d.com:8443/login?user=1#frag"
    res = URLIntelligence.analyze(url)
    assert res["hostname"] == "xn--pple-43d.com"
    assert res["port"] == 8443
    assert "punycode_domain" in res["indicators"]
    assert "credential_url" in res["indicators"]


def test_url_intelligence_batch_accepts_safe_empty_and_instance_calls():
    urls = ["https://example.com/login", "http://evil.test/verify"]
    assert len(URLIntelligence.analyze_batch(urls)) == 2
    assert len(URLIntelligence().analyze_batch(urls)) == 2
    assert URLIntelligence.analyze_batch([]) == []
    assert URLIntelligence.analyze_batch(None) == []


def test_domain_intelligence():
    res = DomainIntelligence.analyze("login-verify-secure.com")
    assert "login" in res["suspicious_keywords_found"]
    assert "verify" in res["suspicious_keywords_found"]


def test_attachment_analyzer():
    attachments = [
        {"filename": "safe.pdf", "content_type": "application/pdf", "size": 500, "extension": "pdf"},
        {"filename": "malware.exe", "content_type": "application/x-msdownload", "size": 1000, "extension": "exe"},
        {"filename": "doc.pdf.bat", "content_type": "text/plain", "size": 200, "extension": "bat"}
    ]
    res = AttachmentAnalyzer.analyze(attachments)
    assert res["high_risk_count"] == 2
    assert len(res["findings"]) >= 2


def test_content_analyzer():
    email_data = {
        "plain_text": "URGENT: Your account is suspended. Verify password immediately or wire transfer funds.",
        "html_body": "<form action='http://evil.com'><input type='password'></form>"
    }
    res = ContentAnalyzer.analyze(email_data)
    assert "urgent" in res["urgency_keywords"]
    assert "password" in res["credential_keywords"]
    assert res["is_bec_indicator"] is True
    assert "embedded_form" in res["html_indicators"]
    assert len(res["findings"]) >= 2


def test_ml_classifier_unavailable():
    clf = MLClassifier("nonexistent_path.joblib")
    pred = clf.predict("Test email body")
    assert pred["status"] == "unavailable"
    assert pred["label"] == "unknown"


def test_risk_scorer_and_fusion():
    header_forensics = {"forensic_findings": [{"finding_id": "test.high", "severity": "high", "title": "High Risk Header", "evidence_class": "strong_risk_signal"}]}
    authentication = {"findings": [{"finding_id": "auth.fail", "severity": "high", "title": "Auth Failed", "evidence_class": "strong_risk_signal"}]}
    iocs = {"iocs": []}
    url_intel = [{"normalized": "https://evil.com", "indicators": ["credential_url"], "findings": [{"finding_id": "url.cred", "severity": "high", "title": "Credential URL", "evidence_class": "strong_risk_signal"}]}]
    domain_intel = {}
    threat_intel = []
    attachments = {"findings": []}
    content = {"findings": [{"finding_id": "content.bec", "severity": "high", "title": "BEC Detected", "evidence_class": "strong_risk_signal"}]}
    ml_res = {"status": "unavailable"}
    rule_res = {}

    risk = RiskEngine.calculate_risk(
        header_forensics, authentication, iocs, url_intel, domain_intel,
        threat_intel, attachments, content, ml_res, rule_res
    )
    assert risk["risk_score"] > 50
    assert risk["verdict"] == "malicious"
    assert len(risk["score_breakdown"]) >= 3


def test_risk_engine_exposes_provenance_ledger_for_reproducible_scoring():
    header_forensics = {"forensic_findings": [{"finding_id": "header.spoof", "severity": "high", "title": "Spoofed sender", "risk_relevance": "risk_contributing", "evidence_class": "strong_risk_signal", "confidence": 90, "related_iocs": ["sender@example.com"]}]}
    authentication = {"findings": [{"finding_id": "auth.spf.fail", "severity": "medium", "title": "SPF failed", "risk_relevance": "risk_contributing", "evidence_class": "strong_risk_signal", "confidence": 85, "related_iocs": ["mail.example.com"]}]}
    iocs = {"iocs": []}
    url_intel = []
    domain_intel = {}
    threat_intel = []
    attachments = {"findings": []}
    content = {"findings": []}
    ml_res = {"status": "unavailable"}
    rule_res = {}

    risk = RiskEngine.calculate_risk(
        header_forensics, authentication, iocs, url_intel, domain_intel,
        threat_intel, attachments, content, ml_res, rule_res
    )

    assert "evidence_ledger" in risk
    assert len(risk["evidence_ledger"]) >= 2
    assert all(set(["source", "signal", "points", "confidence", "evidence_class", "evidence_refs"]).issubset(item) for item in risk["evidence_ledger"])
    assert risk["risk_score"] == sum(item["points"] for item in risk["evidence_ledger"] if item["points"] > 0)


def test_risk_engine_ignores_threat_intel_for_authentication_context_domains():
    risk = RiskEngine.calculate_risk(
        {}, {}, {"iocs": []}, [], {},
        [{
            "provider": "ThreatFox",
            "status": "ok",
            "reputation": "malicious",
            "is_malicious": True,
            "confidence": 100,
            "indicator": "google.com",
            "metadata": {
                "ioc_source": "authentication",
                "ti_scoring_eligible": False,
            },
        }],
        {"findings": []}, {"findings": []}, {"status": "unavailable"}, {},
    )

    assert risk["risk_score"] == 0
    assert not any(item["source"] == "ti_ThreatFox" for item in risk["score_breakdown"])


def test_threat_reasoning_and_attack_chain():
    breakdown = [{"source": "Header", "reason": "Spoofed From", "points": 25}]
    findings = []
    reasoning = ThreatReasoningEngine.generate_reasoning("malicious", 75, breakdown, findings)
    assert "malicious" in reasoning["summary"].lower()
    assert len(reasoning["decision_path"]) > 0

    header_forensics = {"mail_flow": {"hop_count": 2, "origin_ip": "1.2.3.4"}}
    authentication = {"findings": [{"title": "Auth Failed", "severity": "high", "finding_id": "auth.spf.fail", "confidence": 100}]}
    url_intel = [{"normalized": "http://evil.com", "risk_indicators": 1, "indicators": ["suspicious_tld"]}]
    attachments = {"findings": []}
    content = {"findings": [{"finding_id": "content.social_engineering.urgency", "title": "Urgency"}], "urgency_keywords": ["urgent"]}

    chain = AttackChainReconstruction.reconstruct(
        header_forensics, authentication, url_intel, attachments, content
    )
    stages = [s["stage"] for s in chain]
    assert "initial_delivery" in stages
    assert "authentication_anomaly" in stages
    assert "social_engineering" in stages

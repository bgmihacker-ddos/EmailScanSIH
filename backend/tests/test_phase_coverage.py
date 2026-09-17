"""Comprehensive test suite verifying Phases 6B through 10 requirements completely offline.

Tests cover:
- 6B: Header forensics & mail flow
- 6C: Authentication analysis (SPF/DKIM/DMARC/ARC)
- 6D: IOC extraction & provenance
- 6E: URL/Domain/IP intelligence
- 6F: Mocked threat intelligence providers & error handling
- 6G: Static attachment analysis
- 6H: Content & phishing analysis
- 6I: ML classifier CPU abstraction & fallback
- 6J: Hybrid risk scoring & fusion
- 6K: Threat reasoning
- 6L: Attack chain reconstruction
- API & Persistence: endpoints, reports, dashboard, search, and security constraints.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services.email_parser import EmailParser
from app.services.header_forensics import HeaderForensicsAnalyzer
from app.services.authentication_analyzer import AuthenticationAnalyzer
from app.services.ioc_extractor import IOCExtractor, compute_hash
from app.services.url_analyzer import URLIntelligence
from app.services.domain_analyzer import DomainIntelligence
from app.services.threat_intelligence import (
    VirusTotalProvider,
    URLhausProvider,
    ThreatFoxProvider,
    AbuseIPDBProvider,
    ThreatIntelligenceService,
)
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.content_analyzer import ContentAnalyzer
from app.ml.classifier import MLClassifier
from app.detection.risk_scorer import RiskEngine
from app.services.threat_reasoning import ThreatReasoningEngine
from app.services.attack_chain import AttackChainReconstruction

client = TestClient(app)


# ============================================================================
# Phase 6B: Header Forensics
# ============================================================================

def test_6b_received_chain_multihop_and_ips():
    raw_email = (
        b"Received: from mx.receiver.com (mx.receiver.com [2001:4860:4860::8888]) by inbox.com; Mon, 07 Sep 2026 12:05:00 +0000\r\n"
        b"Received: from relay.net (relay.net [192.168.1.100]) by mx.receiver.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Received: from source.org (source.org [8.8.8.8]) by relay.net; Mon, 07 Sep 2026 11:55:00 +0000\r\n"
        b"From: Alice <alice@spoofed.com>\r\n"
        b"To: Bob <bob@receiver.com>\r\n"
        b"Reply-To: Evil <evil@phish.com>\r\n"
        b"Return-Path: <bounce@differ.com>\r\n"
        b"Date: Mon, 07 Sep 2026 11:50:00 +0000\r\n"
        b"Message-ID: <msg123@source.org>\r\n\r\nTest"
    )
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)

    assert forensics["mail_flow"]["hop_count"] == 3
    assert forensics["mail_flow"]["origin_ip"] == "8.8.8.8"
    assert forensics["domain_relationships"]["relationships"]["from_to_reply_to"] == "different_domain"
    assert forensics["domain_relationships"]["relationships"]["from_to_return_path"] == "different_domain"

    # Verify IP classifications present
    classes = forensics["ip_classifications"]
    assert any(entry["ip"] == "192.168.1.100" and entry["classification"] == "private" for entry in classes)
    assert any(entry["ip"] == "8.8.8.8" and entry["classification"] == "public" for entry in classes)


def test_6b_duplicate_headers_and_timeline():
    raw_email = (
        b"From: one@example.com\r\n"
        b"From: two@example.com\r\n"
        b"Subject: Subject 1\r\n"
        b"Received: from b.com by c.com; Mon, 07 Sep 2026 12:01:00 +0000\r\n"
        b"Received: from a.com by b.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n\r\nBody"
    )
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)

    findings = [f["finding_id"] for f in forensics["forensic_findings"]]
    assert "header.duplicate.from" in findings
    assert len(forensics["mail_flow"]["timeline"]) == 2


# ============================================================================
# Phase 6C: Authentication Analysis
# ============================================================================

def test_6c_auth_analysis_comprehensive():
    forensics = {
        "authentication_evidence": {
            "spf": {"available": True, "status": "fail", "sources": ["received-spf"], "reported_by_header": ["fail"]},
            "dkim": {"available": True, "status": "pass", "sources": ["authentication-results"], "reported_by_header": ["pass"]},
            "dmarc": {"available": True, "status": "fail", "sources": ["authentication-results"], "reported_by_header": ["fail"]},
            "arc": {"available": True, "status": "pass", "sources": ["arc-seal"], "reported_by_header": ["pass"]},
        },
        "domain_relationships": {"from_domain": "example.com"}
    }
    email_data = {
        "headers": {
            "authentication-results": "mx.example.com; dkim=pass header.i=@example.com",
            "dkim-signature": ["v=1; a=rsa-sha256; d=example.com; s=s1; h=from:to:subject;"],
            "arc-seal": ["i=1; a=rsa-sha256; cv=none; d=example.com; s=arc;"],
        }
    }
    with patch.object(AuthenticationAnalyzer, "_fetch_txt", return_value=None):
        res = AuthenticationAnalyzer.analyze(forensics, email_data)

    assert res["spf"]["status"] == "fail"
    assert res["spf"]["verified"] is False  # Header claims only remain unverified
    assert res["dkim"]["status"] == "pass"
    assert len(res["dkim"]["signatures"]) == 1
    assert res["arc"]["status"] == "pass"
    assert any(f["finding_id"] == "auth.dmarc.fail" for f in res["findings"])


def test_6c_missing_and_malformed_auth():
    forensics = {"authentication_evidence": {}, "domain_relationships": {}}
    res = AuthenticationAnalyzer.analyze(forensics, {"headers": {}})

    assert res["spf"]["status"] == "missing"
    assert res["dkim"]["status"] == "missing"
    assert res["dmarc"]["status"] == "missing"
    assert res["arc"]["status"] == "missing"


# ============================================================================
# Phase 6D: IOC Extraction & Provenance
# ============================================================================

def test_6d_ioc_extractor():
    parsed_email = {
        "received_chain": [{"ips": ["192.168.1.1", "2001:db8::1"], "from_server": "mail.test.com"}],
        "addresses": {"from": {"address": "sender@test.com", "domain": "test.com"}},
        "message_id": "<123@test.com>",
        "plain_text": "Check https://evil.com/login and http://10.0.0.1/admin or contact support@phish.org",
        "html_body": "<a href='https://evil.com/login'>Link</a>",
        "urls": ["https://evil.com/login", "http://10.0.0.1/admin"],
        "attachments": [{"filename": "invoice.pdf.exe", "content_type": "application/x-msdownload", "size": 2048}],
    }
    extracted = IOCExtractor.extract(parsed_email)
    iocs = extracted["iocs"]
    types = {i["type"] for i in iocs}

    assert "url" in types
    assert "domain" in types
    assert "email" in types
    assert "ip" in types
    assert "ipv6" in types
    assert "filename" in types
    assert "message_id" in types

    # Check deduplication and provenance
    urls = [i for i in iocs if i["type"] == "url" and i["value"] == "https://evil.com/login"]
    assert len(urls) == 1
    assert urls[0]["source"] in ["body", "urls"]


def test_6d_authentication_field_labels_are_not_domains():
    parsed_email = {
        "authentication_headers": {
            "authentication-results": (
                "mx.example.com; dkim=pass header.i=@sender.example.com; "
                "spf=pass smtp.mailfrom=sender@example.com; "
                "dmarc=pass header.from=sender.example.com"
            )
        }
    }

    domains = {
        item["value"]
        for item in IOCExtractor.extract(parsed_email)["iocs"]
        if item["type"] == "domain"
    }

    assert "smtp.mailfrom" not in domains
    assert "header.from" not in domains
    assert "sender.example.com" in domains


def test_6d_attachment_hashing():
    data = b"malicious binary payload"
    h = compute_hash(data)
    assert len(h["sha256"]) == 64
    assert len(h["md5"]) == 32


# ============================================================================
# Phase 6E: URL / Domain / IP Intelligence
# ============================================================================

def test_6e_url_intelligence():
    url = "http://admin:secret@xn--pple-43d.com:8080/path?arg=1#frag"
    res = URLIntelligence.analyze(url)

    assert "ip_hosted_url" not in res["indicators"]
    assert res["port"] == 8080
    assert "punycode_domain" in res["indicators"]
    assert "credential_url" in res["indicators"]


def test_6e_domain_intelligence_offline():
    res = DomainIntelligence.analyze("login-update-account.com")
    assert "login" in res["suspicious_keywords_found"]
    assert "update" in res["suspicious_keywords_found"]
    assert res["tld"] == "com"


# ============================================================================
# Phase 6F: Mocked Threat Intelligence Providers
# ============================================================================

@pytest.mark.asyncio
async def test_6f_virustotal_mocked():
    # Unconfigured key check
    with patch("app.services.threat_intelligence.settings.VIRUSTOTAL_API_KEY", None):
        vt_nokey = VirusTotalProvider()
        res = await vt_nokey.lookup("domain", "evil.com")
        assert res["status"] == "not_configured"

    # Mocked 200 OK
    with patch("app.services.threat_intelligence.settings.VIRUSTOTAL_API_KEY", "mock_key"):
        vt = VirusTotalProvider()
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {"attributes": {"last_analysis_stats": {"malicious": 10, "suspicious": 2}}}
            }
            mock_get.return_value = mock_resp

            res_ok = await vt.lookup("domain", "evil.com")
            assert res_ok["status"] == "ok"
            assert res_ok["reputation"] == "malicious"
            assert res_ok["detections"] == 12

        # Mocked 401 / 403
        vt._circuit_breaker_until = 0
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_get.return_value = mock_resp
            res_unauth = await vt.lookup("domain", "evil.com")
            assert res_unauth["status"] == "unavailable"

        # Mocked 429 Rate limit
        vt._circuit_breaker_until = 0
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_get.return_value = mock_resp
            res_rl = await vt.lookup("domain", "evil.com")
            assert res_rl["status"] == "rate_limited"

        # Mocked Timeout
        vt._circuit_breaker_until = 0
        with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Timeout")):
            res_to = await vt.lookup("domain", "evil.com")
            assert res_to["status"] == "timeout"


@pytest.mark.asyncio
async def test_6f_urlhaus_mocked():
    with patch("app.services.threat_intelligence.settings.URLHAUS_API_KEY", "test_key"):
        uh = URLhausProvider()
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"query_status": "ok", "tags": ["phishing"]}
            mock_post.return_value = mock_resp

            res = await uh.lookup("url", "https://evil.com/phish")
            assert res["status"] == "ok"
            assert res["reputation"] == "malicious"
            assert "phishing" in res["categories"]
            assert mock_post.call_args.kwargs["headers"] == {"Auth-Key": "test_key"}


@pytest.mark.asyncio
async def test_6f_threatfox_mocked():
    with patch("app.services.threat_intelligence.settings.THREATFOX_API_KEY", "test_key"):
        tf = ThreatFoxProvider()
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "query_status": "ok",
                "data": [{"confidence_level": 90, "threat_type": "botnet_cc"}],
            }
            mock_post.return_value = mock_resp

            res = await tf.lookup("ip", "1.2.3.4")
            assert res["status"] == "ok"
            assert res["confidence"] == 90
            assert "botnet_cc" in res["categories"]
            assert mock_post.call_args.kwargs["headers"] == {"Auth-Key": "test_key"}


@pytest.mark.asyncio
async def test_6f_abuseipdb_mocked():
    with patch("app.services.threat_intelligence.settings.ABUSEIPDB_API_KEY", "test_key"):
        ab = AbuseIPDBProvider()
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": {"abuseConfidenceScore": 85}}
            mock_get.return_value = mock_resp

            res = await ab.lookup("ip", "5.6.7.8")
            assert res["status"] == "ok"
            assert res["confidence"] == 85
            assert res["reputation"] == "malicious"


# ============================================================================
# Phase 6G: Attachment Static Analysis
# ============================================================================

def test_6g_attachment_analysis():
    attachments = [
        {"filename": "invoice.pdf.exe", "content_type": "application/x-msdownload", "size": 5000, "extension": "exe"},
        {"filename": "document.docm", "content_type": "application/vnd.ms-word.document.macroenabled.12", "size": 1000, "extension": "docm"},
        {"filename": "safe.txt", "content_type": "text/plain", "size": 200, "extension": "txt"},
    ]
    res = AttachmentAnalyzer.analyze(attachments)

    assert res["high_risk_count"] == 1
    assert len(res["findings"]) == 2
    indics = [ind for a in res["attachments"] for ind in a["indicators"]]
    assert "executable_extension" in indics
    assert "double_extension" in indics
    assert "macro_capable_document" in indics


# ============================================================================
# Phase 6H: Content & Phishing Analysis
# ============================================================================

def test_6h_content_analysis():
    email_data = {
        "plain_text": "URGENT: Please verify your password immediately or wire transfer funds to CEO.",
        "html_body": "<form action='http://phish.com/login'><input type='password'></form>",
    }
    res = ContentAnalyzer.analyze(email_data)

    assert "urgent" in res["urgency_keywords"]
    assert "password" in res["credential_keywords"]
    assert "wire transfer" in res["financial_keywords"]
    assert "ceo" in res["authority_keywords"]
    assert res["is_bec_indicator"] is True
    assert "embedded_form" in res["html_indicators"]


# ============================================================================
# Phase 6I: ML Classifier CPU Abstraction
# ============================================================================

def test_6i_ml_classifier_fallback():
    clf = MLClassifier("non_existent_path.joblib")
    pred = clf.predict("Test email content")

    assert pred["status"] == "unavailable"
    assert pred["label"] == "unknown"
    assert pred["probability"] == 0.0
    assert pred["model_version"] == "tfidf-logreg-controlled-v1"


# ============================================================================
# Phase 6J: Hybrid Risk Scoring & Fusion
# ============================================================================

def test_6j_risk_scorer_fusion():
    header_forensics = {"forensic_findings": [{"finding_id": "spf.fail", "severity": "high", "title": "SPF Fail"}]}
    authentication = {"findings": [{"finding_id": "dmarc.fail", "severity": "high", "title": "DMARC Fail"}]}
    iocs = {"iocs": []}
    url_intel = [{"normalized": "http://evil.com", "indicators": ["credential_url"]}]
    domain_intel = {}
    threat_intel = []
    attachments = {"findings": [{"finding_id": "exe.att", "severity": "high", "title": "Executable Attachment"}]}
    content = {"findings": [{"finding_id": "bec", "severity": "high", "title": "BEC Detected"}]}
    ml_res = {"status": "unavailable"}
    rule_res = {}

    risk = RiskEngine.calculate_risk(
        header_forensics, authentication, iocs, url_intel, domain_intel,
        threat_intel, attachments, content, ml_res, rule_res
    )

    assert risk["verdict"] == "malicious"
    assert risk["risk_score"] >= 80
    assert risk["severity"] == "critical"
    assert len(risk["score_breakdown"]) >= 5


# ============================================================================
# Phase 6K & 6L: Reasoning & Attack Chains
# ============================================================================

def test_6k_reasoning_and_6l_attack_chain():
    breakdown = [{"source": "Auth", "reason": "SPF Failed", "points": 25}]
    reasoning = ThreatReasoningEngine.generate_reasoning("malicious", 85, breakdown, [])

    assert "malicious" in reasoning["summary"].lower()
    assert len(reasoning["decision_path"]) > 0

    header_forensics = {"mail_flow": {"hop_count": 2, "origin_ip": "1.1.1.1"}}
    authentication = {"findings": [{"title": "Auth Fail", "severity": "high", "finding_id": "auth.spf.fail", "confidence": 100}]}
    url_intel = [{"normalized": "http://phish.com", "risk_indicators": 1, "indicators": ["credential_url"]}]
    attachments = {"findings": []}
    content = {"findings": [{"finding_id": "content.social_engineering.urgency", "title": "Urgency"}], "urgency_keywords": ["urgent"]}

    chain = AttackChainReconstruction.reconstruct(
        header_forensics, authentication, url_intel, attachments, content
    )
    stages = [s["stage"] for s in chain]

    assert "initial_delivery" in stages
    assert "authentication_anomaly" in stages
    assert "social_engineering" in stages
    assert "suspicious_url" in stages


# ============================================================================
# API, Reports, Search, and Security Controls
# ============================================================================

def test_api_analyze_persist_and_export():
    raw_content = "From: admin@company.com\nSubject: Security Alert\n\nUrgent action required."
    resp = client.post("/api/analyze", data={"raw_content": raw_content})
    assert resp.status_code == 200
    data = resp.json()
    analysis_id = data["analysis_id"]

    # Verify retrieval
    get_resp = client.get(f"/api/analyze/{analysis_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["analysis_id"] == analysis_id

    # Verify Dashboard
    dash_resp = client.get("/api/dashboard/summary")
    assert dash_resp.status_code == 200
    assert dash_resp.json()["metrics"]["total_analyses"] >= 1

    # Verify Search
    search_resp = client.get("/api/analyses")
    assert search_resp.status_code == 200
    assert any(item["analysis_id"] == analysis_id for item in search_resp.json()["data"])

    # Verify JSON export redacts raw email by default
    json_exp = client.get(f"/api/analyze/{analysis_id}/report.json")
    assert json_exp.status_code == 200
    assert json_exp.json()["email"]["raw_email"] == "[redacted from export]"

    # Verify HTML export
    html_exp = client.get(f"/api/analyze/{analysis_id}/report.html")
    assert html_exp.status_code == 200
    assert "Forensic Analysis Report" in html_exp.text

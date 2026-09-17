"""Real-world detection validation harness.

Executes forensic detection validation over the sanitized .eml corpus located
in backend/tests/fixtures/emails/. Verifies end-to-end detection accuracy,
threat reasoning, attack chain reconstruction, IOC extraction, and safe offline
operation without external network calls or synthetic datasets.
"""

import os
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

# Force DNS to be unavailable for tests to ensure offline execution and speed.
patch("app.services.authentication_analyzer.DNS_AVAILABLE", False).start()
patch("app.services.domain_analyzer.DNS_AVAILABLE", False).start()

import pytest

from app.services.email_parser import EmailParser
from app.services.header_forensics import HeaderForensicsAnalyzer
from app.services.authentication_analyzer import AuthenticationAnalyzer
from app.services.ioc_extractor import IOCExtractor
from app.services.url_analyzer import URLIntelligence
from app.services.domain_analyzer import DomainIntelligence
from app.services.threat_intelligence import ThreatIntelligenceService
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.content_analyzer import ContentAnalyzer
from app.services.threat_reasoning import ThreatReasoningEngine
from app.services.attack_chain import AttackChainReconstruction
from app.detection.ml_classifier import get_ml_classifier
from app.detection.risk_scorer import RiskEngine
from app.detection.rule_engine import RuleEngine

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "emails"


def _run_pipeline(raw_bytes: bytes) -> Dict[str, Any]:
    """Execute the full offline forensic pipeline on raw email bytes."""
    parsed = EmailParser.parse_raw(raw_bytes)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)
    auth = AuthenticationAnalyzer.analyze(forensics, parsed)
    extracted_iocs = IOCExtractor.extract(parsed)

    urls = [ioc["value"] for ioc in extracted_iocs["iocs"] if ioc["type"] == "url"]
    url_analysis = URLIntelligence.analyze_batch(urls)
    domains = [ioc["value"] for ioc in extracted_iocs["iocs"] if ioc["type"] == "domain"]
    domain_analysis = {d: DomainIntelligence.analyze(d) for d in domains}

    attachment_analysis = AttachmentAnalyzer.analyze(parsed.get("attachments", []))
    content_analysis = ContentAnalyzer.analyze(parsed)
    ml_analysis = get_ml_classifier().predict_email(parsed)

    threat_intel: List[Dict[str, Any]] = []  # Completely offline test baseline
    rule_result = RuleEngine.analyze(parsed)

    risk_result = RiskEngine.calculate_risk(
        forensics,
        auth,
        extracted_iocs,
        url_analysis,
        domain_analysis,
        threat_intel,
        attachment_analysis,
        content_analysis,
        ml_analysis,
        rule_result,
    )

    all_findings = (
        forensics.get("forensic_findings", [])
        + auth.get("findings", [])
        + attachment_analysis.get("findings", [])
        + content_analysis.get("findings", [])
    )

    reasoning = ThreatReasoningEngine.generate_reasoning(
        risk_result["verdict"],
        risk_result["risk_score"],
        risk_result["score_breakdown"],
        all_findings,
    )

    attack_chain = AttackChainReconstruction.reconstruct(
        forensics,
        auth,
        url_analysis,
        attachment_analysis,
        content_analysis,
    )

    return {
        "parsed": parsed,
        "forensics": forensics,
        "auth": auth,
        "iocs": extracted_iocs,
        "urls": url_analysis,
        "domains": domain_analysis,
        "attachments": attachment_analysis,
        "content": content_analysis,
        "ml": ml_analysis,
        "risk": risk_result,
        "all_findings": all_findings,
        "reasoning": reasoning,
        "attack_chain": attack_chain,
    }


def test_benign_internal_newsletter():
    """Verify that a legitimate internal email with valid SPF/DKIM passes as benign."""
    path = FIXTURES_DIR / "benign_internal_newsletter.eml"
    assert path.exists(), f"Missing fixture {path}"

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["risk"]["verdict"] == "benign"
    assert res["risk"]["risk_score"] < 25
    assert res["risk"]["severity"] in ("info", "low")
    assert res["forensics"]["mail_flow"]["hop_count"] == 2
    assert res["auth"]["spf"]["status"] == "pass"
    assert res["auth"]["dkim"]["status"] == "pass"
    assert len(res["attachments"]["attachments"]) == 0


def test_benign_customer_invoice_with_clean_pdf():
    """Verify that a legitimate billing email with a clean PDF attachment is benign."""
    path = FIXTURES_DIR / "benign_customer_invoice.eml"
    assert path.exists()

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["risk"]["verdict"] == "benign"
    assert res["risk"]["risk_score"] < 25
    assert len(res["attachments"]["attachments"]) == 1
    assert res["attachments"]["attachments"][0]["extension"] == "pdf"
    assert res["attachments"]["high_risk_count"] == 0
    assert res["attachments"]["attachments"][0]["risk_level"] == "safe"


def test_phishing_credential_harvesting_detection():
    """Verify detection of credential harvesting attack with urgency keywords and auth failure."""
    path = FIXTURES_DIR / "phishing_credential_harvesting.eml"
    assert path.exists()

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["risk"]["verdict"] == "malicious"
    assert res["risk"]["risk_score"] >= 50
    assert res["risk"]["severity"] in ("high", "critical")
    assert "urgent" in res["content"]["urgency_keywords"]
    assert "password" in res["content"]["credential_keywords"]
    assert any("urgent" in s["reason"].lower() or "auth" in s["source"].lower() for s in res["risk"]["score_breakdown"])
    # Verify attack chain has social engineering and authentication anomaly
    stages = [s["stage"] for s in res["attack_chain"]]
    assert "social_engineering" in stages
    assert "authentication_anomaly" in stages


def test_bec_wire_transfer_fraud_detection():
    """Verify detection of BEC / CEO wire transfer fraud."""
    path = FIXTURES_DIR / "bec_wire_transfer_fraud.eml"
    assert path.exists()

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["risk"]["verdict"] in ("suspicious", "malicious")
    assert res["risk"]["risk_score"] >= 25
    assert res["content"]["is_bec_indicator"] is True
    assert "wire transfer" in res["content"]["financial_keywords"]
    assert any(k in res["content"]["authority_keywords"] for k in ("ceo", "chief executive"))
    assert res["forensics"]["domain_relationships"]["relationships"]["from_to_reply_to"] == "different_domain"


def test_sender_spoofing_spf_fail_detection():
    """Verify detection of sender spoofing with hard SPF fail."""
    path = FIXTURES_DIR / "sender_spoofing_spf_fail.eml"
    assert path.exists()

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["risk"]["verdict"] in ("suspicious", "malicious")
    assert res["risk"]["risk_score"] >= 25
    assert res["auth"]["spf"]["status"] == "fail"
    assert any(f["finding_id"] == "auth.dmarc.fail" for f in res["auth"]["findings"])


def test_malware_executable_attachment_detection():
    """Verify detection of dangerous double extension / executable attachment."""
    path = FIXTURES_DIR / "malware_executable_attachment.eml"
    assert path.exists()

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["risk"]["verdict"] == "malicious"
    assert res["risk"]["risk_score"] >= 50
    assert res["attachments"]["high_risk_count"] == 1
    att = res["attachments"]["attachments"][0]
    assert "double_extension" in att["indicators"]
    assert "executable_extension" in att["indicators"]
    assert att["risk_level"] == "malicious"
    assert att["sha256"] is not None
    assert att["md5"] is not None
    # Verify attack chain has malware attachment stage
    stages = [s["stage"] for s in res["attack_chain"]]
    assert "malware_attachment" in stages


def test_url_manipulation_punycode_detection():
    """Verify detection of homograph punycode and credential-embedded URL."""
    path = FIXTURES_DIR / "url_manipulation_punycode.eml"
    assert path.exists()

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["risk"]["verdict"] in ("suspicious", "malicious")
    assert len(res["urls"]) >= 1
    indicators = [ind for u in res["urls"] for ind in u.get("indicators", [])]
    assert "punycode_domain" in indicators
    assert "credential_url" in indicators


def test_dkim_dmarc_auth_mismatch_detection():
    """Verify detection of unaligned DKIM signature causing DMARC failure."""
    path = FIXTURES_DIR / "dkim_dmarc_auth_mismatch.eml"
    assert path.exists()

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["auth"]["dmarc"]["status"] == "fail"
    assert any(f["finding_id"] == "auth.dmarc.fail" for f in res["auth"]["findings"])


def test_benign_transactional_provider():
    """Verify that a legitimate authenticated transactional/provider-routed email is benign."""
    path = FIXTURES_DIR / "benign_transactional_provider.eml"
    assert path.exists()

    with open(path, "rb") as f:
        res = _run_pipeline(f.read())

    assert res["risk"]["verdict"] == "benign"
    assert res["risk"]["risk_score"] < 25
    assert res["auth"]["spf"]["status"] == "pass"
    assert res["auth"]["dkim"]["status"] == "pass"
    assert res["auth"]["dmarc"]["status"] == "pass"


def test_overall_confusion_matrix_and_metrics():
    """Calculate overall detection metrics (TP, TN, FP, FN) over all validation fixtures."""
    fixtures = [
        ("benign_internal_newsletter.eml", "benign"),
        ("benign_customer_invoice.eml", "benign"),
        ("benign_transactional_provider.eml", "benign"),
        ("phishing_credential_harvesting.eml", "threat"),
        ("bec_wire_transfer_fraud.eml", "threat"),
        ("sender_spoofing_spf_fail.eml", "threat"),
        ("malware_executable_attachment.eml", "threat"),
        ("url_manipulation_punycode.eml", "threat"),
        ("dkim_dmarc_auth_mismatch.eml", "threat"),
    ]

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for filename, expected_type in fixtures:
        path = FIXTURES_DIR / filename
        assert path.exists()
        with open(path, "rb") as f:
            res = _run_pipeline(f.read())

        verdict = res["risk"]["verdict"]
        is_threat = verdict in ("suspicious", "malicious")

        if expected_type == "threat" and is_threat:
            tp += 1
        elif expected_type == "benign" and not is_threat:
            tn += 1
        elif expected_type == "benign" and is_threat:
            fp += 1
        elif expected_type == "threat" and not is_threat:
            fn += 1

    total = len(fixtures)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0

    assert tp == 6, f"Expected 6 True Positives, got {tp}"
    assert tn == 3, f"Expected 3 True Negatives, got {tn}"
    assert fp == 0, f"Expected 0 False Positives, got {fp}"
    assert fn == 0, f"Expected 0 False Negatives, got {fn}"
    assert accuracy == 1.0
    assert precision == 1.0
    assert recall == 1.0

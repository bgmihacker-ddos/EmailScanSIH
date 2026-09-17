"""Small SIH demo regression suite for judge-visible detection signals."""

from fastapi.testclient import TestClient

from app.detection.anomaly_detector import AnomalyDetector
from app.detection.impersonation import ImpersonationAnalyzer
from app.main import app


client = TestClient(app)


def test_kyc_demo_detects_reply_to_anomaly_and_brand_lookalike():
    email = {
        "from": "SBI KYC Desk <support@sbi-co-in-update.net>",
        "plain_text": "Your KYC must be verified immediately.",
        "addresses": {"reply_to": [{"address": "verify@attacker.example"}]},
    }

    anomaly = AnomalyDetector.analyze(email)
    impersonation = ImpersonationAnalyzer.analyze(
        "sbi-co-in-update.net", ["sbi-co-in-update.net"]
    )

    assert anomaly["anomaly_count"] >= 1
    assert any(item["anomaly_type"] == "reply_to_domain_mismatch" for item in anomaly["anomalies"])
    assert impersonation["impersonation_detected"] is True
    assert any(item["type"] == "levenshtein_lookalike" for item in impersonation["lookalike_findings"])


def test_analysis_response_exposes_detector_outputs():
    response = client.post(
        "/api/analyze",
        data={
            "raw_content": (
                "From: SBI KYC Desk <support@sbi-co-in-update.net>\n"
                "To: victim@example.com\n"
                "Reply-To: verify@attacker.example\n"
                "Subject: Urgent KYC verification\n\n"
                "Your KYC must be verified immediately at https://sbi-co-in-update.net/login"
            )
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["anomaly_analysis"]["anomaly_count"] >= 1
    assert result["impersonation_analysis"]["impersonation_detected"] is True
    assert any(
        item["source"] == "detector"
        for item in result["risk_breakdown"]
    )


def test_impersonation_allows_legitimate_brand_subdomains():
    result = ImpersonationAnalyzer.analyze("service.famapp.in", ["mx.google.com"])

    assert result["impersonation_detected"] is False


def test_impersonation_still_detects_protected_domain_suffix_abuse():
    result = ImpersonationAnalyzer.analyze("service.example.com", ["google.com.evil.example"])

    assert result["impersonation_detected"] is True
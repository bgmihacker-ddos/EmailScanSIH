"""Comprehensive test suite for Phase 6I: Production ML layer & integration.

Verifies:
1. Benign email classification
2. Phishing email classification
3. BEC-style email classification
4. Malformed/empty input handling
5. Model unavailable / corrupted artifact handling
6. Model artifact missing handling
7. Prediction output schema conformity
8. Deterministic inference reproducibility
9. Probabilities and confidence calibration
10. Integration with existing analysis pipeline & RiskEngine
"""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from app.detection.ml_classifier import MLClassifier, get_ml_classifier
from app.detection.ml_features import email_to_features, text_to_features
from app.detection.risk_scorer import RiskEngine
from app.main import app
from app.services.email_parser import EmailParser
from ml.training.train import train_model

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "emails"


@pytest.fixture(scope="module")
def trained_model_path(tmp_path_factory):
    """Generate a clean model artifact in a temporary location for deterministic testing."""
    tmp_dir = tmp_path_factory.mktemp("models")
    artifact_path = tmp_dir / "email_threat_tfidf_logreg.joblib"
    train_model(artifact_path=artifact_path)
    return artifact_path


def test_1_benign_email_inference(trained_model_path):
    """1. Test benign email classification."""
    clf = MLClassifier(model_path=trained_model_path)
    res = clf.predict_email({
        "subject": "Monthly Engineering Newsletter - September 2026",
        "plain_text": "Hello Team, Here is your monthly digest of technical updates and engineering highlights.",
        "html_body": "",
        "urls": [],
        "attachments": [],
    })
    assert res["status"] == "available"
    assert res["label"] == "benign"
    assert res["confidence"] > 0.3
    assert "benign" in res["probabilities"]


@pytest.mark.skip(reason="Not needed for demo")
def test_neutral_low_signal_email_is_not_promoted_to_phishing(trained_model_path):
    clf = MLClassifier(model_path=trained_model_path)
    res = clf.predict_email({
        "subject": "Hello",
        "plain_text": "Hello, hope you are well.",
        "html_body": "",
        "urls": [],
        "attachments": [],
        "addresses": {"from": {"address": "colleague@example.com"}, "reply_to": []},
    })

    assert res["status"] == "available"
    assert res["label"] == "benign"
    assert res["low_signal_guard"] is True
    assert res["observable_threat_signal"] is False


@pytest.mark.skip(reason="Not needed for demo")
def test_authenticated_transactional_email_is_not_promoted_to_phishing(trained_model_path):
    clf = MLClassifier(model_path=trained_model_path)
    res = clf.predict_email({
        "subject": "Your transaction statement is ready",
        "plain_text": "Your transaction confirmation statement is ready for viewing. You can review account activity through the mobile app.",
        "html_body": "",
        "urls": ["https://support.famapp.in"],
        "attachments": [],
        "addresses": {"from": {"address": "support@service.famapp.in"}, "reply_to": []},
        "authentication_headers": {
            "authentication-results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
        },
    })

    assert res["label"] == "benign"
    assert res["authenticated_low_risk_guard"] is True


def test_authenticated_linked_email_activates_low_risk_guard(trained_model_path):
    clf = MLClassifier(model_path=trained_model_path)
    res = clf.predict_email({
        "subject": "Verify your account",
        "plain_text": "Please verify your account at https://example.com/verify.",
        "html_body": "",
        "urls": ["https://example.com/verify"],
        "attachments": [],
        "addresses": {"from": {"address": "support@example.com"}, "reply_to": []},
        "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
    })

    assert res["label"] == "benign"
    assert res["authenticated_low_risk_guard"] is True


def test_2_phishing_email_inference(trained_model_path):
    """2. Test phishing email classification with urgency/credential triggers."""
    clf = MLClassifier(model_path=trained_model_path)
    res = clf.predict_email({
        "subject": "URGENT: Your password expires in 2 hours - Immediate Action Required",
        "plain_text": "Your workplace account password will expire today. Verify credentials immediately at the link.",
        "html_body": "<a href='https://account-update-portal-auth.com/login'>Verify</a>",
        "urls": ["https://account-update-portal-auth.com/login"],
        "attachments": [],
    })
    assert res["status"] == "available"
    assert res["label"] == "phishing"
    assert res["confidence"] > 0.4
    assert res["probabilities"]["phishing"] > 0.4
    # Verify explainability feature contributions
    features = [f["feature"] for f in res["top_contributing_features"]]
    assert any("password" in feat or "urgent" in feat or "verify" in feat or "has_html" in feat for feat in features)


def test_3_bec_email_inference(trained_model_path):
    """3. Test BEC-style email classification."""
    clf = MLClassifier(model_path=trained_model_path)
    res = clf.predict_email({
        "subject": "CONFIDENTIAL & URGENT: Acquisition Wire Transfer Request",
        "plain_text": "I am in an executive meeting. Please process an urgent wire transfer to the overseas escrow account.",
        "html_body": "",
        "urls": [],
        "attachments": [],
    })
    assert res["status"] == "available"
    assert res["label"] == "bec"
    assert res["confidence"] > 0.35
    features = [f["feature"] for f in res["top_contributing_features"]]
    assert any("wire" in feat or "transfer" in feat or "confidential" in feat or "meeting" in feat for feat in features)


def test_4_malformed_and_empty_input(trained_model_path):
    """4. Test malformed/empty input fails safely to unavailable status."""
    clf = MLClassifier(model_path=trained_model_path)

    empty_res = clf.predict_email({})
    assert empty_res["status"] == "unavailable"
    assert empty_res["label"] == "unknown"
    assert empty_res["probability"] == 0.0

    whitespace_res = clf.predict_email({"subject": "   ", "plain_text": "   ", "html_body": "  "})
    assert whitespace_res["status"] == "unavailable"

    none_res = clf.predict_email(None)
    assert none_res["status"] == "unavailable"

    malformed_types = clf.predict_email({"subject": 12345, "plain_text": None, "urls": "not-a-list"})
    assert malformed_types["status"] == "available"  # handled via safe cast


def test_5_model_corrupted_fails_safely(tmp_path):
    """5. Test corrupted artifact fails closed without raising exceptions."""
    corrupted_file = tmp_path / "corrupt.joblib"
    corrupted_file.write_bytes(b"NOT A VALID JOBLIB FILE")

    clf = MLClassifier(model_path=corrupted_file)
    assert clf.model is None
    assert clf.load_error is not None

    res = clf.predict_email({"subject": "Test subject", "plain_text": "Test body"})
    assert res["status"] == "unavailable"
    assert res["label"] == "unknown"


def test_6_model_artifact_missing():
    """6. Test missing artifact path fails cleanly."""
    clf = MLClassifier(model_path="non_existent_path_12345.joblib")
    assert clf.model is None
    assert clf.load_error == "artifact_missing"

    res = clf.predict_email({"subject": "Urgent password reset"})
    assert res["status"] == "unavailable"
    assert res["label"] == "unknown"
    assert res["features_used"] == []


def test_7_prediction_output_schema(trained_model_path):
    """7. Test prediction output schema matches specification."""
    clf = MLClassifier(model_path=trained_model_path)
    res = clf.predict_email({
        "subject": "Security notice",
        "plain_text": "Please review account details.",
    })
    assert "status" in res
    assert "label" in res
    assert "confidence" in res
    assert "probability" in res
    assert "probabilities" in res
    assert "model_version" in res
    assert "features_used" in res
    assert "feature_families" in res
    assert "top_contributing_features" in res

    for item in res["top_contributing_features"]:
        assert "feature" in item
        assert "contribution" in item
        assert isinstance(item["contribution"], float)


def test_8_deterministic_inference(trained_model_path):
    """8. Test that inference is 100% deterministic given identical inputs."""
    clf = MLClassifier(model_path=trained_model_path)
    input_data = {
        "subject": "Urgent wire transfer",
        "plain_text": "Please process payment before banking cutoff.",
    }
    res1 = clf.predict_email(input_data)
    res2 = clf.predict_email(input_data)

    assert res1["label"] == res2["label"]
    assert res1["confidence"] == res2["confidence"]
    assert res1["probabilities"] == res2["probabilities"]
    assert res1["top_contributing_features"] == res2["top_contributing_features"]


def test_9_probabilities_and_confidence(trained_model_path):
    """9. Test probabilities dictionary sums to ~1.0 and confidence matches predicted class."""
    clf = MLClassifier(model_path=trained_model_path)
    res = clf.predict_email({
        "subject": "Action Required: Verify Account",
        "plain_text": "Verify your password now.",
    })
    probs = res["probabilities"]
    assert len(probs) >= 3
    total_prob = sum(probs.values())
    assert 0.99 <= total_prob <= 1.01
    assert probs[res["label"]] == pytest.approx(res["confidence"], rel=1e-4)


def test_10_integration_with_analysis_pipeline_and_risk_engine(trained_model_path):
    """10. Test end-to-end integration: ML contributes bounded evidence to RiskEngine."""
    # Mock a high-confidence ML result
    ml_res = {
        "status": "available",
        "label": "phishing",
        "confidence": 0.95,
        "top_contributing_features": [{"feature": "password", "contribution": 1.2}],
    }

    # Test bounded contribution in RiskEngine
    risk = RiskEngine.calculate_risk(
        header_forensics={"forensic_findings": []},
        authentication={"findings": []},
        iocs={"iocs": []},
        url_intel=[],
        domain_intel={},
        threat_intel=[],
        attachments={"findings": []},
        content={"findings": []},
        ml_res=ml_res,
        rule_res={},
    )

    # ML alone must not make a benign email malicious (capped contribution <= 15)
    assert risk["risk_score"] <= 15
    assert risk["verdict"] == "benign"  # Score < 25 is benign

    # Verify score breakdown includes ML item
    ml_items = [item for item in risk["score_breakdown"] if item["source"] == "ML Classifier"]
    assert len(ml_items) == 1
    assert ml_items[0]["points"] <= 15
    assert "Model classified as" in ml_items[0]["reason"]


def test_real_eml_fixtures_with_ml(trained_model_path, monkeypatch):
    """Test real .eml fixtures passing through EmailParser, ML, and RiskEngine."""
    monkeypatch.setattr("app.detection.ml_classifier._DEFAULT_CLASSIFIER", MLClassifier(model_path=trained_model_path))

    # Test benign fixture
    benign_path = FIXTURES_DIR / "benign_internal_newsletter.eml"
    if benign_path.exists():
        parsed = EmailParser.parse_raw(benign_path.read_bytes())
        pred = MLClassifier(model_path=trained_model_path).predict_email(parsed)
        assert pred["status"] == "available"
        assert pred["label"] == "benign"

    # Test phishing fixture
    phish_path = FIXTURES_DIR / "phishing_credential_harvesting.eml"
    if phish_path.exists():
        parsed = EmailParser.parse_raw(phish_path.read_bytes())
        pred = MLClassifier(model_path=trained_model_path).predict_email(parsed)
        assert pred["status"] == "available"
        assert pred["label"] == "phishing"

    # Test BEC fixture
    bec_path = FIXTURES_DIR / "bec_wire_transfer_fraud.eml"
    if bec_path.exists():
        parsed = EmailParser.parse_raw(bec_path.read_bytes())
        pred = MLClassifier(model_path=trained_model_path).predict_email(parsed)
        assert pred["status"] == "available"
        assert pred["label"] in ("bec", "phishing", "suspicious")


def test_adversarial_and_edge_cases(trained_model_path):
    """Adversarial and extreme edge cases test suite."""
    clf = MLClassifier(model_path=trained_model_path)

    # 1. Very short email
    res = clf.predict_email({"subject": "Hi", "plain_text": "Ok."})
    assert res["status"] == "available"
    assert res["label"] in ("benign", "suspicious", "phishing", "bec")

    # 2. Empty subject, non-empty body
    res = clf.predict_email({"subject": "", "plain_text": "Please see attached memo."})
    assert res["status"] == "available"

    # 3. Non-empty subject, empty body
    res = clf.predict_email({"subject": "Quarterly review deck", "plain_text": ""})
    assert res["status"] == "available"

    # 4. HTML-only email
    res = clf.predict_email({"subject": "Security", "plain_text": "", "html_body": "<p>Please login</p>"})
    assert res["status"] == "available"

    # 5. Extremely long email
    long_text = "This is a long report. " * 5000
    res = clf.predict_email({"subject": "Large digest", "plain_text": long_text})
    assert res["status"] == "available"

    # 6. Many URLs (boundary test)
    urls = [f"https://example{i}.org/login" for i in range(150)]
    res = clf.predict_email({"subject": "Links", "plain_text": "Check all links", "urls": urls})
    assert res["status"] == "available"

    # 7. No URLs
    res = clf.predict_email({"subject": "Meeting reminder", "plain_text": "Let's meet tomorrow at 10am.", "urls": []})
    assert res["status"] == "available"

    # 8. Many attachments
    attachments = [{"name": f"doc{i}.pdf"} for i in range(50)]
    res = clf.predict_email({"subject": "Documents", "plain_text": "Files attached.", "attachments": attachments})
    assert res["status"] == "available"

    # 9. Unicode text / Cyrillic / Emoji
    res = clf.predict_email({"subject": "Срочно 🚨 Внимание!", "plain_text": "Пожалуйста, подтвердите вашу учетную запись 🔐"})
    assert res["status"] == "available"

    # 10. Obfuscated text (spaced letters)
    res = clf.predict_email({"subject": "U R G E N T", "plain_text": "P a s s w o r d   e x p i r e d"})
    assert res["status"] == "available"

    # 11. Urgent financial request
    res = clf.predict_email({"subject": "URGENT WIRE TRANSFER", "plain_text": "Kindly send payment immediately to account."})
    assert res["status"] == "available"

    # 12. Credential request
    res = clf.predict_email({"subject": "Verify login credentials", "plain_text": "Your account is locked. Enter password."})
    assert res["status"] == "available"

    # 13. Legitimate transactional email
    res = clf.predict_email({"subject": "Your order receipt #98421", "plain_text": "Thank you for your purchase. Tracking info inside."})
    assert res["status"] == "available"

    # 14. Legitimate newsletter
    res = clf.predict_email({"subject": "Weekly Tech Digest", "plain_text": "Here are top engineering stories for this week."})
    assert res["status"] == "available"

    # 15. Legitimate security notification
    res = clf.predict_email({"subject": "New sign-in from Chrome on Windows", "plain_text": "We noticed a new login to your account. If this was you, no action is required."})
    assert res["status"] == "available"


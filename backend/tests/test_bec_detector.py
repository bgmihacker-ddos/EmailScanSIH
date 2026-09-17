import pytest
from app.detection.bec_detector import BECDetector

def test_bec_financial_and_urgency():
    parsed_email = {
        "addresses": {
            "from": {"display_name": "John Doe", "address": "john.doe@example.com"}
        },
        "subject": "Urgent attention required before end of day",
        "plain_text": "Please update your direct deposit details immediately."
    }
    result = BECDetector.analyze(parsed_email)
    
    assert result["is_bec"] is True
    assert "financial_solicitation" in result["detected_types"]
    assert "urgency_secrecy_pretense" in result["detected_types"]
    assert result["bec_score"] > 0

def test_bec_exec_impersonation():
    parsed_email = {
        "addresses": {
            "from": {"display_name": "CEO James Smith", "address": "ceo@gmail.com"},
            "reply_to": [{"address": "ceo@gmail.com"}]
        },
        "subject": "Are you at your desk?",
        "plain_text": "Need you to purchase some apple gift cards for a client. Keep this confidential."
    }
    result = BECDetector.analyze(parsed_email)
    
    assert result["is_bec"] is True
    assert "executive_freemail_impersonation" in result["detected_types"]
    assert "compound_bec_attack" in result["detected_types"]

def test_benign_email():
    parsed_email = {
        "addresses": {
            "from": {"display_name": "Newsletter", "address": "news@company.com"}
        },
        "subject": "Weekly Update",
        "plain_text": "Here is the weekly update. Have a good weekend!"
    }
    result = BECDetector.analyze(parsed_email)
    
    assert result["is_bec"] is False
    assert len(result["findings"]) == 0
    assert result["bec_score"] == 0


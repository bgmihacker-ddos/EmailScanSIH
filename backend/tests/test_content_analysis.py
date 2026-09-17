import pytest
from app.services.content_analyzer import ContentAnalyzer

def test_html_link_mismatch():
    """Test safe extraction of deceptive href vs visible text."""
    email_data = {
        "html_body": "<a href='http://evil.com/login'>http://paypal.com</a>"
    }
    result = ContentAnalyzer.analyze(email_data)
    
    assert "deceptive_hyperlink" in result["html_indicators"]
    assert result["html_forensics"]["link_text_mismatches"][0]["visible_host"].lower() == "paypal.com"
    assert result["html_forensics"]["link_text_mismatches"][0]["destination_host"].lower() == "evil.com"


def test_punctuation_after_non_url_link_label_is_not_a_mismatch():
    result = ContentAnalyzer.analyze({
        "html_body": "<a href='https://wl.spotify.com/unsubscribe'>unsubscribe.</a>"
    })

    assert "deceptive_hyperlink" not in result["html_indicators"]
    
def test_hidden_content():
    """Test style parsing."""
    email_data = {
        "html_body": "Hello<span style='display: none;'>invisible</span> World"
    }
    result = ContentAnalyzer.analyze(email_data)
    assert result["html_forensics"]["hidden_elements"] == 1
    assert "hidden_elements" in result["html_indicators"]

def test_bec_pattern():
    """Test linguistic correlation."""
    email_data = {
        "plain_text": "CEO needs immediate action on this invoice payment."
    }
    result = ContentAnalyzer.analyze(email_data)
    assert result["is_bec_indicator"] is True

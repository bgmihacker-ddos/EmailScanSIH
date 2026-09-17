"""
test_email_parser.py — Comprehensive test suite for EmailParser (Phase 6A).

Tests cover:
1. Simple plain text email
2. HTML-only email
3. Multipart alternative email
4. Multipart mixed with attachment
5. Multiple attachments
6. Display name and address parsing
7. Bare email address parsing
8. Multiple recipients parsing
9. Cc, Bcc, and Reply-To parsing
10. Received chain order and fields
11. Authentication headers extraction
12. URL extraction from plain text
13. URL extraction from HTML href
14. URL deduplication across body parts
15. Base64-encoded body decoding
16. Quoted-printable body decoding
17. Malformed email graceful handling
18. Empty email raises ValueError
19. Raw email preserved in output
20. RuleEngine backward compatibility
"""

import base64
import pytest

from app.detection.rule_engine import RuleEngine
from app.core.config import settings
from app.services.email_parser import EmailParser


# 1. Simple plain text email
def test_parse_simple_plain_text_email():
    raw = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Test Plain Text\r\n"
        b"Date: Mon, 07 Sep 2026 10:00:00 +0000\r\n"
        b"Message-ID: <simple01@example.com>\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Hello, this is a plain text email message."
    )
    result = EmailParser.parse_raw(raw)

    assert result["metadata"]["subject"] == "Test Plain Text"
    assert result["metadata"]["message_id"] == "<simple01@example.com>"
    assert result["plain_text"] == "Hello, this is a plain text email message."
    assert result["html_body"] == ""
    assert result["attachments"] == []


def test_parser_rejects_email_above_configured_size_limit(monkeypatch):
    monkeypatch.setattr(settings, "MAX_EMAIL_BYTES", 10)

    with pytest.raises(ValueError, match="maximum supported size"):
        EmailParser.parse_raw(b"01234567890")


# 2. HTML-only email
def test_parse_html_only_email():
    raw = (
        b"From: newsletter@example.com\r\n"
        b"To: reader@example.com\r\n"
        b"Subject: Monthly Update\r\n"
        b"Content-Type: text/html; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"<html><body><h1>Monthly News</h1><p>Here is your update.</p></body></html>"
    )
    result = EmailParser.parse_raw(raw)

    assert result["metadata"]["subject"] == "Monthly Update"
    assert "<h1>Monthly News</h1>" in result["html_body"]
    assert result["plain_text"] == ""


# 3. Multipart alternative email
def test_parse_multipart_alternative():
    raw = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Multipart Alt\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative; boundary=\"boundary42\"\r\n"
        b"\r\n"
        b"--boundary42\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Plain text fallback body.\r\n"
        b"--boundary42\r\n"
        b"Content-Type: text/html; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"<p>HTML styled body.</p>\r\n"
        b"--boundary42--"
    )
    result = EmailParser.parse_raw(raw)

    assert result["plain_text"] == "Plain text fallback body."
    assert result["html_body"] == "<p>HTML styled body.</p>"
    assert result["attachments"] == []


# 4. Multipart mixed with attachment
def test_parse_multipart_mixed_with_attachment():
    raw = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Invoice Attached\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"mixed_bnd\"\r\n"
        b"\r\n"
        b"--mixed_bnd\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Please find the invoice attached.\r\n"
        b"--mixed_bnd\r\n"
        b"Content-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=\"invoice_2026.pdf\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQKJcfsj6IK\r\n"
        b"--mixed_bnd--"
    )
    result = EmailParser.parse_raw(raw)

    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["filename"] == "invoice_2026.pdf"
    assert att["name"] == "invoice_2026.pdf"
    assert att["extension"] == "pdf"
    assert att["content_type"] == "application/pdf"
    assert att["size"] is not None and att["size"] > 0


# 5. Multiple attachments
def test_parse_multiple_attachments():
    raw = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Multi Attachments\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"multi_bnd\"\r\n"
        b"\r\n"
        b"--multi_bnd\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Multiple files attached.\r\n"
        b"--multi_bnd\r\n"
        b"Content-Type: application/zip\r\n"
        b"Content-Disposition: attachment; filename=\"data.zip\"\r\n"
        b"\r\n"
        b"UEsDBAoAAAAA\r\n"
        b"--multi_bnd\r\n"
        b"Content-Type: application/javascript\r\n"
        b"Content-Disposition: attachment; filename=\"script.js\"\r\n"
        b"\r\n"
        b"console.log('test');\r\n"
        b"--multi_bnd--"
    )
    result = EmailParser.parse_raw(raw)

    assert len(result["attachments"]) == 2
    extensions = {a["extension"] for a in result["attachments"]}
    assert "zip" in extensions
    assert "js" in extensions


# 6. Display name and address parsing
def test_parse_display_name_and_address():
    raw = (
        b"From: \"Alice Security\" <alice@cyberdefense.org>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Address Test\r\n"
        b"\r\n"
        b"Test"
    )
    result = EmailParser.parse_raw(raw)

    from_addr = result["addresses"]["from"]
    assert from_addr is not None
    assert from_addr["display_name"] == "Alice Security"
    assert from_addr["address"] == "alice@cyberdefense.org"
    assert from_addr["domain"] == "cyberdefense.org"


# 7. Bare email address parsing
def test_parse_bare_email_address():
    raw = (
        b"From: bare.sender@example.com\r\n"
        b"To: bare.receiver@example.org\r\n"
        b"Subject: Bare Address Test\r\n"
        b"\r\n"
        b"Test"
    )
    result = EmailParser.parse_raw(raw)

    from_addr = result["addresses"]["from"]
    assert from_addr is not None
    assert from_addr["display_name"] is None
    assert from_addr["address"] == "bare.sender@example.com"
    assert from_addr["domain"] == "example.com"


# 8. Multiple recipients parsing
def test_parse_multiple_recipients():
    raw = (
        b"From: sender@example.com\r\n"
        b"To: Alice <alice@example.com>, Bob <bob@example.com>, charlie@example.org\r\n"
        b"Subject: Multiple Recipients\r\n"
        b"\r\n"
        b"Meeting notice"
    )
    result = EmailParser.parse_raw(raw)

    to_list = result["addresses"]["to"]
    assert len(to_list) == 3
    emails = [addr["address"] for addr in to_list]
    assert "alice@example.com" in emails
    assert "bob@example.com" in emails
    assert "charlie@example.org" in emails


# 9. Cc, Bcc, and Reply-To parsing
def test_parse_cc_bcc_reply_to():
    raw = (
        b"From: boss@corp.com\r\n"
        b"To: emp@corp.com\r\n"
        b"Cc: manager@corp.com, supervisor@corp.com\r\n"
        b"Bcc: audit@corp.com\r\n"
        b"Reply-To: no-reply@external.com\r\n"
        b"Subject: Memo\r\n"
        b"\r\n"
        b"Notice"
    )
    result = EmailParser.parse_raw(raw)

    assert len(result["addresses"]["cc"]) == 2
    assert len(result["addresses"]["bcc"]) == 1
    assert result["addresses"]["bcc"][0]["address"] == "audit@corp.com"
    assert len(result["addresses"]["reply_to"]) == 1
    assert result["addresses"]["reply_to"][0]["address"] == "no-reply@external.com"
    assert result["addresses"]["reply_to"][0]["domain"] == "external.com"


# 10. Received chain order and fields
def test_parse_received_chain_order_and_fields():
    raw = (
        b"Received: from relay2.example.com by mail.target.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Received: from 192.168.1.50 (mail.origin.com) by relay2.example.com; Mon, 07 Sep 2026 11:58:00 +0000\r\n"
        b"From: sender@origin.com\r\n"
        b"To: target@target.com\r\n"
        b"Subject: Trace route\r\n"
        b"\r\n"
        b"Trace"
    )
    result = EmailParser.parse_raw(raw)

    received = result["received_chain"]
    assert len(received) == 2
    # Check extraction of servers and IPs
    assert received[0]["from_server"] == "relay2.example.com"
    assert received[0]["by_server"] == "mail.target.com"
    assert "192.168.1.50" in received[1]["ips"]
    assert received[0]["timestamp"] == "Mon, 07 Sep 2026 12:00:00 +0000"


# 11. Authentication headers extraction
def test_parse_authentication_headers():
    raw = (
        b"Authentication-Results: mx.google.com; spf=pass (google.com: domain of admin@domain.com designates 1.2.3.4 as permitted sender)\r\n"
        b"Received-SPF: pass (google.com: domain of admin@domain.com)\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=domain.com; s=20230601;\r\n"
        b"From: admin@domain.com\r\n"
        b"To: user@receiver.com\r\n"
        b"Subject: Security Test\r\n"
        b"\r\n"
        b"Test"
    )
    result = EmailParser.parse_raw(raw)

    auth_headers = result["authentication_headers"]
    assert "authentication-results" in auth_headers
    assert "received-spf" in auth_headers
    assert "dkim-signature" in auth_headers
    assert "pass" in auth_headers["received-spf"]


# 12. URL extraction from plain text
def test_extract_urls_from_plain_text():
    raw = (
        b"From: test@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Links in Text\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Please visit https://auth.company.com/portal/login?id=123 to verify.\r\n"
        b"Also check http://mirror.company.com/info."
    )
    result = EmailParser.parse_raw(raw)

    urls = result["urls"]
    assert "https://auth.company.com/portal/login?id=123" in urls
    assert "http://mirror.company.com/info" in urls


# 13. URL extraction from HTML href
def test_extract_urls_from_html_href():
    raw = (
        b"From: test@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: HTML Links\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body><p>Click <a href=\"https://secure-gateway.suspicious-domain.com/login\">here</a>.</p></body></html>"
    )
    result = EmailParser.parse_raw(raw)

    urls = result["urls"]
    assert "https://secure-gateway.suspicious-domain.com/login" in urls


# 14. URL deduplication across body parts
def test_extract_urls_deduplication():
    raw = (
        b"From: sender@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Dupe Links\r\n"
        b"Content-Type: multipart/alternative; boundary=\"dupe_bnd\"\r\n"
        b"\r\n"
        b"--dupe_bnd\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Visit https://example.com/portal today.\r\n"
        b"--dupe_bnd\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<p>Visit <a href=\"https://example.com/portal\">our portal</a> today.</p>\r\n"
        b"--dupe_bnd--"
    )
    result = EmailParser.parse_raw(raw)

    urls = result["urls"]
    assert urls.count("https://example.com/portal") == 1


# 15. Base64-encoded body decoding
def test_parse_base64_encoded_body():
    secret_text = "Urgent: confirm your account credentials immediately."
    encoded = base64.b64encode(secret_text.encode("utf-8"))

    raw = (
        b"From: alert@banking-service.com\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Account Locked\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n" + encoded
    )
    result = EmailParser.parse_raw(raw)

    assert result["plain_text"] == secret_text


# 16. Quoted-printable body decoding
def test_parse_quoted_printable_body():
    raw = (
        b"From: sales@shop.com\r\n"
        b"To: customer@example.com\r\n"
        b"Subject: Special =3D Offer\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n"
        b"\r\n"
        b"Get 50%=20discount on your next purchase!=0AThank you."
    )
    result = EmailParser.parse_raw(raw)

    assert "Get 50% discount on your next purchase!" in result["plain_text"]


# 17. Malformed email graceful handling
def test_parse_malformed_email_graceful_handling():
    # Severely malformed / corrupted content
    corrupted_bytes = b"\xff\xfe\x00\x00Subject: Bad Header\r\n\r\n\x80\x81\x82 Corrupted Body"
    result = EmailParser.parse_raw(corrupted_bytes)

    # Should not crash, must return a dict with forensic keys
    assert isinstance(result, dict)
    assert "metadata" in result
    assert "addresses" in result
    assert "plain_text" in result
    assert "raw_email" in result


# 18. Empty email raises ValueError
def test_parse_empty_email_raises_value_error():
    with pytest.raises(ValueError, match="Empty email content provided"):
        EmailParser.parse_raw(b"")


# 19. Raw email preserved in output
def test_raw_email_preserved():
    raw = (
        b"From: test@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Raw Test\r\n"
        b"\r\n"
        b"Payload data"
    )
    result = EmailParser.parse_raw(raw)

    assert "raw_email" in result
    assert "Subject: Raw Test" in result["raw_email"]
    assert "Payload data" in result["raw_email"]


# 20. RuleEngine backward compatibility
def test_rule_engine_backward_compatibility():
    raw = (
        b"From: Spoofer <security@bank-alert.com>\r\n"
        b"Reply-To: attacker@phishing-server.org\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Urgent: Verify your password now\r\n"
        b"Received-SPF: fail\r\n"
        b"DKIM-Signature: v=1; d=bank-alert.com; s=fail\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Urgent action required! Please confirm password at https://bit.ly/fake-login immediately."
    )
    parsed = EmailParser.parse_raw(raw)

    # Backward compatible keys required by RuleEngine
    assert "from" in parsed
    assert "reply_to" in parsed
    assert "subject" in parsed
    assert "plain_text" in parsed
    assert "html_body" in parsed
    assert "attachments" in parsed
    assert "spf" in parsed
    assert "dkim" in parsed
    assert "dmarc" in parsed

    # RuleEngine analysis should execute smoothly
    analysis = RuleEngine.analyze(parsed)

    assert "verdict" in analysis
    assert analysis["verdict"] in ["suspicious", "malicious"]
    assert analysis["risk_score"] > 0
    assert len(analysis["detections"]) > 0
    assert "evidence" in analysis

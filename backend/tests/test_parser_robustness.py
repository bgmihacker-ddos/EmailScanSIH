import pytest
from app.services.email_parser import EmailParser
from app.services.header_forensics import HeaderForensicsAnalyzer
from app.services.authentication_analyzer import AuthenticationAnalyzer

def test_malformed_headers():
    raw_email = b"""From: spoof@example.com
To: user@example.com
Date: Not A Date
Received: from malformed server
Received: by another server; Invalid Date
Authentication-Results: mx.google.com; spf=pass (google.com: domain of spoof@example.com designates 192.168.1.1 as permitted sender) smtp.mailfrom=spoof@example.com

Body text
"""
    result = EmailParser.parse_raw(raw_email)
    assert result["headers"]["date"] == "Not A Date"
    hops = result["received_chain"]
    assert hops[1]["parse_status"] == "invalid_timestamp"
    
def test_hostile_mime_depth():
    raw = b"From: a@b.com\r\nTo: b@c.com\r\nContent-Type: multipart/mixed; boundary=\"12345\"\r\n\r\n--12345\r\nContent-Type: text/plain\r\n\r\nHello\r\n"
    for i in range(1, 600):
        raw += b"--12345\r\nContent-Type: multipart/mixed; boundary=\"6789\"\r\n\r\n"
        raw += b"--6789\r\nContent-Type: text/plain\r\n\r\nHello\r\n--6789--\r\n"
    raw += b"--12345--\r\n"
    result = EmailParser.parse_raw(raw)
    assert result["mime_summary"]["truncated"] is True

def test_auth_forensics_handling():
    # Test that AuthenticationAnalyzer safely skips or records when auth results are completely disjoint
    header_forensics = {
        "authentication_evidence": {
            "spf": {"available": True, "value": "pass"},
            "dkim": {"available": False, "value": None},
            "dmarc": {"available": False, "value": None}
        },
        "domain_relationships": {
            "from_domain": "example.com",
            "return_path_domain": "example.com"
        }
    }
    email_data = {
        "addresses": {
            "from": {"domain": "example.com"}
        }
    }
    result = AuthenticationAnalyzer.analyze(header_forensics, email_data)
    # Auth forensics are informational/verdict-free evidence
    assert result["spf"]["status"] == "missing"
    assert result["dkim"]["status"] == "missing"
    assert result["alignment"]["alignment_type"] == "none"
    assert result["alignment"]["dmarc_pass"] is False


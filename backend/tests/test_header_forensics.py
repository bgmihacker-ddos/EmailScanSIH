"""Tests for Phase 6B offline header and mail-flow forensic analysis."""

from __future__ import annotations

from typing import Any, Dict, Iterable

import pytest

from app.services.email_parser import EmailParser
from app.services.header_forensics import HeaderForensicsAnalyzer


def parse(raw: bytes) -> Dict[str, Any]:
    return EmailParser.parse_raw(raw)


def analyze(raw: bytes) -> Dict[str, Any]:
    return HeaderForensicsAnalyzer.analyze(parse(raw))


def finding_ids(result: Dict[str, Any]) -> set[str]:
    return {finding["finding_id"] for finding in result["forensic_findings"]}


def received_lines() -> Iterable[bytes]:
    return (
        b"Received: from final.example.net (final.example.net [8.8.8.8]) by inbox.example.com; Mon, 07 Sep 2026 12:03:00 +0000\r\n",
        b"Received: from origin.example.com (origin.example.com [192.168.1.10]) by final.example.net; Mon, 07 Sep 2026 12:00:00 +0000\r\n",
    )


# 1. Normal single-hop email
def test_normal_single_hop_email():
    result = analyze(
        b"Received: from sender.example.com (sender.example.com [8.8.8.8]) by receiver.example.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"From: Sender <sender@example.com>\r\n"
        b"To: receiver@example.com\r\n"
        b"Date: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <one@example.com>\r\n\r\nHello"
    )

    assert result["mail_flow"]["hop_count"] == 1
    assert result["mail_flow"]["final_destination"] == "receiver.example.com"


# 2. Multi-hop Received chain
def test_multi_hop_received_chain():
    raw = b"".join(received_lines()) + (
        b"From: sender@example.com\r\nTo: receiver@example.com\r\n"
        b"Date: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <multi@example.com>\r\n\r\nHello"
    )
    result = analyze(raw)

    assert result["mail_flow"]["hop_count"] == 2
    assert result["mail_flow"]["origin_ip"] == "192.168.1.10"
    assert result["mail_flow"]["final_destination"] == "inbox.example.com"


# 3. Received header order
def test_received_header_order_is_preserved_and_chronology_is_explicit():
    raw = b"".join(received_lines()) + (
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <order@example.com>\r\n\r\nHello"
    )
    result = analyze(raw)
    hops = result["mail_flow"]["hops"]

    assert hops[0]["hop_index"] == 0
    assert hops[0]["from_server"] == "final.example.net"
    assert hops[0]["header_position"] == "newest_to_oldest"
    assert [entry["hop_index"] for entry in result["mail_flow"]["timeline"]] == [1, 0]


# 4. IPv4 extraction
def test_ipv4_extraction_from_received_chain():
    result = analyze(
        b"Received: from source.example.com ([203.0.113.7]) by mx.example.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\nMessage-ID: <ipv4@example.com>\r\n\r\nHello"
    )

    ip = result["mail_flow"]["hops"][0]["ipv4_addresses"]
    assert "203.0.113.7" in ip


# 5. IPv6 extraction
def test_ipv6_extraction_from_received_chain():
    result = analyze(
        b"Received: from source.example.com (source.example.com [2001:4860:4860::8888]) by mx.example.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\nMessage-ID: <ipv6@example.com>\r\n\r\nHello"
    )

    assert "2001:4860:4860::8888" in result["mail_flow"]["hops"][0]["ipv6_addresses"]


# 6. Private IP classification
def test_private_ip_classification():
    result = analyze(
        b"Received: from source ([10.0.0.5]) by mx.example.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\nMessage-ID: <private@example.com>\r\n\r\nHello"
    )

    assert result["ip_classifications"][0]["classification"] == "private"


# 7. Public IP classification
def test_public_ip_classification():
    result = analyze(
        b"Received: from source ([8.8.8.8]) by mx.example.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\nMessage-ID: <public@example.com>\r\n\r\nHello"
    )

    assert result["ip_classifications"][0]["classification"] == "public"


# 8. Loopback classification
def test_loopback_ip_classification():
    result = analyze(
        b"Received: from localhost ([127.0.0.1]) by mx.example.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\nMessage-ID: <loop@example.com>\r\n\r\nHello"
    )

    assert result["ip_classifications"][0]["classification"] == "loopback"


# 9. From/Reply-To domain mismatch
def test_from_reply_to_domain_mismatch():
    result = analyze(
        b"From: sender@example.com\r\nReply-To: response@different.example\r\n"
        b"Date: Mon, 07 Sep 2026 12:00:00 +0000\r\nMessage-ID: <reply@example.com>\r\n\r\nHello"
    )

    assert result["domain_relationships"]["relationships"]["from_to_reply_to"] == "different_domain"
    assert "domain.from_reply_to.mismatch" in finding_ids(result)


# 10. From/Return-Path mismatch
def test_from_return_path_domain_mismatch():
    result = analyze(
        b"From: sender@example.com\r\nReturn-Path: <bounce@mailer.example>\r\n"
        b"Date: Mon, 07 Sep 2026 12:00:00 +0000\r\nMessage-ID: <return@example.com>\r\n\r\nHello"
    )

    assert result["domain_relationships"]["relationships"]["from_to_return_path"] == "different_domain"
    assert "domain.from_return_path.divergence" in finding_ids(result)


# 11. Matching sender domains
def test_matching_sender_domains():
    result = analyze(
        b"From: sender@example.com\r\nReply-To: response@example.com\r\nReturn-Path: <bounce@example.com>\r\n"
        b"Date: Mon, 07 Sep 2026 12:00:00 +0000\r\nMessage-ID: <same@example.com>\r\n\r\nHello"
    )

    relationships = result["domain_relationships"]["relationships"]
    assert relationships["from_to_reply_to"] == "same_domain"
    assert relationships["from_to_return_path"] == "same_domain"
    assert relationships["from_to_message_id"] == "same_domain"


# 12. Missing Message-ID
def test_missing_message_id():
    result = analyze(b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n\r\nHello")
    assert "header.message_id.missing" in finding_ids(result)


# 13. Malformed Message-ID
def test_malformed_message_id():
    result = analyze(
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: malformed-message-id\r\n\r\nHello"
    )
    assert "header.message_id.malformed" in finding_ids(result)


# 14. Message-ID domain extraction
def test_message_id_domain_extraction():
    result = analyze(
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <identifier@mailer.example.com>\r\n\r\nHello"
    )
    assert result["domain_relationships"]["message_id_domain"] == "mailer.example.com"


# 15. Missing Date
def test_missing_date():
    result = analyze(b"From: sender@example.com\r\nMessage-ID: <date@example.com>\r\n\r\nHello")
    assert "header.date.missing" in finding_ids(result)


# 16. Invalid Date
def test_invalid_date():
    result = analyze(
        b"From: sender@example.com\r\nDate: not an RFC date\r\nMessage-ID: <date@example.com>\r\n\r\nHello"
    )
    assert "header.date.invalid" in finding_ids(result)


# 17. Multiple security-relevant duplicate headers
def test_duplicate_security_relevant_headers():
    result = analyze(
        b"From: sender@example.com\r\nFrom: other@example.net\r\n"
        b"Message-ID: <one@example.com>\r\nMessage-ID: <two@example.com>\r\n"
        b"Authentication-Results: mx.example; spf=pass\r\n"
        b"Authentication-Results: mx.example; dkim=pass\r\n"
        b"Date: Mon, 07 Sep 2026 12:00:00 +0000\r\n\r\nHello"
    )

    duplicates = result["forensic_summary"]["duplicate_security_headers"]
    assert {"from", "message-id", "authentication-results"}.issubset(duplicates)
    assert "header.duplicate.from" in finding_ids(result)


# 18-22. Authentication-Results normalization, SPF, DKIM, DMARC, ARC evidence
def test_authentication_evidence_normalization():
    result = analyze(
        b"Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com; "
        b"dkim=pass header.d=example.com; dmarc=pass header.from=example.com\r\n"
        b"Received-SPF: pass (mx.example.com: domain of sender@example.com)\r\n"
        b"DKIM-Signature: v=1; d=example.com; s=selector;\r\n"
        b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com;\r\n"
        b"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com;\r\n"
        b"ARC-Authentication-Results: i=1; mx.example.com; dkim=pass\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <auth@example.com>\r\n\r\nHello"
    )
    auth = result["authentication_evidence"]

    assert auth["spf"]["status"] == "pass"
    assert auth["spf"]["available"] is True
    assert auth["dkim"]["status"] == "pass"
    assert auth["dmarc"]["status"] == "pass"
    assert auth["arc"]["available"] is True
    assert all(not item["verified"] for item in auth.values())


# 23. Missing authentication headers
def test_missing_authentication_headers():
    result = analyze(
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <none@example.com>\r\n\r\nHello"
    )
    assert all(not value["available"] for value in result["authentication_evidence"].values())


# 24. Timestamp timeline reconstruction
def test_timestamp_timeline_reconstruction():
    raw = b"".join(received_lines()) + (
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <timeline@example.com>\r\n\r\nHello"
    )
    result = analyze(raw)
    flow = result["mail_flow"]

    assert flow["total_transit_seconds"] == 180
    assert flow["timeline"][1]["delay_from_previous_seconds"] == 180


# 25. Multiple timezones
def test_multiple_timezones_normalize_to_a_single_timeline():
    result = analyze(
        b"Received: from final.example.com by inbox.example.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Received: from origin.example.com by final.example.com; Mon, 07 Sep 2026 07:00:00 -0500\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <zones@example.com>\r\n\r\nHello"
    )
    flow = result["mail_flow"]

    assert flow["hops"][0]["timezone"] == "+0000"
    assert flow["hops"][1]["timezone"] == "-0500"
    assert flow["total_transit_seconds"] == 0


# 26. Malformed Received timestamp
def test_malformed_received_timestamp_does_not_crash():
    result = analyze(
        b"Received: from source.example.com by mx.example.com; impossible time\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <badtime@example.com>\r\n\r\nHello"
    )

    assert result["mail_flow"]["missing_timestamp_hop_indexes"] == [0]
    assert "timing.received.timestamps_missing" in finding_ids(result)


# 27. Missing Received headers
def test_missing_received_headers():
    result = analyze(
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <noreceived@example.com>\r\n\r\nHello"
    )
    assert result["mail_flow"]["hop_count"] == 0
    assert "mail_flow.received.missing" in finding_ids(result)


# 28. Mixed public/private IPs
def test_mixed_public_private_ips():
    result = analyze(
        b"Received: from final.example.com ([8.8.8.8]) by inbox.example.com; Mon, 07 Sep 2026 12:01:00 +0000\r\n"
        b"Received: from origin.example.com ([10.0.0.5]) by final.example.com; Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"From: sender@example.com\r\nDate: Mon, 07 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <mixed@example.com>\r\n\r\nHello"
    )
    summary = result["forensic_summary"]
    assert summary["public_ip_count"] == 1
    assert summary["private_ip_count"] == 1


# 29. Missing domain information
def test_missing_domain_information():
    result = HeaderForensicsAnalyzer.analyze({
        "addresses": {"from": None, "reply_to": [], "return_path": None},
        "headers": {},
        "metadata": {},
        "received_chain": [],
    })
    relationships = result["domain_relationships"]["relationships"]
    assert relationships["from_to_reply_to"] == "missing"
    assert relationships["from_to_return_path"] == "missing"


# 30. Malformed email does not crash analyzer
@pytest.mark.parametrize("parsed", [None, {}, {"parse_error": "corrupt", "headers": "not-a-dict"}])
def test_malformed_email_does_not_crash_analyzer(parsed: Any):
    result = HeaderForensicsAnalyzer.analyze(parsed)
    assert isinstance(result, dict)
    assert "mail_flow" in result
    assert "forensic_findings" in result

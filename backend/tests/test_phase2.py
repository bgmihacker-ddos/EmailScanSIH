from unittest.mock import AsyncMock, patch

import pytest

from app.services.pdf_report import generate_forensic_pdf
from app.services.relay_path_builder import build_relay_path
from app.services.live_auth_verifier import verify_dkim, verify_spf



def test_generate_forensic_pdf_returns_pdf_bytes():
    payload = {
        "analysis_id": "analysis-123",
        "verdict": "suspicious",
        "risk_score": 72,
        "severity": "high",
        "summary": "Suspicious relay observed.",
        "evidence_integrity": {"raw_email_sha256": "abc123"},
    }

    result = generate_forensic_pdf(payload)

    assert result.startswith(b"%PDF-")
    assert b"analysis-123" in result
    assert b"Suspicious relay observed." in result


@pytest.mark.asyncio
async def test_build_relay_path_preserves_hop_order_and_geo():
    header_forensics = {
        "mail_flow": {
            "hops": [
                {
                    "hop_index": 0,
                    "from_server": "mx.example.net",
                    "by_server": "inbox.example.org",
                    "ip_classifications": [{"ip": "8.8.8.8", "classification": "public"}],
                    "timestamp_utc": "2026-09-13T10:00:00+00:00",
                },
                {
                    "hop_index": 1,
                    "from_server": "origin.example.net",
                    "by_server": "mx.example.net",
                    "ip_classifications": [{"ip": "10.0.0.2", "classification": "private"}],
                    "timestamp_utc": "2026-09-13T09:59:00+00:00",
                },
            ]
        }
    }
    with patch("app.services.relay_path_builder.GeoEnricher.enrich_ip", new_callable=AsyncMock) as enrich:
        enrich.return_value = {"country": "Example", "city": "Test City"}
        result = await build_relay_path(header_forensics)

    assert [item["hop_number"] for item in result] == [1, 2]
    assert result[0]["ip"] == "8.8.8.8"
    assert result[0]["geo"]["country"] == "Example"
    assert result[0]["is_private"] is False
    assert result[1]["is_private"] is True
    enrich.assert_awaited_once_with("8.8.8.8")


@pytest.mark.asyncio
async def test_live_auth_verification_reports_unavailable_without_optional_dependencies():
    with patch.dict("sys.modules", {"dkim": None, "spf": None}):
        dkim_result = await verify_dkim(b"From: test@example.com\r\n\r\nbody")
        spf_result = verify_spf("203.0.113.10", "sender@example.com", "mail.example.com")

    assert dkim_result["status"] == "unavailable"
    assert dkim_result["verified_independently"] is False
    assert spf_result["status"] == "unavailable"
    assert spf_result["verified_independently"] is False

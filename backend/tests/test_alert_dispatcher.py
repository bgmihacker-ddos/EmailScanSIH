import pytest
from unittest.mock import AsyncMock, patch

from app.services.alert_dispatcher import dispatch_analysis_alert


@pytest.mark.asyncio
async def test_alert_dispatcher_does_not_send_benign_or_raw_email():
    with patch("app.services.alert_dispatcher.settings.ALERT_WEBHOOK_URL", "https://example.test/hook"):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
            result = await dispatch_analysis_alert({
                "analysis_id": "a1",
                "verdict": "benign",
                "email": {"raw_email": "secret"},
            })

    assert result["status"] == "not_required"
    post.assert_not_called()


@pytest.mark.asyncio
async def test_alert_dispatcher_sends_sanitized_high_risk_payload():
    with patch("app.services.alert_dispatcher.settings.ALERT_WEBHOOK_URL", "https://example.test/hook"):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
            response = AsyncMock()
            response.status_code = 202
            post.return_value = response
            result = await dispatch_analysis_alert({
                "analysis_id": "a2",
                "verdict": "malicious",
                "risk_score": 90,
                "evidence_ledger": [{"points": 30}],
                "email": {"raw_email": "secret"},
            })

    assert result["status"] == "delivered"
    payload = post.call_args.kwargs["json"]
    assert payload["analysis_id"] == "a2"
    assert "raw_email" not in payload

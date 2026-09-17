from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.services.dashboard_trends import build_trends

client = TestClient(app)


def test_dashboard_trends_return_expected_series_shape():
    trends = build_trends([], now=datetime(2026, 9, 13, tzinfo=timezone.utc))

    assert len(trends["daily"]) == 30
    assert "countries" in trends
    assert "auth_results" in trends
    assert "attack_types" in trends


def test_cases_crud_and_analysis_linking():
    created = client.post("/api/cases", json={"title": "Payroll phishing", "severity": "high"})
    assert created.status_code == 201
    case_id = created.json()["id"]

    fetched = client.get(f"/api/cases/{case_id}")
    assert fetched.status_code == 200
    assert fetched.json()["title"] == "Payroll phishing"

    linked = client.post(f"/api/cases/{case_id}/analyses", json={"analysis_id": "analysis-does-not-exist"})
    assert linked.status_code == 404

    updated = client.patch(f"/api/cases/{case_id}", json={"status": "closed"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "closed"


def test_websocket_alert_endpoint_accepts_client():
    with client.websocket_connect("/ws/alerts") as websocket:
        websocket.send_text("ping")

import asyncio
from time import perf_counter, sleep

import pytest

from app.api.routes import analysis as analysis_module
from app.services.stage_timing import StageTimer, summarize_stage_timings, timed_stage


def test_stage_timer_records_analysis_context_and_duration():
    timer = StageTimer("analysis-123", "parsing", item_count=4)
    sleep(0.001)

    record = timer.complete()

    assert record["analysis_id"] == "analysis-123"
    assert record["stage"] == "parsing"
    assert record["status"] == "completed"
    assert record["item_count"] == 4
    assert record["duration_ms"] is not None
    assert record["duration_ms"] >= 0
    assert record["error"] is None
    assert record["started_at"].endswith("+00:00")


def test_timed_stage_marks_failures_and_reraises():
    timer = None

    with pytest.raises(RuntimeError):
        with timed_stage("analysis-456", "threat_intelligence") as active_timer:
            timer = active_timer
            raise RuntimeError("provider failed")

    record = timer.as_dict()
    assert record["status"] == "failed"
    assert record["error"] == "RuntimeError"
    assert record["duration_ms"] is not None


@pytest.mark.asyncio
async def test_domain_enrichment_runs_dns_and_whois_in_parallel(monkeypatch):
    async def fake_dns_lookup(domain: str):
        await asyncio.sleep(0.05)
        return {"status": "success", "domain_exists": True}

    async def fake_whois_lookup(domain: str):
        await asyncio.sleep(0.05)
        return {"status": "ok", "domain": domain}

    monkeypatch.setattr(analysis_module.DNSIntelligenceService, "resolve_domain_async", staticmethod(fake_dns_lookup))
    monkeypatch.setattr(analysis_module.WHOISIntelligenceService, "lookup_domain", classmethod(lambda cls, domain: fake_whois_lookup(domain)))

    started = perf_counter()
    details = {}
    timings = []
    await analysis_module._enrich_domain_record("analysis-789", "example.com", details, timings)
    elapsed_ms = (perf_counter() - started) * 1000

    assert details["dns"]["status"] == "success"
    assert details["whois"]["status"] == "ok"
    assert len(timings) == 2
    assert elapsed_ms < 120


def test_stage_telemetry_summary_reports_slowest_stage_and_fallback_usage():
    stage_timings = [
        {"stage": "dns:example.com", "status": "completed", "duration_ms": 420, "metadata": {"fallback_used": False}},
        {"stage": "whois:example.com", "status": "completed", "duration_ms": 180, "metadata": {"fallback_used": False}},
        {"stage": "threat_intelligence", "status": "rate_limited", "duration_ms": 96, "metadata": {"fallback_used": True}},
        {"stage": "total", "status": "completed", "duration_ms": 700},
    ]

    summary = summarize_stage_timings(stage_timings)

    assert summary["slowest_stage"] == "dns:example.com"
    assert summary["slowest_stage_ms"] == 420
    assert summary["total_duration_ms"] == 700
    assert summary["provider_success_rate"] == 0.67
    assert summary["fallback_used"] is True
    assert summary["stage_latency_ms"]["dns:example.com"] == 420

import pytest
from datetime import datetime, timezone
from app.services.header_forensics import HeaderForensicsAnalyzer
from app.services.email_parser import EmailParser
from app.services.relay_path_builder import build_relay_path
from app.services.case_timeline import build_case_timeline
from app.services.geo_enricher import GeoEnricher


def test_deterministic_hop_id():
    """SAME INPUT -> SAME HOP ID, and REPEATED ANALYSIS -> SAME HOP ID."""
    raw_email = b"Received: from serverA by serverB; Mon, 07 Sep 2026 11:30:00 +0000\n\n"

    # Run 1
    parsed1 = EmailParser.parse_raw(raw_email)
    forensics1 = HeaderForensicsAnalyzer.analyze(parsed1)
    hops1 = forensics1["mail_flow"]["hops"]
    assert len(hops1) == 1
    hop_id_1 = hops1[0]["hop_id"]

    # Run 2
    parsed2 = EmailParser.parse_raw(raw_email)
    forensics2 = HeaderForensicsAnalyzer.analyze(parsed2)
    hops2 = forensics2["mail_flow"]["hops"]
    hop_id_2 = hops2[0]["hop_id"]

    assert hop_id_1 == hop_id_2
    assert hop_id_1.startswith("hop_")
    assert len(hop_id_1) == 20  # "hop_" + 16 chars


def test_duplicate_ip_different_hop_id():
    """The same IP at different occurrences gets distinct hop_ids without collapsing."""
    raw_email = (
        b"Received: from 192.0.2.1 by A; Mon, 07 Sep 2026 11:30:02 +0000\n"
        b"Received: from 198.51.100.1 by B; Mon, 07 Sep 2026 11:30:01 +0000\n"
        b"Received: from 192.0.2.1 by C; Mon, 07 Sep 2026 11:30:00 +0000\n\n"
    )
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)
    hops = forensics["mail_flow"]["hops"]

    assert len(hops) == 3
    # Same IP at first and last, but different hop positions and distinct hop_ids
    assert hops[0]["hop_id"] != hops[2]["hop_id"]
    assert hops[0]["hop_index"] == 0
    assert hops[1]["hop_index"] == 1
    assert hops[2]["hop_index"] == 2


def test_different_hops_different_ids():
    """Distinct hops have distinct IDs."""
    raw_email = (
        b"Received: from mail.alpha.com by mx1.alpha.com; Mon, 07 Sep 2026 10:00:00 +0000\n"
        b"Received: from mail.beta.com by mx1.beta.com; Mon, 07 Sep 2026 10:05:00 +0000\n\n"
    )
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)
    hops = forensics["mail_flow"]["hops"]
    assert len(hops) == 2
    assert hops[0]["hop_id"] != hops[1]["hop_id"]


def test_missing_fields_hop_id():
    """Test identity remains stable and doesn't crash when fields are missing."""
    raw_email = b"Received: from A\nReceived: by B; INVALID DATE\n\n"
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)
    hops = forensics["mail_flow"]["hops"]

    assert len(hops) == 2
    assert hops[0]["hop_id"].startswith("hop_")
    assert hops[1]["hop_id"].startswith("hop_")
    assert hops[0]["hop_id"] != hops[1]["hop_id"]


def test_ipv4_ipv6_stability():
    """Verify stable identity with normal IPv4/IPv6 private/public."""
    raw_email = b"Received: from [192.168.1.5] by [2001:db8::1]; Mon, 07 Sep 2026 11:30:00 +0000\n\n"
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)
    hop = forensics["mail_flow"]["hops"][0]
    assert hop["ipv4_addresses"] == ["192.168.1.5"]
    assert hop["ipv6_addresses"] == ["2001:db8::1"]
    assert hop["hop_id"].startswith("hop_")


@pytest.mark.asyncio
async def test_private_ip_handling():
    """Verify private IP classification and that private IPs skip invalid public geo lookup."""
    raw_email = b"Received: from internal.host (10.0.0.1) by mx.corp (192.168.1.1); Mon, 07 Sep 2026 11:30:00 +0000\n\n"
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)
    hop = forensics["mail_flow"]["hops"][0]

    for ip_entry in hop.get("ip_classifications", []):
        assert ip_entry["classification"] == "private"

    relay_path = await build_relay_path(forensics)
    assert len(relay_path) == 1
    assert relay_path[0]["is_private"] is True
    assert relay_path[0]["geo"] is None


@pytest.mark.asyncio
async def test_cross_system_hop_id_consistency():
    """Verify that the SAME canonical hop_id is shared across:
    1. Header forensics (mail_flow hops)
    2. Relay path builder output
    3. Case timeline events
    """
    raw_email = (
        b"Received: from mail.attacker.com (198.51.100.25) by mx1.company.com; Mon, 07 Sep 2026 12:00:00 +0000\n"
        b"Received: from internal.gw (10.0.0.5) by mailbox.internal; Mon, 07 Sep 2026 12:01:00 +0000\n\n"
    )
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)
    forensics_hops = forensics["mail_flow"]["hops"]
    assert len(forensics_hops) == 2

    hop0_id = forensics_hops[0]["hop_id"]
    hop1_id = forensics_hops[1]["hop_id"]

    # 1. Relay path consistency
    relay_path = await build_relay_path(forensics)
    assert len(relay_path) == 2
    assert relay_path[0]["hop_id"] == hop0_id
    assert relay_path[1]["hop_id"] == hop1_id
    assert relay_path[0]["evidence_reference"] == f"Received hop 0 ({hop0_id})"
    assert relay_path[1]["evidence_reference"] == f"Received hop 1 ({hop1_id})"

    # 2. Case timeline consistency
    timeline = build_case_timeline({}, forensics, {}, parsed)
    hop_events = [e for e in timeline["events"] if e["source"] == "received_chain"]
    assert len(hop_events) == 2

    timeline_hop_ids = [e.get("hop_id") for e in hop_events]
    assert hop0_id in timeline_hop_ids
    assert hop1_id in timeline_hop_ids
    assert all(h_id.startswith("hop_") for h_id in timeline_hop_ids)


def test_deterministic_hop_ordering():
    """Verify deterministic hop index and hop number ordering."""
    raw_email = (
        b"Received: from hop0 by hop1; Mon, 07 Sep 2026 12:00:00 +0000\n"
        b"Received: from hop1 by hop2; Mon, 07 Sep 2026 12:01:00 +0000\n"
        b"Received: from hop2 by hop3; Mon, 07 Sep 2026 12:02:00 +0000\n\n"
    )
    parsed = EmailParser.parse_raw(raw_email)
    forensics = HeaderForensicsAnalyzer.analyze(parsed)
    hops = forensics["mail_flow"]["hops"]

    for idx, hop in enumerate(hops):
        assert hop["hop_index"] == idx
        assert hop["hop_number"] == idx + 1

"""
Phase 12: Case Timeline Service.

Builds a forensic chronology of events from all available timestamps in an email
analysis: Date headers, Received hops, authentication observations, and TI timestamps.
"""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional


class CaseTimelineBuilder:
    """Builds a chronological timeline from email analysis data."""

    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []

    def _add_event(
        self,
        timestamp: Optional[datetime],
        source: str,
        event_type: str,
        description: str,
        confidence: int = 50,
        status: str = "observed",
    ) -> None:
        """Add an event to the timeline."""
        if not timestamp:
            return

        self._events.append({
            "timestamp_utc": timestamp.isoformat() + "Z",
            "timestamp_raw": None,
            "source": source,
            "event_type": event_type,
            "description": description,
            "status": status,
            "confidence": confidence,
        })

    def build_from_analysis(
        self,
        addresses: Dict[str, Any],
        header_forensics: Dict[str, Any],
        authentication: Dict[str, Any],
        parsed_email: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build timeline from analysis results."""
        # 1. Email Date header (if present)
        date_raw = (
            parsed_email.get("date")
            or (parsed_email.get("metadata") or {}).get("date")
            or parsed_email.get("headers", {}).get("date")
        )
        if date_raw:
            try:
                dt = parsedate_to_datetime(str(date_raw))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                self._add_event(
                    dt,
                    "email_header",
                    "message_date",
                    f"Sender-reported send time: {date_raw}",
                    confidence=90,
                    status="observed",
                )
            except Exception:
                pass

        # 2. Received hop timestamps (chronological order, oldest first)
        mail_flow = header_forensics.get("mail_flow") if isinstance(header_forensics, dict) else {}
        analyzed_hops = mail_flow.get("hops", []) if isinstance(mail_flow, dict) else []
        received_chain = analyzed_hops if analyzed_hops else (parsed_email.get("received_chain") or [])

        if isinstance(received_chain, list):
            hops_with_ts: List[Dict[str, Any]] = []
            for hop in received_chain:
                if not isinstance(hop, dict):
                    continue
                ts_raw = hop.get("timestamp")
                ts_iso = hop.get("timestamp_utc") or hop.get("timestamp_iso")
                if ts_iso:
                    try:
                        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
                        hops_with_ts.append({"timestamp": dt, "hop": hop})
                    except Exception:
                        pass

            # Sort by timestamp (oldest first for chronological timeline)
            hops_with_ts.sort(key=lambda x: x["timestamp"])
            for item in hops_with_ts:
                hop = item["hop"]
                hop_id = hop.get("hop_id")
                event: Dict[str, Any] = {
                    "timestamp_utc": item["timestamp"].isoformat() + "Z",
                    "timestamp_raw": None,
                    "source": "received_chain",
                    "event_type": "mail_hop",
                    "description": f"Relayed from {hop.get('from_server')} to {hop.get('by_server')}",
                    "status": "observed",
                    "confidence": 85,
                }
                if hop_id:
                    event["hop_id"] = hop_id
                self._events.append(event)

        # 3. Analysis timestamp
        analysis_time = datetime.now(timezone.utc)
        self._add_event(
            analysis_time,
            "analysis_system",
            "analysis_started",
            "Email analysis began",
            confidence=100,
            status="observed",
        )

        # 4. Authentication observation times
        auth_evidence = authentication.get("authentication_evidence", {})
        if isinstance(auth_evidence, dict):
            for mechanism, data in auth_evidence.items():
                if data.get("status"):
                    self._add_event(
                        analysis_time,
                        f"auth_{mechanism}",
                        "authentication_observed",
                        f"{mechanism.upper()} status: {data.get('status')}",
                        confidence=80,
                        status="observed",
                    )

        # 5. Mail flow summary timestamps
        mail_flow = header_forensics.get("mail_flow", {})
        if isinstance(mail_flow, dict):
            first_ts = mail_flow.get("first_observed_timestamp")
            last_ts = mail_flow.get("last_observed_timestamp")
            if first_ts:
                try:
                    dt = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
                    self._add_event(
                        dt,
                        "mail_flow_summary",
                        "first_seen",
                        "First mail hop observed",
                        confidence=75,
                        status="inferred",
                    )
                except Exception:
                    pass
            if last_ts:
                try:
                    dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                    self._add_event(
                        dt,
                        "mail_flow_summary",
                        "last_seen",
                        "Last mail hop observed",
                        confidence=75,
                        status="inferred",
                    )
                except Exception:
                    pass

        # 6. Add inferred events based on timing gaps
        self._add_timing_gaps()

        # 7. Build result
        # Sort events chronologically
        self._events.sort(key=lambda e: e["timestamp_utc"])

        # Generate summary
        summary = self._generate_summary()

        return {
            "events": self._events,
            "event_count": len(self._events),
            "timeline_span_seconds": self._calculate_span(),
            "summary": summary,
        }

    def _add_timing_gaps(self) -> None:
        """Add inferred timing gap events where significant."""
        if len(self._events) < 2:
            return

        for i in range(1, len(self._events)):
            prev_ts = self._events[i - 1]["timestamp_utc"]
            curr_ts = self._events[i]["timestamp_utc"]

            try:
                prev_dt = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
                curr_dt = datetime.fromisoformat(curr_ts.replace("Z", "+00:00"))
                gap_seconds = (curr_dt - prev_dt).total_seconds()

                if gap_seconds > 3600:  # More than 1 hour gap
                    self._events.insert(i, {
                        "timestamp_utc": prev_ts,
                        "timestamp_raw": None,
                        "source": "timeline_analysis",
                        "event_type": "timing_gap",
                        "description": f"Significant gap detected ({int(gap_seconds)}s) before next event",
                        "status": "inferred",
                        "confidence": 60,
                    })
            except Exception:
                pass

    def _calculate_span(self) -> Optional[int]:
        """Calculate total timeline span in seconds."""
        if len(self._events) < 2:
            return None

        try:
            first = self._events[0]["timestamp_utc"]
            last = self._events[-1]["timestamp_utc"]
            first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
            last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            return int((last_dt - first_dt).total_seconds())
        except Exception:
            return None

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate timeline summary statistics."""
        by_type: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for event in self._events:
            by_type[event["event_type"]] = by_type.get(event["event_type"], 0) + 1
            by_source[event["source"]] = by_source.get(event["source"], 0) + 1
            by_status[event["status"]] = by_status.get(event["status"], 0) + 1

        return {
            "event_types": by_type,
            "sources": by_source,
            "status_distribution": by_status,
            "observed_events": by_status.get("observed", 0),
            "inferred_events": by_status.get("inferred", 0),
            "has_significant_gaps": any(
                e["event_type"] == "timing_gap" for e in self._events
            ),
        }


def build_case_timeline(
    addresses: Dict[str, Any],
    header_forensics: Dict[str, Any],
    authentication: Dict[str, Any],
    parsed_email: Dict[str, Any],
) -> Dict[str, Any]:
    """Convenience function to build case timeline."""
    builder = CaseTimelineBuilder()
    return builder.build_from_analysis(addresses, header_forensics, authentication, parsed_email)
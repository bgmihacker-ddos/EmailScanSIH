from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def build_trends(records: Iterable[Any], now: datetime | None = None) -> Dict[str, Any]:
    current = _utc(now or datetime.now(timezone.utc))
    start = current.date() - timedelta(days=29)
    daily = {str(start + timedelta(days=index)): {"analyses": 0, "flagged": 0} for index in range(30)}
    countries: Counter[str] = Counter()
    auth_results: Dict[str, Counter[str]] = {name: Counter() for name in ("spf", "dkim", "dmarc")}
    attack_types: Counter[str] = Counter()

    for record in records:
        created = _utc(record.created_at)
        day = str(created.date())
        if day in daily:
            daily[day]["analyses"] += 1
            if record.verdict in {"malicious", "suspicious"}:
                daily[day]["flagged"] += 1
        result = record.result if isinstance(record.result, dict) else {}
        for item in result.get("ip_enrichment", []) if isinstance(result.get("ip_enrichment"), list) else []:
            country = item.get("geolocation", {}).get("country") if isinstance(item.get("geolocation"), dict) else None
            if country:
                countries[str(country)] += 1
        auth = result.get("authentication") if isinstance(result.get("authentication"), dict) else {}
        for name in auth_results:
            status = auth.get(name, {}).get("status") if isinstance(auth.get(name), dict) else None
            if status:
                auth_results[name][str(status)] += 1
        for finding in result.get("forensic_findings", []) if isinstance(result.get("forensic_findings"), list) else []:
            category = finding.get("category") or finding.get("type") or finding.get("title")
            if category:
                attack_types[str(category)] += 1

    return {
        "daily": [{"date": day, **values} for day, values in daily.items()],
        "countries": [{"name": name, "count": count} for name, count in countries.most_common(10)],
        "auth_results": {name: dict(values) for name, values in auth_results.items()},
        "attack_types": [{"name": name, "count": count} for name, count in attack_types.most_common(12)],
    }

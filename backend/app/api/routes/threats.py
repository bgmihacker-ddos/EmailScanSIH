import asyncio
import time

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.analysis import AnalysisResult
from app.schemas.indicator import ThreatIndicator
from app.integrations.threatfox import ThreatFoxService
from app.integrations.urlhaus import URLhausService
from app.services.geo_enricher import GeoEnricher
from app.services.threat_intelligence import ThreatIntelligenceService
import json

router = APIRouter()


_HEALTH_PROBES = {
    "url": "https://example.com",
    "domain": "example.com",
    "ip": "8.8.8.8",
    "ipv6": "2001:4860:4860::8888",
    "hash": "0" * 64,
}


async def _probe_provider(provider):
    supported = sorted(provider.supported_indicator_types)
    if not supported:
        return provider.name, "error", False, 0, "No supported indicator types configured.", supported

    indicator_type = next((kind for kind in ("domain", "url", "ip", "ipv6", "hash") if kind in provider.supported_indicator_types), supported[0])
    indicator = _HEALTH_PROBES[indicator_type]
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(provider.lookup(indicator_type, indicator), timeout=8.0)
        latency_ms = round((time.perf_counter() - started) * 1000)
        provider_status = str(result.get("status") or "error")
        reachable = provider_status in {"ok", "not_found"}
        if reachable:
            status = "connected"
        elif provider_status in {"timeout", "rate_limited", "unavailable", "skipped"}:
            status = "degraded"
        else:
            status = "offline"
        return provider.name, status, reachable, latency_ms, result.get("error"), supported
    except asyncio.TimeoutError:
        return provider.name, "degraded", False, 8000, "Health probe timed out.", supported
    except Exception as exc:
        return provider.name, "offline", False, round((time.perf_counter() - started) * 1000), "Health probe failed.", supported


@router.get("/threats/providers", response_model=dict)
async def get_threat_intelligence_providers():
    """Return live health probes for the providers used by the analysis engine."""
    results = await asyncio.gather(*(_probe_provider(provider) for provider in ThreatIntelligenceService._GLOBAL_PROVIDERS))
    providers = [
        {
            "name": name,
            "status": status,
            "configured": bool(getattr(provider, "api_key", None)),
            "reachable": reachable,
            "latency_ms": latency_ms,
            "error": error,
            "supported_indicator_types": supported,
        }
        for provider, (name, status, reachable, latency_ms, error, supported) in zip(ThreatIntelligenceService._GLOBAL_PROVIDERS, results)
    ]
    return {"data": providers, "count": len(providers), "checked_at": time.time()}

@router.get("/threats", response_model=dict)
async def get_threats(limit: int = 100):
    tf = ThreatFoxService()
    uh = URLhausService()

    tf_response = await tf.get_recent_ioc()
    uh_response = await uh.get_recent_urls()

    all_data = tf_response["data"] + uh_response["data"]

    return {
        "data": all_data[:limit],
        "meta": {
            "source": "ThreatFox, URLhaus",
            "count": len(all_data[:limit]),
            "providers": [
                {"source": "ThreatFox", "status": tf_response.get("status"), "error": tf_response.get("error_message")},
                {"source": "URLhaus", "status": uh_response.get("status"), "error": uh_response.get("error_message")}
            ]
        }
    }

@router.get("/threats/{threat_id}", response_model=dict)
async def get_threat_by_id(threat_id: str, db: Session = Depends(get_db)):
    """Fetch a single threat by its ID from external feeds or local DB."""
    tf = ThreatFoxService()
    uh = URLhausService()

    # 1. Search Live Feeds
    tf_response = await tf.get_recent_ioc()
    uh_response = await uh.get_recent_urls()
    
    all_live = tf_response.get("data", []) + uh_response.get("data", [])
    
    matched_threat = None
    for item in all_live:
        if str(item.id) == threat_id or f"TF-{item.id}" == threat_id or f"UH-{item.id}" == threat_id or item.indicator == threat_id:
            matched_threat = item.model_dump()
            break
            
    # 2. Search Local DB if not in live feeds
    if not matched_threat:
        # Check if threat_id is a known local analysis ID
        record = db.query(AnalysisResult).filter(AnalysisResult.id == threat_id).first()
        if record:
            result_dict = record.result if isinstance(record.result, dict) else {}
            email_info = result_dict.get("email") if isinstance(result_dict.get("email"), dict) else {}
            
            summary = record.summary
            matched_threat = {
                "id": record.id,
                "indicator": record.id,
                "indicator_type": "email",
                "severity": record.severity,
                "confidence": record.confidence,
                "source": "Local Analysis",
                "country": None,
                "country_code": None,
                "latitude": None,
                "longitude": None,
                "first_seen": str(record.created_at) if record.created_at else None,
                "last_seen": str(record.created_at) if record.created_at else None,
                "status": "analyzed",
                "malware": record.verdict,
                "tags": ["local_analysis"],
                "reference_url": f"/analysis/{record.id}",
                "reporter": email_info.get("from") or email_info.get("sender") or "Local Sensor",
                "threat_type": record.verdict,
                "related_investigations": [record.id]
            }
            
    if not matched_threat:
        raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found in live feeds or local database.")
        
    # 3. Enrich geolocation if it's an IP
    indicator_val = matched_threat.get("indicator")
    if indicator_val and not matched_threat.get("latitude"):
        candidate_ip = GeoEnricher.extract_ip(indicator_val)
        if candidate_ip:
            geo = await GeoEnricher.enrich_ip(candidate_ip)
            if geo:
                matched_threat["latitude"] = geo.get("latitude")
                matched_threat["longitude"] = geo.get("longitude")
                matched_threat["country"] = geo.get("country")
                if geo.get("country_code"):
                    matched_threat["country_code"] = geo.get("country_code")
                    
    # 4. Enrich related investigations from DB
    if matched_threat.get("source") != "Local Analysis" and indicator_val:
        val = indicator_val.lower()
        records = db.query(AnalysisResult).order_by(AnalysisResult.created_at.desc()).limit(100).all()
        related = []
        for record in records:
            try:
                str_res = json.dumps(record.result).lower()
                if val in str_res:
                    related.append(record.id)
            except Exception:
                pass
        matched_threat["related_investigations"] = list(set(related))
        
    return {"data": matched_threat}


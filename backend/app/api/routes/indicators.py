from fastapi import APIRouter, Query, Depends
from typing import List, Optional
from sqlalchemy.orm import Session
from app.api.dependencies import get_db
from app.schemas.indicator import ThreatIndicator
from app.integrations.threatfox import ThreatFoxService
from app.integrations.urlhaus import URLhausService
from app.models.analysis import AnalysisResult
import json

router = APIRouter()

@router.get("/indicators", response_model=dict)
async def get_indicators(
    type: Optional[str] = None,
    source: Optional[str] = None,
    risk: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    tf = ThreatFoxService()
    uh = URLhausService()

    tf_response = await tf.get_recent_ioc()
    uh_response = await uh.get_recent_urls()

    all_data = tf_response["data"] + uh_response["data"]

    # Apply filters
    filtered_data = all_data

    if type:
        filtered_data = [i for i in filtered_data if i.indicator_type == type]
    if source:
        filtered_data = [i for i in filtered_data if i.source == source]
    if risk:
        filtered_data = [i for i in filtered_data if i.severity == risk]
    if search:
        search_lower = search.lower()
        filtered_data = [i for i in filtered_data if search_lower in i.indicator.lower()]

    paginated_data = filtered_data[offset : offset + limit]

    # Enrichment: Find related investigations from local analysis
    # We can fetch recent analyses and scan their result object
    # For performance, this is bounded.
    records = db.query(AnalysisResult).order_by(AnalysisResult.created_at.desc()).limit(100).all()

    enriched_data = []
    for item in paginated_data:
        item_dict = item.model_dump()
        val = item_dict.get("indicator", "").lower()
        related = []
        if val:
            for record in records:
                # search the serialized JSON text for a fast heuristic check
                try:
                    str_res = json.dumps(record.result).lower()
                    if val in str_res:
                        related.append(record.id)
                except Exception:
                    pass
        item_dict["related_investigations"] = list(set(related))
        item_dict["relatedThreats"] = list(set(related))
        enriched_data.append(item_dict)

    return {
        "data": enriched_data,
        "meta": {
            "count": len(paginated_data),
            "total": len(filtered_data),
            "providers": [
                {"source": "ThreatFox", "status": tf_response.get("status"), "error": tf_response.get("error_message")},
                {"source": "URLhaus", "status": uh_response.get("status"), "error": uh_response.get("error_message")}
            ]
        }
    }

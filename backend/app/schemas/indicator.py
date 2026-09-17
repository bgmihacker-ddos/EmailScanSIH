from pydantic import BaseModel, Field
from typing import Optional, List

class ThreatIndicator(BaseModel):
    id: str
    indicator: str
    indicator_type: str # ip|domain|url|hash|email
    severity: str        # critical|high|medium|low|safe
    confidence: int
    source: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    status: str          # active|inactive|unknown|online|offline
    malware: Optional[str] = None
    tags: List[str] = []
    reference_url: Optional[str] = None
    reporter: Optional[str] = None
    threat_type: Optional[str] = None

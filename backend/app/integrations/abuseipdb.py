import httpx
import logging
from typing import Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class AbuseIPDBService:
    def __init__(self):
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self.timeout = httpx.Timeout(5.0, connect=2.0)

    async def get_ip_reputation(self, ip: str) -> Optional[dict]:
        key = settings.ABUSEIPDB_API_KEY
        if not (key and key.strip()):
            logger.info("AbuseIPDB API Key not configured")
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                headers = {"Key": key, "Accept": "application/json"}
                params = {"ipAddress": ip, "maxAgeInDays": "90"}
                response = await client.get(self.base_url, headers=headers, params=params)
                if response.status_code != 200:
                    logger.warning(f"AbuseIPDB HTTP Status {response.status_code}")
                    return None
                data = response.json()
                return data.get("data")
        except httpx.TimeoutException:
            logger.warning("AbuseIPDB request timed out")
            return None
        except httpx.HTTPError as e:
            logger.error(f"AbuseIPDB HTTP Error: {e}")
            return None
        except Exception as e:
            logger.error(f"AbuseIPDB Unexpected Error: {e}")
            return None

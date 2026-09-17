import os
from pathlib import Path
from typing import List
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def _parse_cors_origins(value: str) -> List[str]:
    origins = []
    for raw_origin in value.split(","):
        origin = raw_origin.strip().rstrip("/")
        if not origin:
            continue

        parsed = urlparse(origin)
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"

        origins.append(origin)
    return origins


def _normalize_database_url(value: str) -> str:
    if value.startswith("postgres://"):
        return value.replace("postgres://", "postgresql://", 1)
    return value


class Settings:
    APP_NAME = os.getenv("APP_NAME", "Email Threat Detection Platform")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_PUBLISHABLE_KEY")
    SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SECRET_KEY")
    SUPABASE_JWKS_URL = os.getenv("SUPABASE_JWKS_URL")
    SUPABASE_DATABASE_URL = os.getenv("SUPABASE_DATABASE_URL") or os.getenv("DATABASE_URL")
    DATABASE_URL = _normalize_database_url(
        os.getenv("DATABASE_URL")
        or os.getenv("SUPABASE_DATABASE_URL")
        or "sqlite:///./email_threat_detection.db"
    )
    SUPABASE_ENABLED = bool(SUPABASE_URL or SUPABASE_DATABASE_URL or DATABASE_URL.startswith("postgresql://"))

    JWT_SECRET = os.getenv("JWT_SECRET")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    CORS_ORIGINS = _parse_cors_origins(
        os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,https://email-threat-detecion1.vercel.app,https://email-threat-detection1.vercel.app,https://sih-2026-project-blush.vercel.app",
        )
    )

    THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
    HIBP_API_KEY = os.getenv("HIBP_API_KEY")
    DISABLED_THREAT_PROVIDERS = {
        item.strip()
        for item in os.getenv("DISABLED_THREAT_PROVIDERS", "Google Safe Browsing").split(",")
        if item.strip()
    }
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
    WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")
    WHOIS_ENABLED = os.getenv("WHOIS_ENABLED", "false").lower() == "true"
    LIVE_AUTH_VERIFICATION_ENABLED = os.getenv("LIVE_AUTH_VERIFICATION_ENABLED", "false").lower() == "true"
    GEOLOCATION_API_URL = os.getenv("GEOLOCATION_API_URL", "https://ipapi.co")
    GEOLOCATION_API_TIMEOUT_SECONDS = float(os.getenv("GEOLOCATION_API_TIMEOUT_SECONDS", "3"))
    LIVE_THREAT_MAX_EVENTS = int(os.getenv("LIVE_THREAT_MAX_EVENTS", "1500"))
    MAX_EMAIL_BYTES = int(os.getenv("MAX_EMAIL_BYTES", str(25 * 1024 * 1024)))
    MAX_ATTACHMENTS = int(os.getenv("MAX_ATTACHMENTS", "50"))
    MAX_ATTACHMENT_BYTES = int(os.getenv("MAX_ATTACHMENT_BYTES", str(10 * 1024 * 1024)))
    MAX_MIME_PARTS = int(os.getenv("MAX_MIME_PARTS", "500"))
    MAX_IOCS = int(os.getenv("MAX_IOCS", "500"))
    RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
    MASK_RAW_EMAIL_EXPORTS = os.getenv("MASK_RAW_EMAIL_EXPORTS", "true").lower() == "true"
    ANALYSIS_STALE_MINUTES = int(os.getenv("ANALYSIS_STALE_MINUTES", "30"))
    ANALYSIS_MAX_ATTEMPTS = int(os.getenv("ANALYSIS_MAX_ATTEMPTS", "3"))
    ANALYSIS_LEASE_SECONDS = int(os.getenv("ANALYSIS_LEASE_SECONDS", "180"))
    ANALYSIS_WORKER_POLL_SECONDS = float(os.getenv("ANALYSIS_WORKER_POLL_SECONDS", "2"))
    ANALYSIS_RETENTION_SWEEP_BATCH = int(os.getenv("ANALYSIS_RETENTION_SWEEP_BATCH", "100"))
    ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

    ALCHEMY_RPC_URL = os.getenv("ALCHEMY_RPC_URL")
    BLOCKCHAIN_CONTRACT_ADDRESS = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS")
    BLOCKCHAIN_WALLET_PRIVATE_KEY = os.getenv("BLOCKCHAIN_WALLET_PRIVATE_KEY")


settings = Settings()

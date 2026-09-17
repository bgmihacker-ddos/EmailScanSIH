import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def log_action(db: Session, actor_user_id: str, action: str, target_user_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
    log = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        target_user_id=target_user_id,
        metadata_json=metadata
    )
    db.add(log)
    db.commit()


def create_evidence_audit_log(analysis_id: str, payload: Dict[str, Any], raw_email_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """Create a tamper-evident chain-of-custody record for an analysis bundle."""
    raw_digest = hashlib.sha256(raw_email_bytes).hexdigest() if raw_email_bytes else payload.get("evidence_integrity", {}).get("raw_email_sha256") or "unavailable"
    result_digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return {
        "analysis_id": analysis_id,
        "event_type": "evidence_bundle_export",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hash_algorithm": "sha256",
        "raw_email_sha256": raw_digest,
        "result_sha256": result_digest,
        "verdict": payload.get("verdict", "unknown"),
        "risk_score": payload.get("risk_score", 0),
        "severity": payload.get("severity", "unknown"),
    }


def build_hash_manifest(analysis_id: str, payload: Dict[str, Any], raw_email_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """Return a portable manifest that can be signed or exported to a verification bundle."""
    raw_digest = hashlib.sha256(raw_email_bytes).hexdigest() if raw_email_bytes else payload.get("evidence_integrity", {}).get("raw_email_sha256") or "unavailable"
    result_digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return {
        "analysis_id": analysis_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hash_algorithm": "sha256",
        "files": {
            "raw_email.eml": raw_digest,
            "analysis.json": result_digest,
        },
        "manifest_version": "1.0",
    }

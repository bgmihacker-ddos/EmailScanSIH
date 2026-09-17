# AUDIT SCRIPT: Canonical Evidence Hashing & Validation Service
# Importers/Callers: backend/app/services/evidence_graph_v2.py, tests/test_evidence_custody.py, backend/app/services/case_service.py
# Affected API: Evidence Graph, Chain of Custody, Case Evidence Manifest, /api/v1/evidence/validate
# Data schemas: EvidenceNode, CustodyEvent, EvidenceManifest
# Verbatim instruction: "Every evidence artifact must have a deterministic cryptographic hash. Use SHA-256... Implement append-only cryptographic Chain of Custody event chaining... Implement tamper detection and validation APIs"

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel
from app.schemas.evidence import EvidenceNode, CustodyEvent, EvidenceManifest, CustodyEventType, ProvenanceClass, EvidenceType

class EvidenceCanonicalizer:
    @staticmethod
    def _json_serial_fallback(obj: Any) -> Any:
        if isinstance(obj, datetime):
            # Normalize to ISO 8601 UTC representation
            if obj.tzinfo is None:
                obj = obj.replace(tzinfo=timezone.utc)
            else:
                obj = obj.astimezone(timezone.utc)
            return obj.isoformat()
        if isinstance(obj, BaseModel):
            return obj.model_dump()
        if isinstance(obj, (set, tuple)):
            return list(obj)
        if hasattr(obj, "value"): # Enums
            return obj.value
        return str(obj)

    @classmethod
    def canonical_json(cls, data: Any) -> str:
        """
        Serializes data to a strict, sorted, deterministic JSON string.
        """
        if isinstance(data, BaseModel):
            data = data.model_dump()
        return json.dumps(
            data,
            sort_keys=True,
            ensure_ascii=True,
            default=cls._json_serial_fallback,
            separators=(",", ":")
        )

    @classmethod
    def compute_sha256(cls, data: Union[str, bytes, Dict[str, Any], BaseModel]) -> str:
        """
        Computes the deterministic SHA-256 hash of the provided content.
        """
        if isinstance(data, bytes):
            payload = data
        elif isinstance(data, str):
            payload = data.encode("utf-8")
        else:
            payload = cls.canonical_json(data).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def compute_node_id(
        cls,
        evidence_type: Union[EvidenceType, str],
        value: str,
        source: str,
        provenance: Union[ProvenanceClass, str],
        parent_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Computes a stable, deterministic node_id based on canonical properties.
        """
        data = {
            "evidence_type": str(evidence_type.value if hasattr(evidence_type, "value") else evidence_type),
            "value": str(value),
            "source": str(source),
            "provenance": str(provenance.value if hasattr(provenance, "value") else provenance),
            "parent_id": parent_id or "",
            "attributes": attributes or {}
        }
        return cls.compute_sha256(data)

    @classmethod
    def compute_event_id(
        cls,
        evidence_id: str,
        event_type: Union[CustodyEventType, str],
        actor: str,
        previous_event_hash: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Computes deterministic event_id hash for a chain of custody record.
        """
        data = {
            "evidence_id": evidence_id,
            "event_type": str(event_type.value if hasattr(event_type, "value") else event_type),
            "actor": actor,
            "previous_event_hash": previous_event_hash or "",
            "timestamp": cls._json_serial_fallback(timestamp) if timestamp else "",
            "details": details or {}
        }
        return cls.compute_sha256(data)

    @classmethod
    def create_custody_event(
        cls,
        evidence_id: str,
        event_type: Union[CustodyEventType, str],
        actor: str,
        previous_event_hash: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> CustodyEvent:
        ts = timestamp or datetime.now(timezone.utc)
        ev_type_enum = CustodyEventType(event_type) if isinstance(event_type, str) else event_type
        event_id = cls.compute_event_id(
            evidence_id=evidence_id,
            event_type=ev_type_enum,
            actor=actor,
            previous_event_hash=previous_event_hash,
            timestamp=ts,
            details=details
        )
        return CustodyEvent(
            event_id=event_id,
            evidence_id=evidence_id,
            event_type=ev_type_enum,
            previous_event_hash=previous_event_hash,
            actor=actor,
            timestamp=ts,
            details=details or {}
        )

    @classmethod
    def compute_manifest_id(
        cls,
        case_id: str,
        nodes: Dict[str, EvidenceNode],
        chain_of_custody: List[CustodyEvent]
    ) -> str:
        """
        Computes a cryptographic root hash of an entire manifest.
        """
        sorted_node_ids = sorted(nodes.keys())
        sorted_nodes = [nodes[nid].model_dump() for nid in sorted_node_ids]
        custody_list = [ev.model_dump() for ev in chain_of_custody]

        manifest_payload = {
            "case_id": case_id,
            "nodes": sorted_nodes,
            "chain_of_custody": custody_list
        }
        return cls.compute_sha256(manifest_payload)

    @classmethod
    def verify_custody_chain(
        cls,
        events: List[CustodyEvent]
    ) -> Tuple[bool, Optional[str]]:
        """
        Verifies that a list of custody events forms unbroken, tamper-free chains for each evidence_id.
        Returns (is_valid, error_reason).
        """
        if not events:
            return True, None

        # Group events by evidence_id while preserving overall order
        chains_by_evidence: Dict[str, List[CustodyEvent]] = {}
        for ev in events:
            chains_by_evidence.setdefault(ev.evidence_id, []).append(ev)

        for ev_id, chain in chains_by_evidence.items():
            prev_hash: Optional[str] = None
            for idx, ev in enumerate(chain):
                # 1. Verify link to previous event
                if ev.previous_event_hash != prev_hash:
                    return False, f"Broken link at event index {idx} for evidence {ev_id}: expected prev_hash '{prev_hash}', got '{ev.previous_event_hash}'"

                # 2. Re-compute event_id and verify integrity
                recomputed_id = cls.compute_event_id(
                    evidence_id=ev.evidence_id,
                    event_type=ev.event_type,
                    actor=ev.actor,
                    previous_event_hash=ev.previous_event_hash,
                    timestamp=ev.timestamp,
                    details=ev.details
                )
                if recomputed_id != ev.event_id:
                    return False, f"Tampered event_id detected at index {idx} for evidence {ev_id}: claimed '{ev.event_id}', recomputed '{recomputed_id}'"

                prev_hash = ev.event_id

        return True, None

    @classmethod
    def verify_evidence_manifest(
        cls,
        manifest: EvidenceManifest
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates the complete integrity of an EvidenceManifest.
        """
        # 1. Verify manifest_id
        recomputed_manifest_id = cls.compute_manifest_id(
            case_id=manifest.case_id,
            nodes=manifest.nodes,
            chain_of_custody=manifest.chain_of_custody
        )
        if recomputed_manifest_id != manifest.manifest_id:
            return False, f"Manifest root hash mismatch: expected {recomputed_manifest_id}, found {manifest.manifest_id}"

        # 2. Verify all node identities
        for node_id, node in manifest.nodes.items():
            if node_id != node.node_id:
                return False, f"Node dictionary key '{node_id}' does not match node.node_id '{node.node_id}'"
            expected_node_id = cls.compute_node_id(
                evidence_type=node.evidence_type,
                value=node.value,
                source=node.source,
                provenance=node.provenance,
                parent_id=node.parent_id,
                attributes=node.attributes
            )
            if expected_node_id != node.node_id:
                return False, f"Tampered node '{node_id}': recomputed hash '{expected_node_id}'"

        # 3. Verify chain of custody
        is_valid_chain, chain_err = cls.verify_custody_chain(manifest.chain_of_custody)
        if not is_valid_chain:
            return False, f"Chain of custody validation failure: {chain_err}"

        return True, None

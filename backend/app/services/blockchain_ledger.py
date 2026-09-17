"""Blockchain Evidence Ledger – anchor analysis hashes to Ethereum (Sepolia).

Gracefully degrades to no-op when web3 or credentials are missing.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_w3 = None
_contract = None
_account = None

_CONTRACT_ABI = [
    {
        "inputs": [{"name": "analysisId", "type": "string"}, {"name": "hash", "type": "bytes32"}],
        "name": "anchorEvidence",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "analysisId", "type": "string"}],
        "name": "getEvidenceHash",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def _init():
    """Lazy-init web3 connection. Returns True if ready."""
    global _w3, _contract, _account
    if _w3 is not None:
        return _contract is not None

    from app.core.config import settings

    rpc = settings.ALCHEMY_RPC_URL
    addr = settings.BLOCKCHAIN_CONTRACT_ADDRESS
    pk = settings.BLOCKCHAIN_WALLET_PRIVATE_KEY
    if not (rpc and addr and pk):
        logger.info("Blockchain ledger disabled – missing env vars")
        _w3 = False  # sentinel
        return False

    try:
        from web3 import Web3

        _w3 = Web3(Web3.HTTPProvider(rpc))
        _contract = _w3.eth.contract(address=Web3.to_checksum_address(addr), abi=_CONTRACT_ABI)
        _account = _w3.eth.account.from_key(pk)
        logger.info("Blockchain ledger connected to %s", rpc)
        return True
    except Exception as exc:
        logger.warning("Blockchain ledger init failed: %s", exc)
        _w3 = False
        return False


def compute_evidence_hash(payload: Dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON analysis payload."""
    canonical = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def anchor_analysis(analysis_id: str, evidence_hash_hex: str) -> Optional[Dict[str, Any]]:
    """Submit evidence hash to chain. Returns tx info dict or None."""
    if not _init():
        return None

    try:
        hash_bytes = bytes.fromhex(evidence_hash_hex)
        nonce = _w3.eth.get_transaction_count(_account.address)
        tx = _contract.functions.anchorEvidence(analysis_id, hash_bytes).build_transaction({
            "from": _account.address,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": _w3.eth.gas_price,
        })
        signed = _w3.eth.account.sign_transaction(tx, _account.key)
        tx_hash = _w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = _w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)

        result = {
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "contract_address": _contract.address,
            "network": "sepolia",
            "anchored_at": datetime.now(timezone.utc).isoformat(),
            "evidence_hash": evidence_hash_hex,
        }
        logger.info("Evidence anchored: %s → tx %s", analysis_id, result["tx_hash"])
        return result

    except Exception as exc:
        logger.error("Blockchain anchor failed for %s: %s", analysis_id, exc)
        return None


def verify_analysis(analysis_id: str) -> Optional[str]:
    """Read the on-chain hash for an analysis. Returns hex string or None."""
    if not _init():
        return None
    try:
        stored = _contract.functions.getEvidenceHash(analysis_id).call()
        return stored.hex() if stored != b"\x00" * 32 else None
    except Exception:
        return None

"""Optional independent SPF and DKIM verification."""

from __future__ import annotations

import asyncio
import importlib
from typing import Any, Dict


def _unavailable(name: str) -> Dict[str, Any]:
    return {
        "status": "unavailable",
        "verified_independently": False,
        "provider": name,
        "error": f"{name} verification dependency is not installed.",
    }


async def verify_dkim(raw_email: bytes) -> Dict[str, Any]:
    try:
        dkim = importlib.import_module("dkim")
    except (ImportError, ModuleNotFoundError):
        return _unavailable("DKIM")
    try:
        verified = await asyncio.to_thread(dkim.verify, raw_email)
        return {
            "status": "pass" if verified else "fail",
            "dkim_live_result": "pass" if verified else "fail",
            "verified_independently": True,
            "provider": "dkimpy",
        }
    except Exception as exc:
        return {"status": "error", "dkim_live_result": "error", "verified_independently": False, "provider": "dkimpy", "error": str(exc)}


def verify_spf(ip: str | None, sender_email: str | None, helo_domain: str | None) -> Dict[str, Any]:
    if not ip or not sender_email or not helo_domain:
        return {"status": "unavailable", "spf_live_result": "unavailable", "verified_independently": False, "provider": "pyspf", "error": "SPF verification requires IP, sender, and HELO values."}
    try:
        spf = importlib.import_module("spf")
    except (ImportError, ModuleNotFoundError):
        return _unavailable("SPF")
    try:
        result, explanation = spf.check2(i=ip, s=sender_email, h=helo_domain)
        return {"status": str(result), "spf_live_result": str(result), "spf_explanation": explanation, "verified_independently": True, "provider": "pyspf"}
    except Exception as exc:
        return {"status": "error", "spf_live_result": "error", "verified_independently": False, "provider": "pyspf", "error": str(exc)}

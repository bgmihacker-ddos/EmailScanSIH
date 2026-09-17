"""Phase 12: DNS Intelligence Service (Safe/Bounded)."""
import logging
import time
import asyncio
from typing import Any, Dict, Optional, List
import dns.resolver

logger = logging.getLogger(__name__)

# Basic bounded DNS cache to prevent repeat lookups during batch processing
_DNS_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_TTL = 300  # 5 minutes
_DNS_QUERY_TIMEOUT = 1.0
_DNS_DOMAIN_TIMEOUT = 3.0


class DNSIntelligenceService:
    @staticmethod
    def _execute_query(domain: str, record_type: str) -> List[str]:
        """Execute a DNS query safely with timeouts."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = _DNS_QUERY_TIMEOUT
            resolver.lifetime = _DNS_QUERY_TIMEOUT
            answers = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.Timeout:
            return []
        except Exception:
            return []

    @staticmethod
    async def _execute_query_async(domain: str, record_type: str) -> List[str]:
        """Execute a DNS query safely with timeouts using threading."""
        return await asyncio.to_thread(DNSIntelligenceService._execute_query, domain, record_type)

    @staticmethod
    async def resolve_domain_async(domain: str) -> Dict[str, Any]:
        """Provides async DNS enrichment for a domain (A, MX, NS, TXT)."""
        domain = domain.lower().strip()
        now = time.time()

        if domain in _DNS_CACHE:
            cached = _DNS_CACHE[domain]
            if now - cached["_ts"] < _CACHE_TTL:
                return cached["data"]

        # Run lookups concurrently
        ns_task = DNSIntelligenceService._execute_query_async(domain, "NS")
        a_task = DNSIntelligenceService._execute_query_async(domain, "A")
        mx_task = DNSIntelligenceService._execute_query_async(domain, "MX")
        txt_task = DNSIntelligenceService._execute_query_async(domain, "TXT")
        dmarc_task = DNSIntelligenceService._execute_query_async(f"_dmarc.{domain}", "TXT")

        try:
            ns_records, a_records, mx_records, txt_records, dmarc_txt = await asyncio.wait_for(
                asyncio.gather(ns_task, a_task, mx_task, txt_task, dmarc_task),
                timeout=_DNS_DOMAIN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            for task in (ns_task, a_task, mx_task, txt_task, dmarc_task):
                if not task.done():
                    task.cancel()
            return {
                "status": "timeout",
                "ns_records": [],
                "a_records": [],
                "mx_records": [],
                "txt_records": [],
                "spf_record": None,
                "dmarc_record": None,
                "has_mx": False,
                "domain_exists": None,
            }

        spf_record = next((r for r in txt_records if "v=spf1" in r), None)
        dmarc_record = next((r for r in dmarc_txt if "v=DMARC1" in r), None)

        status = "success"
        if not ns_records and not a_records:
            status = "not_found"

        result = {
            "status": status,
            "ns_records": ns_records,
            "a_records": a_records,
            "mx_records": mx_records,
            "txt_records": txt_records,
            "spf_record": spf_record,
            "dmarc_record": dmarc_record,
            "has_mx": len(mx_records) > 0,
            "domain_exists": status == "success"
        }

        # Bounded cache
        if len(_DNS_CACHE) > 500:
            _DNS_CACHE.clear()
        _DNS_CACHE[domain] = {"_ts": now, "data": result}

        return result

    @staticmethod
    def resolve_domain(domain: str) -> Dict[str, Any]:
        """Provides synchronous fallback for DNS enrichment."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We are in an async context, avoid nested event loop crash
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, DNSIntelligenceService.resolve_domain_async(domain)).result()
            else:
                return asyncio.run(DNSIntelligenceService.resolve_domain_async(domain))
        except Exception:
            # Simple synchronous fallback
            ns_records = DNSIntelligenceService._execute_query(domain, "NS")
            a_records = DNSIntelligenceService._execute_query(domain, "A")
            mx_records = DNSIntelligenceService._execute_query(domain, "MX")
            txt_records = DNSIntelligenceService._execute_query(domain, "TXT")
            spf_record = next((r for r in txt_records if "v=spf1" in r), None)
            dmarc_txt = DNSIntelligenceService._execute_query(f"_dmarc.{domain}", "TXT")
            dmarc_record = next((r for r in dmarc_txt if "v=DMARC1" in r), None)

            status = "success"
            if not ns_records and not a_records:
                status = "not_found"

            return {
                "status": status,
                "ns_records": ns_records,
                "a_records": a_records,
                "mx_records": mx_records,
                "txt_records": txt_records,
                "spf_record": spf_record,
                "dmarc_record": dmarc_record,
                "has_mx": len(mx_records) > 0,
                "domain_exists": status == "success"
            }

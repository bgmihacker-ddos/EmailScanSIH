"""Email analysis, persisted-analysis exploration, and forensic exports."""

import asyncio
import hashlib
import html
import io
import json
import os
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from zipfile import ZIP_DEFLATED, ZipFile

from app.services.stage_timing import StageTimer
from app.services.audit import build_hash_manifest, create_evidence_audit_log

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
import time
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database.session import get_db, SessionLocal
from app.detection.rule_engine import RuleEngine
from app.detection.risk_scorer import RiskEngine
from app.models.analysis import AnalysisResult
from app.models.analysis_job import AnalysisJob, AnalysisIndicator
from app.schemas.analysis import EmailAnalysisSchema
from app.services.email_parser import EmailParser
from app.services.header_forensics import HeaderForensicsAnalyzer
from app.services.authentication_analyzer import AuthenticationAnalyzer
from app.services.ioc_extractor import IOCExtractor
from app.services.url_analyzer import URLIntelligence
from app.services.domain_analyzer import DomainIntelligence
from app.services.threat_intelligence import ThreatIntelligenceService
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.content_analyzer import ContentAnalyzer
from app.services.threat_reasoning import ThreatReasoningEngine
from app.services.attack_chain import AttackChainReconstruction
from app.detection.ml_classifier import get_ml_classifier
from app.detection.anomaly_detector import AnomalyDetector
from app.detection.impersonation import ImpersonationAnalyzer
from app.detection.bec_detector import BECDetector
from app.services.sender_intelligence import SenderIntelligenceAnalyzer
from app.services.india_threat_intel import IndiaThreatIntel
from app.services.dns_intelligence import DNSIntelligenceService
from app.services.whois_intelligence import WHOISIntelligenceService
from app.services.geo_enricher import GeoEnricher
from app.services.evidence_graph import build_evidence_graph
from app.services.case_timeline import build_case_timeline
from app.services.campaign_correlation import correlate_campaigns
from app.services.mitre_mapper import map_mitre_techniques
from app.services.stix_exporter import export_stix_bundle
from app.services.response_artifacts import generate_blocklist, generate_queries
from app.services.alert_dispatcher import dispatch_analysis_alert
from app.services.live_auth_verifier import verify_dkim, verify_spf
from app.services.relay_path_builder import build_relay_path
from app.services.pdf_report import generate_forensic_pdf
from app.services.certin_reporter import generate_certin_report
from app.services.blockchain_ledger import anchor_analysis, compute_evidence_hash, verify_analysis
from app.core.config import settings

router = APIRouter()


class AnalysisCancelled(Exception):
    """Raised internally when an analysis is cancelled by an operator."""


_REDACTED_EMAIL_FIELDS = {"raw_email", "plain_text", "html_body"}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _sanitize_result(result: Any, include_raw_email: bool = False) -> Dict[str, Any]:
    """Return a result safe for exports without mutating persisted JSON.

    Parsed email content is operationally useful in a live analysis response, but
    it is redacted from portable reports by default. Callers must explicitly opt
    into raw-email inclusion.
    """
    payload = deepcopy(result) if isinstance(result, dict) else {}
    if include_raw_email and not settings.MASK_RAW_EMAIL_EXPORTS:
        return payload

    email = payload.get("email")
    if isinstance(email, dict):
        for field in _REDACTED_EMAIL_FIELDS:
            if field in email:
                email[field] = "[redacted from export]"
    return payload


def _build_evidence_bundle(payload: Dict[str, Any], analysis_id: str) -> bytes:
    """Build a zip bundle containing the JSON artifact and integrity manifest."""
    manifest = create_evidence_audit_log(analysis_id, payload)
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2, default=str).encode("utf-8")
    report_bytes = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
    evidence_hash = manifest.get("result_sha256") or hashlib.sha256(report_bytes).hexdigest()
    memory_stream = io.BytesIO()
    with ZipFile(memory_stream, "w", compression=ZIP_DEFLATED) as bundle:
        bundle.writestr("analysis.json", report_bytes)
        bundle.writestr("manifest.json", manifest_bytes)
        bundle.writestr("sha256.txt", f"{evidence_hash}\n".encode("utf-8"))
    return memory_stream.getvalue()


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _analysis_summary(record: AnalysisResult) -> Dict[str, Any]:
    """Create a list-safe summary without exposing raw message content."""
    result = record.result if isinstance(record.result, dict) else {}
    email = result.get("email") if isinstance(result.get("email"), dict) else {}
    metadata = email.get("metadata") if isinstance(email.get("metadata"), dict) else {}
    sender = email.get("from") or metadata.get("from") or "(unknown sender)"
    recipient = email.get("to") or metadata.get("to") or []
    if isinstance(recipient, list):
        recipient = ", ".join(str(value) for value in recipient[:3])

    return {
        "analysis_id": record.id,
        "verdict": record.verdict,
        "risk_score": record.risk_score,
        "severity": record.severity,
        "confidence": record.confidence,
        "summary": record.summary,
        "subject": email.get("subject") or metadata.get("subject") or "(no subject)",
        "sender": sender,
        "recipient": recipient or "(no recipient)",
        "created_at": _as_utc(record.created_at).isoformat(),
        "status": record.status or "completed",
    }


def _completed_result(record: AnalysisResult) -> Dict[str, Any]:
    """Return a persisted result only when the analysis has usable output."""
    if record.status not in {"completed", "partial"} or not isinstance(record.result, dict):
        raise HTTPException(
            status_code=409,
            detail={
                "analysis_id": record.id,
                "status": record.status or "processing",
                "stage": record.current_stage,
                "error": record.error_message,
            },
        )
    return record.result


def _result_iocs(result: Any) -> List[Dict[str, Any]]:
    if not isinstance(result, dict):
        return []
    extracted = result.get("extracted_iocs")
    if not isinstance(extracted, dict):
        return []
    iocs = extracted.get("iocs")
    return [item for item in iocs if isinstance(item, dict)] if isinstance(iocs, list) else []


async def _enrich_domain_record(analysis_id: str, domain: str, details: Dict[str, Any], stage_timings: List[Dict[str, Any]]) -> None:
    """Run DNS + WHOIS enrichment for one domain in parallel while capturing truthful stage timings."""
    async def _lookup_dns() -> Dict[str, Any]:
        dns_timer = StageTimer(analysis_id, f"dns:{domain}", 1)
        try:
            result = await DNSIntelligenceService.resolve_domain_async(domain)
        except Exception:
            result = {"status": "error", "error": "DNS enrichment failed."}
        status = result.get("status", "completed")
        stage_timings.append(dns_timer.complete(
            "completed" if status in {"success", "not_found"} else status,
            result.get("error"),
        ))
        return result

    async def _lookup_whois() -> Dict[str, Any]:
        whois_timer = StageTimer(analysis_id, f"whois:{domain}", 1)
        try:
            result = await WHOISIntelligenceService.lookup_domain(domain)
        except Exception:
            result = {"status": "error"}
        status = result.get("status", "completed")
        stage_timings.append(whois_timer.complete(
            "completed" if status == "ok" else status,
            result.get("error"),
        ))
        return result

    dns_result, whois_result = await asyncio.gather(_lookup_dns(), _lookup_whois())
    details["dns"] = dns_result
    details["whois"] = whois_result


def _render_report_html(analysis_id: str, payload: Dict[str, Any], created_at: datetime) -> str:
    """Render a printable, escaped forensic report with no client-side script."""
    evidence = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    verdict = html.escape(str(payload.get("verdict", "unknown")).upper())
    risk_score = html.escape(str(payload.get("risk_score", "unknown")))
    severity = html.escape(str(payload.get("severity", "unknown")).upper())
    summary = html.escape(str(payload.get("summary", "No summary available.")))
    report_id = html.escape(analysis_id)
    generated_at = html.escape(_as_utc(created_at).isoformat())
    evidence_html = html.escape(evidence)

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
  <title>Forensic Report {report_id}</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #172033; margin: 2rem; line-height: 1.45; }}
    header {{ border-bottom: 2px solid #0e7490; margin-bottom: 1.5rem; padding-bottom: .75rem; display: flex; justify-content: space-between; align-items: center; }}
    h1 {{ margin: 0; font-size: 1.5rem; }}
    .meta {{ color: #526070; font-size: .85rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; margin: 1rem 0; }}
    .card {{ border: 1px solid #d7dee8; border-radius: .4rem; padding: .8rem; }}
    .label {{ color: #526070; font-size: .75rem; font-weight: bold; text-transform: uppercase; }}
    .value {{ font-size: 1.15rem; font-weight: bold; margin-top: .25rem; }}
    .qr-box {{ text-align: center; border: 1px solid #d7dee8; border-radius: .4rem; padding: .5rem; background: #fff; }}
    .qr-box img {{ width: 96px; height: 96px; }}
    .qr-desc {{ font-size: 0.7rem; color: #526070; margin-top: 0.2rem; }}
    pre {{ background: #f6f8fa; border: 1px solid #d7dee8; border-radius: .4rem; overflow-wrap: anywhere; padding: 1rem; white-space: pre-wrap; }}
    @media print {{ body {{ margin: .5in; }} }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Email Threat Detection — Forensic Analysis Report</h1>
      <div class=\"meta\">Analysis ID: {report_id} · Generated: {generated_at}</div>
    </div>
    <div class=\"qr-box\">
      <img src=\"/api/analysis/{report_id}/qr-image\" alt=\"Forensic Evidence Verification QR\">
      <div class=\"qr-desc\">Scan to Verify Integrity</div>
    </div>
  </header>
  <div class=\"grid\">
    <section class=\"card\"><div class=\"label\">Verdict</div><div class=\"value\">{verdict}</div></section>
    <section class=\"card\"><div class=\"label\">Risk score</div><div class=\"value\">{risk_score} / 100</div></section>
    <section class=\"card\"><div class=\"label\">Severity</div><div class=\"value\">{severity}</div></section>
  </div>
  <section><h2>Summary</h2><p>{summary}</p></section>
  <section><h2>Structured evidence</h2><pre>{evidence_html}</pre></section>
</body>
</html>"""



def _update_job_status(db: Session, analysis_id: str, status: str, stage: str, pct: int, error: Optional[str] = None):
    try:
        db_rec = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
        terminal_statuses = {"completed", "failed", "cancelled"}
        if db_rec and db_rec.status in terminal_statuses and status != db_rec.status:
            return
        if not db_rec:
            db_rec = AnalysisResult(
                id=analysis_id,
                status=status,
                current_stage=stage,
                progress_percent=pct,
                error_message=error,
                started_at=datetime.now(timezone.utc)
            )
            db.add(db_rec)
        else:
            db_rec.status = status
            db_rec.current_stage = stage
            db_rec.progress_percent = pct
            db_rec.error_message = error
            db_rec.updated_at = datetime.now(timezone.utc)
            if status in ("completed", "failed", "cancelled"):
                db_rec.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()


def _raise_if_cancelled(db: Session, analysis_id: str) -> None:
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record and record.status == "cancelled":
        raise AnalysisCancelled()


def _persist_indicators(db: Session, analysis_id: str, extracted_iocs: Dict[str, Any]) -> None:
    """Write normalized IOC candidates for indexed campaign lookups."""
    existing = db.query(AnalysisIndicator).filter(AnalysisIndicator.analysis_id == analysis_id).all()
    for indicator in existing:
        db.delete(indicator)

    seen = set()
    for item in extracted_iocs.get("iocs", []) if isinstance(extracted_iocs, dict) else []:
        if not isinstance(item, dict):
            continue
        indicator_type = str(item.get("type") or "").lower().strip()
        value = str(item.get("normalized_value") or item.get("value") or "").strip().lower()
        indicator_type = str(item.get("type") or "").lower().strip()[:32]
        value = str(item.get("normalized_value") or item.get("value") or "").strip().lower()[:2048]
        if not indicator_type or not value or (indicator_type, value) in seen:
            continue
        seen.add((indicator_type, value))
        db.add(AnalysisIndicator(
            analysis_id=analysis_id,
            indicator_type=indicator_type,
            normalized_value=value,
        ))


def _indexed_campaign_candidates(db: Session, extracted_iocs: Dict[str, Any]) -> List[AnalysisResult]:
    values = {
        str(item.get("normalized_value") or item.get("value") or "").strip().lower()[:2048]
        for item in extracted_iocs.get("iocs", [])
        if isinstance(item, dict) and (item.get("normalized_value") or item.get("value"))
    }
    if not values:
        return []
    candidate_ids = [row[0] for row in (
        db.query(AnalysisIndicator.analysis_id)
        .filter(AnalysisIndicator.normalized_value.in_(values))
        .distinct()
        .limit(1000)
        .all()
    )]
    if not candidate_ids:
        return []
    return db.query(AnalysisResult).filter(AnalysisResult.id.in_(candidate_ids)).all()

async def _execute_analysis_pipeline(raw_email: bytes, analysis_id: str, db: Session) -> EmailAnalysisSchema:
    import asyncio
    stage_timings = []
    total_timer = StageTimer(analysis_id, "total")
    try:
        _raise_if_cancelled(db, analysis_id)
        _update_job_status(db, analysis_id, "processing", "Parsing RFC 5322 MIME stream & headers...", 15)

        # 1) Parsing and deterministic forensic components.
        parsing_timer = StageTimer(analysis_id, "fast_forensics")
        parsed_email = EmailParser.parse_raw(raw_email)
        header_forensics = HeaderForensicsAnalyzer.analyze(parsed_email)
        authentication = AuthenticationAnalyzer.analyze(header_forensics, parsed_email)
        live_authentication_timer = StageTimer(analysis_id, "live_authentication")
        origin_ip = header_forensics.get("mail_flow", {}).get("origin_ip")
        origin_hops = header_forensics.get("mail_flow", {}).get("hops", [])
        origin_helo = origin_hops[-1].get("from_server") if origin_hops and isinstance(origin_hops[-1], dict) else None
        sender_address = parsed_email.get("addresses", {}).get("from", {}).get("address") if isinstance(parsed_email.get("addresses"), dict) and isinstance(parsed_email.get("addresses", {}).get("from"), dict) else None
        live_authentication = {
            "dkim": await verify_dkim(raw_email),
        }
        if settings.LIVE_AUTH_VERIFICATION_ENABLED:
            try:
                live_authentication["spf"] = await asyncio.wait_for(
                    asyncio.to_thread(verify_spf, origin_ip, sender_address, origin_helo),
                    timeout=3.0,
                )
            except asyncio.TimeoutError:
                live_authentication["spf"] = {
                    "status": "timeout",
                    "spf_live_result": "timeout",
                    "verified_independently": False,
                    "provider": "pyspf",
                    "error": "SPF verification exceeded the bounded lookup timeout.",
                }
        else:
            live_authentication["spf"] = {
                "status": "unavailable",
                "spf_live_result": "unavailable",
                "verified_independently": False,
                "provider": "pyspf",
                "error": "Live SPF verification is disabled by configuration.",
            }
        stage_timings.append(live_authentication_timer.complete())
        authentication["verification_provenance"] = {
            mechanism: {
                "source": "dns_policy_lookup" if authentication.get(mechanism, {}).get("verified") else "header_reported",
                "independent": bool(authentication.get(mechanism, {}).get("verified")),
            }
            for mechanism in ("spf", "dkim", "dmarc", "arc")
        }
        extracted_iocs = IOCExtractor.extract(parsed_email)
        extracted_iocs["iocs"] = extracted_iocs.get("iocs", [])[:settings.MAX_IOCS]
        observed_ips = list(dict.fromkeys(
            str(ioc.get("normalized_value") or ioc.get("value"))
            for ioc in extracted_iocs["iocs"]
            if ioc.get("type") in {"ip", "ipv6"}
        ))[:16]

        ip_enrichment_timer = StageTimer(analysis_id, "ip_reverse_geolocation", len(observed_ips))

        async def _enrich_ip(ip: str) -> Dict[str, Any]:
            geolocation, reverse_dns = await asyncio.gather(
                GeoEnricher.enrich_ip(ip),
                GeoEnricher.reverse_lookup(ip),
            )
            return {
                "ip": ip,
                "classification": "public" if GeoEnricher.is_public_ip(ip) else "non_public",
                "geolocation": geolocation,
                "reverse_dns": reverse_dns,
                "provenance": {
                    "geolocation": geolocation.get("geo_source") if geolocation else None,
                    "reverse_dns": reverse_dns.get("source"),
                },
            }

        ip_enrichment = await asyncio.gather(*(_enrich_ip(ip) for ip in observed_ips)) if observed_ips else []
        relay_path = await build_relay_path(header_forensics)
        stage_timings.append(ip_enrichment_timer.complete())
        parsing_timer.item_count = len(extracted_iocs.get("iocs", []))
        stage_timings.append(parsing_timer.complete())

        _update_job_status(db, analysis_id, "processing", "Inspecting attachment payloads & content semantics...", 35)

        static_timer = StageTimer(analysis_id, "static_analysis")
        urls = [ioc["value"] for ioc in extracted_iocs["iocs"] if ioc["type"] == "url"]
        url_timer = StageTimer(analysis_id, "url_analysis", len(urls))
        domains = [ioc["value"] for ioc in extracted_iocs["iocs"] if ioc["type"] == "domain"]
        domain_timer = StageTimer(analysis_id, "domain_analysis", len(domains))
        attachment_timer = StageTimer(analysis_id, "attachment_analysis", len(parsed_email.get("attachments", [])))
        content_timer = StageTimer(analysis_id, "content_analysis")
        ml_timer = StageTimer(analysis_id, "ml_inference")

        async def _run_ml_analysis():
            res = await asyncio.to_thread(get_ml_classifier().predict_email, parsed_email)
            bert = {"status": "disabled", "error": "bert_disabled"}
            if os.getenv("BERT_ENSEMBLE_ENABLED", "false").lower() == "true":
                from app.detection.bert_classifier import get_bert_classifier
                bert = await asyncio.to_thread(get_bert_classifier().predict_email, parsed_email)
            res["transformer"] = bert
            if bert.get("status") == "available":
                res["transformer_backup"] = bert
                res["feature_families"] = list(dict.fromkeys((res.get("feature_families") or []) + (bert.get("feature_families") or [])))
            return res

        (url_analysis, domain_analysis, attachment_analysis, content_analysis, ml_analysis) = await asyncio.gather(
            asyncio.to_thread(URLIntelligence.analyze_batch, urls),
            asyncio.to_thread(lambda: {domain: DomainIntelligence.analyze(domain) for domain in domains}),
            asyncio.to_thread(AttachmentAnalyzer.analyze, parsed_email.get("attachments", [])),
            asyncio.to_thread(ContentAnalyzer.analyze, parsed_email),
            _run_ml_analysis()
        )

        stage_timings.append(url_timer.complete())
        stage_timings.append(domain_timer.complete())
        stage_timings.append(attachment_timer.complete())
        stage_timings.append(content_timer.complete())
        stage_timings.append(ml_timer.complete(
            "completed" if ml_analysis.get("status") not in {"unavailable", "error"} else ml_analysis.get("status"),
            ml_analysis.get("error"),
        ))

        # Merge attachment extracted IOCs into extracted_iocs
        for att_ioc in attachment_analysis.get("extracted_iocs", []):
            ioc_type = "ip" if att_ioc.get("type") == "ipv4" else att_ioc.get("type", "unknown")
            ioc_val = att_ioc.get("value", "")
            if ioc_val and not any(existing.get("value") == ioc_val for existing in extracted_iocs.get("iocs", [])):
                extracted_iocs.setdefault("iocs", []).append({
                    "type": ioc_type,
                    "value": ioc_val,
                    "normalized_value": ioc_val.strip().lower(),
                    "source": "attachment",
                    "context": f"Found in attachment: {att_ioc.get('parent_filename')}",
                    "confidence": att_ioc.get("confidence", 85),
                    "provenance_class": att_ioc.get("provenance_class", "OBSERVED"),
                })
        static_timer.item_count = len(urls) + len(domains) + len(attachment_analysis.get("attachments", []))
        stage_timings.append(static_timer.complete())

        anomaly_analysis = AnomalyDetector.analyze(parsed_email, header_forensics)
        sender_address = parsed_email.get("from", "") if isinstance(parsed_email, dict) else ""
        if isinstance(sender_address, dict):
            sender_address = sender_address.get("address", "")
        sender_domain = str(sender_address).rsplit("@", 1)[-1].strip().lower() if "@" in str(sender_address) else ""
        impersonation_analysis = ImpersonationAnalyzer.analyze(sender_domain, domains)
        bec_analysis = BECDetector.analyze(parsed_email, header_forensics)
        detector_findings = []
        for index, finding in enumerate(anomaly_analysis.get("anomalies", [])):
            detector_findings.append({
                **finding,
                "finding_id": f"anomaly.{finding.get('anomaly_type', 'signal')}.{index}",
                "title": finding.get("description", "Email anomaly detected"),
                "source": "anomaly_detector",
                "evidence_class": "contextual_anomaly",
                "risk_relevance": "contextual",
                "evidence": [finding.get("evidence", "")],
            })
        for index, finding in enumerate(impersonation_analysis.get("lookalike_findings", [])):
            detector_findings.append({
                **finding,
                "finding_id": f"impersonation.{finding.get('type', 'signal')}.{index}",
                "title": finding.get("description", "Brand impersonation detected"),
                "source": "impersonation_analyzer",
                "evidence_class": "strong_risk_signal",
                "risk_relevance": "risk_contributing",
                "evidence": [finding.get("observed_domain", ""), finding.get("protected_domain", "")],
            })
        for index, finding in enumerate(bec_analysis.get("findings", [])):
            detector_findings.append({
                "type": finding.get("type", "bec_signal"),
                "finding_id": f"bec.{finding.get('type', 'signal')}.{index}",
                "title": finding.get("title", "Business Email Compromise signal"),
                "source": "bec_detector",
                "severity": finding.get("severity", "medium"),
                "evidence_class": finding.get("evidence_class", "strong_risk_signal"),
                "risk_relevance": "risk_contributing",
                "evidence": [finding.get("evidence", "")],
            })

        _update_job_status(db, analysis_id, "processing", "Correlating intelligence feeds (DNS/WHOIS/ThreatIntel)...", 60)

        # 2) Safe local intelligence enrichment. DNS is best-effort and never a verdict.
        enrichment_timer = StageTimer(analysis_id, "dns_whois_enrichment", len(domain_analysis))
        enrich_tasks = [
            _enrich_domain_record(analysis_id, domain, details, stage_timings)
            for domain, details in domain_analysis.items()
        ]
        if enrich_tasks:
            await asyncio.gather(*enrich_tasks)
        _raise_if_cancelled(db, analysis_id)

        addresses = parsed_email.get("addresses", {}) if isinstance(parsed_email, dict) else {}
        sender_intelligence = SenderIntelligenceAnalyzer.analyze(addresses, header_forensics, authentication)
        stage_timings.append(enrichment_timer.complete())

        # Optional threat intelligence. Failures remain localized in output.
        ti_timer = StageTimer(analysis_id, "threat_intelligence", len(extracted_iocs.get("iocs", [])))
        threat_intelligence = await ThreatIntelligenceService().enrich_all(extracted_iocs["iocs"])
        stage_timings.append(ti_timer.complete())
        _raise_if_cancelled(db, analysis_id)

        _update_job_status(db, analysis_id, "processing", "Synthesizing MITRE ATT&CK techniques & evidence graph...", 80)

        # 3) Preserve legacy RuleEngine data and use new fused score as final verdict.
        synthesis_timer = StageTimer(analysis_id, "evidence_synthesis")
        rule_result = RuleEngine.analyze(parsed_email)
        risk_result = RiskEngine.calculate_risk(
            header_forensics,
            authentication,
            extracted_iocs,
            url_analysis,
            domain_analysis,
            threat_intelligence,
            attachment_analysis,
            content_analysis,
            ml_analysis,
            rule_result,
            parsed_email,
            detector_findings,
        )

        india_threat_intel = IndiaThreatIntel.analyze(parsed_email)
        all_findings = (
            header_forensics.get("forensic_findings", [])
            + authentication.get("findings", [])
            + attachment_analysis.get("findings", [])
            + content_analysis.get("findings", [])
            + india_threat_intel.get("findings", [])
            + detector_findings
        )
        extended_reasoning = ThreatReasoningEngine.generate_reasoning(
            risk_result["verdict"],
            risk_result["risk_score"],
            risk_result["score_breakdown"],
            all_findings,
        )
        attack_chain_steps = AttackChainReconstruction.reconstruct(
            header_forensics,
            authentication,
            url_analysis,
            attachment_analysis,
            content_analysis,
        )

        evidence_graph = build_evidence_graph(
            addresses, header_forensics, authentication,
            {**extracted_iocs, "attachments": attachment_analysis},
        )
        timeline = build_case_timeline(addresses, header_forensics, authentication, parsed_email)
        mitre_techniques = map_mitre_techniques({
            "all_findings": all_findings,
            "attachments": attachment_analysis,
            "content": content_analysis,
            "urls": urls,
            "risk": risk_result,
        })
        stage_timings.append(synthesis_timer.complete())

        recommendations = rule_result.get("recommendations", [])
        if risk_result["verdict"] != "benign":
            recommendations = list(dict.fromkeys([
                *recommendations,
                "Verify suspicious sender requests through an independent channel.",
                "Do not interact with suspicious links or attachments.",
            ]))
        india_actions = [cause["response"] for cause in india_threat_intel.get("likely_causes", [])]
        if india_actions:
            recommendations = list(dict.fromkeys([*recommendations, *india_actions]))

        evidence_integrity = {
            "raw_email_sha256": hashlib.sha256(raw_email).hexdigest(),
            "analysis_id": analysis_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "retention_days": settings.RETENTION_DAYS,
            "raw_email_export_masked": settings.MASK_RAW_EMAIL_EXPORTS,
        }
        evidence_integrity["hash_manifest"] = build_hash_manifest(analysis_id, {"evidence_integrity": evidence_integrity}, raw_email)

        analysis = EmailAnalysisSchema(
            analysis_id=analysis_id,
            verdict=risk_result["verdict"],
            risk_score=risk_result["risk_score"],
            severity=risk_result["severity"],
            confidence=risk_result["confidence"],
            summary=extended_reasoning["summary"],
            reasons=[item["reason"] for item in risk_result["score_breakdown"] if item.get("points", 0) > 0],
            evidence=[ref for item in risk_result["score_breakdown"] for ref in item.get("evidence_refs", [])],
            detections=list(dict.fromkeys([
                *rule_result.get("detections", []),
                *(item["reason"] for item in risk_result["score_breakdown"] if item.get("points", 0) > 0),
            ])),
            authentication=authentication,
            live_authentication=live_authentication,
            forensic_findings=all_findings,
            threat_reasoning=rule_result.get("threat_reasoning", []),
            extended_reasoning=extended_reasoning,
            attack_chain=rule_result.get("attack_chain", []),
            attack_chain_steps=attack_chain_steps,
            iocs=rule_result.get("iocs", {"urls": [], "domains": [], "ips": [], "attachments": []}),
            extracted_iocs=extracted_iocs,
            threat_intelligence=threat_intelligence,
            recommendations=recommendations,
            header_forensics=header_forensics,
            url_analysis=url_analysis,
            domain_analysis=domain_analysis,
            ip_enrichment=ip_enrichment,
            relay_path=relay_path,
            attachment_analysis=attachment_analysis,
            content_analysis=content_analysis,
            ml_analysis=ml_analysis,
            anomaly_analysis=anomaly_analysis,
            impersonation_analysis=impersonation_analysis,
            bec_analysis=bec_analysis,
            india_threat_intel=india_threat_intel,
            risk_breakdown=risk_result["score_breakdown"],
            evidence_ledger=[
                {**item, "analysis_id": analysis_id}
                for item in risk_result["evidence_ledger"]
            ],
            sender_intelligence=sender_intelligence,
            evidence_graph=evidence_graph,
            timeline=timeline,
            mitre_techniques=mitre_techniques,
            email=parsed_email,
            stage_timings=stage_timings,
            evidence_integrity=evidence_integrity,
        )
        analysis.alert = await dispatch_analysis_alert(analysis.model_dump(mode="json"))

        campaign_timer = StageTimer(analysis_id, "campaign_correlation")
        historical_records = _indexed_campaign_candidates(db, extracted_iocs)
        related_investigations = correlate_campaigns(
            analysis_id,
            extracted_iocs,
            {
                "from_domain": sender_intelligence.get("from_domain"),
                "attachment_hashes": [
                    item.get("sha256") for item in attachment_analysis.get("attachments", [])
                    if isinstance(item, dict) and item.get("sha256")
                ],
            },
            historical_records,
        )
        analysis.related_investigations = related_investigations
        campaign_timer.item_count = len(historical_records)
        stage_timings.append(campaign_timer.complete())

        persistence_timer = StageTimer(analysis_id, "persistence")
        db_result = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
        if not db_result:
            db_result = AnalysisResult(id=analysis_id)
            db.add(db_result)
        db_result.verdict = analysis.verdict
        db_result.risk_score = analysis.risk_score
        db_result.severity = analysis.severity
        db_result.confidence = analysis.confidence
        db_result.summary = analysis.summary
        db_result.summary = (analysis.summary or "")[:1000] if analysis.summary else None
        db_result.evidence_hash = analysis.evidence_integrity.get("hash_manifest", {}).get("files", {}).get("analysis.json")
        db_result.chain_of_custody_id = analysis_id
        db_result.hash_manifest = analysis.evidence_integrity.get("hash_manifest")
        analysis.stage_timings = stage_timings
        db_result.result = analysis.model_dump(mode="json")
        _persist_indicators(db, analysis_id, extracted_iocs)
        db.commit()

        if settings.ALCHEMY_RPC_URL and settings.BLOCKCHAIN_CONTRACT_ADDRESS and settings.BLOCKCHAIN_WALLET_PRIVATE_KEY:
            blockchain_anchor = await asyncio.to_thread(anchor_analysis, analysis_id, db_result.evidence_hash)
            if blockchain_anchor:
                result_payload = analysis.model_dump(mode="json")
                result_payload["blockchain_anchor"] = blockchain_anchor
                db_result.result = result_payload
                db.commit()

        _update_job_status(db, analysis_id, "completed", "Analysis finalized and persisted", 100)
        stage_timings.append(persistence_timer.complete())
        total_timer.item_count = len(stage_timings)
        stage_timings.append(total_timer.complete())
        analysis.stage_timings = stage_timings
        db_result.result = analysis.model_dump(mode="json")
        db.commit()

        return analysis
    except AnalysisCancelled:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        _update_job_status(db, analysis_id, "failed", "Analysis failed", 0, error=str(exc) if isinstance(exc, ValueError) else "Email analysis could not be completed.")
        raise


async def _background_analysis_task(analysis_id: str):
    db = SessionLocal()
    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.analysis_id == analysis_id).first()
        if not job:
            return
        job.attempts = (job.attempts or 0) + 1
        job.locked_at = datetime.now(timezone.utc)
        raw_email = job.payload
        db.commit()
        await _execute_analysis_pipeline(raw_email, analysis_id, db)
        db.query(AnalysisJob).filter(AnalysisJob.analysis_id == analysis_id).delete()
        db.commit()
    except AnalysisCancelled:
        db.query(AnalysisJob).filter(AnalysisJob.analysis_id == analysis_id).delete()
        db.commit()
    except Exception:
        db.rollback()
        db.query(AnalysisJob).filter(AnalysisJob.analysis_id == analysis_id).delete()
        db.commit()
    finally:
        db.close()


def _background_analysis_thread(analysis_id: str):
    asyncio.run(_background_analysis_task(analysis_id))


@router.post("/analyze")
async def analyze_email(
    background_tasks: BackgroundTasks,
    raw_content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    async_mode: bool = Form(False),
    db: Session = Depends(get_db),
):
    if not raw_content and not file:
        raise HTTPException(status_code=400, detail="No email content provided.")

    if file:
        raw_email = await file.read()
    else:
        raw_email = raw_content.encode("utf-8")

    analysis_id = str(uuid.uuid4())

    if async_mode:
        _update_job_status(db, analysis_id, "queued", "Queued for forensic ingestion", 5)
        db.add(AnalysisJob(analysis_id=analysis_id, payload=raw_email))
        db.commit()
        background_tasks.add_task(_background_analysis_thread, analysis_id)
        return {
            "analysis_id": analysis_id,
            "status": "queued",
            "stage": "Queued for forensic ingestion",
            "progress_pct": 5,
            "error": None,
        }

    try:
        return await _execute_analysis_pipeline(raw_email, analysis_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=500, detail="Email analysis could not be completed.")


@router.get("/analyze/{analysis_id}/status")
def get_analysis_status(analysis_id: str, db: Session = Depends(get_db)):
    db_result = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if db_result is not None:
        if db_result.status in {"queued", "processing"} and db_result.started_at:
            age_minutes = (datetime.now(timezone.utc) - _as_utc(db_result.started_at)).total_seconds() / 60
            if age_minutes > settings.ANALYSIS_STALE_MINUTES:
                _update_job_status(db, analysis_id, "failed", "Analysis expired as stale", 0, error="Analysis worker became stale and was recovered.")
                db_result.status = "failed"
                db_result.current_stage = "Analysis expired as stale"
                db_result.error_message = "Analysis worker became stale and was recovered."
        return {
            "analysis_id": analysis_id,
            "status": db_result.status or "completed",
            "stage": db_result.current_stage or "Analysis finalized and persisted",
            "progress_pct": db_result.progress_percent if db_result.progress_percent is not None else 100,
            "error": db_result.error_message,
        }

    raise HTTPException(status_code=404, detail="Analysis job not found.")


@router.post("/analyze/{analysis_id}/cancel")
def cancel_analysis(analysis_id: str, db: Session = Depends(get_db)):
    db_result = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if db_result is None:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    if db_result.status in {"completed", "failed", "cancelled"}:
        return {"analysis_id": analysis_id, "status": db_result.status, "cancelled": db_result.status == "cancelled"}
    _update_job_status(db, analysis_id, "cancelled", "Cancelled by operator", db_result.progress_percent or 0)
    return {"analysis_id": analysis_id, "status": "cancelled", "cancelled": True}


@router.get("/analyze/{analysis_id}", response_model=EmailAnalysisSchema)
async def get_analysis(analysis_id: str, db: Session = Depends(get_db)):
    db_result = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if db_result is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    return EmailAnalysisSchema(**_completed_result(db_result))


_ANALYSES_LIST_CACHE: Dict[Tuple, Tuple[float, Dict[str, Any]]] = {}


def invalidate_analyses_cache() -> None:
    """Invalidate analyses list cache upon new scan completion."""
    _ANALYSES_LIST_CACHE.clear()


@router.get("/analyses", response_model=dict)
def list_analyses(
    query: Optional[str] = Query(None, min_length=1, max_length=200),
    verdict: Optional[str] = Query(None, pattern="^(benign|suspicious|malicious)$"),
    severity: Optional[str] = Query(None, pattern="^(info|low|medium|high|critical)$"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List compact persisted analysis records with server-side filters."""
    query_val = str(query).strip() if (query is not None and not hasattr(query, "default")) else None
    verdict_val = str(verdict) if (verdict is not None and not hasattr(verdict, "default")) else None
    severity_val = str(severity) if (severity is not None and not hasattr(severity, "default")) else None
    limit_val = int(limit.default if hasattr(limit, "default") else limit)
    offset_val = int(offset.default if hasattr(offset, "default") else offset)

    cache_key = (query_val, verdict_val, severity_val, limit_val, offset_val)
    now_ts = time.time()
    if cache_key in _ANALYSES_LIST_CACHE:
        cached_ts, cached_payload = _ANALYSES_LIST_CACHE[cache_key]
        if now_ts < cached_ts:
            return cached_payload

    is_postgres = "postgres" in str(db.bind.url)

    # If PostgreSQL, use direct JSON field projection to avoid downloading huge result payloads (8x speedup)
    if is_postgres and not query_val:
        where_clauses = ["status IN ('completed', 'partial')"]
        params: Dict[str, Any] = {"limit": limit_val, "offset": offset_val}
        if verdict_val:
            where_clauses.append("verdict = :verdict")
            params["verdict"] = verdict_val
        if severity_val:
            where_clauses.append("severity = :severity")
            params["severity"] = severity_val

        where_sql = " AND ".join(where_clauses)
        count_sql = text(f"SELECT count(*) FROM analysis_results WHERE {where_sql}")
        total = db.execute(count_sql, params).scalar() or 0

        query_sql = text(f"""
            SELECT id, verdict, risk_score, severity, confidence, summary, created_at, status,
                   COALESCE(result->'email'->>'subject', result->'email'->'metadata'->>'subject', '(no subject)') as subject,
                   COALESCE(result->'email'->>'from', result->'email'->'metadata'->>'from', '(unknown sender)') as sender,
                   COALESCE(result->'email'->>'to', result->'email'->'metadata'->>'to', '(no recipient)') as recipient
            FROM analysis_results
            WHERE {where_sql}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """)
        rows = db.execute(query_sql, params).fetchall()
        data = []
        for row in rows:
            data.append({
                "analysis_id": str(row[0]),
                "verdict": row[1],
                "risk_score": row[2],
                "severity": row[3],
                "confidence": row[4],
                "summary": row[5],
                "created_at": _as_utc(row[6]).isoformat() if row[6] else None,
                "status": row[7] or "completed",
                "subject": row[8] or "(no subject)",
                "sender": row[9] or "(unknown sender)",
                "recipient": row[10] or "(no recipient)",
            })
        result_payload = {"data": data, "meta": {"total": total, "limit": limit_val, "offset": offset_val}}
        _ANALYSES_LIST_CACHE[cache_key] = (now_ts + 8.0, result_payload)
        return result_payload

    # Fallback for complex search queries or SQLite
    statement = db.query(AnalysisResult)
    if verdict_val:
        statement = statement.filter(AnalysisResult.verdict == verdict_val)
    if severity_val:
        statement = statement.filter(AnalysisResult.severity == severity_val)
    if query_val:
        escaped_query = query_val.replace("%", "\\%").replace("_", "\\_")
        match = f"%{escaped_query}%"
        statement = statement.filter(
            (AnalysisResult.summary.ilike(match)) | (AnalysisResult.id.ilike(match))
        )

    total = statement.count()
    records = statement.order_by(AnalysisResult.created_at.desc()).offset(offset_val).limit(limit_val).all()
    result_payload = {"data": [_analysis_summary(record) for record in records], "meta": {"total": total, "limit": limit_val, "offset": offset_val}}
    _ANALYSES_LIST_CACHE[cache_key] = (now_ts + 8.0, result_payload)
    return result_payload


@router.get("/analyses/iocs/search", response_model=dict)
def search_persisted_iocs(
    value: Optional[str] = Query(None, min_length=1, max_length=500),
    indicator_type: Optional[str] = Query(None, alias="type", max_length=32),
    limit: int = Query(100, ge=1, le=250),
    db: Session = Depends(get_db),
):
    """Search IOCs observed in persisted local analyses without external lookups."""
    # JSON querying differs between SQLite and PostgreSQL, so bounded filtering is
    # intentionally performed in Python for cross-database compatibility.
    records = db.query(AnalysisResult).order_by(AnalysisResult.created_at.desc()).limit(1000).all()
    needle = value.lower() if value else ""
    matches: List[Dict[str, Any]] = []
    seen = set()

    for record in records:
        result_dict = record.result if isinstance(record.result, dict) else {}
        email_info = result_dict.get("email") if isinstance(result_dict.get("email"), dict) else {}
        email_subject = email_info.get("subject") or "(No subject)"
        email_sender = email_info.get("from") or email_info.get("sender") or "Sender not available in parsed message"

        for ioc in _result_iocs(record.result):
            current_type = str(ioc.get("type") or "")
            current_value = str(ioc.get("normalized_value") or ioc.get("value") or "")
            if indicator_type and current_type != indicator_type:
                continue
            if needle and needle not in current_value.lower():
                continue
            key = (current_type, current_value.lower(), record.id)
            if not current_value or key in seen:
                continue
            seen.add(key)
            matches.append({
                "indicator": current_value,
                "type": current_type,
                "confidence": ioc.get("confidence") or 80,
                "sources": ioc.get("sources") or ioc.get("source") or ["local_analysis"],
                "context": ioc.get("context") or "Extracted from message body/headers",
                "analysis_id": record.id,
                "email_subject": email_subject,
                "email_sender": email_sender,
                "verdict": record.verdict,
                "severity": record.severity,
                "risk_score": record.risk_score,
                "created_at": _as_utc(record.created_at).isoformat(),
            })
            if len(matches) >= limit:
                return {"data": matches, "meta": {"limit": limit, "truncated": True, "source": "persisted_local_analyses"}}

    return {"data": matches, "meta": {"limit": limit, "truncated": False, "source": "persisted_local_analyses"}}


@router.get("/analyze/{analysis_id}/report.json")
def export_analysis_json(
    analysis_id: str,
    include_raw_email: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Download portable structured evidence, redacting message content by default."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    payload = _sanitize_result(_completed_result(record), include_raw_email=include_raw_email)
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id}.json"'},
    )


@router.get("/analysis/{analysis_id}/certin")
def export_certin_report(analysis_id: str, db: Session = Depends(get_db)):
    """Download a sanitized CERT-In incident report for a completed analysis."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    payload = _sanitize_result(_completed_result(record))
    report = generate_certin_report({**payload, "analysis_id": payload.get("analysis_id", record.id)})
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id}-certin-report.json"'},
        media_type="application/json",
    )


@router.get("/analysis/{analysis_id}/blockchain/verify")
def verify_blockchain_evidence(analysis_id: str, db: Session = Depends(get_db)):
    """Compare persisted evidence with the hash recorded on the configured chain."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    payload = _completed_result(record)
    anchor = payload.get("blockchain_anchor") or payload.get("ledger_anchor") or {}
    tx_hash = anchor.get("tx_hash") or anchor.get("transaction_hash") or anchor.get("tx")
    local_hash = record.evidence_hash or compute_evidence_hash(payload)
    on_chain_hash = verify_analysis(analysis_id)

    if on_chain_hash:
        matches = local_hash.lower() == on_chain_hash.lower().removeprefix("0x")
        status = "match" if matches else "mismatch"
    elif tx_hash:
        matches = False
        status = "unavailable"
    else:
        matches = False
        status = "not_anchored"

    network = anchor.get("network") or anchor.get("chain") or "sepolia"
    etherscan_url = f"https://sepolia.etherscan.io/tx/{tx_hash}" if tx_hash and network.lower() == "sepolia" else None
    return {
        "analysis_id": analysis_id,
        "status": status,
        "matches": matches,
        "local_hash": local_hash,
        "on_chain_hash": on_chain_hash,
        "tx_hash": tx_hash,
        "network": network,
        "block_number": anchor.get("block_number"),
        "etherscan_url": etherscan_url,
    }


@router.get("/analyze/{analysis_id}/evidence-bundle.zip")
def export_analysis_bundle(analysis_id: str, db: Session = Depends(get_db)):
    """Download a tamper-evident evidence bundle with the JSON artifact and SHA-256 manifest."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    payload = _sanitize_result(_completed_result(record))
    bundle = _build_evidence_bundle(payload, analysis_id)
    return StreamingResponse(
        iter([bundle]),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id}-bundle.zip"'},
    )


@router.get("/analyze/{analysis_id}/report.stix")
def export_analysis_stix(analysis_id: str, db: Session = Depends(get_db)):
    """Export sanitized evidence as a STIX 2.1 bundle."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return JSONResponse(
        content=export_stix_bundle(record.id, _sanitize_result(_completed_result(record))),
        headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id}.stix.json"'},
        media_type="application/stix+json",
    )


@router.get("/analyze/{analysis_id}/blocklist.csv")
def export_analysis_blocklist(analysis_id: str, db: Session = Depends(get_db)):
    """Export a bounded IOC blocklist without raw email content."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    from fastapi.responses import PlainTextResponse
    response = PlainTextResponse(generate_blocklist(_sanitize_result(_completed_result(record))), media_type="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="analysis-{analysis_id}-blocklist.csv"'
    return response


@router.get("/analyze/{analysis_id}/queries")
def export_analysis_queries(analysis_id: str, db: Session = Depends(get_db)):
    """Return SIEM query templates generated from observed IOCs."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return generate_queries(_sanitize_result(_completed_result(record)))


@router.get("/analyses/{analysis_id}/related")
def get_related_investigations(analysis_id: str, db: Session = Depends(get_db)):
    """Return campaign-correlation results persisted on an analysis."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return {"data": (record.result or {}).get("related_investigations", []), "analysis_id": analysis_id}


@router.get("/analyze/{analysis_id}/report.html", response_class=HTMLResponse)
def export_analysis_html(
    analysis_id: str,
    include_raw_email: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Serve a printable HTML report containing escaped structured evidence."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    payload = _sanitize_result(_completed_result(record), include_raw_email=include_raw_email)
    response = HTMLResponse(_render_report_html(record.id, payload, record.created_at))
    response.headers["Content-Disposition"] = f'inline; filename="analysis-{analysis_id}.html"'
    return response


@router.get("/analyze/{analysis_id}/report.pdf")
def export_analysis_pdf(analysis_id: str, db: Session = Depends(get_db)):
    """Download a sanitized portable PDF forensic report."""
    record = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    payload = _sanitize_result(_completed_result(record))
    return StreamingResponse(
        iter([generate_forensic_pdf(payload)]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id}.pdf"'},
    )

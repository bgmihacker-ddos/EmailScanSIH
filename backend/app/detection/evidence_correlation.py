"""Phase 2: Evidence Correlation Module.

Normalizes forensic findings from disparate analyzer services into a canonical
format for risk scoring and threat reasoning. Performs deduplication,
evidence clustering, and confidence recalibration.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class EvidenceRecord:
    """Normalized unit of evidence consumed by the risk scorer."""

    base_points: int = 0
    title: str = ""
    finding_id: str = ""
    source: str = "unknown"
    source_family: str = "unknown"
    confidence: int = 0
    evidence_class: str = "informational"
    evidence_refs: List[str] = field(default_factory=list)
    severity: str = "info"
    scoring_eligible: bool = True
    non_scoring_reason: str = None
    cluster_key: str = None
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    scoring_records: List[EvidenceRecord]
    mitigating_records: List[EvidenceRecord]
    evidence_records: List[EvidenceRecord]
    suppressed_records: List[EvidenceRecord]
    confidence: int
    summary_notes: List[str]
    clusters: Dict[str, Any]
    evidence_families_present: List[str] = field(default_factory=list)


class EvidenceCorrelator:
    """Canonical normalization and correlation layer for forensic findings."""

    _SOURCE_NAMES = {
        "header": "header_forensics",
        "authentication": "authentication_analyzer",
        "attachment": "attachment_analyzer",
        "content": "content_analyzer",
        "url": "url_intelligence",
        "domain": "domain_intelligence",
        "spf": "authentication_analyzer",
        "dkim": "authentication_analyzer",
        "dmarc": "authentication_analyzer",
    }
    _POINTS = {"critical": 30, "high": 20, "medium": 10, "low": 4, "info": 0}

    @staticmethod
    def _normalize_auth_result(result: str) -> str:
        r = str(result).lower()
        if r == "reject":
            return "fail"
        return r

    @staticmethod
    def _legacy_findings(
        findings: Any,
        fallback_source: str,
        seen: set,
        suppressed: List[EvidenceRecord],
    ) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not isinstance(findings, list):
            return records

        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            finding_id = str(finding.get("finding_id") or f"{fallback_source}.{index}")
            related = finding.get("related_iocs") or finding.get("evidence") or []
            if not isinstance(related, list):
                related = [str(related)]
            source = EvidenceCorrelator._SOURCE_NAMES.get(str(finding.get("category") or fallback_source), fallback_source)
            severity = str(finding.get("severity") or "info").lower()
            evidence_class = str(finding.get("evidence_class") or "strong_risk_signal")
            risk_relevance = str(finding.get("risk_relevance") or "risk_contributing")
            mitre_techniques = finding.get("mitre_techniques") or []
            if not isinstance(mitre_techniques, list):
                mitre_techniques = []

            record = EvidenceRecord(
                base_points=EvidenceCorrelator._POINTS.get(severity, 0),
                title=str(finding.get("title") or finding_id),
                finding_id=finding_id,
                source=source,
                source_family=source,
                confidence=int(finding.get("confidence") or 50),
                evidence_class=evidence_class,
                evidence_refs=[str(value) for value in related],
                severity=severity,
                cluster_key=finding.get("cluster_key"),
                mitre_techniques=[str(t) for t in mitre_techniques],
            )
            if finding_id in seen:
                suppressed.append(record)
                continue
            seen.add(finding_id)
            if risk_relevance == "mitigating":
                record.base_points = -min(10, max(2, record.base_points))
            elif evidence_class in ("contextual_anomaly", "informational", "mitigating") or risk_relevance != "risk_contributing":
                # Cap contextual indicators to avoid stacking them up to a malicious verdict
                record.base_points = min(record.base_points, 4)
            records.append(record)
        return records

    @staticmethod
    def _normalize_urls(url_intelligence: Any, seen: set, suppressed: List[EvidenceRecord]) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not isinstance(url_intelligence, dict):
            return records

        urls = url_intelligence.get("urls", [])
        if not isinstance(urls, list):
            return records

        for index, url in enumerate(urls):
            if not isinstance(url, dict):
                continue

            url_value = url.get("url") or url.get("normalized") or url.get("value") or f"url-{index}"
            domain = url.get("domain") or ""
            indicators = url.get("indicators") or url.get("threat_types", [])
            risk_score = url.get("risk_score", 0)

            finding_id = f"url.{url_value}"
            cluster_key = f"host_cluster_{domain}" if domain else None

            if finding_id in seen:
                suppressed.append(EvidenceRecord(
                    base_points=0, title=f"Suspicious URL", finding_id=finding_id,
                    source="url_intelligence", source_family="url",
                    confidence=90, evidence_class="informational", evidence_refs=[],
                    scoring_eligible=False, non_scoring_reason="duplicate", cluster_key=cluster_key,
                ))
                continue
            seen.add(finding_id)

            is_credential = any(
                str(item).lower() in ("credential", "credential_phishing", "phishing")
                for item in indicators
            )
            has_strong_url_risk = (
                risk_score >= 40
                or is_credential
                or any(
                    str(item).lower() in (
                        "punycode_domain",
                        "ip_hosted_url",
                        "credential_url",
                        "brand_impersonation",
                        "url_shortener",
                        "suspicious_tld",
                        "suspicious_port",
                    )
                    for item in indicators
                )
                or any(
                    isinstance(f, dict) and f.get("risk_relevance") == "risk_contributing"
                    for f in url.get("findings", [])
                )
            )

            if not has_strong_url_risk:
                base_points = 0
                evidence_class = "informational"
                severity = "info"
            else:
                base_points = 20 if is_credential else 10
                if risk_score >= 80:
                    base_points = max(base_points, 20)
                evidence_class = "strong_risk_signal"
                severity = "high" if risk_score >= 80 else "medium"

            records.append(EvidenceRecord(
                base_points=base_points,
                title=f"Suspicious URL: {url_value}" if has_strong_url_risk else f"URL: {url_value}",
                finding_id=finding_id,
                source="url_intelligence",
                source_family="url",
                confidence=90,
                evidence_class=evidence_class,
                evidence_refs=[url_value, *[str(item) for item in indicators]],
                severity=severity,
                cluster_key=cluster_key,
                scoring_eligible=has_strong_url_risk,
                non_scoring_reason=None if has_strong_url_risk else "informational_only",
            ))
        return records

    @staticmethod
    def _normalize_auth(authentication: Any, seen: set, suppressed: List[EvidenceRecord]) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not isinstance(authentication, dict):
            return records

        auth_mechanisms = ["spf", "dkim", "dmarc"]
        for mech in auth_mechanisms:
            if mech in authentication:
                result_data = authentication[mech]
                if not isinstance(result_data, dict):
                    continue
                result = EvidenceCorrelator._normalize_auth_result(result_data.get("result", ""))
                domain = result_data.get("domain", "")

                finding_id = f"auth_{mech}_{result}"
                if finding_id in seen:
                    suppressed.append(EvidenceRecord(
                        base_points=0, title=f"{mech.upper()} result", finding_id=finding_id,
                        source="authentication_analyzer", source_family="authentication",
                        confidence=85, evidence_class="informational", evidence_refs=[],
                        scoring_eligible=False, non_scoring_reason="duplicate",
                    ))
                    continue
                seen.add(finding_id)

                if result in ("pass", "success"):
                    records.append(EvidenceRecord(
                        base_points=-5,
                        title=f"{mech.upper()} authentication passed",
                        finding_id=finding_id,
                        source="authentication_analyzer",
                        source_family="authentication",
                        confidence=85,
                        evidence_class="strong_risk_signal",
                        evidence_refs=[f"domain: {domain}", f"result: {result}"],
                        severity="info",
                        mitre_techniques=[],
                    ))
                elif result in ("fail", "softfail", "neutral"):
                    records.append(EvidenceRecord(
                        base_points=15,
                        title=f"{mech.upper()} authentication failed",
                        finding_id=finding_id,
                        source="authentication_analyzer",
                        source_family="authentication",
                        confidence=80,
                        evidence_class="strong_risk_signal",
                        evidence_refs=[f"domain: {domain}", f"result: {result}"],
                        severity="medium",
                        mitre_techniques=["T1566.002"],
                    ))
                elif result in ("reject",):
                    records.append(EvidenceRecord(
                        base_points=20,
                        title=f"{mech.upper()} authentication rejected",
                        finding_id=finding_id,
                        source="authentication_analyzer",
                        source_family="authentication",
                        confidence=90,
                        evidence_class="strong_risk_signal",
                        evidence_refs=[f"domain: {domain}", f"result: reject"],
                        severity="high",
                        mitre_techniques=["T1566.002"],
                    ))

        findings = authentication.get("findings", [])
        if isinstance(findings, list):
            records.extend(EvidenceCorrelator._legacy_findings(findings, "authentication_analyzer", seen, suppressed))

        return records

    @staticmethod
    def _normalize_ml(
        ml_prediction: Any,
        authentication: Dict[str, Any],
        seen: set,
        suppressed: List[EvidenceRecord],
    ) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not isinstance(ml_prediction, dict):
            return records
        if ml_prediction.get("status") in {
            "unavailable",
            "not_configured",
            "timeout",
            "error",
        }:
            return records
        if ml_prediction.get("status") is None and not ml_prediction.get("prediction") and not ml_prediction.get("label"):
            return records

        label = str(ml_prediction.get("label") or ml_prediction.get("prediction") or "").lower()
        if not label:
            return records

        probability = float(ml_prediction.get("probability") or ml_prediction.get("confidence") or 0.5)
        base_points = min(15, int(probability * 20))
        if label in ("phishing", "malicious", "threat", "spam"):
            auth_passes = all(
                isinstance(authentication.get(auth_mech), dict)
                and EvidenceCorrelator._normalize_auth_result(
                    authentication[auth_mech].get("status", "")
                ) == "pass"
                for auth_mech in ("spf", "dkim", "dmarc")
            )
            if auth_passes:
                base_points = 0
        elif label in ("benign", "safe", "legitimate"):
            # Check for strong authentication failures (SPF/DKIM/DMARC fail)
            # If authentication has failed, ML benign mitigation should not apply
            auth_failures = [
                auth_mech for auth_mech in ("spf", "dkim", "dmarc")
                if isinstance(authentication.get(auth_mech), dict)
                and EvidenceCorrelator._normalize_auth_result(
                    authentication[auth_mech].get("status", "")
                ) in ("fail", "softfail", "neutral", "reject")
            ]
            if auth_failures:
                # ML benign prediction does not mitigate hard authentication failures
                base_points = 0
            else:
                base_points = -base_points
        else:
            base_points = int(base_points * 0.5)

        finding_id = "ml_classifier_prediction"
        if finding_id in seen:
            suppressed.append(EvidenceRecord(
                base_points=0, title=f"ML: {label}", finding_id=finding_id,
                source="ml_classifier", source_family="model",
                confidence=int(probability * 100), evidence_class="informational",
                evidence_refs=[], scoring_eligible=False, non_scoring_reason="duplicate",
            ))
            return records
        seen.add(finding_id)

        records.append(EvidenceRecord(
            base_points=base_points,
            title=f"ML classified as {label}",
            finding_id=finding_id,
            source="ml_classifier",
            source_family="model",
            confidence=int(probability * 100),
            evidence_class="informational",
            evidence_refs=[f"probability: {probability:.2%}"],
            severity="info",
        ))
        return records

    @staticmethod
    def _normalize_domain(domain_intelligence: Any, seen: set, suppressed: List[EvidenceRecord]) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not isinstance(domain_intelligence, dict):
            return records

        for domain, data in domain_intelligence.items():
            if not isinstance(data, dict):
                continue

            risk_score = data.get("risk_score", 0)
            impersonated_brand = data.get("impersonated_brand")

            findings = data.get("findings", [])
            # Filter findings to distinguish between strong risk signals and contextual anomalies
            strong_risk_findings = [f for f in findings if f.get("risk_relevance") == "risk_contributing"]
            has_strong_risk = risk_score >= 40 or impersonated_brand or bool(strong_risk_findings)

            finding_id = f"domain.{domain}"
            cluster_key = f"host_cluster_{domain}"

            if finding_id in seen:
                suppressed.append(EvidenceRecord(
                    base_points=0, title=f"Domain: {domain}", finding_id=finding_id,
                    source="domain_intelligence", source_family="domain",
                    confidence=80, evidence_class="informational", evidence_refs=[],
                    scoring_eligible=False, non_scoring_reason="duplicate", cluster_key=cluster_key,
                ))
                continue
            seen.add(finding_id)

            base_points = 0

            if has_strong_risk:
                base_points = 10
                if risk_score >= 80:
                    base_points = 20
                if impersonated_brand:
                    base_points = max(base_points, 25)
            else:
                base_points = 0

            records.append(EvidenceRecord(
                base_points=base_points,
                title=f"Suspicious domain: {domain}" if base_points > 5 else f"Domain observed: {domain}",
                finding_id=finding_id,
                source="domain_intelligence",
                source_family="domain",
                confidence=80,
                evidence_class="strong_risk_signal" if base_points > 5 else "informational",
                evidence_refs=[f"domain: {domain}", f"risk_score: {risk_score}"],
                severity="high" if risk_score >= 80 else "medium" if base_points > 5 else "info",
                cluster_key=cluster_key,
                mitre_techniques=["T1566.002"] if impersonated_brand else [],
                scoring_eligible=has_strong_risk,
                non_scoring_reason=None if has_strong_risk else "informational_only",
            ))
        return records

    @staticmethod
    def _normalize_attachments(attachment_analysis: Any, seen: set, suppressed: List[EvidenceRecord]) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not isinstance(attachment_analysis, dict):
            return records

        attachments = attachment_analysis.get("attachments", [])
        findings = attachment_analysis.get("findings", [])

        records.extend(EvidenceCorrelator._legacy_findings(findings, "attachment_analyzer", seen, suppressed))

        for att in attachments if isinstance(attachments, list) else []:
            if not isinstance(att, dict):
                continue

            filename = att.get("filename") or att.get("name", "")
            is_executable = att.get("is_executable") or att.get("has_double_extension") or "executable_extension" in att.get("indicators", []) or "double_extension" in att.get("indicators", [])
            is_malicious = att.get("is_malicious") or att.get("risk_level") == "malicious"

            finding_id = f"attachment.{filename}"
            if not finding_id or finding_id in seen:
                continue
            seen.add(finding_id)

            if is_executable or is_malicious:
                severity = "critical" if is_malicious else "high"
                base_pts = 50 if is_malicious else 40
                records.append(EvidenceRecord(
                    base_points=base_pts,
                    title=f"Malicious attachment: {filename}",
                    finding_id=finding_id,
                    source="attachment_analyzer",
                    source_family="attachment",
                    confidence=95,
                    evidence_class="strong_risk_signal",
                    evidence_refs=[f"filename: {filename}"],
                    severity=severity,
                    mitre_techniques=["T1566.001"],
                ))
            else:
                # Track clean attachments as 0 point, non-scoring informational context
                records.append(EvidenceRecord(
                    base_points=0,
                    title=f"Clean attachment: {filename}",
                    finding_id=finding_id,
                    source="attachment_analyzer",
                    source_family="attachment",
                    confidence=60,
                    evidence_class="informational",
                    evidence_refs=[f"filename: {filename}"],
                    severity="info",
                    scoring_eligible=False,
                    non_scoring_reason="clean",
                ))
        return records

    @staticmethod
    def _normalize_threat_intel(threat_intelligence: Any, seen: set, suppressed: List[EvidenceRecord]) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not isinstance(threat_intelligence, dict):
            return records

        for provider, data in threat_intelligence.items():
            if not isinstance(data, dict):
                continue
            status = str(data.get("status", "")).lower()

            finding_id = f"ti_{provider}"
            if finding_id in seen:
                suppressed.append(EvidenceRecord(
                    base_points=0, title=f"TI: {provider}", finding_id=finding_id,
                    source=f"ti_{provider}", source_family="reputation",
                    confidence=50, evidence_class="informational", evidence_refs=[],
                    scoring_eligible=False, non_scoring_reason="duplicate",
                ))
                continue
            seen.add(finding_id)

            metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            if metadata.get("ti_scoring_eligible") is False:
                records.append(EvidenceRecord(
                    base_points=0,
                    title=f"{provider}: header domain enrichment",
                    finding_id=finding_id,
                    source=f"ti_{provider}",
                    source_family="reputation",
                    confidence=min(50, int(data.get("confidence") or 0)),
                    evidence_class="informational",
                    evidence_refs=[
                        f"indicator: {data.get('indicator') or data.get('target')}",
                        f"source: {metadata.get('ioc_source')}",
                    ],
                    severity="info",
                    scoring_eligible=False,
                    non_scoring_reason="header_domain_context",
                ))
                continue

            if status == "ok":
                is_malicious = data.get("is_malicious")
                reputation = str(data.get("reputation") or "unknown").lower()
                if is_malicious is True or reputation in {"malicious", "threat"}:
                    provider_confidence = min(100, max(0, int(data.get("confidence") or 0)))
                    explicit_verdict = is_malicious is True
                    confirmed = explicit_verdict or provider_confidence >= 90
                    if explicit_verdict and provider_confidence == 0:
                        provider_confidence = 90
                    records.append(EvidenceRecord(
                        base_points=25 if confirmed else 10,
                        title=f"{provider} confirmed malicious" if confirmed else f"{provider} reported malicious",
                        finding_id=finding_id,
                        source=f"ti_{provider}",
                        source_family="reputation",
                        confidence=provider_confidence,
                        evidence_class="confirmed_malicious" if confirmed else "strong_risk_signal",
                        evidence_refs=[
                            f"indicator: {data.get('indicator') or data.get('target')}",
                            f"provider_confidence: {provider_confidence}%",
                            f"detections: {data.get('detections', data.get('positives', 0))}",
                        ],
                        severity="critical" if confirmed else "medium",
                    ))
                elif is_malicious is False and reputation in {"clean", "benign", "safe"}:
                    records.append(EvidenceRecord(
                        base_points=-3,
                        title=f"{provider} confirmed clean",
                        finding_id=finding_id,
                        source=f"ti_{provider}",
                        source_family="reputation",
                        confidence=95,
                        evidence_class="mitigating",
                        evidence_refs=[f"status: ok"],
                        severity="info",
                    ))
                else:
                    records.append(EvidenceRecord(
                        base_points=0,
                        title=f"{provider}: result requires interpretation",
                        finding_id=finding_id,
                        source=f"ti_{provider}",
                        source_family="reputation",
                        confidence=30,
                        evidence_class="informational",
                        evidence_refs=[f"status: {status}", f"reputation: {reputation}"],
                        severity="info",
                        scoring_eligible=False,
                        non_scoring_reason="no_explicit_verdict",
                    ))
            elif status in (
                "timeout",
                "rate_limited",
                "not_found",
                "not_configured",
                "error",
                "unavailable",
                "skipped",
                "circuit_broken",
            ):
                records.append(EvidenceRecord(
                    base_points=0,
                    title=f"{provider}: {status}",
                    finding_id=finding_id,
                    source=f"ti_{provider}",
                    source_family="reputation",
                    confidence=30,
                    evidence_class="informational",
                    evidence_refs=[f"status: {status}", f"fallback_used: {str(data.get('fallback_used', False)).lower()}"] if isinstance(data, dict) else [f"status: {status}"],
                    severity="info",
                    scoring_eligible=False,
                    non_scoring_reason=status,
                ))
        return records

    @staticmethod
    def correlate(
        header_forensics: Dict[str, Any] = None,
        authentication: Dict[str, Any] = None,
        extracted_iocs: Dict[str, Any] = None,
        url_intelligence: Dict[str, Any] = None,
        domain_intelligence: Dict[str, Any] = None,
        threat_intelligence: Dict[str, Any] = None,
        attachment_analysis: Dict[str, Any] = None,
        content_analysis: Dict[str, Any] = None,
        ml_prediction: Dict[str, Any] = None,
        rule_detections: List[Dict[str, Any]] = None,
        detector_findings: List[Dict[str, Any]] = None,
    ) -> CorrelationResult:
        header_forensics = header_forensics or {}
        authentication = authentication or {}
        extracted_iocs = extracted_iocs or {}
        url_intelligence = url_intelligence or {}
        domain_intelligence = domain_intelligence or {}
        threat_intelligence = threat_intelligence or {}
        attachment_analysis = attachment_analysis or {}
        content_analysis = content_analysis or {}
        ml_prediction = ml_prediction or {}
        rule_detections = rule_detections or []
        detector_findings = detector_findings or []

        seen: set = set()
        suppressed: List[EvidenceRecord] = []
        scoring = []

        scoring.extend(EvidenceCorrelator._legacy_findings(header_forensics.get("forensic_findings", []), "header_forensics", seen, suppressed))
        scoring.extend(EvidenceCorrelator._normalize_auth(authentication, seen, suppressed))
        scoring.extend(EvidenceCorrelator._normalize_attachments(attachment_analysis, seen, suppressed))
        scoring.extend(EvidenceCorrelator._legacy_findings(attachment_analysis.get("findings", []), "attachment_analyzer", seen, suppressed))
        scoring.extend(EvidenceCorrelator._legacy_findings(content_analysis.get("findings", []), "content_analyzer", seen, suppressed))
        scoring.extend(EvidenceCorrelator._normalize_urls(url_intelligence, seen, suppressed))
        scoring.extend(EvidenceCorrelator._normalize_domain(domain_intelligence, seen, suppressed))
        scoring.extend(EvidenceCorrelator._normalize_ml(ml_prediction, authentication, seen, suppressed))
        scoring.extend(EvidenceCorrelator._normalize_threat_intel(threat_intelligence, seen, suppressed))
        scoring.extend(EvidenceCorrelator._legacy_findings(detector_findings, "detector", seen, suppressed))

        # A stripped message is not inherently malicious, but urgency combined
        # with several missing delivery-trace headers is materially stronger than
        # either context alone. Keep this bounded and require no passing auth
        # result so legitimate authenticated messages do not receive this boost.
        missing_trace_ids = {
            "header.date.missing",
            "header.message_id.missing",
            "mail_flow.received.missing",
        }
        missing_trace = [record for record in scoring if record.finding_id in missing_trace_ids]
        urgency_present = any(
            record.finding_id == "content.social_engineering.urgency"
            for record in scoring
        )
        auth_pass = any(
            isinstance(value, dict)
            and EvidenceCorrelator._normalize_auth_result(value.get("result", "")) in ("pass", "success")
            for value in authentication.values()
        )
        correlation_id = "correlation.urgent_incomplete_delivery"
        if len(missing_trace) >= 2 and urgency_present and not auth_pass and correlation_id not in seen:
            seen.add(correlation_id)
            scoring.append(EvidenceRecord(
                # Missing headers are common in pasted, forwarded, and
                # partially captured messages. Keep this contextual only;
                # urgency must be corroborated by observable infrastructure.
                base_points=4,
                title="Urgent message with incomplete delivery headers",
                finding_id=correlation_id,
                source="evidence_correlation",
                source_family="correlation",
                confidence=60,
                evidence_class="contextual_anomaly",
                evidence_refs=[
                    "signal: urgent/coercive language",
                    f"missing_headers: {', '.join(record.finding_id for record in missing_trace)}",
                ],
                severity="low",
            ))

        # Handle clustering for host clusters (e.g. url & domain matching cluster_key)
        # Group scoring records by cluster_key
        clustered_scoring = []
        cluster_map: Dict[str, List[EvidenceRecord]] = {}
        for r in scoring:
            if r.cluster_key:
                cluster_map.setdefault(r.cluster_key, []).append(r)
            else:
                clustered_scoring.append(r)

        for ckey, records in cluster_map.items():
            # Pick highest point record as primary
            records.sort(key=lambda x: x.base_points, reverse=True)
            clustered_scoring.append(records[0])
            for suppressed_rec in records[1:]:
                suppressed_rec.cluster_key = ckey
                suppressed.append(suppressed_rec)

        scoring = clustered_scoring

        mitigating = [record for record in scoring if record.base_points < 0]
        zero_point = [record for record in scoring if record.base_points == 0]
        scoring = [record for record in scoring if record.base_points > 0]
        suppressed.extend(zero_point)
        families = {record.source_family for record in scoring}
        evidence_families = list(families)

        corroboration_bonus = 0
        if len(families) >= 3:
            corroboration_bonus = 10
        elif len(families) >= 2:
            corroboration_bonus = 5

        ti_confirmed = any(
            isinstance(ti, dict) and ti.get("status") == "ok" and ti.get("is_malicious")
            for ti in threat_intelligence.values() if isinstance(threat_intelligence, dict)
        ) or any(
            r.evidence_class == "confirmed_malicious" for r in scoring
        )
        if ti_confirmed:
            corroboration_bonus += 20  # Boost for confirmed TI to hit high confidence

        # If clean/mitigating email (passing auth), give high confidence
        if mitigating and not scoring:
            confidence = 85
        else:
            confidence = min(100, 40 + len(families) * 10 + min(15, len(scoring) * 2) + corroboration_bonus)
            if not scoring and not mitigating:
                confidence = 30

        all_evidence = [*scoring, *mitigating, *suppressed]

        return CorrelationResult(
            scoring_records=scoring,
            mitigating_records=mitigating,
            evidence_records=all_evidence,
            suppressed_records=suppressed,
            confidence=confidence,
            summary_notes=[f"Normalized {len(scoring)} scoring signals across {len(families)} analyzer families."],
            clusters={"analyzer_families": sorted(families)},
            evidence_families_present=evidence_families,
        )

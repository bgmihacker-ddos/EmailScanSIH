"""Deterministic, offline email header and mail-flow forensic analysis.

This module analyzes structured output from :mod:`app.services.email_parser`.
It does not contact external services or independently verify SPF, DKIM, DMARC,
or ARC records. Authentication outcomes are reported only as sender-provided
header evidence.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple


_AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-zA-Z][a-zA-Z0-9_-]*)",
    re.IGNORECASE,
)
_AUTH_DOMAIN_RE = re.compile(r"\b(?:header\.)?from\s*=\s*([^\s;()]+)", re.IGNORECASE)
_MESSAGE_ID_RE = re.compile(r"^\s*<([^<>\s@]+)@([^<>\s@]+)>\s*$")
_IP_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*)(?![0-9A-Fa-f:.])"
)

_KNOWN_PROVIDERS: Dict[str, List[str]] = {
    "google": ["google.com", "gmail.com", "googlemail.com", "gmr-mx.google.com"],
    "microsoft": ["outlook.com", "protection.outlook.com", "microsoft.com", "office365.com", "hotmail.com"],
    "amazon_ses": ["amazonses.com", "amazonaws.com"],
    "sendgrid": ["sendgrid.net", "sendgrid.com"],
    "mailgun": ["mailgun.org", "mailgun.net"],
    "mailchimp": ["mcsv.net", "mailchimp.com", "mandrillapp.com"],
    "postmark": ["postmarkapp.com", "wildbit.com"],
    "fastmail": ["messagingengine.com", "fastmail.com"],
}


def _as_list(value: Any) -> List[str]:
    """Return a scalar or list-like header value as a list of nonempty strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None and str(item)]
    return [str(value)] if str(value) else []


def _normalized_domain(value: Optional[str]) -> Optional[str]:
    """Normalize a possible DNS name without attempting resolution."""
    if not value:
        return None
    domain = str(value).strip().strip(".<>[]()\"'").lower()
    if not domain or " " in domain or "@" in domain:
        return None
    return domain


def _domain_relationship(left: Optional[str], right: Optional[str]) -> str:
    """Describe an offline relationship between two domain names."""
    left = _normalized_domain(left)
    right = _normalized_domain(right)
    if not left or not right:
        return "missing"
    if left == right:
        return "same_domain"
    if left.endswith("." + right) or right.endswith("." + left):
        return "subdomain_relationship"
    return "different_domain"


def _extract_auth_domains(header_values: Iterable[str]) -> List[str]:
    """Extract domain claims from Authentication-Results evidence only."""
    domains: List[str] = []
    for value in header_values:
        for match in _AUTH_DOMAIN_RE.findall(value):
            candidate = _normalized_domain(match)
            if candidate and candidate not in domains:
                domains.append(candidate)
    return domains


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse an RFC-style timestamp safely, returning None on malformed input."""
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None

    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp_iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _timezone_label(value: Optional[str]) -> Optional[str]:
    """Retain the timezone portion of a Received timestamp where present."""
    if not value:
        return None
    match = re.search(r"([+-]\d{4}|(?:UTC|GMT))\s*$", value, re.IGNORECASE)
    return match.group(1) if match else None


def _classify_ip(ip_value: Any) -> Dict[str, Any]:
    """Classify an IP strictly from address properties, not reputation."""
    text = str(ip_value or "").strip()
    entry: Dict[str, Any] = {
        "ip": text,
        "version": None,
        "classification": "invalid/unknown",
        "source": "received",
        "evidence_class": "informational",
    }
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return entry

    entry["version"] = parsed.version
    if parsed.is_loopback:
        entry["classification"] = "loopback"
    elif parsed.is_link_local:
        entry["classification"] = "link_local"
    elif parsed.is_multicast:
        entry["classification"] = "multicast"
    elif parsed.is_unspecified:
        entry["classification"] = "unspecified"
    elif parsed.is_private:
        entry["classification"] = "private"
    elif parsed.is_reserved:
        entry["classification"] = "reserved"
    elif parsed.is_global:
        entry["classification"] = "public"
    else:
        entry["classification"] = "reserved"
    return entry


def _finding(
    finding_id: str,
    category: str,
    title: str,
    description: str,
    severity: str = "info",
    confidence: int = 100,
    evidence: Optional[List[str]] = None,
    related_iocs: Optional[List[str]] = None,
    evidence_class: str = "contextual_anomaly",
    risk_relevance: str = "contextual",
) -> Dict[str, Any]:
    """Build a JSON-serializable structured forensic finding."""
    return {
        "finding_id": finding_id,
        "category": category,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence or [],
        "related_iocs": related_iocs or [],
        "evidence_class": evidence_class,
        "risk_relevance": risk_relevance,
    }


class HeaderForensicsAnalyzer:
    """Analyze parsed email headers without deciding the final threat verdict."""

    _DUPLICATE_HEADERS = (
        "from",
        "reply-to",
        "return-path",
        "date",
        "message-id",
        "authentication-results",
        "dkim-signature",
        "arc-seal",
        "arc-message-signature",
        "arc-authentication-results",
    )

    @staticmethod
    def analyze(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """Return deterministic header/mail-flow forensic evidence.

        The method accepts a partial or malformed parser result and always
        returns the documented top-level objects. It intentionally avoids
        logging email content, performing network requests, or asserting
        cryptographic verification of authentication records.
        """
        source = parsed_email if isinstance(parsed_email, dict) else {}
        findings: List[Dict[str, Any]] = []

        addresses = source.get("addresses") if isinstance(source.get("addresses"), dict) else {}
        headers = source.get("headers") if isinstance(source.get("headers"), dict) else {}
        metadata = source.get("metadata") if isinstance(source.get("metadata"), dict) else {}

        domains = HeaderForensicsAnalyzer._analyze_domains(source, addresses, headers, metadata, findings)
        mail_flow = HeaderForensicsAnalyzer._analyze_mail_flow(source, findings)
        authentication = HeaderForensicsAnalyzer._analyze_authentication(source, findings)
        header_completeness = HeaderForensicsAnalyzer._analyze_header_completeness(source, metadata, findings)
        duplicates = HeaderForensicsAnalyzer._analyze_duplicates(headers, findings)

        # Identify legitimate infrastructure providers
        identified_providers = HeaderForensicsAnalyzer._identify_providers(mail_flow, domains)

        # Extract extended headers and mail characteristics (Phase 4)
        extended_headers = {
            "x_originating_ip": _as_list(headers.get("x-originating-ip") or headers.get("x-sender-ip") or headers.get("x-client-ip")),
            "x_mailer": headers.get("x-mailer"),
            "user_agent": headers.get("user-agent"),
            "x_priority": headers.get("x-priority"),
            "importance": headers.get("importance"),
            "list_unsubscribe": headers.get("list-unsubscribe"),
            "list_unsubscribe_post": headers.get("list-unsubscribe-post"),
            "list_id": headers.get("list-id"),
            "precedence": headers.get("precedence"),
            "auto_submitted": headers.get("auto-submitted"),
            "feedback_id": headers.get("feedback-id"),
            "provider_headers": {
                key: value for key, value in headers.items()
                if str(key).lower().startswith(("x-gm-", "x-ms-", "x-forefront-"))
            },
        }
        has_list_headers = bool(
            extended_headers["list_unsubscribe"]
            or extended_headers["list_id"]
            or extended_headers["feedback_id"]
        )
        is_automated = bool(
            extended_headers["auto_submitted"]
            or (str(extended_headers["precedence"] or "").lower() in ("bulk", "list", "junk"))
            or has_list_headers
        )
        mail_characteristics = {
            "is_bulk_sender": bool(has_list_headers or (str(extended_headers["precedence"] or "").lower() == "bulk")),
            "is_transactional": bool(identified_providers and not has_list_headers),
            "is_automated": is_automated,
            "has_list_headers": has_list_headers,
        }

        ip_counts = {
            "public": sum(ip["classification"] == "public" for ip in mail_flow["ip_addresses"]),
            "private": sum(ip["classification"] == "private" for ip in mail_flow["ip_addresses"]),
            "loopback": sum(ip["classification"] == "loopback" for ip in mail_flow["ip_addresses"]),
            "other": sum(
                ip["classification"] not in {"public", "private", "loopback"}
                for ip in mail_flow["ip_addresses"]
            ),
        }
        summary = {
            "header_completeness": header_completeness,
            "hop_count": mail_flow["hop_count"],
            "origin_ip": mail_flow["origin_ip"],
            "final_destination": mail_flow["final_destination"],
            "public_ip_count": ip_counts["public"],
            "private_ip_count": ip_counts["private"],
            "loopback_ip_count": ip_counts["loopback"],
            "domain_mismatches": [
                key for key, relationship in domains["relationships"].items()
                if relationship == "different_domain"
            ],
            "authentication_evidence_availability": {
                name: value["available"] for name, value in authentication.items()
            },
            "duplicate_security_headers": list(duplicates),
            "anomalies_detected": len(findings),
            "header_anomaly_count": sum(
                finding["severity"] in {"low", "medium", "high", "critical"}
                for finding in findings
            ),
            "identified_providers": identified_providers,
        }

        return {
            "mail_flow": mail_flow,
            "domain_relationships": domains,
            "ip_classifications": mail_flow["ip_addresses"],
            "authentication_evidence": authentication,
            "forensic_findings": findings,
            "forensic_summary": summary,
            "extended_headers": extended_headers,
            "mail_characteristics": mail_characteristics,
        }

    @staticmethod
    def _identify_providers(mail_flow: Dict[str, Any], domains: Dict[str, Any]) -> List[str]:
        """Recognize known legitimate infrastructure patterns as informational context."""
        found: set[str] = set()
        candidates: List[str] = list(domains.get("received_domains") or [])
        if domains.get("from_domain"):
            candidates.append(domains["from_domain"])
        if domains.get("return_path_domain"):
            candidates.append(domains["return_path_domain"])

        for hop in mail_flow.get("hops", []):
            for srv in (hop.get("from_server"), hop.get("by_server")):
                if srv:
                    candidates.append(str(srv).lower())

        for provider, provider_domains in _KNOWN_PROVIDERS.items():
            for p_dom in provider_domains:
                for candidate in candidates:
                    if candidate and (candidate == p_dom or candidate.endswith("." + p_dom)):
                        found.add(provider)
                        break

        return sorted(found)

    @staticmethod
    def _address_domain(addresses: Dict[str, Any], field: str) -> Optional[str]:
        address = addresses.get(field)
        if isinstance(address, list):
            address = address[0] if address else None
        if isinstance(address, dict):
            domain = _normalized_domain(address.get("domain"))
            if domain:
                return domain
            raw_address = address.get("address")
            if isinstance(raw_address, str) and "@" in raw_address:
                return _normalized_domain(raw_address.rsplit("@", 1)[1])
        return None

    @staticmethod
    def _analyze_domains(
        source: Dict[str, Any],
        addresses: Dict[str, Any],
        headers: Dict[str, Any],
        metadata: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        from_domain = HeaderForensicsAnalyzer._address_domain(addresses, "from")
        reply_to_domain = HeaderForensicsAnalyzer._address_domain(addresses, "reply_to")
        return_path_domain = HeaderForensicsAnalyzer._address_domain(addresses, "return_path")
        sender_domain = HeaderForensicsAnalyzer._address_domain(addresses, "sender") or _normalized_domain(headers.get("sender"))

        # Display-name spoofing check (e.g. "PayPal Support <security@attacker.com>")
        from_entry = addresses.get("from")
        if isinstance(from_entry, list) and from_entry:
            from_entry = from_entry[0]
        if isinstance(from_entry, dict):
            disp_name = str(from_entry.get("display_name") or "").strip()
            actual_addr = str(from_entry.get("address") or "").strip()
            if disp_name and "@" in disp_name:
                embedded_match = re.search(r"[\w\.-]+@([a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})", disp_name)
                if embedded_match:
                    embedded_domain = _normalized_domain(embedded_match.group(1))
                    if embedded_domain and from_domain and embedded_domain != from_domain:
                        findings.append(_finding(
                            "identity.display_name.spoofing",
                            "identity",
                            "Display name contains conflicting email address",
                            f"The From display name '{disp_name}' contains an address under '{embedded_domain}', while actual sender is '{from_domain}'. This is a strong indicator of display-name deception.",
                            "high",
                            95,
                            [f"Display Name: {disp_name}", f"Actual Address: {actual_addr}"],
                            [from_domain, embedded_domain],
                            evidence_class="strong_risk_signal",
                            risk_relevance="risk_contributing",
                        ))

        message_id_raw = source.get("message_id") or metadata.get("message_id")
        message_id_domain = None
        if message_id_raw:
            match = _MESSAGE_ID_RE.match(str(message_id_raw))
            if match:
                message_id_domain = _normalized_domain(match.group(2))
            else:
                findings.append(_finding(
                    "header.message_id.malformed",
                    "header",
                    "Malformed Message-ID header",
                    "The Message-ID header is present but does not match the expected <local-part@domain> structure.",
                    "low",
                    95,
                    [str(message_id_raw)],
                    evidence_class="contextual_anomaly",
                    risk_relevance="contextual",
                ))
        else:
            findings.append(_finding(
                "header.message_id.missing",
                "header",
                "Message-ID header is missing",
                "The message has no Message-ID header, which reduces traceability but is not by itself proof of malicious activity.",
                "low",
                100,
                evidence_class="contextual_anomaly",
                risk_relevance="contextual",
            ))

        parser_auth = source.get("authentication_headers")
        parser_auth = parser_auth if isinstance(parser_auth, dict) else {}
        auth_values = _as_list(parser_auth.get("authentication-results"))
        if not auth_values:
            auth_values = _as_list(headers.get("authentication-results"))
        authentication_domains = _extract_auth_domains(auth_values)

        received_hosts: List[str] = []
        for hop in source.get("received_chain") or []:
            if not isinstance(hop, dict):
                continue
            for value in (hop.get("from_server"), hop.get("by_server")):
                domain = _normalized_domain(value)
                if domain and domain not in received_hosts:
                    received_hosts.append(domain)

        relationships = {
            "from_to_reply_to": _domain_relationship(from_domain, reply_to_domain),
            "from_to_return_path": _domain_relationship(from_domain, return_path_domain),
            "from_to_message_id": _domain_relationship(from_domain, message_id_domain),
        }
        if sender_domain:
            relationships["from_to_sender"] = _domain_relationship(from_domain, sender_domain)

        if authentication_domains:
            relationships["from_to_authentication_results"] = _domain_relationship(
                from_domain,
                authentication_domains[0],
            )
        else:
            relationships["from_to_authentication_results"] = "missing"

        if relationships["from_to_reply_to"] == "different_domain":
            findings.append(_finding(
                "domain.from_reply_to.mismatch",
                "domain",
                "Reply-To domain differs from From domain",
                "The Reply-To address points to a different domain than the visible sender. This can be legitimate for mailing lists and CRM tools, so it is recorded as contextual evidence.",
                "medium",
                95,
                [f"From domain: {from_domain}", f"Reply-To domain: {reply_to_domain}"],
                [value for value in (from_domain, reply_to_domain) if value],
                evidence_class="contextual_anomaly",
                risk_relevance="contextual",
            ))

        if relationships["from_to_return_path"] == "different_domain":
            findings.append(_finding(
                "domain.from_return_path.divergence",
                "domain",
                "Return-Path domain differs from From domain",
                "The envelope return path differs from the visible sender. This is standard for third-party ESPs (e.g. SendGrid, Mailgun) and is recorded as contextual evidence.",
                "low",
                90,
                [f"From domain: {from_domain}", f"Return-Path domain: {return_path_domain}"],
                [value for value in (from_domain, return_path_domain) if value],
                evidence_class="contextual_anomaly",
                risk_relevance="contextual",
            ))

        if relationships["from_to_message_id"] == "different_domain":
            findings.append(_finding(
                "domain.from_message_id.difference",
                "domain",
                "Message-ID domain differs from From domain",
                "The Message-ID was generated under a different domain than the visible sender. This regularly occurs with cloud relays and transactional mailers.",
                "low",
                85,
                [f"From domain: {from_domain}", f"Message-ID domain: {message_id_domain}"],
                [value for value in (from_domain, message_id_domain) if value],
                evidence_class="contextual_anomaly",
                risk_relevance="contextual",
            ))

        return {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "sender_domain": sender_domain,
            "message_id_domain": message_id_domain,
            "received_domains": received_hosts,
            "authentication_results_domains": authentication_domains,
            "relationships": relationships,
        }

    @staticmethod
    def _received_ip_values(hop: Dict[str, Any]) -> List[str]:
        """Recover valid IP literals, correcting incomplete parser IPv6 matches."""
        raw_values = hop.get("ips") if isinstance(hop.get("ips"), list) else []
        raw_text = str(hop.get("raw") or "")
        candidates = _IP_CANDIDATE_RE.findall(raw_text)
        values: List[str] = []
        for value in [*raw_values, *candidates]:
            try:
                parsed = ipaddress.ip_address(str(value).strip("[]"))
            except ValueError:
                continue
            normalized = str(parsed)
            if normalized not in values:
                values.append(normalized)
        return values

    @staticmethod
    def _analyze_mail_flow(source: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        received_chain = source.get("received_chain") or []
        if not isinstance(received_chain, list):
            received_chain = []

        hops: List[Dict[str, Any]] = []
        seen_ips: set[str] = set()
        ip_addresses: List[Dict[str, Any]] = []
        timestamps: List[Tuple[int, datetime]] = []
        missing_timestamps: List[int] = []

        for index, raw_hop in enumerate(received_chain):
            hop = raw_hop if isinstance(raw_hop, dict) else {"raw": str(raw_hop)}
            raw_ips = HeaderForensicsAnalyzer._received_ip_values(hop)
            ipv4 = []
            ipv6 = []
            classifications = []
            for raw_ip in raw_ips:
                classified = _classify_ip(raw_ip)
                classifications.append(classified)
                if classified["version"] == 4:
                    ipv4.append(classified["ip"])
                elif classified["version"] == 6:
                    ipv6.append(classified["ip"])
                if classified["ip"] not in seen_ips:
                    seen_ips.add(classified["ip"])
                    ip_addresses.append(classified)

            timestamp_raw = hop.get("timestamp")
            timestamp = _parse_timestamp(timestamp_raw)
            if timestamp:
                timestamps.append((index, timestamp))
            else:
                missing_timestamps.append(index)

            from_server = hop.get("from_server")
            by_server = hop.get("by_server")
            timestamp_iso = _timestamp_iso(timestamp)

            # Phase 3: Stable deterministic Hop Identity (hop_id)
            import hashlib
            hasher = hashlib.sha256()
            hasher.update(str(index).encode())
            hasher.update((from_server or "").encode())
            hasher.update((by_server or "").encode())
            hasher.update((timestamp_iso or "").encode())
            hasher.update(str(hop.get("raw") or "").encode())
            hop_id = "hop_" + hasher.hexdigest()[:16]

            normalized_hop = {
                "hop_id": hop_id,
                "hop_index": index,
                "hop_number": index + 1,
                "raw": hop.get("raw") or "",
                "from_server": from_server,
                "by_server": by_server,
                "from_domain": _normalized_domain(from_server),
                "by_domain": _normalized_domain(by_server),
                "protocol": hop.get("protocol"),
                "ipv4_addresses": ipv4,
                "ipv6_addresses": ipv6,
                "ip_classifications": classifications,
                "timestamp": timestamp_raw,
                "timestamp_utc": timestamp_iso,
                "timezone": _timezone_label(timestamp_raw),
                "header_position": "newest_to_oldest",
                "parse_status": hop.get("parse_status", "ok"),
            }
            hops.append(normalized_hop)

            for classified in classifications:
                if classified["classification"] in {"private", "loopback", "link_local", "reserved", "unspecified"}:
                    findings.append(_finding(
                        f"ip.received.{classified['classification']}.{classified['ip']}",
                        "ip",
                        f"{classified['classification'].replace('_', ' ').title()} IP in Received header",
                        "A non-public IP address appears in a Received header. This reflects internal network hops or VPN routing and is not a reputation judgment.",
                        "info",
                        100,
                        [f"Hop {index}: {classified['ip']}"],
                        [classified["ip"]],
                        evidence_class="informational",
                        risk_relevance="informational",
                    ))

        if not hops:
            findings.append(_finding(
                "mail_flow.received.missing",
                "mail_flow",
                "Received headers are missing",
                "No Received header chain is available, so delivery routing cannot be reconstructed.",
                "low",
                100,
                evidence_class="contextual_anomaly",
                risk_relevance="contextual",
            ))

        timeline_entries: List[Dict[str, Any]] = []
        chronological = sorted(timestamps, key=lambda item: item[1])
        for position, (hop_index, timestamp) in enumerate(chronological):
            previous = chronological[position - 1][1] if position else None
            timeline_entries.append({
                "hop_index": hop_index,
                "timestamp_utc": _timestamp_iso(timestamp),
                "delay_from_previous_seconds": (
                    int((timestamp - previous).total_seconds()) if previous else None
                ),
            })

        if len(timestamps) >= 2:
            header_times = [timestamp for _, timestamp in timestamps]
            unexpected = any(
                header_times[position] < header_times[position + 1]
                for position in range(len(header_times) - 1)
            )
            if unexpected:
                findings.append(_finding(
                    "timing.received.header_order",
                    "timing",
                    "Received timestamps do not follow expected header order",
                    "Received headers are normally ordered newest to oldest; one or more parsed timestamps suggest an ordering inconsistency.",
                    "low",
                    80,
                    [f"Hop {index}: {_timestamp_iso(timestamp)}" for index, timestamp in timestamps],
                    evidence_class="contextual_anomaly",
                    risk_relevance="contextual",
                ))

        if missing_timestamps and hops:
            findings.append(_finding(
                "timing.received.timestamps_missing",
                "timing",
                "One or more Received timestamps are unavailable",
                "Delivery timing is partial because some Received headers lack a usable timestamp.",
                "info",
                100,
                [f"Hop indexes: {', '.join(map(str, missing_timestamps))}"],
                evidence_class="informational",
                risk_relevance="informational",
            ))

        first = chronological[0][1] if chronological else None
        last = chronological[-1][1] if chronological else None
        origin_hop = hops[-1] if hops else None
        final_hop = hops[0] if hops else None
        origin_ip = None
        if origin_hop:
            origin_ip = next(
                (item["ip"] for item in origin_hop["ip_classifications"] if item["classification"] != "invalid/unknown"),
                None,
            )

        return {
            "hops": hops,
            "hop_count": len(hops),
            "origin_ip": origin_ip,
            "final_destination": final_hop.get("by_server") if final_hop else None,
            "timeline": timeline_entries,
            "first_observed_timestamp": _timestamp_iso(first),
            "last_observed_timestamp": _timestamp_iso(last),
            "total_transit_seconds": int((last - first).total_seconds()) if first and last else None,
            "missing_timestamp_hop_indexes": missing_timestamps,
            "ip_addresses": ip_addresses,
        }

    @staticmethod
    def _analyze_authentication(source: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        headers = source.get("headers") if isinstance(source.get("headers"), dict) else {}
        parser_auth = source.get("authentication_headers")
        auth_headers = parser_auth if isinstance(parser_auth, dict) else {}
        auth_results = _as_list(auth_headers.get("authentication-results") or headers.get("authentication-results"))
        received_spf = _as_list(auth_headers.get("received-spf") or headers.get("received-spf"))
        dkim_signatures = _as_list(auth_headers.get("dkim-signature") or headers.get("dkim-signature"))
        arc_headers = {
            key: _as_list(auth_headers.get(key) or headers.get(key))
            for key in ("arc-seal", "arc-message-signature", "arc-authentication-results")
        }

        normalized: Dict[str, Dict[str, Any]] = {
            "spf": HeaderForensicsAnalyzer._auth_entry(),
            "dkim": HeaderForensicsAnalyzer._auth_entry(),
            "dmarc": HeaderForensicsAnalyzer._auth_entry(),
            "arc": HeaderForensicsAnalyzer._auth_entry(),
        }

        for value in auth_results:
            for mechanism, status in _AUTH_RESULT_RE.findall(value):
                entry = normalized[mechanism.lower()]
                if entry["status"] is None:
                    entry["status"] = status.lower()
                entry["available"] = True
                entry["sources"].append("authentication-results")
                entry["reported_by_header"].append(value)
                entry["verified"] = False

        for value in received_spf:
            status_match = re.match(r"\s*([a-zA-Z][a-zA-Z0-9_-]*)", value)
            entry = normalized["spf"]
            entry["available"] = True
            if entry["status"] is None and status_match:
                entry["status"] = status_match.group(1).lower()
            entry["sources"].append("received-spf")
            entry["reported_by_header"].append(value)

        for value in dkim_signatures:
            entry = normalized["dkim"]
            entry["available"] = True
            entry["sources"].append("dkim-signature")
            entry["reported_by_header"].append(value)

        for key, values in arc_headers.items():
            for value in values:
                entry = normalized["arc"]
                entry["available"] = True
                entry["sources"].append(key)
                entry["reported_by_header"].append(value)

        for mechanism, entry in normalized.items():
            entry["sources"] = list(dict.fromkeys(entry["sources"]))
            entry["reported_by_header"] = list(dict.fromkeys(entry["reported_by_header"]))
            if entry["available"]:
                findings.append(_finding(
                    f"authentication.{mechanism}.reported",
                    "authentication",
                    f"{mechanism.upper()} header evidence is available",
                    "Authentication evidence was reported by message headers; it was not independently verified during this analysis.",
                    "info",
                    100,
                    [f"Reported status: {entry['status'] or 'not specified'}", *entry["sources"]],
                    evidence_class="informational",
                    risk_relevance="informational",
                ))

        return normalized

    @staticmethod
    def _auth_entry() -> Dict[str, Any]:
        return {
            "available": False,
            "status": None,
            "sources": [],
            "reported_by_header": [],
            "verified": False,
        }

    @staticmethod
    def _analyze_header_completeness(
        source: Dict[str, Any],
        metadata: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        subject = source.get("subject") if source.get("subject") is not None else metadata.get("subject")
        date_value = source.get("date") if source.get("date") is not None else metadata.get("date")
        from_value = source.get("from") if source.get("from") is not None else metadata.get("from")
        required = {
            "from": bool(from_value),
            "to": bool(source.get("to") or metadata.get("to")),
            "subject": subject is not None,
            "date": bool(date_value),
            "message_id": bool(source.get("message_id") or metadata.get("message_id")),
        }

        if not date_value:
            findings.append(_finding(
                "header.date.missing",
                "header",
                "Date header is missing",
                "The message has no Date header, preventing confirmation of the sender-reported send time.",
                "low",
                100,
                evidence_class="contextual_anomaly",
                risk_relevance="contextual",
            ))
        else:
            parsed_date = _parse_timestamp(str(date_value))
            if not parsed_date:
                findings.append(_finding(
                    "header.date.invalid",
                    "header",
                    "Date header is malformed",
                    "The Date header could not be parsed as an RFC-style timestamp.",
                    "low",
                    100,
                    [str(date_value)],
                    evidence_class="contextual_anomaly",
                    risk_relevance="contextual",
                ))
            else:
                now = datetime.now(timezone.utc)
                if parsed_date > now:
                    findings.append(_finding(
                        "header.date.future",
                        "header",
                        "Date header is in the future",
                        "The sender-reported Date is later than the analysis time. Clock skew can explain this, so it is retained as forensic evidence.",
                        "low",
                        95,
                        [_timestamp_iso(parsed_date) or ""],
                        evidence_class="contextual_anomaly",
                        risk_relevance="contextual",
                    ))
                if _timezone_label(str(date_value)) is None:
                    findings.append(_finding(
                        "header.date.timezone_missing",
                        "header",
                        "Date header has no explicit timezone",
                        "The Date header lacks a detectable timezone, making exact temporal correlation less reliable.",
                        "info",
                        90,
                        [str(date_value)],
                        evidence_class="informational",
                        risk_relevance="informational",
                    ))

        return {
            "required_headers": required,
            "present_count": sum(required.values()),
            "missing_headers": [name for name, present in required.items() if not present],
            "date_timezone": _timezone_label(str(date_value)) if date_value else None,
        }

    @staticmethod
    def _analyze_duplicates(headers: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, int]:
        duplicates: Dict[str, int] = {}
        lowered_headers = {str(key).lower(): value for key, value in headers.items()}
        for name in HeaderForensicsAnalyzer._DUPLICATE_HEADERS:
            values = _as_list(lowered_headers.get(name))
            if len(values) <= 1:
                continue
            duplicates[name] = len(values)
            severity = "low" if name in {"from", "reply-to", "return-path", "date", "message-id"} else "info"
            findings.append(_finding(
                f"header.duplicate.{name}",
                "header" if not name.startswith("arc") else "authentication",
                f"Duplicate {name} header",
                "Multiple instances of this security-relevant header are present. This is reported for review and is not by itself a malicious classification.",
                severity,
                100,
                [f"Occurrences: {len(values)}"],
                evidence_class="contextual_anomaly",
                risk_relevance="contextual",
            ))
        return duplicates

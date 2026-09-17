# 🏆 Standout Strategy + Full Upgrade Plan — SIH 2026

> **Project**: Email Threat Detection & Intelligence Platform  
> **Organization**: AICTE — Cyber Security Cell  
> **Theme**: Blockchain & Cybersecurity

---

## Part 1 — What Will Make Us Stand Out

### What 90% of Teams Will Build (the "Basic" Version)

- Upload email → show headers → "phishing detected" label
- Maybe VirusTotal API
- Simple ML classifier
- Basic React dashboard
- No forensic output, no geo tracing

**Our project is already miles ahead of this.** But to truly stand out:

---

### 🏆 7 Things That Will Make Judges Remember Us

#### 1. 🔗 Blockchain Evidence Ledger (Theme Match!)

> Our SIH theme is literally **"Blockchain & Cybersecurity"** — yet most email security projects will ignore the blockchain part. This is our **#1 differentiator**.

**What to do**: Store evidence hashes on a blockchain for tamper-proof chain-of-custody.

| Approach | Effort | How |
|---|---|---|
| **Ethereum Sepolia testnet** (free) | 4-5 hrs | Deploy a simple smart contract that stores `SHA-256(email) + timestamp + analyst_id`. Use `web3.py` + free Alchemy/Infura API. |
| **Polygon Mumbai testnet** (free, fast) | 4-5 hrs | Same as above, near-instant confirmations |
| **IPFS + hash anchoring** | 3 hrs | Store forensic report on IPFS (Pinata free tier), anchor hash on-chain |

**Why it wins**: When a judge asks *"where's the blockchain?"*, we say:

> *"Every forensic report gets its SHA-256 hash written to an immutable blockchain ledger. This gives legal-grade evidence integrity — no one can tamper with the investigation after the fact. The transaction ID is embedded in the PDF report for verification."*

**Nobody else will do this.** It directly matches the theme and solves the real problem of evidence integrity for law enforcement.

---

#### 2. 🎯 Live Demo With Real Phishing Emails

**Don't demo with fake data.** During the presentation:

- Have 3-4 **real phishing emails** ready (from spam folder, publicly available samples, or PhishBowl)
- Upload them **live** in front of judges
- Show the platform detecting threats in **real-time** (our pipeline already does this!)
- Show the geo trace map lighting up with the attacker's origin

**Impact**: Judges see it's not a toy — it works on actual threats.

---

#### 3. 🇮🇳 India-Specific Threat Intelligence

Most tools are US/Europe focused. Our platform is for **AICTE** (Indian government). Add India context:

| Feature | What to Add |
|---|---|
| **Indian bank impersonation detection** | Detect spoofing of SBI, HDFC, ICICI, PNB, Paytm, PhonePe, UPI-related phishing |
| **Indian government domain whitelist** | `.gov.in`, `.nic.in`, `.ac.in` — flag emails claiming to be from these but sent from elsewhere |
| **Hindi/regional language phishing** | Note in NLP analysis that multilingual phishing is detected (even if basic) |
| **UPI fraud patterns** | Detect "UPI refund", "KYC update", "Aadhaar verification" scam patterns |
| **Indian timezone correlation** | If email claims to be from an Indian org but originates from a non-IST timezone, flag it |

**Why it wins**: Shows the solution is **contextualized for India**, not a generic global tool. AICTE judges will love this.

---

#### 4. 📊 Attack Simulation / Red Team Mode

Add a **"Simulate Attack"** feature where you can craft a test email and see how the platform would score it:

```
[Simulate Attack Page]
From: ____  (e.g., ceo@your-org.com)
To: ____
Subject: ____
Body: ____
☐ Spoof SPF   ☐ Fake DKIM   ☐ Lookalike domain

[Run Simulation] → Shows risk score, what was detected, what wasn't
```

**Why it wins**: Judges can **interact** with it. It shows the platform doesn't just detect — it helps **train security teams** by showing what would and wouldn't be caught.

---

#### 5. 📱 One-Click "Report to CERT-In" Export

India's national CERT is **CERT-In**. Add a button:

> **📤 Report to CERT-In**

That generates a pre-formatted incident report in CERT-In's expected format with:
- Incident type (phishing / BEC / malware)
- Attacker IP + geolocation
- IOCs (URLs, domains, IPs, hashes)
- Timeline
- Evidence attachments

**Why it wins**: Shows we understand the **real-world workflow** — detection isn't enough, the finding needs to reach the right authority. Nobody else will have this.

---

#### 6. ⚡ Speed + Scale Story

During the demo, **show the processing speed**:

Our project already has `stage_timing.py` tracking per-stage timing. Display it:

```
Email parsed .............. 120ms
Header forensics .......... 340ms
SPF/DKIM/DMARC ............ 280ms
NLP content analysis ...... 450ms
URL intelligence .......... 380ms
GeoIP enrichment .......... 220ms
Threat intel (6 providers). 890ms
Risk scoring .............. 50ms
────────────────────────────────
Total analysis time: 2.7 seconds
```

**Why it wins**: Shows engineering maturity. We're not just "it works" — we've measured and optimized it.

---

#### 7. 🔬 Explainable AI — "Why Did We Flag This?"

We already have `threat_reasoning.py`. Make it **front and center** in the UI:

Instead of just showing "Score: 87 — Phishing", show:

```
⚠️ This email was classified as PHISHING (87/100) because:

1. 🔴 SPF authentication FAILED — sender IP 185.x.x.x is not authorized 
      to send for paypa1.com
2. 🔴 Domain "paypa1.com" is a homoglyph of "paypal.com" 
      (registered 3 days ago)
3. 🟡 Email body contains urgency language: "immediate action required", 
      "account suspended", "verify within 24 hours"
4. 🔴 URL redirects through bit.ly to a credential harvesting page
5. 🟡 Originating IP (Lagos, Nigeria) is hosted on DigitalOcean 
      behind a VPN proxy
```

**Why it wins**: Judges understand the reasoning. It's not a black box. This is the difference between a "student project" and a "production tool."

---

### 🎯 The Standout Formula

| What Others Do | What We Should Do |
|---|---|
| Generic phishing detector | **India-specific** threat detection (UPI, SBI, .gov.in) |
| No blockchain | **Blockchain evidence ledger** (matches theme directly) |
| Fake demo data | **Live demo** with real phishing emails |
| "Phishing detected" label | **Explainable AI** — 5 reasons why, human-readable |
| No output | **PDF forensic report** + **CERT-In export** |
| Static dashboard | **Relay trace map** + **evidence graph** + **attack simulation** |
| No speed metrics | **2.7 second analysis** with stage-by-stage timing |

**The winning formula: Blockchain + India context + Live demo + Visual forensics + Explainability**

---

---

## Part 2 — Gaps vs SIH Problem Statement

| Requirement from Problem Statement | Current Status | Priority |
|---|---|---|
| **PDF/DOCX Forensic Report Generation** | ❌ Not implemented (Reports page exists but no PDF export) | 🔴 High |
| **Relay Path Visual Trace Map** | ❌ No SMTP hop-by-hop map visualization | 🔴 High |
| **VPN/TOR/Proxy Detection** | ❌ No anonymization detection on originating IPs | 🔴 High |
| **Graph-based entity visualization** (interactive) | ⚠️ Backend `evidence_graph.py` exists but no frontend graph UI | 🟡 Medium |
| **Real-time WebSocket alerts** | ⚠️ Webhook exists but no live push to dashboard | 🟡 Medium |
| **Deep Learning model** (BERT/Transformer) | ⚠️ Only TF-IDF + LogReg; no transformer model | 🟡 Medium |
| **Chain-of-custody evidence hashing** | ⚠️ SHA-256 exists for raw email but no full audit chain | 🟡 Medium |
| **Searchable case management** | ⚠️ Campaign correlation exists but no case grouping UI | 🟡 Medium |
| **PhishTank integration** | ❌ Not integrated | 🟢 Low |
| **Spamhaus DNSBL** | ❌ Not integrated | 🟢 Low |
| **TOR exit node list** checking | ❌ Not integrated | 🟢 Low |

---

---

## Part 3 — Phase-by-Phase Upgrade Roadmap

### Phase 1 — Quick Wins (1–2 hours each)

> These can all be done in a single day. Each one adds a tangible feature with minimal code changes. All APIs are **100% free**.

---

#### 1.1 VPN / Proxy / Hosting Detection via ip-api.com

**⏱ Effort**: 1 hour  
**💰 Cost**: Free (already using ip-api.com as fallback)  
**📁 File to modify**: `backend/app/services/geo_enricher.py`

**What to do**:

The ip-api.com fallback URL at line 96 is:
```
http://ip-api.com/json/{clean_ip}
```

Change it to include proxy/hosting/mobile fields:
```
http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,city,lat,lon,isp,org,as,proxy,hosting,mobile
```

Then in the result parsing section (~line 143–158), extract and include:
```python
result = {
    "latitude": float(lat),
    "longitude": float(lon),
    "country": str(country),
    "country_code": str(country_code) if country_code else None,
    "city": data.get("city"),
    "geo_source": source_label,
    # NEW FIELDS
    "is_proxy": data.get("proxy", False),
    "is_hosting": data.get("hosting", False),
    "is_mobile": data.get("mobile", False),
    "isp": data.get("isp"),
    "org": data.get("org"),
    "asn": data.get("as"),
}
```

**Frontend**: Display a badge on the analysis result page: `🔒 VPN/Proxy Detected` or `☁️ Hosted Infrastructure`.

---

#### 1.2 Domain Age Extraction from RDAP

**⏱ Effort**: 1 hour  
**💰 Cost**: Free (RDAP is already integrated)  
**📁 File to modify**: `backend/app/services/threat_intelligence.py` — `RDAPProvider` class (~line 298)

**What to do**:

In the `RDAPProvider.lookup()` method, after parsing the RDAP response, extract domain registration date:

```python
# Inside RDAPProvider.lookup(), after getting payload
events = payload.get("events", [])
registration_date = None
domain_age_days = None

for event in events:
    if event.get("eventAction") == "registration":
        try:
            from datetime import datetime, timezone
            reg_str = event.get("eventDate", "")
            reg_dt = datetime.fromisoformat(reg_str.replace("Z", "+00:00"))
            registration_date = reg_str
            domain_age_days = (datetime.now(timezone.utc) - reg_dt).days
        except (ValueError, TypeError):
            pass
        break

# Add to metadata dict
metadata={
    "name": payload.get("name"),
    "ldh_name": payload.get("ldhName"),
    "status": payload.get("status", []),
    "events": payload.get("events", []),
    # NEW
    "registration_date": registration_date,
    "domain_age_days": domain_age_days,
    "is_newly_registered": domain_age_days is not None and domain_age_days < 30,
}
```

**Impact**: Any domain registered < 30 days ago is flagged as suspicious. This is a **very strong phishing indicator**.

---

#### 1.3 Shodan InternetDB Integration

**⏱ Effort**: 1 hour  
**💰 Cost**: Free, **no API key needed**  
**📁 New file**: `backend/app/integrations/shodan_internetdb.py`

**API**: `GET https://internetdb.shodan.io/{ip}`

**Response** (no auth required):
```json
{
  "cpes": ["cpe:/a:apache:http_server:2.4.41"],
  "hostnames": ["mail.example.com"],
  "ip": "1.2.3.4",
  "ports": [22, 25, 80, 443, 587],
  "tags": ["self-signed", "cloud"],
  "vulns": ["CVE-2021-44228"]
}
```

**Create the service**:

```python
# backend/app/integrations/shodan_internetdb.py
import httpx
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class ShodanInternetDBService:
    """Free Shodan InternetDB lookup — no API key required."""

    BASE_URL = "https://internetdb.shodan.io"

    async def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.BASE_URL}/{ip}")
                if response.status_code == 404:
                    return {"status": "not_found", "ip": ip}
                if response.status_code != 200:
                    return None
                data = response.json()
                return {
                    "ip": ip,
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                    "cpes": data.get("cpes", []),
                    "has_smtp": 25 in data.get("ports", []) or 587 in data.get("ports", []),
                    "vuln_count": len(data.get("vulns", [])),
                }
        except Exception as e:
            logger.debug(f"Shodan InternetDB lookup failed for {ip}: {e}")
            return None
```

**Wire it into** the analysis pipeline in `backend/app/api/routes/analysis.py` — call it after GeoIP enrichment on the originating IP.

**Value**: Shows open ports (is SMTP port 25 open?), known vulnerabilities, and whether the IP is tagged as "cloud" or "self-signed". Free infrastructure fingerprinting.

---

#### 1.4 Spamhaus DNSBL Check

**⏱ Effort**: 1 hour  
**💰 Cost**: Free (DNS-based, uses `dnspython` — already in deps)  
**📁 New file**: `backend/app/integrations/spamhaus_dnsbl.py`

**How DNSBL works**: Reverse the IP octets and query `{reversed}.zen.spamhaus.org`. If it resolves, the IP is blacklisted.

```python
# backend/app/integrations/spamhaus_dnsbl.py
import dns.resolver
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

DNSBL_ZONES = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
]

SPAMHAUS_CODES = {
    "127.0.0.2": "SBL (direct spam source)",
    "127.0.0.3": "SBL CSS (spam domain)",
    "127.0.0.4": "XBL (exploited host)",
    "127.0.0.9": "DROP (hijacked netblock)",
    "127.0.0.10": "PBL (end-user IP, should not send mail)",
    "127.0.0.11": "PBL (ISP policy block)",
}

async def check_dnsbl(ip: str) -> Dict[str, Any]:
    """Check if an IP is listed on DNS-based blacklists."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    listings = []

    for zone, zone_name in DNSBL_ZONES:
        query = f"{reversed_ip}.{zone}"
        try:
            answers = dns.resolver.resolve(query, "A")
            for rdata in answers:
                code = str(rdata)
                reason = SPAMHAUS_CODES.get(code, "Listed")
                listings.append({
                    "zone": zone_name,
                    "code": code,
                    "reason": reason,
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception as e:
            logger.debug(f"DNSBL check failed for {ip} on {zone}: {e}")

    return {
        "ip": ip,
        "is_blacklisted": len(listings) > 0,
        "blacklist_count": len(listings),
        "listings": listings,
    }
```

**No API key needed.** Just DNS queries via `dnspython`.

---

#### 1.5 TOR Exit Node List

**⏱ Effort**: 2 hours  
**💰 Cost**: Free (official TOR Project list)  
**📁 New file**: `backend/app/integrations/tor_exit_nodes.py`

**Source**: `https://check.torproject.org/torbulkexitlist`  
Updated every ~30 minutes. Download and cache.

```python
# backend/app/integrations/tor_exit_nodes.py
import httpx
import logging
import time
from typing import Set

logger = logging.getLogger(__name__)

class TorExitNodeChecker:
    """Check if an IP is a known TOR exit node."""

    TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
    _cache: Set[str] = set()
    _cache_time: float = 0
    CACHE_TTL = 3600  # refresh every hour

    @classmethod
    async def _refresh_cache(cls) -> None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(cls.TOR_LIST_URL)
                if response.status_code == 200:
                    lines = response.text.strip().split("\n")
                    cls._cache = {
                        line.strip() for line in lines
                        if line.strip() and not line.startswith("#")
                    }
                    cls._cache_time = time.monotonic()
                    logger.info(f"TOR exit node list refreshed: {len(cls._cache)} nodes")
        except Exception as e:
            logger.warning(f"Failed to refresh TOR exit node list: {e}")

    @classmethod
    async def is_tor_exit(cls, ip: str) -> bool:
        if time.monotonic() - cls._cache_time > cls.CACHE_TTL:
            await cls._refresh_cache()
        return ip.strip() in cls._cache

    @classmethod
    async def check_ip(cls, ip: str) -> dict:
        is_tor = await cls.is_tor_exit(ip)
        return {
            "ip": ip,
            "is_tor_exit_node": is_tor,
            "source": "torproject.org/torbulkexitlist",
            "cache_size": len(cls._cache),
        }
```

**Wire into** `geo_enricher.py` or the analysis pipeline — add `is_tor_exit_node` to the geo result.

---

#### 1.6 PhishTank Integration

**⏱ Effort**: 2 hours  
**💰 Cost**: Free (requires signup at phishtank.org)  
**📁 File to modify**: `backend/app/services/threat_intelligence.py`  
**📁 File to modify**: `backend/app/core/config.py`

**Add to config.py**:
```python
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
```

**Add new provider class** (follow the existing `URLhausProvider` pattern):

```python
class PhishTankProvider(ThreatIntelProvider):
    """PhishTank verified phishing URL lookup."""

    def __init__(self) -> None:
        super().__init__("PhishTank", settings.PHISHTANK_API_KEY)
        self.supported_indicator_types = {"url"}

    async def lookup(self, indicator_type: str, indicator: str,
                     client: Optional[httpx.AsyncClient] = None) -> ProviderResult:
        if not self.is_healthy():
            return self.unavailable_result(indicator_type, indicator)
        value = _normalize_indicator(indicator_type, indicator)
        if indicator_type != "url" or not value:
            return self.invalid_result(indicator_type, indicator)
        try:
            payload = {
                "url": value,
                "format": "json",
                "app_key": self.api_key,
            }
            if client is not None:
                response = await client.post(
                    "https://checkurl.phishtank.com/checkurl/",
                    data=payload
                )
            else:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as lc:
                    response = await lc.post(
                        "https://checkurl.phishtank.com/checkurl/",
                        data=payload
                    )
            if response.status_code != 200:
                return _result(self.name, value, indicator_type, "error")
            data = response.json().get("results", {})
            is_phish = data.get("in_database") and data.get("valid")
            return _result(
                self.name, value, indicator_type, "ok",
                "malicious" if is_phish else "unknown",
                1 if is_phish else 0,
                95 if is_phish else 0,
                ["phishing"] if is_phish else [],
                references=[data.get("phish_detail_page", "")],
            )
        except httpx.TimeoutException:
            return _result(self.name, value, indicator_type, "timeout")
        except (httpx.HTTPError, ValueError):
            return _result(self.name, value, indicator_type, "error")
```

**Register it** in the `ThreatIntelligenceService` provider list alongside existing providers.

---

### Phase 2 — High Priority (3–5 hours each)

> These three features are **explicitly mentioned** in the SIH problem statement. Judges will look for them.

---

#### 2.1 PDF Forensic Report Generation

**⏱ Effort**: 4–5 hours  
**💰 Cost**: Free  
**📦 Install**: `pip install weasyprint jinja2`  
**📁 New files**:
- `backend/app/services/pdf_report.py` — Report generation logic
- `backend/app/templates/forensic_report.html` — Jinja2 HTML template
- `backend/app/api/routes/analysis.py` — New export endpoint

**Step 1 — Create the HTML template** (`backend/app/templates/forensic_report.html`):

Include these sections in the template:
1. **Header**: Platform logo, report ID, generation timestamp, SHA-256 hash
2. **Executive Summary**: Risk verdict, confidence score, classification
3. **Email Metadata Table**: From, To, Subject, Date, Message-ID, Return-Path
4. **Authentication Results**: SPF ✅/❌, DKIM ✅/❌, DMARC ✅/❌ with details
5. **Relay Path Table**: Hop #, Server, IP, Country, City, Timestamp
6. **Geolocation Map**: Static map image (Geoapify Static Maps API — free 3K/day)
7. **URL Analysis Table**: URL, verdict, redirect chain, domain age
8. **IOC Table**: Type, Value, Severity, Source
9. **MITRE ATT&CK Techniques**: Technique ID, Name, Tactic (already computed)
10. **NLP Content Analysis**: Phishing score, urgency cues, social engineering patterns
11. **Attribution Assessment**: Confidence score, VPN/TOR flags, infrastructure analysis
12. **Evidence Integrity**: SHA-256 of original .eml, analysis timestamp, analyst ID

**Step 2 — Create the PDF service** (`backend/app/services/pdf_report.py`):

```python
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from pathlib import Path
import io

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

def generate_forensic_pdf(analysis_data: dict) -> bytes:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("forensic_report.html")
    html_content = template.render(analysis=analysis_data)
    pdf_bytes = HTML(string=html_content).write_pdf()
    return pdf_bytes
```

**Step 3 — Add API endpoint** in `backend/app/api/routes/analysis.py`:

```python
from fastapi.responses import StreamingResponse

@router.get("/analysis/{analysis_id}/export/pdf")
async def export_analysis_pdf(analysis_id: str, db: Session = Depends(get_db)):
    # Fetch analysis result (similar to existing export_analysis_json)
    # Generate PDF
    from app.services.pdf_report import generate_forensic_pdf
    pdf_bytes = generate_forensic_pdf(analysis_dict)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=forensic_report_{analysis_id}.pdf"}
    )
```

**Step 4 — Add PDF button to frontend** `frontend/src/pages/Reports.tsx`:

Add a new export button alongside the existing JSON and HTML export buttons.

**Static Map Image for PDF** (free):
```
https://maps.geoapify.com/v1/staticmap?style=dark-matter&width=600&height=300&marker=lonlat:{lon},{lat};color:red&apiKey={GEOAPIFY_KEY}
```
We already have `VITE_GEOAPIFY_API_KEY` configured!

---

#### 2.2 Relay Path Visual Trace Map

**⏱ Effort**: 4–5 hours  
**💰 Cost**: Free (MapLibre GL already in deps)  
**📁 New files**:
- `frontend/src/components/analysis/RelayPathMap.tsx` — Interactive map component
- `backend/app/services/relay_path_builder.py` — Structured relay path with geo data

**Step 1 — Backend: Build structured relay path** (`backend/app/services/relay_path_builder.py`):

```python
"""Build a geo-enriched relay path from email headers."""

from typing import Any, Dict, List
from app.services.geo_enricher import GeoEnricher

async def build_relay_path(header_forensics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract relay hops and enrich each with geolocation."""
    hops = header_forensics.get("relay_chain", [])
    enriched_hops = []

    for i, hop in enumerate(hops):
        ip = hop.get("ip")
        geo = None
        if ip and GeoEnricher.is_public_ip(ip):
            geo = await GeoEnricher.enrich_ip(ip)

        enriched_hops.append({
            "hop_number": i + 1,
            "from_server": hop.get("from_host", "Unknown"),
            "by_server": hop.get("by_host", "Unknown"),
            "ip": ip,
            "timestamp": hop.get("timestamp"),
            "geo": geo,
            "is_private": not GeoEnricher.is_public_ip(ip) if ip else True,
        })

    return enriched_hops
```

**Step 2 — Frontend: Interactive Relay Map** (`frontend/src/components/analysis/RelayPathMap.tsx`):

Use MapLibre GL (already in `package.json`) to:
1. Plot each relay hop as a numbered marker on the world map
2. Draw animated lines connecting hops in sequence
3. Color-code: 🟢 safe hops, 🔴 suspicious/flagged hops, ⚫ private IPs (no geo)
4. Tooltip on each marker: server name, IP, country, city, timestamp
5. Highlight the originating hop (first public IP) with a special marker

**Map tiles** (free): Use Geoapify tiles (key already configured in `.env`):
```
https://maps.geoapify.com/v1/tile/dark-matter/{z}/{x}/{y}.png?apiKey={key}
```

---

#### 2.3 Live SPF/DKIM Re-Verification

**⏱ Effort**: 3 hours  
**💰 Cost**: Free (open-source libraries)  
**📦 Install**: `pip install dkimpy pyspf`  
**📁 New file**: `backend/app/services/live_auth_verifier.py`

**Why**: Our `header_forensics.py` currently only **parses** the `Authentication-Results` header — it trusts what the receiving server reported. Adding **live verification** independently confirms the results.

```python
# backend/app/services/live_auth_verifier.py
"""Live SPF and DKIM verification using dkimpy and pyspf."""

import dkim
import spf
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

async def verify_dkim(raw_email: bytes) -> Dict[str, Any]:
    """Independently verify DKIM signature on raw email bytes."""
    try:
        result = dkim.verify(raw_email)
        return {
            "dkim_live_result": "pass" if result else "fail",
            "verified_independently": True,
        }
    except dkim.DKIMException as e:
        return {"dkim_live_result": "error", "error": str(e)}
    except Exception as e:
        return {"dkim_live_result": "error", "error": str(e)}

def verify_spf(ip: str, sender_email: str, helo_domain: str) -> Dict[str, Any]:
    """Independently verify SPF for the sending IP."""
    try:
        result, explanation = spf.check2(
            i=ip, s=sender_email, h=helo_domain
        )
        return {
            "spf_live_result": result,
            "spf_explanation": explanation,
            "verified_independently": True,
        }
    except Exception as e:
        return {"spf_live_result": "error", "error": str(e)}
```

**Wire into pipeline**: Call after `header_forensics` stage. Compare live results with header-reported results — if they disagree, flag as anomaly.

---

### Phase 3 — Medium Priority (4–6 hours each)

---

#### 3.1 Interactive Evidence Graph Visualization

**⏱ Effort**: 4–5 hours  
**💰 Cost**: Free  
**📦 Install**: `npm install vis-network vis-data`  
**📁 New file**: `frontend/src/components/analysis/EvidenceGraph.tsx`

**Backend**: Already done! `evidence_graph.py` builds nodes + edges.

**Frontend**: Create a vis-network component showing:
- Email node at center
- Connected domains, IPs, URLs, attachments as satellite nodes
- Edges labeled with relationship type
- Click a node → sidebar shows details
- Color/size by risk level

Node type → color mapping:
```
email: "#06b6d4"      (cyan)
domain: "#f59e0b"     (amber)
ip: "#ef4444"         (red)
sender: "#22c55e"     (green)
url: "#a855f7"        (purple)
attachment: "#f97316"  (orange)
campaign: "#ec4899"   (pink)
```

---

#### 3.2 Real-Time WebSocket Alerts

**⏱ Effort**: 4 hours  
**💰 Cost**: Free (FastAPI built-in WebSocket)  
**📁 Files to modify**:
- `backend/app/main.py` — Add WebSocket endpoint
- `backend/app/services/alert_dispatcher.py` — Push to WebSocket
- `frontend/src/hooks/useWebSocket.ts` — New hook
- `frontend/src/pages/Dashboard.tsx` — Live alert feed

**Backend — Add WebSocket endpoint in main.py**:

```python
from fastapi import WebSocket, WebSocketDisconnect
from typing import List

connected_clients: List[WebSocket] = []

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

async def broadcast_alert(alert_data: dict):
    for client in connected_clients:
        try:
            await client.send_json(alert_data)
        except:
            connected_clients.remove(client)
```

---

#### 3.3 Case Management UI

**⏱ Effort**: 5–6 hours  
**📁 New files**:
- `backend/app/models/case.py` — Case database model
- `backend/app/api/routes/cases.py` — CRUD API
- `frontend/src/pages/Cases.tsx` — Case list view
- `frontend/src/pages/CaseDetail.tsx` — Single case view

**API endpoints**:
- `POST /api/cases` — Create case
- `GET /api/cases` — List cases with filters
- `GET /api/cases/{id}` — Get case detail with linked analyses
- `PATCH /api/cases/{id}` — Update status/severity
- `POST /api/cases/{id}/analyses` — Link analysis to case
- `POST /api/cases/{id}/notes` — Add analyst notes

---

#### 3.4 Dashboard Trend Charts

**⏱ Effort**: 3–4 hours  
**📁 Files to modify**:
- `backend/app/api/routes/dashboard.py` — New trend data endpoints
- `frontend/src/pages/Dashboard.tsx` — Add chart components

**New API endpoints**:
- `GET /dashboard/trends/daily` — Threats by day
- `GET /dashboard/trends/countries` — Top attacking countries
- `GET /dashboard/trends/auth-results` — SPF/DKIM/DMARC pass/fail rates
- `GET /dashboard/trends/attack-types` — Attack type distribution

**Frontend charts** (using Recharts, already installed):
1. **Line chart**: Threats by day (last 30 days)
2. **Bar chart**: Top 10 attacking countries
3. **Pie chart**: SPF/DKIM/DMARC pass vs fail rates
4. **Area chart**: Attack type distribution over time

---

#### 3.5 MITRE ATT&CK Heatmap Visualization

**⏱ Effort**: 3 hours  
**📁 New file**: `frontend/src/components/analysis/MitreHeatmap.tsx`

**Backend**: Already done! `mitre_mapper.py` maps findings to techniques.

**Frontend**: Matrix visualization with:
- Rows = MITRE Tactics
- Columns = Techniques
- Cells colored by detection confidence
- Click a cell → show evidence

---

### Phase 4 — Advanced Features (6–10 hours each)

---

#### 4.1 DistilBERT ML Model Upgrade

**⏱ Effort**: 8–10 hours  
**📦 Install**: `pip install transformers torch onnxruntime`  
**📁 New files**:
- `ml/training/train_bert.py` — Fine-tuning script
- `ml/models/distilbert_email_classifier/` — Model artifacts
- `backend/app/detection/bert_classifier.py` — Inference service

**Approach**:
1. Fine-tune DistilBERT on existing `public_email_threats.jsonl`
2. Export to ONNX for fast CPU inference (no GPU needed)
3. Ensemble with existing TF-IDF + LogReg (40% TF-IDF + 60% BERT)

---

#### 4.2 Bulk Email Analysis (Batch Upload)

**⏱ Effort**: 5–6 hours  
**📁 New files**:
- `backend/app/api/routes/batch_analysis.py` — Batch upload endpoint
- `frontend/src/pages/BatchAnalysis.tsx` — Batch upload UI

**Support**: Multiple `.eml` files, `.zip` archives, `.mbox` format.

---

#### 4.3 Chain-of-Custody Evidence Integrity

**⏱ Effort**: 4–5 hours  
**📁 Files to modify**:
- `backend/app/models/analysis.py` — Add evidence hash fields
- `backend/app/services/audit.py` — Expand audit logging

**Evidence Bundle Export** (`GET /api/analysis/{id}/export/evidence-bundle`):
Returns a `.zip` containing original email, analysis JSON, PDF report, hash manifest, and audit log.

---

### Phase 5 — Polish & Nice-to-Have (1–2 hours each)

---

#### 5.1 IPQualityScore Integration

**⏱ Effort**: 1–2 hours  
**💰 Cost**: Free (5,000 lookups/month)  
**API**: `GET https://ipqualityscore.com/api/json/ip/{api_key}/{ip}`

Returns: fraud_score, VPN, TOR, proxy, bot, recent_abuse, ISP, city, country.

---

#### 5.2 HaveIBeenPwned Domain Search

**⏱ Effort**: 1 hour  
**💰 Cost**: Free (domain search is free, no key needed)  
**API**: `GET https://haveibeenpwned.com/api/v3/breaches?domain={domain}`

Check if the sender's domain has been involved in a data breach.

---

## 📋 Implementation Checklist

### Phase 1 — Quick Wins
- [x] 1.1 — Add `proxy,hosting,mobile,isp,org,as` fields to ip-api.com calls
- [x] 1.2 — Extract `registration_date` and `domain_age_days` from RDAP events
- [x] 1.3 — Create `shodan_internetdb.py` integration (no key)
- [x] 1.4 — Create `spamhaus_dnsbl.py` (DNSBL via dnspython)
- [x] 1.5 — Create `tor_exit_nodes.py` (download + cache TOR list)
- [x] 1.6 — Add `PhishTankProvider` class to threat_intelligence.py

### Phase 2 — High Priority
- [x] 2.1 — Create dependency-light PDF report service + API endpoint and frontend export controls
- [x] 2.2 — Create `RelayPathMap.tsx` using MapLibre + `relay_path_builder.py` backend
- [x] 2.3 — Add optional `dkimpy`/`pyspf` live authentication verifier with truthful fallback states

### Phase 3 — Medium Priority
- [x] 3.1 — Create `EvidenceGraph.tsx` visualization using the persisted evidence graph
- [x] 3.2 — Add WebSocket alert endpoint, broadcast manager, and `useWebSocket.ts` hook
- [x] 3.3 — Create Case model, CRUD API, `Cases.tsx` + `CaseDetail.tsx` pages
- [x] 3.4 — Add trend API endpoint and daily/country/authentication/attack-type dashboard charts
- [x] 3.5 — Create `MitreHeatmap.tsx` component

### Phase 4 — Advanced
- [ ] 4.1 — Install `transformers torch onnxruntime`, train DistilBERT, create `bert_classifier.py`
- [ ] 4.2 — Create `batch_analysis.py` API + `BatchAnalysis.tsx` page
- [ ] 4.3 — Create evidence bundle export with integrity hashes

### Phase 5 — Polish
- [ ] 5.1 — Add `IPQualityScoreProvider` to threat_intelligence.py
- [ ] 5.2 — Create `hibp.py` for domain breach lookup

---

## 📦 Install Commands

```bash
# Phase 1-2 (backend)
pip install weasyprint jinja2 dkimpy pyspf

# Phase 3 (frontend)
npm install vis-network vis-data

# Phase 4 (ML upgrade — only if doing BERT)
pip install transformers torch onnxruntime
```

## 🔑 Environment Variables to Add

```env
# Phase 1.6
PHISHTANK_API_KEY=your_key_here

# Phase 5.1
IPQUALITYSCORE_API_KEY=your_key_here
```

> Most new integrations require **NO new API keys**. Shodan InternetDB, Spamhaus DNSBL, TOR exit node list, RDAP, ip-api.com proxy flags, and HaveIBeenPwned are all **keyless and free**.

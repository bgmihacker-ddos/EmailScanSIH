# Analysis Timing Baseline

Date: 2026-09-09
Fixture: `tests/fixtures/emails/benign_transactional_provider.eml`
Initial analysis ID: `04aa74bd-be2c-4f7a-9a7d-f7fcc56b870c`
Verdict: `benign`
Risk score: `5/100`
HTTP status: `200`

## Measured Stages

| Stage | Status | Duration | Items |
|---|---:|---:|---:|
| fast_forensics | completed | 1,959 ms | 15 IOCs |
| static_analysis | completed | 5,916 ms | 10 items |
| dns_whois_enrichment | completed | 26,506 ms | 9 domains |
| threat_intelligence | completed | 2,652 ms | 15 IOCs |
| evidence_synthesis | completed | 1 ms | n/a |
| campaign_correlation | completed | 148 ms | 58 historical records |
| persistence | completed | 44 ms | n/a |
| total | completed | 37,464 ms | 7 timing records |

## Findings

- DNS/WHOIS enrichment is the dominant bottleneck at approximately 26.5 seconds.
- Static analysis takes approximately 5.9 seconds and should be decomposed further in the next profiling pass.
- Threat intelligence takes approximately 2.7 seconds for 15 IOCs.
- Campaign correlation is currently small for this run, but the pipeline still loads 58 historical records before correlation.
- WHOIS emitted HTTP 401 warnings during the run. This must remain an explicit provider-unavailable state and must not be interpreted as clean or malicious.
- The result remained benign with risk score 5, so the timing instrumentation did not alter the verdict.

## After Enrichment-Input Cleanup

Authentication parser labels such as `smtp.mailfrom` and `header.from` are no longer treated as real domains for enrichment.

| Stage | Duration | Items |
|---|---:|---:|
| fast_forensics | 1,976 ms | 13 IOCs |
| static_analysis | 4,988 ms | 8 items |
| dns_whois_enrichment | 12,016 ms | 7 domains |
| threat_intelligence | 2,808 ms | 13 IOCs |
| campaign_correlation | 96 ms | 62 historical records |
| persistence | 25 ms | n/a |
| total | 22,078 ms | 7 timing records |

Updated analysis ID: `252eb529-a0bc-46d6-997d-e53cbd75f733`

This reduced total time by approximately 41% and DNS/WHOIS work by approximately 55%. The sanitized message remained benign, with risk score 0 after removing non-evidence parser labels.

## Per-Domain DNS/WHOIS Breakdown

Latest analysis ID: `ae882a8a-81d2-4954-844d-bda72724c693`

- Total duration: `21,887 ms`
- DNS per-domain peak: `5,513 ms`
- WHOIS cold probe: `4,519 ms`
- WHOIS subsequent provider-health short-circuit: approximately `2,020 ms`
- DNS and WHOIS statuses remained explicit as `error`/`timeout`; no unavailable provider was interpreted as clean.
- Verdict remained `benign`, risk score `5/100`.

## Next Action

Phase 1 should continue by decomposing DNS and WHOIS timing separately per domain. Do not increase timeouts to address this result.

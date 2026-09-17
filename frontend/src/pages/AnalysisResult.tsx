import { useEffect, useState, type ReactNode } from 'react';
import { ArrowLeft, Ban, Check, ChevronDown, ChevronRight, CircleAlert, Copy, Download, ExternalLink, FileSearch, Fingerprint, Globe2, Cpu, Mail, MapPin, Radio, ShieldAlert, ShieldCheck, Timer, TriangleAlert, Zap } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { downloadReport, exportCertinReport, getAnalysisById, verifyBlockchainEvidence, type BlockchainVerification } from '../services/analysisApi';
import { RelayPathMap } from '../components/analysis/RelayPathMap';
import { EvidenceGraph } from '../components/analysis/EvidenceGraph';
import { MitreHeatmap } from '../components/analysis/MitreHeatmap';
import { RelatedInvestigations } from '../components/analysis/RelatedInvestigations';

type RecordValue = Record<string, any>;

export default function AnalysisResult() {
  const { id } = useParams();
  const [analysis, setAnalysis] = useState<RecordValue | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState({ headers: false, raw: false });
  const [certinExporting, setCertinExporting] = useState(false);
  const [certinError, setCertinError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getAnalysisById(id).then(setAnalysis).catch((reason) => setError(reason.message || 'Failed to load analysis.')).finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingState />;
  if (error || !analysis) return <div className="mx-auto max-w-5xl rounded border border-critical/40 bg-critical/10 p-5 text-sm text-critical">{error || 'Analysis not found.'}</div>;

  const email = analysis.email || {};
  const metadata = email.metadata || {};
  const auth = analysis.authentication || {};
  const headers = analysis.header_forensics || {};
  const flow = headers.mail_flow || {};
  const content = analysis.content_analysis || {};
  const findings = Array.isArray(analysis.forensic_findings) ? analysis.forensic_findings : [];
  const iocs = extractedIocs(analysis);
  const verdict = String(analysis.verdict || 'unknown').toLowerCase();
  const risk = Number(analysis.risk_score || 0);
  const breakdown = Array.isArray(analysis.risk_breakdown) ? analysis.risk_breakdown : [];
  const riskFindings = breakdown.filter((item: RecordValue) => item.points > 0 && (item.evidence_class === 'strong_risk_signal' || item.evidence_class === 'confirmed_malicious' || item.risk_relevance === 'risk_contributing'));
  const contextFindings = findings.filter((item: RecordValue) => item.evidence_class === 'contextual_anomaly' || item.evidence_class === 'informational' || item.risk_relevance === 'contextual');
  const subject = metadata.subject || email.subject || 'Untitled investigation';
  const sender = metadata.from || email.from || 'Sender unavailable';
  const recipient = firstRecipient(metadata.to || email.to);
  const evidenceHash = analysis.evidence_hash || analysis.hash_manifest?.sha256 || analysis.hash_manifest?.raw_email_sha256;
  const ledger = analysis.blockchain_anchor || analysis.ledger_anchor || {};
  const certDraft = buildCertDraft({ analysis, subject, sender, risk, verdict });

  const handleCertinExport = async () => {
    if (!id) return;
    setCertinExporting(true);
    setCertinError(null);
    try {
      await exportCertinReport(id);
    } catch (reason: any) {
      setCertinError(reason.message || 'CERT-In report export failed.');
    } finally {
      setCertinExporting(false);
    }
  };

  return <div className="mx-auto max-w-[1500px] space-y-6 pb-14 text-ink-dim">
    <header className="border-b border-hairline-strong pb-6"><div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"><div><Link to="/history" className="mb-4 inline-flex items-center gap-2 text-xs uppercase tracking-[0.16em] text-ink-mute hover:text-accent"><ArrowLeft size={14} /> Case history</Link><p className="report-kicker">Case file · {subject}.eml</p><h1 className="mt-2 text-2xl font-semibold text-ink">{subject}</h1><p className="mt-2 text-sm text-ink-dim"><span className="text-ink-dim">{sender}</span><span className="mx-2 text-ink-faint">→</span>{recipient}</p><p className="mt-1 font-mono text-xs text-ink-mute">{formatDate(metadata.date || email.date || analysis.created_at)} · analysis {analysis.analysis_id}</p></div><div className="flex flex-wrap gap-2"><button onClick={() => id && downloadReport(id, 'json')} className="btn-secondary"><Download size={14} /> JSON</button><button onClick={() => id && downloadReport(id, 'html')} className="btn-secondary"><Download size={14} /> HTML</button><button onClick={() => id && downloadReport(id, 'pdf')} className="btn-secondary"><Download size={14} /> PDF</button><button onClick={handleCertinExport} disabled={certinExporting} className="btn-secondary disabled:cursor-wait disabled:opacity-60"><Download size={14} /> {certinExporting ? 'CERT-In...' : 'CERT-In JSON'}</button></div></div>{certinError && <p className="mt-3 text-xs text-critical">{certinError}</p>}</header>
    <nav className="flex flex-wrap gap-2 border-b border-hairline pb-4 font-mono text-[10px] uppercase tracking-widest text-ink-mute">{['Verdict', 'Why flagged', 'Mail flow', 'Authentication', 'Headers', 'Content', 'Email preview', 'Infrastructure', 'Raw email'].map((item, index) => <a key={item} href={`#${item === 'Why flagged' ? 'findings' : slug(item)}`} className="rounded border border-hairline-strong px-2.5 py-1.5 hover:border-accent/50 hover:text-accent"><span className="mr-1.5 text-accent/70">{String(index + 1).padStart(2, '0')}</span>{item}</a>)}</nav>
    <section id="verdict" className={`grid gap-6 rounded-lg border p-6 lg:grid-cols-[1fr_auto] ${verdictBorder(verdict)}`}><div><p className="report-kicker">Investigation complete · {subject}.eml</p><div className="mt-3 flex flex-wrap items-center gap-3"><h2 className={`text-4xl font-bold uppercase ${verdictTone(verdict)}`}>{displayVerdict(verdict)}</h2><span className="rounded border border-hairline-strong px-2 py-1 font-mono text-[10px] uppercase text-ink-dim">{analysis.severity || 'unknown'} severity</span></div><p className="mt-4 max-w-3xl text-sm leading-7 text-ink-dim">{analysis.summary || 'No executive summary was returned.'}</p><div className="mt-5 flex flex-wrap gap-3 text-xs text-ink-dim"><Metric icon={<Timer size={14} />} label="Status" value={analysis.status || 'completed'} /><Metric icon={<FileSearch size={14} />} label="Confidence" value={analysis.confidence !== undefined ? `${analysis.confidence}%` : 'unavailable'} /><Metric icon={<Globe2 size={14} />} label="Observed IOCs" value={String(iocs.length)} /></div></div><div className="min-w-[190px] border-l border-hairline-strong pl-6 lg:self-center"><p className="report-kicker">Composite risk</p><p className={`mt-1 font-mono text-5xl font-bold ${verdictTone(verdict)}`}>{risk}<span className="text-lg text-ink-faint">/100</span></p><div className="mt-3 h-2 overflow-hidden rounded-full bg-hairline"><div className={`h-full ${risk >= 70 ? 'bg-critical' : risk >= 40 ? 'bg-medium' : 'bg-safe'}`} style={{ width: `${Math.min(100, Math.max(0, risk))}%` }} /></div></div></section>
    <TacticalAlertBanner analysis={analysis} verdict={verdict} risk={risk} subject={subject} certDraft={certDraft} evidenceHash={evidenceHash} ledger={ledger} id={id} />
    {verdict !== 'benign' && risk >= 30 && (
      <TacticalAlertBanner analysis={analysis} verdict={verdict} risk={risk} subject={subject} certDraft={certDraft} evidenceHash={evidenceHash} ledger={ledger} id={id} />
    )}
    <DetectionLayerConsensusPanel analysis={analysis} />
    <DetectionEvidencePanel analysis={analysis} />
    <TriangulatedVerdict analysis={analysis} risk={risk} auth={auth} />
    <RelatedInvestigations related={analysis.related_investigations || []} />
    <section id="findings" className="grid scroll-mt-6 gap-5 border-b border-hairline-strong pb-6 lg:grid-cols-[1.15fr_0.85fr]"><div><p className="report-kicker">Plain-language explanation</p><h2 className="mt-1 text-xl font-semibold text-ink">Why did we flag this?</h2><div className="mt-4 space-y-2">{riskFindings.slice(0, 4).map((item: RecordValue, index: number) => <div key={`${item.finding_id || item.title || 'signal'}-${index}`} className="flex items-start gap-3 border-l-2 border-critical/60 bg-critical/10 px-3 py-2.5 text-sm text-ink-dim"><span className="font-mono text-[10px] text-critical">{String(index + 1).padStart(2, '0')}</span><span>{item.reason || item.title || 'Risk signal observed'} <strong className="font-mono text-critical">+{item.points || 0}</strong></span></div>)}{!riskFindings.length && <Empty text="No priority risk evidence returned." />}</div></div><div><p className="report-kicker">Recommended response</p><h2 className="mt-1 text-xl font-semibold text-ink">Containment guidance</h2><ul className="mt-4 space-y-2 text-sm leading-6 text-ink-dim">{(Array.isArray(analysis.recommendations) ? analysis.recommendations : []).slice(0, 4).map((item: string, index: number) => <li key={`${item}-${index}`} className="border-l-2 border-accent/50 pl-3">{item}</li>)}{!analysis.recommendations?.length && <li className="text-ink-mute">No additional response guidance was returned.</li>}</ul></div></section>
    <section className="border-b border-hairline-strong pb-6"><p className="report-kicker">Attack path</p><h2 className="mt-1 text-xl font-semibold text-ink">Observed delivery sequence</h2><div className="mt-4 flex flex-wrap items-center gap-2">{(Array.isArray(analysis.attack_chain_steps) ? analysis.attack_chain_steps : Array.isArray(analysis.attack_chain) ? analysis.attack_chain : []).slice(0, 6).map((step: RecordValue, index: number) => <div key={`${step.stage || step.name || 'step'}-${index}`} className="flex items-center gap-2"><span className="rounded border border-hairline-strong bg-surface px-3 py-2 font-mono text-xs text-ink-dim">{step.stage || step.name || step.title || 'Observed signal'}</span>{index < 5 && <span className="text-accent/70">→</span>}</div>)}{!analysis.attack_chain_steps?.length && !analysis.attack_chain?.length && <Empty text="No attack path was reconstructed." />}</div></section>
    <ReportSection id="findings" title="Key findings" subtitle="Signal review"><div className="grid gap-5 lg:grid-cols-2"><EvidenceGroup title="Risk-contributing evidence" icon={<TriangleAlert size={16} />} tone="red" items={riskFindings.map((item: RecordValue) => `${item.reason || item.title || 'Observed risk signal'} · +${item.points} points`)} empty="No strong risk-contributing evidence was returned." /><EvidenceGroup title="Contextual and informational evidence" icon={<CircleAlert size={16} />} tone="amber" items={contextFindings.map((item: RecordValue) => item.title || item.description)} empty="No contextual or informational findings were returned." /></div></ReportSection>
    <ReportSection id="mail-flow" title="Mail transfer flow" subtitle="SMTP path reconstruction"><div className="mb-5 flex flex-wrap gap-3 font-mono text-xs text-ink-dim"><span>{flow.hop_count || 0} parsed hops</span><span className="text-ink-faint/60">·</span><span>{flow.timeline?.length || 0} system stages</span><span className="text-ink-faint/60">·</span><span>Origin {flow.origin_ip || 'unavailable'}</span></div><ThreatHopTimeline hops={flow.hops || []} origin={flow.origin_ip} /><div className="mb-5"><RelayPathMap hops={analysis.relay_path || []} /></div><div className="grid gap-3 md:grid-cols-3">{(flow.hops || []).map((hop: RecordValue, index: number) => <div key={index} className="rounded border border-hairline-strong bg-surface p-4"><p className="report-kicker">Hop {index + 1}</p><p className="mt-2 break-all font-mono text-sm text-ink">{hop.from_server || hop.from_host || 'Observed relay'}</p><p className="my-2 text-xs text-accent">↓ mail transport ↓</p><p className="break-all font-mono text-sm text-ink-dim">{hop.by_server || hop.by_host || 'Destination relay'}</p><p className="mt-3 text-[11px] text-ink-mute">{hop.source_ip || 'IP unavailable'} · {hop.timestamp_utc || hop.timestamp || 'timestamp unavailable'}</p></div>)}</div>{!flow.hops?.length && <Empty text="No Received-chain hops were parsed." />}</ReportSection>
    <div className="grid gap-5 lg:grid-cols-2"><ReportSection id="authentication" title="Trust signals" subtitle="Authentication"><div className="grid grid-cols-2 gap-3">{['spf', 'dkim', 'dmarc', 'arc'].map((name) => <div key={name} className="rounded border border-hairline-strong bg-surface p-4"><p className="report-kicker">{name}</p><p className={`mt-2 font-mono text-xl font-bold uppercase ${authTone(auth[name]?.status)}`}>{auth[name]?.status || 'not available'}</p><p className="mt-2 text-[11px] text-ink-mute">{auth[name]?.verified ? 'Independently verified' : 'Parsed from message headers'}</p></div>)}</div><p className="mt-4 text-xs text-ink-mute">Header authentication is evidence, not a verdict by itself.</p></ReportSection><ReportSection id="content" title="Content signals" subtitle="Message content"><div className="grid grid-cols-2 gap-3 text-xs">{[['HTML detected', email.html_body ? 'YES' : 'NO'], ['Active script', content.html_forensics?.javascript_references ? 'DETECTED' : 'NOT DETECTED'], ['Tracking pixels', String(content.html_forensics?.tracking_pixels || 0)], ['Attachments', String((email.attachments || []).length)]].map(([label, value]) => <div key={label} className="rounded border border-hairline-strong bg-surface p-3"><p className="report-kicker">{label}</p><p className="mt-2 font-mono text-sm text-ink-dim">{value}</p></div>)}</div><p className="mt-4 whitespace-pre-wrap text-sm leading-7 text-ink-dim">{email.plain_text || 'No plain-text body was returned.'}</p></ReportSection></div>
    <ReportSection id="headers" title="Identity and transport evidence" subtitle="Header forensics"><div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">{[['Message-ID', metadata.message_id || email.message_id], ['Return-Path', metadata.return_path || email.return_path], ['MIME type', metadata.content_type || email.content_type], ['Sender domain', headers.domain_relationships?.from_domain]].map(([label, value]) => <DataField key={label} label={label} value={value || 'unavailable'} />)}</div><button className="mt-5 inline-flex items-center gap-2 text-xs text-accent hover:text-accent" onClick={() => setOpen((state) => ({ ...state, headers: !state.headers }))}>{open.headers ? <ChevronDown size={14} /> : <ChevronRight size={14} />} View parsed headers</button>{open.headers && <pre className="mt-3 max-h-96 overflow-auto rounded border border-hairline-strong bg-sunken p-4 font-mono text-[11px] leading-6 text-ink-dim">{JSON.stringify(email.headers || {}, null, 2)}</pre>}</ReportSection>
    <div className="grid gap-5 lg:grid-cols-2"><ReportSection id="evidence-graph" title="Evidence graph" subtitle="Entity relationships"><EvidenceGraph graph={analysis.evidence_graph || {}} /></ReportSection><ReportSection id="mitre" title="MITRE ATT&CK coverage" subtitle="Technique mapping"><MitreHeatmap techniques={analysis.mitre_techniques || []} /></ReportSection></div>
    <div className="grid gap-5 lg:grid-cols-2"><ReportSection id="email-preview" title="Inbox view" subtitle="Message view"><div className="rounded border border-hairline-strong bg-surface p-5"><p className="report-kicker">Rendered message</p><div className="mt-4 space-y-2 border-b border-hairline-strong pb-4 text-sm"><DataField label="From" value={sender} /><DataField label="To" value={recipient} /><DataField label="Subject" value={subject} /></div><div className="mt-4 whitespace-pre-wrap text-sm leading-7 text-ink-dim">{email.plain_text || 'No preview content available.'}</div></div></ReportSection><ReportSection id="infrastructure" title="Observed infrastructure" subtitle="Evidence index"><ProviderTable results={analysis.threat_intelligence} /><IpEnrichmentTable results={analysis.ip_enrichment} /><div className="mt-5 grid grid-cols-2 gap-3"><IocMetric icon={<Globe2 size={15} />} label="Domains" value={uniqueIocs(iocs, 'domain').length} /><IocMetric icon={<ShieldCheck size={15} />} label="IPs" value={uniqueIocs(iocs, 'ip', 'ipv6').length} /><IocMetric icon={<Mail size={15} />} label="Emails" value={uniqueIocs(iocs, 'email').length} /><IocMetric icon={<FileSearch size={15} />} label="URLs" value={uniqueIocs(iocs, 'url').length} /></div></ReportSection></div>
    <ReportSection id="raw-email" title="Raw email" subtitle="Source evidence"><button className="inline-flex items-center gap-2 text-xs text-accent hover:text-accent" onClick={() => setOpen((state) => ({ ...state, raw: !state.raw }))}>{open.raw ? <ChevronDown size={14} /> : <ChevronRight size={14} />} {open.raw ? 'Hide raw source' : 'Show raw source'}</button>{open.raw && <pre className="mt-3 max-h-[500px] overflow-auto rounded border border-hairline-strong bg-sunken p-4 font-mono text-[11px] leading-6 text-ink-mute">{email.raw_email || analysis.raw_email || 'Raw email was not included in this response.'}</pre>}</ReportSection>
    <IntegrityBox evidenceHash={evidenceHash} ledger={ledger} analysisId={id} />
  </div>;
}

function DetectionEvidencePanel({ analysis }: { analysis: RecordValue }) {
  const anomalyItems = Array.isArray(analysis.anomaly_analysis?.anomalies) ? analysis.anomaly_analysis.anomalies : [];
  const impersonationItems = Array.isArray(analysis.impersonation_analysis?.lookalike_findings) ? analysis.impersonation_analysis.lookalike_findings : [];
  const detectorItems = [...anomalyItems, ...impersonationItems];
  return <section className="rounded-lg border border-accent/25 bg-surface p-5"><div className="flex flex-wrap items-end justify-between gap-3"><div><p className="report-kicker">Judge-visible evidence</p><h2 className="mt-1 text-xl font-semibold text-ink">Why this message is suspicious</h2></div><span className="font-mono text-[10px] uppercase tracking-widest text-ink-mute">{detectorItems.length} detector signals</span></div>{detectorItems.length ? <div className="mt-4 grid gap-3 md:grid-cols-2">{detectorItems.slice(0, 6).map((item: RecordValue, index: number) => <div key={`${item.anomaly_type || item.type || 'signal'}-${index}`} className="rounded border border-hairline-strong bg-raised p-4"><div className="flex items-start justify-between gap-3"><div className="flex items-start gap-2"><CircleAlert size={15} className="mt-0.5 shrink-0 text-accent" /><p className="text-sm font-medium text-ink-dim">{item.description || 'Detection signal observed'}</p></div><span className={`shrink-0 font-mono text-[10px] uppercase ${item.severity === 'critical' || item.severity === 'high' ? 'text-critical' : 'text-medium'}`}>{item.severity || 'signal'}</span></div><p className="mt-2 font-mono text-[10px] text-ink-mute">Confidence {item.confidence || 0}% · {item.evidence || item.observed_domain || 'Evidence recorded'}</p></div>)}</div> : <p className="mt-4 rounded border border-dashed border-hairline-strong p-4 text-sm text-ink-mute">No anomaly or impersonation signal was returned for this message.</p>}</section>;
}

function TacticalAlertBanner({ analysis, verdict, risk, subject, certDraft, evidenceHash, ledger, id }: { analysis: RecordValue; verdict: string; risk: number; subject: string; certDraft: string; evidenceHash?: string; ledger: RecordValue; id?: string }) {
  const [copied, setCopied] = useState(false);
  const txHash = ledger.tx_hash || ledger.transaction_hash || ledger.tx;
  const classification = `${verdict === 'malicious' ? 'CRITICAL PHISHING' : verdict.toUpperCase()} (${risk}/100)`;
  const copyDraft = async () => {
    await navigator.clipboard?.writeText(certDraft);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };
  return <section className={`overflow-hidden rounded-lg border ${risk >= 70 ? 'border-critical/60 bg-critical/15' : 'border-medium/50 bg-medium/10'} shadow-[0_12px_50px_rgba(0,0,0,0.2)]`}>
    <div className="flex flex-col gap-4 border-b border-white/10 p-5 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex items-start gap-3"><div className={`rounded border p-2 ${risk >= 70 ? 'border-critical/50 text-critical' : 'border-medium/50 text-medium'}`}><ShieldAlert size={22} /></div><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-dim">Tactical incident alert</p><h2 className="mt-1 text-xl font-bold uppercase text-ink">{classification} <span className="text-ink-dim">· {analysis.attack_type || 'CREDENTIAL HARVESTING'}</span></h2></div></div>
      <div className="flex items-start gap-3"><div className={`rounded border p-2 ${risk >= 70 ? 'border-critical/50 text-critical' : 'border-medium/50 text-medium'}`}><ShieldAlert size={22} /></div><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-dim">Tactical incident alert</p><h2 className="mt-1 text-xl font-bold uppercase text-ink">{classification} <span className="text-ink-dim">· {analysis.attack_type || (verdict === 'malicious' ? 'CONFIRMED PHISHING THREAT' : 'SUSPICIOUS THREAT DETECTED')}</span></h2></div></div>
      <div className="flex shrink-0 items-center gap-2 font-mono text-[10px] text-ink-dim"><Radio size={14} className="animate-pulse text-critical" /> Incident dossier {id ? id.slice(0, 8) : 'local'}</div>
    </div>
    <div className="flex flex-wrap gap-2 p-4">
      <button type="button" onClick={() => id && downloadReport(id, 'pdf')} className="btn-secondary"><Download size={14} /> Export Court-Ready PDF</button>
      <a href={txHash ? `https://sepolia.etherscan.io/tx/${txHash}` : undefined} target="_blank" rel="noreferrer" className={`btn-secondary ${txHash ? '' : 'pointer-events-none opacity-40'}`}><ExternalLink size={14} /> View on Etherscan</a>
      <button type="button" onClick={copyDraft} className="btn-secondary"><Copy size={14} /> {copied ? 'CERT-In Draft Copied' : 'Copy CERT-In Incident Draft'}</button>
      <button type="button" onClick={() => navigator.clipboard?.writeText(evidenceHash || subject)} className="btn-secondary"><Ban size={14} /> Contain & Block Sender IP</button>
    </div>
  </section>;
}

function DetectionLayerConsensusPanel({ analysis }: { analysis: RecordValue }) {
  const ml = analysis.ml_analysis || {};
  const transformer = ml.transformer || ml.transformer_backup || {};
  const isTransformerActive = transformer.status === 'available' || transformer.inference_active;

  const auth = analysis.authentication || {};
  const trust = trustRisk(auth);

  const becScore = analysis.bec_analysis?.attack_chain?.length ? 85 : 0;

  const urlScore = (analysis.url_analysis?.results || []).some((u: RecordValue) => (u.findings || []).some((f: RecordValue) => f.severity === 'high')) ? 90 : 0;
  const domainScore = analysis.domain_analysis?.results?.some((d: RecordValue) => (d.findings || []).some((f: RecordValue) => f.severity === 'high')) ? 90 : 0;

  const attachmentScore = analysis.attachment_analysis?.attachments?.some((a: RecordValue) => a.verdict === 'malicious' || (a.findings || []).some((f: RecordValue) => f.severity === 'high')) ? 95 : 0;

  const intelScore = analysis.threat_intelligence?.some((i: RecordValue) => i.status === 'malicious') ? 100 : 0;

  const getStatus = (score: number, highThreshold: number) => score >= highThreshold ? { statusText: 'MALICIOUS', color: 'text-critical' } : score > 30 ? { statusText: 'SUSPICIOUS', color: 'text-medium' } : { statusText: 'CLEAN', color: 'text-safe' };

  const mlDecision = String(ml.decision_label || ml.label || '').toLowerCase();
  const isThreat = mlDecision === 'phishing' || mlDecision === 'malicious' || mlDecision === 'suspicious';
  const threatProb = typeof ml.threat_probability === 'number'
    ? ml.threat_probability
    : typeof ml.raw_threat_probability === 'number'
      ? ml.raw_threat_probability
      : (ml.probabilities?.phishing ?? (isThreat ? (ml.confidence || 0.8) : 0));
  
  const mlScore = isThreat 
    ? Math.round(Math.max(threatProb, ml.confidence || 0) * 100)
    : Math.round(threatProb * 100);

  const mlStatus = !isThreat
    ? { statusText: 'CLEAN', color: 'text-safe' }
    : mlScore >= 70
      ? { statusText: 'MALICIOUS', color: 'text-critical' }
      : { statusText: 'SUSPICIOUS', color: 'text-medium' };

  const panels = [
    { name: 'ML Classifier', label: isTransformerActive ? 'DistilBERT — ACTIVE' : 'DistilBERT — FALLBACK (TF-IDF/Heuristics)', score: ml.confidence ? ml.confidence * 100 : 0, ...getStatus(ml.confidence ? ml.confidence * 100 : 0, 70), icon: <Cpu size={14} /> },
    { name: 'ML Classifier', label: isTransformerActive ? 'DistilBERT — ACTIVE' : 'DistilBERT — FALLBACK (TF-IDF/Heuristics)', score: mlScore, ...mlStatus, icon: <Cpu size={14} /> },
    { name: 'BEC Engine', label: 'Behavioral Analysis', score: becScore, ...getStatus(becScore, 70), icon: <Zap size={14} /> },
    { name: 'Header/Auth', label: 'SPF/DKIM/DMARC', score: trust, ...getStatus(trust, 70), icon: <Fingerprint size={14} /> },
    { name: 'URL/Domain', label: 'Lexical & Phishing', score: Math.max(urlScore, domainScore), ...getStatus(Math.max(urlScore, domainScore), 70), icon: <Globe2 size={14} /> },
    { name: 'Attachments', label: 'Static Analysis', score: attachmentScore, ...getStatus(attachmentScore, 70), icon: <FileSearch size={14} /> },
    { name: 'Threat Intel', label: 'IP & Graph Feeds', score: intelScore, ...getStatus(intelScore, 70), icon: <ShieldAlert size={14} /> },
  ];

  const maliciousCount = panels.filter(p => p.statusText === 'MALICIOUS' || p.score >= 70).length;
  const suspiciousCount = panels.filter(p => p.statusText === 'SUSPICIOUS' || (p.score >= 30 && p.score < 70)).length;
  const cleanCount = panels.filter(p => p.statusText === 'CLEAN' || p.score < 30).length;
  
  const mlPanel = panels.find(p => p.name === 'ML Classifier');
  const mlIsOutlier = mlPanel && (mlPanel.statusText !== 'CLEAN' || mlPanel.score >= 30) && (maliciousCount + suspiciousCount === 1);
  const isDissent = mlIsOutlier || (maliciousCount + suspiciousCount > 0 && cleanCount > 0 && cleanCount >= 4);

  return (
    <section className="rounded-lg border border-hairline-strong bg-surface p-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="report-kicker">Multi-Pillar Consensus</p>
          <h2 className="mt-1 flex items-center gap-2 text-xl font-semibold text-ink">
            Detection Layer Agreement
            {isDissent && <span className="text-sm font-normal text-medium flex items-center gap-1 ml-2"><TriangleAlert size={14} /> MODEL DISSENT</span>}
          </h2>
        </div>
        <div className="flex flex-wrap gap-2 text-[10px] font-mono uppercase tracking-widest">
          {cleanCount > 0 && <span className="rounded border border-safe/50 bg-safe/10 px-2 py-1 text-safe">{cleanCount}/6 layers → CLEAN</span>}
          {suspiciousCount > 0 && <span className="rounded border border-medium/50 bg-medium/10 px-2 py-1 text-medium">{suspiciousCount}/6 layers → SUSPICIOUS</span>}
          {maliciousCount > 0 && <span className="rounded border border-critical/50 bg-critical/10 px-2 py-1 text-critical">{maliciousCount}/6 layers → MALICIOUS</span>}
        </div>
      </div>
      {isDissent && <p className="mt-3 text-xs text-medium">⚠️ Fusion analysis notes a strong divergence among forensic engines. ML layer identifies latent risk patterns that static heuristics did not surface.</p>}
      <div className="mt-5 grid grid-cols-2 lg:grid-cols-3 gap-3">
        {panels.map((p, i) => (
          <div key={i} className="rounded border border-hairline bg-raised p-3 flex flex-col justify-between">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2 text-ink-dim text-sm">
                {p.icon}
                <span className="font-semibold text-ink-dim">{p.name}</span>
              </div>
              <span className={`font-mono text-[10px] uppercase font-bold ${p.color}`}>{p.score >= 70 ? 'MALICIOUS' : p.score > 30 ? 'SUSPICIOUS' : 'CLEAN'}</span>
            </div>
            <div className="mt-2 text-[10px] text-ink-mute uppercase tracking-wider">{p.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function TriangulatedVerdict({ analysis, risk, auth }: { analysis: RecordValue; risk: number; auth: RecordValue }) {
  const trust = trustRisk(auth);
  const infrastructure = clampScore(Number(analysis.infrastructure_risk ?? analysis.ip_reputation?.risk_score ?? risk));
  const linguistic = clampScore(Number(analysis.linguistic_risk ?? analysis.content_analysis?.linguistic_risk ?? risk));
  const pillars = [
    { label: 'Cryptographic Trust', score: trust, detail: authDetail(auth), icon: <Fingerprint size={15} /> },
    { label: 'Infrastructure Risk', score: infrastructure, detail: analysis.ip_enrichment?.[0]?.geolocation?.country || 'Origin intelligence unavailable', icon: <Globe2 size={15} /> },
    { label: 'Linguistic Intent', score: linguistic, detail: `${analysis.content_analysis?.urgency_cues || 'Signal'} · ${analysis.content_analysis?.coercion_markers || 'contextual'} markers`, icon: <Zap size={15} /> },
  ];
  return <section className="rounded-lg border border-hairline-strong bg-surface p-5"><div className="flex flex-wrap items-end justify-between gap-3"><div><p className="report-kicker">Decision support</p><h2 className="mt-1 text-xl font-semibold text-ink">Triangulated verdict</h2></div><span className="font-mono text-[10px] uppercase tracking-widest text-ink-mute">Three independent signal pillars</span></div><div className="mt-5 grid gap-3 lg:grid-cols-3">{pillars.map((pillar) => <div key={pillar.label} className="rounded border border-hairline-strong bg-raised p-4"><div className="flex items-center justify-between text-xs text-ink-dim"><span className="flex items-center gap-2 text-accent">{pillar.icon}{pillar.label}</span><strong className={pillar.score >= 70 ? 'text-critical' : pillar.score >= 40 ? 'text-medium' : 'text-safe'}>{pillar.score}%</strong></div><div className="mx-auto mt-4 h-24 w-24 rounded-full p-2" style={{ background: `conic-gradient(${pillar.score >= 70 ? '#F4586B' : pillar.score >= 40 ? '#E8B44A' : '#3ECF8E'} ${pillar.score * 3.6}deg, rgba(255,255,255,0.06) 0deg)` }}><div className="flex h-full w-full items-center justify-center rounded-full bg-raised font-mono text-[10px] text-ink-dim">RISK</div></div><p className="mt-3 text-center text-[11px] text-ink-mute">{pillar.detail}</p></div>)}</div></section>;
}

function ThreatHopTimeline({ hops, origin }: { hops: RecordValue[]; origin?: string }) {
  const [selected, setSelected] = useState(0);
  const active = hops[selected];
  if (!hops.length) return null;
  return <div className="mb-5 rounded border border-accent/20 bg-sunken p-4"><div className="flex items-center gap-2 text-[10px] uppercase tracking-widest text-accent"><MapPin size={14} /> Interactive threat hop timeline</div><div className="mt-4 flex gap-2 overflow-x-auto pb-2">{hops.map((hop, index) => <button type="button" key={`${hop.source_ip || hop.from_server || index}`} onClick={() => setSelected(index)} className={`flex min-w-[150px] items-center gap-2 rounded border px-3 py-2 text-left ${selected === index ? 'border-critical/60 bg-critical/10' : 'border-hairline-strong bg-surface'}`}><span className={`h-2 w-2 rounded-full ${selected === index ? 'bg-critical animate-pulse-slow' : 'bg-accent'}`} /><span><span className="block text-[10px] text-ink-mute">Hop {index + 1}</span><span className="block truncate font-mono text-xs text-ink-dim">{hop.by_server || hop.by_host || hop.from_server || 'Relay'}</span></span>{index < hops.length - 1 && <span className="text-accent/70">→</span>}</button>)}</div><div className="mt-2 grid gap-2 text-xs text-ink-dim sm:grid-cols-4"><span>Origin: <strong className="font-mono text-ink-dim">{origin || active?.source_ip || 'unavailable'}</strong></span><span>WHOIS: <strong className="text-ink-dim">{active?.whois?.organization || active?.whois?.registrar || 'unavailable'}</strong></span><span>ISP: <strong className="text-ink-dim">{active?.isp || active?.geolocation?.isp || 'unavailable'}</strong></span><span>Geo: <strong className="text-ink-dim">{active?.geolocation ? [active.geolocation.city, active.geolocation.country].filter(Boolean).join(', ') : 'unavailable'}</strong></span></div></div>;
}

function IntegrityBox({ evidenceHash, ledger, analysisId }: { evidenceHash?: string; ledger: RecordValue; analysisId?: string }) {
  const [verification, setVerification] = useState<BlockchainVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const txHash = ledger.tx_hash || ledger.transaction_hash || ledger.tx;
  const verify = async () => {
    if (!analysisId) return;
    setVerifying(true);
    setError(null);
    try {
      setVerification(await verifyBlockchainEvidence(analysisId));
    } catch (reason: any) {
      setError(reason.message || 'Blockchain verification failed.');
    } finally {
      setVerifying(false);
    }
  };
  const status = verification?.status;
  const statusLabel = status === 'match' ? 'MATCH' : status === 'mismatch' ? 'HASH MISMATCH' : status === 'unavailable' ? 'CHAIN UNAVAILABLE' : status === 'not_anchored' ? 'NOT ANCHORED' : evidenceHash ? 'READY TO VERIFY' : 'AWAITING HASH';
  const statusClass = status === 'match' ? 'border-safe/40 text-safe' : status === 'mismatch' ? 'border-critical/40 text-critical' : status ? 'border-medium/40 text-medium' : 'border-hairline-strong text-ink-mute';
  const etherscanUrl = verification?.etherscan_url || (txHash ? `https://sepolia.etherscan.io/tx/${txHash}` : undefined);
  return <section className="rounded-lg border border-safe/30 bg-safe/5 p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div className="flex items-center gap-2"><ShieldCheck size={20} className="text-safe" /><div><p className="report-kicker">Court-admissible evidence integrity</p><h2 className="mt-1 text-xl font-semibold text-ink">Cryptographic chain of custody</h2></div></div><span className={`inline-flex items-center gap-2 rounded border px-2 py-1 font-mono text-[10px] uppercase ${statusClass}`}>{status === 'match' ? <Check size={13} /> : <Fingerprint size={13} />}{statusLabel}</span></div><div className="mt-5 grid gap-3 md:grid-cols-3"><div className="rounded border border-hairline-strong bg-sunken p-3"><p className="report-kicker">Raw email SHA-256 digest</p><p className="mt-2 break-all font-mono text-xs text-ink-dim">{verification?.local_hash || evidenceHash || 'Not returned by analysis pipeline'}</p></div><div className="rounded border border-hairline-strong bg-sunken p-3"><p className="report-kicker">Blockchain anchor</p><p className="mt-2 font-mono text-sm text-ink-dim">{verification?.network || ledger.network || ledger.chain || 'Sepolia Testnet (Ethereum)'}</p>{verification?.on_chain_hash && <p className="mt-2 break-all font-mono text-[10px] text-ink-mute">On-chain: {verification.on_chain_hash}</p>}</div><div className="rounded border border-hairline-strong bg-sunken p-3"><p className="report-kicker">Smart contract transaction</p>{etherscanUrl ? <a href={etherscanUrl} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-2 break-all font-mono text-xs text-accent hover:text-accent">{verification?.tx_hash || txHash}<ExternalLink size={13} /></a> : <p className="mt-2 font-mono text-xs text-ink-mute">No ledger transaction recorded</p>}</div></div><div className="mt-4 flex flex-wrap items-center gap-3"><button type="button" onClick={verify} disabled={verifying || !analysisId} className="btn-secondary disabled:cursor-wait disabled:opacity-60">{verifying ? 'VERIFYING...' : 'Verify →'}</button>{error && <span className="text-xs text-critical">{error}</span>}{verification?.block_number && <span className="font-mono text-[10px] text-ink-mute">Block {verification.block_number}</span>}</div></section>;
}

function ReportSection({ id, title, subtitle, children }: { id: string; title: string; subtitle: string; children: ReactNode }) {
  const secondary = ['headers', 'infrastructure', 'raw-email'].includes(id);
  if (secondary) {
    return <details id={id} className="scroll-mt-5 border-t border-hairline-strong pt-5 group"><summary className="cursor-pointer list-none"><p className="report-kicker">{subtitle}</p><div className="mt-1 flex items-center justify-between gap-4"><h2 className="text-xl font-semibold text-ink">{title}</h2><span className="font-mono text-[10px] uppercase tracking-widest text-accent group-open:text-ink-mute">{id === 'raw-email' ? 'Open source' : 'Expand evidence'}</span></div></summary><div className="mt-4">{children}</div></details>;
  }
  return <section id={id} className="scroll-mt-5 border-t border-hairline-strong pt-5"><p className="report-kicker">{subtitle}</p><h2 className="mt-1 text-xl font-semibold text-ink">{title}</h2><div className="mt-4">{children}</div></section>;
}
/* Removed from the result view; scan progress is shown live during ingestion.
function EvidenceTimeline({ stages }: { stages: RecordValue[] }) {
  const durations = stages.map((stage) => Number(stage.duration_ms || stage.duration || 0));
  const maxDuration = Math.max(...durations, 1);
  const totalDuration = durations.reduce((sum, duration) => sum + duration, 0);
  return <section id="evidence-timeline" className="scroll-mt-5 border-t border-hairline-strong pt-5"><div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between"><div><p className="report-kicker">Pipeline trace</p><h2 className="mt-1 text-xl font-semibold text-ink">Analysis Evidence Timeline</h2><p className="mt-2 text-xs text-ink-mute">Measured processing stages from ingestion to persisted verdict. This is execution evidence, not generated narrative.</p></div><div className="font-mono text-xs text-ink-mute">{stages.length ? `${formatDuration(totalDuration)} total trace` : 'Timing data unavailable'}</div></div>{stages.length ? <div className="mt-5 overflow-hidden rounded border border-hairline-strong bg-surface"><div className="grid grid-cols-[2rem_1fr_auto] gap-3 border-b border-hairline-strong bg-sunken px-4 py-3 report-kicker"><span>#</span><span>Stage</span><span>Duration</span></div><div className="divide-y divide-hairline">{stages.map((stage, index) => { const duration = Number(stage.duration_ms || stage.duration || 0); const status = String(stage.status || 'completed').toLowerCase(); const failed = ['error', 'failed', 'timeout'].includes(status); return <div key={`${stage.stage || 'stage'}-${index}`} className="grid grid-cols-[2rem_1fr_auto] gap-3 px-4 py-3 text-xs"><div className="flex items-start justify-center pt-0.5 text-ink-faint">{failed ? <XCircle size={14} className="text-critical" /> : status === 'running' ? <CircleDot size={14} className="text-medium" /> : <CheckCircle2 size={14} className="text-safe" />}</div><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="font-mono text-ink-dim">{stage.stage || 'Unnamed stage'}</span><span className={`font-mono text-[10px] uppercase ${failed ? 'text-critical' : status === 'running' ? 'text-medium' : 'text-safe'}`}>{status}</span>{stage.item_count !== undefined && <span className="font-mono text-[10px] text-ink-faint">{stage.item_count} items</span>}</div><div className="mt-2 h-1 overflow-hidden rounded-full bg-hairline"><div className={`h-full ${failed ? 'bg-critical' : 'bg-accent'}`} style={{ width: `${Math.max(duration ? 3 : 0, Math.min(100, duration / maxDuration * 100))}%` }} /></div>{stage.error && <p className="mt-2 text-[11px] text-critical">{stage.error}</p>}</div><span className="whitespace-nowrap font-mono text-ink-dim">{formatDuration(duration)}</span></div>; })}</div></div> : <div className="mt-5 rounded border border-dashed border-hairline-strong px-4 py-8 text-center text-xs text-ink-faint">Older analyses do not contain stage timing records.</div>}</section>;
}
*/
function EvidenceGroup({ title, icon, tone, items, empty }: { title: string; icon: ReactNode; tone: 'red' | 'amber'; items: string[]; empty: string }) { return <div className="rounded border border-hairline-strong bg-raised p-5"><div className={`flex items-center gap-2 text-sm font-semibold ${tone === 'red' ? 'text-critical' : 'text-medium'}`}>{icon}{title}</div>{items.length ? <ul className="mt-4 space-y-3 text-sm text-ink-dim">{items.map((item, index) => <li key={`${item}-${index}`} className="border-l-2 border-current pl-3">{item}</li>)}</ul> : <p className="mt-4 text-sm text-ink-faint">{empty}</p>}</div>; }
function ProviderTable({ results }: { results: any }) { const providers = [...new Map((Array.isArray(results) ? results : []).map((item: RecordValue) => [item.provider, item.status || 'unknown'])).entries()]; return <div className="overflow-hidden rounded border border-hairline-strong"><div className="grid grid-cols-[1fr_auto] bg-surface px-3 py-2 report-kicker"><span>Provider</span><span>Status</span></div>{providers.length ? providers.map(([name, status]) => <div key={name} className="grid grid-cols-[1fr_auto] border-t border-hairline-strong px-3 py-3 text-xs"><span className="text-ink-dim">{name}</span><span className={`font-mono uppercase ${status === 'not_found' ? 'text-safe' : status === 'timeout' || status === 'error' ? 'text-medium' : 'text-ink-dim'}`}>{status}</span></div>) : <p className="p-4 text-xs text-ink-faint">No provider results returned.</p>}</div>; }
function IpEnrichmentTable({ results }: { results: any }) { const items = Array.isArray(results) ? results : []; return <div className="mt-4 overflow-hidden rounded border border-hairline-strong"><div className="bg-surface px-3 py-2 report-kicker">Reverse lookup and geolocation</div>{items.length ? items.map((item: RecordValue) => <div key={item.ip} className="border-t border-hairline-strong px-3 py-3 text-xs"><div className="flex flex-wrap justify-between gap-2"><span className="font-mono text-ink-dim">{item.ip}</span><span className="uppercase text-ink-mute">{item.classification}</span></div><div className="mt-2 grid gap-1 text-ink-dim sm:grid-cols-2"><span>PTR: <strong className="text-ink-dim">{item.reverse_dns?.hostname || item.reverse_dns?.status || 'unavailable'}</strong></span><span>Location: <strong className="text-ink-dim">{item.geolocation ? [item.geolocation.city, item.geolocation.country].filter(Boolean).join(', ') : 'unavailable'}</strong></span></div><p className="mt-1 font-mono text-[10px] text-ink-faint">{item.provenance?.reverse_dns || 'reverse_dns_ptr'} · {item.provenance?.geolocation || 'no geolocation provider'}</p></div>) : <p className="p-4 text-xs text-ink-faint">No public IPs available for reverse lookup.</p>}</div>; }
function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) { return <span className="inline-flex items-center gap-2 rounded border border-hairline-strong bg-surface px-3 py-2"><span className="text-accent">{icon}</span><span className="text-ink-mute">{label}</span><span className="font-mono text-ink-dim">{value}</span></span>; }
function IocMetric({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) { return <div className="rounded border border-hairline-strong bg-surface p-3"><div className="flex items-center gap-2 text-xs text-ink-mute">{icon}{label}</div><p className="mt-2 font-mono text-xl text-ink-dim">{value}</p></div>; }
function DataField({ label, value }: { label: string; value: any }) { return <div className="flex min-w-0 gap-2 text-xs"><strong className="shrink-0 text-ink-mute">{label}</strong><span className="break-all text-ink-dim">{String(value)}</span></div>; }
function LoadingState() { return <div className="mx-auto max-w-5xl space-y-4"><div className="h-28 animate-pulse rounded border border-hairline bg-raised" /><div className="h-64 animate-pulse rounded border border-hairline bg-raised" /><p className="font-mono text-xs text-accent">LOADING FORENSIC REPORT...</p></div>; }
function Empty({ text }: { text: string }) { return <p className="rounded border border-dashed border-hairline-strong p-5 text-center text-xs text-ink-faint">{text}</p>; }
function extractedIocs(analysis: RecordValue) { return Array.isArray(analysis.extracted_iocs?.iocs) ? analysis.extracted_iocs.iocs : Array.isArray(analysis.iocs) ? analysis.iocs : []; }
function uniqueIocs(iocs: RecordValue[], ...types: string[]) { return [...new Set(iocs.filter((ioc) => types.includes(ioc.type)).map((ioc) => ioc.normalized_value || ioc.value).filter(Boolean))]; }
function firstRecipient(value: any) { return Array.isArray(value) ? value.slice(0, 3).join(', ') || 'Recipient unavailable' : value || 'Recipient unavailable'; }
function formatDate(value?: string) { if (!value) return 'Date unavailable'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString(); }
function slug(value: string) { return value.toLowerCase().replace(/ /g, '-'); }
function displayVerdict(value: string) { return value === 'benign' ? 'Legitimate' : value; }
function verdictTone(value: string) { return value === 'malicious' ? 'text-critical' : value === 'suspicious' ? 'text-medium' : value === 'benign' ? 'text-safe' : 'text-ink-dim'; }
function verdictBorder(value: string) { return value === 'malicious' ? 'border-critical/40 bg-critical/10' : value === 'suspicious' ? 'border-medium/40 bg-medium/10' : 'border-safe/30 bg-safe/10'; }
function authTone(value?: string) { return value === 'pass' ? 'text-safe' : ['fail', 'reject'].includes(value || '') ? 'text-critical' : 'text-ink-mute'; }
function clampScore(value: number) { return Number.isFinite(value) ? Math.min(100, Math.max(0, Math.round(value))) : 0; }
function trustRisk(auth: RecordValue) { const statuses = ['spf', 'dkim', 'dmarc'].map((name) => String(auth[name]?.status || '').toLowerCase()).filter(Boolean); if (!statuses.length) return 0; return clampScore((statuses.filter((status) => ['fail', 'reject', 'none', 'missing'].includes(status)).length / statuses.length) * 100); }
function authDetail(auth: RecordValue) { return ['spf', 'dkim', 'dmarc'].map((name) => `${name.toUpperCase()}: ${auth[name]?.status || 'unavailable'}`).join(' | '); }
function buildCertDraft({ analysis, subject, sender, risk, verdict }: { analysis: RecordValue; subject: string; sender: string; risk: number; verdict: string }) { return [`CERT-In incident draft`, `Subject: ${subject}`, `Sender: ${sender}`, `Classification: ${verdict.toUpperCase()}`, `Risk score: ${risk}/100`, `Summary: ${analysis.summary || 'No summary returned.'}`, `Analysis ID: ${analysis.analysis_id || 'unavailable'}`].join('\n'); }
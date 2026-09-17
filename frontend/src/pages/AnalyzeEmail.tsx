import { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { analyzeEmail, getAnalysisStatus, getGmailInboxStatus, listGmailMessages, scanGmailMessage, type GmailMessage } from '../services/analysisApi';
import { BASE_URL } from '../services/api';
import {
  FileUp, X, MailSearch, FileText, ShieldCheck, ArrowRight,
  AlertTriangle, CheckCircle2, Clock3, Cpu, Globe, Binary, Layers, Radar, Zap, Inbox, RefreshCw, ScanSearch
} from 'lucide-react';

const SCAN_STAGES = [
  'MIME Parser & Token Dissector',
  'Cryptographic Re-Verification (SPF/DKIM/DMARC)',
  'Global Hop GeoTracing & TOR Exit Node Check',
  'Threat Fusion & Multi-Model Scoring',
  'Blockchain Ledger Anchoring',
];

type InputMode = 'file' | 'mime' | 'triage';
type DemoScenario = { name: string; icon: string; description: string; content: string };

const DEMO_SCENARIOS: DemoScenario[] = [
  {
    name: 'Clean Corporate Memo',
    icon: '🟢',
    description: 'Legitimate SPF/DKIM/DMARC pass',
    content: `From: "IT Support" <it.admin@example.com>\nTo: engineering-team@example.com\nSubject: Notice: Scheduled GitHub Enterprise Maintenance on Friday\nDate: Tue, 13 Sep 2026 12:00:00 +0000\nMessage-ID: <clean-business-12345@example.com>\nReceived: from mail.example.com (10.0.0.12) by mx.example.com\nAuthentication-Results: mx.example.com; spf=pass (mx.example.com: domain of it.admin@example.com designates 10.0.0.12 as permitted sender) smtp.mailfrom=it.admin@example.com; dkim=pass header.i=@example.com; dmarc=pass (p=reject sp=reject dis=none) header.from=example.com\nContent-Type: text/plain; charset="UTF-8"\n\nHi Team,\n\nJust a quick reminder that we will have scheduled maintenance on our internal GitHub Enterprise instance this Friday at 10:00 PM EST.\n\nThe system will be read-only for approximately 2 hours while we apply the latest security patches.\n\nPlease make sure to push any pending work before the maintenance window begins.\n\nBest,\nIT Infrastructure Team`,
  },
  {
    name: 'CEO Urgent Wire Transfer (BEC)',
    icon: '💼',
    description: 'Executive impersonation without links',
    content: `From: "Chief Executive Officer" <ceo@enterprise-corp.co>\nTo: vp.finance@example.com\nSubject: Urgent Confidential Payroll Wire Transfer Required\nDate: Tue, 13 Sep 2026 10:20:00 +0000\nMessage-ID: <bec-alert-999@enterprise-corp.co>\nReceived: from mail.enterprise-corp.co (203.0.113.44) by mx.example.com\nAuthentication-Results: mx.example.com; spf=softfail; dkim=none; dmarc=none\nContent-Type: text/plain; charset="UTF-8"\n\nSarah,\n\nI am currently in a confidential offsite meeting with potential partners and cannot be reached by phone.\n\nWe need to process an urgent vendor payment of $48,500 immediately to secure our negotiations before the afternoon cutoff.\n\nPlease process the wire transfer to the following account details right away. Do not call me to confirm as I cannot take calls right now. I will explain everything when I return to the office.\n\nSend me the confirmation screen as soon as it is done.\n\nRegards,\nCEO`,
  },
  {
    name: 'Bank Credential Harvesting Phish',
    icon: '🏦',
    description: 'Suspended account credential lure',
    content: `From: "Chase Bank Compliance" <alert@chase-secure-update-net.com>\nTo: customer@example.com\nSubject: ACTION REQUIRED: Unusual sign-in activity detected on your account\nDate: Tue, 13 Sep 2026 09:15:00 +0000\nMessage-ID: <phish-chase-888@chase-secure-update-net.com>\nReceived: from proxy.chase-secure-update-net.com (185.220.101.5) by mx.example.com\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\nContent-Type: text/plain; charset="UTF-8"\n\nDear Customer,\n\nWe detected unusual login activity on your Chase online banking account from a new location (IP Address: 45.33.22.11).\n\nFor your security, we have temporarily suspended your account functionalities.\n\nTo restore your access and prevent permanent account closure, please verify your identity immediately:\nhttps://chase-secure-update-net.com/verify-identity/\n\nIf you do not complete this verification within 24 hours, your account will remain locked.\n\nSincerely,\nChase Fraud Prevention Team`,
  },
  {
    name: 'Typosquat / Lookalike Domain',
    icon: '🎯',
    description: 'Microsoft lookalike impersonation',
    content: `From: "Microsoft Support" <support@micosoft-service.com>\nTo: security@example.com\nSubject: Critical Security Alert: Your Microsoft 365 Password Expires Today\nDate: Tue, 13 Sep 2026 14:30:00 +0000\nMessage-ID: <typosquat-777@micosoft-service.com>\nReceived: from mailout.micosoft-service.com (198.51.100.123) by mx.example.com\nAuthentication-Results: mx.example.com; spf=pass (mx.example.com: domain of support@micosoft-service.com designates 198.51.100.123 as permitted sender) smtp.mailfrom=support@micosoft-service.com; dkim=pass header.i=@micosoft-service.com; dmarc=pass header.from=micosoft-service.com\nContent-Type: text/plain; charset="UTF-8"\n\nHello,\n\nYour Microsoft 365 Exchange password for security@example.com is set to expire in 2 hours.\n\nYou must retain your current password to continue using Outlook, OneDrive, and Teams without interruption.\n\nPlease click the secure Microsoft portal link below to keep your current password active:\nhttps://login.micosoft-service.com/auth/login?user=security@example.com\n\nIf this action is not completed, your email services will be disconnected globally.\n\nMicrosoft Security Team`,
  },
  {
    name: 'Weaponized Macro Invoice Attachment',
    icon: '📎',
    description: 'Invoice with executable XLSM payload',
    content: `From: "Accounts Payable" <billing@vendor-invoice-mail.com>\nTo: finance@example.com\nSubject: OVERDUE: Invoice Inv-88421 - Immediate Payment Required\nDate: Tue, 13 Sep 2026 11:05:00 +0000\nMessage-ID: <malware-555@vendor-invoice-mail.com>\nReceived: from invoice-host.vendor-invoice-mail.com (198.51.100.77) by mx.example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="invoice-boundary"\n\n--invoice-boundary\nContent-Type: text/plain; charset="UTF-8"\n\nDear Finance,\n\nAttached is the overdue invoice relative to the services provided last month.\nPlease kindly review the attached document and process the payment at your earliest convenience to avoid late fees.\n\nNote: Since this is a protected document, you will need to "Enable Content" or "Enable Macros" upon opening it to view the full billing details.\n\nThank you,\nAccounts Payable Department\n\n--invoice-boundary\nContent-Type: application/vnd.ms-excel; name="Invoice_88421.xlsm"\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename="Invoice_88421.xlsm"\n\nUEsDBBQAAAAIAAAAAAAAAAAAAAAAAAAAAAAIAAAAZXhsL3ZjUHJvamVjdC5iaW5VAgAA\nc29tZW1hbHdhcmVwYXlsb2FkYmFzZTY0ZHVtbXltYWNyb2NvZGVoZXJlCg==\n--invoice-boundary--`,
  },
];

export default function AnalyzeEmail() {
  const [emailContent, setEmailContent] = useState('');
  const [filePreview, setFilePreview] = useState('');
  const [inputMode, setInputMode] = useState<InputMode>('file');
  const [activeScenario, setActiveScenario] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [stageText, setStageText] = useState('Reading RFC 5322 MIME stream & headers...');
  const [progressPct, setProgressPct] = useState(0);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [gmailConnected, setGmailConnected] = useState(false);
  const [gmailMessages, setGmailMessages] = useState<GmailMessage[]>([]);
  const [isLoadingGmail, setIsLoadingGmail] = useState(false);
  const [scanningGmailId, setScanningGmailId] = useState<string | null>(null);
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadGmailMessages = async () => {
    setIsLoadingGmail(true);
    setError(null);
    try {
      const status = await getGmailInboxStatus();
      const canReadGmail = status.connected && status.gmail_readonly;
      setGmailConnected(canReadGmail);
      if (canReadGmail) {
        const result = await Promise.race([
          listGmailMessages(),
          new Promise<never>((_, reject) => window.setTimeout(() => reject(new Error('Gmail inbox request timed out. Please try Refresh inbox again.')), 30000)),
        ]);
        setGmailMessages(result.messages);
      } else {
        setGmailMessages([]);
      }
    } catch (reason: any) {
      setError(reason?.message || 'Could not load Gmail messages.');
    } finally {
      setIsLoadingGmail(false);
    }
  };

  useEffect(() => {
    void loadGmailMessages();
  }, []);

  useEffect(() => {
    if (!isAnalyzing || !startedAt) return;
    const timer = window.setInterval(() => setElapsedSeconds(Math.floor((Date.now() - startedAt) / 1000)), 250);
    return () => window.clearInterval(timer);
  }, [isAnalyzing, startedAt]);

  useEffect(() => {
    if (!file) {
      setFilePreview('');
      return;
    }
    file.text().then(setFilePreview).catch(() => setFilePreview(''));
  }, [file]);

  const acceptFile = (selectedFile?: File) => {
    if (!selectedFile) return;
    if (!selectedFile.name.toLowerCase().endsWith('.eml')) {
      setError('Invalid format: Only RFC 822/5322 .eml message files are supported.');
      setFile(null);
      return;
    }
    setError(null);
    setActiveScenario(null);
    setFile(selectedFile);
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => acceptFile(event.target.files?.[0]);
  const handleDrop = (event: React.DragEvent) => {
    event.preventDefault();
    acceptFile(event.dataTransfer.files?.[0]);
  };

  const startAnalysis = async (content: string, selectedFile?: File) => {
    if (!content.trim() && !selectedFile) {
      setError('Please provide email source via file upload (.eml) or paste raw MIME contents.');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setStageText('Queued for forensic ingestion');
    setProgressPct(5);
    setStartedAt(Date.now());
    setElapsedSeconds(0);

    try {
      const initResult = await analyzeEmail(content, selectedFile);
      const { analysis_id } = initResult;

      const pollStatus = async () => {
        try {
          const statusResult = await getAnalysisStatus(analysis_id);

          setStageText(statusResult.stage || 'Processing...');
          setProgressPct(statusResult.progress_pct || 0);

          if (statusResult.status === 'completed') {
            navigate(`/analysis/${analysis_id}`);
          } else if (statusResult.status === 'failed') {
            setError(statusResult.error || 'Forensic analysis failed.');
            setIsAnalyzing(false);
            setStartedAt(null);
          } else {
            setTimeout(pollStatus, 500);
          }
        } catch (err: any) {
          setError(err?.message || 'Error fetching analysis status.');
          setIsAnalyzing(false);
          setStartedAt(null);
        }
      };

      setTimeout(pollStatus, 500);
    } catch (err: any) {
      setError(err?.message || 'Forensic analysis failed to start. Verify MIME validity and network connection.');
      setIsAnalyzing(false);
      setStartedAt(null);
    }
  };

  const handleAnalyze = () => startAnalysis(emailContent, file || undefined);

  const handleGmailScan = async (message: GmailMessage) => {
    setScanningGmailId(message.id);
    setError(null);
    setIsAnalyzing(true);
    setStageText('Queued from Gmail inbox');
    setProgressPct(5);
    setStartedAt(Date.now());
    setElapsedSeconds(0);
    try {
      const result = await scanGmailMessage(message.id);
      const pollStatus = async () => {
        try {
          const status = await getAnalysisStatus(result.analysis_id);
          setStageText(status.stage || 'Processing Gmail message...');
          setProgressPct(status.progress_pct || 0);
          if (status.status === 'completed') {
            navigate(`/analysis/${result.analysis_id}`);
            return;
          }
          if (status.status === 'failed') {
            throw new Error(status.error || 'Gmail message analysis failed.');
          }
          window.setTimeout(() => void pollStatus(), 700);
        } catch (reason: any) {
          setError(reason?.message || 'Gmail message analysis failed.');
          setIsAnalyzing(false);
          setStartedAt(null);
        }
      };
      window.setTimeout(() => void pollStatus(), 500);
    } catch (reason: any) {
      setError(reason?.message || 'Could not queue the Gmail message for analysis.');
      setIsAnalyzing(false);
      setStartedAt(null);
    } finally {
      setScanningGmailId(null);
    }
  };

  const connectGoogle = () => {
    window.location.assign(`${BASE_URL}/api/auth/google/login`);
  };

  const loadScenario = (scenario: DemoScenario) => {
    setInputMode('mime');
    setActiveScenario(scenario.name);
    setFile(null);
    setEmailContent(scenario.content);
    setError(null);
    void startAnalysis(scenario.content);
  };

  const previewText = filePreview || emailContent;
  const previewSubject = previewText.match(/^Subject:\s*(.+)$/im)?.[1]?.trim() || 'Subject not detected';
  const previewSender = previewText.match(/^From:\s*(.+)$/im)?.[1]?.trim() || 'Sender not detected';
  const previewHops = (previewText.match(/^Received:/gim) || []).length;
  const previewSize = file ? file.size : new Blob([previewText]).size;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      {/* Header */}
      <header className="relative overflow-hidden rounded-xl border border-hairline-strong bg-raised/80 p-6 shadow-[0_20px_60px_rgba(2,12,15,0.22)]">
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-accent shadow-[0_0_10px_rgba(88,214,192,0.8)] animate-pulse" />
          <p className="text-[10px] font-mono font-bold uppercase tracking-[0.2em] text-accent">INGESTION PIPELINE · FORENSIC INTAKE</p>
        </div>
        <h1 className="mt-1.5 text-2xl font-bold tracking-tight text-ink">Email Investigation Lab</h1>
        <p className="mt-1 max-w-3xl text-xs text-ink-mute font-mono">
          Submit suspicious messages for deterministic header forensics, authentication verification, macro inspection, and entity relationship graphing.
        </p>
      </header>

      <section className="space-y-3">
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-hairline bg-raised/90 p-2 font-mono text-[10px] uppercase tracking-wider">
          {([
            ['file', 'File Upload (.eml)'],
            ['mime', 'Direct MIME Paste'],
            ['triage', 'Quick URL / Header Triage'],
          ] as [InputMode, string][]).map(([mode, label]) => (
            <button key={mode} type="button" onClick={() => setInputMode(mode)} className={`rounded px-3 py-2 transition ${inputMode === mode ? 'bg-accent text-[#071018]' : 'text-ink-mute hover:bg-raised hover:text-ink-dim'}`}>
              {label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.18em] text-medium">
          <Zap size={13} /> Demo attack scenarios · one click to load and scan
        </div>
      </section>

      <section className="rounded-xl border border-hairline-strong bg-raised/90 p-5 shadow-[0_18px_45px_rgba(2,12,15,0.2)]">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="rounded border border-hairline-strong bg-accent-soft p-2.5 text-accent"><Inbox size={19} /></div>
            <div>
              <p className="font-mono text-[9px] font-bold uppercase tracking-[0.2em] text-accent">GMAIL INBOX · READ ONLY</p>
              <h2 className="mt-1 text-base font-semibold text-ink">Choose an email to scan</h2>
              <p className="mt-1 text-xs text-ink-mute">Select one message and send its original MIME source to the forensic pipeline.</p>
            </div>
          </div>
          {gmailConnected ? <button type="button" onClick={() => void loadGmailMessages()} disabled={isLoadingGmail} className="inline-flex items-center justify-center gap-2 rounded border border-hairline-strong px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-accent hover:bg-raised disabled:opacity-50">
            <RefreshCw size={13} className={isLoadingGmail ? 'animate-spin' : ''} /> Refresh inbox
          </button> : <button type="button" onClick={connectGoogle} className="inline-flex items-center justify-center gap-2 rounded bg-accent px-3 py-2 font-mono text-[10px] font-bold uppercase tracking-wider text-[#071018] hover:brightness-110">
            <span className="flex h-4 w-4 items-center justify-center rounded-full bg-white text-[10px] font-bold text-[#4285f4]">G</span> Connect Google &amp; Gmail
          </button>}
        </div>
        {!gmailConnected && !isLoadingGmail && <p className="mt-4 rounded border border-medium/40 bg-medium/10 p-3 text-xs font-mono text-medium">Connect Google with Gmail read access to choose a message from your inbox.</p>}
        {gmailConnected && !isLoadingGmail && gmailMessages.length === 0 && <p className="mt-4 rounded border border-hairline-strong bg-sunken p-3 text-xs font-mono text-ink-mute">No messages are available in the Gmail inbox.</p>}
        {gmailMessages.length > 0 && <div className="mt-4 space-y-2">
          {gmailMessages.map((message) => <div key={message.id} className="flex flex-col gap-3 rounded border border-hairline-strong bg-sunken p-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="truncate text-xs font-semibold text-ink">{message.subject}</p>
              <p className="mt-1 truncate font-mono text-[10px] text-accent">{message.sender}</p>
              <p className="mt-1 truncate text-[11px] text-ink-mute">{message.snippet || 'No preview available.'}</p>
            </div>
            <button type="button" onClick={() => void handleGmailScan(message)} disabled={scanningGmailId !== null || isAnalyzing} className="inline-flex shrink-0 items-center justify-center gap-2 rounded bg-accent px-3 py-2 font-mono text-[10px] font-bold uppercase tracking-wider text-[#071018] hover:brightness-110 disabled:cursor-wait disabled:opacity-50">
              <ScanSearch size={13} /> {scanningGmailId === message.id ? 'Queueing...' : 'Scan email'}
            </button>
          </div>)}
        </div>}
      </section>

      {/* Primary Intake Grid */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-5">
        {/* Upload Box */}
        <section className="lg:col-span-3 rounded-xl border border-hairline bg-raised/90 p-6 shadow-[0_18px_45px_rgba(2,12,15,0.2)] flex flex-col justify-between">
          <div>
            <div className="flex items-start gap-3">
              <div className="rounded border border-hairline bg-surface p-2.5 text-accent">
                <FileUp size={20} />
              </div>
              <div>
                <span className="soc-label !text-accent bg-accent-soft rounded border border-accent/30">
                  RECOMMENDED INTAKE
                </span>
                <h2 className="mt-1 text-base font-semibold text-ink">Upload RFC 5322 EML File</h2>
                <p className="mt-0.5 text-xs text-ink-mute font-mono">
                  Preserves raw Received headers, boundary delimiters, and binary attachment payloads.
                </p>
              </div>
            </div>

            <div className="mt-5 grid gap-2 sm:grid-cols-2">
              {DEMO_SCENARIOS.map((scenario) => (
                <button key={scenario.name} type="button" onClick={() => loadScenario(scenario)} disabled={isAnalyzing} className={`group rounded border px-3 py-2 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${activeScenario === scenario.name ? 'border-accent/60 bg-accent-soft' : 'border-hairline-strong bg-sunken hover:border-accent/50'}`}>
                  <span className="flex items-center gap-2 text-xs font-semibold text-ink-dim"><span>{scenario.icon}</span>{scenario.name}</span>
                  <span className="mt-1 block text-[10px] font-mono text-ink-mute group-hover:text-ink-dim">{scenario.description}</span>
                </button>
              ))}
            </div>

            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="mt-5 flex min-h-52 cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-hairline-strong bg-sunken p-6 text-center transition-all hover:border-accent/60 hover:bg-accent-soft/40"
            >
              {file ? (
                <div className="flex max-w-full items-center gap-3 rounded-lg border border-accent/40 bg-raised px-5 py-3.5 shadow-md">
                  <FileText size={22} className="shrink-0 text-accent" />
                  <div className="min-w-0 text-left font-mono">
                    <p className="truncate text-xs font-bold text-ink">{file.name}</p>
                    <p className="mt-0.5 text-[10px] text-ink-mute">
                      {(file.size / 1024).toFixed(1)} KB • EML Archive Loaded
                    </p>
                  </div>
                  <button
                    aria-label="Remove uploaded email"
                    onClick={(e) => {
                      e.stopPropagation();
                      setFile(null);
                    }}
                    className="ml-3 rounded p-1 text-ink-mute hover:bg-critical/10 hover:text-critical transition-colors"
                  >
                    <X size={16} />
                  </button>
                </div>
              ) : (
                <>
                  <div className="rounded-full bg-raised p-3 border border-hairline text-ink-mute mb-2">
                    <FileUp size={26} className="text-accent" />
                  </div>
                  <p className="text-xs font-semibold uppercase font-mono tracking-wider text-ink-dim">
                    Drop .eml file here to inspect
                  </p>
                  <p className="mt-1 text-[11px] text-ink-mute font-mono">
                    or click to select from local forensic storage
                  </p>
                </>
              )}
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                accept=".eml"
                className="hidden"
              />
            </div>
          </div>

          <div className="mt-4 flex items-center justify-between pt-3 border-t border-hairline/60 text-[11px] font-mono text-ink-mute">
            <span>Supported: RFC 822, RFC 2822, RFC 5322</span>
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="text-xs font-mono text-accent hover:text-accent font-semibold"
            >
              Browse Files...
            </button>
          </div>
        </section>

        {/* Forensic Capabilities Checklist */}
        <aside className="lg:col-span-2 rounded-xl border border-hairline bg-raised/90 p-6 shadow-[0_18px_45px_rgba(2,12,15,0.2)] flex flex-col justify-between">
          <div>
            <p className="text-[9px] font-mono font-bold uppercase tracking-[0.2em] text-ink-mute">ENGINE CAPABILITIES</p>
            <h3 className="mt-1 text-sm font-semibold text-ink-dim">Automated Pipeline Coverage</h3>

            <div className="mt-4 space-y-3.5 font-mono text-xs">
              <div className="flex gap-3">
                <ShieldCheck size={16} className="mt-0.5 shrink-0 text-safe" />
                <div>
                  <p className="font-semibold text-ink-dim">Cryptographic Auth Verification</p>
                  <p className="text-[11px] text-ink-mute leading-relaxed">
                    Evaluates SPF records, DKIM public key signatures, DMARC policies, and ARC seals.
                  </p>
                </div>
              </div>

              <div className="flex gap-3">
                <Layers size={16} className="mt-0.5 shrink-0 text-accent" />
                <div>
                  <p className="font-semibold text-ink-dim">Mail Flow Chronology</p>
                  <p className="text-[11px] text-ink-mute leading-relaxed">
                    Traces every MTA hop, calculating propagation delay and detecting IP divergence.
                  </p>
                </div>
              </div>

              <div className="flex gap-3">
                <Binary size={16} className="mt-0.5 shrink-0 text-ink-dim" />
                <div>
                  <p className="font-semibold text-ink-dim">Deep Attachment Forensics</p>
                  <p className="text-[11px] text-ink-mute leading-relaxed">
                    Inspects magic bytes, detects VBA macros/OLE streams, and computes SHA-256 hashes.
                  </p>
                </div>
              </div>

              <div className="flex gap-3">
                <Globe size={16} className="mt-0.5 shrink-0 text-medium" />
                <div>
                  <p className="font-semibold text-ink-dim">Threat Intelligence & MITRE ATT&CK</p>
                  <p className="text-[11px] text-ink-mute leading-relaxed">
                    Maps indicators to T1566 phishing techniques, extracting structured STIX 2.1 entities.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6 rounded border border-hairline bg-sunken p-3 text-[10px] font-mono text-ink-mute leading-relaxed">
            Data Safety: Local processing mode. No unencrypted content is shared with external parties.
          </div>
        </aside>
      </div>

      {/* Raw MIME Paste Option */}
      <section className="rounded-xl border border-hairline bg-raised/90 p-6 shadow-[0_18px_45px_rgba(2,12,15,0.2)]">
        <div className="flex items-start gap-3">
          <div className="rounded border border-hairline bg-raised p-2.5 text-ink-dim">
            <MailSearch size={20} />
          </div>
          <div>
            <span className="soc-label !text-accent bg-accent-soft rounded border border-accent/30">
              DIRECT INPUT
            </span>
            <h2 className="mt-1 text-base font-semibold text-ink">{inputMode === 'triage' ? 'Quick URL / Header Triage' : 'Paste Raw MIME / Header Text'}</h2>
            <p className="mt-0.5 text-xs text-ink-mute font-mono">
              {inputMode === 'triage' ? 'Paste a suspicious URL or compact header block for immediate routing and IOC preview.' : 'Alternative ingestion path for clipboard transfers or raw terminal logs.'}
            </p>
          </div>
        </div>

        <textarea
          className="mt-4 h-56 w-full resize-y rounded-lg border border-hairline-strong bg-sunken p-4 font-mono text-xs leading-relaxed text-ink-dim outline-none transition-all placeholder:text-ink-faint/60 focus:border-accent focus:ring-1 focus:ring-accent/20"
          placeholder={`Delivered-To: victim@enterprise.corp
Received: from mail.attacker.net (mail.attacker.net [198.51.100.24])
    by mx.google.com with ESMTPS id ...
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain does not designate 198.51.100.24)
From: "Security Alert" <security@update-service.com>
To: victim@enterprise.corp
Subject: Urgent: Verify Account Access Immediately
Date: Tue, 08 Sep 2026 10:00:00 +0000
Content-Type: text/html; charset="UTF-8"

Please verify your credentials at http://suspicious-login-portal.com/login`}
          value={emailContent}
          onChange={(e) => {
            setEmailContent(e.target.value);
            setActiveScenario(null);
            if (error) setError(null);
          }}
        />
      </section>

      {previewText.trim() && !isAnalyzing && (
        <section className="rounded-lg border border-accent/30 bg-surface p-4 font-mono shadow-none">
          <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-accent"><Radar size={14} className="animate-pulse" /> Client-side pre-flight summary</div>
          <div className="mt-3 grid gap-3 sm:grid-cols-4">
            <PreflightItem label="Sender" value={previewSender} />
            <PreflightItem label="Subject" value={previewSubject} />
            <PreflightItem label="Payload" value={`${previewSize.toLocaleString()} bytes`} />
            <PreflightItem label="Hop estimate" value={`${previewHops} Received headers`} />
          </div>
        </section>
      )}

      {/* Active Pipeline Progress Display */}
      {isAnalyzing && (
        <div className="rounded-lg border border-accent/40 bg-accent-soft p-5 shadow-lg space-y-3 font-mono">
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2 text-accent font-bold">
              <Cpu size={15} className="animate-spin text-accent" />
              LIVE SCAN FEED
            </span>
            <span className="text-ink-mute text-[11px]">
              {Math.min(100, Math.max(0, progressPct))}% COMPLETE
            </span>
          </div>

          <div className="relative h-24 overflow-hidden rounded border border-accent/20 bg-sunken">
            <div className="absolute inset-y-0 left-0 w-1/2 animate-[scan_2.4s_linear_infinite] border-r border-accent/60 bg-gradient-to-r from-transparent via-accent/10 to-accent/20" />
            <div className="absolute inset-0 flex items-center justify-center"><div className="h-14 w-14 rounded-full border border-accent/40 shadow-[0_0_24px_rgba(76,158,235,0.25)]"><div className="ml-7 h-7 origin-bottom border-l border-accent/80 rotate-45" /></div></div>
            <div className="absolute bottom-2 left-3 right-3 h-1 overflow-hidden rounded bg-raised"><div className="h-full bg-accent transition-all duration-500" style={{ width: `${Math.min(100, Math.max(0, progressPct))}%` }} /></div>
          </div>

          <p className="border-l-2 border-accent/60 pl-3 text-xs leading-6 text-ink-dim" aria-live="polite">
            {stageText}
          </p>

          <div className="flex items-center gap-2 text-[10px] uppercase tracking-widest text-ink-mute">
            <Clock3 size={13} className="text-accent" />
            <span>Elapsed {String(Math.floor(elapsedSeconds / 60)).padStart(2, '0')}:{String(elapsedSeconds % 60).padStart(2, '0')}</span>
            <span className="text-ink-faint/60">·</span>
            <span>Evidence collection active</span>
          </div>

          <div className="grid gap-2 border-t border-accent/20 pt-3 sm:grid-cols-5">
            {SCAN_STAGES.map((stage, index) => {
              const threshold = [5, 20, 40, 65, 85][index] ?? 85;
              const complete = progressPct > threshold || (index === 0 && progressPct >= threshold);
              const active = !complete && progressPct >= threshold - 10;
              return <div key={stage} className={`flex items-center gap-2 text-[10px] leading-4 ${complete ? 'text-safe' : active ? 'text-ink-dim' : 'text-ink-faint'}`}><span className="shrink-0">{complete ? <CheckCircle2 size={13} /> : <span className={`block h-2 w-2 rounded-full ${active ? 'animate-pulse bg-accent' : 'bg-ink-faint'}`} />}</span><span>{stage}</span></div>;
            })}
          </div>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div role="alert" className="flex items-center gap-2.5 rounded-lg border border-critical/40 bg-critical/10 p-4 text-xs font-mono text-critical shadow-md">
          <AlertTriangle size={17} className="shrink-0 text-critical" />
          <span>{error}</span>
        </div>
      )}

      {/* Action Footer */}
      <div className="flex flex-col gap-3 border-t border-hairline pt-5 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-xs text-ink-mute font-mono">
          {file
            ? `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`
            : emailContent.trim()
            ? `MIME stream loaded (${emailContent.length} bytes)`
            : 'Select an .eml file or paste email content above to begin.'}
        </p>

        <button
          onClick={handleAnalyze}
          disabled={isAnalyzing}
          className="btn-primary min-w-56 py-3 disabled:opacity-50 disabled:cursor-not-allowed font-mono"
        >
          {isAnalyzing ? (
            <>
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/20 border-t-white" />
              <span>PROCESSING...</span>
            </>
          ) : (
            <>
              <span>EXECUTE FORENSIC ANALYSIS</span>
              <ArrowRight size={15} />
            </>
          )}
        </button>
      </div>
    </div>
  );
}

function PreflightItem({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0 border-l border-accent/30 pl-3"><p className="text-[9px] uppercase tracking-widest text-ink-mute">{label}</p><p className="mt-1 truncate text-xs text-ink-dim" title={value}>{value}</p></div>;
}

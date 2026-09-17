import { useState, useEffect } from 'react';
import { apiFetch } from '../services/api';
import { searchPersistedIocs } from '../services/analysisApi';
import { Severity, ThreatIndicator } from '../types';
import { useToast } from '../context/ToastContext';
import {
  Search, Filter, Copy, Database, Radio, ChevronDown, ChevronRight,
  ExternalLink, ShieldAlert, Globe, Clock, Activity, Server, FileText
} from 'lucide-react';
import { categorizeIoc } from '../utils/iocCategorization';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { SecurityEnvironmentBackground } from '../components/common/SecurityEnvironmentBackground';

export interface ProviderStatus {
  source: string;
  status: 'ok' | 'not_configured' | 'unavailable' | 'timeout' | 'error';
  error?: string | null;
}

export interface WorkbenchIndicator extends ThreatIndicator {
  // Local Analysis specific context
  analysis_id?: string;
  email_subject?: string;
  email_sender?: string;
  verdict?: string;
  risk_score?: number;
  created_at?: string;
  context?: string;
}

export default function Indicators() {
  const [indicators, setIndicators] = useState<WorkbenchIndicator[]>([]);
  const [providers, setProviders] = useState<ProviderStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('ALL');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [sourceMode, setSourceMode] = useState<'live' | 'local'>('live');
  const [expanded, setExpanded] = useState<string | null>(null);
  const { addToast } = useToast();

  useEffect(() => {
    let cancelled = false;

    const loadData = async () => {
      setLoading(true);
      try {
        if (sourceMode === 'live') {
          const response = await apiFetch('/api/indicators');
          if (!cancelled) {
            const rawList: any[] = response.data || [];
            const mapped: WorkbenchIndicator[] = rawList.map((item: any) => ({
              id: String(item.id),
              indicator: item.indicator || '',
              indicator_type: normalizeIocType(item.indicator_type),
              severity: normalizeSeverity(item.severity),
              confidence: item.confidence || 0,
              source: item.source || 'Threat Intelligence Feed',
              country: item.country || null,
              country_code: item.country_code || null,
              latitude: item.latitude ?? null,
              longitude: item.longitude ?? null,
              first_seen: item.first_seen || null,
              last_seen: item.last_seen || null,
              status: item.status || 'inactive',
              malware: item.malware || null,
              tags: Array.isArray(item.tags) ? item.tags : [],
              reference_url: item.reference_url || null,
              reporter: item.reporter || null,
              threat_type: item.threat_type || null,
              relatedThreats: item.relatedThreats || [],
              related_investigations: item.related_investigations || [],
            }));
            setIndicators(mapped);
            if (response.meta?.providers) {
              setProviders(response.meta.providers);
            }
          }
        } else {
          const response = await searchPersistedIocs(
            searchTerm.trim() || '',
            selectedType === 'ALL' ? undefined : selectedType.toLowerCase()
          );
          if (!cancelled) {
            const rawMatches: any[] = response.data || [];
            const mapped: WorkbenchIndicator[] = rawMatches.map((item: any, index: number) => ({
              id: `local-${item.analysis_id}-${item.indicator}-${index}`,
              indicator: item.indicator || '',
              indicator_type: normalizeIocType(item.type),
              severity: normalizeSeverity(item.severity),
              confidence: item.confidence || 80,
              source: 'Persisted Local Analysis',
              first_seen: item.created_at || null,
              last_seen: item.created_at || null,
              status: 'active',
              analysis_id: item.analysis_id,
              email_subject: item.email_subject || '(No subject)',
              email_sender: item.email_sender || 'Sender not available in parsed message',
              verdict: item.verdict,
              risk_score: item.risk_score,
              created_at: item.created_at,
              context: item.context || 'Extracted forensic evidence',
              relatedThreats: item.analysis_id ? [item.analysis_id] : [],
              related_investigations: item.analysis_id ? [item.analysis_id] : [],
              tags: item.sources || ['local_email_evidence']
            }));
            setIndicators(mapped);
          }
        }
      } catch (err) {
        console.error('Failed to load indicators:', err);
        if (!cancelled) setIndicators([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    const timer = window.setTimeout(loadData, sourceMode === 'local' ? 300 : 0);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [sourceMode, searchTerm, selectedType]);

  const filtered = indicators.filter(item => {
    const term = searchTerm.toLowerCase();
    const matchesSearch = !searchTerm ||
      item.indicator.toLowerCase().includes(term) ||
      (item.source || '').toLowerCase().includes(term) ||
      (item.malware || '').toLowerCase().includes(term) ||
      (item.reporter || '').toLowerCase().includes(term) ||
      (item.threat_type || '').toLowerCase().includes(term) ||
      (item.email_subject || '').toLowerCase().includes(term) ||
      (item.analysis_id || '').toLowerCase().includes(term) ||
      (item.tags || []).some(tag => tag.toLowerCase().includes(term));

    const matchesType = selectedType === 'ALL' || item.indicator_type === selectedType;
    const category = categorizeIoc({ value: item.indicator, source: item.source || '', type: item.indicator_type });
    return matchesSearch && matchesType && (selectedCategory === 'ALL' || category === selectedCategory);
  });

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      addToast('Indicator copied to clipboard', 'info');
    } catch {
      addToast('Clipboard access was unavailable', 'warning');
    }
  };

  return (
    <div className="mx-auto max-w-[1680px] space-y-5 font-sans">
      <SecurityEnvironmentBackground profile="indicators" intensity="subtle" />

      {/* Header */}
      <header className="relative z-10 flex flex-col gap-4 border-b border-hairline pb-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-accent animate-pulse" />
            <p className="text-[10px] font-mono font-bold uppercase tracking-[0.2em] text-accent">
              THREAT INTELLIGENCE WORKBENCH
            </p>
          </div>
          <h1 className="mt-1.5 text-2xl font-bold tracking-tight text-ink">Indicator Intelligence Center</h1>
          <p className="mt-1 text-xs text-ink-mute font-mono">
            Direct feed ingestion from ThreatFox, URLhaus, and local forensic investigations with full provider provenance.
          </p>
        </div>

        {/* Real Provider Connectivity Status */}
        {sourceMode === 'live' && providers.length > 0 && (
          <div className="flex flex-wrap items-center gap-2.5 font-mono text-[11px]">
            <span className="text-[10px] font-bold uppercase tracking-wider text-ink-mute mr-1">Feeds:</span>
            {providers.map(p => (
              <div
                key={p.source}
                className={`flex items-center gap-1.5 rounded border px-2.5 py-1 ${
                  p.status === 'ok'
                    ? 'border-safe/30 bg-safe/10 text-safe'
                    : p.status === 'not_configured'
                    ? 'border-hairline bg-sunken/50 text-ink-mute'
                    : 'border-critical/30 bg-critical/10 text-critical'
                }`}
                title={p.error || undefined}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    p.status === 'ok'
                      ? 'bg-safe'
                      : p.status === 'not_configured'
                      ? 'bg-ink-faint'
                      : 'bg-critical'
                  }`}
                />
                <span className="font-semibold">{p.source}</span>
                <span className="text-[9px] uppercase tracking-wider opacity-80">
                  {p.status === 'ok' ? 'Connected' : p.status === 'not_configured' ? 'Not Configured' : 'Degraded'}
                </span>
              </div>
            ))}
          </div>
        )}
      </header>

      {/* Mode Selector Tabs */}
      <div className="relative z-10 flex gap-2 border-b border-hairline">
        <SourceTab
          active={sourceMode === 'live'}
          onClick={() => { setSourceMode('live'); setExpanded(null); }}
          icon={Radio}
          label="Live Intelligence Feeds (ThreatFox / URLhaus)"
        />
        <SourceTab
          active={sourceMode === 'local'}
          onClick={() => { setSourceMode('local'); setExpanded(null); }}
          icon={Database}
          label="Local Email Forensic IOCs"
        />
      </div>

      {/* Filter and Search Bar */}
      <section className="relative z-10 flex flex-col gap-3 rounded-lg border border-hairline bg-raised/90 p-4 shadow-lg xl:flex-row">
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-3 top-2.5 text-ink-mute" size={15} />
          <input
            placeholder={
              sourceMode === 'live'
                ? "Search IOC, IP, domain, URL, hash, malware, reporter, or tags..."
                : "Search local IOC value, analysis ID, sender, or subject..."
            }
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full rounded-lg border border-hairline-strong bg-sunken py-2 pl-9 pr-3 text-xs font-mono text-ink-dim outline-none placeholder:text-ink-faint focus:border-accent/60 focus:ring-1 focus:ring-accent/20"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Filter size={14} className="text-ink-mute" />
          <FilterSelect
            label="Type"
            value={selectedType}
            setValue={setSelectedType}
            options={['ALL', 'IP', 'Domain', 'URL', 'Hash', 'Email']}
          />
          <FilterSelect
            label="Category"
            value={selectedCategory}
            setValue={setSelectedCategory}
            options={['ALL', 'Actual IOC', 'Infrastructure', 'Forensic Artifact']}
          />
        </div>
      </section>

      {/* Main Table / Workbench */}
      <section className="relative z-10 overflow-hidden rounded-lg border border-hairline bg-raised/90 shadow-lg">
        <div className="flex items-center justify-between border-b border-hairline px-5 py-4">
          <div>
            <p className="text-[9px] font-mono font-bold uppercase tracking-[0.18em] text-ink-mute">
              {sourceMode === 'live' ? 'External Threat Provider Observations' : 'Locally Analyzed Evidence Records'}
            </p>
            <p className="mt-1 text-xs text-ink-dim font-mono">
              <span className="font-bold text-accent">{filtered.length}</span> indicators matching active criteria
            </p>
          </div>

          <div className="hidden items-center gap-4 text-[10px] text-ink-mute md:flex font-mono">
            <span className="flex items-center gap-1.5">
              <i className="h-2 w-2 rounded-full bg-critical" /> Actual IOC
            </span>
            <span className="flex items-center gap-1.5">
              <i className="h-2 w-2 rounded-full bg-medium" /> Infrastructure
            </span>
            <span className="flex items-center gap-1.5">
              <i className="h-2 w-2 rounded-full bg-accent" /> Forensic Artifact
            </span>
          </div>
        </div>

        {loading ? (
          <div className="space-y-2 p-5">
            {[1, 2, 3, 4, 5].map(row => (
              <div key={row} className="h-12 animate-pulse rounded bg-surface border border-hairline" />
            ))}
          </div>
        ) : !filtered.length ? (
          <div className="p-12 text-center font-mono text-xs text-ink-mute">
            No indicators match the search or filter query.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1000px] text-left text-xs font-mono">
              <thead className="bg-sunken text-[10px] uppercase tracking-wider text-ink-mute border-b border-hairline">
                <tr>
                  <th className="px-5 py-3">Indicator</th>
                  <th className="px-4 py-3">Classification</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Provenance / Feed</th>
                  <th className="px-5 py-3">{sourceMode === 'live' ? 'Last Seen / Online' : 'Observation Date'}</th>
                  <th className="px-3 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline/60">
                {filtered.map(item => {
                  const category = categorizeIoc({
                    value: item.indicator,
                    source: item.source || '',
                    type: item.indicator_type
                  });
                  const isExpanded = expanded === item.id;

                  return (
                    <IndicatorRow
                      key={item.id}
                      item={item}
                      category={category}
                      isExpanded={isExpanded}
                      onToggle={() => setExpanded(isExpanded ? null : item.id)}
                      onCopy={() => handleCopy(item.indicator)}
                      sourceMode={sourceMode}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function IndicatorRow({
  item,
  category,
  isExpanded,
  onToggle,
  onCopy,
  sourceMode
}: {
  item: WorkbenchIndicator;
  category: string;
  isExpanded: boolean;
  onToggle: () => void;
  onCopy: () => void;
  sourceMode: 'live' | 'local';
}) {
  const confidenceLabel =
    item.source === 'ThreatFox'
      ? 'ThreatFox Confidence'
      : item.source === 'URLhaus'
      ? 'URLhaus Reputation Score'
      : 'Local Evidence Confidence';

  return (
    <>
      <tr className={`transition-colors hover:bg-surface ${isExpanded ? 'bg-sunken' : ''}`}>
        <td className="max-w-[340px] px-5 py-3.5">
          <button
            onClick={onToggle}
            className="flex items-center gap-2 text-left font-mono text-xs text-accent hover:text-ink-dim truncate w-full"
            title={item.indicator}
          >
            {isExpanded ? <ChevronDown size={14} className="shrink-0 text-accent" /> : <ChevronRight size={14} className="shrink-0 text-ink-mute" />}
            <span className="truncate">{item.indicator}</span>
          </button>
        </td>

        <td className="px-4 py-3.5 whitespace-nowrap">
          <span
            className={`text-[10px] font-bold uppercase tracking-wider ${
              category === 'Actual IOC'
                ? 'text-critical'
                : category === 'Infrastructure'
                ? 'text-medium'
                : 'text-accent'
            }`}
          >
            {category}
          </span>
        </td>

        <td className="px-4 py-3.5 text-ink-dim">{item.indicator_type}</td>

        <td className="px-4 py-3.5">
          <SeverityBadge severity={item.severity} />
        </td>

        <td className="px-4 py-3.5 font-mono text-ink-dim" title={confidenceLabel}>
          {item.confidence}%
        </td>

        <td className="max-w-[190px] px-4 py-3.5 truncate">
          <span
            className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
              item.source === 'ThreatFox'
                ? 'bg-medium/10 text-medium border border-medium/30'
                : item.source === 'URLhaus'
                ? 'bg-critical/15 text-critical border border-critical/30'
                : 'bg-accent/10 text-accent border border-accent/30'
            }`}
          >
            {item.source}
          </span>
        </td>

        <td className="whitespace-nowrap px-5 py-3.5 text-ink-mute text-[11px]">
          {formatTimestamp(item.last_seen || item.first_seen, 'No subsequent sightings')}
        </td>

        <td className="px-3 py-3.5 text-right whitespace-nowrap">
          <button
            onClick={onCopy}
            className="rounded p-1.5 text-ink-mute hover:bg-raised hover:text-accent transition-colors"
            title="Copy indicator value"
          >
            <Copy size={13} />
          </button>
        </td>
      </tr>

      {/* Expanded Intelligence Drawer */}
      {isExpanded && (
        <tr className="border-t border-hairline-strong bg-sunken">
          <td colSpan={8} className="p-0">
            <div className="p-5 space-y-4 border-l-2 border-accent/60 bg-surface/95 text-xs font-mono">
              {/* Row 1: Identity & Provenance */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 border-b border-hairline pb-4">
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute">Provider Provenance</p>
                  <p className="mt-1 text-ink-dim font-semibold flex items-center gap-1.5">
                    <Server size={13} className="text-accent" />
                    {item.source}
                  </p>
                </div>

                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute">First Observed</p>
                  <p className="mt-1 text-ink-dim flex items-center gap-1.5">
                    <Clock size={13} className="text-ink-mute" />
                    {formatTimestamp(item.first_seen, 'Not reported by source')}
                  </p>
                </div>

                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute">Last Observed / Online</p>
                  <p className="mt-1 text-ink-dim flex items-center gap-1.5">
                    <Clock size={13} className="text-ink-mute" />
                    {formatTimestamp(item.last_seen, 'No subsequent sightings')}
                  </p>
                </div>

                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute">Operational Status</p>
                  <p className="mt-1 text-ink-dim font-semibold flex items-center gap-1.5">
                    <Activity size={13} className={item.status === 'online' || item.status === 'active' ? 'text-critical' : 'text-ink-mute'} />
                    {item.status ? item.status.toUpperCase() : 'Not reported'}
                  </p>
                </div>
              </div>

              {/* Row 2: Threat & Attribution Context */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 border-b border-hairline pb-4">
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute">Threat Type / Category</p>
                  <p className="mt-1 text-ink-dim font-semibold flex items-center gap-1.5">
                    <ShieldAlert size={13} className="text-medium" />
                    {item.threat_type || (sourceMode === 'local' ? (item.verdict?.toUpperCase() || 'EVIDENCE') : 'Not reported by source')}
                  </p>
                </div>

                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute">Malware Family / Payload</p>
                  <p className="mt-1 text-ink-dim">
                    {item.malware || 'None reported'}
                  </p>
                </div>

                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute">Reporter / Attribution</p>
                  <p className="mt-1 text-ink-dim">
                    {item.reporter || (sourceMode === 'local' ? item.email_sender : 'Not reported')}
                  </p>
                </div>

                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute">Reference URL / Advisory</p>
                  {item.reference_url ? (
                    <a
                      href={item.reference_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mt-1 inline-flex items-center gap-1 text-accent hover:text-accent truncate max-w-full"
                    >
                      <ExternalLink size={12} />
                      <span className="truncate">{item.reference_url}</span>
                    </a>
                  ) : (
                    <p className="mt-1 text-ink-mute italic">No external link available</p>
                  )}
                </div>
              </div>

              {/* Row 3: Tags & Infrastructure */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-b border-hairline pb-4">
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute mb-1.5">Observed Tags</p>
                  {item.tags && item.tags.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {item.tags.map((tag, i) => (
                        <span key={i} className="rounded bg-raised px-2 py-0.5 text-[10px] text-ink-dim border border-hairline-strong">
                          {tag}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-ink-mute italic text-[11px]">No tags provided</p>
                  )}
                </div>

                <div>
                  <p className="text-[9px] uppercase tracking-wider text-ink-mute mb-1.5">Geospatial Telemetry</p>
                  {item.country || item.country_code ? (
                    <p className="text-ink-dim flex items-center gap-1.5">
                      <Globe size={13} className="text-accent" />
                      {item.country || item.country_code}
                      {item.latitude && item.longitude && (
                        <span className="text-ink-mute text-[10px]">
                          ({item.latitude.toFixed(2)}, {item.longitude.toFixed(2)})
                        </span>
                      )}
                    </p>
                  ) : (
                    <p className="text-ink-mute italic text-[11px]">No geolocation reported</p>
                  )}
                </div>
              </div>

              {/* Row 4: Relationships & Local Investigation Links */}
              <div>
                <p className="text-[9px] uppercase tracking-wider text-ink-mute mb-2">
                  Correlated Local Investigations
                </p>
                {item.related_investigations && item.related_investigations.length > 0 ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-ink-dim font-semibold">
                      {item.related_investigations.length} {item.related_investigations.length === 1 ? 'investigation matches this indicator:' : 'investigations match this indicator:'}
                    </span>
                    {item.related_investigations.map(analysisId => (
                      <a
                        key={analysisId}
                        href={`/analysis/${analysisId}`}
                        className="inline-flex items-center gap-1 rounded border border-accent/30 bg-accent/10 px-2.5 py-1 text-[11px] text-accent hover:bg-accent/10 hover:border-accent/60 transition-colors"
                      >
                        <FileText size={11} />
                        <span>Case #{analysisId}</span>
                      </a>
                    ))}
                  </div>
                ) : (
                  <p className="text-ink-mute italic text-[11px]">
                    No related local investigations observed in analysis database.
                  </p>
                )}
              </div>

              {/* If Local Analysis Mode: Show Email Case Context */}
              {sourceMode === 'local' && item.analysis_id && (
                <div className="rounded border border-hairline-strong bg-sunken p-3 space-y-1.5 text-[11px]">
                  <p className="text-[9px] uppercase tracking-wider text-accent font-bold">Investigation Forensic Context</p>
                  <p className="text-ink-dim"><strong className="text-ink-mute">Email Subject:</strong> {item.email_subject}</p>
                  <p className="text-ink-dim"><strong className="text-ink-mute">Sender:</strong> {item.email_sender}</p>
                  <p className="text-ink-dim"><strong className="text-ink-mute">Extraction Context:</strong> {item.context}</p>
                  <p className="text-ink-dim">
                    <strong className="text-ink-mute">Verdict:</strong> <span className="uppercase font-bold">{item.verdict}</span> (Risk Score: {item.risk_score}/100)
                  </p>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function SourceTab({
  active,
  onClick,
  icon: Icon,
  label
}: {
  active: boolean;
  onClick: () => void;
  icon: typeof Radio;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-2 border-b-2 px-4 py-2.5 text-xs font-mono font-bold uppercase tracking-wider transition-colors ${
        active
          ? 'border-accent/60 text-accent bg-accent/5'
          : 'border-transparent text-ink-mute hover:text-ink-dim hover:bg-raised'
      }`}
    >
      <Icon size={14} />
      {label}
    </button>
  );
}

function FilterSelect({
  label,
  value,
  setValue,
  options
}: {
  label: string;
  value: string;
  setValue: (value: string) => void;
  options: string[];
}) {
  return (
    <select
      aria-label={label}
      value={value}
      onChange={e => setValue(e.target.value)}
      className="rounded-lg border border-hairline-strong bg-sunken px-2.5 py-1.5 text-xs font-mono text-ink-dim outline-none focus:border-accent/60"
    >
      {options.map(opt => (
        <option key={opt} value={opt}>
          {opt === 'ALL' ? `All ${label}` : opt}
        </option>
      ))}
    </select>
  );
}

function normalizeIocType(value?: string): 'IP' | 'Domain' | 'URL' | 'Email' | 'Hash' {
  const type = String(value || '').toLowerCase();
  if (type === 'url') return 'URL';
  if (type === 'domain') return 'Domain';
  if (type === 'ip' || type === 'ipv6') return 'IP';
  if (type === 'email') return 'Email';
  return 'Hash';
}

function normalizeSeverity(value?: string): Severity {
  const sev = String(value || '').toLowerCase();
  if (sev === 'critical') return 'Critical';
  if (sev === 'high') return 'High';
  if (sev === 'medium') return 'Medium';
  if (sev === 'low') return 'Low';
  return 'Safe';
}

function formatTimestamp(value?: string | null, fallback: string = 'Not reported by source'): string {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toUTCString().replace('GMT', 'UTC');
}

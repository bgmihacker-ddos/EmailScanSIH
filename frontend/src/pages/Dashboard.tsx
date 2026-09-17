import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, LineChart, Line } from 'recharts';
import { ArrowRight, MailSearch, Shield, Activity, Database, Clock, ChevronRight, Terminal } from 'lucide-react';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { MetricCard } from '../components/common/MetricCard';
import { SecurityEnvironmentBackground } from '../components/common/SecurityEnvironmentBackground';
import { DashboardSummary, DashboardTrends, getDashboardSummary, getDashboardTrends } from '../services/analysisApi';
import { useWebSocketAlerts } from '../hooks/useWebSocket';
import { CHART, chartTick, chartTooltip, severityFill } from '../utils/chartTheme';

const EMPTY_SUMMARY: DashboardSummary = {
  metrics: { total_analyses: 0, flagged_analyses: 0, malicious_analyses: 0, average_risk_score: 0 },
  verdict_counts: {},
  severity_counts: {},
  activity: [],
  distribution: [],
  top_indicators: [],
  recent_analyses: [],
  data_source: 'persisted_local_analyses',
};

export default function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary>(EMPTY_SUMMARY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [trends, setTrends] = useState<DashboardTrends | null>(null);
  const { alerts, connected } = useWebSocketAlerts();

  useEffect(() => {
    getDashboardSummary()
      .then(setSummary)
      .catch(() => setError('Forensic dashboard metrics are currently unavailable.'))
      .finally(() => setLoading(false));
    getDashboardTrends().then(setTrends).catch(() => setTrends(null));
  }, []);

  const totalIOCs = summary.top_indicators.reduce((acc, curr) => acc + curr.count, 0);

  return (
    <div className="relative mx-auto max-w-[1680px] space-y-5">
      <SecurityEnvironmentBackground profile="dashboard" intensity="subtle" />
      {/* Page header */}
      <header className="relative z-10 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="animate-live-dot h-2 w-2 rounded-full bg-accent text-accent" />
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-accent">Security operations · email forensics</p>
          </div>
          <h1 className="mt-3 text-2xl font-semibold tracking-tight text-ink">
            Investigation overview
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-ink-dim">
            A measured view of recent email investigations, risk posture, and infrastructure evidence.
          </p>
        </div>

        <div className="flex flex-col items-stretch gap-3 sm:flex-row sm:items-center">
          <div className="hidden border-l border-hairline pl-4 sm:block"><p className="soc-label">Operating posture</p><p className="mt-1 flex items-center gap-1.5 text-xs font-medium text-safe"><span className="h-1.5 w-1.5 rounded-full bg-safe" /> Evidence collection active</p></div>
          <Link
            to="/analyze"
            className="btn-primary"
          >
            <MailSearch size={15} />
            <span>Analyze EML / MIME</span>
            <ArrowRight size={14} />
          </Link>
        </div>
      </header>

      {/* Telemetry Strip — sunken rail */}
      <div className="relative z-10 grid grid-cols-2 gap-3 rounded-lg border border-hairline bg-sunken/70 py-3 text-xs font-mono md:grid-cols-4">
        <div className="flex items-center gap-2.5 px-3">
          <Database size={14} className="shrink-0 text-accent" />
          <div className="min-w-0">
            <p className="text-[9px] uppercase tracking-wider text-ink-mute">Data Repository</p>
            <p className="truncate text-xs font-semibold text-ink-dim">{summary.data_source || 'Local SQLite Store'}</p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 px-3 md:border-l md:border-hairline">
          <Shield size={14} className="shrink-0 text-safe" />
          <div className="min-w-0">
            <p className="text-[9px] uppercase tracking-wider text-ink-mute">Forensic Engine</p>
            <p className="text-xs font-semibold text-ink-dim">Deterministic V1.5</p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 px-3 md:border-l md:border-hairline">
          <Activity size={14} className="shrink-0 text-medium" />
          <div className="min-w-0">
            <p className="text-[9px] uppercase tracking-wider text-ink-mute">Total IOCs Extracted</p>
            <p className="text-xs font-semibold text-ink-dim">{loading ? '—' : totalIOCs}</p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 px-3 md:border-l md:border-hairline">
          <Clock size={14} className="shrink-0 text-ink-mute" />
          <div className="min-w-0">
            <p className="text-[9px] uppercase tracking-wider text-ink-mute">Pipeline Mode</p>
            <p className="flex items-center gap-1.5 text-xs font-semibold text-safe">
              <span className="h-1.5 w-1.5 rounded-full bg-safe" />
              Real-time Ingestion
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div className="relative z-10 rounded-md border border-medium/40 bg-medium/10 px-4 py-3 font-mono text-xs text-medium">
          {error}
        </div>
      )}

      {/* Metric Cards Grid */}
      <section className="relative z-10 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          title="Total Investigations"
          value={loading ? '—' : summary.metrics.total_analyses}
          tone="text-accent"
        />
        <MetricCard
          title="Flagged Investigations"
          value={loading ? '—' : summary.metrics.flagged_analyses}
          tone="text-medium"
        />
        <MetricCard
          title="Malicious Verdicts"
          value={loading ? '—' : summary.metrics.malicious_analyses}
          tone="text-critical"
        />
        <MetricCard
          title="Average Risk Score"
          value={loading ? '—' : `${summary.metrics.average_risk_score}/100`}
          tone={summary.metrics.average_risk_score >= 60 ? 'text-critical' : 'text-high'}
        />
      </section>

      {/* Analytical Charts & Threat Indicators */}
      <section className="relative z-10 grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* Activity Volume Chart */}
        <div className="soc-panel xl:col-span-6 p-5">
          <SectionTitle eyebrow="INVESTIGATION CHRONOLOGY" title="Threat Activity Volume" />
          <div className="mt-4">
            {summary.activity.length ? (
              <ResponsiveContainer width="100%" height={190}>
                <BarChart data={summary.activity} barGap={4}>
                  <XAxis dataKey="date" tick={chartTick} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={chartTooltip} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar dataKey="analyses" name="Total Ingested" fill={CHART.accent} radius={[3, 3, 0, 0]} />
                  <Bar dataKey="flagged" name="High Risk Flagged" fill={CHART.medium} radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState text="No persisted activity timeline available yet." />
            )}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="soc-panel xl:col-span-3 p-5">
          <SectionTitle eyebrow="RISK POSTURE" title="Severity Distribution" />
          <div className="mt-4">
            {summary.distribution.length ? (
              <div className="relative">
                <ResponsiveContainer width="100%" height={190}>
                  <PieChart>
                    <Pie data={summary.distribution} innerRadius={58} outerRadius={84} paddingAngle={4} dataKey="value">
                      {summary.distribution.map((entry) => (
                        <Cell key={entry.name} fill={severityFill(entry.name, entry.color)} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={chartTooltip} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-ink-mute">Investigations</span>
                  <span className="font-mono text-xl font-bold text-ink">{summary.metrics.total_analyses}</span>
                </div>
              </div>
            ) : (
              <EmptyState text="No distribution data available." />
            )}
          </div>
        </div>

        {/* Top Indicators */}
        <div className="soc-panel xl:col-span-3 p-5">
          <SectionTitle eyebrow="FORENSIC ARTIFACTS" title="Observed Intelligence Indicators" />
          <div className="mt-4">
            {summary.top_indicators.length ? (
              <div className="max-h-[190px] space-y-1.5 overflow-y-auto pr-1">
                {summary.top_indicators.map((item, index) => (
                  <div key={item.indicator} className="flex items-center justify-between gap-3 rounded border border-hairline bg-sunken px-3 py-2 transition-colors hover:border-accent/30">
                    <div className="flex min-w-0 items-center gap-2.5">
                      <span className="w-4 font-mono text-[10px] text-ink-faint">{String(index + 1).padStart(2, '0')}</span>
                      <span className="truncate font-mono text-xs text-ink-dim" title={item.indicator}>
                        {item.indicator}
                      </span>
                    </div>
                    <span className="shrink-0 rounded border border-accent/25 bg-accent-soft px-2 py-0.5 font-mono text-[10px] text-accent">
                      {item.count} hit{item.count !== 1 ? 's' : ''}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState text="No indicators extracted yet. Run an analysis to populate." />
            )}
          </div>
        </div>
      </section>

      <section className="relative z-10 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="soc-panel p-5"><SectionTitle eyebrow="ORIGIN ANALYSIS" title="Top countries" /><ResponsiveContainer width="100%" height={180}><BarChart data={trends?.countries || []} layout="vertical"><XAxis type="number" allowDecimals={false} hide /><YAxis type="category" dataKey="name" width={82} tick={{ fill: '#A6B0C2', fontSize: 10 }} /><Tooltip contentStyle={chartTooltip} /><Bar dataKey="count" fill={CHART.accent} radius={[0, 3, 3, 0]} /></BarChart></ResponsiveContainer></div>
        <div className="soc-panel p-5"><SectionTitle eyebrow="TRUST ANALYSIS" title="Authentication results" /><div className="mt-4 space-y-3">{['spf', 'dkim', 'dmarc'].map((name) => <div key={name} className="flex items-center justify-between border-b border-hairline pb-2 text-xs"><span className="font-mono uppercase text-ink-mute">{name}</span><span className="font-mono text-ink-dim">{Object.entries(trends?.auth_results?.[name] || {}).map(([status, count]) => `${status}: ${count}`).join(' · ') || 'no observations'}</span></div>)}</div></div>
        <div className="soc-panel p-5"><SectionTitle eyebrow="ATTACK TAXONOMY" title="Observed attack types" /><div className="mt-4 space-y-2">{(trends?.attack_types || []).slice(0, 6).map((item) => <div key={item.name} className="flex items-center justify-between rounded bg-sunken px-3 py-2 text-xs"><span className="truncate text-ink-dim">{item.name}</span><span className="font-mono text-accent">{item.count}</span></div>)}{!trends?.attack_types?.length && <EmptyState text="No attack types observed yet." />}</div></div>
      </section>

      <section className="relative z-10 grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="soc-panel xl:col-span-8 p-5"><SectionTitle eyebrow="TREND TELEMETRY" title="Thirty-day investigation trend" /><div className="mt-4"><ResponsiveContainer width="100%" height={220}><LineChart data={trends?.daily || []}><XAxis dataKey="date" tick={chartTick} /><YAxis allowDecimals={false} tick={chartTick} /><Tooltip contentStyle={chartTooltip} /><Line type="monotone" dataKey="analyses" stroke={CHART.accent} strokeWidth={2} dot={false} /><Line type="monotone" dataKey="flagged" stroke={CHART.medium} strokeWidth={2} dot={false} /></LineChart></ResponsiveContainer></div></div>
        <div className="soc-panel xl:col-span-4 p-5"><SectionTitle eyebrow="LIVE ALERTS" title={connected ? 'WebSocket connected' : 'WebSocket unavailable'} /><div className="mt-4 space-y-2">{alerts.length ? alerts.map((alert, index) => <div key={`${alert.analysis_id}-${index}`} className="rounded border border-critical/30 bg-critical/10 p-3 text-xs"><p className="font-mono text-critical">{alert.verdict || 'alert'} · {alert.risk_score ?? '—'}/100</p><p className="mt-1 text-ink-dim">{alert.summary || alert.analysis_id}</p></div>) : <EmptyState text="No live alerts received in this session." />}</div></div>
      </section>

      {/* Recent Investigation Queue Table */}
      <section className="soc-panel relative z-10 overflow-hidden">
        <div className="flex items-center justify-between border-b border-hairline bg-sunken px-5 py-4">
          <div className="flex items-center gap-2">
            <Terminal size={15} className="text-accent" />
            <SectionTitle eyebrow="CASE LOG" title="Recent Email Investigations" compact />
          </div>
          <Link className="inline-flex items-center gap-1 font-mono text-xs text-accent transition-colors hover:brightness-125" to="/history">
            Complete History <ArrowRight size={13} />
          </Link>
        </div>

        {summary.recent_analyses.length ? (
          <div className="overflow-x-auto">
            <table className="soc-table min-w-[800px]">
              <thead>
                <tr>
                  <th className="px-5 py-3">Subject / Case ID</th>
                  <th className="px-4 py-3">Sender Identity</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Risk Score</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {summary.recent_analyses.map((item) => (
                  <tr key={item.analysis_id}>
                    <td className="px-5 py-3.5">
                      <Link to={`/analysis/${item.analysis_id}`} className="block max-w-[340px] truncate font-medium text-ink-dim transition-colors hover:text-accent">
                        {item.subject || 'Untitled Subject'}
                      </Link>
                      <span className="font-mono text-[10px] text-ink-faint">{item.analysis_id}</span>
                    </td>
                    <td className="max-w-[200px] truncate px-4 py-3.5 font-mono text-[11px] text-ink-mute">
                      {item.sender || 'Unknown Sender'}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3.5 font-mono text-[11px] text-ink-mute">
                      {formatDate(item.created_at)}
                    </td>
                    <td className="px-4 py-3.5 font-mono">
                      <span className={`rounded border px-2 py-0.5 text-[11px] font-bold ${
                        item.risk_score >= 70
                          ? 'severity-critical'
                          : item.risk_score >= 40
                          ? 'severity-medium'
                          : 'severity-safe'
                      }`}>
                        {item.risk_score} / 100
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      <SeverityBadge severity={item.severity} />
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <Link
                        to={`/analysis/${item.analysis_id}`}
                        className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-accent transition-colors hover:brightness-125"
                      >
                        Inspect <ChevronRight size={13} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-10">
            <EmptyState text="No investigations found in database. Ingest an EML file to initialize SOC feed." />
          </div>
        )}
      </section>
    </div>
  );
}

function SectionTitle({ eyebrow, title, compact = false }: { eyebrow: string; title: string; compact?: boolean }) {
  return (
    <div>
      <p className="soc-label">{eyebrow}</p>
      <h2 className={`${compact ? 'mt-0.5 text-sm' : 'mt-1 text-base'} font-semibold text-ink`}>{title}</h2>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="flex h-[180px] items-center justify-center px-6 text-center font-mono text-xs text-ink-mute">
      {text}
    </div>
  );
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toLocaleString();
}

import { ThreatMap } from '../components/map/ThreatMap';
import { useState, useEffect } from 'react';
import { getLiveThreats } from '../services/threatApi';
import { ThreatMapEvent } from '../types/threats';
import { Activity, AlertTriangle, Globe2, Radio, RefreshCw, ShieldAlert, Terminal } from 'lucide-react';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { SecurityEnvironmentBackground } from '../components/common/SecurityEnvironmentBackground';

export default function LiveThreat() {
  const [threatEvents, setThreatEvents] = useState<ThreatMapEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const loadThreats = () => {
    setLoading(true);
    setError(null);
    getLiveThreats().then(setThreatEvents).catch(() => setError('Failed to load live threat feed.')).finally(() => setLoading(false));
  };

  useEffect(() => { loadThreats(); }, []);

  const selected = threatEvents.find(event => event.id === selectedId);
  const highCount = threatEvents.filter(event => event.severity === 'High' || event.severity === 'Critical').length;
  const sourceCount = new Set(threatEvents.map(event => event.source).filter(Boolean)).size;

  return (
    <div className="mx-auto max-w-[1680px] space-y-5 font-sans">
      <SecurityEnvironmentBackground profile="live_threat" intensity="moderate" />

      <header className="relative z-10 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="animate-live-dot h-2 w-2 rounded-full bg-critical text-critical" />
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-critical">TELEMETRY & GEOSPATIAL CENTER</p>
          </div>
          <h1 className="mt-3 text-2xl font-semibold tracking-tight text-ink">Live Threat Intelligence Feed</h1>
          <p className="mt-1.5 font-mono text-xs text-ink-mute">Real-time geospatial infrastructure attribution and threat campaign telemetry.</p>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-critical/25 bg-critical/10 px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-critical">
          <span className="animate-pulse-slow h-2 w-2 rounded-full bg-critical" /> Live Telemetry Active
        </div>
      </header>

      <div className="relative z-10 flex items-start gap-3 rounded-md border border-medium/30 bg-medium/5 px-4 py-3 font-mono text-xs leading-relaxed text-medium">
        <AlertTriangle size={15} className="mt-0.5 shrink-0" />
        <p><strong>Infrastructure attribution notice:</strong> Map pins visualize observed infrastructure or reporting gateways. Location points reflect reported telemetry metadata, not inherently verified attacker locations.</p>
      </div>

      {error && (
        <div className="relative z-10 flex items-center justify-between rounded-md border border-critical/40 bg-critical/10 px-4 py-3 font-mono text-xs text-critical">
          <span>{error}</span>
          <button onClick={loadThreats} className="btn-secondary !py-1 hover:!border-critical/50 hover:!text-critical">
            <RefreshCw size={12} /> Retry
          </button>
        </div>
      )}

      {/* Stats Grid */}
      <div className="relative z-10 grid grid-cols-2 gap-3 md:grid-cols-4">
        <HudMetric label="Observed Events" value={loading ? '—' : threatEvents.length} icon={Radio} />
        <HudMetric label="Elevated Severity" value={loading ? '—' : highCount} icon={ShieldAlert} tone="text-critical" />
        <HudMetric label="Intelligence Sources" value={loading ? '—' : sourceCount} icon={Globe2} tone="text-ink-dim" />
        <HudMetric label="Feed Status" value={loading ? 'Loading' : error ? 'Degraded' : 'Operational'} icon={Activity} tone={error ? 'text-medium' : 'text-safe'} />
      </div>

      <div className="relative z-10 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        {/* Map Section — dominant war-room surface */}
        <section className="soc-panel flex min-h-[650px] flex-col overflow-hidden !bg-deck/60">
          <div className="mb-4 flex items-center justify-between px-1">
            <div className="flex items-center gap-2">
              <Terminal size={15} className="text-accent" />
              <div>
                <p className="soc-label">Geospatial Intelligence</p>
                <h2 className="mt-1 text-sm font-semibold text-ink-dim">Observed infrastructure surface area</h2>
              </div>
            </div>
            <div className="hidden items-center gap-4 font-mono text-[10px] text-ink-mute sm:flex">
              <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-critical" /> High</span>
              <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-medium" /> Medium</span>
              <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-low" /> Low</span>
            </div>
          </div>
          <div className="flex-1 overflow-hidden rounded-md border border-hairline bg-sunken">
            {loading ? (
              <div className="flex h-full animate-pulse items-center justify-center font-mono text-xs text-accent">
                CALIBRATING GEOSPATIAL TELEMETRY…
              </div>
            ) : (
              <ThreatMap threatEvents={threatEvents} />
            )}
          </div>
        </section>

        {/* Aside Feed — dense mono list */}
        <aside className="soc-panel flex min-h-[650px] flex-col p-5">
          <div className="flex items-start justify-between border-b border-hairline pb-4">
            <div>
              <p className="soc-label">Live Ingestion</p>
              <h2 className="mt-1 text-sm font-semibold text-ink-dim">Event Feed <span className="font-mono text-[11px] font-normal text-ink-mute">({threatEvents.length})</span></h2>
            </div>
            <button
              onClick={loadThreats}
              title="Refresh feed"
              className="rounded p-1.5 text-ink-mute transition-colors hover:bg-raised hover:text-accent"
            >
              <RefreshCw size={14} />
            </button>
          </div>

          <div className="mt-4 flex-1 space-y-2 overflow-y-auto pr-1">
            {!loading && !threatEvents.length && (
              <p className="rounded border border-dashed border-hairline-strong p-4 text-center font-mono text-xs text-ink-faint">No live threat events available.</p>
            )}
            {threatEvents.map(event => (
              <button
                key={event.id}
                onClick={() => setSelectedId(event.id)}
                className={`w-full rounded-md border p-3 text-left transition-colors ${selectedId === event.id ? 'border-accent/40 bg-accent-soft' : 'border-hairline bg-sunken hover:border-hairline-strong'}`}
              >
                <div className="mb-2 flex items-center justify-between gap-2">
                  <SeverityBadge severity={event.severity} />
                  <span className="font-mono text-[9px] text-ink-mute">{event.confidence}% Conf.</span>
                </div>
                <p className="truncate font-mono text-xs font-semibold text-ink-dim">{event.threatType}</p>
                <p className="mt-0.5 truncate font-mono text-[10px] text-ink-mute">{event.country} · {event.city !== 'Not reported' ? `${event.city} · ` : ''}{event.source || 'Unknown source'}</p>
                <p className="mt-2 break-all font-mono text-[10px] text-accent">{event.indicator || 'Indicator not reported'}</p>
                <div className="mt-2 grid grid-cols-2 gap-2 border-t border-hairline pt-2 font-mono text-[9px] text-ink-mute">
                  <span>Malware: <strong className="font-normal text-ink-dim">{event.malware || 'None reported'}</strong></span>
                  <span>Status: <strong className="font-normal uppercase text-ink-dim">{event.status || 'Unknown'}</strong></span>
                  <span>First: <strong className="font-normal text-ink-dim">{formatDate(event.first_seen || event.timestamp)}</strong></span>
                  <span>Last: <strong className="font-normal text-ink-dim">{formatDate(event.last_seen || event.timestamp)}</strong></span>
                </div>
                {!!event.tags?.length && <div className="mt-2 flex flex-wrap gap-1">{event.tags.slice(0, 3).map((tag) => <span key={tag} className="rounded border border-hairline-strong px-1.5 py-0.5 text-[9px] text-ink-mute">{tag}</span>)}</div>}
              </button>
            ))}
          </div>

          {selected && (
            <div className="mt-4 space-y-2 rounded-md border border-accent/25 bg-sunken p-4 font-mono text-[11px] text-ink-dim">
              <div className="flex items-center justify-between border-b border-hairline pb-2">
                <p className="soc-label !text-accent">Selected Event Telemetry</p>
                <span className="text-[9px] text-ink-mute">{selected.source}</span>
              </div>
              <div>
                <p className="text-[9px] uppercase text-ink-mute">Indicator</p>
                <p className="mt-0.5 break-all font-semibold text-accent">{selected.indicator || selected.id}</p>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <p className="text-[9px] uppercase text-ink-mute">Threat Type</p>
                  <p className="mt-0.5 text-ink-dim">{selected.threat_type || selected.threatType}</p>
                </div>
                <div>
                  <p className="text-[9px] uppercase text-ink-mute">Malware / Payload</p>
                  <p className="mt-0.5 text-ink-dim">{selected.malware || 'None reported'}</p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <p className="text-[9px] uppercase text-ink-mute">Location</p>
                  <p className="mt-0.5 text-ink-dim">{selected.city !== 'Not reported' && selected.city ? `${selected.city}, ${selected.country}` : selected.country}</p>
                </div>
                <div>
                  <p className="text-[9px] uppercase text-ink-mute">Status</p>
                  <p className="mt-0.5 font-semibold uppercase text-ink-dim">{selected.status || 'Unknown'}</p>
                </div>
              </div>
              <div>
                <p className="text-[9px] uppercase text-ink-mute">First Seen / Timestamp</p>
                <p className="mt-0.5 text-ink-dim">{formatDate(selected.first_seen || selected.timestamp)}</p>
              </div>
              {selected.reporter && (
                <div>
                  <p className="text-[9px] uppercase text-ink-mute">Reporter</p>
                  <p className="mt-0.5 text-ink-dim">{selected.reporter}</p>
                </div>
              )}
              {selected.reference_url && (
                <div>
                  <p className="text-[9px] uppercase text-ink-mute">Reference</p>
                  <a href={selected.reference_url} target="_blank" rel="noreferrer" className="mt-0.5 block truncate text-accent hover:underline">
                    {selected.reference_url}
                  </a>
                </div>
              )}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function HudMetric({ label, value, icon: Icon, tone = 'text-accent' }: { label: string; value: string | number; icon: typeof Activity; tone?: string }) {
  return (
    <div className="metric-card">
      <div className="flex items-center justify-between">
        <p className="soc-label">{label}</p>
        <Icon size={14} className={tone} />
      </div>
      <p className={`mt-2 font-mono text-xl font-semibold ${tone}`}>{value}</p>
    </div>
  );
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

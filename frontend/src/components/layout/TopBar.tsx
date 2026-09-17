import { useState, useEffect, useRef } from 'react';
import { Bell, User, Search, X, ExternalLink, Shield, FileText, Mail, Activity, Wifi, Server, Eye, ChevronRight } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { globalSearch, SearchResult } from '../../services/searchApi';
import { useWebSocketAlerts } from '../../hooks/useWebSocket';
import { useNavigate } from 'react-router-dom';

/* ── Threat-Level Rail (signature element) ─────────────────────
 * Global posture computed from the live WebSocket alert feed.
 * SEVERE / ELEVATED / GUARDED / LOW — the whole room glances here. */
type Posture = { level: string; color: string; glow: string; bg: string; border: string };

function computePosture(alerts: { severity?: string; risk_score?: number }[], connected: boolean): Posture {
  const weight = (a: { severity?: string; risk_score?: number }) => {
    const sev = String(a.severity || '').toLowerCase();
    if (sev === 'critical' || (a.risk_score ?? 0) >= 80) return 4;
    if (sev === 'high' || (a.risk_score ?? 0) >= 60) return 3;
    if (sev === 'medium' || (a.risk_score ?? 0) >= 40) return 2;
    if (sev) return 1;
    return 2; // unclassified alert counts as medium
  };
  const total = alerts.reduce((sum, a) => sum + weight(a), 0);
  if (total >= 10) return { level: 'SEVERE', color: 'text-critical', glow: 'var(--alert-critical)', bg: 'rgba(244,88,107,0.10)', border: 'rgba(244,88,107,0.45)' };
  if (total >= 5) return { level: 'ELEVATED', color: 'text-high', glow: 'var(--alert-high)', bg: 'rgba(240,121,74,0.10)', border: 'rgba(240,121,74,0.45)' };
  if (total >= 1 || !connected) return { level: 'GUARDED', color: 'text-medium', glow: 'var(--alert-medium)', bg: 'rgba(232,180,74,0.08)', border: 'rgba(232,180,74,0.4)' };
  return { level: 'LOW', color: 'text-safe', glow: 'var(--alert-safe)', bg: 'rgba(62,207,142,0.08)', border: 'rgba(62,207,142,0.4)' };
}

export function TopBar() {
  const { user } = useAuth();
  const { addToast } = useToast();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [showResults, setShowResults] = useState(false);
  const [searching, setSearching] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);
  const { alerts, connected } = useWebSocketAlerts();
  const posture = computePosture(alerts, connected);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(event.target as Node)) {
        setShowResults(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    const debounceTimer = setTimeout(() => {
      if (searchQuery.trim().length > 2) {
        setSearching(true);
        globalSearch(searchQuery).then(results => {
          setSearchResults(results);
          setSearching(false);
          setShowResults(true);
        });
      } else {
        setSearchResults([]);
        setShowResults(false);
      }
    }, 300);

    return () => clearTimeout(debounceTimer);
  }, [searchQuery]);

  const getResultIcon = (type: SearchResult['type']) => {
    switch (type) {
      case 'Threat': return <Shield className="text-critical" size={14} />;
      case 'Indicator': return <Activity className="text-medium" size={14} />;
      case 'EmailScan': return <Mail className="text-low" size={14} />;
      case 'Report': return <FileText className="text-safe" size={14} />;
      case 'User': return <User className="text-ink-dim" size={14} />;
      case 'IntelProvider': return <Wifi className="text-low" size={14} />;
      case 'SystemService': return <Server className="text-high" size={14} />;
      case 'AuditLog': return <Eye className="text-ink-mute" size={14} />;
      default: return <Search className="text-ink-mute" size={14} />;
    }
  };

  const handleResultClick = (result: SearchResult) => {
    setShowResults(false);
    setSearchQuery('');

    switch (result.type) {
      case 'Threat':
        navigate(`/threats/${result.id}`);
        addToast(`Navigated to threat: ${result.data.type}`, 'info');
        break;
      case 'Indicator':
        addToast(`Opening IOC: ${result.data.ioc}`, 'info');
        break;
      case 'EmailScan':
        navigate(`/analysis/${result.id}`);
        addToast(`Opening email scan: ${result.data.subject}`, 'info');
        break;
      case 'Report':
        addToast(`Opening report: ${result.data.title}`, 'info');
        break;
      case 'User':
        addToast(`Viewing user: ${result.data.name}`, 'info');
        break;
      default:
        addToast(`Viewing ${result.type.toLowerCase()}`, 'info');
    }
  };

  const handleClearSearch = () => {
    setSearchQuery('');
    setSearchResults([]);
    setShowResults(false);
  };

  const formatResultType = (type: string) => {
    const typeMap: Record<string, string> = {
      Threat: 'THREAT',
      Indicator: 'IOC',
      EmailScan: 'SCAN',
      Report: 'REPORT',
      User: 'USER',
      IntelProvider: 'TI',
      SystemService: 'SYS',
      AuditLog: 'AUDIT'
    };
    return typeMap[type] || type;
  };

  return (
    <header className="relative z-20 flex h-14 shrink-0 items-center justify-between border-b border-hairline bg-surface/90 px-4 backdrop-blur-md md:px-6">
      {/* Breadcrumb / Location */}
      <div className="flex items-center gap-2.5 text-xs">
        <span className="flex h-6 items-center gap-1.5 rounded border border-hairline bg-sunken px-2 font-mono text-[9px] uppercase tracking-[0.18em] text-ink-mute">
          <Shield size={11} className="text-accent" />
          SOC / LOCAL NODE
        </span>
        <ChevronRight size={12} className="text-ink-faint" />
        <h2 className="hidden text-[13px] font-medium text-ink md:block">
          Security operations
        </h2>
      </div>

      <div className="flex items-center gap-3 md:gap-5">
        {/* ── Threat-Level Rail ── */}
        <div
          className="animate-posture flex h-8 items-center gap-2.5 rounded-md border px-3"
          style={{ background: posture.bg, borderColor: posture.border }}
          title={`Live posture from ${alerts.length} recent alert${alerts.length !== 1 ? 's' : ''} · feed ${connected ? 'connected' : 'offline'}`}
        >
          <span
            className="h-2 w-2 rounded-full"
            style={{ background: posture.glow, boxShadow: `0 0 8px ${posture.glow}` }}
          />
          <span className={`font-mono text-[10px] font-bold uppercase tracking-[0.16em] ${posture.color}`}>
            {posture.level}
          </span>
          {alerts.length > 0 && (
            <span className="border-l pl-2.5 font-mono text-[10px] text-ink-dim" style={{ borderColor: posture.border }}>
              {alerts.length} live
            </span>
          )}
        </div>

        {/* Global Search */}
        <div className="relative hidden lg:block" ref={searchRef}>
          <div className="relative">
            <Search className="absolute left-3 top-2.5 text-ink-faint" size={14} />
            <input
              type="text"
              placeholder="Search threats, IOCs, scans, reports, domains…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onFocus={() => searchQuery.trim().length > 2 && setShowResults(true)}
              className="soc-input w-72 !py-2 !pl-9 !pr-8 !text-xs"
            />
            {searchQuery && (
              <button
                onClick={handleClearSearch}
                className="absolute right-2 top-2 text-ink-faint transition-colors hover:text-ink"
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Search Results Dropdown */}
          {showResults && (
            <div className="soc-panel-elevated absolute left-0 top-full z-50 mt-2 max-h-[60vh] w-[400px] overflow-y-auto">
              <div className="border-b border-hairline px-3 py-2.5">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-mute">
                  {searching ? 'Searching threat intelligence…' : `${searchResults.length} results found`}
                </p>
              </div>

              {searching ? (
                <div className="animate-pulse p-4 text-center font-mono text-xs text-ink-mute">
                  Querying index…
                </div>
              ) : searchResults.length === 0 ? (
                <div className="p-6 text-center font-mono text-xs text-ink-faint">
                  <Search size={22} className="mx-auto mb-2 text-ink-faint/60" />
                  No matches found for "{searchQuery}"
                  <p className="mt-2 text-[10px] text-ink-faint/70">Try: threat ID, domain, IP, or hash</p>
                </div>
              ) : (
                <div className="divide-y divide-hairline">
                  {searchResults.map((result) => (
                    <button
                      key={result.id}
                      onClick={() => handleResultClick(result)}
                      className="flex w-full items-start gap-3 p-3 text-left transition-colors hover:bg-raised"
                    >
                      <div className="mt-0.5 flex-shrink-0">
                        {getResultIcon(result.type)}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="mb-1 flex items-center gap-2">
                          <span className="truncate text-xs font-semibold text-ink">{result.title}</span>
                          <span className="rounded border border-hairline bg-sunken px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-ink-mute">
                            {formatResultType(result.type)}
                          </span>
                          <span className="ml-auto font-mono text-[9px] text-accent">
                            {result.relevance}%
                          </span>
                        </div>
                        <p className="line-clamp-2 text-xs text-ink-mute">{result.description}</p>
                      </div>
                      <ExternalLink size={12} className="mt-0.5 flex-shrink-0 text-ink-faint" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Live feed + Notifications + User */}
        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 border-l border-hairline pl-3 font-mono text-[9px] font-semibold uppercase tracking-[0.14em] text-safe md:flex">
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-safe animate-live-dot text-safe' : 'bg-medium'}`} />
            {connected ? 'Feed live' : 'Feed offline'}
          </div>

          <button className="relative flex h-8 w-8 items-center justify-center rounded-md border border-hairline text-ink-mute transition-colors hover:border-hairline-strong hover:text-ink" aria-label="Notifications">
            <Bell size={15} />
            {alerts.length > 0 && (
              <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-critical" />
            )}
          </button>

          <div className="flex items-center gap-2.5 border-l border-hairline pl-3">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-hairline-strong bg-raised font-mono text-[11px] font-semibold text-accent">
                {user?.name?.charAt(0) || '?'}
              </div>
              <div className="hidden lg:block">
                <p className="text-xs font-medium text-ink">{user?.name || 'Analyst'}</p>
                <p className="font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-ink-mute">
                  {user?.role === 'admin' ? 'Administrator' : 'Security Analyst'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

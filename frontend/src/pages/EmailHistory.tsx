import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter, Shield, ArrowUpRight } from 'lucide-react';
import { AnalysisSummary, listAnalyses } from '../services/analysisApi';
import { SeverityBadge } from '../components/common/SeverityBadge';

export default function EmailHistory() {
  const [scans, setScans] = useState<AnalysisSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedVerdict, setSelectedVerdict] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      setLoading(true);
      try {
        const response = await listAnalyses({
          query: searchTerm.trim() || undefined,
          verdict: selectedVerdict || undefined,
          severity: selectedSeverity || undefined,
        });
        if (!cancelled) {
          setScans(response.data || []);
        }
      } catch {
        if (!cancelled) {
          setScans([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, 250);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [searchTerm, selectedVerdict, selectedSeverity]);

  return (
    <div className="mx-auto max-w-[1600px] space-y-5">
      <header className="flex items-center gap-3 border-b border-hairline pb-5">
        <div className="rounded border border-accent/20 bg-accent/10 p-2 text-accent">
          <Shield size={19} />
        </div>
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-accent/70">Investigation archive</p>
          <h1 className="mt-1 text-2xl font-semibold text-ink">Email investigation history</h1>
          <p className="mt-1 text-sm text-ink-mute">Reopen persisted forensic analyses and review verdict progression.</p>
        </div>
      </header>

      <section className="flex flex-col gap-3 rounded border border-hairline bg-raised p-4 xl:flex-row">
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-3 top-2.5 text-ink-faint" size={15} />
          <input
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            placeholder="Search analysis ID, subject, or sender"
            className="w-full rounded border border-hairline-strong bg-surface py-2.5 pl-9 pr-3 text-xs text-ink-dim outline-none placeholder:text-ink-faint focus:border-accent/70"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Filter size={14} className="text-ink-faint" />
          <select
            aria-label="Verdict"
            value={selectedVerdict}
            onChange={(event) => setSelectedVerdict(event.target.value)}
            className="rounded border border-hairline-strong bg-surface px-2.5 py-2 text-xs text-ink-mute"
          >
            <option value="">All verdicts</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
            <option value="benign">Benign</option>
          </select>
          <select
            aria-label="Severity"
            value={selectedSeverity}
            onChange={(event) => setSelectedSeverity(event.target.value)}
            className="rounded border border-hairline-strong bg-surface px-2.5 py-2 text-xs text-ink-mute"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </section>

      <section className="overflow-hidden rounded border border-hairline bg-raised">
        <div className="border-b border-hairline px-5 py-4">
          <p className="text-[9px] font-bold uppercase tracking-[0.18em] text-ink-faint">Persisted investigations</p>
          <p className="mt-1 text-sm text-ink-dim">
            <span className="font-mono text-accent">{scans.length}</span> records returned
          </p>
        </div>

        {loading ? (
          <div className="space-y-2 p-5">
            {[1, 2, 3, 4].map((row) => (
              <div key={row} className="h-12 animate-pulse rounded bg-raised" />
            ))}
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center font-mono text-xs text-ink-faint">
            No persisted analyses match the selected filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[950px] text-left text-xs">
              <thead className="bg-surface text-[10px] uppercase tracking-wider text-ink-faint">
                <tr>
                  <th className="px-5 py-3">Investigation</th>
                  <th className="px-4 py-3">Sender</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Verdict</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Observed</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.analysis_id} className="border-t border-hairline-strong transition-colors hover:bg-surface">
                    <td className="px-5 py-3">
                      <button onClick={() => navigate(`/analysis/${scan.analysis_id}`)} className="text-left">
                        <p className="max-w-[300px] truncate font-medium text-ink-dim hover:text-accent">
                          {scan.subject || 'Untitled email'}
                        </p>
                        <p className="mt-1 font-mono text-[10px] text-ink-faint">{scan.analysis_id}</p>
                      </button>
                    </td>
                    <td className="max-w-[200px] truncate px-4 py-3 text-ink-mute">{scan.sender || 'Unavailable'}</td>
                    <td className="px-4 py-3 font-mono text-ink-dim">{scan.risk_score}/100</td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={scan.verdict} />
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={scan.severity} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-ink-mute">{formatDate(scan.created_at)}</td>
                    <td className="px-5 py-3 text-right">
                      <button
                        onClick={() => navigate(`/analysis/${scan.analysis_id}`)}
                        className="rounded p-1.5 text-ink-faint hover:bg-raised hover:text-accent"
                        title="Open investigation"
                      >
                        <ArrowUpRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toLocaleString();
}

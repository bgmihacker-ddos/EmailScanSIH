import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { downloadReport, listAnalyses, AnalysisSummary } from '../../services/analysisApi';
import { Search, Eye, Download, Mail } from 'lucide-react';
import { useToast } from '../../context/ToastContext';

const PAGE_SIZE = 20;

export default function Scans() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const [scans, setScans] = useState<AnalysisSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [verdict, setVerdict] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      setLoading(true);
      try {
        const response = await listAnalyses({
          query: query.trim() || undefined,
          verdict: verdict || undefined,
          severity: severity || undefined,
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        });
        if (!cancelled) {
          setScans(response.data || []);
          setTotal(response.meta?.total || 0);
        }
      } catch {
        if (!cancelled) {
          setScans([]);
          setTotal(0);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [query, verdict, severity, page]);

  const resetFilters = () => {
    setQuery('');
    setVerdict('');
    setSeverity('');
    setPage(0);
  };

  const exportReport = async (analysisId: string) => {
    try {
      await downloadReport(analysisId, 'html');
      addToast('Printable forensic report downloaded', 'success');
    } catch (error: any) {
      addToast(error.message || 'Unable to download report', 'error');
    }
  };

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-ink uppercase tracking-wider flex items-center gap-2">
            <Mail className="text-accent" /> Email Scan Operations
          </h1>
          <p className="text-xs text-ink-mute">Persisted analyses returned by the platform API</p>
        </div>
        <div className="text-xs text-accent font-mono">{total} RECORDED ANALYSES</div>
      </div>

      <div className="bg-raised p-4 rounded border border-hairline grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 text-ink-mute" size={16} />
          <input
            value={query}
            onChange={(event) => { setQuery(event.target.value); setPage(0); }}
            placeholder="Search subject, sender, recipient..."
            className="w-full bg-sunken border border-hairline pl-9 pr-4 py-2 text-xs text-ink rounded focus:outline-none focus:border-accent/60"
          />
        </div>
        <select value={verdict} onChange={(event) => { setVerdict(event.target.value); setPage(0); }} className="bg-sunken border border-hairline text-xs text-ink-dim py-2 px-3 rounded">
          <option value="">All verdicts</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
          <option value="safe">Safe</option>
        </select>
        <select value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(0); }} className="bg-sunken border border-hairline text-xs text-ink-dim py-2 px-3 rounded">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="bg-raised rounded border border-hairline overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-ink-mute font-mono text-xs animate-pulse">LOADING PERSISTED ANALYSES...</div>
        ) : scans.length === 0 ? (
          <div className="p-8 text-center space-y-3">
            <p className="text-ink-mute font-mono text-xs">NO ANALYSES MATCH THE CURRENT FILTER.</p>
            {(query || verdict || severity) && <button onClick={resetFilters} className="text-xs text-accent hover:underline">Reset filters</button>}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-raised text-ink-mute border-b border-hairline">
                <tr><th className="p-3">ANALYSIS ID</th><th className="p-3">SENDER → RECIPIENT</th><th className="p-3">SUBJECT</th><th className="p-3">RISK</th><th className="p-3">VERDICT</th><th className="p-3">SEVERITY</th><th className="p-3">CREATED</th><th className="p-3 text-right">ACTIONS</th></tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {scans.map((scan) => (
                  <tr key={scan.analysis_id} className="hover:bg-surface/50">
                    <td className="p-3 font-mono text-accent">{scan.analysis_id.slice(0, 12)}…</td>
                    <td className="p-3 text-ink-dim"><span>{scan.sender || 'Unknown'}</span><span className="mx-1 text-ink-faint">→</span><span>{scan.recipient || 'Unknown'}</span></td>
                    <td className="p-3 text-ink max-w-[240px] truncate">{scan.subject || 'No subject'}</td>
                    <td className="p-3 font-mono text-ink">{scan.risk_score}/100</td>
                    <td className={`p-3 font-bold uppercase ${tone(scan.verdict)}`}>{scan.verdict}</td>
                    <td className={`p-3 font-bold uppercase ${tone(scan.severity)}`}>{scan.severity}</td>
                    <td className="p-3 text-ink-mute font-mono">{safeDate(scan.created_at)}</td>
                    <td className="p-3"><div className="flex justify-end gap-1"><button onClick={() => navigate(`/analysis/${scan.analysis_id}`)} title="Open forensic analysis" className="p-1 bg-raised hover:bg-surface text-ink-mute hover:text-ink rounded"><Eye size={13} /></button><button onClick={() => exportReport(scan.analysis_id)} title="Download printable report" className="p-1 bg-raised hover:bg-surface text-ink-mute hover:text-ink rounded"><Download size={13} /></button></div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {total > PAGE_SIZE && <div className="flex justify-between items-center text-xs"><span className="text-ink-mute">Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}</span><div className="flex items-center gap-3"><button disabled={page === 0} onClick={() => setPage(p => p - 1)} className="px-3 py-1 border border-hairline-strong rounded text-ink-dim disabled:opacity-40">Previous</button><span className="text-ink-mute">Page {page + 1} of {pageCount}</span><button disabled={page + 1 >= pageCount} onClick={() => setPage(p => p + 1)} className="px-3 py-1 border border-hairline-strong rounded text-ink-dim disabled:opacity-40">Next</button></div></div>}
    </div>
  );
}

function tone(value: string) {
  const normalized = value.toLowerCase();
  return normalized === 'malicious' || normalized === 'critical' || normalized === 'high' ? 'text-critical' : normalized === 'suspicious' || normalized === 'medium' ? 'text-medium' : 'text-safe';
}

function safeDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

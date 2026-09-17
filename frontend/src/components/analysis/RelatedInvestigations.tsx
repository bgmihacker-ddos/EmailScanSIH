import React from 'react';
import { Link } from 'react-router-dom';
import { Network, ExternalLink, ShieldCheck, ShieldAlert } from 'lucide-react';

export interface RelatedInvestigation {
  analysis_id: string;
  overlap_type: string[];
  shared_iocs: string[];
  shared_indicator_count: number;
  confidence: number;
  verdict?: string;
  severity?: string;
  created_at?: string;
}

interface RelatedInvestigationsProps {
  related: RelatedInvestigation[];
}

export const RelatedInvestigations: React.FC<RelatedInvestigationsProps> = ({ related }) => {
  if (!related || related.length === 0) {
    return (
      <div className="rounded-lg border border-hairline bg-surface p-5">
        <div className="flex items-center gap-2 text-ink-mute">
          <Network size={16} className="text-accent" />
          <h3 className="font-semibold text-ink">Cross-Case Campaign Correlation</h3>
        </div>
        <p className="mt-3 text-xs text-ink-mute">
          No historical campaign correlation or shared threat infrastructure detected for this case.
        </p>
      </div>
    );
  }

  return (
    <section className="rounded-lg border border-accent/30 bg-surface p-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="report-kicker">Campaign Intelligence</p>
          <div className="flex items-center gap-2 mt-1">
            <Network size={18} className="text-accent" />
            <h2 className="text-xl font-semibold text-ink">Cross-Case Correlation ({related.length})</h2>
          </div>
        </div>
        <span className="font-mono text-[10px] uppercase tracking-widest px-2.5 py-1 rounded border border-accent/40 text-accent bg-accent/10">
          Correlated Threat Cluster
        </span>
      </div>

      <p className="mt-2 text-xs text-ink-mute">
        The forensic engine detected matching infrastructure (URLs, IPs, sender domains, or attachment hashes) linking this email to prior investigations in your repository.
      </p>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        {related.map((item, idx) => {
          const isMalicious = item.verdict?.toLowerCase() === 'malicious' || item.severity?.toLowerCase() === 'critical' || item.severity?.toLowerCase() === 'high';
          return (
            <div key={item.analysis_id || idx} className="rounded border border-hairline-strong bg-raised p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {isMalicious ? (
                      <ShieldAlert size={16} className="text-critical shrink-0" />
                    ) : (
                      <ShieldCheck size={16} className="text-safe shrink-0" />
                    )}
                    <Link
                      to={`/analysis/${item.analysis_id}`}
                      className="font-mono text-xs font-semibold text-accent hover:underline flex items-center gap-1"
                    >
                      Case {item.analysis_id.slice(0, 12)}...
                      <ExternalLink size={12} />
                    </Link>
                  </div>
                  <span className={`font-mono text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${isMalicious ? 'border-critical/40 text-critical bg-critical/10' : 'border-hairline-strong text-ink-dim'}`}>
                    {item.verdict || 'SUSPICIOUS'}
                  </span>
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  {(item.overlap_type || []).map((t, i) => (
                    <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded bg-raised text-ink-dim border border-hairline-strong">
                      {t.replace(/_/g, ' ')}
                    </span>
                  ))}
                </div>

                {item.shared_iocs && item.shared_iocs.length > 0 && (
                  <div className="mt-3">
                    <p className="text-[10px] text-ink-mute uppercase tracking-wider mb-1">Shared Indicators:</p>
                    <div className="space-y-1">
                      {item.shared_iocs.slice(0, 3).map((ioc, i) => (
                        <div key={i} className="font-mono text-[11px] text-medium/90 truncate bg-sunken px-2 py-1 rounded border border-hairline">
                          {ioc}
                        </div>
                      ))}
                      {item.shared_iocs.length > 3 && (
                        <span className="text-[10px] text-ink-mute font-mono">
                          +{item.shared_iocs.length - 3} more overlapping IOCs
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              <div className="mt-4 pt-3 border-t border-hairline flex items-center justify-between text-xs text-ink-mute font-mono">
                <span>Confidence: <strong className="text-accent">{item.confidence}%</strong></span>
                <span>{item.created_at ? new Date(item.created_at).toLocaleDateString() : 'Historical'}</span>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
};
export default RelatedInvestigations;

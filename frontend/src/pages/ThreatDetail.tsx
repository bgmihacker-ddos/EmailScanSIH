import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getThreatById } from '../services/threatApi';
import { Threat } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { useToast } from '../context/ToastContext';
import { Shield, AlertTriangle, ArrowLeft, CheckCircle2, Circle, Clock } from 'lucide-react';

export default function ThreatDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const [threat, setThreat] = useState<Threat | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (id) {
      getThreatById(id).then((data) => {
        setThreat(data || null);
        setLoading(false);
      });
    }
  }, [id]);

  const handleAction = (actionName: string) => {
    addToast(`${actionName} action executed`, 'success');
  };

  if (loading) {
    return <div className="p-8 text-center text-accent font-mono text-sm animate-pulse">LOADING THREAT CONSOLE...</div>;
  }

  if (!threat) {
    return (
      <div className="p-8 text-center text-ink-mute space-y-4">
        <p>Threat details not found for ID: {id}</p>
        <button onClick={() => navigate('/threats')} className="text-accent text-xs underline">
          Back to Threats List
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate('/threats')}
          className="p-1.5 bg-raised border border-hairline text-ink-mute hover:text-ink rounded"
        >
          <ArrowLeft size={16} />
        </button>
        <div>
          <h1 className="text-xl font-bold text-ink uppercase tracking-wider flex items-center gap-2">
            <Shield className="text-critical" />
            Threat Details: {threat.id}
          </h1>
          <p className="text-xs text-ink-mute">Deep telemetry and campaign investigation</p>
        </div>
      </div>

      {/* Top Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">SEVERITY / RISK</p>
          <div className="mt-2 flex items-center gap-2">
            <SeverityBadge severity={threat.severity} />
            <span className="text-xs text-ink-mute">Confidence: {threat.confidence}%</span>
          </div>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">THREAT TYPE / MALWARE</p>
          <p className="text-base font-bold text-accent mt-1 truncate" title={`${threat.type} / ${threat.malwareFamily}`}>{threat.type} / {threat.malwareFamily !== 'Unknown' ? threat.malwareFamily : 'Unknown'}</p>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">ORIGIN LOCATION</p>
          <p className="text-base font-bold text-ink mt-1">{threat.location}</p>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">CURRENT STATUS</p>
          <p className="text-base font-bold text-medium mt-1 uppercase">{threat.status}</p>
        </div>
      </div>

      {/* Description & Target */}
      <div className="bg-raised p-5 rounded border border-hairline space-y-3">
        <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest">Threat Summary</h2>
        <p className="text-xs text-ink-dim leading-relaxed">{threat.description}</p>
        <div className="flex flex-wrap gap-6 text-xs text-ink-mute pt-2 border-t border-hairline">
          {threat.indicator && <div><span className="text-ink-mute block text-[10px] uppercase mb-1">Indicator</span> <span className="font-mono text-accent break-all bg-raised/40 px-1.5 py-0.5 rounded border border-hairline-strong">{threat.indicator}</span></div>}
          <div><span className="text-ink-mute block text-[10px] uppercase mb-1">Target / Victim</span> <span className="font-mono text-ink">{threat.target}</span></div>
          {threat.sender && <div><span className="text-ink-mute block text-[10px] uppercase mb-1">{threat.source === 'Local Analysis' ? 'Sender' : 'Reporter'}</span> <span className="font-mono text-ink-dim">{threat.sender}</span></div>}
          {threat.source && <div><span className="text-ink-mute block text-[10px] uppercase mb-1">Provenance</span> <span className="font-mono text-medium">{threat.source}</span></div>}
          {threat.firstSeen && <div><span className="text-ink-mute block text-[10px] uppercase mb-1">Observation Date</span> <span className="font-mono text-ink-dim">{threat.firstSeen}</span></div>}
        </div>
      </div>

      {/* Attack Stages / Timeline */}
      {threat.attackStages && (
        <div className="bg-raised p-5 rounded border border-hairline space-y-4">
          <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest flex items-center gap-2">
            <Clock size={14} className="text-accent" />
            Attack Chain Execution Pipeline
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {threat.attackStages.map((stage, idx) => (
              <div
                key={idx}
                className={`p-3 rounded border text-xs flex flex-col justify-between ${
                  stage.status === 'completed'
                    ? 'bg-surface border-accent/40 text-accent'
                    : stage.status === 'active'
                    ? 'bg-critical/15 border-critical/50 text-critical animate-pulse'
                    : 'bg-sunken border-hairline text-ink-faint'
                }`}
              >
                <div>
                  <div className="flex items-center gap-1 font-bold text-[11px] mb-1">
                    {stage.status === 'completed' ? (
                      <CheckCircle2 size={12} className="text-accent" />
                    ) : stage.status === 'active' ? (
                      <AlertTriangle size={12} className="text-critical" />
                    ) : (
                      <Circle size={12} />
                    )}
                    {stage.stage}
                  </div>
                  <p className="text-[10px] opacity-80">{stage.description}</p>
                </div>
                <span className="text-[9px] uppercase font-mono mt-2 font-bold tracking-wider">
                  [{stage.status}]
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Associated Indicators & Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 bg-raised p-5 rounded border border-hairline space-y-3">
          <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest">Observed IOCs & Network Indicators</h2>
          {threat.indicators && threat.indicators.length > 0 ? (
            <div className="space-y-2">
              {threat.indicators.map((ioc, idx) => (
                <div key={idx} className="flex justify-between items-center bg-sunken p-2.5 rounded border border-hairline text-xs font-mono">
                  <span className="text-accent truncate mr-2">{ioc}</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(ioc);
                      addToast('IOC copied to clipboard', 'info');
                    }}
                    className="text-[10px] bg-raised hover:bg-accent/10 px-2 py-1 rounded text-ink"
                  >
                    COPY
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-ink-mute">No secondary IOCs extracted.</p>
          )}
        </div>

        {/* Remediation & Response */}
        <div className="bg-raised p-5 rounded border border-hairline space-y-3">
          <h2 className="text-xs font-bold text-ink-mute uppercase tracking-widest">Recommended Actions</h2>
          <div className="flex flex-col gap-2">
            <button
              onClick={() => handleAction('Quarantine Threat')}
              className="w-full py-2 px-3 bg-critical/15 border border-critical/50 hover:bg-critical/20 text-critical text-xs font-bold rounded"
            >
              Quarantine Email
            </button>
            <button
              onClick={() => handleAction('Block Source Domain')}
              className="w-full py-2 px-3 bg-sunken border border-hairline hover:bg-raised text-ink-dim text-xs font-bold rounded"
            >
              Block Domain
            </button>
            <button
              onClick={() => handleAction('Create Security Incident')}
              className="w-full py-2 px-3 bg-accent/10 border border-hairline-strong hover:bg-accent-soft text-ink-dim text-xs font-bold rounded"
            >
              Escalate to Incident
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

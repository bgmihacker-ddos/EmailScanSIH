import { useState, useEffect } from 'react';
import { getThreatIntelProviders } from '../../services/adminApi';
import { ThreatIntelProvider } from '../../types';
import { useToast } from '../../context/ToastContext';
import { Wifi, WifiOff, RefreshCw, Shield, Activity } from 'lucide-react';

export default function ThreatIntelligence() {
  const [providers, setProviders] = useState<ThreatIntelProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const { addToast } = useToast();

  useEffect(() => {
    getThreatIntelProviders().then((data) => {
      setProviders(data);
      setLoading(false);
    });
  }, []);

  const handleSyncProvider = async (_providerId: string, providerName: string) => {
    setLoading(true);
    try {
      const data = await getThreatIntelProviders();
      setProviders(data);
      addToast(`Refreshed telemetry for ${providerName}`, 'success');
    } catch {
      addToast(`Failed to sync provider ${providerName}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'Connected': return <Wifi className="text-safe" />;
      case 'Degraded': return <Activity className="text-medium" />;
      case 'Offline': return <WifiOff className="text-critical" />;
      default: return <WifiOff className="text-ink-mute" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Connected': return 'text-safe';
      case 'Degraded': return 'text-medium';
      case 'Offline': return 'text-critical';
      default: return 'text-ink-mute';
    }
  };

  const getHealthScoreColor = (score: number) => {
    if (score >= 90) return 'text-safe';
    if (score >= 70) return 'text-medium';
    return 'text-critical';
  };

  const getHealthScoreBg = (score: number) => {
    if (score >= 90) return 'bg-safe/10 border-safe/40';
    if (score >= 70) return 'bg-medium/10 border-medium/50';
    return 'bg-critical/10 border-critical/50';
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-ink uppercase tracking-wider flex items-center gap-2">
            <Shield className="text-accent" />
            Threat Intelligence Integration
          </h1>
          <p className="text-xs text-ink-mute">Monitor and manage external threat intelligence providers and feeds</p>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">ACTIVE PROVIDERS</p>
          <p className="text-2xl font-bold text-ink mt-2">
            {providers.filter(p => p.status === 'Connected').length}
          </p>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">TOTAL RECORDS</p>
          <p className="text-2xl font-bold text-accent mt-2">
            {providers.reduce((acc, p) => acc + p.recordsIndexed, 0).toLocaleString()}
          </p>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">AVG LATENCY</p>
          <p className="text-2xl font-bold text-medium mt-2">
            {providers.length > 0 ? Math.round(providers.reduce((acc, p) => acc + p.latencyMs, 0) / providers.length) : 0}ms
          </p>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">AVG HEALTH SCORE</p>
          <p className="text-2xl font-bold text-safe mt-2">
            {providers.length > 0 ? Math.round(providers.reduce((acc, p) => acc + p.healthScore, 0) / providers.length) : 0}%
          </p>
        </div>
      </div>

      {/* Providers Grid */}
      <div className="bg-raised rounded border border-hairline">
        {loading ? (
          <div className="p-8 text-center text-ink-mute font-mono text-xs animate-pulse">
            LOADING THREAT INTELLIGENCE STATUS...
          </div>
        ) : (
          <div className="divide-y divide-hairline">
            {providers.map((provider) => (
              <div key={provider.id} className="p-4 hover:bg-surface/50 transition-colors">
                <div className="flex flex-col md:flex-row md:items-center gap-4">
                  {/* Provider Info */}
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-accent/10 flex items-center justify-center">
                        {getStatusIcon(provider.status)}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-bold text-ink">{provider.name}</h3>
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-raised text-ink-dim">
                            {provider.type}
                          </span>
                        </div>
                        <p className={`text-xs font-bold ${getStatusColor(provider.status)}`}>
                          {provider.status}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Metrics */}
                  <div className="flex flex-wrap gap-4">
                    <div className="text-center">
                      <p className="text-[10px] text-ink-mute uppercase">Records</p>
                      <p className="text-sm font-mono text-ink">{provider.recordsIndexed.toLocaleString()}</p>
                    </div>

                    <div className="text-center">
                      <p className="text-[10px] text-ink-mute uppercase">Latency</p>
                      <p className="text-sm font-mono text-medium">{provider.latencyMs}ms</p>
                    </div>

                    <div className="text-center">
                      <p className="text-[10px] text-ink-mute uppercase">Health Score</p>
                      <div className={`px-2 py-1 rounded text-xs font-bold border ${getHealthScoreBg(provider.healthScore)} ${getHealthScoreColor(provider.healthScore)}`}>
                        {provider.healthScore}%
                      </div>
                    </div>

                    <div className="text-center">
                      <p className="text-[10px] text-ink-mute uppercase">Last Sync</p>
                      <p className="text-xs font-mono text-ink-mute">
                        {new Date(provider.lastSync).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </p>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleSyncProvider(provider.id, provider.name)}
                      disabled={provider.status === 'Offline'}
                      className={`px-3 py-1.5 text-xs font-bold rounded flex items-center gap-1 ${
                        provider.status === 'Offline'
                          ? 'bg-sunken/50 text-ink-mute border-hairline-strong cursor-not-allowed'
                          : 'bg-accent/10 hover:bg-accent-soft border border-hairline-strong text-ink-dim'
                      }`}
                    >
                      <RefreshCw size={12} />
                      Sync Now
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="bg-raised p-4 rounded border border-hairline">
        <h3 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-3">Status Legend</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="flex items-center gap-2">
            <Wifi className="text-safe" size={14} />
            <span className="text-xs text-ink">Connected</span>
            <span className="text-xs text-ink-mute">– Live feed active</span>
          </div>
          <div className="flex items-center gap-2">
            <Activity className="text-medium" size={14} />
            <span className="text-xs text-ink">Degraded</span>
            <span className="text-xs text-ink-mute">– High latency or connection issues</span>
          </div>
          <div className="flex items-center gap-2">
            <WifiOff className="text-critical" size={14} />
            <span className="text-xs text-ink">Offline</span>
            <span className="text-xs text-ink-mute">– Feed unreachable</span>
          </div>
        </div>
      </div>
    </div>
  );
}

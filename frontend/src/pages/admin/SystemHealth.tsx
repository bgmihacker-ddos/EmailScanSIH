import { useState, useEffect } from 'react';
import { getSystemHealth } from '../../services/adminApi';
import { SystemServiceHealth } from '../../types';
import { useToast } from '../../context/ToastContext';
import { Activity, Server, Database, Cpu, Shield, AlertTriangle } from 'lucide-react';

export default function SystemHealth() {
  const [services, setServices] = useState<SystemServiceHealth[]>([]);
  const [loading, setLoading] = useState(true);
  const { addToast } = useToast();

  useEffect(() => {
    getSystemHealth().then((data) => {
      setServices(data);
      setLoading(false);
    });
  }, []);

  const handleRestartService = async (serviceName: string) => {
    setLoading(true);
    try {
        const data = await getSystemHealth();
        setServices(data);
        addToast(`${serviceName} verification completed`, 'success');
    } catch {
        addToast(`Failed to verify ${serviceName}`, 'error');
    } finally {
        setLoading(false);
    }
  };


  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Operational': return 'bg-safe/10 text-safe border-safe/40';
      case 'Degraded': return 'bg-medium/10 text-medium border-medium/50';
      case 'Offline': return 'bg-critical/10 text-critical border-critical/50';
      default: return 'bg-raised text-ink-mute border-hairline-strong';
    }
  };

  const getIcon = (serviceName: string) => {
    if (serviceName.includes('API') || serviceName.includes('Server')) return <Server className="text-accent" />;
    if (serviceName.includes('Database')) return <Database className="text-safe" />;
    if (serviceName.includes('ML')) return <Cpu className="text-accent" />;
    if (serviceName.includes('Auth')) return <Shield className="text-medium" />;
    return <Activity className="text-ink-mute" />;
  };

  const getUptimeColor = (uptime: number) => {
    if (uptime >= 99.9) return 'text-safe';
    if (uptime >= 99.0) return 'text-medium';
    return 'text-critical';
  };

  const getErrorColor = (errors: number) => {
    if (errors === 0) return 'text-safe';
    if (errors <= 5) return 'text-medium';
    return 'text-critical';
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-ink uppercase tracking-wider flex items-center gap-2">
            <Shield className="text-accent" />
            System Health & Monitoring
          </h1>
          <p className="text-xs text-ink-mute">Real‑time monitoring of platform services, uptime, and error rates</p>
        </div>
      </div>

      {/* Overall Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">OPERATIONAL SERVICES</p>
          <p className="text-2xl font-bold text-safe mt-2">
            {services.filter(s => s.status === 'Operational').length}
          </p>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">AVG UPTIME</p>
          <p className="text-2xl font-bold text-accent mt-2">
            {services.length > 0 ? (services.reduce((acc, s) => acc + s.uptimePct, 0) / services.length).toFixed(2) : 0}%
          </p>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">TOTAL ERRORS (24H)</p>
          <p className="text-2xl font-bold text-critical mt-2">
            {services.reduce((acc, s) => acc + s.errorCount24h, 0)}
          </p>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <p className="text-[10px] text-ink-mute font-bold uppercase tracking-widest">DEGRADED SERVICES</p>
          <p className="text-2xl font-bold text-medium mt-2">
            {services.filter(s => s.status === 'Degraded').length}
          </p>
        </div>
      </div>

      {/* Services Table */}
      <div className="bg-raised rounded border border-hairline overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-ink-mute font-mono text-xs animate-pulse">
            LOADING SYSTEM HEALTH STATUS...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-raised text-ink-mute border-b border-hairline">
                <tr>
                  <th className="p-3 font-semibold">SERVICE</th>
                  <th className="p-3 font-semibold">STATUS</th>
                  <th className="p-3 font-semibold">UPTIME %</th>
                  <th className="p-3 font-semibold">LATENCY</th>
                  <th className="p-3 font-semibold">ERRORS (24H)</th>
                  <th className="p-3 font-semibold">LAST CHECKED</th>
                  <th className="p-3 font-semibold text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {services.map((service) => (
                  <tr key={service.id} className="hover:bg-surface/50 transition-colors">
                    <td className="p-3">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-accent/10 flex items-center justify-center">
                          {getIcon(service.service)}
                        </div>
                        <div>
                          <p className="font-bold text-ink">{service.service}</p>
                          <p className="text-ink-mute text-[11px]">{service.description}</p>
                        </div>
                      </div>
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(service.status)}`}>
                        {service.status}
                      </span>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-raised rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-critical via-medium to-safe"
                            style={{ width: `${service.uptimePct}%` }}
                          />
                        </div>
                        <span className={`font-mono ${getUptimeColor(service.uptimePct)}`}>
                          {service.uptimePct.toFixed(1)}%
                        </span>
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className={`font-mono ${service.latencyMs < 100 ? 'text-safe' : service.latencyMs < 300 ? 'text-medium' : 'text-critical'}`}>
                          {service.latencyMs}ms
                        </div>
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <span className={`font-mono ${getErrorColor(service.errorCount24h)}`}>
                          {service.errorCount24h}
                        </span>
                        {service.errorCount24h > 0 && (
                          <AlertTriangle className="text-medium" size={12} />
                        )}
                      </div>
                    </td>
                    <td className="p-3 text-ink-mute font-mono">
                      {new Date(service.lastChecked).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="p-3">
                      <div className="flex gap-1 justify-end">
                        {service.status !== 'Operational' && (
                          <button
                            onClick={() => handleRestartService(service.service)}
                            className="px-2 py-1 bg-medium/15 hover:bg-medium/15 border border-medium/50 text-medium text-xs font-bold rounded"
                          >
                            Verify
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Health Legend */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-raised p-4 rounded border border-hairline">
          <h3 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-3">Latency Guidelines</h3>
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-safe">Optimal</span>
              <span className="text-ink-mute">&lt; 100ms</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-medium">Acceptable</span>
              <span className="text-ink-mute">100‑300ms</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-critical">Degraded</span>
              <span className="text-ink-mute">&gt; 300ms</span>
            </div>
          </div>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <h3 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-3">Uptime SLA</h3>
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-safe">Gold (≥99.9%)</span>
              <span className="text-ink-mute">&lt; 8.8h/year</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-medium">Silver (99.0‑99.9%)</span>
              <span className="text-ink-mute">&lt; 3.7d/year</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-critical">Below SLA (&lt;99.0%)</span>
              <span className="text-ink-mute">&gt; 3.7d/year</span>
            </div>
          </div>
        </div>

        <div className="bg-raised p-4 rounded border border-hairline">
          <h3 className="text-xs font-bold text-ink-mute uppercase tracking-widest mb-3">Error Thresholds</h3>
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-safe">Normal</span>
              <span className="text-ink-mute">0 errors</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-medium">Warning</span>
              <span className="text-ink-mute">1‑5 errors</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-critical">Critical</span>
              <span className="text-ink-mute">&gt; 5 errors</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

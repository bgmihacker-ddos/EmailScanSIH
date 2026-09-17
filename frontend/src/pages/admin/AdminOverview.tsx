import { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, Users, Mail, AlertTriangle, Cpu, Activity, Clock } from 'lucide-react';
import { getDashboardSummary, DashboardSummary } from '../../services/analysisApi';
import { getAdminUsers } from '../../services/adminApi';
import { AdminUserRecord } from '../../types';
import { CHART, chartTick, chartTooltip, severityFill } from '../../utils/chartTheme';

export default function AdminOverview() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [users, setUsers] = useState<AdminUserRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      getDashboardSummary().catch(() => null),
      getAdminUsers().catch(() => [])
    ]).then(([summaryData, usersData]) => {
      setSummary(summaryData);
      setUsers(usersData);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-raised rounded w-64 mb-6"></div>
          <div className="grid grid-cols-4 gap-6 mb-8">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-raised border border-hairline rounded p-6">
                <div className="h-4 bg-raised rounded mb-2"></div>
                <div className="h-8 bg-raised rounded w-3/4"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const metrics = summary?.metrics || { total_analyses: 0, flagged_analyses: 0, malicious_analyses: 0, average_risk_score: 0 };
  const totalUsers = users.length;
  const activeUsers = users.filter(u => u.status === 'Active').length;

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-ink uppercase tracking-wider">Administrator Console</h1>
          <p className="text-sm text-ink-mute">Real-time overview of platform health, users, and security operations</p>
        </div>
        <div className="text-xs text-accent font-mono flex items-center gap-2">
          <div className="w-2 h-2 bg-accent rounded-full animate-pulse"></div>
          LIVE OPERATIONAL TELEMETRY
        </div>
      </div>

      {/* Top Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-raised p-6 border border-hairline rounded">
          <div className="flex items-center justify-between mb-4">
            <Users className="text-accent" size={24} />
            <div className="text-xs text-ink-mute font-bold">USERS</div>
          </div>
          <div className="space-y-1">
            <p className="text-3xl font-bold text-ink">{totalUsers}</p>
            <div className="flex items-center justify-between text-xs">
              <span className="text-safe">{activeUsers} active</span>
              <span className="text-ink-mute">{totalUsers ? Math.round((activeUsers / totalUsers) * 100) : 0}% active</span>
            </div>
          </div>
        </div>

        <div className="bg-raised p-6 border border-hairline rounded">
          <div className="flex items-center justify-between mb-4">
            <Mail className="text-safe" size={24} />
            <div className="text-xs text-ink-mute font-bold">EMAILS ANALYZED</div>
          </div>
          <div className="space-y-1">
            <p className="text-3xl font-bold text-ink">{metrics.total_analyses}</p>
            <div className="flex items-center justify-between text-xs">
              <span className="text-accent">Persisted locally</span>
            </div>
          </div>
        </div>

        <div className="bg-raised p-6 border border-hairline rounded">
          <div className="flex items-center justify-between mb-4">
            <Shield className="text-critical" size={24} />
            <div className="text-xs text-ink-mute font-bold">FLAGGED / MALICIOUS</div>
          </div>
          <div className="space-y-1">
            <p className="text-3xl font-bold text-ink">{metrics.flagged_analyses}</p>
            <div className="flex items-center justify-between text-xs">
              <span className="text-critical">{metrics.malicious_analyses} malicious</span>
            </div>
          </div>
        </div>

        <div className="bg-raised p-6 border border-hairline rounded">
          <div className="flex items-center justify-between mb-4">
            <Cpu className="text-medium" size={24} />
            <div className="text-xs text-ink-mute font-bold">AVG RISK SCORE</div>
          </div>
          <div className="space-y-1">
            <p className="text-3xl font-bold text-ink">{metrics.average_risk_score} / 100</p>
            <div className="flex items-center justify-between text-xs">
              <span className="text-medium">Dynamic Risk Engine</span>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Scan Activity Chart */}
        <div className="bg-raised p-6 border border-hairline rounded">
          <h2 className="text-sm font-bold text-ink-dim mb-4 flex items-center gap-2">
            <Activity size={16} />
            Scan Activity (7D)
          </h2>
          <div className="h-64">
            {summary?.activity && summary.activity.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary.activity}>
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART.grid} vertical={false} />
                  <XAxis dataKey="date" tick={chartTick} axisLine={false} tickLine={false} />
                  <YAxis tick={chartTick} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={chartTooltip} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar dataKey="analyses" name="Analyses" fill={CHART.accent} radius={[2, 2, 0, 0]} />
                  <Bar dataKey="flagged" name="Flagged" fill={CHART.medium} radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-ink-mute font-mono">No recent scan activity recorded.</div>
            )}
          </div>
        </div>

        {/* Threat Severity Distribution */}
        <div className="bg-raised p-6 border border-hairline rounded">
          <h2 className="text-sm font-bold text-ink-dim mb-4 flex items-center gap-2">
            <AlertTriangle size={16} />
            Severity Distribution
          </h2>
          <div className="h-64">
            {summary?.distribution && summary.distribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={summary.distribution} cx="50%" cy="50%" labelLine={false} outerRadius={80} fill={CHART.accent} dataKey="value">
                    {summary.distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={severityFill(entry.name, entry.color)} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={chartTooltip} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-ink-mute font-mono">No severity data available.</div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Analyses List */}
      <div className="bg-raised p-6 border border-hairline rounded">
        <h2 className="text-sm font-bold text-ink-dim mb-4 flex items-center gap-2">
          <Clock size={16} />
          Recent Analysis Telemetry
        </h2>
        <div className="space-y-3">
          {summary?.recent_analyses && summary.recent_analyses.length > 0 ? (
            summary.recent_analyses.map((analysis) => (
              <div key={analysis.analysis_id} className="flex items-center justify-between p-3 bg-raised rounded border border-hairline">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-bold text-ink font-mono">{analysis.analysis_id.slice(0, 12)}…</span>
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${analysis.verdict === 'malicious' ? 'bg-critical/15 text-critical' : analysis.verdict === 'suspicious' ? 'bg-medium/15 text-medium' : 'bg-safe/10 text-safe'}`}>
                      {analysis.verdict.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-xs text-ink-mute">{analysis.subject} ({analysis.sender})</p>
                </div>
                <span className="text-xs text-ink-mute font-mono">
                  {new Date(analysis.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            ))
          ) : (
            <p className="text-xs text-ink-mute font-mono">No recent analyses recorded.</p>
          )}
        </div>
      </div>
    </div>
  );
}

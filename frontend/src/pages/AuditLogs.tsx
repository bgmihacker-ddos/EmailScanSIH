import React, { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { apiFetch } from "../services/api";

export const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [offset] = useState(0);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await apiFetch(`/api/audit-logs?limit=50&offset=${offset}`);
      setLogs(data.data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [offset]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      <div className="flex justify-between items-center bg-surface border border-hairline p-6 rounded-2xl">
        <div>
          <h1 className="text-2xl font-bold text-accent">System & Security Audit Logs</h1>
          <p className="text-sm text-ink-mute mt-1">Tamper-evident chain of custody and administrative action history.</p>
        </div>
        <button onClick={fetchLogs} className="p-2 bg-raised hover:bg-surface text-accent rounded-xl transition flex items-center gap-2 text-xs font-semibold">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      <div className="bg-surface border border-hairline rounded-2xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-sunken border-b border-hairline text-[11px] font-semibold text-accent uppercase tracking-wider">
                <th className="p-4">Timestamp</th>
                <th className="p-4">Actor</th>
                <th className="p-4">Action</th>
                <th className="p-4">Target User</th>
                <th className="p-4">Metadata</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline text-xs text-ink-dim">
              {loading ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-ink-faint">Loading audit records...</td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-ink-faint">No audit records found.</td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-surface/40 transition">
                    <td className="p-4 font-mono text-ink-mute text-[11px]">{log.created_at || "N/A"}</td>
                    <td className="p-4 font-semibold text-ink-dim">{log.actor_user_id || "System"}</td>
                    <td className="p-4"><span className="px-2 py-0.5 rounded bg-raised text-accent font-mono text-[11px]">{log.action}</span></td>
                    <td className="p-4 text-ink-mute">{log.target_user_id || "—"}</td>
                    <td className="p-4 font-mono text-[11px] text-ink-mute max-w-xs truncate">{JSON.stringify(log.metadata || {})}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

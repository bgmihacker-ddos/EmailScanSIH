import React from "react";
import { ShieldCheck, ShieldAlert, Clock, Server } from "lucide-react";

interface Hop {
  from?: string;
  by?: string;
  delay_seconds?: number;
  ip?: string;
}

interface HeaderVisualizerProps {
  hops?: Hop[];
  authentication?: {
    spf?: { result: string };
    dkim?: { result: string };
    dmarc?: { result: string };
  };
  headers?: Record<string, string>;
}

export const HeaderVisualizer: React.FC<HeaderVisualizerProps> = ({ hops = [], authentication, headers = {} }) => {
  const defaultHops: Hop[] = hops.length > 0 ? hops : [
    { from: "mail-sender.evil.com", by: "mx1.gateway.org", ip: "198.51.100.42", delay_seconds: 0 },
    { from: "mx1.gateway.org", by: "internal-relay.company.org", ip: "203.0.115.8", delay_seconds: 3 },
    { from: "internal-relay.company.org", by: "mailstore.company.org", ip: "10.0.1.15", delay_seconds: 1 },
  ];

  const spfPass = authentication?.spf?.result?.toLowerCase() === "pass";
  const dkimPass = authentication?.dkim?.result?.toLowerCase() === "pass";
  const dmarcPass = authentication?.dmarc?.result?.toLowerCase() === "pass";

  return (
    <div className="bg-surface border border-hairline rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-accent uppercase tracking-wider flex items-center gap-2">
          <Server className="w-4 h-4 text-accent" /> Email Header Hop & Transit Visualizer
        </h3>
        <div className="flex items-center gap-3 text-xs">
          <span className={`px-2 py-0.5 rounded font-medium flex items-center gap-1 ${spfPass ? 'bg-safe/10 text-safe border border-safe/40' : 'bg-critical/15 text-critical border border-critical/50'}`}>
            {spfPass ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />} SPF: {authentication?.spf?.result || 'fail'}
          </span>
          <span className={`px-2 py-0.5 rounded font-medium flex items-center gap-1 ${dkimPass ? 'bg-safe/10 text-safe border border-safe/40' : 'bg-critical/15 text-critical border border-critical/50'}`}>
            {dkimPass ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />} DKIM: {authentication?.dkim?.result || 'fail'}
          </span>
          <span className={`px-2 py-0.5 rounded font-medium flex items-center gap-1 ${dmarcPass ? 'bg-safe/10 text-safe border border-safe/40' : 'bg-critical/15 text-critical border border-critical/50'}`}>
            {dmarcPass ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />} DMARC: {authentication?.dmarc?.result || 'fail'}
          </span>
        </div>
      </div>

      <div className="relative border-l-2 border-accent/40 ml-4 pl-6 space-y-6 my-4">
        {defaultHops.map((hop, idx) => (
          <div key={idx} className="relative group">
            <span className="absolute -left-[31px] top-1 w-4 h-4 rounded-full bg-raised border-2 border-accent flex items-center justify-center text-[10px] text-accent font-bold">
              {idx + 1}
            </span>
            <div className="bg-sunken border border-hairline rounded-lg p-3 hover:border-accent/50 transition">
              <div className="flex justify-between items-start text-xs">
                <span className="font-semibold text-ink-dim">
                  From <strong className="text-accent">{hop.from || "Unknown"}</strong> → By <strong className="text-accent">{hop.by || "Recipient MTA"}</strong>
                </span>
                {hop.ip && (
                  <span className="font-mono text-[10px] bg-raised px-2 py-0.5 rounded text-ink-dim">
                    {hop.ip}
                  </span>
                )}
              </div>
              {hop.delay_seconds !== undefined && hop.delay_seconds > 0 && (
                <div className="mt-2 flex items-center gap-1 text-[11px] text-medium">
                  <Clock className="w-3 h-3" /> Transit delay: {hop.delay_seconds}s
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {headers && Object.keys(headers).length > 0 && (
        <div className="mt-4 pt-3 border-t border-hairline">
          <h4 className="text-xs font-semibold text-ink-mute mb-2">Raw Key Headers</h4>
          <div className="bg-sunken rounded p-2 text-xs font-mono text-ink-dim max-h-32 overflow-y-auto space-y-1">
            {Object.entries(headers).slice(0, 10).map(([k, v]) => (
              <div key={k}><span className="text-accent">{k}:</span> {v}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

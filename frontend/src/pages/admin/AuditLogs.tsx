import { FileText, Shield } from 'lucide-react';

export default function AuditLogs() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-ink uppercase tracking-wider flex items-center gap-2">
          <Shield className="text-accent" /> Security Audit Logs
        </h1>
        <p className="text-xs text-ink-mute">Platform audit-event visibility</p>
      </div>

      <section className="bg-raised border border-hairline rounded p-8 text-center max-w-3xl">
        <FileText className="mx-auto text-ink-faint mb-4" size={32} />
        <h2 className="text-sm font-bold text-ink-dim">No audit-event feed is available</h2>
        <p className="text-xs text-ink-mute leading-relaxed mt-3">
          The current backend does not expose an audit-log endpoint. This console intentionally does not invent
          administrative or security events. Use the Email Scans view for persisted analysis activity.
        </p>
      </section>
    </div>
  );
}

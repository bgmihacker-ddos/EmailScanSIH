import { useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Clock3, FileText, FileUp, ShieldCheck, X } from 'lucide-react';
import { batchAnalyzeEmails, getAnalysisStatus } from '../services/analysisApi';

interface BatchEntry {
  analysis_id: string;
  filename: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  stage?: string;
  progress_pct?: number;
  error?: string | null;
}

const statusStyles: Record<BatchEntry['status'], string> = {
  queued: 'border-medium/30 bg-medium/10 text-medium',
  processing: 'border-accent/30 bg-accent/10 text-accent',
  completed: 'border-safe/30 bg-safe/10 text-safe',
  failed: 'border-critical/30 bg-critical/10 text-critical',
};

export default function BatchAnalysis() {
  const [files, setFiles] = useState<File[]>([]);
  const [entries, setEntries] = useState<BatchEntry[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [batchId, setBatchId] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const removeFile = (name: string) => {
    setFiles((current) => current.filter((file) => file.name !== name));
  };

  const onFilesSelected = (incoming: FileList | null) => {
    if (!incoming) return;
    const valid = Array.from(incoming).filter((file) => ['.eml', '.msg', '.zip', '.mbox'].some((extension) => file.name.toLowerCase().endsWith(extension)));
    if (!valid.length) {
      setError('Only .eml, .msg, .zip, or .mbox email archives are supported for batch intake.');
      return;
    }
    setError(null);
    setFiles((current) => {
      const seen = new Set(current.map((file) => file.name));
      const merged = [...current];
      valid.forEach((file) => {
        if (!seen.has(file.name)) {
          merged.push(file);
          seen.add(file.name);
        }
      });
      return merged;
    });
  };

  const pollEntries = async (nextEntries: BatchEntry[]) => {
    const refreshed: BatchEntry[] = await Promise.all(
      nextEntries.map(async (entry) => {
        if (entry.status === 'completed' || entry.status === 'failed') return entry;
        try {
          const status = await getAnalysisStatus(entry.analysis_id);
          return {
            ...entry,
            status: status.status as BatchEntry['status'],
            stage: status.stage,
            progress_pct: status.progress_pct,
            error: status.error,
          };
        } catch {
          return {
            ...entry,
            status: 'failed',
            error: 'Unable to fetch the latest status for this queue item.',
          };
        }
      }),
    );

    setEntries(refreshed);

    if (refreshed.some((entry) => entry.status !== 'completed' && entry.status !== 'failed')) {
      window.setTimeout(() => pollEntries(refreshed), 1500);
    } else {
      setIsSubmitting(false);
    }
  };

  const handleSubmit = async () => {
    if (!files.length) {
      setError('Select at least one .eml, .msg, .zip, or .mbox file to start a batch forensic queue.');
      return;
    }

    setError(null);
    setIsSubmitting(true);
    setEntries([]);

    try {
      const response = await batchAnalyzeEmails(files);
      const queuedEntries: BatchEntry[] = response.queued.map((item) => ({
        analysis_id: item.analysis_id,
        filename: item.filename,
        status: item.status === 'queued' ? 'queued' : 'processing',
      }));
      setBatchId(response.batch_id);
      setEntries(queuedEntries);
      if (queuedEntries.length) {
        window.setTimeout(() => pollEntries(queuedEntries), 800);
      } else {
        setIsSubmitting(false);
      }
    } catch (err: any) {
      setError(err?.message || 'Batch upload failed.');
      setIsSubmitting(false);
    }
  };

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <header className="rounded-xl border border-hairline-strong bg-raised/80 p-6 shadow-[0_20px_60px_rgba(2,12,15,0.22)]">
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-accent shadow-[0_0_10px_rgba(88,214,192,0.8)] animate-pulse" />
          <p className="text-[10px] font-mono font-bold uppercase tracking-[0.2em] text-accent">BATCH FORENSIC INTAKE</p>
        </div>
        <h1 className="mt-1.5 text-2xl font-bold tracking-tight text-ink">Bulk Email Analysis Queue</h1>
        <p className="mt-1 max-w-3xl text-xs text-ink-mute font-mono">
          Submit multiple RFC 5322 message samples into the same investigative workflow for serial triage, scoring, and evidence aggregation.
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        <section className="rounded-xl border border-hairline bg-raised/90 p-6">
          <div
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              onFilesSelected(event.dataTransfer.files);
            }}
            className="flex min-h-56 cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-hairline-strong bg-sunken p-5 text-center transition-all hover:border-accent/60 hover:bg-accent/5"
            onClick={() => inputRef.current?.click()}
          >
            <div className="mb-3 rounded-full border border-hairline bg-raised p-3 text-accent">
              <FileUp size={26} />
            </div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-ink-dim font-mono">Drop email files here</p>
            <p className="mt-1 text-[11px] text-ink-mute font-mono">or click to select .eml, .msg, .zip, or .mbox samples</p>
            <input
              ref={inputRef}
              type="file"
              multiple
              accept=".eml,.msg,.zip,.mbox"
              className="hidden"
              onChange={(event) => onFilesSelected(event.target.files)}
            />
          </div>

          <div className="mt-5 space-y-3">
            {files.length ? (
              <div className="space-y-2">
                {files.map((file) => (
                  <div key={`${file.name}-${file.size}`} className="flex items-center justify-between rounded-lg border border-hairline bg-surface px-3 py-2.5">
                    <div className="flex min-w-0 items-center gap-3">
                      <FileText size={16} className="text-accent" />
                      <div className="min-w-0">
                        <p className="truncate text-xs font-medium text-ink">{file.name}</p>
                        <p className="text-[10px] text-ink-mute font-mono">{(file.size / 1024).toFixed(1)} KB</p>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        removeFile(file.name);
                      }}
                      className="rounded p-1 text-ink-mute hover:bg-critical/20 hover:text-critical"
                      aria-label={`Remove ${file.name}`}
                    >
                      <X size={16} />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-dashed border-hairline-strong bg-surface px-4 py-3 text-[11px] font-mono text-ink-mute">
                No files selected yet.
              </div>
            )}
          </div>

          {error && (
            <div className="mt-5 flex items-start gap-2 rounded-lg border border-critical/30 bg-critical/10 p-3 text-sm text-critical">
              <AlertTriangle size={16} className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="mt-6 flex items-center justify-between border-t border-hairline pt-4">
            <div className="text-[10px] uppercase tracking-[0.2em] text-ink-mute font-mono">
              {files.length ? `${files.length} file(s) queued` : 'Awaiting intake'}
            </div>
            <button
              type="button"
              onClick={handleSubmit}
              disabled={isSubmitting || !files.length}
              className="inline-flex items-center gap-2 rounded-lg border border-accent bg-accent/10 px-4 py-2 text-sm font-medium text-accent transition hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <ShieldCheck size={16} />
              {isSubmitting ? 'Queuing...' : 'Start batch analysis'}
            </button>
          </div>
        </section>

        <aside className="rounded-xl border border-hairline bg-raised/90 p-5">
          <div className="flex items-center gap-2">
            <Clock3 size={16} className="text-accent" />
            <h2 className="text-sm font-semibold text-ink">Live queue</h2>
          </div>

          {batchId && (
            <div className="mt-4 rounded-lg border border-hairline-strong bg-surface p-3 text-[10px] uppercase tracking-[0.14em] text-accent font-mono">
              Batch ID: {batchId}
            </div>
          )}

          <div className="mt-4 space-y-3">
            {entries.length ? (
              entries.map((entry) => (
                <div key={entry.analysis_id} className="rounded-lg border border-hairline bg-surface p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-xs font-medium text-ink">{entry.filename}</p>
                      <p className="mt-1 text-[10px] text-ink-mute font-mono">{entry.analysis_id.slice(0, 8)}…</p>
                    </div>
                    <span className={`inline-flex rounded-full border px-2 py-1 text-[9px] uppercase tracking-[0.12em] font-mono ${statusStyles[entry.status]}`}>
                      {entry.status}
                    </span>
                  </div>
                  {entry.stage && (
                    <p className="mt-2 text-[11px] text-ink-dim">{entry.stage}</p>
                  )}
                  {typeof entry.progress_pct === 'number' && (
                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-raised">
                      <div className="h-full rounded-full bg-accent" style={{ width: `${Math.min(Math.max(entry.progress_pct, 0), 100)}%` }} />
                    </div>
                  )}
                  {entry.error && (
                    <div className="mt-2 flex items-start gap-2 text-[11px] text-critical">
                      <AlertTriangle size={12} className="mt-0.5" />
                      <span>{entry.error}</span>
                    </div>
                  )}
                  {entry.status === 'completed' && (
                    <div className="mt-3 flex items-center gap-1.5 text-[11px] text-safe">
                      <CheckCircle2 size={12} />
                      <span>Result ready for review</span>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="rounded-lg border border-dashed border-hairline-strong bg-surface px-3 py-4 text-[11px] text-ink-mute font-mono">
                Queue is empty until a batch is submitted.
              </div>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}

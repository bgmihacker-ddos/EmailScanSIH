import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Save } from 'lucide-react';
import { apiFetch } from '../services/api';

type Case = { id: string; title: string; description?: string; status: string; severity: string; analysis_ids: string[]; notes: { text: string; created_at: string }[] };

export default function CaseDetail() {
  const { id } = useParams();
  const [item, setItem] = useState<Case | null>(null);
  const [status, setStatus] = useState('open');
  const [note, setNote] = useState('');
  useEffect(() => { if (id) apiFetch(`/api/cases/${id}`).then((value: Case) => { setItem(value); setStatus(value.status); }); }, [id]);
  if (!item) return <p className="text-xs text-ink-mute">Loading case...</p>;
  const save = async () => { await apiFetch(`/api/cases/${item.id}`, { method: 'PATCH', body: JSON.stringify({ status }) }); setItem({ ...item, status }); };
  const addNote = async () => { if (!note.trim()) return; const updated = await apiFetch(`/api/cases/${item.id}/notes`, { method: 'POST', body: JSON.stringify({ text: note }) }) as Case; setItem(updated); setNote(''); };
  return <div className="mx-auto max-w-[1000px] space-y-5"><Link to="/cases" className="inline-flex items-center gap-2 text-xs text-ink-mute hover:text-accent"><ArrowLeft size={14} /> Cases</Link><header className="border-b border-hairline-strong pb-5"><p className="report-kicker">Case file</p><h1 className="mt-1 text-2xl font-semibold text-ink">{item.title}</h1><p className="mt-2 font-mono text-xs text-ink-mute">{item.severity} severity · {item.analysis_ids.length} linked analyses</p></header><section className="rounded border border-hairline-strong bg-raised p-5"><div className="flex gap-2"><select value={status} onChange={(event) => setStatus(event.target.value)} className="rounded border border-hairline-strong bg-surface px-3 py-2 text-sm text-ink-dim"><option value="open">Open</option><option value="investigating">Investigating</option><option value="closed">Closed</option></select><button onClick={save} className="btn-secondary"><Save size={14} /> Save status</button></div><h2 className="mt-6 text-sm font-semibold text-ink">Linked analyses</h2><div className="mt-3 space-y-2">{item.analysis_ids.map((analysisId) => <Link key={analysisId} to={`/analysis/${analysisId}`} className="block rounded border border-hairline-strong px-3 py-2 font-mono text-xs text-accent hover:border-accent/60">{analysisId}</Link>)}{!item.analysis_ids.length && <p className="text-xs text-ink-faint">No analyses linked.</p>}</div></section><section className="rounded border border-hairline-strong bg-raised p-5"><h2 className="text-sm font-semibold text-ink">Analyst notes</h2><div className="mt-3 flex gap-2"><input value={note} onChange={(event) => setNote(event.target.value)} placeholder="Add a note" className="min-w-0 flex-1 rounded border border-hairline-strong bg-surface px-3 py-2 text-sm text-ink-dim" /><button onClick={addNote} className="btn-primary">Add</button></div><div className="mt-4 space-y-2">{item.notes.map((entry, index) => <div key={`${entry.created_at}-${index}`} className="border-l-2 border-accent/60 pl-3 text-sm text-ink-dim">{entry.text}<p className="mt-1 font-mono text-[10px] text-ink-faint">{new Date(entry.created_at).toLocaleString()}</p></div>)}</div></section></div>;
}

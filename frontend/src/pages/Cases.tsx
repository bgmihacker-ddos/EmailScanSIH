import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FolderKanban, Plus } from 'lucide-react';
import { apiFetch } from '../services/api';

type Case = { id: string; title: string; status: string; severity: string; analysis_ids: string[]; updated_at: string };

export default function Cases() {
  const [cases, setCases] = useState<Case[]>([]);
  const [title, setTitle] = useState('');
  const [loading, setLoading] = useState(true);
  const load = () => apiFetch('/api/cases').then((value: { data: Case[] }) => setCases(value.data)).finally(() => setLoading(false));
  useEffect(() => { load().catch(() => setCases([])); }, []);
  const create = async () => { if (!title.trim()) return; await apiFetch('/api/cases', { method: 'POST', body: JSON.stringify({ title, severity: 'medium' }) }); setTitle(''); await load(); };
  return <div className="mx-auto max-w-[1200px] space-y-5"><header className="flex items-end justify-between border-b border-hairline-strong pb-5"><div><p className="report-kicker">Investigation workspace</p><h1 className="mt-1 text-2xl font-semibold text-ink">Cases</h1></div><FolderKanban className="text-accent" /></header><div className="flex gap-2"><input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="New case title" className="min-w-0 flex-1 rounded border border-hairline-strong bg-surface px-3 py-2 text-sm text-ink-dim" /><button onClick={create} className="btn-primary"><Plus size={14} /> Create case</button></div>{loading ? <p className="text-xs text-ink-mute">Loading cases...</p> : <div className="grid gap-3 md:grid-cols-2">{cases.map((item) => <Link key={item.id} to={`/cases/${item.id}`} className="rounded border border-hairline-strong bg-raised p-4 hover:border-accent/60"><p className="font-semibold text-ink">{item.title}</p><p className="mt-2 font-mono text-[10px] uppercase text-ink-mute">{item.status} · {item.severity} · {item.analysis_ids.length} analyses</p><p className="mt-2 text-xs text-ink-faint">Updated {new Date(item.updated_at).toLocaleString()}</p></Link>)}{!cases.length && <p className="text-xs text-ink-faint">No cases created yet.</p>}</div>}</div>;
}

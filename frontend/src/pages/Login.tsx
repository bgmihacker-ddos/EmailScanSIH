import { useEffect, useState, type ReactNode } from 'react';
import { Activity, ArrowUpRight, Check, Fingerprint, Globe2, KeyRound, LockKeyhole, LogIn, Mail, Network, Shield, UserRound } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { SecurityEnvironmentBackground } from '../components/common/SecurityEnvironmentBackground';
import { BASE_URL } from '../services/api';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { login, user } = useAuth();

  useEffect(() => {
    if (user) navigate(user.role === 'admin' ? '/admin' : '/dashboard');
  }, [user, navigate]);

  const handleLogin = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await login(email, password);
    } catch (reason: any) {
      setError(reason.message || 'Invalid credentials or connection error');
      setIsLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    window.location.assign(`${BASE_URL}/api/auth/google/login`);
  };

  return (
    <main className="relative min-h-screen overflow-hidden bg-transparent text-ink-dim">
      <SecurityEnvironmentBackground profile="auth" intensity="moderate" />
      <div className="relative z-10 mx-auto flex min-h-screen w-full max-w-[1500px] flex-col px-5 py-5 sm:px-8 lg:px-12">
        <header className="flex items-center justify-between border-b border-hairline-strong pb-5">
          <Link to="/login" className="group flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-hairline-strong bg-accent-soft text-accent shadow-[0_0_25px_rgba(76,158,235,0.12)] transition-transform group-hover:-rotate-6"><Shield size={19} /></span>
            <span><strong className="block text-sm tracking-[0.12em] text-ink">EMAIL THREAT</strong><span className="font-mono text-[9px] font-semibold uppercase tracking-[0.24em] text-accent">Forensic intelligence</span></span>
          </Link>
          <div className="hidden items-center gap-3 font-mono text-[10px] uppercase tracking-[0.18em] text-ink-mute sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_10px_rgba(76,158,235,0.8)]" /> local analysis node <span className="text-ink-faint">/</span> secure access</div>
        </header>

        <div className="grid flex-1 items-center gap-14 py-12 lg:grid-cols-[1fr_460px] lg:gap-24 lg:py-16">
          <section className="max-w-2xl">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.24em] text-accent">Evidence before assumption</p>
            <h1 className="mt-5 max-w-xl text-5xl font-semibold leading-[1.02] tracking-[-0.045em] text-ink sm:text-6xl">See the message behind the verdict.</h1>
            <p className="mt-6 max-w-lg text-base leading-8 text-ink-dim">A focused workspace for tracing email identity, transport, authentication, and threat intelligence back to the original message.</p>
            <div className="mt-10 grid max-w-xl gap-3 sm:grid-cols-3"><Capability icon={<Network size={16} />} label="Mail flow" detail="Received-chain reconstruction" /><Capability icon={<Fingerprint size={16} />} label="Identity" detail="SPF · DKIM · DMARC" /><Capability icon={<Globe2 size={16} />} label="Intel" detail="Provider-aware enrichment" /></div>
            <div className="mt-12 flex flex-wrap items-center gap-x-6 gap-y-3 border-t border-hairline-strong pt-5 font-mono text-[10px] uppercase tracking-[0.14em] text-ink-mute"><span className="inline-flex items-center gap-2"><Check size={13} className="text-accent" /> RFC 5322 parsing</span><span className="inline-flex items-center gap-2"><Check size={13} className="text-accent" /> STIX 2.1 export</span><span className="inline-flex items-center gap-2"><Check size={13} className="text-accent" /> ATT&amp;CK context</span></div>
            <div className="mt-8 flex flex-wrap items-center gap-4 font-mono text-[10px] uppercase tracking-[0.16em] text-ink-mute">
              <Link to="/policy" className="inline-flex items-center gap-2 text-accent hover:brightness-125">Privacy policy</Link>
              <Link to="/service" className="inline-flex items-center gap-2 text-accent hover:brightness-125">Terms of service</Link>
            </div>
          </section>

          <section className="relative rounded-2xl border border-hairline-strong bg-surface/90 p-8 shadow-[0_28px_90px_rgba(4,7,12,0.5)] backdrop-blur-xl sm:p-8">
            <div className="absolute right-0 top-0 h-28 w-28 overflow-hidden rounded-bl-[5rem] bg-accent/5" />
            <div className="relative">
              <div className="flex items-center justify-between"><div><p className="font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-accent">Analyst gateway</p><h2 className="mt-3 text-2xl font-semibold tracking-tight text-ink">Sign in to console</h2></div><div className="rounded-lg border border-hairline-strong bg-accent-soft p-3 text-accent"><LockKeyhole size={18} /></div></div>
              <p className="mt-3 text-sm leading-6 text-ink-dim">Use your authorized operator credentials to open the investigation workspace.</p>
              {error && <div className="mt-6 rounded-lg border border-critical/40 bg-critical/10 p-3 text-xs leading-5 text-critical">{error}</div>}
              <form onSubmit={handleLogin} className="mt-7 space-y-5"><Field label="Operator email" icon={<Mail size={16} />} value={email} onChange={setEmail} placeholder="analyst@soc.domain" type="email" disabled={isLoading} /><Field label="Access key" icon={<KeyRound size={16} />} value={password} onChange={setPassword} placeholder="Enter access key" type="password" disabled={isLoading} /><button type="submit" disabled={isLoading} className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-3.5 text-xs font-bold uppercase tracking-[0.14em] text-[#071018] shadow-[0_12px_28px_rgba(76,158,235,0.16)] transition hover:brightness-110 disabled:cursor-wait disabled:opacity-60">{isLoading ? <><Activity size={15} className="animate-pulse" /> Verifying access</> : <><LogIn size={15} /> Authenticate operator</>}</button></form>
              <div className="my-7 flex items-center gap-3"><span className="h-px flex-1 bg-hairline" /><span className="font-mono text-[9px] uppercase tracking-[0.18em] text-ink-mute">Federated identity</span><span className="h-px flex-1 bg-hairline" /></div>
              <button type="button" onClick={handleGoogleLogin} disabled={isLoading} className="flex w-full items-center justify-center gap-3 rounded-lg border border-hairline-strong bg-raised px-4 py-3 text-xs font-medium text-ink-dim transition hover:border-accent/60 hover:bg-accent-soft disabled:opacity-60"><GoogleMark /> Continue with Google SSO <ArrowUpRight size={13} className="text-ink-mute" /></button>
              <p className="mt-7 text-center text-xs text-ink-mute">Need an operator account? <Link to="/signup" className="font-medium text-accent hover:brightness-125">Request access</Link></p>
            </div>
          </section>
        </div>

        <footer className="flex flex-col gap-2 border-t border-hairline-strong pt-4 font-mono text-[9px] uppercase tracking-[0.15em] text-ink-faint sm:flex-row sm:items-center sm:justify-between"><span>Protected investigation surface</span><span className="inline-flex items-center gap-2"><UserRound size={11} /> Authorized personnel only · local instance</span></footer>
      </div>
    </main>
  );
}

function Field({ label, icon, value, onChange, placeholder, type, disabled }: { label: string; icon: ReactNode; value: string; onChange: (value: string) => void; placeholder: string; type: string; disabled: boolean }) {
  return <label className="block"><span className="mb-2 block font-mono text-[10px] font-semibold uppercase tracking-[0.15em] text-ink-dim">{label}</span><span className="relative block"><span className="pointer-events-none absolute left-3.5 top-3.5 text-ink-mute">{icon}</span><input type={type} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} required disabled={disabled} autoComplete={type === 'email' ? 'email' : 'current-password'} className="w-full rounded-lg border border-hairline-strong bg-sunken py-3.5 pl-11 pr-4 text-sm text-ink placeholder:text-ink-faint transition focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/20 disabled:opacity-60" /></span></label>;
}

function Capability({ icon, label, detail }: { icon: ReactNode; label: string; detail: string }) { return <div className="rounded-lg border border-hairline-strong bg-raised/60 p-4"><div className="text-accent">{icon}</div><p className="mt-5 text-sm font-medium text-ink-dim">{label}</p><p className="mt-1 text-[11px] leading-5 text-ink-mute">{detail}</p></div>; }
function GoogleMark() { return <span className="flex h-5 w-5 items-center justify-center rounded-full bg-white font-bold text-[11px] text-[#4285f4]">G</span>; }
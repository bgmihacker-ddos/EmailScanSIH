import { ArrowRight, FileText, LockKeyhole, ShieldCheck, Sparkles } from 'lucide-react';
import { Link } from 'react-router-dom';
import { SecurityEnvironmentBackground } from '../components/common/SecurityEnvironmentBackground';

export default function HomePage() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-deck text-ink-dim">
      <SecurityEnvironmentBackground profile="auth" intensity="moderate" />
      <div className="relative z-10 mx-auto flex min-h-screen max-w-6xl flex-col px-5 py-6 sm:px-8 lg:px-12">
        <header className="flex flex-col gap-4 border-b border-hairline-strong pb-5 sm:flex-row sm:items-center sm:justify-between">
          <Link to="/" className="group inline-flex items-center gap-3">
            <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-hairline-strong bg-accent-soft text-accent shadow-[0_0_25px_rgba(76,158,235,0.12)] transition-transform group-hover:-rotate-6">
              <ShieldCheck size={20} />
            </span>
            <span>
              <strong className="block text-sm tracking-[0.12em] text-ink">EMAIL THREAT</strong>
              <span className="font-mono text-[9px] font-semibold uppercase tracking-[0.24em] text-accent">Forensic intelligence</span>
            </span>
          </Link>

          <nav className="flex flex-wrap items-center gap-3 font-mono text-[10px] uppercase tracking-[0.16em] text-ink-mute">
            <Link to="/policy" className="transition hover:text-accent">Privacy policy</Link>
            <Link to="/service" className="transition hover:text-accent">Terms</Link>
            <Link to="/login" className="rounded-full border border-hairline-strong px-3 py-2 text-ink-dim transition hover:border-accent/60 hover:text-accent">Log in</Link>
          </nav>
        </header>

        <section className="grid flex-1 items-center gap-12 py-12 lg:grid-cols-[1.1fr_0.9fr] lg:py-20">
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.24em] text-accent">
              Secure analysis for modern mail operations
            </p>
            <h1 className="mt-5 max-w-xl text-5xl font-semibold leading-[1.02] tracking-[-0.045em] text-ink sm:text-6xl">
              Email threat detection for the security team that needs evidence.
            </h1>
            <p className="mt-6 max-w-xl text-base leading-8 text-ink-dim">
              Email Threat Detection helps analysts trace sender identity, mail flow, authentication signals, and threat intelligence to make defensible decisions quickly and consistently.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-4">
              <Link
                to="/login"
                className="inline-flex items-center gap-2 rounded-lg bg-accent px-5 py-3 text-xs font-bold uppercase tracking-[0.14em] text-[#071018] shadow-[0_12px_28px_rgba(76,158,235,0.16)] transition hover:brightness-110"
              >
                Open console <ArrowRight size={15} />
              </Link>
              <Link
                to="/signup"
                className="inline-flex items-center gap-2 rounded-lg border border-hairline-strong bg-raised px-5 py-3 text-xs font-bold uppercase tracking-[0.14em] text-ink-dim transition hover:border-accent/60"
              >
                Request access
              </Link>
            </div>

            <div className="mt-12 grid gap-4 sm:grid-cols-3">
              <FeatureCard icon={<Sparkles size={18} />} label="Evidence-first" detail="Parse and correlate email identity, headers, and signals." />
              <FeatureCard icon={<LockKeyhole size={18} />} label="Protected" detail="Role-based access to keep analyst work contained and reviewable." />
              <FeatureCard icon={<FileText size={18} />} label="Documented" detail="Privacy and service terms are published for operator transparency." />
            </div>
          </div>

          <div className="rounded-3xl border border-hairline-strong bg-surface/90 p-8 shadow-[0_28px_90px_rgba(4,7,12,0.5)] backdrop-blur-xl sm:p-8">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-accent">Operating scope</p>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight text-ink">Built for trusted investigation workflows.</h2>
            <ul className="mt-6 space-y-4 text-sm leading-7 text-ink-dim">
              <li className="flex items-start gap-3"><span className="mt-2 h-2 w-2 rounded-full bg-accent" />Mailbox and message forensics for suspicious or non-compliant communication.</li>
              <li className="flex items-start gap-3"><span className="mt-2 h-2 w-2 rounded-full bg-accent" />Threat-intelligence enrichment with clear indicators, attribution context, and case records.</li>
              <li className="flex items-start gap-3"><span className="mt-2 h-2 w-2 rounded-full bg-accent" />Operator accountability, audit logs, and external integration controls for SOC workflows.</li>
            </ul>

            <div className="mt-8 rounded-2xl border border-hairline-strong bg-raised/70 p-4 text-sm text-ink-dim">
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-mute">Privacy</span>
                <span className="inline-flex items-center gap-2 text-accent">
                  <LockKeyhole size={14} /> Protected
                </span>
              </div>
              <p className="mt-3 leading-7 text-ink-dim">
                Review the privacy policy and terms before using the live analysis environment or connecting Google-based access.
              </p>
              <div className="mt-4 flex flex-wrap gap-3">
                <Link to="/policy" className="text-accent hover:brightness-125">Privacy policy</Link>
                <Link to="/service" className="text-accent hover:brightness-125">Terms of service</Link>
              </div>
            </div>
          </div>
        </section>

        <footer className="flex flex-col gap-2 border-t border-hairline-strong pt-4 font-mono text-[9px] uppercase tracking-[0.15em] text-ink-faint sm:flex-row sm:items-center sm:justify-between">
          <span>Email Threat Detection</span>
          <div className="flex flex-wrap items-center gap-4">
            <Link to="/policy" className="transition hover:text-accent">Privacy policy</Link>
            <Link to="/service" className="transition hover:text-accent">Terms</Link>
            <Link to="/login" className="transition hover:text-accent">Console access</Link>
          </div>
        </footer>
      </div>
    </main>
  );
}

function FeatureCard({ icon, label, detail }: { icon: React.ReactNode; label: string; detail: string }) {
  return (
    <div className="rounded-xl border border-hairline-strong bg-raised/60 p-4">
      <div className="text-accent">{icon}</div>
      <p className="mt-4 text-sm font-medium text-ink-dim">{label}</p>
      <p className="mt-1 text-[11px] leading-5 text-ink-mute">{detail}</p>
    </div>
  );
}

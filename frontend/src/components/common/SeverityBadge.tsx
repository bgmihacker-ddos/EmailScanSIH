import { Severity } from '../../types';

interface SeverityBadgeProps {
  severity: Severity | 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical' | string;
  className?: string;
  dotOnly?: boolean;
}

export function SeverityBadge({ severity, className = '', dotOnly = false }: SeverityBadgeProps) {
  const sev = String(severity).toLowerCase();

  let colors = 'bg-sunken text-ink-dim border-hairline-strong'; // default
  let dotColor = 'bg-ink-mute';

  if (sev === 'critical') {
    colors = 'severity-critical';
    dotColor = 'bg-critical';
  } else if (sev === 'high' || sev === 'malicious') {
    colors = 'severity-high';
    dotColor = 'bg-high';
  } else if (sev === 'medium' || sev === 'suspicious') {
    colors = 'severity-medium';
    dotColor = 'bg-medium';
  } else if (sev === 'low') {
    colors = 'severity-low';
    dotColor = 'bg-low';
  } else if (sev === 'safe' || sev === 'benign' || sev === 'clean') {
    colors = 'severity-safe';
    dotColor = 'bg-safe';
  } else if (sev === 'info') {
    colors = 'severity-low';
    dotColor = 'bg-low';
  }

  if (dotOnly) {
    return <span className={`inline-block h-2.5 w-2.5 rounded-full ${dotColor} ${className}`} title={String(severity).toUpperCase()} />;
  }

  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider ${colors} ${className}`}>
      <span className={`mr-1.5 h-1.5 w-1.5 rounded-full ${dotColor} animate-pulse-slow`}></span>
      {severity}
    </span>
  );
}

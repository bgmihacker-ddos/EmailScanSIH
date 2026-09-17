interface MetricCardProps {
  title: string;
  value: string | number;
  tone?: string;
  className?: string;
}

export function MetricCard({ title, value, tone = 'text-accent', className = '' }: MetricCardProps) {
  return (
    <div className={`metric-card ${className}`}>
      <p className="soc-label">{title}</p>
      <p className={`mt-2.5 font-mono text-2xl font-semibold tracking-tight ${tone}`}>{value}</p>
    </div>
  );
}

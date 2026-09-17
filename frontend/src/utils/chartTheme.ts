// Shared recharts theming for the SOC design system.
// Severity palette: critical #F4586B / high #F0794A / medium #E8B44A / low #4C9EEB / safe #3ECF8E.
export const CHART = {
  accent: '#4C9EEB',
  medium: '#E8B44A',
  critical: '#F4586B',
  high: '#F0794A',
  safe: '#3ECF8E',
  grid: 'rgba(255,255,255,0.06)',
} as const;

export const chartTooltip = {
  backgroundColor: '#151A25',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: '5px',
  color: '#E9EDF4',
  fontSize: '11px',
  fontFamily: 'IBM Plex Mono, monospace',
};

export const chartTick = {
  fill: '#6B7689',
  fontSize: 10,
  fontFamily: 'IBM Plex Mono, monospace',
};

const SEVERITY_FILL: Record<string, string> = {
  critical: CHART.critical,
  high: CHART.high,
  medium: CHART.medium,
  moderate: CHART.medium,
  low: CHART.accent,
  safe: CHART.safe,
  benign: CHART.safe,
  clean: CHART.safe,
};

// Normalizes backend-provided distribution colors to the SOC severity palette,
// falling back to the backend color for unmapped names.
export function severityFill(name: string, fallback: string): string {
  return SEVERITY_FILL[name.toLowerCase()] ?? fallback;
}

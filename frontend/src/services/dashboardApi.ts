import { getDashboardSummary } from './analysisApi';

export const getDashboardMetrics = async () => {
  const summary = await getDashboardSummary();
  const { total_analyses, flagged_analyses, malicious_analyses, average_risk_score } = summary.metrics;
  return [
    { label: 'EMAILS ANALYZED', value: String(total_analyses), trend: 'persisted', color: 'text-cyan-400' },
    { label: 'FLAGGED', value: String(flagged_analyses), trend: 'local results', color: 'text-red-400' },
    { label: 'MALICIOUS', value: String(malicious_analyses), trend: 'local results', color: 'text-orange-400' },
    { label: 'AVG RISK', value: String(average_risk_score), trend: '/ 100', color: 'text-yellow-400' },
  ];
};

export const getThreatActivity = async () => {
  const summary = await getDashboardSummary();
  return summary.activity.map((item) => ({
    name: item.date.slice(5),
    Analyses: item.analyses,
    Flagged: item.flagged,
  }));
};

export const getDistribution = async () => (await getDashboardSummary()).distribution;

export const getActiveThreats = async () => {
  const summary = await getDashboardSummary();
  return summary.top_indicators.map((item) => ({ name: item.indicator, count: item.count }));
};

export const getRecentLogs = async () => {
  const summary = await getDashboardSummary();
  return summary.recent_analyses.map((item) => ({
    id: item.analysis_id,
    timestamp: item.created_at,
    user: item.sender,
    event: item.summary,
    severity: item.severity,
    status: item.status,
  }));
};

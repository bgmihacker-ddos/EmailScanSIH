export interface SecurityLog {
  id: string;
  timestamp: string;
  user: string;
  event: string;
  type: string;
  severity: string;
  source: string;
  status: 'Success' | 'Failed' | 'Warning';
}

export interface DashboardMetrics {
  emailsAnalyzed: number;
  threatsDetected: number;
  highRisk: number;
  critical: number;
}

export type Role = 'user' | 'admin';

export interface User {
  id: string;
  email: string;
  role: Role;
  name: string;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
}

export type ThreatType = 'Phishing' | 'BEC' | 'Malware' | 'Credential Theft' | 'Suspicious';
export type Severity = 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical';
export type ThreatStatus = 'Open' | 'In Progress' | 'Resolved' | 'Quarantined' | 'active' | 'inactive' | 'online' | 'offline' | 'unknown' | 'analyzed';

export interface Threat {
  id: string;
  type: ThreatType;
  indicator?: string;
  indicator_type?: string;
  threat_type?: string;
  severity: Severity;
  confidence: number;
  target: string;
  location: string;
  country?: string | null;
  country_code?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  firstSeen: string;
  lastSeen: string;
  status: ThreatStatus | string;
  description?: string;
  sender?: string;
  source?: string;
  malware?: string;
  malwareFamily?: string;
  tags?: string[];
  reference_url?: string;
  reference?: string;
  reporter?: string;
  related_investigations?: string[];
  indicators?: string[];
  attackStages?: { stage: string; status: 'completed' | 'active' | 'pending'; description: string }[];
}

export type IOCType = 'IP' | 'Domain' | 'URL' | 'Email' | 'Hash';

export interface ThreatIndicator {
  id: string;
  indicator: string;
  indicator_type: 'IP' | 'Domain' | 'URL' | 'Email' | 'Hash';
  severity: Severity;
  confidence: number;
  source: string;
  country?: string | null;
  country_code?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  first_seen?: string | null;
  last_seen?: string | null;
  status?: string | null; // 'active' | 'inactive' | 'online' | 'offline' | 'unknown' - provider-specific
  malware?: string | null;
  tags?: string[];
  reference_url?: string | null;
  reporter?: string | null;
  threat_type?: string | null;
  related_investigations?: string[];
  // For Local Analysis fields only
  analysis_id?: string;
  email_subject?: string;
  email_sender?: string;
  verdict?: string;
  risk_score?: number;
  created_at?: string;
  context?: string;
  // Legacy field - deprecated
  relatedThreats?: string[];
}

export interface ThreatMapEvent {
  id: string;
  latitude: number;
  longitude: number;
  country: string;
  city: string;
  threatType: ThreatType;
  severity: Severity;
  timestamp: string;
  source: string;
  confidence: number;
}

export interface EmailScanRecord {
  id: string;
  user: string;
  sender: string;
  recipient: string;
  subject: string;
  threatScore: number;
  verdict: 'Safe' | 'Suspicious' | 'Malicious' | 'Critical';
  scannedAt: string;
  status: 'Clean' | 'Quarantined' | 'Blocked' | 'Flagged' | 'Processing' | 'Completed' | 'Failed' | 'Queued';
  processingTimeMs: number;
}

export interface SecurityReport {
  id: string;
  title: string;
  description: string;
  dateRange: string;
  category: string;
  metrics: { label: string; value: string | number; change?: string }[];
  status: 'Ready' | 'Generating';
}

export interface AdminUserRecord {
  id: string;
  name: string;
  email: string;
  role: Role;
  status: 'Active' | 'Suspended' | 'Pending';
  lastLogin: string;
  scansCount: number;
  createdAt: string;
}

export interface ThreatIntelProvider {
  id: string;
  name: string;
  type: string;
  status: 'Connected' | 'Degraded' | 'Offline';
  lastSync: string;
  recordsIndexed: number;
  latencyMs: number;
  healthScore: number;
}

export interface SystemServiceHealth {
  id: string;
  service: string;
  status: 'Operational' | 'Degraded' | 'Offline';
  uptimePct: number;
  latencyMs: number;
  lastChecked: string;
  errorCount24h: number;
  description: string;
}

export interface AuditLogRecord {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  ipAddress: string;
  result: 'Success' | 'Denied' | 'Warning' | 'Failed';
  details?: string;
}

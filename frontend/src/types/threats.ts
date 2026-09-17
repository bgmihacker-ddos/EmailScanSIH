export type ThreatType = 'Phishing' | 'BEC' | 'Malware' | 'Credential Theft' | 'Suspicious';
export type Severity = 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical';
export type Status = 'Open' | 'In Progress' | 'Resolved' | 'Quarantined' | 'active' | 'inactive' | 'online' | 'offline' | 'unknown' | 'analyzed';

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
  status: string;
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

export interface ThreatIndicator {
  id: string;
  indicator: string;
  indicator_type: 'IP' | 'Domain' | 'URL' | 'Email' | 'Hash';
  severity: Severity;
  confidence: number;
  source: string;
  country?: string;
  country_code?: string;
  latitude?: number;
  longitude?: number;
  first_seen?: string;
  last_seen?: string;
  status: 'active' | 'inactive' | 'unknown';
  malware?: string;
  tags?: string[];
  reference_url?: string;
  relatedThreats?: string[];
}

export interface ThreatMapEvent {
  id: string;
  indicator?: string;
  latitude: number | null;
  longitude: number | null;
  country: string;
  city: string;
  threatType: ThreatType;
  threat_type?: string;
  malware?: string;
  severity: Severity;
  timestamp: string;
  first_seen?: string;
  last_seen?: string;
  source: string;
  confidence: number;
  geoSource?: string;
  status: string;
  tags?: string[];
  reference_url?: string;
  reporter?: string;
}

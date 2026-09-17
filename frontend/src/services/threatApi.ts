import { apiFetch } from './api';
import { Threat, ThreatIndicator, ThreatMapEvent, ThreatType } from '../types/threats';

export const getThreats = async (): Promise<Threat[]> => {
  try {
    const response = await apiFetch('/api/threats');
    return (response.data || []).map((item: any) => ({
      id: String(item.id),
      target: item.indicator || 'Unknown',
      indicator: item.indicator,
      indicator_type: item.indicator_type,
      type: normalizeThreatType(item.threat_type || item.indicator_type),
      severity: normalizeSeverity(item.severity),
      confidence: item.confidence || 0,
      location: item.country || 'Not reported',
      country: item.country,
      country_code: item.country_code,
      firstSeen: item.first_seen || 'Not reported',
      lastSeen: item.last_seen || 'Not reported',
      status: normalizeThreatStatus(item.status),
      description: item.malware || 'No description available',
      sender: item.reporter || 'Unknown reporter',
      source: item.source,
      malware: item.malware,
      tags: item.tags,
      reporter: item.reporter,
      reference_url: item.reference_url,
      reference: item.reference_url || 'No reference available'
    }));
  } catch (error) {
    console.error('Error fetching threats:', error);
    return [];
  }
};

export const getThreatById = async (id: string): Promise<Threat | undefined> => {
  try {
    const response = await apiFetch(`/api/threats/${id}`);
    const item = response.data;
    if (!item) return undefined;

    return {
      id: String(item.id),
      target: item.indicator || 'Unknown',
      indicator: item.indicator,
      indicator_type: item.indicator_type,
      type: normalizeThreatType(item.threat_type || item.indicator_type),
      severity: normalizeSeverity(item.severity),
      confidence: item.confidence || 0,
      location: item.country || 'Not reported',
      country: item.country,
      country_code: item.country_code,
      latitude: item.latitude,
      longitude: item.longitude,
      firstSeen: item.first_seen || 'Not reported',
      lastSeen: item.last_seen || 'Not reported',
      status: normalizeThreatStatus(item.status),
      description: item.malware || 'No description available',
      sender: item.reporter || 'Unknown reporter',
      source: item.source,
      malware: item.malware || 'Unknown',
      tags: item.tags || [],
      reporter: item.reporter,
      reference_url: item.reference_url,
      related_investigations: item.related_investigations || [],
      reference: item.reference_url || 'No reference available'
    };
  } catch (error) {
    console.error('Error fetching threat by id:', error);
    return undefined;
  }
};

export const getIndicators = async (): Promise<ThreatIndicator[]> => {
  try {
    const response = await apiFetch('/api/indicators');
    // Backend returns snake_case fields; normalize to match ThreatIndicator type
    return (response.data || []).map((item: any) => ({
      id: String(item.id),
      indicator: item.indicator || '',
      indicator_type: normalizeIndicatorType(item.indicator_type),
      severity: normalizeSeverity(item.severity),
      confidence: typeof item.confidence === 'number' ? item.confidence : 0,
      source: item.source || 'Unknown Feed',
      country: item.country ?? null,
      country_code: item.country_code ?? null,
      latitude: item.latitude ?? null,
      longitude: item.longitude ?? null,
      first_seen: item.first_seen ?? null,
      last_seen: item.last_seen ?? null,
      status: item.status ?? null,
      malware: item.malware ?? null,
      tags: Array.isArray(item.tags) ? item.tags : [],
      reference_url: item.reference_url ?? null,
      reporter: item.reporter ?? null,
      threat_type: item.threat_type ?? null,
      related_investigations: Array.isArray(item.related_investigations) ? item.related_investigations : [],
      relatedThreats: Array.isArray(item.relatedThreats) ? item.relatedThreats : [], // legacy
    }));
  } catch (error) {
    console.error('Error fetching indicators:', error);
    return [];
  }
};

function normalizeIndicatorType(type?: string): 'IP' | 'Domain' | 'URL' | 'Email' | 'Hash' {
  const normalized = String(type || '').toLowerCase();
  if (normalized === 'url') return 'URL';
  if (normalized === 'domain') return 'Domain';
  if (normalized === 'ip' || normalized === 'ipv4' || normalized === 'ipv6') return 'IP';
  if (normalized === 'email') return 'Email';
  return 'Hash';
}

function normalizeThreatType(type?: string): ThreatType {
  const normalized = String(type || '').toLowerCase();
  if (normalized.includes('phishing')) return 'Phishing';
  if (normalized.includes('malware') || normalized.includes('payload')) return 'Malware';
  if (normalized.includes('credential')) return 'Credential Theft';
  if (normalized.includes('bec')) return 'BEC';
  return 'Suspicious';
}

function normalizeSeverity(severity?: string): 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical' {
  const normalized = String(severity || '').toLowerCase();
  if (normalized === 'critical') return 'Critical';
  if (normalized === 'high') return 'High';
  if (normalized === 'medium') return 'Medium';
  if (normalized === 'low') return 'Low';
  return 'Safe';
}

function normalizeThreatStatus(status?: string): string {
  const normalized = String(status || '').toLowerCase();
  if (normalized === 'unknown' || normalized === 'active' || normalized === 'open') return 'Open';
  if (normalized === 'analyzed' || normalized === 'resolved') return 'Resolved';
  if (normalized === 'quarantined') return 'Quarantined';
  if (normalized === 'in_progress' || normalized === 'in progress') return 'In Progress';
  return status || 'Open';
}

export const getLiveThreats = async (): Promise<ThreatMapEvent[]> => {
  try {
    const response = await apiFetch('/api/live-threats');
    return (response.data || []).map((e: any) => ({
      id: e.id,
      indicator: e.indicator,
      latitude: e.latitude ?? null,
      longitude: e.longitude ?? null,
      country: e.country || 'Not reported',
      city: e.city || 'Not reported',
      threatType: normalizeThreatType(e.threat_type || e.indicator_type),
      threat_type: e.threat_type || 'Unknown',
      malware: e.malware || 'No malware reported',
      severity: e.severity === 'critical' || e.severity === 'High' ? 'High' : e.severity === 'high' ? 'High' : e.severity === 'medium' || e.severity === 'Medium' ? 'Medium' : 'Low',
      timestamp: e.timestamp || new Date().toISOString(),
      first_seen: e.first_seen,
      last_seen: e.last_seen,
      source: e.source,
      confidence: e.confidence || 0,
      geoSource: e.geo_source || undefined,
      status: e.status || 'unknown',
      tags: e.tags || [],
      reference_url: e.reference_url,
      reporter: e.reporter
    }));
  } catch (error) {
    console.error('Error fetching live threats:', error);
    return [];
  }
};

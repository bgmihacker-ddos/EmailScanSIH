import { apiFetch } from './api';

const configuredBaseUrl = (import.meta.env.VITE_API_URL || '').trim();
const BASE_URL = (
  import.meta.env.DEV && configuredBaseUrl.includes('email-threat-detection-1-w14g.onrender.com')
    ? ''
    : configuredBaseUrl && !configuredBaseUrl.includes('email-threat-detection1.vercel.app')
      ? configuredBaseUrl
      : import.meta.env.DEV ? '' : 'https://email-threat-detection-1-w14g.onrender.com'
).replace(/\/$/, '');

const authHeaders = (): HeadersInit => {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

export interface AnalysisSummary {
  analysis_id: string;
  verdict: string;
  risk_score: number;
  severity: string;
  confidence: number;
  summary: string;
  subject: string;
  sender: string;
  recipient: string;
  created_at: string;
  status: string;
}

export interface DashboardSummary {
  metrics: {
    total_analyses: number;
    flagged_analyses: number;
    malicious_analyses: number;
    average_risk_score: number;
  };
  verdict_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  activity: { date: string; analyses: number; flagged: number }[];
  distribution: { name: string; value: number; color: string }[];
  top_indicators: { indicator: string; count: number }[];
  recent_analyses: AnalysisSummary[];
  data_source: string;
}

export interface DashboardTrends {
  daily: { date: string; analyses: number; flagged: number }[];
  countries: { name: string; count: number }[];
  auth_results: Record<string, Record<string, number>>;
  attack_types: { name: string; count: number }[];
}

export interface AnalysisStatus {
  analysis_id: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  stage: string;
  progress_pct: number;
  error: string | null;
}

export const analyzeEmail = async (content: string, file?: File): Promise<any> => {
  const formData = new FormData();
  if (file) formData.append('file', file);
  else formData.append('raw_content', content);
  formData.append('async_mode', 'true');

  const response = await fetch(`${BASE_URL}/api/analyze`, {
    method: 'POST',
    body: formData,
    headers: authHeaders(),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || errorData.message || `Analysis failed: ${response.statusText}`);
  }
  clearApiCache();
  return response.json();
};

export const getAnalysisStatus = async (id: string): Promise<AnalysisStatus> =>
  apiFetch(`/api/analyze/${encodeURIComponent(id)}/status`, { headers: authHeaders() });

export const batchAnalyzeEmails = async (files: File[]): Promise<{ batch_id: string; total: number; queued: Array<{ analysis_id: string; filename: string; status: string }> }> => {
  const formData = new FormData();
  files.forEach((file) => formData.append('files', file));

  const response = await fetch(`${BASE_URL}/api/batch/analyze`, {
    method: 'POST',
    body: formData,
    headers: authHeaders(),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || errorData.message || `Batch analysis failed: ${response.statusText}`);
  }
  clearApiCache();
  return response.json();
};

export const getBatchAnalysisStatus = async (batchId: string): Promise<any> =>
  apiFetch(`/api/batch/${encodeURIComponent(batchId)}/status`, { headers: authHeaders() });

export const getGmailInboxStatus = async (): Promise<{ connected: boolean; gmail_readonly: boolean; provider: string; scope?: string; expires_at?: string }> =>
  apiFetch('/api/inbox/gmail/status', { headers: authHeaders() });

export const syncGmailInbox = async (limit = 10): Promise<{ batch_id: string; provider: string; total: number; queued: Array<{ analysis_id: string; status: string }> }> =>
  apiFetch(`/api/inbox/gmail/sync?limit=${limit}`, { method: 'POST', headers: authHeaders() });

export interface GmailMessage {
  id: string;
  thread_id?: string;
  subject: string;
  sender: string;
  date?: string;
  snippet: string;
}

export const listGmailMessages = async (limit = 10): Promise<{ messages: GmailMessage[]; total: number }> =>
  apiFetch(`/api/inbox/gmail/messages?limit=${limit}`, { headers: authHeaders() });

const apiCache = new Map<string, { data: any; expiry: number }>();
const inFlightRequests = new Map<string, Promise<any>>();

export const clearApiCache = () => {
  apiCache.clear();
};

async function cachedFetch<T>(key: string, ttlMs: number, fetcher: () => Promise<T>): Promise<T> {
  const cached = apiCache.get(key);
  if (cached && cached.expiry > Date.now()) {
    return cached.data as T;
  }
  const pending = inFlightRequests.get(key);
  if (pending) {
    return pending as Promise<T>;
  }
  const promise = fetcher()
    .then((data) => {
      apiCache.set(key, { data, expiry: Date.now() + ttlMs });
      return data;
    })
    .finally(() => {
      inFlightRequests.delete(key);
    });
  inFlightRequests.set(key, promise);
  return promise;
}

export const scanGmailMessage = async (messageId: string): Promise<{ analysis_id: string; status: string; message_id: string }> => {
  clearApiCache();
  return apiFetch(`/api/inbox/gmail/messages/${encodeURIComponent(messageId)}/scan`, { method: 'POST', headers: authHeaders() });
};

export const getAnalysisById = async (id: string): Promise<any> =>
  cachedFetch(`analysis:${id}`, 30000, () =>
    apiFetch(`/api/analyze/${encodeURIComponent(id)}`, { headers: authHeaders() })
  );

export const getDashboardSummary = async (forceRefresh = false): Promise<DashboardSummary> => {
  if (forceRefresh) apiCache.delete('dashboard:summary');
  return cachedFetch('dashboard:summary', 10000, () =>
    apiFetch('/api/dashboard/summary', { headers: authHeaders() })
  );
};

export const getDashboardTrends = async (forceRefresh = false): Promise<DashboardTrends> => {
  if (forceRefresh) apiCache.delete('dashboard:trends');
  return cachedFetch('dashboard:trends', 15000, () =>
    apiFetch('/api/dashboard/trends', { headers: authHeaders() })
  );
};

export const listAnalyses = async (params: {
  query?: string;
  verdict?: string;
  severity?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<{ data: AnalysisSummary[]; meta: { total: number; limit: number; offset: number } }> => {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '') search.set(key, String(value));
  });
  const queryString = search.toString();
  return cachedFetch(`analyses:${queryString}`, 5000, () =>
    apiFetch(`/api/analyses${queryString ? `?${queryString}` : ''}`, { headers: authHeaders() })
  );
};

export const searchPersistedIocs = async (value: string, type?: string) => {
  const search = new URLSearchParams({ value });
  if (type) search.set('type', type);
  return apiFetch(`/api/analyses/iocs/search?${search}`, { headers: authHeaders() });
};

export const getReportUrl = (id: string, format: 'json' | 'html' | 'pdf' | 'bundle', includeRawEmail = false) => {
  if (format === 'bundle') {
    return `${BASE_URL}/api/analyze/${encodeURIComponent(id)}/evidence-bundle.zip`;
  }
  return `${BASE_URL}/api/analyze/${encodeURIComponent(id)}/report.${format}${includeRawEmail ? '?include_raw_email=true' : ''}`;
};

export const downloadReport = async (id: string, format: 'json' | 'html' | 'pdf' | 'bundle') => {
  const response = await fetch(getReportUrl(id, format), { headers: authHeaders() });
  if (!response.ok) throw new Error('Report export failed');
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `analysis-${id}.${format === 'bundle' ? 'zip' : format}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};

export interface BlockchainVerification {
  analysis_id: string;
  status: 'match' | 'mismatch' | 'not_anchored' | 'unavailable';
  matches: boolean;
  local_hash: string;
  on_chain_hash: string | null;
  tx_hash: string | null;
  network: string;
  block_number?: number | null;
  etherscan_url: string | null;
}

export const exportCertinReport = async (id: string) => {
  const response = await fetch(`${BASE_URL}/api/analysis/${encodeURIComponent(id)}/certin`, { headers: authHeaders() });
  if (!response.ok) throw new Error('CERT-In report export failed');
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `analysis-${id}-certin-report.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};

export const verifyBlockchainEvidence = async (id: string): Promise<BlockchainVerification> =>
  apiFetch(`/api/analysis/${encodeURIComponent(id)}/blockchain/verify`, { headers: authHeaders() });

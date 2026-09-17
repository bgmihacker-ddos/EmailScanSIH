import { apiFetch } from './api';

const authHeaders = (): HeadersInit => {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

export interface SearchResult {
  id: string;
  type: 'Threat' | 'Indicator' | 'EmailScan' | 'Report' | 'User' | 'IntelProvider' | 'SystemService' | 'AuditLog';
  title: string;
  description: string;
  relevance: number; // 0-100
  data: any;
}

export const globalSearch = async (query: string): Promise<SearchResult[]> => {
  if (!query.trim()) return [];

  const results: SearchResult[] = [];

  try {
    // Search Analyses & IOCs locally
    const [analysesResponse, iocsResponse] = await Promise.allSettled([
      apiFetch(`/api/analyses?query=${encodeURIComponent(query)}&limit=10`, { headers: authHeaders() }),
      apiFetch(`/api/analyses/iocs/search?value=${encodeURIComponent(query)}&limit=10`, { headers: authHeaders() })
    ]);

    if (analysesResponse.status === 'fulfilled' && analysesResponse.value?.data) {
      analysesResponse.value.data.forEach((scan: any) => {
        results.push({
          id: scan.analysis_id,
          type: 'EmailScan',
          title: scan.subject || scan.analysis_id,
          description: `From: ${scan.sender} | Verdict: ${scan.verdict.toUpperCase()}`,
          relevance: 90,
          data: scan,
        });
      });
    }

    if (iocsResponse.status === 'fulfilled' && iocsResponse.value?.data) {
      iocsResponse.value.data.forEach((ioc: any) => {
        results.push({
          id: `${ioc.analysis_id}-${ioc.indicator}`,
          type: 'Indicator',
          title: ioc.indicator,
          description: `Type: ${ioc.type} | Found in Analysis: ${ioc.analysis_id.slice(0,8)}`,
          relevance: 85,
          data: ioc,
        });
      });
    }

  } catch (error) {
    console.error('Error during global search:', error);
  }

  // Sort by relevance
  return results.sort((a, b) => b.relevance - a.relevance).slice(0, 15);
};

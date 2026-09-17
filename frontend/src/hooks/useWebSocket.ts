import { useEffect, useState } from 'react';

type Alert = { analysis_id?: string; verdict?: string; risk_score?: number; severity?: string; summary?: string };

export function useWebSocketAlerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const configuredBaseUrl = import.meta.env.VITE_API_URL || '';
    const baseUrl = import.meta.env.DEV && configuredBaseUrl.includes('email-threat-detection-1-w14g.onrender.com')
      ? `${window.location.protocol}//${window.location.host}`
      : configuredBaseUrl || (import.meta.env.DEV ? `${window.location.protocol}//${window.location.host}` : 'https://email-threat-detection-1-w14g.onrender.com');
    const configured = baseUrl.replace(/^http/, 'ws').replace(/\/$/, '');
    const socket = new WebSocket(`${configured}/ws/alerts`);
    socket.onopen = () => setConnected(true);
    socket.onmessage = (event) => { try { setAlerts((current) => [JSON.parse(event.data), ...current].slice(0, 8)); } catch { /* Ignore malformed server frames. */ } };
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    return () => socket.close();
  }, []);

  return { alerts, connected };
}

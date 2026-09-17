import { useEffect, useRef } from 'react';
import * as maplibregl from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';

type RelayHop = {
  hop_number: number;
  ip?: string | null;
  from_server?: string | null;
  by_server?: string | null;
  timestamp_utc?: string | null;
  is_private?: boolean;
  is_suspicious?: boolean;
  geo?: { latitude?: number; longitude?: number; country?: string; city?: string } | null;
};

export function RelayPathMap({ hops }: { hops: RelayHop[] }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);

  useEffect(() => {
    const points = hops.filter((hop) => Number.isFinite(hop.geo?.longitude) && Number.isFinite(hop.geo?.latitude));
    if (!containerRef.current || !points.length) return;

    const firstPoint = points[0];
    if (!firstPoint) return;
    const map = new maplibregl.Map({
      container: containerRef.current,
      style: {
        version: 8,
        sources: {
          osm: { type: 'raster', tiles: ['https://tile.openstreetmap.org/{z}/{x}/{y}.png'], tileSize: 256, attribution: '© OpenStreetMap contributors' },
        },
        layers: [{ id: 'osm', type: 'raster', source: 'osm' }],
      },
      center: [Number(firstPoint.geo?.longitude), Number(firstPoint.geo?.latitude)],
      zoom: 1.5,
      cooperativeGestures: true,
    });
    mapRef.current = map;

    map.on('load', () => {
      const coordinates = points.map((hop) => [Number(hop.geo?.longitude), Number(hop.geo?.latitude)]);
      map.addSource('relay-path', { type: 'geojson', data: { type: 'Feature', geometry: { type: 'LineString', coordinates }, properties: {} } });
      map.addLayer({ id: 'relay-path-line', type: 'line', source: 'relay-path', paint: { 'line-color': '#4C9EEB', 'line-width': 2.5, 'line-opacity': 0.8 } });
      const bounds = new maplibregl.LngLatBounds();
      points.forEach((hop) => {
        const longitude = Number(hop.geo?.longitude);
        const latitude = Number(hop.geo?.latitude);
        bounds.extend([longitude, latitude]);
        const marker = document.createElement('div');
        marker.className = `flex h-7 w-7 items-center justify-center rounded-full border-2 text-[10px] font-bold text-white shadow ${hop.is_suspicious ? 'border-critical/70 bg-critical' : 'border-accent/70 bg-accent'}`;
        marker.textContent = String(hop.hop_number);
        new maplibregl.Marker({ element: marker })
          .setLngLat([longitude, latitude])
          .setPopup(new maplibregl.Popup({ offset: 16 }).setHTML(`<strong>${escapeHtml(hop.from_server || 'Relay hop')}</strong><br>${escapeHtml(hop.ip || 'IP unavailable')}<br>${escapeHtml([hop.geo?.city, hop.geo?.country].filter(Boolean).join(', ') || 'Location unavailable')}`))
          .addTo(map);
      });
      if (points.length > 1) map.fitBounds(bounds, { padding: 48, maxZoom: 5 });
    });

    return () => { map.remove(); mapRef.current = null; };
  }, [hops]);

  if (!hops.some((hop) => hop.geo?.latitude !== undefined && hop.geo?.longitude !== undefined)) {
    return <div className="rounded border border-dashed border-hairline-strong p-6 text-center text-xs text-ink-faint">No public relay coordinates are available for mapping.</div>;
  }
  return <div ref={containerRef} className="h-[360px] w-full overflow-hidden rounded border border-hairline-strong" aria-label="Relay path map" />;
}

function escapeHtml(value: string) {
  return value.replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character] || character);
}

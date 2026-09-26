import React, { useEffect, useMemo, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup, CircleMarker, Polyline, useMap } from 'react-leaflet';
import L from 'leaflet';
import { AlertTriangle, Crosshair, MapPin, RefreshCw } from 'lucide-react';
import { getCases, getCaseAnalyses, getAnalysis, intel } from '../api';
import { RiskBadge } from './ui';

const CENTER = [22.9734, 78.6569];

function markerIcon(level = 'MEDIUM', origin = false) {
  const cls = String(level).toLowerCase();
  const tone = cls === 'critical' ? '#e11d48' : cls === 'high' ? '#d97706' : cls === 'medium' ? '#ca8a04' : '#16a34a';
  return L.divIcon({
    className: `sg-threat-marker ${origin ? 'origin-marker' : ''}`,
    html: `<span style="--marker:${tone}">${origin ? '!' : ''}</span>`,
    iconSize: [28, 28],
    iconAnchor: [14, 14],
    popupAnchor: [0, -14],
  });
}

function FitBounds({ points }) {
  const map = useMap();
  useEffect(() => {
    if (!points.length) {
      map.setView(CENTER, 4);
      return;
    }
    if (points.length === 1) {
      map.setView([points[0].lat, points[0].lng], 5);
      return;
    }
    map.fitBounds(points.map((p) => [p.lat, p.lng]), { padding: [35, 35], maxZoom: 6 });
  }, [map, points]);
  return null;
}

function MapResizeSync() {
  const map = useMap();
  useEffect(() => {
    const resize = () => map.invalidateSize({ pan: false, animate: false });
    const timer = window.setTimeout(resize, 80);
    window.addEventListener('resize', resize);
    window.addEventListener('orientationchange', resize);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener('resize', resize);
      window.removeEventListener('orientationchange', resize);
    };
  }, [map]);
  return null;
}

function asGeo(details = {}) {
  return details.geolocation || details.geoip || details.geo || details;
}

function riskFrom(point) {
  const flags = (point.risk_flags || []).map((x) => String(x).toLowerCase());
  if (flags.some((x) => x.includes('critical') || x.includes('tor') || x.includes('botnet'))) return 'CRITICAL';
  if (flags.length || point.suspicious) return 'HIGH';
  if (point.origin) return 'MEDIUM';
  return 'LOW';
}

function extractPoints(analysis) {
  const result = [];
  const probableSource = analysis?.email?.forensic_report?.relay_analysis?.probable_source || {};
  const probableIp = probableSource?.earliest_visible_public_hop?.ip || probableSource?.earliest_visible_public_hop?.value || (typeof probableSource?.earliest_visible_public_hop === 'string' ? probableSource.earliest_visible_public_hop : '');
  const iocs = Array.isArray(analysis?.iocs) ? analysis.iocs : [];
  for (const ioc of iocs) {
    if (String(ioc.type || '').toUpperCase() !== 'IP') continue;
    const details = ioc.details || {};
    const geo = asGeo(details);
    const lat = Number(geo.latitude ?? geo.lat);
    const lng = Number(geo.longitude ?? geo.lon ?? geo.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) continue;
    result.push({
      id: `ioc-${analysis.id}-${ioc.value}`,
      analysisId: analysis.id,
      ip: ioc.value,
      lat,
      lng,
      city: geo.city || '',
      country: geo.country || '',
      region: geo.subdivision || geo.region || '',
      asn: geo.asn || null,
      provider: geo.asn_organization || geo.provider || '',
      accuracy: geo.accuracy_radius_km,
      risk_flags: [...(ioc.risk_flags || []), ...(details.risk_flags || []), ...(geo.risk_flags || [])],
      suspicious: Boolean((ioc.risk_flags || []).length || (details.risk_flags || []).length),
      origin: false,
      label: `${ioc.type || 'IP'} · ${ioc.value}`,
    });
  }

  const hops = Array.isArray(analysis?.timeline) ? analysis.timeline.filter((x) => x.event === 'received_hop') : [];
  for (const hopEvent of hops) {
    const hop = hopEvent.value || {};
    const geo = asGeo(hop.geolocation || hop);
    const lat = Number(geo.latitude ?? geo.lat);
    const lng = Number(geo.longitude ?? geo.lon ?? geo.lng);
    if (!hop.ip || !Number.isFinite(lat) || !Number.isFinite(lng)) continue;
    if (result.some((p) => p.ip === hop.ip && p.lat === lat && p.lng === lng)) continue;
    result.push({
      id: `hop-${analysis.id}-${hop.ip}`,
      analysisId: analysis.id,
      ip: hop.ip,
      lat,
      lng,
      city: geo.city || '',
      country: geo.country || '',
      region: geo.subdivision || geo.region || '',
      asn: geo.asn || null,
      provider: geo.asn_organization || geo.provider || '',
      accuracy: geo.accuracy_radius_km,
      risk_flags: [...(hop.risk_flags || []), ...(geo.risk_flags || [])],
      suspicious: Boolean((hop.risk_flags || []).length),
      origin: Boolean(hop.is_probable_source || hop.probable_source || hop.earliest_visible_public_hop),
      label: `Relay hop · ${hop.ip}`,
    });
  }

  return result.map((p) => ({ ...p, origin: Boolean(p.origin || (probableIp && p.ip === probableIp)), risk: riskFrom({ ...p, origin: Boolean(p.origin || (probableIp && p.ip === probableIp)) }) }));
}

export default function ThreatMap({ compact = false, maxCases = 20 }) {
  const [points, setPoints] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);
  const [showOnlySuspicious, setShowOnlySuspicious] = useState(false);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const casesResponse = await getCases();
      const cases = Array.isArray(casesResponse?.data) ? casesResponse.data : casesResponse?.data?.items || [];
      const output = [];

      for (const c of cases.slice(0, maxCases)) {
        const summaryResponse = await getCaseAnalyses(c.id).catch(() => null);
        const analyses = summaryResponse?.data?.analyses || [];
        for (const summary of analyses.slice(0, 3)) {
          const fullResponse = await getAnalysis(summary.id).catch(() => null);
          if (fullResponse?.data) output.push(...extractPoints(fullResponse.data));
        }
      }

      const unique = Array.from(new Map(output.map((p) => [`${p.ip}-${p.lat}-${p.lng}`, p])).values());
      setPoints(unique);
      if (!unique.length) setSelected(null);
    } catch (e) {
      setError(e?.message || 'Could not load infrastructure geolocation data.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const visible = useMemo(
    () => showOnlySuspicious ? points.filter((p) => p.suspicious || p.risk === 'CRITICAL' || p.risk === 'HIGH') : points,
    [points, showOnlySuspicious]
  );

  const lines = useMemo(() => {
    const byAnalysis = new Map();
    visible.forEach((p) => {
      if (!byAnalysis.has(p.analysisId)) byAnalysis.set(p.analysisId, []);
      byAnalysis.get(p.analysisId).push(p);
    });
    return [...byAnalysis.entries()].map(([id, ps]) => ({ id, positions: ps.map((p) => [p.lat, p.lng]) })).filter((x) => x.positions.length > 1);
  }, [visible]);

  const stats = {
    total: points.length,
    suspicious: points.filter((p) => p.suspicious || p.risk === 'CRITICAL' || p.risk === 'HIGH').length,
    origin: points.filter((p) => p.origin).length,
  };

  return (
    <div className={`threat-map-shell ${compact ? 'compact' : ''}`}>
      <div className="map-toolbar">
        <div className="map-toolbar-copy">
          <div className="eyebrow">ORIGIN TRACEABILITY</div>
          <h3>Suspicious infrastructure map</h3>
          <p>Approximate IP/relay geolocation with risk context. A map point represents network infrastructure, not a confirmed person or physical attacker location.</p>
        </div>
        <div className="map-toolbar-actions">
          <label className="map-toggle">
            <input type="checkbox" checked={showOnlySuspicious} onChange={(e) => setShowOnlySuspicious(e.target.checked)} />
            <span>Suspicious only</span>
          </label>
          <button className="icon-btn map-refresh" onClick={load} disabled={loading} title="Refresh map data">
            <RefreshCw size={16} className={loading ? 'spin' : ''} />
          </button>
        </div>
      </div>

      <div className="map-stat-row">
        <span><MapPin size={14} /> {stats.total} mapped</span>
        <span className="map-stat-danger"><AlertTriangle size={14} /> {stats.suspicious} suspicious</span>
        <span><Crosshair size={14} /> {stats.origin} probable origin</span>
      </div>

      <div className="threat-map">
        <MapContainer
          center={CENTER}
          zoom={4}
          scrollWheelZoom={false}
          className="satguard-leaflet-map"
          zoomControl
          attributionControl
        >
          <TileLayer attribution="&copy; OpenStreetMap contributors" url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
          <MapResizeSync />
          <FitBounds points={visible} />
          {lines.map((line) => <Polyline key={line.id} positions={line.positions} pathOptions={{ color: '#168eb6', weight: 2, opacity: 0.45, dashArray: '5 7' }} />)}
          {visible.map((p) => (
            <Marker key={p.id} position={[p.lat, p.lng]} icon={markerIcon(p.risk, p.origin)} eventHandlers={{ click: () => setSelected(p) }}>
              <Popup>
                <div className="map-popup">
                  <b>{p.origin ? 'Probable source infrastructure' : p.label}</b>
                  <span><strong>IP:</strong> {p.ip}</span>
                  <span><strong>Location:</strong> {p.city || 'Unknown'}{p.region ? `, ${p.region}` : ''}{p.country ? `, ${p.country}` : ''}</span>
                  <span><strong>ASN:</strong> {p.asn || '—'}</span>
                  <span><strong>Provider:</strong> {p.provider || '—'}</span>
                  {p.accuracy != null && <span><strong>Accuracy radius:</strong> ~{p.accuracy} km</span>}
                  <RiskBadge level={p.risk} />
                  <small>Infrastructure geolocation is approximate and does not establish identity.</small>
                </div>
              </Popup>
            </Marker>
          ))}
          {!visible.length && <CircleMarker center={CENTER} radius={8} pathOptions={{ color: '#168eb6', fillColor: '#168eb6', fillOpacity: 0.3 }}><Popup>No geolocated public IPs are available yet. Add GeoLite2 City/ASN data to the backend for real coordinates.</Popup></CircleMarker>}
        </MapContainer>
        <div className="map-legend">
          <span><i className="legend-dot critical" /> Critical</span>
          <span><i className="legend-dot high" /> High</span>
          <span><i className="legend-dot medium" /> Context</span>
          <span><i className="legend-dot origin" /> Probable origin</span>
        </div>
        {loading && <div className="map-loading"><RefreshCw size={13} className="spin" /> Updating infrastructure…</div>}
        {error && <div className="map-error">{error}</div>}
      </div>

      {!compact && (
        <div className="map-details-grid">
          <div className="map-selected glass-card">
            <div className="eyebrow">SELECTED INFRASTRUCTURE</div>
            {selected ? (
              <>
                <h4>{selected.ip}</h4>
                <p>{selected.city || 'Unknown city'}{selected.region ? `, ${selected.region}` : ''}{selected.country ? ` · ${selected.country}` : ''}</p>
                <div className="map-detail-chips"><span>ASN {selected.asn || '—'}</span><span>{selected.provider || 'Provider unavailable'}</span><RiskBadge level={selected.risk} /></div>
              </>
            ) : <p>Tap a map marker to inspect its infrastructure context.</p>}
          </div>
          <div className="map-coverage glass-card">
            <div className="eyebrow">EVIDENCE NOTE</div>
            <p>Use the map to correlate relay hops, IP reputation, ASN/cloud context and the earliest reliable public hop. Do not present an IP geolocation as the attacker's exact physical location.</p>
          </div>
        </div>
      )}
    </div>
  );
}

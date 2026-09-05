import {
  CircleMarker,
  MapContainer,
  Polyline,
  Popup,
  TileLayer,
} from "react-leaflet";
import { MapPinned } from "lucide-react";

import "leaflet/dist/leaflet.css";

function getRiskColor(ipInfo) {
  const flags = ipInfo?.risk_flags || [];

  if (
    flags.includes("high_abuse_confidence") ||
    flags.includes("reported_abuse")
  ) {
    return "#ef4444";
  }

  if (
    flags.includes("untrusted_origin_hop") ||
    flags.includes("cloud_hosting_infrastructure")
  ) {
    return "#f59e0b";
  }

  return "#22c55e";
}

function getRiskLabel(ipInfo) {
  const flags = ipInfo?.risk_flags || [];

  if (
    flags.includes("high_abuse_confidence") ||
    flags.includes("reported_abuse")
  ) {
    return "High-risk infrastructure";
  }

  if (flags.length > 0) {
    return "Requires analyst review";
  }

  return "No enrichment risk flag";
}

function InfrastructureMap({ ipIndicators, receivedHops }) {
  const safeIpIndicators = ipIndicators || [];

  const mapPoints = safeIpIndicators
    .filter((item) => {
      const geo = item?.geolocation || {};

      const isPrivate =
        geo?.asn_organization === "Private" ||
        geo?.asn_organization === "Reserved" ||
        geo?.country === "Private" ||
        geo?.country === "Reserved";

      const hasValidCoords =
        typeof geo?.latitude === "number" &&
        typeof geo?.longitude === "number";

      const isPublic = item?.ip_scope === "public";

      return hasValidCoords && !isPrivate && isPublic;
    })
    .map((item) => ({
      ...item,
      coordinates: [
        item.geolocation.latitude,
        item.geolocation.longitude,
      ],
    }));

  const routeCoordinates = (receivedHops || [])
    .map((hop) => {
      const matchedIp = mapPoints.find(
        (item) => item.ip === hop.ip
      );

      return matchedIp ? matchedIp.coordinates : null;
    })
    .filter(Boolean);

  if (mapPoints.length === 0) {
    return (
      <section className="panel map-panel">
        <div className="section-header">
          <div>
            <p className="eyebrow">
              Approximate infrastructure context
            </p>
            <h2>IP Hop Map</h2>
          </div>

          <MapPinned size={25} />
        </div>

        <div className="empty-map">
          No public IPs with valid GeoIP coordinates are available.
          <br />
          Install valid GeoLite2 City/ASN databases or connect a
          permitted GeoIP provider to populate this map.
        </div>
      </section>
    );
  }

  return (
    <section className="panel map-panel">
      <div className="section-header">
        <div>
          <p className="eyebrow">
            Approximate infrastructure context
          </p>
          <h2>IP Hop Map</h2>
        </div>

        <MapPinned size={25} />
      </div>

      <p className="map-note">
        This map visualizes approximate public network infrastructure
        locations from visible mail relay IPs. It does not identify a
        person or confirm an attacker's physical location.
      </p>

      <div className="map-legend">
        <span>
          <i className="legend-green" />
          No enrichment risk flag
        </span>

        <span>
          <i className="legend-orange" />
          Requires review
        </span>

        <span>
          <i className="legend-red" />
          High-risk infrastructure
        </span>
      </div>

      <div className="map-box">
        <MapContainer
          center={mapPoints[0].coordinates}
          zoom={2}
          scrollWheelZoom
          style={{
            height: "480px",
            width: "100%",
          }}
        >
          <TileLayer
            attribution="&copy; OpenStreetMap contributors"
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />

          {routeCoordinates.length > 1 && (
            <Polyline
              positions={routeCoordinates}
              pathOptions={{
                color: "#60a5fa",
                weight: 3,
                dashArray: "8 8",
              }}
            />
          )}

          {mapPoints.map((ipInfo, index) => {
            const geo = ipInfo.geolocation || {};
            const riskFlags = ipInfo.risk_flags || [];
            const markerColor = getRiskColor(ipInfo);

            return (
              <CircleMarker
                center={ipInfo.coordinates}
                key={ipInfo.ip}
                radius={11}
                pathOptions={{
                  color: markerColor,
                  fillColor: markerColor,
                  fillOpacity: 0.82,
                  weight: 3,
                }}
              >
                <Popup>
                  <div className="map-popup">
                    <strong>Relay Hop {index + 1}</strong>
                    <br />

                    <strong>IP:</strong> {ipInfo.ip}
                    <br />

                    <strong>Location:</strong>{" "}
                    {geo.city || "Unknown"},{" "}
                    {geo.subdivision || ""}
                    {geo.subdivision ? ", " : ""}
                    {geo.country || "Unknown"}
                    <br />

                    <strong>ASN:</strong>{" "}
                    {geo.asn || "Unknown"}
                    <br />

                    <strong>Organization:</strong>{" "}
                    {geo.asn_organization || "Unknown"}
                    <br />

                    <strong>Accuracy radius:</strong>{" "}
                    {geo.accuracy_radius_km ?? "Unknown"} km
                    <br />

                    <strong>Assessment:</strong>{" "}
                    {getRiskLabel(ipInfo)}
                    <br />

                    <strong>Risk flags:</strong>{" "}
                    {riskFlags.length > 0
                      ? riskFlags.join(", ")
                      : "None"}
                  </div>
                </Popup>
              </CircleMarker>
            );
          })}
        </MapContainer>
      </div>
    </section>
  );
}

export default InfrastructureMap;
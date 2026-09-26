import React from 'react';
import { Globe2 } from 'lucide-react';
import { PageHeader, Section } from '../components/ui';
import ThreatMap from '../components/ThreatMap';

export default function ThreatMapPage() {
  return (
    <>
      <PageHeader
        eyebrow="INVESTIGATION / GEOLOCATION"
        title="Infrastructure & Origin Map"
        subtitle="Trace suspicious relay infrastructure, approximate geolocation and probable source context from analyzed email evidence."
        actions={
          <span className="live-pill map-page-pill">
            <Globe2 size={13} /> LIVE INFRASTRUCTURE VIEW
          </span>
        }
      />
      <Section
        title="Threat infrastructure"
        subtitle="Leaflet + OpenStreetMap. Locations are approximate network intelligence, not identity attribution."
      >
        <ThreatMap />
      </Section>
    </>
  );
}

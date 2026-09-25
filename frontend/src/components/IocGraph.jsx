import CytoscapeComponent from "react-cytoscapejs";
import {
  FileWarning,
  Globe2,
  Link2,
  Mail,
  Network,
  Server,
} from "lucide-react";

import { buildGraphElements } from "../utils/graphBuilder";

function IocGraph({ data }) {
  const elements = buildGraphElements(data || {});

  const stylesheet = [
    {
      selector: "node",
      style: {
        label: "data(label)",
        color: "#e5e7eb",
        "font-size": "10px",
        "font-weight": 600,
        "text-wrap": "wrap",
        "text-max-width": "115px",
        "text-valign": "center",
        "text-halign": "center",
        width: 58,
        height: 58,
        "border-width": 2,
        "border-color": "#94a3b8",
        "background-color": "#334155",
      },
    },
    {
      selector: 'node[type = "email"]',
      style: {
        shape: "round-rectangle",
        width: 115,
        height: 64,
        "background-color": "#2563eb",
        "border-color": "#93c5fd",
      },
    },
    {
      selector: 'node[type = "domain"]',
      style: {
        "background-color": "#7c3aed",
        "border-color": "#c4b5fd",
      },
    },
    {
      selector: 'node[type = "url"]',
      style: {
        "background-color": "#dc2626",
        "border-color": "#fca5a5",
      },
    },
    {
      selector: 'node[type = "ip"]',
      style: {
        "background-color": "#0891b2",
        "border-color": "#67e8f9",
      },
    },
    {
      selector: 'node[type = "asn"]',
      style: {
        shape: "diamond",
        "background-color": "#059669",
        "border-color": "#6ee7b7",
      },
    },
    {
      selector: 'node[type = "attachment"]',
      style: {
        shape: "hexagon",
        "background-color": "#ea580c",
        "border-color": "#fdba74",
      },
    },
    {
      selector: 'node[type = "hash"]',
      style: {
        shape: "round-rectangle",
        width: 125,
        height: 48,
        "background-color": "#475569",
        "border-color": "#cbd5e1",
      },
    },
    {
      selector: 'node[risk = "critical"]',
      style: {
        "border-width": 5,
        "border-color": "#facc15",
      },
    },
    {
      selector: 'node[risk = "high"]',
      style: {
        "border-width": 4,
        "border-color": "#fb7185",
      },
    },
    {
      selector: 'node[risk = "medium"]',
      style: {
        "border-width": 4,
        "border-color": "#f59e0b",
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": "#64748b",
        "target-arrow-color": "#64748b",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        label: "data(label)",
        color: "#94a3b8",
        "font-size": "8px",
        "text-rotation": "autorotate",
      },
    },
    {
      selector: "node:selected",
      style: {
        "overlay-color": "#60a5fa",
        "overlay-opacity": 0.25,
        "overlay-padding": 12,
      },
    },
  ];

  return (
    <section className="panel graph-panel">
      <div className="section-header">
        <div>
          <p className="eyebrow">Connected forensic evidence</p>
          <h2>IOC Infrastructure Relationship Graph</h2>
        </div>

        <Network size={25} />
      </div>

      <p className="map-note">
        Explore relationships between the email, claimed sender
        identities, suspicious URLs, relay IPs, network organizations,
        and attachment hashes. Click and drag nodes to inspect the
        evidence structure.
      </p>

      <div className="graph-legend">
        <span>
          <Mail size={14} />
          Email
        </span>

        <span>
          <Globe2 size={14} />
          Domain
        </span>

        <span>
          <Link2 size={14} />
          URL
        </span>

        <span>
          <Server size={14} />
          IP / ASN
        </span>

        <span>
          <FileWarning size={14} />
          Attachment / Hash
        </span>
      </div>

      <div className="graph-box">
        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet}
          layout={{
            name: "cose",
            animate: true,
            fit: true,
            padding: 40,
            nodeRepulsion: 8000,
            idealEdgeLength: 120,
          }}
          style={{
            width: "100%",
            height: "550px",
          }}
          cy={(cy) => {
            cy.on("tap", "node", (event) => {
              const node = event.target;

              console.log("Selected graph node:", {
                id: node.id(),
                label: node.data("label"),
                type: node.data("type"),
                risk: node.data("risk"),
              });
            });
          }}
        />
      </div>

      <div className="graph-risk-note">
        <span className="critical-dot" />
        Yellow outline = critical indicator

        <span className="high-dot" />
        Pink outline = high-risk indicator

        <span className="medium-dot" />
        Orange outline = medium-risk indicator
      </div>
    </section>
  );
}

export default IocGraph;
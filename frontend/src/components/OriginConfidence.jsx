import { Info, MapPin, Radar } from "lucide-react";

function OriginConfidence({ probableSource }) {
  const sourceHop = probableSource.earliest_visible_public_hop;

  return (
    <section className="origin-card">
      <div className="origin-icon">
        <Radar size={28} />
      </div>

      <div className="origin-content">
        <p className="eyebrow">Infrastructure attribution</p>
        <h2>Probable Source Context</h2>

        {sourceHop ? (
          <>
            <div className="origin-details">
              <span>
                <MapPin size={17} />
                Earliest visible public IP:
              </span>

              <strong>{sourceHop.ip}</strong>
            </div>

            <div className="origin-details">
              <span>Visible source host:</span>
              <strong>{sourceHop.from_host}</strong>
            </div>
          </>
        ) : (
          <p className="muted-text">
            No safely usable public relay IP was identified.
          </p>
        )}

        <span
          className={`confidence-badge confidence-${probableSource.confidence}`}
        >
          {probableSource.confidence.toUpperCase()} CONFIDENCE
        </span>

        <div className="origin-limitation">
          <Info size={17} />
          <p>{probableSource.limitation}</p>
        </div>
      </div>
    </section>
  );
}

export default OriginConfidence;
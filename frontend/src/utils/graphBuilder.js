function safeId(value) {
  return String(value || "unknown")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "-");
}

function createNode(id, label, type, risk = "low") {
  return {
    data: {
      id,
      label,
      type,
      risk,
    },
  };
}

function createEdge(id, source, target, label) {
  return {
    data: {
      id,
      source,
      target,
      label,
    },
  };
}

export function buildGraphElements(data = {}) {
  const elements = [];

  const senderIdentity = data.sender_identity || {};
  const indicators = data.indicators || {};

  const urls = indicators.urls || [];
  const ips = indicators.ips || [];
  const attachments = indicators.attachments || [];

  const emailNodeId = `email-${safeId(data.case_id)}`;

  elements.push(
    createNode(
      emailNodeId,
      "Suspicious Email",
      "email",
      "high"
    )
  );

  const senderDomains = [
    {
      domain: senderIdentity.from?.domain || "",
      relation: "VISIBLE_FROM",
      risk: "high",
    },
    {
      domain: senderIdentity.reply_to?.domain || "",
      relation: "REPLY_TO",
      risk: "high",
    },
    {
      domain: senderIdentity.return_path?.domain || "",
      relation: "RETURN_PATH",
      risk: "medium",
    },
  ];

  senderDomains.forEach((item) => {
    if (!item.domain) return;

    const domainNodeId = `domain-${safeId(item.domain)}`;

    elements.push(
      createNode(
        domainNodeId,
        item.domain,
        "domain",
        item.risk
      )
    );

    elements.push(
      createEdge(
        `edge-${emailNodeId}-${domainNodeId}-${item.relation}`,
        emailNodeId,
        domainNodeId,
        item.relation
      )
    );
  });

    urls.forEach((url, index) => {
    const urlNodeId = `url-${index}-${safeId(url.hostname)}`;

    const urlRisk =
      url.risk_flags.length > 0 ? "critical" : "low";

    elements.push(
      createNode(
        urlNodeId,
        url.hostname || url.url,
        "url",
        urlRisk
      )
    );

    elements.push(
      createEdge(
        `edge-${emailNodeId}-${urlNodeId}`,
        emailNodeId,
        urlNodeId,
        "CONTAINS_URL"
      )
    );

    if (url.registered_domain) {
      const destinationDomainNodeId =
        `domain-${safeId(url.registered_domain)}`;

      elements.push(
        createNode(
          destinationDomainNodeId,
          url.registered_domain,
          "domain",
          urlRisk
        )
      );

      elements.push(
        createEdge(
          `edge-${urlNodeId}-${destinationDomainNodeId}`,
          urlNodeId,
          destinationDomainNodeId,
          "HOSTED_ON_DOMAIN"
        )
      );
    }
  });

  ips.forEach((ipInfo) => {
    const ipNodeId = `ip-${safeId(ipInfo.ip)}`;

    const ipRisk =
      ipInfo.risk_flags.length > 0 ? "medium" : "low";

    elements.push(
      createNode(
        ipNodeId,
        ipInfo.ip,
        "ip",
        ipRisk
      )
    );

    elements.push(
      createEdge(
        `edge-${emailNodeId}-${ipNodeId}`,
        emailNodeId,
        ipNodeId,
        "RELAYED_THROUGH"
      )
    );

    const geo = ipInfo.geolocation || {};
    const asn = geo.asn;
    const organization = geo.asn_organization;

    if (asn && organization) {
      const asnNodeId = `asn-${safeId(asn)}`;

      elements.push(
        createNode(
          asnNodeId,
          `${asn} · ${organization}`,
          "asn",
          "low"
        )
      );

      elements.push(
        createEdge(
          `edge-${ipNodeId}-${asnNodeId}`,
          ipNodeId,
          asnNodeId,
          "BELONGS_TO"
        )
      );
    }
  });

  attachments.forEach(
    (attachment, index) => {
      const attachmentNodeId =
        `attachment-${index}-${safeId(attachment.filename)}`;

      const attachmentRisk =
        attachment.risk_flags.length > 0
          ? "critical"
          : "low";

      elements.push(
        createNode(
          attachmentNodeId,
          attachment.filename,
          "attachment",
          attachmentRisk
        )
      );

      elements.push(
        createEdge(
          `edge-${emailNodeId}-${attachmentNodeId}`,
          emailNodeId,
          attachmentNodeId,
          "HAS_ATTACHMENT"
        )
      );

      if (attachment.sha256) {
        const hashNodeId =
          `hash-${safeId(attachment.sha256)}`;

        elements.push(
          createNode(
            hashNodeId,
            `SHA-256: ${attachment.sha256.slice(0, 12)}...`,
            "hash",
            attachmentRisk
          )
        );

        elements.push(
          createEdge(
            `edge-${attachmentNodeId}-${hashNodeId}`,
            attachmentNodeId,
            hashNodeId,
            "HAS_HASH"
          )
        );
      }
    }
  );

  return removeDuplicateElements(elements);
}

function removeDuplicateElements(elements) {
  const seenNodes = new Set();
  const seenEdges = new Set();

  return elements.filter((element) => {
    if (element.data.source && element.data.target) {
      if (seenEdges.has(element.data.id)) {
        return false;
      }

      seenEdges.add(element.data.id);
      return true;
    }

    if (seenNodes.has(element.data.id)) {
      return false;
    }

    seenNodes.add(element.data.id);
    return true;
  });
}
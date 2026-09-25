const sampleForensicData = {
  case_id: "CASE-20260905-DEMO1234",

  evidence: {
    source_name: "hidden_link_test.eml",
    evidence_hash_sha256:
      "8a1c7e3d44aaf0dc3190a7f3c0d44e51d3c94baf66cc1d4b9ef0f2177b4e8a11",
    analysis_timestamp_utc: "2026-09-05T00:30:00+00:00",
    evidence_size_bytes: 2840,
    hash_algorithm: "SHA-256",
  },

  message_metadata: {
    subject: "Urgent Account Verification Required",
    message_id: "<hidden-link-test@example.com>",
    date: "Fri, 04 Sep 2026 15:00:00 +0000",
  },

  sender_identity: {
    from: {
      display_name: "Microsoft Security",
      email_address: "security@micros0ft-alert.example",
      domain: "micros0ft-alert.example",
    },

    reply_to: {
      display_name: "",
      email_address: "verify@secure-login-check.example",
      domain: "secure-login-check.example",
    },

    return_path: {
      display_name: "",
      email_address: "bounce@mailer.example",
      domain: "mailer.example",
    },

    analysis: {
      risk_flags: [
        "from_reply_to_domain_mismatch",
        "from_return_path_domain_mismatch",
        "brand_lookalike_domain",
        "display_name_impersonation",
      ],
    },
  },

  email_authentication: {
    reported_results: {
      spf: "fail",
      dkim: "none",
      dmarc: "fail",
    },

    dmarc_forensic_assessment: {
      assessment: "likely_fail",
      visible_from_domain: "micros0ft-alert.example",
      dmarc_dns_policy: "none",
    },
  },

  relay_analysis: {
    received_hops: [
      {
        hop: 1,
        from_host: "unknown-origin-host.example",
        by_host: "relay-node.example",
        ip: "8.8.8.8",
        ip_scope: "public",
        timestamp_utc: "2026-09-04T15:00:00+00:00",
        trusted: false,
        risk_flags: ["untrusted_origin_hop"],
      },
      {
        hop: 2,
        from_host: "relay-node.example",
        by_host: "mx.company.example",
        ip: "1.1.1.1",
        ip_scope: "public",
        timestamp_utc: "2026-09-04T15:00:05+00:00",
        trusted: true,
        risk_flags: [],
      },
    ],

    probable_source: {
      earliest_visible_public_hop: {
        ip: "8.8.8.8",
        from_host: "unknown-origin-host.example",
      },
      confidence: "low",
      limitation:
        "Visible relay infrastructure is not proof of a person's identity or exact location.",
    },
  },

  indicators: {
    ips: [
      {
        ip: "8.8.8.8",
        ip_scope: "public",
        geolocation: {
          country: "United States",
          country_iso_code: "US",
          city: "Mountain View",
          subdivision: "California",
          latitude: 37.4056,
          longitude: -122.0775,
          accuracy_radius_km: 1000,
          asn: 15169,
          asn_organization: "Google LLC",
        },
        reputation: {
          source: "offline_fallback",
          status: "ok",
          abuse_confidence_score: 0,
          risk_flags: [],
        },
        risk_flags: ["untrusted_origin_hop"],
      },
      {
        ip: "1.1.1.1",
        ip_scope: "public",
        geolocation: {
          country: "Australia",
          country_iso_code: "AU",
          city: "Sydney",
          subdivision: "New South Wales",
          latitude: -33.8688,
          longitude: 151.2093,
          accuracy_radius_km: 1000,
          asn: 13335,
          asn_organization: "Cloudflare Inc.",
        },
        reputation: {
          source: "offline_fallback",
          status: "ok",
          abuse_confidence_score: 0,
          risk_flags: [],
        },
        risk_flags: [],
      },
    ],

    urls: [
      {
        url: "http://secure-login-check.example/verify?account=user",
        visible_text: "https://www.microsoft.com",
        hostname: "secure-login-check.example",
        registered_domain: "secure-login-check.example",
        source: "html_anchor",
        risk_flags: [
          "visible_link_destination_mismatch",
          "known_malicious_url",
        ],
        reputation: {
          source: "offline_fallback",
          status: "ok",
          threat: "phishing",
          risk_flags: [
            "known_malicious_url",
            "phishing_indicator",
          ],
        },
      },
      {
        url: "https://bit.ly/demo-security-link",
        visible_text: "Verify your account",
        hostname: "bit.ly",
        registered_domain: "bit.ly",
        source: "html_anchor",
        risk_flags: ["shortened_url"],
      },
    ],

    domains: [
      "micros0ft-alert.example",
      "secure-login-check.example",
      "mailer.example",
    ],

    attachments: [
      {
        filename: "invoice.pdf.exe",
        mime_type: "application/octet-stream",
        size_bytes: 48,
        sha256:
          "a564e89f2b1d2d9132cefb4a0d19d0b0d1c643e2c5e7e1b2d3e4f5a6b7c8d9e0",
        risk_flags: [
          "dangerous_extension",
          "double_extension",
        ],
      },
    ],
  },

  forensic_findings: [
    {
      severity: "high",
      category: "email_authentication",
      message: "Receiver-reported SPF validation failed.",
    },
    {
      severity: "high",
      category: "email_authentication",
      message: "Receiver-reported DMARC validation failed.",
    },
    {
      severity: "high",
      category: "url_deception",
      message:
        "Visible hyperlink text and actual destination domain do not match.",
    },
    {
      severity: "critical",
      category: "threat_intelligence",
      message:
        "URL matched threat-intelligence data: secure-login-check.example.",
    },
    {
      severity: "high",
      category: "attachment",
      message:
        "Attachment invoice.pdf.exe has a dangerous double extension.",
    },
  ],
};

export default sampleForensicData;
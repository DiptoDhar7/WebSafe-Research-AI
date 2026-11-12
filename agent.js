const https = require("https");
const http = require("http");
const dns = require("dns").promises;

const input = process.argv[2] || "https://example.com";

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 8000;
const MAX_BODY = 30000;

const USER_AGENT =
  "WebSafe-Research-AI/2.0 (public-research-only)";

function normalizeUrl(value) {
  const raw = String(value || "").trim();

  if (!raw) {
    throw new Error("No website URL was provided.");
  }

  return /^https?:\/\//i.test(raw)
    ? raw
    : "https://" + raw;
}

function requestOnce(targetUrl) {
  return new Promise((resolve, reject) => {
    let parsedUrl;

    try {
      parsedUrl = new URL(targetUrl);
    } catch {
      reject(new Error("Invalid website URL."));
      return;
    }

    if (
      parsedUrl.protocol !== "https:" &&
      parsedUrl.protocol !== "http:"
    ) {
      reject(
        new Error("Only HTTP and HTTPS websites are supported.")
      );
      return;
    }

    const client =
      parsedUrl.protocol === "https:" ? https : http;

    const request = client.get(
      targetUrl,
      {
        timeout: TIMEOUT_MS,

        headers: {
          "User-Agent": USER_AGENT,
          "Accept":
            "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.8"
        }
      },

      (response) => {
        const headers = {};

        for (const [key, value] of Object.entries(
          response.headers
        )) {
          headers[key.toLowerCase()] = value;
        }

        let location = null;

        if (headers.location) {
          try {
            location = new URL(
              headers.location,
              targetUrl
            ).href;
          } catch {
            location = null;
          }
        }

        const socket = response.socket;

        const tls =
          socket && socket.encrypted
            ? {
                protocol:
                  typeof socket.getProtocol === "function"
                    ? socket.getProtocol()
                    : null,

                authorized:
                  typeof socket.authorized === "boolean"
                    ? socket.authorized
                    : null,

                authorizationError:
                  socket.authorizationError || null,

                certificate:
                  typeof socket.getPeerCertificate ===
                  "function"
                    ? socket.getPeerCertificate()
                    : null
              }
            : null;

        let body = "";

        response.setEncoding("utf8");

        response.on("data", (chunk) => {
          if (body.length < MAX_BODY) {
            body += chunk.slice(
              0,
              MAX_BODY - body.length
            );
          }
        });

        response.on("end", () => {
          resolve({
            targetUrl,
            statusCode:
              response.statusCode || 0,
            headers,
            location,
            body,
            tls
          });
        });

        response.on("error", reject);
      }
    );

    request.on("timeout", () => {
      request.destroy(
        new Error("Website request timed out.")
      );
    });

    request.on("error", reject);
  });
}

async function followRedirects(startUrl) {
  const chain = [];

  let currentUrl = startUrl;

  for (
    let attempt = 0;
    attempt <= MAX_REDIRECTS;
    attempt++
  ) {
    const result =
      await requestOnce(currentUrl);

    chain.push({
      url: currentUrl,
      statusCode: result.statusCode,
      location: result.location
    });

    const isRedirect =
      result.statusCode >= 300 &&
      result.statusCode < 400;

    if (
      isRedirect &&
      result.location
    ) {
      if (
        attempt === MAX_REDIRECTS
      ) {
        return {
          final: result,
          chain,
          redirectLimit: true
        };
      }

      currentUrl =
        result.location;

      continue;
    }

    return {
      final: result,
      chain,
      redirectLimit: false
    };
  }

  throw new Error(
    "Redirect analysis failed."
  );
}

function headerExists(headers, name) {
  return Boolean(
    headers[name.toLowerCase()]
  );
}

function isIpAddress(hostname) {
  return (
    /^\d{1,3}(\.\d{1,3}){3}$/.test(
      hostname
    ) ||
    hostname.includes(":")
  );
}

function analyzeDomain(url) {
  const parsed =
    new URL(url);

  const hostname =
    parsed.hostname.toLowerCase();

  const warnings = [];

  if (isIpAddress(hostname)) {
    warnings.push(
      "IP address used instead of a normal domain"
    );
  }

  if (hostname.includes("xn--")) {
    warnings.push(
      "Punycode hostname detected"
    );
  }

  if (hostname.length > 45) {
    warnings.push(
      "Unusually long hostname"
    );
  }

  if (
    (hostname.match(/-/g) || [])
      .length >= 3
  ) {
    warnings.push(
      "Multiple hyphens in hostname"
    );
  }

  if (
    (hostname.match(/\./g) || [])
      .length >= 4
  ) {
    warnings.push(
      "Deep subdomain structure"
    );
  }

  const cautionTlds = [
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".work",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
    ".ga"
  ];

  if (
    cautionTlds.some((tld) =>
      hostname.endsWith(tld)
    )
  ) {
    warnings.push(
      "Domain ending requires additional caution"
    );
  }

  return {
    hostname,
    warnings
  };
}

function analyzeSecurityHeaders(headers) {
  const checks = {
    hsts: headerExists(
      headers,
      "strict-transport-security"
    ),

    csp: headerExists(
      headers,
      "content-security-policy"
    ),

    xContentType: headerExists(
      headers,
      "x-content-type-options"
    ),

    xFrame: headerExists(
      headers,
      "x-frame-options"
    ),

    referrer: headerExists(
      headers,
      "referrer-policy"
    ),

    permissions: headerExists(
      headers,
      "permissions-policy"
    )
  };

  return {
    checks,
    count:
      Object.values(checks)
        .filter(Boolean)
        .length
  };
}

function stripHtml(html) {
  return html
    .replace(
      /<script[\s\S]*?<\/script>/gi,
      " "
    )
    .replace(
      /<style[\s\S]*?<\/style>/gi,
      " "
    )
    .replace(
      /<[^>]+>/g,
      " "
    )
    .replace(
      /&nbsp;/gi,
      " "
    )
    .replace(
      /&amp;/gi,
      "&"
    )
    .replace(
      /\s+/g,
      " "
    )
    .trim();
}

function analyzePage(
  body,
  finalUrl
) {
  const title =
    (
      body.match(
        /<title[^>]*>([\s\S]*?)<\/title>/i
      ) || [null, ""]
    )[1]
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 160);

  const description =
    (
      body.match(
        /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i
      ) ||
      body.match(
        /<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i
      ) ||
      [null, ""]
    )[1]
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 220);

  const text =
    stripHtml(body).toLowerCase();

  const signals = [];

  const patterns = [
    [
      /(password|sign in|log in|login|create account|register)/i,
      "Account/login language detected"
    ],

    [
      /(credit card|debit card|payment|pay now|checkout|deposit|withdraw)/i,
      "Payment-related language detected"
    ],

    [
      /(download now|free download|download link|apk download)/i,
      "Download-related language detected"
    ],

    [
      /(18\+|adult content|nsfw)/i,
      "Adult-content signal detected"
    ],

    [
      /(bet now|casino|sportsbook|gambling|jackpot)/i,
      "Gambling-related language detected"
    ],

    [
      /(urgent|act now|limited time|claim now|congratulations)/i,
      "High-pressure promotional language detected"
    ]
  ];

  for (
    const [pattern, message]
    of patterns
  ) {
    if (pattern.test(text)) {
      signals.push(message);
    }
  }

  const externalLinks =
    new Set();

  const hrefRegex =
    /href=["']([^"']+)["']/gi;

  let match;

  while (
    (match =
      hrefRegex.exec(body)) !== null &&
    externalLinks.size < 30
  ) {
    try {
      const link =
        new URL(
          match[1],
          finalUrl
        );

      if (
        link.hostname &&
        link.hostname !==
          new URL(finalUrl).hostname
      ) {
        externalLinks.add(
          link.hostname
        );
      }
    } catch {}
  }

  return {
    title:
      title || null,

    description:
      description || null,

    contentSignals:
      signals,

    externalDomains:
      [...externalLinks]
  };
}

function analyzeAds(
  body,
  finalUrl
) {
  const lower =
    body.toLowerCase();

  const adPatterns = [
    /googleads/i,
    /googlesyndication/i,
    /doubleclick/i,
    /adsbygoogle/i,
    /adservice\.google/i,
    /\badsterra\b/i,
    /\bpropellerads\b/i,
    /\bpopads\b/i,
    /\badskeeper\b/i,
    /\btaboola\b/i,
    /\boutbrain\b/i,

    /class=["'][^"']*(ad|advert|banner)[^"']*["']/i,

    /id=["'][^"']*(ad|advert|banner)[^"']*["']/i
  ];

  const adHits =
    adPatterns.filter(
      (pattern) =>
        pattern.test(lower)
    ).length;

  const popupSignals = [
    /window\.open\s*\(/i,
    /popunder/i,
    /onclick=["'][^"']*(window\.open|location\.href)/i,
    /beforeunload/i
  ].filter(
    (pattern) =>
      pattern.test(body)
  ).length;

  const adLinkCount =
    (
      body.match(
        /\b(ad|advert|advertisement|ads)\b/gi
      ) || []
    ).length;

  const excessive =
    adHits >= 4 ||
    adLinkCount >= 12 ||
    popupSignals >= 2;

  const suspicious =
    /casino|betting|gambling|adult|crypto.*deposit|free.*prize|claim.*reward/i.test(
      stripHtml(body)
    );

  return {
    detected:
      adHits > 0 ||
      adLinkCount > 0,

    adHits,

    popupSignals,

    excessive,

    suspicious,

    externalAdSignals:
      adHits
  };
}

async function analyzeDns(
  hostname
) {
  if (isIpAddress(hostname)) {
    return {
      a: [],
      aaaa: [],
      mx: [],
      ns: [],
      errors: []
    };
  }

  const result = {
    a: [],
    aaaa: [],
    mx: [],
    ns: [],
    errors: []
  };

  const jobs = [
    ["a", dns.resolve4(hostname)],
    ["aaaa", dns.resolve6(hostname)],
    ["mx", dns.resolveMx(hostname)],
    ["ns", dns.resolveNs(hostname)]
  ];

  const settled =
    await Promise.allSettled(
      jobs.map(
        ([, promise]) =>
          promise
      )
    );

  settled.forEach(
    (item, index) => {
      const key =
        jobs[index][0];

      if (
        item.status ===
        "fulfilled"
      ) {
        result[key] =
          item.value;
      } else {
        result.errors.push(
          `${key.toUpperCase()} lookup unavailable`
        );
      }
    }
  );

  return result;
}

function getCertificateInfo(
  tls
) {
  if (
    !tls ||
    !tls.certificate ||
    !Object.keys(
      tls.certificate
    ).length
  ) {
    return null;
  }

  const cert =
    tls.certificate;

  return {
    subject:
      cert.subject?.CN ||
      null,

    issuer:
      cert.issuer?.CN ||
      cert.issuer?.O ||
      null,

    validFrom:
      cert.valid_from ||
      null,

    validTo:
      cert.valid_to ||
      null,

    subjectAltName:
      cert.subjectaltname ||
      null,

    fingerprint256:
      cert.fingerprint256 ||
      null
  };
}

async function getRdapInfo(
  hostname
) {
  if (
    isIpAddress(hostname) ||
    hostname.includes(
      "localhost"
    )
  ) {
    return null;
  }

  return new Promise(
    (resolve) => {
      const target =
        `https://rdap.org/domain/${encodeURIComponent(
          hostname
        )}`;

      const request =
        https.get(
          target,
          {
            timeout:
              TIMEOUT_MS,

            headers: {
              "User-Agent":
                USER_AGENT,

              Accept:
                "application/rdap+json, application/json"
            }
          },

          (response) => {
            let body = "";

            response.setEncoding(
              "utf8"
            );

            response.on(
              "data",
              (chunk) => {
                if (
                  body.length <
                  15000
                ) {
                  body +=
                    chunk.slice(
                      0,
                      15000 -
                        body.length
                    );
                }
              }
            );

            response.on(
              "end",
              () => {
                try {
                  if (
                    response.statusCode >=
                      200 &&
                    response.statusCode <
                      300
                  ) {
                    const data =
                      JSON.parse(
                        body
                      );

                    const events =
                      Array.isArray(
                        data.events
                      )
                        ? data.events
                        : [];

                    const registration =
                      events.find(
                        (event) =>
                          event.eventAction ===
                          "registration"
                      )?.eventDate ||
                      null;

                    const expiration =
                      events.find(
                        (event) =>
                          event.eventAction ===
                          "expiration"
                      )?.eventDate ||
                      null;

                    resolve({
                      status:
                        "available",

                      registration,

                      expiration,

                      registrar:
                        data.entities
                          ?.find(
                            (entity) =>
                              Array.isArray(
                                entity.roles
                              ) &&
                              entity.roles.includes(
                                "registrar"
                              )
                          )
                          ?.vcardArray?.[3]?.[1] ||
                        null
                    });

                    return;
                  }

                  resolve({
                    status:
                      "unavailable"
                  });
                } catch {
                  resolve({
                    status:
                      "unavailable"
                  });
                }
              }
            );

            response.on(
              "error",
              () =>
                resolve({
                  status:
                    "unavailable"
                })
            );
          }
        );

      request.on(
        "timeout",
        () => {
          request.destroy();
        }
      );

      request.on(
        "error",
        () =>
          resolve({
            status:
              "unavailable"
          })
      );
    }
  );
}

function calculateRisk(
  data
) {
  let score = 0;

  const reasons = [];

  const finalUrl =
    new URL(
      data.final.targetUrl
    );

  const originalUrl =
    new URL(
      data.startUrl
    );

  if (
    finalUrl.protocol !==
    "https:"
  ) {
    score += 25;

    reasons.push(
      "The final website does not use HTTPS."
    );
  } else {
    reasons.push(
      "The final website uses HTTPS."
    );
  }

  if (
    data.final.statusCode >=
    400
  ) {
    score += 20;

    reasons.push(
      `The final HTTP response is ${data.final.statusCode}.`
    );
  } else if (
    data.final.statusCode >=
      200 &&
    data.final.statusCode <
      400
  ) {
    reasons.push(
      `The website returned HTTP ${data.final.statusCode}.`
    );
  }

  if (
    data.redirectCount > 0
  ) {
    score += Math.min(
      data.redirectCount * 3,
      10
    );

    reasons.push(
      `The website used ${data.redirectCount} redirect(s).`
    );
  }

  if (
    data.redirectLimit
  ) {
    score += 12;

    reasons.push(
      "The redirect limit was reached."
    );
  }

  if (
    data.redirectCount > 4
  ) {
    score += 10;

    reasons.push(
      "The redirect chain is unusually long."
    );
  }

  if (
    data.domainWarnings.length
  ) {
    score += Math.min(
      data.domainWarnings.length * 8,
      30
    );

    reasons.push(
      "One or more domain characteristics require additional caution."
    );
  } else {
    reasons.push(
      "No obvious domain-structure warning indicators were observed."
    );
  }

  if (
    data.tls?.authorized === false
  ) {
    score += 20;

    reasons.push(
      "TLS certificate verification failed."
    );
  } else if (
    data.tls?.authorized === true
  ) {
    reasons.push(
      "TLS certificate verification succeeded."
    );
  } else if (
    finalUrl.protocol ===
    "https:"
  ) {
    score += 5;

    reasons.push(
      "TLS certificate details could not be verified by the research run."
    );
  }

  if (
    data.security.count ===
    0
  ) {
    score += 8;

    reasons.push(
      "No checked security headers were observed."
    );
  } else if (
    data.security.count < 3
  ) {
    score += 4;

    reasons.push(
      `Only ${data.security.count}/6 checked security headers were observed.`
    );
  } else {
    reasons.push(
      `${data.security.count}/6 checked security headers were observed.`
    );
  }

  if (
    data.page.contentSignals
      .length >= 3
  ) {
    score += 6;

    reasons.push(
      "Multiple content signals require additional context before trusting the site."
    );
  }

  if (
    data.ads.excessive
  ) {
    score += 8;

    reasons.push(
      "The page shows signals consistent with excessive advertising or popup behavior."
    );
  }

  if (
    data.ads.suspicious
  ) {
    score += 5;

    reasons.push(
      "Advertising/content patterns include terms that may require additional caution."
    );
  }

  if (
    originalUrl.hostname !==
    finalUrl.hostname
  ) {
    score += 8;

    reasons.push(
      "The final hostname differs from the original hostname."
    );
  }

  if (
    data.rdap?.status ===
    "available"
  ) {
    reasons.push(
      "Public RDAP domain information was available."
    );
  } else {
    reasons.push(
      "Public RDAP domain information was not available in this run."
    );
  }

  score =
    Math.min(
      score,
      100
    );

  let risk =
    "LOW";

  if (
    score >= 55
  ) {
    risk =
      "HIGH";
  } else if (
    score >= 25
  ) {
    risk =
      "MEDIUM";
  }

  let confidence =
    65;

  if (
    finalUrl.protocol ===
    "https:"
  ) {
    confidence += 5;
  }

  if (
    data.tls?.authorized ===
    true
  ) {
    confidence += 8;
  }

  if (
    data.security.count >=
    3
  ) {
    confidence += 5;
  }

  if (
    data.page.title
  ) {
    confidence += 4;
  }

  if (
    data.dns.a.length ||
    data.dns.aaaa.length
  ) {
    confidence += 3;
  }

  if (
    data.rdap?.status ===
    "available"
  ) {
    confidence += 4;
  }

  confidence =
    Math.min(
      confidence,
      96
    );

  return {
    score,
    risk,
    confidence,
    reasons
  };
}

function printHeaderDetails(
  checks
) {
  const labels = {
    hsts: "HSTS",
    csp: "CSP",
    xContentType:
      "X-Content-Type-Options",
    xFrame:
      "X-Frame-Options",
    referrer:
      "Referrer-Policy",
    permissions:
      "Permissions-Policy"
  };

  for (
    const [key, label]
    of Object.entries(labels)
  ) {
    console.log(
      `  • ${label}: ${
        checks[key]
          ? "✅ Present"
          : "❌ Missing"
      }`
    );
  }
}

function printGuidance(
  risk
) {
  console.log("");

  console.log(
    "👤 USER GUIDANCE"
  );

  if (
    risk === "LOW"
  ) {
    console.log(
      "Browsing: 🟡 Use Caution"
    );

    console.log(
      "Personal Data: 🟡 Verify First"
    );

    console.log(
      "Account: 🟠 Verify Carefully"
    );

    console.log(
      "Payment: 🟠 Verify Before Paying"
    );

  } else {
    console.log(
      "Browsing: ⚠️ Use Strong Caution"
    );

    console.log(
      "Personal Data: 🚫 Avoid Until Verified"
    );

    console.log(
      "Account: 🚫 Verify First"
    );

    console.log(
      "Payment: 🚫 Do Not Proceed Without Verification"
    );
  }
}

async function main() {
  console.log("");

  console.log(
    "🛡️ WebSafe Research AI"
  );

  console.log("");

  console.log(
    `🌐 Website: ${input}`
  );

  console.log("");

  try {
    const startUrl =
      normalizeUrl(input);

    const domain =
      analyzeDomain(
        startUrl
      );

    const result =
      await followRedirects(
        startUrl
      );

    const final =
      result.final;

    const finalUrl =
      new URL(
        final.targetUrl
      );

    const security =
      analyzeSecurityHeaders(
        final.headers
      );

    const tls =
      final.tls;

    const certificate =
      getCertificateInfo(
        tls
      );

    const page =
      analyzePage(
        final.body,
        final.targetUrl
      );

    const ads =
      analyzeAds(
        final.body,
        final.targetUrl
      );

    const dnsInfo =
      await analyzeDns(
        finalUrl.hostname
      );

    const rdap =
      await getRdapInfo(
        finalUrl.hostname
      );

    const redirectCount =
      result.chain.length - 1;

    const risk =
      calculateRisk({
        startUrl,
        final,
        redirectCount,
        redirectLimit:
          result.redirectLimit,
        domainWarnings:
          domain.warnings,
        security,
        tls,
        page,
        ads,
        dns: dnsInfo,
        rdap
      });

    console.log(
      `🛡️ Risk: ${risk.risk}`
    );

    console.log(
      `🎯 Confidence: ${risk.confidence}%`
    );

    console.log(
      `📊 Risk Score: ${risk.score}/100`
    );

    console.log("");

    console.log(
      "🔎 KEY FINDINGS"
    );

    console.log(
      `• HTTPS: ${
        finalUrl.protocol ===
        "https:"
          ? "✅ PASS"
          : "⚠️ WARNING"
      }`
    );

    console.log(
      `• HTTP Status: ${final.statusCode}`
    );

    console.log(
      `• Redirects: ${
        redirectCount === 0
          ? "✅ NONE"
          : `${redirectCount} detected`
      }`
    );

    console.log(
      `• SSL/TLS: ${
        tls?.authorized === true
          ? "✅ VERIFIED"
          : tls?.authorized === false
          ? "⚠️ NOT VERIFIED"
          : "❓ NOT VERIFIED"
      }`
    );

    if (
      tls?.protocol
    ) {
      console.log(
        `• TLS Protocol: ${tls.protocol}`
      );
    }

    console.log(
      `• Security Headers: ${security.count}/6`
    );

    console.log(
      `• Domain Signals: ${
        domain.warnings.length
          ? "⚠️ CAUTION"
          : "✅ NO BASIC WARNING"
      }`
    );

    console.log("");

    console.log(
      "🔐 CERTIFICATE"
    );

    if (
      certificate
    ) {
      console.log(
        `• Subject: ${
          certificate.subject ||
          "Not available"
        }`
      );

      console.log(
        `• Issuer: ${
          certificate.issuer ||
          "Not available"
        }`
      );

      console.log(
        `• Valid From: ${
          certificate.validFrom ||
          "Not available"
        }`
      );

      console.log(
        `• Valid To: ${
          certificate.validTo ||
          "Not available"
        }`
      );

    } else {
      console.log(
        "• ❓ Certificate details not available."
      );
    }

    console.log("");

    console.log(
      "🏷️ WEBSITE IDENTITY"
    );

    console.log(
      `• Title: ${
        page.title ||
        "❓ Not detected"
      }`
    );

    console.log(
      `• Description: ${
        page.description ||
        "❓ Not detected"
      }`
    );

    console.log("");

    console.log(
      "📄 PAGE CONTENT SIGNALS"
    );

    if (
      page.contentSignals.length
    ) {
      page.contentSignals
        .slice(0, 8)
        .forEach(
          (signal) =>
            console.log(
              `• ⚠️ ${signal}`
            )
        );

    } else {
      console.log(
        "• ✅ No checked content warning pattern detected."
      );
    }

    if (
      page.externalDomains.length
    ) {
      console.log(
        `• External domains observed: ${page.externalDomains
          .slice(0, 10)
          .join(", ")}`
      );
    }

    console.log("");

    console.log(
      "🛡️ SECURITY HEADERS"
    );

    printHeaderDetails(
      security.checks
    );

    console.log("");

    console.log(
      "🌍 DOMAIN & DNS"
    );

    console.log(
      `• Hostname: ${domain.hostname}`
    );

    console.log(
      `• A: ${
        dnsInfo.a.length
          ? dnsInfo.a
              .slice(0, 5)
              .join(", ")
          : "❓ Not available"
      }`
    );

    console.log(
      `• AAAA: ${
        dnsInfo.aaaa.length
          ? dnsInfo.aaaa
              .slice(0, 3)
              .join(", ")
          : "❓ Not available"
      }`
    );

    console.log(
      `• MX: ${
        dnsInfo.mx.length
          ? dnsInfo.mx
              .slice(0, 5)
              .map(
                (item) =>
                  item.exchange
              )
              .join(", ")
          : "❓ Not available"
      }`
    );

    console.log(
      `• NS: ${
        dnsInfo.ns.length
          ? dnsInfo.ns
              .slice(0, 5)
              .join(", ")
          : "❓ Not available"
      }`
    );

    console.log(
      `• RDAP: ${
        rdap?.status ===
        "available"
          ? "✅ Public domain data available"
          : "❓ Not available"
      }`
    );

    console.log("");

    console.log(
      "📢 AD & POPUP ANALYSIS"
    );

    console.log(
      `• Advertisements: ${
        ads.detected
          ? "⚠️ DETECTED"
          : "✅ NOT DETECTED"
      }`
    );

    console.log(
      `• Popup Signals: ${
        ads.popupSignals > 0
          ? `⚠️ ${ads.popupSignals} detected`
          : "✅ NOT DETECTED"
      }`
    );

    console.log(
      `• Excessive Ads: ${
        ads.excessive
          ? "⚠️ POSSIBLE"
          : "✅ NOT DETECTED"
      }`
    );

    console.log(
      `• Suspicious Ad/Content Signals: ${
        ads.suspicious
          ? "⚠️ DETECTED"
          : "✅ NOT DETECTED"
      }`
    );

    console.log("");

    console.log(
      "🧠 TRUST REASONING"
    );

    risk.reasons
      .slice(0, 10)
      .forEach(
        (reason) =>
          console.log(
            `• ${reason}`
          )
      );

    domain.warnings
      .slice(0, 5)
      .forEach(
        (warning) =>
          console.log(
            `• Domain signal: ${warning}`
          )
      );

    printGuidance(
      risk.risk
    );

    console.log("");

    console.log(
      "⚠️ IMPORTANT"
    );

    console.log(
      "AI-generated research assessment — not a guarantee that the website is safe or fraudulent."
    );

    console.log(
      "Results may change over time. Verify important information yourself."
    );

    console.log("");

    console.log(
      "🔐 RESEARCH MODE: PUBLIC / PASSIVE ONLY"
    );

    console.log(
      "🚫 Hacking: DISABLED"
    );

    console.log(
      "🚫 Exploitation: DISABLED"
    );

    console.log(
      "🚫 Unauthorized Access: DISABLED"
    );

    console.log("");

  } catch (error) {
    console.log(
      "❌ Website Check Failed"
    );

    console.log(
      `Reason: ${error.message}`
    );

    console.log("");

    console.log(
      "No safety verdict was produced because the public research check could not be completed."
    );

    console.log("");
  }
}

main();

const https = require("https");
const http = require("http");
const dns = require("dns").promises;

/* =========================================================
   WebSafe Research AI — Final V3
   Public / Passive Website Research Only
========================================================= */

const input = process.argv[2] || "https://example.com";

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT = 8000;
const MAX_BODY = 30000;

const USER_AGENT =
  "WebSafe-Research-AI/3.0 (public-research-only)";

/* =========================================================
   BASIC HELPERS
========================================================= */

function normalizeUrl(value) {
  const raw = String(value || "").trim();

  if (!raw) {
    throw new Error("No website URL was provided.");
  }

  return /^https?:\/\//i.test(raw)
    ? raw
    : "https://" + raw;
}

function isIpAddress(hostname) {
  return (
    /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
    hostname.includes(":")
  );
}

function unique(values) {
  return [...new Set(values)];
}

function containsAny(text, patterns) {
  const value = String(text || "").toLowerCase();

  return patterns.some(pattern =>
    value.includes(String(pattern).toLowerCase())
  );
}

function countMatches(text, patterns) {
  const value = String(text || "").toLowerCase();

  return patterns.reduce((count, pattern) => {
    const matches = value.match(pattern);
    return count + (matches ? matches.length : 0);
  }, 0);
}

function stripHtml(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

/* =========================================================
   HTTP / HTTPS REQUEST
========================================================= */

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
        new Error(
          "Only HTTP and HTTPS websites are supported."
        )
      );
      return;
    }

    const client =
      parsedUrl.protocol === "https:"
        ? https
        : http;

    const request = client.get(
      targetUrl,
      {
        timeout: REQUEST_TIMEOUT,

        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
          "Accept-Language":
            "en-US,en;q=0.8"
        }
      },

      response => {
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
                  typeof socket.getProtocol ===
                  "function"
                    ? socket.getProtocol()
                    : null,

                authorized:
                  typeof socket.authorized ===
                  "boolean"
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

        response.on("data", chunk => {
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
            statusCode: response.statusCode || 0,
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

/* =========================================================
   REDIRECT ANALYSIS
========================================================= */

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
      if (attempt === MAX_REDIRECTS) {
        return {
          final: result,
          chain,
          redirectLimit: true
        };
      }

      currentUrl = result.location;
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
/* =========================================================
   DOMAIN & SECURITY ANALYSIS
========================================================= */

function analyzeDomain(url) {
  const parsed = new URL(url);
  const hostname = parsed.hostname.toLowerCase();

  const labels = hostname.split(".").filter(Boolean);

  const warnings = [];

  if (isIpAddress(hostname)) {
    warnings.push("IP address used instead of a normal domain");
  }

  if (hostname.includes("xn--")) {
    warnings.push("Punycode hostname detected");
  }

  if (hostname.length > 60) {
    warnings.push("Unusually long hostname");
  }

  const hyphenCount =
    (hostname.match(/-/g) || []).length;

  if (hyphenCount >= 3) {
    warnings.push("Multiple hyphens in hostname");
  }

  if (labels.length >= 5) {
    warnings.push("Deep subdomain structure");
  }

  const cautionTlds = [
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".xyz",
    ".shop",
    ".work",
    ".buzz",
    ".country"
  ];

  const cautionTld = cautionTlds.find(tld =>
    hostname.endsWith(tld)
  );

  if (cautionTld) {
    warnings.push(
      `Caution TLD detected: ${cautionTld}`
    );
  }

  return {
    hostname,
    isIp: isIpAddress(hostname),
    punycode: hostname.includes("xn--"),
    hostnameLength: hostname.length,
    labelCount: labels.length,
    warnings
  };
}


/* =========================================================
   SECURITY HEADER ANALYSIS
========================================================= */

function analyzeSecurityHeaders(headers) {
  const checks = {
    "Strict-Transport-Security":
      "strict-transport-security",

    "Content-Security-Policy":
      "content-security-policy",

    "X-Content-Type-Options":
      "x-content-type-options",

    "X-Frame-Options":
      "x-frame-options",

    "Referrer-Policy":
      "referrer-policy",

    "Permissions-Policy":
      "permissions-policy"
  };

  const results = {};

  let present = 0;

  for (const [name, header] of Object.entries(checks)) {
    const value = headers[header];

    const exists =
      value !== undefined &&
      value !== null &&
      String(value).trim() !== "";

    results[name] = {
      present: exists,
      value: exists ? String(value) : null
    };

    if (exists) {
      present++;
    }
  }

  return {
    results,
    present,
    total: Object.keys(checks).length
  };
}


/* =========================================================
   HTML META / WEBSITE IDENTITY
========================================================= */

function decodeHtmlEntities(value) {
  return String(value || "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/\s+/g, " ")
    .trim();
}

function extractMeta(html) {
  const source = String(html || "");

  const titleMatch =
    source.match(
      /<title[^>]*>([\s\S]*?)<\/title>/i
    );

  const descriptionMatch =
    source.match(
      /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i
    ) ||
    source.match(
      /<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i
    );

  const ogTitleMatch =
    source.match(
      /<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']*)["']/i
    ) ||
    source.match(
      /<meta[^>]+content=["']([^"']*)["'][^>]+property=["']og:title["']/i
    );

  const ogDescriptionMatch =
    source.match(
      /<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']*)["']/i
    ) ||
    source.match(
      /<meta[^>]+content=["']([^"']*)["'][^>]+property=["']og:description["']/i
    );

  const languageMatch =
    source.match(
      /<html[^>]+lang=["']([^"']+)["']/i
    );

  return {
    title: decodeHtmlEntities(
      titleMatch ? titleMatch[1] : ""
    ),

    description: decodeHtmlEntities(
      descriptionMatch
        ? descriptionMatch[1]
        : ""
    ),

    ogTitle: decodeHtmlEntities(
      ogTitleMatch
        ? ogTitleMatch[1]
        : ""
    ),

    ogDescription: decodeHtmlEntities(
      ogDescriptionMatch
        ? ogDescriptionMatch[1]
        : ""
    ),

    language:
      languageMatch
        ? languageMatch[1].trim()
        : null
  };
}


/* =========================================================
   PAGE INTELLIGENCE
========================================================= */

function analyzePage(body, finalUrl) {
  const html = String(body || "");

  const meta = extractMeta(html);

  const visibleText =
    stripHtml(html).toLowerCase();

  const searchableText = [
    visibleText,
    meta.title,
    meta.description,
    meta.ogTitle,
    meta.ogDescription
  ]
    .join(" ")
    .toLowerCase();

  const signals = {
    login: containsAny(searchableText, [
      "login",
      "log in",
      "sign in",
      "signin",
      "create account",
      "my account"
    ]),

    payment: containsAny(searchableText, [
      "payment",
      "checkout",
      "credit card",
      "debit card",
      "pay now",
      "billing",
      "visa",
      "mastercard"
    ]),

    download: containsAny(searchableText, [
      "download",
      "apk",
      "installer",
      "download app"
    ]),

    adult: containsAny(searchableText, [
      "adult",
      "porn",
      "xxx",
      "18+",
      "nsfw",
      "explicit content",
      "onlyfans"
    ]),

    gambling: containsAny(searchableText, [
      "casino",
      "betting",
      "sportsbook",
      "gambling",
      "bet now",
      "slot",
      "roulette",
      "poker"
    ]),

    crypto: containsAny(searchableText, [
      "crypto",
      "cryptocurrency",
      "token",
      "tokens",
      "bitcoin",
      "ethereum",
      "blockchain",
      "wallet",
      "web3",
      "coin"
    ]),

    trading: containsAny(searchableText, [
      "trade",
      "trading",
      "exchange",
      "buy crypto",
      "sell crypto",
      "swap"
    ]),

    investment: containsAny(searchableText, [
      "investment",
      "invest now",
      "guaranteed return",
      "profit",
      "roi",
      "passive income"
    ]),

    shopping: containsAny(searchableText, [
      "shop",
      "shopping",
      "product",
      "products",
      "add to cart",
      "cart",
      "store"
    ]),

    highPressure: containsAny(searchableText, [
      "act now",
      "limited time",
      "urgent",
      "last chance",
      "don't miss",
      "expires today",
      "claim now"
    ]),

    contact: containsAny(searchableText, [
      "contact us",
      "contact",
      "support",
      "customer service",
      "help center"
    ]),

    privacy: containsAny(searchableText, [
      "privacy policy",
      "privacy"
    ]),

    terms: containsAny(searchableText, [
      "terms of service",
      "terms and conditions",
      "terms of use"
    ])
  };

  const externalDomains = [];

  const linkPattern =
    /(?:href|src)=["'](https?:\/\/[^"'#\s]+)/gi;

  let match;

  while (
    (match = linkPattern.exec(html)) !== null
  ) {
    try {
      const externalUrl =
        new URL(match[1]);

      const finalHost =
        new URL(finalUrl).hostname;

      if (
        externalUrl.hostname &&
        externalUrl.hostname !== finalHost
      ) {
        externalDomains.push(
          externalUrl.hostname
        );
      }
    } catch {
      // Ignore malformed external URLs.
    }
  }

  return {
    meta,

    textLength: visibleText.length,

    signals,

    externalDomains:
      unique(externalDomains).slice(0, 30)
  };
}


/* =========================================================
   WEBSITE CATEGORY DETECTION
========================================================= */

function detectCategories(page) {
  const s = page.signals;

  const categories = {
    financial:
      Boolean(
        s.crypto ||
        s.trading ||
        s.investment
      ),

    adult:
      Boolean(s.adult),

    gambling:
      Boolean(s.gambling),

    commerce:
      Boolean(
        s.shopping ||
        s.payment
      )
  };

  return categories;
}
/* =========================================================
   ADVERTISEMENT & POPUP INTELLIGENCE
========================================================= */

function analyzeAds(body, externalDomains) {
  const html = String(body || "");
  const text = stripHtml(html).toLowerCase();

  const adNetworkPatterns = [
    "googlesyndication.com",
    "doubleclick.net",
    "googleadservices.com",
    "adservice.google.com",
    "amazon-adsystem.com",
    "adnxs.com",
    "adsbygoogle",
    "propellerads",
    "popads",
    "adsterra",
    "exoclick",
    "trafficjunky"
  ];

  const adMarkerPatterns = [
    "advertisement",
    "advertising",
    "sponsored",
    "ads by google",
    "adchoices",
    "banner ad"
  ];

  const popupPatterns = [
    "popup",
    "pop-up",
    "popunder",
    "pop-under",
    "window.open("
  ];

  const suspiciousPatterns = [
    "click here to win",
    "you are a winner",
    "claim your prize",
    "congratulations",
    "virus detected",
    "your device is infected",
    "install now",
    "download now"
  ];

  const detectedAdNetworks =
    externalDomains.filter(domain =>
      adNetworkPatterns.some(pattern =>
        domain.toLowerCase().includes(pattern)
      )
    );

  const adMarkers =
    adMarkerPatterns.filter(pattern =>
      text.includes(pattern)
    );

  const popupSignals =
    popupPatterns.filter(pattern =>
      html.toLowerCase().includes(pattern)
    );

  const suspiciousSignals =
    suspiciousPatterns.filter(pattern =>
      text.includes(pattern)
    );

  const adDetected =
    detectedAdNetworks.length > 0 ||
    adMarkers.length > 0;

  const popupDetected =
    popupSignals.length > 0;

  const suspiciousDetected =
    suspiciousSignals.length > 0;

  const excessiveAds =
    detectedAdNetworks.length >= 3 ||
    adMarkers.length >= 4;

  return {
    detected: adDetected,
    detectedAdNetworks:
      unique(detectedAdNetworks),

    adMarkers:
      unique(adMarkers),

    popupDetected,

    popupSignals:
      unique(popupSignals),

    excessiveAds,

    suspiciousDetected,

    suspiciousSignals:
      unique(suspiciousSignals)
  };
}


/* =========================================================
   DNS ANALYSIS
========================================================= */

async function resolveDns(hostname) {
  const result = {
    A: [],
    AAAA: [],
    MX: [],
    NS: []
  };

  const tasks = [
    ["A", dns.resolve4(hostname)],
    ["AAAA", dns.resolve6(hostname)],
    ["MX", dns.resolveMx(hostname)],
    ["NS", dns.resolveNs(hostname)]
  ];

  const settled =
    await Promise.allSettled(
      tasks.map(item => item[1])
    );

  for (let i = 0; i < tasks.length; i++) {
    const type = tasks[i][0];
    const response = settled[i];

    if (response.status !== "fulfilled") {
      continue;
    }

    if (type === "MX") {
      result.MX =
        response.value
          .map(item => item.exchange)
          .filter(Boolean);
    } else {
      result[type] =
        response.value || [];
    }
  }

  return result;
}


/* =========================================================
   TLS CERTIFICATE ANALYSIS
========================================================= */

function analyzeCertificate(tls) {
  if (!tls || !tls.certificate) {
    return {
      available: false,
      subject: null,
      issuer: null,
      validFrom: null,
      validTo: null,
      subjectAltName: null,
      fingerprint256: null
    };
  }

  const certificate =
    tls.certificate;

  return {
    available: true,

    subject:
      certificate.subject
        ? (
            certificate.subject.CN ||
            certificate.subject.commonName ||
            null
          )
        : null,

    issuer:
      certificate.issuer
        ? (
            certificate.issuer.CN ||
            certificate.issuer.commonName ||
            null
          )
        : null,

    validFrom:
      certificate.valid_from || null,

    validTo:
      certificate.valid_to || null,

    subjectAltName:
      certificate.subjectaltname || null,

    fingerprint256:
      certificate.fingerprint256 || null
  };
}


/* =========================================================
   RDAP / PUBLIC DOMAIN EVIDENCE
========================================================= */

function getRdap(hostname) {
  return new Promise(resolve => {
    const url =
      `https://rdap.org/domain/${encodeURIComponent(
        hostname
      )}`;

    const request =
      https.get(
        url,
        {
          timeout: REQUEST_TIMEOUT,

          headers: {
            "User-Agent": USER_AGENT,
            Accept:
              "application/rdap+json, application/json"
          }
        },

        response => {
          let body = "";

          response.setEncoding("utf8");

          response.on("data", chunk => {
            if (body.length < 20000) {
              body += chunk.slice(
                0,
                20000 - body.length
              );
            }
          });

          response.on("end", () => {
            if (
              response.statusCode < 200 ||
              response.statusCode >= 300
            ) {
              resolve({
                available: false,
                statusCode:
                  response.statusCode || 0
              });
              return;
            }

            try {
              const data =
                JSON.parse(body);

              const events =
                Array.isArray(data.events)
                  ? data.events
                  : [];

              const registration =
                events.find(
                  event =>
                    event.eventAction ===
                    "registration"
                );

              const expiration =
                events.find(
                  event =>
                    event.eventAction ===
                    "expiration"
                );

              let registrar = null;

              if (
                Array.isArray(data.entities)
              ) {
                const entity =
                  data.entities.find(
                    item =>
                      Array.isArray(
                        item.roles
                      ) &&
                      item.roles.includes(
                        "registrar"
                      )
                  );

                if (
                  entity &&
                  entity.vcardArray &&
                  Array.isArray(
                    entity.vcardArray[1]
                  )
                ) {
                  const fn =
                    entity.vcardArray[1].find(
                      item =>
                        item[0] === "fn"
                    );

                  if (fn && fn[3]) {
                    registrar =
                      String(fn[3]);
                  }
                }
              }

              resolve({
                available: true,

                statusCode:
                  response.statusCode,

                registration:
                  registration
                    ? registration.eventDate
                    : null,

                expiration:
                  expiration
                    ? expiration.eventDate
                    : null,

                registrar
              });
            } catch {
              resolve({
                available: false,
                statusCode:
                  response.statusCode
              });
            }
          });

          response.on("error", () => {
            resolve({
              available: false,
              statusCode: 0
            });
          });
        }
      );

    request.on("timeout", () => {
      request.destroy();
    });

    request.on("error", () => {
      resolve({
        available: false,
        statusCode: 0
      });
    });
  });
}


/* =========================================================
   WEBSITE INFRASTRUCTURE SIGNALS
========================================================= */

function analyzeInfrastructure(headers, externalDomains) {
  const server =
    String(
      headers["server"] || ""
    ).toLowerCase();

  const poweredBy =
    String(
      headers["x-powered-by"] || ""
    ).toLowerCase();

  const cdnSignals = [];

  if (
    server.includes("cloudflare") ||
    headers["cf-ray"] ||
    headers["cf-cache-status"]
  ) {
    cdnSignals.push("Cloudflare");
  }

  if (
    server.includes("cloudfront") ||
    headers["x-amz-cf-id"]
  ) {
    cdnSignals.push("Amazon CloudFront");
  }

  if (
    server.includes("fastly") ||
    headers["x-served-by"]
  ) {
    cdnSignals.push("Fastly");
  }

  const analyticsDomains =
    externalDomains.filter(domain =>
      containsAny(domain, [
        "google-analytics",
        "googletagmanager",
        "analytics",
        "segment.io",
        "hotjar",
        "clarity.ms"
      ])
    );

  const paymentDomains =
    externalDomains.filter(domain =>
      containsAny(domain, [
        "stripe",
        "paypal",
        "braintree",
        "checkout.com",
        "razorpay",
        "paystack"
      ])
    );

  return {
    server:
      server || null,

    poweredBy:
      poweredBy || null,

    cdn:
      unique(cdnSignals),

    analytics:
      unique(analyticsDomains),

    paymentServices:
      unique(paymentDomains)
  };
              }
/* =========================================================
   RISK ENGINE
========================================================= */

function calculateRisk(data) {
  let score = 0;
  const reasons = [];

  const {
    initialUrl,
    finalUrl,
    finalResponse,
    domain,
    headers,
    page,
    ads,
    certificate,
    rdap,
    redirectChain
  } = data;

  /* -------------------------------------------------------
     HTTPS / CONNECTION
  ------------------------------------------------------- */

  const finalParsed =
    new URL(finalUrl);

  if (finalParsed.protocol !== "https:") {
    score += 20;
    reasons.push(
      "The final website connection is not using HTTPS."
    );
  } else {
    reasons.push(
      "The final website uses HTTPS."
    );
  }

  /* -------------------------------------------------------
     HTTP STATUS
  ------------------------------------------------------- */

  const status =
    finalResponse.statusCode;

  if (status >= 400) {
    score += 15;

    reasons.push(
      `The website returned HTTP ${status}.`
    );
  } else if (
    status >= 200 &&
    status < 400
  ) {
    reasons.push(
      `The website returned HTTP ${status}.`
    );
  }

  /* -------------------------------------------------------
     REDIRECTS
  ------------------------------------------------------- */

  const redirectCount =
    Math.max(
      0,
      redirectChain.length - 1
    );

  if (redirectCount >= 4) {
    score += 12;

    reasons.push(
      `A high number of redirects was observed (${redirectCount}).`
    );
  } else if (redirectCount > 0) {
    reasons.push(
      `The website used ${redirectCount} redirect${
        redirectCount === 1 ? "" : "s"
      }.`
    );
  } else {
    reasons.push(
      "No redirects were observed."
    );
  }

  /* -------------------------------------------------------
     REDIRECT LIMIT
  ------------------------------------------------------- */

  if (data.redirectLimit) {
    score += 20;

    reasons.push(
      "The redirect chain reached the analysis limit."
    );
  }

  /* -------------------------------------------------------
     DOMAIN SIGNALS
  ------------------------------------------------------- */

  if (domain.isIp) {
    score += 12;

    reasons.push(
      "The website uses an IP address instead of a normal domain."
    );
  }

  if (domain.punycode) {
    score += 10;

    reasons.push(
      "Punycode was detected in the hostname."
    );
  }

  if (domain.warnings.length > 0) {
    score += Math.min(
      domain.warnings.length * 3,
      12
    );

    reasons.push(
      "Basic domain-structure warning indicators were observed."
    );
  } else {
    reasons.push(
      "No obvious basic domain-structure warning indicators were observed."
    );
  }

  /* -------------------------------------------------------
     TLS
  ------------------------------------------------------- */

  if (
    finalParsed.protocol === "https:" &&
    finalResponse.tls
  ) {
    if (
      finalResponse.tls.authorized === false
    ) {
      score += 25;

      reasons.push(
        "TLS certificate verification did not succeed."
      );
    } else if (
      finalResponse.tls.authorized === true
    ) {
      reasons.push(
        "TLS certificate verification succeeded."
      );
    }

    if (
      finalResponse.tls.protocol &&
      /^TLSv1\.0|^TLSv1\.1/i.test(
        finalResponse.tls.protocol
      )
    ) {
      score += 15;

      reasons.push(
        `An older TLS protocol was reported: ${finalResponse.tls.protocol}.`
      );
    }
  }

  /* -------------------------------------------------------
     CERTIFICATE
  ------------------------------------------------------- */

  if (
    certificate.available
  ) {
    const now =
      Date.now();

    const validFrom =
      certificate.validFrom
        ? Date.parse(
            certificate.validFrom
          )
        : NaN;

    const validTo =
      certificate.validTo
        ? Date.parse(
            certificate.validTo
          )
        : NaN;

    if (
      Number.isFinite(validFrom) &&
      now < validFrom
    ) {
      score += 20;

      reasons.push(
        "The TLS certificate is not yet valid."
      );
    }

    if (
      Number.isFinite(validTo) &&
      now > validTo
    ) {
      score += 25;

      reasons.push(
        "The TLS certificate appears to be expired."
      );
    }

    if (
      Number.isFinite(validTo) &&
      validTo > now &&
      validTo - now < 7 * 24 * 60 * 60 * 1000
    ) {
      score += 2;

      reasons.push(
        "The TLS certificate is close to its expiration date."
      );
    }
  }

  /* -------------------------------------------------------
     SECURITY HEADERS
  ------------------------------------------------------- */

  const headerCount =
    headers.present;

  if (headerCount === 0) {
    score += 8;

    reasons.push(
      "None of the six checked security headers were observed."
    );
  } else if (
    headerCount <= 2
  ) {
    score += 4;

    reasons.push(
      `Only ${headerCount}/6 checked security headers were observed.`
    );
  } else {
    reasons.push(
      `${headerCount}/6 checked security headers were observed.`
    );
  }

  /* -------------------------------------------------------
     CONTENT SIGNALS
  ------------------------------------------------------- */

  if (
    page.signals.highPressure
  ) {
    score += 6;

    reasons.push(
      "High-pressure or urgency language was detected."
    );
  }

  /* -------------------------------------------------------
     AD / POPUP BEHAVIOR
  ------------------------------------------------------- */

  if (
    ads.suspiciousDetected
  ) {
    score += 12;

    reasons.push(
      "Suspicious advertising or warning-style content signals were detected."
    );
  }

  if (
    ads.popupDetected
  ) {
    score += 3;

    reasons.push(
      "Popup or pop-under related signals were detected."
    );
  }

  if (
    ads.excessiveAds
  ) {
    score += 4;

    reasons.push(
      "A relatively high number of advertising signals was detected."
    );
  }

  /* -------------------------------------------------------
     IMPORTANT:
     CATEGORY ACTIVITY IS NOT AUTOMATICALLY FRAUD
  ------------------------------------------------------- */

  if (
    page.signals.crypto ||
    page.signals.trading ||
    page.signals.investment
  ) {
    reasons.push(
      "Financial or crypto-related activity was detected; this alone does not prove fraud."
    );
  }

  if (
    page.signals.adult
  ) {
    reasons.push(
      "Adult-content signals were detected."
    );
  }

  if (
    page.signals.gambling
  ) {
    reasons.push(
      "Gambling or betting signals were detected."
    );
  }

  /* -------------------------------------------------------
     RDAP
  ------------------------------------------------------- */

  if (
    rdap &&
    !rdap.available
  ) {
    reasons.push(
      "Public RDAP domain information was not available in this run."
    );
  } else if (
    rdap &&
    rdap.available
  ) {
    reasons.push(
      "Public RDAP domain information was available."
    );
  }

  /* -------------------------------------------------------
     FINAL SCORE
  ------------------------------------------------------- */

  score =
    Math.max(
      0,
      Math.min(
        100,
        Math.round(score)
      )
    );

  let risk = "LOW";

  if (score >= 55) {
    risk = "HIGH";
  } else if (score >= 25) {
    risk = "MEDIUM";
  }

  /* -------------------------------------------------------
     CONFIDENCE
  ------------------------------------------------------- */

  let confidence = 70;

  if (finalResponse.statusCode) {
    confidence += 5;
  }

  if (finalResponse.tls) {
    confidence += 5;
  }

  if (certificate.available) {
    confidence += 5;
  }

  if (
    headers.present > 0
  ) {
    confidence += 3;
  }

  if (
    rdap &&
    rdap.available
  ) {
    confidence += 3;
  }

  confidence =
    Math.min(
      95,
      confidence
    );

  return {
    score,
    risk,
    confidence,
    reasons
  };
}


/* =========================================================
   DYNAMIC CATEGORY SECTIONS
========================================================= */

function buildCategorySections(page) {
  const sections = [];

  const s =
    page.signals;

  /* -------------------------------------------------------
     FINANCIAL
  ------------------------------------------------------- */

  if (
    s.crypto ||
    s.trading ||
    s.investment
  ) {
    sections.push({
      title:
        "💰 FINANCIAL ACTIVITY",

      lines: [
        `• Crypto/Token: ${
          s.crypto
            ? "⚠️ DETECTED"
            : "❓ NOT VERIFIED"
        }`,

        `• Trading: ${
          s.trading
            ? "⚠️ DETECTED"
            : "❓ NOT VERIFIED"
        }`,

        `• Investment Claims: ${
          s.investment
            ? "⚠️ DETECTED"
            : "❓ NOT VERIFIED"
        }`,

        "• Payment: ❓ NOT VERIFIED",

        "",

        "⚠️ Note:",

        "Financial activity does not by itself prove fraud.",

        "Verify the service, operators and transaction terms before sending money or connecting a wallet."
      ]
    });
  }

  /* -------------------------------------------------------
     ADULT
  ------------------------------------------------------- */

  if (s.adult) {
    sections.push({
      title:
        "🔞 CONTENT CATEGORY",

      lines: [
        "• Adult Content: ⚠️ DETECTED",
        "• Age Restriction: ⚠️ PRESENT"
      ]
    });
  }

  /* -------------------------------------------------------
     GAMBLING
  ------------------------------------------------------- */

  if (s.gambling) {
    sections.push({
      title:
        "🎰 GAMBLING ACTIVITY",

      lines: [
        "• Gambling: ⚠️ DETECTED",
        "• Betting: ⚠️ DETECTED",
        `• Payment/Deposit: ${
          s.payment
            ? "⚠️ DETECTED"
            : "❓ NOT VERIFIED"
        }`
      ]
    });
  }

  /* -------------------------------------------------------
     COMMERCE
  ------------------------------------------------------- */

  if (
    s.shopping ||
    s.payment
  ) {
    sections.push({
      title:
        "🛒 COMMERCE ACTIVITY",

      lines: [
        `• Products/Shopping: ${
          s.shopping
            ? "⚠️ DETECTED"
            : "❓ NOT VERIFIED"
        }`,

        `• Checkout: ${
          s.payment
            ? "⚠️ DETECTED"
            : "❓ NOT VERIFIED"
        }`,

        `• Payment: ${
          s.payment
            ? "⚠️ DETECTED"
            : "❓ NOT VERIFIED"
        }`
      ]
    });
  }

  return sections;
}


/* =========================================================
   USER GUIDANCE
========================================================= */

function buildGuidance(risk, page) {
  let browsing =
    "🟢 Generally OK";

  let personalData =
    "🟢 Normal Caution";

  let account =
    "🟢 Verify Normally";

  let payment =
    "🟡 Verify Before Paying";

  if (risk === "MEDIUM") {
    browsing =
      "🟡 Use Caution";

    personalData =
      "🟡 Verify First";

    account =
      "🟠 Verify Carefully";

    payment =
      "🟠 Verify Before Paying";
  }

  if (risk === "HIGH") {
    browsing =
      "🔴 High Caution";

    personalData =
      "🔴 Avoid Sharing Sensitive Data";

    account =
      "🔴 Verify Independently";

    payment =
      "🔴 Avoid Payment Until Verified";
  }

  if (
    page.signals.crypto ||
    page.signals.trading ||
    page.signals.investment
  ) {
    payment =
      risk === "HIGH"
        ? "🔴 Avoid Payment Until Verified"
        : "🟠 Verify Before Sending Money";
  }

  return {
    browsing,
    personalData,
    account,
    payment
  };
}


/* =========================================================
   TRUST REASONING
========================================================= */

function buildTrustReasoning(data, riskResult) {
  const lines = [];

  const {
    finalResponse,
    finalUrl,
    headers,
    certificate,
    domain,
    page,
    ads,
    rdap
  } = data;

  const protocol =
    new URL(finalUrl).protocol;

  if (protocol === "https:") {
    lines.push(
      "• The final website uses HTTPS."
    );
  } else {
    lines.push(
      "• The final website does not use HTTPS."
    );
  }

  if (
    finalResponse.tls &&
    finalResponse.tls.authorized === true
  ) {
    lines.push(
      "• TLS certificate verification succeeded."
    );
  }

  if (
    finalResponse.tls &&
    finalResponse.tls.authorized === false
  ) {
    lines.push(
      "• TLS certificate verification did not succeed."
    );
  }

  lines.push(
    `• The website returned HTTP ${finalResponse.statusCode}.`
  );

  if (
    domain.warnings.length === 0
  ) {
    lines.push(
      "• No obvious basic domain-structure warning indicators were observed."
    );
  }

  if (
    certificate.available
  ) {
    lines.push(
      "• A public TLS certificate was obtained during the research."
    );
  }

  lines.push(
    `• ${headers.present}/6 checked security headers were observed.`
  );

  if (
    page.signals.crypto ||
    page.signals.trading ||
    page.signals.investment
  ) {
    lines.push(
      "• Financial or crypto-related activity was detected and should be verified independently."
    );
  }

  if (
    ads.suspiciousDetected
  ) {
    lines.push(
      "• Suspicious advertising or warning-style content signals were detected."
    );
  }

  if (
    rdap &&
    !rdap.available
  ) {
    lines.push(
      "• Public RDAP domain information was not available in this run."
    );
  }

  return lines;
}
/* =========================================================
   REPORT BUILDER
========================================================= */

function buildReport(data, riskResult) {
  const {
    initialUrl,
    finalUrl,
    finalResponse,
    domain,
    headers,
    page,
    ads,
    certificate,
    dnsInfo,
    rdap,
    redirectChain,
    infrastructure
  } = data;

  const categorySections =
    buildCategorySections(page);

  const guidance =
    buildGuidance(
      riskResult.risk,
      page
    );

  const trustReasoning =
    buildTrustReasoning(
      data,
      riskResult
    );

  const lines = [];

  lines.push(
    "🛡️ WebSafe Research AI"
  );
  lines.push("");

  lines.push(
    `🌐 Website: ${initialUrl}`
  );

  if (
    finalUrl !== initialUrl
  ) {
    lines.push(
      `🔗 Final URL: ${finalUrl}`
    );
  }

  lines.push("");

  lines.push(
    `🛡️ Risk: ${riskResult.risk}`
  );

  lines.push(
    `🎯 Confidence: ${riskResult.confidence}%`
  );

  lines.push(
    `📊 Risk Score: ${riskResult.score}/100`
  );

  lines.push("");

  /* -------------------------------------------------------
     KEY FINDINGS
  ------------------------------------------------------- */

  lines.push(
    "🔎 KEY FINDINGS"
  );

  lines.push(
    `• HTTPS: ${
      new URL(finalUrl).protocol === "https:"
        ? "✅ PASS"
        : "⚠️ NOT USED"
    }`
  );

  lines.push(
    `• HTTP Status: ${finalResponse.statusCode}`
  );

  lines.push(
    `• Redirects: ${
      redirectChain.length > 1
        ? `⚠️ ${redirectChain.length - 1}`
        : "✅ NONE"
    }`
  );

  lines.push(
    `• SSL/TLS: ${
      finalResponse.tls &&
      finalResponse.tls.authorized === true
        ? "✅ VERIFIED"
        : finalResponse.tls
          ? "⚠️ NOT VERIFIED"
          : "❓ NOT AVAILABLE"
    }`
  );

  lines.push(
    `• Security Headers: ${headers.present}/${headers.total}`
  );

  lines.push(
    `• Domain Signals: ${
      domain.warnings.length === 0
        ? "✅ NO BASIC WARNING"
        : `⚠️ ${domain.warnings.length} WARNING(S)`
    }`
  );

  lines.push("");

  /* -------------------------------------------------------
     WEBSITE IDENTITY
  ------------------------------------------------------- */

  lines.push(
    "🏷️ WEBSITE IDENTITY"
  );

  lines.push(
    `• Title: ${
      page.meta.title ||
      "❓ Not available"
    }`
  );

  lines.push(
    `• Description: ${
      page.meta.description ||
      "❓ Not available"
    }`
  );

  if (page.meta.ogTitle) {
    lines.push(
      `• Open Graph Title: ${page.meta.ogTitle}`
    );
  }

  if (page.meta.ogDescription) {
    lines.push(
      `• Open Graph Description: ${page.meta.ogDescription}`
    );
  }

  lines.push(
    `• Language: ${
      page.meta.language ||
      "❓ Not detected"
    }`
  );

  lines.push("");

  /* -------------------------------------------------------
     CATEGORY SECTIONS
  ------------------------------------------------------- */

  for (
    const section of categorySections
  ) {
    lines.push(section.title);

    for (
      const line of section.lines
    ) {
      lines.push(line);
    }

    lines.push("");
  }

  /* -------------------------------------------------------
     PAGE CONTENT SIGNALS
  ------------------------------------------------------- */

  lines.push(
    "📄 PAGE CONTENT SIGNALS"
  );

  const detectedSignals =
    Object.entries(
      page.signals
    )
      .filter(
        ([, detected]) =>
          detected
      )
      .map(
        ([name]) => name
      );

  if (
    detectedSignals.length === 0
  ) {
    lines.push(
      "• ✅ No checked content warning pattern detected."
    );
  } else {
    lines.push(
      `• ⚠️ Detected: ${detectedSignals.join(", ")}`
    );
  }

  lines.push("");

  /* -------------------------------------------------------
     ADVERTISEMENT ANALYSIS
  ------------------------------------------------------- */

  lines.push(
    "📢 AD & POPUP ANALYSIS"
  );

  lines.push(
    `• Advertisements: ${
      ads.detected
        ? "⚠️ DETECTED"
        : "✅ NOT DETECTED"
    }`
  );

  lines.push(
    `• Popup Signals: ${
      ads.popupDetected
        ? "⚠️ DETECTED"
        : "✅ NOT DETECTED"
    }`
  );

  lines.push(
    `• Excessive Ads: ${
      ads.excessiveAds
        ? "⚠️ DETECTED"
        : "✅ NOT DETECTED"
    }`
  );

  lines.push(
    `• Suspicious Ad/Content Signals: ${
      ads.suspiciousDetected
        ? "⚠️ DETECTED"
        : "✅ NOT DETECTED"
    }`
  );

  lines.push("");

  /* -------------------------------------------------------
     CERTIFICATE
  ------------------------------------------------------- */

  lines.push(
    "🔐 CERTIFICATE"
  );

  if (certificate.available) {
    lines.push(
      `• Subject: ${
        certificate.subject ||
        "❓ Not available"
      }`
    );

    lines.push(
      `• Issuer: ${
        certificate.issuer ||
        "❓ Not available"
      }`
    );

    lines.push(
      `• Valid From: ${
        certificate.validFrom ||
        "❓ Not available"
      }`
    );

    lines.push(
      `• Valid To: ${
        certificate.validTo ||
        "❓ Not available"
      }`
    );
  } else {
    lines.push(
      "• ❓ Certificate information not available."
    );
  }

  lines.push("");

  /* -------------------------------------------------------
     SECURITY HEADERS
  ------------------------------------------------------- */

  lines.push(
    "🛡️ SECURITY HEADERS"
  );

  for (
    const [name, result]
    of Object.entries(
      headers.results
    )
  ) {
    lines.push(
      `  • ${name}: ${
        result.present
          ? "✅ Present"
          : "❌ Missing"
      }`
    );
  }

  lines.push("");

  /* -------------------------------------------------------
     DOMAIN & DNS
  ------------------------------------------------------- */

  lines.push(
    "🌍 DOMAIN & DNS"
  );

  lines.push(
    `• Hostname: ${domain.hostname}`
  );

  lines.push(
    `• A: ${
      dnsInfo.A.length
        ? dnsInfo.A.join(", ")
        : "❓ Not available"
    }`
  );

  lines.push(
    `• AAAA: ${
      dnsInfo.AAAA.length
        ? dnsInfo.AAAA.join(", ")
        : "❓ Not available"
    }`
  );

  lines.push(
    `• MX: ${
      dnsInfo.MX.length
        ? dnsInfo.MX.join(", ")
        : "❓ Not available"
    }`
  );

  lines.push(
    `• NS: ${
      dnsInfo.NS.length
        ? dnsInfo.NS.join(", ")
        : "❓ Not available"
    }`
  );

  if (
    domain.punycode
  ) {
    lines.push(
      "• Punycode: ⚠️ Detected"
    );
  }

  lines.push(
    `• RDAP: ${
      rdap.available
        ? "✅ Available"
        : "❓ Not available"
    }`
  );

  lines.push("");

  /* -------------------------------------------------------
     INFRASTRUCTURE
  ------------------------------------------------------- */

  if (
    infrastructure.cdn.length ||
    infrastructure.analytics.length ||
    infrastructure.paymentServices.length
  ) {
    lines.push(
      "🌐 EXTERNAL INFRASTRUCTURE"
    );

    if (
      infrastructure.cdn.length
    ) {
      lines.push(
        `• CDN: ${infrastructure.cdn.join(", ")}`
      );
    }

    if (
      infrastructure.analytics.length
    ) {
      lines.push(
        `• Analytics: ${infrastructure.analytics.join(", ")}`
      );
    }

    if (
      infrastructure.paymentServices.length
    ) {
      lines.push(
        `• Payment Services: ${infrastructure.paymentServices.join(", ")}`
      );
    }

    lines.push("");
  }

  /* -------------------------------------------------------
     TRUST REASONING
  ------------------------------------------------------- */

  lines.push(
    "🧠 TRUST REASONING"
  );

  for (
    const reason of trustReasoning
  ) {
    lines.push(reason);
  }

  lines.push("");

  /* -------------------------------------------------------
     USER GUIDANCE
  ------------------------------------------------------- */

  lines.push(
    "👤 USER GUIDANCE"
  );

  lines.push(
    `Browsing: ${guidance.browsing}`
  );

  lines.push(
    `Personal Data: ${guidance.personalData}`
  );

  lines.push(
    `Account: ${guidance.account}`
  );

  lines.push(
    `Payment: ${guidance.payment}`
  );

  lines.push("");

  /* -------------------------------------------------------
     IMPORTANT
  ------------------------------------------------------- */

  lines.push(
    "⚠️ IMPORTANT"
  );

  lines.push(
    "Automated research assessment generated by WebSafe Research AI — not a guarantee that the website is safe or fraudulent."
  );

  lines.push(
    "Results may change over time. Verify important information yourself."
  );

  lines.push("");

  lines.push(
    "🔐 RESEARCH MODE: PUBLIC / PASSIVE ONLY"
  );

  lines.push(
    "🚫 Hacking: DISABLED"
  );

  lines.push(
    "🚫 Exploitation: DISABLED"
  );

  lines.push(
    "🚫 Unauthorized Access: DISABLED"
  );

  return lines.join("\n");
}


/* =========================================================
   MAIN RESEARCH ENGINE
========================================================= */

async function main() {
  const initialUrl =
    normalizeUrl(input);

  const initialDomain =
    analyzeDomain(initialUrl);

  const redirectResult =
    await followRedirects(
      initialUrl
    );

  const finalResponse =
    redirectResult.final;

  const finalUrl =
    finalResponse.targetUrl;

  const finalDomain =
    analyzeDomain(finalUrl);

  const headers =
    analyzeSecurityHeaders(
      finalResponse.headers
    );

  const certificate =
    analyzeCertificate(
      finalResponse.tls
    );

  const page =
    analyzePage(
      finalResponse.body,
      finalUrl
    );

  const categories =
    detectCategories(page);

  const ads =
    analyzeAds(
      finalResponse.body,
      page.externalDomains
    );

  const infrastructure =
    analyzeInfrastructure(
      finalResponse.headers,
      page.externalDomains
    );

  const hostname =
    finalDomain.hostname;

  /* -------------------------------------------------------
     DNS + RDAP IN PARALLEL
  ------------------------------------------------------- */

  const [
    dnsInfo,
    rdap
  ] = await Promise.all([
    resolveDns(hostname),
    getRdap(hostname)
  ]);

  const data = {
    initialUrl,

    finalUrl,

    initialDomain,

    finalDomain,

    finalResponse,

    domain:
      finalDomain,

    headers,

    page,

    categories,

    ads,

    certificate,

    dnsInfo,

    rdap,

    infrastructure,

    redirectChain:
      redirectResult.chain,

    redirectLimit:
      redirectResult.redirectLimit
  };

  const riskResult =
    calculateRisk(
      data
    );

  const report =
    buildReport(
      data,
      riskResult
    );

  console.log(report);
}


/* =========================================================
   ERROR HANDLING
========================================================= */

main().catch(error => {
  console.error(
    "🛡️ WebSafe Research AI"
  );

  console.error("");

  console.error(
    "❌ Research failed."
  );

  console.error(
    `Reason: ${
      error && error.message
        ? error.message
        : "Unknown error"
    }`
  );

  console.error("");

  console.error(
    "🔐 RESEARCH MODE: PUBLIC / PASSIVE ONLY"
  );

  process.exitCode = 1;
});

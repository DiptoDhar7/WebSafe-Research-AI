const https = require("https");
const http = require("http");

const input = process.argv[2] || "https://example.com";

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 8000;

const USER_AGENT =
  "WebSafe-Research-AI/1.0 (public-research-only)";

function normalizeUrl(value) {
  const raw = String(value || "").trim();

  if (!raw) {
    throw new Error("No website URL was provided.");
  }

  if (/^https?:\/\//i.test(raw)) {
    return raw;
  }

  return "https://" + raw;
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

        let body = "";

        response.setEncoding("utf8");

        response.on("data", (chunk) => {
          if (body.length < 20000) {
            body += chunk.slice(
              0,
              20000 - body.length
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
            socket: response.socket
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
    const result = await requestOnce(currentUrl);

    chain.push({
      url: currentUrl,
      statusCode: result.statusCode,
      location: result.location
    });

    const isRedirect =
      result.statusCode >= 300 &&
      result.statusCode < 400;

    if (isRedirect && result.location) {
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

  throw new Error("Redirect analysis failed.");
}

function headerExists(headers, name) {
  return Boolean(headers[name.toLowerCase()]);
}

function isIpAddress(hostname) {
  return (
    /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
    hostname.includes(":")
  );
}

function analyzeDomain(url) {
  const parsed = new URL(url);

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

  const hyphenCount =
    (hostname.match(/-/g) || []).length;

  if (hyphenCount >= 3) {
    warnings.push(
      "Multiple hyphens in hostname"
    );
  }

  const dotCount =
    (hostname.match(/\./g) || []).length;

  if (dotCount >= 4) {
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

  const count =
    Object.values(checks).filter(Boolean).length;

  return {
    checks,
    count
  };
}

function calculateRisk(data) {
  let score = 0;

  const reasons = [];

  const finalUrl =
    new URL(data.final.targetUrl);

  const originalUrl =
    new URL(data.startUrl);

  if (finalUrl.protocol !== "https:") {
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
    data.final.statusCode >= 400
  ) {
    score += 20;

    reasons.push(
      `The final HTTP response is ${data.final.statusCode}.`
    );
  }

  const redirectCount =
    data.chain.length - 1;

  if (redirectCount > 0) {
    score += Math.min(
      redirectCount * 3,
      10
    );

    reasons.push(
      `The website used ${redirectCount} redirect(s).`
    );
  }

  if (redirectCount > 4) {
    score += 10;

    reasons.push(
      "The redirect chain is unusually long."
    );
  }

  if (data.domainWarnings.length > 0) {
    score += Math.min(
      data.domainWarnings.length * 8,
      30
    );

    reasons.push(
      "One or more domain characteristics require additional caution."
    );
  } else {
    reasons.push(
      "No obvious domain warning indicators were observed."
    );
  }

  if (
    data.securityHeaderCount < 2
  ) {
    score += 10;

    reasons.push(
      "Only limited common security headers were observed."
    );
  }

  if (
    data.securityHeaderCount >= 4
  ) {
    reasons.push(
      "Several common security headers were observed."
    );
  }

  if (
    originalUrl.protocol === "http:" &&
    finalUrl.protocol === "https:"
  ) {
    reasons.push(
      "The website upgraded the connection from HTTP to HTTPS."
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

  let risk = "LOW";

  if (score >= 55) {
    risk = "HIGH";
  } else if (score >= 25) {
    risk = "MEDIUM";
  }

  let confidence = 70;

  if (finalUrl.protocol === "https:") {
    confidence += 8;
  }

  if (
    data.securityHeaderCount >= 3
  ) {
    confidence += 7;
  }

  if (
    data.domainWarnings.length === 0
  ) {
    confidence += 6;
  }

  if (
    data.final.statusCode >= 200 &&
    data.final.statusCode < 400
  ) {
    confidence += 5;
  }

  confidence = Math.min(
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

function getTlsInfo(socket) {
  if (
    !socket ||
    typeof socket.getProtocol !== "function"
  ) {
    return {
      protocol: null,
      authorized: null
    };
  }

  return {
    protocol:
      socket.getProtocol(),

    authorized:
      typeof socket.authorized === "boolean"
        ? socket.authorized
        : null
  };
}

function printGuidance(risk) {
  console.log("");
  console.log("👤 USER GUIDANCE");

  if (risk === "LOW") {
    console.log(
      "Browsing: ✅ Generally OK"
    );

    console.log(
      "Personal Data: 🟢 Normal Caution"
    );

    console.log(
      "Account: 🟢 Verify Normally"
    );

    console.log(
      "Payment: 🟡 Verify Before Paying"
    );

    return;
  }

  if (risk === "MEDIUM") {
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

    return;
  }

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
      analyzeDomain(startUrl);

    const result =
      await followRedirects(startUrl);

    const final =
      result.final;

    const security =
      analyzeSecurityHeaders(
        final.headers
      );

    const tls =
      getTlsInfo(final.socket);

    const risk =
      calculateRisk({
        startUrl,
        final,
        chain: result.chain,
        domainWarnings:
          domain.warnings,
        securityHeaderCount:
          security.count
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
      "🔎 Key Findings"
    );

    console.log(
      `• HTTPS: ${
        new URL(final.targetUrl)
          .protocol === "https:"
          ? "✅ PASS"
          : "⚠️ WARNING"
      }`
    );

    console.log(
      `• SSL/TLS: ${
        tls.authorized === true
          ? "✅ CERTIFICATE VERIFIED"
          : tls.authorized === false
          ? "⚠️ CERTIFICATE NOT VERIFIED"
          : "ℹ️ NOT AVAILABLE"
      }`
    );

    console.log(
      `• HTTP Status: ${final.statusCode}`
    );

    const redirectCount =
      result.chain.length - 1;

    console.log(
      `• Redirects: ${
        redirectCount <= 1
          ? "✅ NORMAL"
          : redirectCount <= 3
          ? "🟡 MULTIPLE"
          : "⚠️ UNUSUAL"
      }`
    );

    console.log(
      `• Security Headers: ${
        security.count >= 4
          ? "✅ GOOD"
          : security.count >= 2
          ? "🟡 FAIR"
          : "⚠️ LIMITED"
      } (${security.count}/6)`
    );

    console.log(
      `• Domain Signals: ${
        domain.warnings.length === 0
          ? "✅ NORMAL"
          : "⚠️ CAUTION"
      }`
    );

    if (tls.protocol) {
      console.log(
        `• TLS Protocol: ${tls.protocol}`
      );
    }

    console.log("");

    console.log(
      "🧠 TRUST REASONING"
    );

    for (
      const reason of
      risk.reasons.slice(0, 6)
    ) {
      console.log(
        `• ${reason}`
      );
    }

    for (
      const warning of
      domain.warnings.slice(0, 4)
    ) {
      console.log(
        `• Domain signal: ${warning}`
      );
    }

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

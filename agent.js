'use strict';

/*
 * WebSafe Research AI — V3
 * Public / Passive Website Research Only
 *
 * V3 goals:
 * - Stronger evidence-based risk scoring
 * - Dynamic activity detection
 * - Website identity intelligence
 * - Financial / Crypto detection
 * - Gambling detection
 * - Adult-content detection
 * - Commerce / payment detection
 * - Download / APK detection
 * - Dynamic trust reasoning
 * - Deterministic results
 */

const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const { URL } = require('url');

const USER_AGENT =
  'WebSafe-Research-AI/3.0 (Public Passive Research)';

const REQUEST_TIMEOUT = 8000;
const MAX_REDIRECTS = 5;
const MAX_BODY_SIZE = 120000;

const SECURITY_HEADERS = [
  ['HSTS', 'strict-transport-security'],
  ['CSP', 'content-security-policy'],
  ['X-Content-Type-Options', 'x-content-type-options'],
  ['X-Frame-Options', 'x-frame-options'],
  ['Referrer-Policy', 'referrer-policy'],
  ['Permissions-Policy', 'permissions-policy']
];

/* ---------------------------------------------------------
   BASIC HELPERS
--------------------------------------------------------- */

function normalizeUrl(input) {
  let value = String(input || '').trim();

  if (!value) {
    throw new Error('Website URL is required.');
  }

  if (!/^https?:\/\//i.test(value)) {
    value = 'https://' + value;
  }

  const parsed = new URL(value);

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP and HTTPS websites are supported.');
  }

  return parsed.toString();
}

function safeHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return 'unknown';
  }
}

function truncate(value, max = 500) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();

  if (text.length <= max) {
    return text;
  }

  return text.slice(0, max - 3) + '...';
}

function escapeHtmlEntities(text) {
  return String(text || '')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>');
}

function stripHtml(html) {
  return String(html || '')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function cleanText(text) {
  return escapeHtmlEntities(
    String(text || '')
      .replace(/\s+/g, ' ')
      .trim()
  );
}

function containsAny(text, patterns) {
  const value = String(text || '').toLowerCase();

  return patterns.some(pattern => {
    if (pattern instanceof RegExp) {
      return pattern.test(value);
    }

    return value.includes(String(pattern).toLowerCase());
  });
}

function countMatches(text, patterns) {
  const value = String(text || '').toLowerCase();
  let count = 0;

  for (const pattern of patterns) {
    if (pattern instanceof RegExp) {
      const flags = pattern.flags.includes('g')
        ? pattern.flags
        : pattern.flags + 'g';

      const regex = new RegExp(pattern.source, flags);
      const matches = value.match(regex);

      if (matches) {
        count += matches.length;
      }
    } else {
      const needle = String(pattern).toLowerCase();

      if (needle && value.includes(needle)) {
        count += 1;
      }
    }
  }

  return count;
}

function unique(values) {
  return [...new Set(
    values
      .filter(Boolean)
      .map(value => String(value).trim())
      .filter(Boolean)
  )];
}

/* ---------------------------------------------------------
   HTTP / HTTPS RESEARCH
--------------------------------------------------------- */

function requestPage(url, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    let parsed;

    try {
      parsed = new URL(url);
    } catch {
      reject(new Error('Invalid URL.'));
      return;
    }

    const transport = parsed.protocol === 'https:' ? https : http;

    const options = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || undefined,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8'
      },
      timeout: REQUEST_TIMEOUT
    };

    const req = transport.request(options, res => {
      const chunks = [];
      let total = 0;

      res.on('data', chunk => {
        total += chunk.length;

        if (total <= MAX_BODY_SIZE) {
          chunks.push(chunk);
        }
      });

      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');

        const location = res.headers.location;

        if (
          location &&
          [301, 302, 303, 307, 308].includes(res.statusCode) &&
          redirectsLeft > 0
        ) {
          let nextUrl;

          try {
            nextUrl = new URL(location, url).toString();
          } catch {
            nextUrl = null;
          }

          if (nextUrl) {
            requestPage(nextUrl, redirectsLeft - 1)
              .then(result => {
                resolve({
                  ...result,
                  redirects: [
                    {
                      from: url,
                      to: nextUrl,
                      status: res.statusCode
                    },
                    ...(result.redirects || [])
                  ]
                });
              })
              .catch(reject);

            return;
          }
        }

        resolve({
          requestedUrl: url,
          finalUrl: url,
          statusCode: res.statusCode || 0,
          headers: res.headers || {},
          body,
          redirects: [],
          socket: req.socket
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error('Request timed out.'));
    });

    req.on('error', reject);

    req.end();
  });
}

/* ---------------------------------------------------------
   TLS INFORMATION
--------------------------------------------------------- */

function getTlsInfo(response) {
  const socket = response && response.socket;

  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    return {
      available: false,
      verified: false,
      protocol: null,
      authorizationError: null,
      certificate: null
    };
  }

  const certificate = socket.getPeerCertificate(true);

  return {
    available: true,
    verified: socket.authorized === true,
    protocol:
      typeof socket.getProtocol === 'function'
        ? socket.getProtocol()
        : null,
    authorizationError: socket.authorizationError || null,
    certificate: certificate && Object.keys(certificate).length
      ? certificate
      : null
  };
}

/* ---------------------------------------------------------
   SECURITY HEADERS
--------------------------------------------------------- */

function analyzeSecurityHeaders(headers) {
  const normalized = {};

  for (const [key, value] of Object.entries(headers || {})) {
    normalized[String(key).toLowerCase()] = value;
  }

  const results = [];
  let present = 0;

  for (const [label, header] of SECURITY_HEADERS) {
    const exists = Boolean(normalized[header]);

    if (exists) {
      present += 1;
    }

    results.push({
      label,
      header,
      present,
      value: exists ? truncate(normalized[header], 180) : null
    });
  }

  return {
    present,
    total: SECURITY_HEADERS.length,
    results
  };
}

/* ---------------------------------------------------------
   DOMAIN SIGNALS
--------------------------------------------------------- */

function analyzeDomain(url) {
  const hostname = safeHost(url);
  const lower = hostname.toLowerCase();

  const isIp =
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(lower) ||
    lower.includes(':');

  const signals = [];

  if (isIp) {
    signals.push('IP address used instead of a normal domain');
  }

  if (lower.includes('xn--')) {
    signals.push('Punycode hostname detected');
  }

  if (lower.length > 45) {
    signals.push('Unusually long hostname');
  }

  const hyphenCount = (lower.match(/-/g) || []).length;

  if (hyphenCount >= 4) {
    signals.push('Many hyphens in hostname');
  }

  const labels = lower.split('.').filter(Boolean);

  if (labels.length >= 5) {
    signals.push('Deep subdomain structure');
  }

  const cautionTlds = [
    '.zip',
    '.mov',
    '.click',
    '.top',
    '.work',
    '.download'
  ];

  if (cautionTlds.some(tld => lower.endsWith(tld))) {
    signals.push('Caution-listed TLD');
  }

  return {
    hostname,
    isIp,
    labels,
    signals,
    warning: signals.length > 0
  };
}

/* ---------------------------------------------------------
   HTML METADATA
--------------------------------------------------------- */

function extractMeta(html) {
  const source = String(html || '');

  const titleMatch = source.match(
    /<title\b[^>]*>([\s\S]*?)<\/title>/i
  );

  const descriptionMatch = source.match(
    /<meta\b[^>]*name=["']description["'][^>]*content=["']([^"']*)["'][^>]*>/i
  ) || source.match(
    /<meta\b[^>]*content=["']([^"']*)["'][^>]*name=["']description["'][^>]*>/i
  );

  const ogTitleMatch = source.match(
    /<meta\b[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["'][^>]*>/i
  ) || source.match(
    /<meta\b[^>]*content=["']([^"']*)["'][^>]*property=["']og:title["'][^>]*>/i
  );

  const ogDescriptionMatch = source.match(
    /<meta\b[^>]*property=["']og:description["'][^>]*content=["']([^"']*)["'][^>]*>/i
  ) || source.match(
    /<meta\b[^>]*content=["']([^"']*)["'][^>]*property=["']og:description["'][^>]*>/i
  );

  const title = cleanText(
    titleMatch ? titleMatch[1] : ''
  );

  const description = cleanText(
    descriptionMatch ? descriptionMatch[1] : ''
  );

  const ogTitle = cleanText(
    ogTitleMatch ? ogTitleMatch[1] : ''
  );

  const ogDescription = cleanText(
    ogDescriptionMatch ? ogDescriptionMatch[1] : ''
  );

  return {
    title: truncate(title, 300),
    description: truncate(description, 700),
    ogTitle: truncate(ogTitle, 300),
    ogDescription: truncate(ogDescription, 700)
  };
  }
/* ---------------------------------------------------------
   PAGE INTELLIGENCE
--------------------------------------------------------- */

function analyzePage(body, meta, finalUrl) {
  const html = String(body || '');
  const visibleText = stripHtml(html);

  /*
   * Metadata is included because important website activity
   * may appear in title or description.
   */
  const identityText = [
    meta.title,
    meta.description,
    meta.ogTitle,
    meta.ogDescription,
    visibleText
  ].join(' ');

  const text = identityText.toLowerCase();

  const signals = {
    login: containsAny(text, [
      'login',
      'log in',
      'sign in',
      'signin',
      'create account',
      'my account',
      'register'
    ]),

    payment: containsAny(text, [
      'payment',
      'pay now',
      'checkout',
      'billing',
      'credit card',
      'debit card',
      'paypal',
      'stripe',
      'deposit',
      'withdraw'
    ]),

    download: containsAny(text, [
      'download',
      'download now',
      'apk',
      'android app',
      'install app',
      'software download'
    ]),

    adult: containsAny(text, [
      '18+',
      '18 plus',
      'adult content',
      'adult video',
      'adult videos',
      'porn',
      'pornography',
      'nsfw',
      'xxx'
    ]),

    gambling: containsAny(text, [
      'casino',
      'online casino',
      'gambling',
      'betting',
      'sports betting',
      'bet now',
      'slot games',
      'roulette',
      'blackjack',
      'poker'
    ]),

    highPressure: containsAny(text, [
      'act now',
      'limited time',
      'urgent',
      'guaranteed profit',
      'guaranteed return',
      'risk free',
      'risk-free',
      'double your money',
      '100% profit',
      'last chance'
    ]),

    contact: containsAny(text, [
      'contact us',
      'contact',
      'support',
      'customer support',
      'help center'
    ]),

    privacy: containsAny(text, [
      'privacy policy',
      'privacy',
      'terms of service',
      'terms and conditions',
      'cookie policy'
    ]),

    crypto: containsAny(text, [
      'cryptocurrency',
      'crypto',
      'bitcoin',
      'ethereum',
      'token',
      'tokens',
      'blockchain',
      'web3',
      'defi',
      'nft',
      'wallet',
      'connect wallet',
      'crypto wallet',
      'coin launch',
      'launch coin',
      'project token',
      'project tokens'
    ]),

    trading: containsAny(text, [
      'trade crypto',
      'crypto trading',
      'token trading',
      'trading platform',
      'trade tokens',
      'buy tokens',
      'sell tokens',
      'exchange',
      'swap tokens',
      'swap crypto'
    ]),

    investment: containsAny(text, [
      'investment',
      'invest now',
      'invest today',
      'earn daily',
      'passive income',
      'investment return',
      'roi',
      'high return',
      'profit guarantee',
      'guaranteed returns'
    ]),

    commerce: containsAny(text, [
      'shop',
      'shopping',
      'store',
      'products',
      'product',
      'buy now',
      'add to cart',
      'cart',
      'checkout',
      'order now'
    ])
  };

  const externalDomains = extractExternalDomains(
    html,
    finalUrl
  );

  const detected = [];

  if (
    signals.crypto ||
    signals.trading ||
    signals.investment
  ) {
    detected.push('financial');
  }

  if (signals.gambling) {
    detected.push('gambling');
  }

  if (signals.adult) {
    detected.push('adult');
  }

  if (
    signals.commerce ||
    signals.payment
  ) {
    detected.push('commerce');
  }

  if (signals.download) {
    detected.push('download');
  }

  return {
    meta,
    visibleTextLength: visibleText.length,
    signals,
    detectedCategories: unique(detected),
    externalDomains
  };
}
/* ---------------------------------------------------------
   EXTERNAL DOMAIN ANALYSIS
--------------------------------------------------------- */

function extractExternalDomains(html, finalUrl) {
  const source = String(html || '');
  const domains = [];

  let baseHost = '';

  try {
    baseHost = new URL(finalUrl).hostname.toLowerCase();
  } catch {
    return [];
  }

  const regex = /(?:href|src)=["']([^"']+)["']/gi;
  let match;

  while ((match = regex.exec(source)) !== null) {
    const raw = match[1];

    try {
      const absolute = new URL(raw, finalUrl);
      const host = absolute.hostname.toLowerCase();

      if (
        host &&
        host !== baseHost &&
        !host.endsWith('.' + baseHost)
      ) {
        domains.push(host);
      }
    } catch {
      // Ignore malformed URLs.
    }

    if (domains.length >= 40) {
      break;
    }
  }

  return unique(domains);
}

/* ---------------------------------------------------------
   ADVERTISEMENT INTELLIGENCE
--------------------------------------------------------- */

function analyzeAds(body, finalUrl) {
  const html = String(body || '');
  const lower = html.toLowerCase();

  const adNetworks = [
    'googlesyndication.com',
    'doubleclick.net',
    'googleadservices.com',
    'adsbygoogle',
    'adsterra.com',
    'propellerads.com',
    'popads.net',
    'adskeeper.com',
    'taboola.com',
    'outbrain.com'
  ];

  const detectedNetworks = adNetworks.filter(
    network => lower.includes(network)
  );

  const adClassSignals = [
    'class="ad"',
    "class='ad'",
    'class="ads"',
    "class='ads'",
    'class="advert',
    "class='advert",
    'id="ad-',
    "id='ad-",
    'id="ads-',
    "id='ads-",
    'banner-ad',
    'advertisement'
  ];

  const adMarkers = countMatches(
    html,
    adClassSignals
  );

  const popupSignals = containsAny(lower, [
    'window.open(',
    'popunder',
    'popup',
    'onclick="window.open',
    "onclick='window.open"
  ]);

  const forcedRedirectSignals = containsAny(lower, [
    'location.href',
    'window.location',
    'location.replace',
    'meta http-equiv="refresh"'
  ]);

  const suspiciousAdWords = containsAny(lower, [
    'you are the lucky winner',
    'claim your prize',
    'virus detected',
    'your device is infected',
    'click to remove virus',
    'congratulations you won'
  ]);

  const excessive =
    adMarkers >= 12 ||
    detectedNetworks.length >= 4;

  return {
    detected:
      detectedNetworks.length > 0 ||
      adMarkers > 0,

    networks: detectedNetworks,
    adMarkers,
    popupSignals,
    forcedRedirectSignals,
    excessive,
    suspiciousAdWords
  };
}

/* ---------------------------------------------------------
   DNS RESEARCH
--------------------------------------------------------- */

async function resolveDns(hostname) {
  const result = {
    A: [],
    AAAA: [],
    MX: [],
    NS: []
  };

  const tasks = [
    ['A', dns.resolve4(hostname)],
    ['AAAA', dns.resolve6(hostname)],
    ['MX', dns.resolveMx(hostname)],
    ['NS', dns.resolveNs(hostname)]
  ];

  const settled = await Promise.allSettled(
    tasks.map(task => task[1])
  );

  for (let i = 0; i < tasks.length; i += 1) {
    const [type] = tasks[i];
    const item = settled[i];

    if (item.status === 'fulfilled') {
      result[type] = item.value;
    }
  }

  return result;
}

/* ---------------------------------------------------------
   RDAP PUBLIC DOMAIN RESEARCH
--------------------------------------------------------- */

async function fetchJson(url) {
  return new Promise((resolve, reject) => {
    let parsed;

    try {
      parsed = new URL(url);
    } catch {
      reject(new Error('Invalid JSON URL.'));
      return;
    }

    const req = https.get(
      {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'application/rdap+json, application/json'
        },
        timeout: REQUEST_TIMEOUT
      },
      res => {
        const chunks = [];

        res.on('data', chunk => {
          chunks.push(chunk);
        });

        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');

          if (
            res.statusCode < 200 ||
            res.statusCode >= 300
          ) {
            reject(
              new Error(`HTTP ${res.statusCode}`)
            );
            return;
          }

          try {
            resolve(JSON.parse(raw));
          } catch {
            reject(new Error('Invalid JSON response.'));
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(
        new Error('RDAP request timed out.')
      );
          });

    req.on('error', reject);

    req.end();
  });
}

async function getRdap(hostname) {
  try {
    const data = await fetchJson(
      `https://rdap.org/domain/${encodeURIComponent(hostname)}`
    );

    return {
      available: true,
      data
    };
  } catch {
    return {
      available: false,
      data: null
    };
  }
}
/* ---------------------------------------------------------
   CERTIFICATE INFORMATION
--------------------------------------------------------- */

function analyzeCertificate(tls) {
  if (!tls || !tls.certificate) {
    return {
      available: false,
      subject: null,
      issuer: null,
      validFrom: null,
      validTo: null
    };
  }

  const certificate = tls.certificate;

  const subject =
    certificate.subject &&
    (certificate.subject.CN ||
      certificate.subject.commonName);

  const issuer =
    certificate.issuer &&
    (certificate.issuer.CN ||
      certificate.issuer.commonName);

  return {
    available: true,
    subject: subject || null,
    issuer: issuer || null,
    validFrom: certificate.valid_from || null,
    validTo: certificate.valid_to || null
  };
}

/* ---------------------------------------------------------
   RISK ENGINE
--------------------------------------------------------- */

function calculateRisk({
  url,
  response,
  tls,
  security,
  domain,
  page,
  ads,
  dnsInfo,
  rdap
}) {
  let score = 0;
  const reasons = [];
  const positives = [];

  /*
   * Technical security
   */

  if (url.startsWith('https://')) {
    score -= 4;
    positives.push('HTTPS is enabled.');
  } else {
    score += 18;
    reasons.push(
      'The website does not use HTTPS.'
    );
  }

  if (tls.available) {
    if (tls.verified) {
      score -= 3;
      positives.push(
        'TLS certificate verification succeeded.'
      );
    } else {
      score += 25;
      reasons.push(
        'TLS certificate verification failed.'
      );
    }
  }

  if (
    response &&
    response.statusCode >= 400
  ) {
    score += 12;
    reasons.push(
      `The website returned HTTP ${response.statusCode}.`
    );
  } else if (
    response &&
    response.statusCode >= 200 &&
    response.statusCode < 400
  ) {
    positives.push(
      `The website returned HTTP ${response.statusCode}.`
    );
  }

  if (
    response &&
    response.redirects.length >= 3
  ) {
    score += 12;
    reasons.push(
      `Multiple redirects were observed (${response.redirects.length}).`
    );
  } else if (
    response &&
    response.redirects.length === 0
  ) {
    positives.push(
      'No redirects were observed.'
    );
  }

  /*
   * Domain signals
   */

  if (domain.signals.length > 0) {
    score += Math.min(
      domain.signals.length * 7,
      28
    );

    for (const signal of domain.signals) {
      reasons.push(signal + '.');
    }
  } else {
    positives.push(
      'No basic domain-structure warning indicators were observed.'
    );
  }

  /*
   * Security headers
   */

  const missingHeaders =
    security.total - security.present;

  if (missingHeaders >= 5) {
    score += 8;
  } else if (missingHeaders >= 3) {
    score += 5;
  } else if (missingHeaders === 0) {
    score -= 3;

    positives.push(
      'All checked security headers were present.'
    );
  }

  /*
   * Financial / crypto
   */

  if (page.signals.crypto) {
    score += 9;

    reasons.push(
      'Crypto or token-related activity was detected.'
    );
  }

  if (page.signals.trading) {
    score += 7;

    reasons.push(
      'Trading-related activity was detected.'
    );
  }

  if (page.signals.investment) {
    score += 10;

    reasons.push(
      'Investment or return-related claims were detected.'
    );
  }

  if (page.signals.highPressure) {
    score += 12;

    reasons.push(
      'High-pressure or unusually strong promotional language was detected.'
    );
  }

  /*
   * Gambling
   */

  if (page.signals.gambling) {
    score += 8;

    reasons.push(
      'Gambling or betting activity was detected.'
    );
  }

  /*
   * Adult content is contextual.
   * It is not automatically treated as fraud.
   */

  if (page.signals.adult) {
    score += 1;
  }

  /*
   * Commerce / payment
   */

  if (page.signals.payment) {
    score += 5;

    reasons.push(
      'Payment or checkout-related activity was detected.'
    );
  }

  /*
   * Downloads
   */

  if (page.signals.download) {
    score += 3;
  }

  /*
   * Advertising
   */

  if (ads.popupSignals) {
    score += 4;

    reasons.push(
      'Popup or popunder signals were detected.'
    );
  }

  if (ads.forcedRedirectSignals) {
    score += 8;

    reasons.push(
      'Client-side redirect signals were detected.'
    );
  }

  if (ads.suspiciousAdWords) {
    score += 12;

    reasons.push(
      'Suspicious scareware or prize-style advertising language was detected.'
    );
  }

  if (ads.excessive) {
    score += 4;

    reasons.push(
      'A high level of advertising markers was detected.'
    );
  }

  /*
   * Public evidence availability
   */

  if (rdap.available) {
    positives.push(
      'Public RDAP domain information was available.'
    );
  }

  if (
    dnsInfo.A.length === 0 &&
    dnsInfo.AAAA.length === 0
  ) {
    score += 5;

    reasons.push(
      'No public A or AAAA DNS record was resolved.'
    );
  }

  /*
   * Deterministic bounded score.
   */

  score = Math.max(
    0,
    Math.min(100, Math.round(score))
  );

  let risk;

  if (score <= 19) {
    risk = 'LOW';
  } else if (score <= 39) {
    risk = 'LOW-MODERATE';
  } else if (score <= 59) {
    risk = 'MEDIUM';
  } else if (score <= 79) {
    risk = 'HIGH';
  } else {
    risk = 'VERY HIGH';
  }

  /*
   * Confidence is evidence coverage,
   * NOT a safety percentage.
   */

  let confidence = 55;

  if (response) confidence += 8;
  if (tls.available) confidence += 7;
  if (security.present >= 3) confidence += 4;
  if (page.meta.title) confidence += 4;
  if (page.meta.description) confidence += 4;

  if (
    dnsInfo.A.length ||
    dnsInfo.AAAA.length
  ) {
    confidence += 4;
  }

  if (dnsInfo.NS.length) {
    confidence += 3;
  }

  if (rdap.available) {
    confidence += 5;
  }

  if (page.visibleTextLength > 500) {
    confidence += 3;
  }

  confidence = Math.max(
    50,
    Math.min(97, confidence)
  );

  return {
    score,
    risk,
    confidence,
    reasons: unique(reasons),
    positives: unique(positives)
  };
      }

/* ---------------------------------------------------------
   DYNAMIC CATEGORY REPORTS
--------------------------------------------------------- */

function buildFinancialSection(page) {
  const s = page.signals;

  if (
    !s.crypto &&
    !s.trading &&
    !s.investment &&
    !s.payment
  ) {
    return '';
  }

  const lines = [];

  lines.push('');
  lines.push('💰 FINANCIAL ACTIVITY');
  lines.push('');

  if (s.crypto) {
    lines.push('• Crypto/Token: ⚠️ DETECTED');
  } else {
    lines.push('• Crypto/Token: ❓ NOT DETECTED');
  }

  if (s.trading) {
    lines.push('• Trading: ⚠️ DETECTED');
  } else {
    lines.push('• Trading: ❓ NOT DETECTED');
  }

  if (s.investment) {
    lines.push('• Investment Claims: ⚠️ DETECTED');
  } else {
    lines.push('• Investment Claims: ❓ NOT VERIFIED');
  }

  if (s.payment) {
    lines.push('• Payment Activity: ⚠️ DETECTED');
  } else {
    lines.push('• Payment Activity: ❓ NOT VERIFIED');
  }

  lines.push('');
  lines.push('⚠️ NOTE');
  lines.push(
    'Financial activity does not by itself prove fraud.'
  );
  lines.push(
    'Verify the service, operators and transaction terms'
  );
  lines.push(
    'before sending money or connecting a wallet.'
  );

  return lines.join('\n');
}

function buildGamblingSection(page) {
  const s = page.signals;

  if (!s.gambling) {
    return '';
  }

  const lines = [
    '',
    '🎰 GAMBLING ACTIVITY',
    '',
    '• Gambling: ⚠️ DETECTED',
    '• Betting: ⚠️ DETECTED'
  ];

  if (s.payment) {
    lines.push(
      '• Payment/Deposit: ⚠️ DETECTED'
    );
  } else {
    lines.push(
      '• Payment/Deposit: ❓ NOT VERIFIED'
    );
  }

  lines.push('');
  lines.push('⚠️ NOTE');
  lines.push(
    'Gambling activity does not by itself prove fraud.'
  );
  lines.push(
    'Check licensing, operator identity and payment terms'
  );
  lines.push(
    'before depositing money.'
  );

  return lines.join('\n');
}

function buildAdultSection(page) {
  if (!page.signals.adult) {
    return '';
  }

  return [
    '',
    '🔞 CONTENT CATEGORY',
    '',
    '• Adult Content: ⚠️ DETECTED',
    '• Age Restriction: ⚠️ PRESENT',
    '',
    '⚠️ NOTE',
    'Adult content was detected from public page signals.',
    'This category alone does not indicate that the website'
    + ' is fraudulent or technically unsafe.'
  ].join('\n');
}

/* ---------------------------------------------------------
   COMMERCE / DOWNLOAD / CATEGORY HELPERS
--------------------------------------------------------- */

function buildCommerceSection(page) {
  const s = page.signals;

  if (!s.commerce && !s.payment) {
    return '';
  }

  const lines = [
    '',
    '🛒 COMMERCE ACTIVITY',
    ''
  ];

  if (s.commerce) {
    lines.push(
      '• Products/Shopping: ⚠️ DETECTED'
    );
  } else {
    lines.push(
      '• Products/Shopping: ❓ NOT DETECTED'
    );
  }

  if (s.payment) {
    lines.push(
      '• Checkout/Payment: ⚠️ DETECTED'
    );
  } else {
    lines.push(
      '• Checkout/Payment: ❓ NOT VERIFIED'
    );
  }

  lines.push('');
  lines.push('⚠️ NOTE');
  lines.push(
    'Shopping or payment activity does not by itself'
  );
  lines.push(
    'prove that a website is fraudulent.'
  );
  lines.push(
    'Verify the seller, product details and payment terms'
  );
  lines.push(
    'before making a purchase.'
  );

  return lines.join('\n');
}

function buildDownloadSection(page) {
  if (!page.signals.download) {
    return '';
  }

  return [
    '',
    '📥 DOWNLOAD ACTIVITY',
    '',
    '• Download/App Signals: ⚠️ DETECTED',
    '',
    '⚠️ NOTE',
    'A downloadable file or app-related signal was found.',
    'Verify the source and file before downloading or installing.'
  ].join('\n');
}

/* ---------------------------------------------------------
   CONTENT SIGNAL SUMMARY
--------------------------------------------------------- */

function buildContentSection(page) {
  const s = page.signals;
  const detected = [];

  if (s.login) {
    detected.push('Login/Account');
  }

  if (s.payment) {
    detected.push('Payment');
  }

  if (s.contact) {
    detected.push('Contact/Support');
  }

  if (s.privacy) {
    detected.push('Privacy/Terms');
  }

  if (s.highPressure) {
    detected.push('High-Pressure Language');
  }

  if (detected.length === 0) {
    return [
      '',
      '📄 PAGE CONTENT SIGNALS',
      '• ℹ️ No major checked content signal detected.'
    ].join('\n');
  }

  return [
    '',
    '📄 PAGE CONTENT SIGNALS',
    ...detected.map(
      item => `• ⚠️ ${item}: DETECTED`
    )
  ].join('\n');
}

/* ---------------------------------------------------------
   IDENTITY CLASSIFICATION
--------------------------------------------------------- */

function classifyWebsite(page, finalUrl) {
  const text = [
    page.meta.title,
    page.meta.description,
    page.meta.ogTitle,
    page.meta.ogDescription
  ]
    .join(' ')
    .toLowerCase();

  if (
    page.signals.crypto ||
    page.signals.trading ||
    page.signals.investment
  ) {
    return 'Financial / Crypto-related website';
  }

  if (page.signals.gambling) {
    return 'Gambling / Betting-related website';
  }

  if (page.signals.adult) {
    return 'Adult-content website';
  }

  if (
    page.signals.commerce ||
    page.signals.payment
  ) {
    return 'Commerce / Shopping-related website';
  }

  if (page.signals.download) {
    return 'Download / Software-related website';
  }

  if (
    text.includes('github') ||
    text.includes('open source') ||
    text.includes('developer') ||
    text.includes('repository')
  ) {
    return 'Developer / Technology-related website';
  }

  if (
    page.signals.login ||
    page.signals.contact ||
    page.signals.privacy
  ) {
    return 'General web service / information website';
  }

  try {
    const hostname = new URL(finalUrl).hostname;

    return `General website (${hostname})`;
  } catch {
    return 'General website';
  }
}

/* ---------------------------------------------------------
   TRUST REASONING
--------------------------------------------------------- */

function buildTrustReasoning(result) {
  const lines = [
    '',
    '🧠 TRUST REASONING'
  ];

  const reasons = result.reasons || [];
  const positives = result.positives || [];

  for (const item of positives.slice(0, 5)) {
    lines.push(`• ${item}`);
  }

  for (const item of reasons.slice(0, 8)) {
    lines.push(`• ⚠️ ${item}`);
  }

  if (
    positives.length === 0 &&
    reasons.length === 0
  ) {
    lines.push(
      '• Limited public evidence was available in this run.'
    );
  }

  lines.push('');
  lines.push(
    'The assessment is based on the public evidence'
  );
  lines.push(
    'observed during this research run.'
  );

  return lines.join('\n');
  }

/* ---------------------------------------------------------
   USER GUIDANCE
--------------------------------------------------------- */

function buildUserGuidance(page, risk) {
  let browsing = '🟢 Generally OK';
  let personalData = '🟢 Normal Caution';
  let account = '🟢 Verify Normally';
  let payment = '🟢 Verify Normally';

  if (risk.score >= 20) {
    browsing = '🟡 Use Caution';
    personalData = '🟡 Verify First';
    account = '🟡 Verify Carefully';
  }

  if (risk.score >= 40) {
    browsing = '🟠 Proceed Carefully';
    personalData = '🟠 Avoid Unnecessary Sharing';
    account = '🟠 Verify Before Using';
  }

  if (risk.score >= 60) {
    browsing = '🔴 High Caution';
    personalData = '🔴 Avoid Sharing Sensitive Data';
    account = '🔴 Avoid Unless Verified';
  }

  if (
    page.signals.payment ||
    page.signals.crypto ||
    page.signals.trading ||
    page.signals.investment ||
    page.signals.gambling
  ) {
    payment = '🟠 Verify Before Paying';
  }

  return [
    '',
    '👤 USER GUIDANCE',
    `Browsing: ${browsing}`,
    `Personal Data: ${personalData}`,
    `Account: ${account}`,
    `Payment: ${payment}`
  ].join('\n');
}

/* ---------------------------------------------------------
   SECURITY HEADER REPORT
--------------------------------------------------------- */

function buildSecurityHeaderSection(security) {
  const headers = security.headers || {};

  const names = [
    ['HSTS', 'strict-transport-security'],
    ['CSP', 'content-security-policy'],
    [
      'X-Content-Type-Options',
      'x-content-type-options'
    ],
    ['X-Frame-Options', 'x-frame-options'],
    ['Referrer-Policy', 'referrer-policy'],
    ['Permissions-Policy', 'permissions-policy']
  ];

  const lines = [
    '',
    '🛡️ SECURITY HEADERS'
  ];

  for (const [label, key] of names) {
    if (headers[key]) {
      lines.push(`  • ${label}: ✅ Present`);
    } else {
      lines.push(`  • ${label}: ❌ Missing`);
    }
  }

  return lines.join('\n');
}

/* ---------------------------------------------------------
   DOMAIN & DNS REPORT
--------------------------------------------------------- */

function buildDnsSection(domain, dnsInfo, rdap) {
  const lines = [
    '',
    '🌍 DOMAIN & DNS',
    `• Hostname: ${domain.hostname}`,
    `• A: ${
      dnsInfo.A.length
        ? dnsInfo.A.join(', ')
        : '❓ Not available'
    }`,
    `• AAAA: ${
      dnsInfo.AAAA.length
        ? dnsInfo.AAAA.join(', ')
        : '❓ Not available'
    }`,
    `• MX: ${
      dnsInfo.MX.length
        ? dnsInfo.MX
            .map(item => item.exchange || item)
            .join(', ')
        : '❓ Not available'
    }`,
    `• NS: ${
      dnsInfo.NS.length
        ? dnsInfo.NS.join(', ')
        : '❓ Not available'
    }`,
    `• RDAP: ${
      rdap.available
        ? '✅ AVAILABLE'
        : '❓ NOT AVAILABLE'
    }`
  ];

  return lines.join('\n');
}

/* ---------------------------------------------------------
   CERTIFICATE REPORT
--------------------------------------------------------- */

function buildCertificateSection(certificate) {
  if (!certificate.available) {
    return [
      '',
      '🔐 CERTIFICATE',
      '• ℹ️ Certificate details not available.'
    ].join('\n');
  }

  return [
    '',
    '🔐 CERTIFICATE',
    `• Subject: ${
      certificate.subject || 'Unknown'
    }`,
    `• Issuer: ${
      certificate.issuer || 'Unknown'
    }`,
    `• Valid From: ${
      certificate.validFrom || 'Unknown'
    }`,
    `• Valid To: ${
      certificate.validTo || 'Unknown'
    }`
  ].join('\n');
}

/* ---------------------------------------------------------
   ADVERTISEMENT REPORT
--------------------------------------------------------- */

function buildAdSection(ads) {
  const lines = [
    '',
    '📢 AD & POPUP ANALYSIS',
    `• Advertisements: ${
      ads.detected
        ? '⚠️ DETECTED'
        : '✅ NOT DETECTED'
    }`,
    `• Popup Signals: ${
      ads.popupSignals
        ? '⚠️ DETECTED'
        : '✅ NOT DETECTED'
    }`,
    `• Excessive Ads: ${
      ads.excessive
        ? '⚠️ DETECTED'
        : '✅ NOT DETECTED'
    }`,
    `• Suspicious Ad/Content Signals: ${
      ads.suspiciousAdWords
        ? '⚠️ DETECTED'
        : '✅ NOT DETECTED'
    }`
  ];

  if (ads.networks.length > 0) {
    lines.push(
      `• Ad Networks: ${ads.networks.join(', ')}`
    );
  }

  return lines.join('\n');
}

/* ---------------------------------------------------------
   MAIN REPORT BUILDER
--------------------------------------------------------- */

function buildReport(data) {
  const {
    requestedUrl,
    finalUrl,
    response,
    tls,
    security,
    domain,
    page,
    ads,
    dnsInfo,
    rdap,
    risk,
    certificate
  } = data;

  const lines = [
    '🛡️ WebSafe Research AI',
    '',
    `🌐 Website: ${requestedUrl}`,
    ''
  ];

  lines.push(
    `🛡️ Risk: ${risk.risk}`,
    `🎯 Confidence: ${risk.confidence}%`,
    `📊 Risk Score: ${risk.score}/100`,
    '',
    '🔎 KEY FINDINGS',
    `• HTTPS: ${
      requestedUrl.startsWith('https://')
        ? '✅ PASS'
        : '❌ NOT SECURE'
    }`,
    `• HTTP Status: ${
      response
        ? response.statusCode
        : '❓ UNKNOWN'
    }`,
    `• Redirects: ${
      response && response.redirects.length === 0
        ? '✅ NONE'
        : response
          ? `⚠️ ${response.redirects.length}`
          : '❓ UNKNOWN'
    }`,
    `• SSL/TLS: ${
      tls.available
        ? tls.verified
          ? '✅ VERIFIED'
          : '❌ FAILED'
        : '❓ NOT AVAILABLE'
    }`
  );

  if (tls.protocol) {
    lines.push(
      `• TLS Protocol: ${tls.protocol}`
    );
  }

  lines.push(
    `• Security Headers: ${security.present}/${security.total}`,
    `• Domain Signals: ${
      domain.signals.length === 0
        ? '✅ NO BASIC WARNING'
        : `⚠️ ${domain.signals.length} WARNING(S)`
    }`
  );

  lines.push(
    '',
    '🏷️ WEBSITE IDENTITY',
    `• Title: ${
      page.meta.title || 'Not available'
    }`,
    `• Description: ${
      page.meta.description || 'Not available'
    }`,
    `• Classification: ${
      classifyWebsite(page, finalUrl)
    }`
  );

  lines.push(
    buildContentSection(page)
  );

  lines.push(
    buildCertificateSection(certificate)
  );

  lines.push(
    buildSecurityHeaderSection(security)
  );

  lines.push(
    buildDnsSection(
      domain,
      dnsInfo,
      rdap
    )
  );

  lines.push(
    buildAdSection(ads)
  );

  /*
   * IMPORTANT:
   * These sections are conditional.
   * They appear only when relevant activity is detected.
   */

  lines.push(
    buildFinancialSection(page)
  );

  lines.push(
    buildGamblingSection(page)
  );

  lines.push(
    buildAdultSection(page)
  );

  lines.push(
    buildCommerceSection(page)
  );

  lines.push(
    buildDownloadSection(page)
  );

  lines.push(
    buildTrustReasoning(risk)
  );

  lines.push(
    buildUserGuidance(page, risk)
  );

  lines.push(
    '',
    '⚠️ IMPORTANT',
    'AI-generated research assessment — not a guarantee',
    'that the website is safe or fraudulent.',
    'Results may change over time. Verify important',
    'information yourself.',
    '',
    '🔐 RESEARCH MODE: PUBLIC / PASSIVE ONLY',
    '🚫 Hacking: DISABLED',
    '🚫 Exploitation: DISABLED',
    '🚫 Unauthorized Access: DISABLED'
  );

  return lines
    .filter(line => line !== undefined)
    .join('\n');
}
/* ---------------------------------------------------------
   MAIN
--------------------------------------------------------- */

async function main() {
  const input = process.argv[2];

  if (!input) {
    console.error(
      'Usage: node agent.js <website-url>'
    );
    process.exit(1);
  }

  let requestedUrl;

  try {
    requestedUrl = normalizeUrl(input);
  } catch (error) {
    console.error(
      '❌ Invalid website URL.'
    );
    process.exit(1);
  }

  let response;

  try {
    response = await fetchWebsite(requestedUrl);
  } catch (error) {
    console.error(
      '❌ Website research failed.'
    );
    console.error(
      `Reason: ${error.message}`
    );
    process.exit(1);
  }

  const finalUrl =
    response.finalUrl || requestedUrl;

  let parsedFinalUrl;

  try {
    parsedFinalUrl = new URL(finalUrl);
  } catch {
    console.error(
      '❌ Final website URL could not be parsed.'
    );
    process.exit(1);
  }

  const hostname =
    parsedFinalUrl.hostname.toLowerCase();

  /*
   * Run independent public research tasks together.
   * This keeps the research reasonably fast.
   */

  const [
    dnsInfo,
    rdap
  ] = await Promise.all([
    resolveDns(hostname),
    getRdap(hostname)
  ]);

  const page =
    analyzePage(
      response.body || '',
      response.meta || {},
      finalUrl
    );

  const ads =
    analyzeAds(
      response.body || '',
      finalUrl
    );

  const security =
    analyzeSecurityHeaders(
      response.headers || {}
    );

  const domain =
    analyzeDomain(
      hostname
    );

  const tls =
    response.tls || {
      available: false,
      verified: false,
      protocol: null,
      certificate: null
    };

  const certificate =
    analyzeCertificate(tls);

  const risk =
    calculateRisk({
      url: finalUrl,
      response,
      tls,
      security,
      domain,
      page,
      ads,
      dnsInfo,
      rdap
    });

  const report =
    buildReport({
      requestedUrl,
      finalUrl,
      response,
      tls,
      security,
      domain,
      page,
      ads,
      dnsInfo,
      rdap,
      risk,
      certificate
    });

  console.log(report);
}

/* ---------------------------------------------------------
   START WEBSAFE RESEARCH AI
--------------------------------------------------------- */

main().catch(error => {
  console.error('');
  console.error(
    '❌ WebSafe Research AI stopped unexpectedly.'
  );
  console.error(
    `Reason: ${error.message}`
  );
  process.exit(1);
});

// analyzers/deep-checks.js
// Passive checks for concrete weaknesses that browsers do not show in their UI.
// Nothing here sends extra requests or probes the server — it only reads what
// the page, its response headers, and the browser have already exposed.
//
// Finding flags:
//   blocker: true  → do not trust this page with sensitive data
//   caution: true  → trust with care

function versionLessThan(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y;
  }
  return false;
}

// Version is read from the script URL only (e.g. jquery-1.12.4.min.js,
// /jquery/3.6.0/, jquery@3.6.0, jquery.min.js?ver=3.6.0).
const LIBRARIES = [
  {
    name: 'jQuery', slug: 'jquery',
    vulnerable: v => versionLessThan(v, '3.5.0'),
    note: 'versions before 3.5.0 have known XSS flaws (CVE-2020-11022, CVE-2020-11023)'
  },
  {
    name: 'Bootstrap', slug: 'bootstrap',
    vulnerable: v => versionLessThan(v, '3.4.1') || (v.startsWith('4.') && versionLessThan(v, '4.3.1')),
    note: 'versions before 3.4.1 / 4.3.1 have a known XSS flaw (CVE-2019-8331)'
  },
  {
    name: 'AngularJS', slug: 'angular',
    vulnerable: v => v.startsWith('1.'),
    note: 'AngularJS 1.x is end-of-life and no longer receives security fixes'
  },
  {
    name: 'Lodash', slug: 'lodash',
    vulnerable: v => versionLessThan(v, '4.17.21'),
    note: 'versions before 4.17.21 have known injection / prototype-pollution flaws (CVE-2021-23337)'
  }
];

function findVulnerableLibraries(scripts) {
  const hits = new Map();
  for (const src of scripts || []) {
    for (const lib of LIBRARIES) {
      const re = new RegExp(`${lib.slug}(?:\\.min)?(?:\\.js)?(?:\\?ver)?[/@=.-]?v?(\\d+\\.\\d+\\.\\d+)`, 'i');
      const m = src.match(re);
      if (m && lib.vulnerable(m[1]) && !hits.has(lib.name)) {
        hits.set(lib.name, { name: lib.name, version: m[1], note: lib.note });
      }
    }
  }
  return [...hits.values()];
}

export function runDeepChecks(pageData, isHttps) {
  const findings = [];
  let penalty = 0;

  const add = (type, icon, text, flags = {}) =>
    findings.push({ type, icon, text, category: 'security', ...flags });

  const headers = pageData.responseHeaders?.headers || null;

  // 1. Certificate error reported by the browser
  if (pageData.certError) {
    penalty += 15;
    add('danger', '✗',
      `The browser reported a certificate error for this site (${pageData.certError.error}). ` +
      'Its identity could not be verified, so the connection could be intercepted — and the browser warning was bypassed.',
      { blocker: true });
  }

  // 2. Login forms
  const pwForms = pageData.passwordForms || [];

  if (pwForms.some(f => f.method === 'get')) {
    penalty += 5;
    add('danger', '✗',
      'Login form sends the password in the URL (GET) — it can be stored in browser history, server logs, and Referer headers.',
      { blocker: true });
  }

  if (isHttps && pwForms.some(f => f.actionProtocol === 'http:')) {
    penalty += 6;
    add('danger', '✗',
      'Login form submits over unencrypted HTTP even though this page is HTTPS — the password travels in plain text.',
      { blocker: true });
  }

  if (isHttps && pwForms.length > 0 && headers && !headers['strict-transport-security']) {
    add('warning', '⚠',
      'Login page without HSTS — on an untrusted network (e.g. public Wi-Fi) an attacker could strip HTTPS before you reach this page.',
      { caution: true });
  }

  // 3. Known-vulnerable JavaScript libraries
  const vulnerable = findVulnerableLibraries(pageData.scripts);
  vulnerable.forEach(v =>
    add('danger', '✗', `${v.name} ${v.version} detected — ${v.note}.`, { caution: true })
  );
  penalty += Math.min(6, vulnerable.length * 3);

  // 4. Session ID exposed in URLs
  if (pageData.sessionIdInUrl) {
    penalty += 3;
    add('warning', '⚠',
      'Session ID appears in page URLs — it can leak through history, logs, shared links, and Referer headers, allowing session hijacking.',
      { caution: true });
  }

  // 5. Weak Content-Security-Policy
  const csp = headers?.['content-security-policy'] || '';
  if (csp) {
    const scriptSrc = (csp.match(/script-src[^;]*/i) || csp.match(/default-src[^;]*/i) || [''])[0];
    const hasNonceOrHash = /'nonce-|'sha(256|384|512)-|'strict-dynamic'/i.test(scriptSrc);
    if (/'unsafe-inline'/i.test(scriptSrc) && !hasNonceOrHash) {
      penalty += 1;
      add('warning', '⚠',
        "Content-Security-Policy allows inline scripts ('unsafe-inline'), which removes most of its protection against XSS.");
    }
  }

  // 6. HSTS strength
  const hsts = headers?.['strict-transport-security'];
  if (hsts) {
    const m = hsts.match(/max-age=(\d+)/i);
    if (m && Number(m[1]) < 15552000) {
      add('neutral', 'ℹ',
        `HSTS max-age is short (${Math.round(Number(m[1]) / 86400)} days) — at least 180 days is recommended.`);
    }
  }

  // 7. Subresource Integrity (informational — often unavoidable for analytics)
  const noSri = pageData.thirdPartyNoSRI || 0;
  if (noSri > 0) {
    add('neutral', 'ℹ',
      `${noSri} third-party script(s) loaded without Subresource Integrity — tampered code from that provider would not be detected. Not scored.`);
  }

  return { penalty, findings };
}
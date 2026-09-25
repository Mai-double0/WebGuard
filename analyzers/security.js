// analyzers/security.js
// Security indicators. Observations alone are informational; points are
// deducted only for real risk signals. Returns a score (0–25) and findings.

const SESSION_COOKIE = /sess|sid|auth|token|login|jsession|phpsessid|asp\.net/i;

export function analyzeSecurity(pageData) {
  const findings = [];
  let score = 25;

  const add = (type, icon, text) =>
    findings.push({ type, icon, text, category: 'security' });

  const isHttps  = pageData.protocol === 'https:';
  const pageHost = (pageData.domain || '').replace(/^www\./, '');

  // =====================
  // HTTPS
  // =====================
  if (isHttps) {
    add('positive', '✓', 'HTTPS connection detected — data is encrypted in transit.');
  } else {
    score -= 10;
    add('danger', '✗', 'No HTTPS — connection is unencrypted. Avoid entering sensitive data.');
  }

  // =====================
  // MIXED CONTENT
  // =====================
  const mixedCount = pageData.mixedContentIndicators?.length || 0;
  if (mixedCount > 0) {
    score -= 5;
    add('warning', '⚠', `Mixed content detected — ${mixedCount} HTTP resource(s) loaded on an HTTPS page.`);
  }

  // =====================
  // SECURITY HEADERS & COOKIES
  // =====================
  score -= analyzeHeaders(pageData, isHttps, add);

  // =====================
  // HIDDEN IFRAMES
  // =====================
  const hiddenThirdParty = (pageData.hiddenIframes || [])
    .filter(f => f.src && pageHost && !f.src.includes(pageHost));
  if (hiddenThirdParty.length > 2) {
    score -= 2;
    add('warning', '⚠', `${hiddenThirdParty.length} hidden third-party iframes detected.`);
  } else if (hiddenThirdParty.length > 0) {
    add('neutral', 'ℹ', `${hiddenThirdParty.length} hidden third-party iframe(s) — often analytics or payment widgets.`);
  }

  // =====================
  // DOWNLOADS — judged by context, not presence
  // =====================
  const downloads = pageData.downloadLinks || [];
  const risky   = downloads.filter(d => d.protocol === 'http:' || d.isIP || d.doubleExt);
  const offsite = downloads.filter(d => !d.sameSite && !risky.includes(d));

  if (risky.length > 0) {
    score -= 6;
    add('danger', '✗', `${risky.length} executable download(s) with risky traits (unencrypted, IP-address host, or disguised file extension).`);
  } else if (offsite.length > 0) {
    score -= 1;
    add('neutral', 'ℹ', `${offsite.length} executable download(s) hosted on another domain — common for CDNs. Confirm the source if unsure.`);
  } else if (downloads.length > 0) {
    add('neutral', 'ℹ', 'Executable downloads offered by this site over HTTPS — normal for software sites.');
  }

  // =====================
  // FORMS
  // =====================
  const externalForms = pageData.externalFormActions?.length || 0;
  if (externalForms > 0 && pageData.hasPasswordField) {
    score -= 6;
    add('danger', '✗', 'A login form submits to an external domain — credentials would leave this site.');
  } else if (externalForms > 0) {
    score -= 2;
    add('warning', '⚠', `${externalForms} form(s) submit data to external domains — verify the destination.`);
  }

  if (pageData.hasPasswordField && !isHttps) {
    score -= 8;
    add('danger', '✗', 'Password field on an unencrypted (HTTP) page — credentials could be intercepted.');
  }

  // =====================
  // IP ADDRESS DOMAIN
  // =====================
  if (pageData.hasIPAddress) {
    score -= 6;
    add('danger', '✗', 'Site is accessed via IP address instead of a domain name — unusual for legitimate sites.');
  }

  score = Math.max(0, Math.min(25, score));
  return { score, maxScore: 25, findings };
}

// =====================
// HEADER + COOKIE ANALYSIS
// Returns the total penalty. Missing headers are hardening gaps,
// not proof of a vulnerability — the finding text says so.
// =====================
function analyzeHeaders(pageData, isHttps, add) {
  const rh = pageData.responseHeaders;

  if (!rh) {
    add('neutral', 'ℹ', 'Security headers: not available — response headers were not captured for this page (e.g. cached or restricted load). Not scored.');
    return 0;
  }

  const h = rh.headers || {};
  let penalty = 0;

  // Content-Security-Policy
  const csp = h['content-security-policy'] || '';
  if (csp) {
    add('positive', '✓', 'Content-Security-Policy header present.');
  } else if (pageData.hasMetaCSP) {
    add('positive', '✓', 'Content-Security-Policy set via meta tag.');
  } else {
    penalty += 3;
    add('warning', '⚠', 'Content-Security-Policy not set — less protection against script injection (XSS). A hardening gap, not proof of a vulnerability.');
  }

  // HSTS (only meaningful on HTTPS)
  if (isHttps) {
    if (h['strict-transport-security']) {
      add('positive', '✓', 'HSTS header present — browsers will refuse to downgrade this site to HTTP.');
    } else {
      penalty += 2;
      add('warning', '⚠', 'Strict-Transport-Security (HSTS) not set — a first visit could be downgraded to HTTP on a hostile network.');
    }
  }

  // Clickjacking protection
  const frameProtected = h['x-frame-options'] || /frame-ancestors/i.test(csp);
  if (!frameProtected) {
    penalty += 2;
    add('warning', '⚠', 'No clickjacking protection (X-Frame-Options or CSP frame-ancestors) — another site could embed this page.');
  }

  // MIME sniffing
  if (!(h['x-content-type-options'] || '').toLowerCase().includes('nosniff')) {
    penalty += 1;
    add('warning', '⚠', 'X-Content-Type-Options: nosniff not set.');
  }

  // Referrer-Policy — modern browsers have a safe default, so informational only
  if (!h['referrer-policy']) {
    add('neutral', 'ℹ', 'Referrer-Policy not set — the browser default applies. Not scored.');
  }

  // Server version disclosure
  const banner = [h['server'], h['x-powered-by']].filter(Boolean).find(v => /\d/.test(v));
  if (banner) {
    penalty += 1;
    add('warning', '⚠', `Server software version disclosed ("${banner.slice(0, 60)}") — makes it easier to look up known vulnerabilities.`);
  }

  // Session cookie flags
  const cookies = (rh.setCookies || []).map(c => ({
    name:     c.split('=')[0].trim(),
    secure:   /;\s*secure/i.test(c),
    httpOnly: /;\s*httponly/i.test(c)
  }));
  const sessionCookies = cookies.filter(c => SESSION_COOKIE.test(c.name));

  const noHttpOnly = sessionCookies.filter(c => !c.httpOnly);
  if (noHttpOnly.length > 0) {
    penalty += 2;
    add('warning', '⚠', `Session cookie(s) without HttpOnly (${noHttpOnly.slice(0, 3).map(c => c.name).join(', ')}) — page scripts can read them, so an XSS bug could steal the session.`);
  }

  if (isHttps) {
    const noSecure = sessionCookies.filter(c => !c.secure);
    if (noSecure.length > 0) {
      penalty += 2;
      add('warning', '⚠', `Session cookie(s) without the Secure flag (${noSecure.slice(0, 3).map(c => c.name).join(', ')}) — could be sent over unencrypted HTTP.`);
    }
  }

  return penalty;
}
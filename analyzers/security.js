// analyzers/security.js
// Security indicators. Observations alone are informational; points are
// deducted only for real risk signals. Returns a score (0–25) and findings.
//
// Finding flags used by the trust verdict:
//   blocker: true → do not trust this page with sensitive data
//   caution: true → trust with care

import { runDeepChecks } from './deep-checks.js';

// Session cookie detection. Substring matching (e.g. /sid/) flags unrelated
// cookies such as SIDCC or activitySessionId, so names are matched exactly or
// by whole word instead.
const KNOWN_SESSION_NAMES = new Set([
  'jsessionid', 'phpsessid', 'asp.net_sessionid', 'connect.sid',
  'laravel_session', 'ci_session', 'sessionid', 'session_id', 'sid'
]);
const KNOWN_SESSION_PATTERNS = [
  /^aspsessionid[a-z]*$/,  // classic ASP: ASPSESSIONIDQQQRSTUV
  /_session$/             // framework convention: myapp_session
];
const SESSION_WORDS = new Set(['session', 'sessionid']);

// 'known' → a well-known session cookie name
// 'maybe' → "session" appears as a whole word, but the name is not a known one
// null    → not treated as a session cookie
export function classifySessionCookie(name) {
  // __Host- / __Secure- are cookie-name prefixes, not part of the name itself
  const n = String(name || '').toLowerCase().replace(/^__(host|secure)-/, '');
  if (KNOWN_SESSION_NAMES.has(n) || KNOWN_SESSION_PATTERNS.some(p => p.test(n))) return 'known';
  if (n.split(/[_\-.:]/).some(word => SESSION_WORDS.has(word))) return 'maybe';
  return null;
}

export function analyzeSecurity(pageData) {
  const findings = [];
  let score = 25;

  const add = (type, icon, text, flags = {}) =>
    findings.push({ type, icon, text, category: 'security', ...flags });

  const isHttps  = pageData.protocol === 'https:';
  const pageHost = (pageData.domain || '').replace(/^www\./, '');

  // =====================
  // HTTPS
  // =====================
  if (isHttps) {
    add('positive', '✓', 'HTTPS connection detected — data is encrypted in transit.');
  } else {
    score -= 10;
    add('danger', '✗', 'No HTTPS — connection is unencrypted. Avoid entering sensitive data.', { caution: true });
  }

  // =====================
  // MIXED CONTENT
  // =====================
  const mixedCount = pageData.mixedContentIndicators?.length || 0;
  if (mixedCount > 0) {
    score -= 5;
    add('warning', '⚠', `Mixed content detected — ${mixedCount} HTTP resource(s) loaded on an HTTPS page.`, { caution: true });
  }

  // =====================
  // SECURITY HEADERS & COOKIES
  // =====================
  score -= analyzeHeaders(pageData, isHttps, add);

  // =====================
  // DEEP CHECKS (certificate, login forms, vulnerable libraries, sessions)
  // =====================
  const deep = runDeepChecks(pageData, isHttps);
  score -= deep.penalty;
  findings.push(...deep.findings);

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
    add('danger', '✗', `${risky.length} executable download(s) with risky traits (unencrypted, IP-address host, or disguised file extension).`, { blocker: true });
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
    add('danger', '✗', 'A login form submits to an external domain — credentials would leave this site.', { blocker: true });
  } else if (externalForms > 0) {
    score -= 2;
    add('warning', '⚠', `${externalForms} form(s) submit data to external domains — verify the destination.`, { caution: true });
  }

  if (pageData.hasPasswordField && !isHttps) {
    score -= 8;
    add('danger', '✗', 'Password field on an unencrypted (HTTP) page — credentials could be intercepted.', { blocker: true });
  }

  // =====================
  // IP ADDRESS DOMAIN
  // =====================
  if (pageData.hasIPAddress) {
    score -= 6;
    add('danger', '✗', 'Site is accessed via IP address instead of a domain name — unusual for legitimate sites.', { caution: true });
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
        add('neutral', 'ℹ', 'Security headers: not available — this page was loaded before WebGuard started, or restored from cache. Reload the page (Ctrl+Shift+R) for a full check. Not scored.');
    return 0;
  }

  const h = rh.headers || {};
  let penalty = 0;

  const csp = h['content-security-policy'] || '';
  if (csp) {
    add('positive', '✓', 'Content-Security-Policy header present.');
  } else if (pageData.hasMetaCSP) {
    add('positive', '✓', 'Content-Security-Policy set via meta tag.');
  } else {
    penalty += 3;
    add('warning', '⚠', 'Content-Security-Policy not set — less protection against script injection (XSS). A hardening gap, not proof of a vulnerability.');
  }

  if (isHttps) {
    if (h['strict-transport-security']) {
      add('positive', '✓', 'HSTS header present — browsers will refuse to downgrade this site to HTTP.');
    } else {
      penalty += 2;
      add('warning', '⚠', 'Strict-Transport-Security (HSTS) not set — a first visit could be downgraded to HTTP on a hostile network.');
    }
  }

  const frameProtected = h['x-frame-options'] || /frame-ancestors/i.test(csp);
  if (!frameProtected) {
    penalty += 2;
    add('warning', '⚠', 'No clickjacking protection (X-Frame-Options or CSP frame-ancestors) — another site could embed this page.');
  }

  if (!(h['x-content-type-options'] || '').toLowerCase().includes('nosniff')) {
    penalty += 1;
    add('warning', '⚠', 'X-Content-Type-Options: nosniff not set.');
  }

  if (!h['referrer-policy']) {
    add('neutral', 'ℹ', 'Referrer-Policy not set — the browser default applies. Not scored.');
  }

  const banner = [h['server'], h['x-powered-by']].filter(Boolean).find(v => /\d/.test(v));
  if (banner) {
    penalty += 1;
    add('warning', '⚠', `Server software version disclosed ("${banner.slice(0, 60)}") — makes it easier to look up known vulnerabilities.`);
  }

  const sessionCookies = (rh.cookies || [])
    .map(c => ({ ...c, kind: classifySessionCookie(c.name) }))
    .filter(c => c.kind);

  penalty += reportSessionCookieFlags(sessionCookies, pageData.hasPasswordField === true, isHttps, add);

  return penalty;
}

// A cookie with a well-known session name is reported (and can affect the
// verdict) as a session cookie. One that only might be a session cookie is
// penalised only when the page has a login form; otherwise it is informational.
// Only cookie names and flags are ever read.
function reportSessionCookieFlags(cookies, hasLoginForm, isHttps, add) {
  const checks = [
    {
      label: 'HttpOnly',
      missing: c => !c.httpOnly,
      risk: 'page scripts can read them, so an XSS bug could steal the session'
    },
    {
      label: 'the Secure flag',
      missing: c => !c.secure,
      risk: 'they could be sent over unencrypted HTTP',
      httpsOnly: true
    }
  ];

  const names = list => list.slice(0, 3).map(c => c.name).join(', ');
  let penalty = 0;

  for (const check of checks) {
    if (check.httpsOnly && !isHttps) continue;

    const known = cookies.filter(c => c.kind === 'known' && check.missing(c));
    const maybe = cookies.filter(c => c.kind === 'maybe' && check.missing(c));

    if (known.length > 0) {
      penalty += 2;
      add('warning', '⚠', `Session cookie(s) without ${check.label} (${names(known)}) — ${check.risk}.`, { caution: true });
    }

    if (maybe.length > 0 && hasLoginForm) {
      penalty += 2;
      add('warning', '⚠', `Cookie(s) that may be session cookies are missing ${check.label} (${names(maybe)}). This page has a login form, so if they hold a login session, ${check.risk}.`, { caution: true });
    } else if (maybe.length > 0) {
      add('neutral', 'ℹ', `Cookie(s) that may be session cookies are missing ${check.label} (${names(maybe)}). Not scored: no login form was found on this page, so there is no sign they protect a login session.`);
    }
  }

  return penalty;
}
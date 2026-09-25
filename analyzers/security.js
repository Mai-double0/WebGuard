// analyzers/security.js
// Security indicators. Principle: an observation alone is informational;
// points are deducted only when it appears with a real risk signal.
// Returns a security score (0–25) and list of findings.

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
  // CONTENT SECURITY POLICY
  // Headers are not read yet, so absence is NOT scored.
  // =====================
  if (pageData.hasMetaCSP) {
    add('positive', '✓', 'Content-Security-Policy detected via meta tag.');
  } else {
    add('neutral', 'ℹ', 'Security headers (CSP, HSTS, X-Frame-Options): not available — header inspection is not implemented yet. Not scored.');
  }

  // =====================
  // HIDDEN IFRAMES
  // Common for analytics/payments — only third-party hidden frames are noted.
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
  const risky = downloads.filter(d => d.protocol === 'http:' || d.isIP || d.doubleExt);
  const offsite = downloads.filter(d => !d.sameSite && !risky.includes(d));

  if (risky.length > 0) {
    score -= 6;
    add('danger', '✗', `${risky.length} executable download(s) with risky traits (unencrypted, IP-address host, or disguised file extension).`);
  } else if (offsite.length > 0) {
    score -= 1;
    add('neutral', 'ℹ', `${offsite.length} executable download(s) hosted on another domain — common for CDNs. Confirm the source if unsure.`);
  } else if (downloads.length > 0) {
    add('neutral', 'ℹ', 'Executable downloads offered by this site over HTTPS — normal for software sites.');
  } else {
    add('positive', '✓', 'No executable download links detected.');
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
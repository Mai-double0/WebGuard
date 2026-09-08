// analyzers/security.js
// Analyzes security-related indicators from collected page data.
// Returns a security score (0–25) and list of findings.

export function analyzeSecurity(pageData) {
  const findings = [];
  let score = 25; // Start at max, deduct for issues

  // =====================
  // HTTPS CHECK
  // =====================
  if (pageData.protocol === 'https:') {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'HTTPS connection detected — data is encrypted in transit.',
      category: 'security'
    });
  } else {
    score -= 10;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: 'No HTTPS — connection is unencrypted. Avoid entering sensitive data.',
      category: 'security'
    });
  }

  // =====================
  // MIXED CONTENT
  // =====================
  const mixedCount = pageData.mixedContentIndicators?.length || 0;
  if (mixedCount > 0) {
    score -= 5;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `Mixed content detected — ${mixedCount} HTTP resource(s) loaded on an HTTPS page.`,
      category: 'security'
    });
  }

  // =====================
  // CONTENT SECURITY POLICY
  // =====================
  if (pageData.hasMetaCSP) {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'Content-Security-Policy detected via meta tag.',
      category: 'security'
    });
  } else {
    score -= 4;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: 'Content-Security-Policy not detected. This header reduces exposure to injection attacks.',
      category: 'security'
    });
  }

  // =====================
  // HIDDEN IFRAMES
  // =====================
  const hiddenIframeCount = pageData.hiddenIframes?.length || 0;
  if (hiddenIframeCount > 0) {
    score -= 5;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${hiddenIframeCount} hidden iframe(s) detected — these are not visible to the user.`,
      category: 'security'
    });
  }

  // =====================
  // SUSPICIOUS DOWNLOADS
  // =====================
  if (pageData.hasDownloadLinks) {
    score -= 3;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: 'Executable download links detected (.exe, .dmg, .msi, .bat, .sh). Verify before downloading.',
      category: 'security'
    });
  } else {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'No suspicious download links detected.',
      category: 'security'
    });
  }

  // =====================
  // EXTERNAL FORM ACTIONS
  // =====================
  const externalForms = pageData.externalFormActions?.length || 0;
  if (externalForms > 0) {
    score -= 5;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: `${externalForms} form(s) submit data to external domains — verify the destination.`,
      category: 'security'
    });
  }

  // =====================
  // BEFORE UNLOAD HOOK
  // =====================
  if (pageData.hasBeforeUnload) {
    score -= 2;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: 'Page uses beforeunload — may attempt to prevent you from leaving.',
      category: 'security'
    });
  }

  // =====================
  // IP ADDRESS DOMAIN
  // =====================
  if (pageData.hasIPAddress) {
    score -= 6;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: 'Site is accessed via IP address instead of a domain name — unusual for legitimate sites.',
      category: 'security'
    });
  }
  // =====================
// LOGIN FORM SECURITY
// =====================
if (pageData.hasPasswordField && pageData.formCount > 0) {
  score -= 4;
  findings.push({
    type: 'warning',
    icon: '⚠',
    text: 'Login form detected — verify this site is legitimate before entering credentials.',
    category: 'security'
  });
}

// =====================
// NO SECURITY HEADERS (heuristic — check via meta tags only)
// =====================
const hasAnySecurityMeta = pageData.hasMetaCSP;
if (!hasAnySecurityMeta && pageData.protocol === 'https:') {
  score -= 3;
  findings.push({
    type: 'warning',
    icon: '⚠',
    text: 'No security-hardening meta tags detected. Security headers may be absent.',
    category: 'security'
  });
}

  // Clamp score
  score = Math.max(0, Math.min(25, score));

  return { score, maxScore: 25, findings };
}
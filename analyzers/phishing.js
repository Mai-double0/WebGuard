// analyzers/phishing.js
// Analyzes phishing-related indicators from collected page data.
// Heuristic assessment only — does not definitively identify phishing.
// Returns a phishing score (0–25) and list of findings.

export function analyzePhishing(pageData) {
  const findings = [];
  let score = 25; // Start at max, deduct for indicators

  // =====================
  // IP ADDRESS INSTEAD OF DOMAIN
  // =====================
  if (pageData.hasIPAddress) {
    score -= 10;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: 'Site uses an IP address instead of a domain — strong phishing indicator.',
      category: 'phishing'
    });
  }

  // =====================
  // PUNYCODE / IDN DOMAIN
  // =====================
  if (pageData.hasPunycode) {
    score -= 8;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: 'Punycode/internationalized domain detected — may be impersonating another site.',
      category: 'phishing'
    });
  }

  // =====================
  // SUSPICIOUS CHARACTERS IN DOMAIN
  // =====================
  if (pageData.hasSuspiciousChars) {
    score -= 5;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: 'Suspicious characters detected in domain name.',
      category: 'phishing'
    });
  }

  // =====================
  // EXCESSIVE SUBDOMAINS
  // =====================
  const subdomainCount = pageData.subdomainCount || 0;
  if (subdomainCount >= 3) {
    score -= 5;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `Excessive subdomains detected (${subdomainCount} levels) — may be disguising the real domain.`,
      category: 'phishing'
    });
  } else if (subdomainCount >= 2) {
    score -= 2;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `Multiple subdomains detected (${subdomainCount} levels).`,
      category: 'phishing'
    });
  }

  // =====================
  // PASSWORD FIELD
  // =====================
  const otherPhishingSignals =
    pageData.hasIPAddress ||
    pageData.hasPunycode ||
    (pageData.subdomainCount || 0) >= 3 ||
    pageData.protocol !== 'https:' ||
    (pageData.externalFormActions?.length || 0) > 0;

  if (pageData.hasPasswordField && otherPhishingSignals) {
    score -= 8;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: 'Login form appears together with other phishing indicators — do not enter credentials unless you are certain of this site.',
      category: 'phishing'
    });
  } else if (pageData.hasPasswordField) {
    findings.push({
      type: 'neutral',
      icon: 'ℹ',
      text: 'Login form present, with no other phishing indicators alongside it. Always check the domain before signing in.',
      category: 'phishing'
    });
  } else {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'No password fields detected on this page.',
      category: 'phishing'
    });
  }

  // =====================
  // VERY LONG URL
  // =====================
  if (pageData.urlLength > 200) {
    score -= 4;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `Unusually long URL detected (${pageData.urlLength} characters) — may be obfuscating destination.`,
      category: 'phishing'
    });
  }

  // =====================
  // URL ENCODED CHARACTERS
  // =====================
  if (pageData.hasEncodedChars) {
    score -= 3;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: 'URL contains encoded characters — may be obfuscating the actual destination.',
      category: 'phishing'
    });
  }

  // =====================
  // POSITIVE: NO HTTP (uses HTTPS)
  // =====================
  if (pageData.protocol === 'https:' && !pageData.hasIPAddress && !pageData.hasPunycode) {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'No major phishing URL indicators detected.',
      category: 'phishing'
    });
  }

  // Clamp score
  score = Math.max(0, Math.min(25, score));

  return { score, maxScore: 25, findings };
}
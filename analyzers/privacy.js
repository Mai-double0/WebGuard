// analyzers/privacy.js
// Analyzes privacy-related indicators from collected page data.
// Returns a privacy score (0–30) and list of findings.

export function analyzePrivacy(pageData) {
  const findings = [];
  let score = 30; // Start at max, deduct for issues

  // =====================
  // THIRD-PARTY DOMAINS
  // =====================
  const thirdPartyCount = pageData.thirdPartyDomains?.length || 0;

  if (thirdPartyCount === 0) {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'No third-party domains detected.',
      category: 'privacy'
    });
  } else if (thirdPartyCount <= 5) {
    score -= 3;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${thirdPartyCount} third-party domain(s) detected — low level of external involvement.`,
      category: 'privacy'
    });
  } else if (thirdPartyCount <= 15) {
    score -= 8;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${thirdPartyCount} third-party domains detected — moderate external data sharing.`,
      category: 'privacy'
    });
  } else {
    score -= 14;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: `${thirdPartyCount} third-party domains detected — high level of external involvement.`,
      category: 'privacy'
    });
  }

  // =====================
  // TRACKING RESOURCES
  // =====================
  const trackingCount = pageData.trackingResources?.length || 0;

  if (trackingCount === 0) {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'No tracking-related resources detected.',
      category: 'privacy'
    });
  } else if (trackingCount <= 3) {
    score -= 4;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${trackingCount} tracking-related resource(s) detected.`,
      category: 'privacy'
    });
  } else {
    score -= 8;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: `${trackingCount} tracking-related resources detected — significant tracking activity.`,
      category: 'privacy'
    });
  }

  // =====================
  // ADVERTISING RESOURCES
  // =====================
  const adCount = pageData.adResources?.length || 0;
  if (adCount > 0) {
    score -= Math.min(5, adCount);
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${adCount} advertising-related resource(s) detected.`,
      category: 'privacy'
    });
  }

  // =====================
  // ANALYTICS RESOURCES
  // =====================
  const analyticsCount = pageData.analyticsResources?.length || 0;
  if (analyticsCount > 0) {
    score -= Math.min(3, analyticsCount);
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${analyticsCount} analytics service(s) detected — usage data may be collected.`,
      category: 'privacy'
    });
  }

  // =====================
  // THIRD-PARTY IFRAMES
  // =====================
  const thirdPartyIframeCount = pageData.thirdPartyIframes?.length || 0;
  if (thirdPartyIframeCount > 0) {
    score -= 3;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${thirdPartyIframeCount} third-party iframe(s) detected — embedded external content.`,
      category: 'privacy'
    });
  }

  // =====================
  // CREDIT CARD FIELDS
  // =====================
  if (pageData.hasCreditCard) {
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: 'Payment/credit card fields detected — ensure this is a trusted site before entering data.',
      category: 'privacy'
    });
  }

  // Clamp score
  score = Math.max(0, Math.min(30, score));

  return { score, maxScore: 30, findings };
}
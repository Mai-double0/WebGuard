// analyzers/resources.js
// Analyzes resource and network-related indicators from collected page data.
// Returns a resource score (0–20) and list of findings.

export function analyzeResources(pageData) {
  const findings = [];
  let score = 20; // Start at max, deduct for issues

  // =====================
  // THIRD-PARTY SCRIPTS
  // =====================
  const thirdPartyScriptCount = pageData.thirdPartyScripts?.length || 0;

  if (thirdPartyScriptCount === 0) {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'No third-party scripts detected.',
      category: 'resources'
    });
  } else if (thirdPartyScriptCount <= 5) {
    score -= 3;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${thirdPartyScriptCount} third-party script(s) detected.`,
      category: 'resources'
    });
  } else {
    score -= 7;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${thirdPartyScriptCount} third-party scripts detected — each script extends trust to an external party.`,
      category: 'resources'
    });
  }

  // =====================
  // TOTAL SCRIPTS
  // =====================
  const totalScripts = pageData.scripts?.length || 0;
  if (totalScripts > 20) {
    score -= 3;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `High script count: ${totalScripts} JavaScript files loaded.`,
      category: 'resources'
    });
  }

  // =====================
  // IFRAMES
  // =====================
  const iframeCount = pageData.iframes?.length || 0;
  if (iframeCount > 5) {
    score -= 4;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${iframeCount} iframes detected on this page.`,
      category: 'resources'
    });
  } else if (iframeCount > 0) {
    score -= 1;
    findings.push({
      type: 'neutral',
      icon: 'ℹ',
      text: `${iframeCount} iframe(s) detected.`,
      category: 'resources'
    });
  }

  // =====================
  // THIRD-PARTY IMAGES
  // =====================
  const thirdPartyImageCount = pageData.thirdPartyImages?.length || 0;
  if (thirdPartyImageCount > 20) {
    score -= 2;
    findings.push({
      type: 'warning',
      icon: '⚠',
      text: `${thirdPartyImageCount} images loaded from third-party domains.`,
      category: 'resources'
    });
  }

  // =====================
  // MIXED CONTENT
  // =====================
  const mixedCount = pageData.mixedContentIndicators?.length || 0;
  if (mixedCount > 0) {
    score -= 5;
    findings.push({
      type: 'danger',
      icon: '✗',
      text: `${mixedCount} mixed content resource(s) — HTTP resources on an HTTPS page.`,
      category: 'resources'
    });
  } else if (pageData.protocol === 'https:') {
    findings.push({
      type: 'positive',
      icon: '✓',
      text: 'No mixed content detected.',
      category: 'resources'
    });
  }

  // =====================
  // SUMMARY FINDING
  // =====================
  const totalThirdParty = pageData.thirdPartyDomains?.length || 0;
  findings.push({
    type: totalThirdParty > 10 ? 'warning' : 'neutral',
    icon: 'ℹ',
    text: `Total: ${totalScripts} scripts, ${iframeCount} iframes, ${totalThirdParty} third-party domains.`,
    category: 'resources'
  });

  // Clamp score
  score = Math.max(0, Math.min(20, score));

  return { score, maxScore: 20, findings };
}
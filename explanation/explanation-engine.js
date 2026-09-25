// explanation/explanation-engine.js
// Generates human-readable explanations for risk scores.
// Turns raw findings into structured, plain-language explanations
// that help users understand WHY a score was given.

// =====================
// MAIN EXPLANATION FUNCTION
// =====================

export function generateExplanation(result) {
  const { score, riskLevel, riskLabel, findings, pageData } = result;

  return {
    summary:          generateSummary(score, riskLevel, riskLabel, pageData),
    findingDetails:   generateFindingDetails(findings),
    recommendations:  generateRecommendations(result),
    educationalNotes: generateEducationalNotes(result)
  };
}

// =====================
// SUMMARY
// =====================

function generateSummary(score, riskLevel, riskLabel, pageData) {
  const domain = pageData?.domain || 'this website';

  const summaries = {
    'very-low': `${domain} shows very low risk indicators. The site uses HTTPS, has minimal third-party involvement, and no significant security or privacy concerns were detected.`,
    'low':      `${domain} shows low risk indicators. A small number of minor issues were detected, but no critical security or privacy concerns were found.`,
    'moderate': `${domain} shows moderate risk indicators. Several security or privacy concerns were detected. Review the findings below before sharing sensitive information.`,
    'high':     `${domain} shows high risk indicators. Multiple significant security or privacy issues were detected. Exercise caution on this site.`,
    'critical': `${domain} shows critical risk indicators. Serious security or privacy concerns were detected. Avoid entering any personal or sensitive information on this site.`
  };

  return {
    text:       summaries[riskLevel] || `Risk assessment complete for ${domain}.`,
    score,
    riskLevel,
    riskLabel,
    disclaimer: 'This is a heuristic risk assessment based on observable indicators. It does not guarantee the site is safe or unsafe.'
  };
}

// =====================
// FINDING DETAILS
// =====================

function generateFindingDetails(findings) {
  if (!findings || !findings.length) {
    return [{
      type:        'neutral',
      icon:        'ℹ',
      text:        'No findings to display.',
      explanation: 'No observable risk indicators were detected.',
      category:    'general'
    }];
  }

  return findings.map(f => ({
    ...f,
    explanation: getExplanation(f.text)
  }));
}

// Maps finding text patterns to plain-language explanations
function getExplanation(text) {
  if (!text) return '';

  const explanations = [
    {
      match: /HTTPS connection detected/i,
      explain: 'HTTPS encrypts data between your browser and the server, preventing interception by third parties.'
    },
    {
      match: /No HTTPS/i,
      explain: 'Without HTTPS, your connection is unencrypted. Anyone on the same network could potentially intercept data you send or receive.'
    },
    {
      match: /Content-Security-Policy not detected/i,
      explain: 'CSP is a security header that helps prevent cross-site scripting (XSS) attacks. Its absence does not mean the site is unsafe, but it is a security hardening measure.'
    },
    {
      match: /Content-Security-Policy detected/i,
      explain: 'The site has implemented a Content Security Policy, which helps protect against certain injection attacks.'
    },
    {
      match: /Mixed content/i,
      explain: 'Mixed content occurs when an HTTPS page loads resources over HTTP. This can weaken the security of the page.'
    },
    {
      match: /third-party domain/i,
      explain: 'Third-party domains are external services contacted by the page. Each one represents an additional party that may receive information about your visit.'
    },
    {
      match: /tracking/i,
      explain: 'Tracking scripts monitor user behavior across websites. They may collect data about pages you visit, clicks, and other interactions.'
    },
    {
      match: /advertising/i,
      explain: 'Advertising resources may track your browsing behavior to serve targeted advertisements.'
    },
    {
      match: /analytics/i,
      explain: 'Analytics services collect data about how visitors use a website, including page views, time spent, and interactions.'
    },
    {
      match: /hidden iframe/i,
      explain: 'Hidden iframes embed invisible content from another source. Legitimate uses exist (payment processors), but they can also be used maliciously.'
    },
    {
      match: /IP address/i,
      explain: 'Legitimate websites typically use domain names. Accessing a site via IP address directly is unusual and is sometimes associated with phishing.'
    },
    {
      match: /Punycode/i,
      explain: 'Punycode domains use encoded characters that can visually resemble legitimate domains (e.g., paypal.com vs pаypal.com using Cyrillic characters).'
    },
    {
      match: /password/i,
      explain: 'Pages with login forms are higher-value targets for phishing. Always verify the domain before entering credentials.'
    },
    {
      match: /download/i,
      explain: 'Executable files (.exe, .dmg, .msi) can install software on your computer. Only download files from sources you trust.'
    },
    {
      match: /subdomain/i,
      explain: 'Phishing sites sometimes use excessive subdomains to make URLs look like legitimate domains (e.g., paypal.com.malicious.com).'
    },
    {
      match: /external.*form/i,
      explain: 'When a form submits data to a different domain than the page you are on, your data may be sent to an unexpected third party.'
    },
    {
      match: /beforeunload/i,
      explain: 'Some sites use beforeunload events to display a dialog when you try to leave. This is sometimes used legitimately (unsaved changes), but can also be used to trap users.'
    },
    {
      match: /encoded characters/i,
      explain: 'URL encoding can be used to obscure the real destination of a link, which is a technique sometimes used in phishing.'
    },
    {
      match: /third-party script/i,
      explain: 'External scripts run with the same permissions as the hosting page. A compromised third-party script could affect all sites that load it.'
    }
  ];

  for (const entry of explanations) {
    if (entry.match.test(text)) return entry.explain;
  }

  return 'This indicator contributes to the overall risk assessment.';
}

// =====================
// RECOMMENDATIONS
// =====================

function generateRecommendations(result) {
  const recs = [];
  const { pageData, categories } = result;

  if (pageData?.protocol !== 'https:') {
    recs.push({
      priority: 'high',
      icon:     '🔒',
      text:     'Avoid entering any personal information on this page — the connection is not encrypted.'
    });
  }

  if (pageData?.hasPasswordField && pageData?.protocol !== 'https:') {
    recs.push({
      priority: 'critical',
      icon:     '🚨',
      text:     'Do not enter your password — this login form is on an unencrypted page.'
    });
  }

  if (pageData?.hasIPAddress) {
    recs.push({
      priority: 'high',
      icon:     '⚠',
      text:     'This site is accessed via IP address. Verify you intended to visit this destination.'
    });
  }

  if (pageData?.hasPunycode) {
    recs.push({
      priority: 'high',
      icon:     '⚠',
      text:     'Verify the domain name carefully — it may be impersonating a known website.'
    });
  }

  if ((pageData?.thirdPartyDomains?.length || 0) > 15) {
    recs.push({
      priority: 'medium',
      icon:     '🕵️',
      text:     'This page contacts many third-party domains. Consider using a privacy-focused browser or extension to limit tracking.'
    });
  }

  if (pageData?.hasDownloadLinks) {
    recs.push({
      priority: 'medium',
      icon:     '📥',
      text:     'Executable download links were found. Only download files you explicitly requested from sources you trust.'
    });
  }

  if (pageData?.externalFormActions?.length > 0) {
    recs.push({
      priority: 'high',
      icon:     '📤',
      text:     'A form on this page sends data to an external domain. Verify the destination before submitting.'
    });
  }

  if (categories?.privacy?.score < 15) {
    recs.push({
      priority: 'medium',
      icon:     '🛡',
      text:     'High privacy risk detected. Consider using a tracker blocker or privacy-focused browser.'
    });
  }

  // Always include a general reminder
  recs.push({
    priority: 'info',
    icon:     'ℹ',
    text:     'WebGuard provides a heuristic assessment. Always use your own judgment when deciding to share personal information online.'
  });

  return recs;
}

// =====================
// EDUCATIONAL NOTES
// =====================

function generateEducationalNotes(result) {
  const notes = [];
  const { pageData } = result;

  if ((pageData?.thirdPartyDomains?.length || 0) > 0) {
    notes.push({
      title: 'What are third-party domains?',
      text:  'When you visit a website, it often loads resources from other websites (third parties). These include analytics tools, advertising networks, fonts, and social media buttons. Each third party may receive information about your visit.'
    });
  }

  if ((pageData?.trackingResources?.length || 0) > 0) {
    notes.push({
      title: 'What is web tracking?',
      text:  'Tracking scripts follow your activity across websites to build a profile of your interests and behavior. This data is often used for targeted advertising or sold to data brokers.'
    });
  }

  if (pageData?.hasPasswordField) {
    notes.push({
      title: 'How to spot phishing login pages',
      text:  'Always check the domain in your browser address bar before entering a password. Phishing sites often use domains that look similar to real ones but are slightly different (e.g., paypa1.com instead of paypal.com).'
    });
  }

  if (!pageData?.hasMetaCSP) {
    notes.push({
      title: 'What is Content-Security-Policy?',
      text:  'CSP is a security header that tells the browser which sources of content are allowed. Sites without CSP may be more vulnerable to certain attacks, but its absence alone does not mean the site is malicious.'
    });
  }

  return notes;
}

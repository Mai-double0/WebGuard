// scoring/risk-engine.js
// Combines the four analyzers into a final risk score, then applies
// transparent caps so missing evidence never produces a "perfect" score.

import { analyzeSecurity }  from '../analyzers/security.js';
import { analyzePrivacy }   from '../analyzers/privacy.js';
import { analyzePhishing }  from '../analyzers/phishing.js';
import { analyzeResources } from '../analyzers/resources.js';

// Weights (sum = 100): Security 35, Privacy 25, Phishing 25, Resources 15
// Caps:
//   CEILING       — passive analysis can't rule out server-side flaws
//   COVERAGE_CAP  — applied when some checks could not run
//   Weakest link  — weak Security or Phishing limits the overall level
const CEILING      = 95;
const COVERAGE_CAP = 85;

export function getRiskLevel(score) {
  if (score >= 90) return 'very-low';
  if (score >= 75) return 'low';
  if (score >= 50) return 'moderate';
  if (score >= 25) return 'high';
  return 'critical';
}

export function getRiskLabel(score) {
  if (score >= 90) return 'VERY LOW RISK';
  if (score >= 75) return 'LOW RISK';
  if (score >= 50) return 'MODERATE RISK';
  if (score >= 25) return 'HIGH RISK';
  return 'CRITICAL RISK';
}

export function runRiskEngine(pageData) {
  const security  = analyzeSecurity(pageData);
  const privacy   = analyzePrivacy(pageData);
  const phishing  = analyzePhishing(pageData);
  const resources = analyzeResources(pageData);

  const weighted =
    Math.round((security.score  / 25) * 35) +
    Math.round((privacy.score   / 30) * 25) +
    Math.round((phishing.score  / 25) * 25) +
    Math.round((resources.score / 20) * 15);

  let score = Math.max(0, Math.min(100, weighted));
  const scoreNotes = [];

  const cap = (limit, reason) => {
    if (score > limit) {
      score = limit;
      scoreNotes.push({ type: 'neutral', icon: 'ℹ', text: `Score capped at ${limit} — ${reason}`, category: 'score' });
    }
  };

  // 1. Ceiling
  cap(CEILING, 'passive analysis cannot rule out server-side vulnerabilities, so WebGuard never reports zero risk.');

  // 2. Coverage
  const missing = [];
  if (!pageData.responseHeaders) missing.push('security headers were not captured');
  if (pageData.limitedAnalysis)  missing.push('page content could not be inspected');
  if (missing.length) cap(COVERAGE_CAP, `some checks could not run (${missing.join('; ')}).`);

  // 3. Weakest link (direct-risk categories only)
  const direct = [
    { label: 'Security', pct: security.score / 25 },
    { label: 'Phishing', pct: phishing.score / 25 }
  ];
  const worst = direct.reduce((a, b) => (b.pct < a.pct ? b : a));
  const worstPct = Math.round(worst.pct * 100);

  if (worst.pct < 0.4) {
    cap(49, `${worst.label} score is weak (${worstPct}%); strong results in other categories should not hide it.`);
  } else if (worst.pct < 0.6) {
    cap(74, `${worst.label} score is weak (${worstPct}%); strong results in other categories should not hide it.`);
  }

  const allFindings = [
    ...security.findings,
    ...phishing.findings,
    ...privacy.findings,
    ...resources.findings
  ];
  const issues    = allFindings.filter(f => f.type !== 'positive');
  const positives = allFindings.filter(f => f.type === 'positive');

  return {
    score,
    riskLevel: getRiskLevel(score),
    riskLabel: getRiskLabel(score),
    categories: {
      security:  { score: security.score,  maxScore: 25 },
      privacy:   { score: privacy.score,   maxScore: 30 },
      phishing:  { score: phishing.score,  maxScore: 25 },
      resources: { score: resources.score, maxScore: 20 }
    },
    // Cap explanations first, so the user sees why the score is what it is
    findings: [...scoreNotes, ...issues, ...positives],
    details: { security, privacy, phishing, resources },
    pageData
  };
}
// scoring/risk-engine.js
// Combines the four analyzers into a final risk score, applies transparent
// caps, and produces a trust verdict: can this page be trusted with sensitive data?

import { analyzeSecurity }  from '../analyzers/security.js';
import { analyzePrivacy }   from '../analyzers/privacy.js';
import { analyzePhishing }  from '../analyzers/phishing.js';
import { analyzeResources } from '../analyzers/resources.js';

// Weights (sum = 100): Security 35, Privacy 25, Phishing 25, Resources 15
const CEILING      = 95;  // passive analysis can't rule out server-side flaws
const COVERAGE_CAP = 85;  // some checks could not run
const BLOCKER_CAP  = 49;  // a concrete reason not to trust the page

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

function buildVerdict(findings, score, coverageLimited) {
  const blockers = findings.filter(f => f.blocker).map(f => f.text);
  const cautions = findings.filter(f => f.caution).map(f => f.text);

  if (blockers.length) {
    return { level: 'no', label: 'Do not enter passwords or payment details', reasons: blockers.slice(0, 2) };
  }
  if (cautions.length) {
    return { level: 'caution', label: 'Use with caution', reasons: cautions.slice(0, 2) };
  }
  if (score < 75) {
    return { level: 'caution', label: 'Use with caution', reasons: ['Several weaker security or privacy indicators add up — see the findings.'] };
  }
  if (coverageLimited) {
    return { level: 'caution', label: 'Not fully checked', reasons: ['Some checks could not run on this page, so WebGuard cannot give a full verdict.'] };
  }
  return { level: 'ok', label: 'No blocking issues found', reasons: ['Nothing observed suggests avoiding this page. This is not a guarantee of safety.'] };
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

  const allFindings = [
    ...security.findings,
    ...phishing.findings,
    ...privacy.findings,
    ...resources.findings
  ];

  // 1. Ceiling
  cap(CEILING, 'passive analysis cannot rule out server-side vulnerabilities, so WebGuard never reports zero risk.');

  // 2. Coverage
  const missing = [];
  if (!pageData.responseHeaders) missing.push('security headers were not captured');
  if (pageData.limitedAnalysis)  missing.push('page content could not be inspected');
  const coverageLimited = missing.length > 0;
  if (coverageLimited) cap(COVERAGE_CAP, `some checks could not run (${missing.join('; ')}).`);

  // 3. Blockers
  if (allFindings.some(f => f.blocker)) {
    cap(BLOCKER_CAP, 'a serious issue was found that makes this page unsafe for sensitive data.');
  }

  // 4. Weakest link (direct-risk categories only)
  const direct = [
    { label: 'Security', pct: security.score / 25 },
    { label: 'Phishing', pct: phishing.score / 25 }
  ];
  const worst = direct.reduce((a, b) => (b.pct < a.pct ? b : a));
  const worstPct = Math.round(worst.pct * 100);
  if (worst.pct < 0.4) {
    cap(49, `${worst.label} score is weak (${worstPct}%); strong results elsewhere should not hide it.`);
  } else if (worst.pct < 0.6) {
    cap(74, `${worst.label} score is weak (${worstPct}%); strong results elsewhere should not hide it.`);
  }

  // Order: cap reasons → blockers → other issues → positives
  const issues    = allFindings.filter(f => f.type !== 'positive');
  const positives = allFindings.filter(f => f.type === 'positive');
  const findings  = [
    ...scoreNotes,
    ...issues.filter(f => f.blocker),
    ...issues.filter(f => !f.blocker),
    ...positives
  ];

  return {
    score,
    riskLevel: getRiskLevel(score),
    riskLabel: getRiskLabel(score),
    verdict:   buildVerdict(allFindings, score, coverageLimited),
    categories: {
      security:  { score: security.score,  maxScore: 25 },
      privacy:   { score: privacy.score,   maxScore: 30 },
      phishing:  { score: phishing.score,  maxScore: 25 },
      resources: { score: resources.score, maxScore: 20 }
    },
    findings,
    details: { security, privacy, phishing, resources },
    pageData
  };
}
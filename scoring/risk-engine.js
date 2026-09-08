// scoring/risk-engine.js
import { analyzeSecurity }  from '../analyzers/security.js';
import { analyzePrivacy }   from '../analyzers/privacy.js';
import { analyzePhishing }  from '../analyzers/phishing.js';
import { analyzeResources } from '../analyzers/resources.js';

// Score weights:
// Security:  35 (most important — direct risk)
// Privacy:   25 (important but not immediate danger)
// Phishing:  25 (critical when triggered)
// Resources: 15 (contextual)
// Total:    100

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

  // Scale each category score to its new weight
  const secScaled  = Math.round((security.score  / 25) * 35);
  const privScaled = Math.round((privacy.score   / 30) * 25);
  const phiScaled  = Math.round((phishing.score  / 25) * 25);
  const resScaled  = Math.round((resources.score / 20) * 15);

  const totalScore = secScaled + privScaled + phiScaled + resScaled;
  const score = Math.max(0, Math.min(100, totalScore));

  const riskLevel = getRiskLevel(score);
  const riskLabel = getRiskLabel(score);

  const allFindings = [
    ...security.findings,
    ...phishing.findings,
    ...privacy.findings,
    ...resources.findings
  ];

  const positiveFindings = allFindings.filter(f => f.type === 'positive');
  const issueFindings    = allFindings.filter(f => f.type !== 'positive');
  const findings = [...issueFindings, ...positiveFindings];

  return {
    score,
    riskLevel,
    riskLabel,
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
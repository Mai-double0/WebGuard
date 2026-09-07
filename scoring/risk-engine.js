// scoring/risk-engine.js
// Combines all four analyzer results into a final risk score.
// Each category has a defined max score:
//   Security:  25
//   Privacy:   30
//   Phishing:  25
//   Resources: 20
//   Total:    100

import { analyzeSecurity }  from '../analyzers/security.js';
import { analyzePrivacy }   from '../analyzers/privacy.js';
import { analyzePhishing }  from '../analyzers/phishing.js';
import { analyzeResources } from '../analyzers/resources.js';

// =====================
// RISK LEVEL HELPERS
// =====================

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

// =====================
// MAIN SCORING FUNCTION
// =====================

export function runRiskEngine(pageData) {
  // Run all four analyzers
  const security  = analyzeSecurity(pageData);
  const privacy   = analyzePrivacy(pageData);
  const phishing  = analyzePhishing(pageData);
  const resources = analyzeResources(pageData);

  // Sum category scores
  const totalScore = security.score + privacy.score + phishing.score + resources.score;

  // Clamp to 0–100
  const score = Math.max(0, Math.min(100, totalScore));

  const riskLevel = getRiskLevel(score);
  const riskLabel = getRiskLabel(score);

  // Combine all findings into one list
  // Order: security → phishing → privacy → resources
  const allFindings = [
    ...security.findings,
    ...phishing.findings,
    ...privacy.findings,
    ...resources.findings
  ];

  // Separate into positive and warning/danger for ordered display
  const positiveFindings = allFindings.filter(f => f.type === 'positive');
  const issueFindings    = allFindings.filter(f => f.type !== 'positive');

  // Issues first, positives at the end
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
    // Raw analyzer results for dashboard detail view
    details: { security, privacy, phishing, resources },
    pageData
  };
}
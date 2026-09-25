// utils/helpers.js
// Shared helpers used by the service worker, risk engine, explanation engine,
// popup, and dashboard.

// =====================
// RISK LEVEL
// Higher score = lower observed risk.
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

// Unknown or missing level → neutral grey
export function getRiskColor(level) {
  const colors = {
    'very-low': '#22c55e',
    'low':      '#22c55e',
    'moderate': '#eab308',
    'high':     '#f97316',
    'critical': '#ef4444'
  };
  return colors[level] || '#64748b';
}

// =====================
// CATEGORY LEVEL
// Same thresholds, applied to the category's percentage of its maximum.
// =====================

export function getCategoryLevel(score, maxScore) {
  return getRiskLevel((score / maxScore) * 100);
}

export function getCategoryLabel(score, maxScore) {
  const pct = (score / maxScore) * 100;
  if (pct >= 75) return 'LOW';
  if (pct >= 50) return 'MODERATE';
  if (pct >= 25) return 'HIGH';
  return 'CRITICAL';
}

// =====================
// URLS
// =====================

// Browser-internal pages cannot be scanned
export function isAnalyzableUrl(url) {
  return !!url &&
    !url.startsWith('chrome://') &&
    !url.startsWith('chrome-extension://') &&
    url !== 'about:blank';
}

// =====================
// DOM
// Page-derived text is only ever set through textContent, never parsed as HTML.
// =====================

export function createEl(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

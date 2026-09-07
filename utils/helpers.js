// utils/helpers.js
// Shared utility functions used across WebGuard modules.

// =====================
// RISK LEVEL
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
// DOMAIN HELPERS
// =====================

export function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export function extractProtocol(url) {
  try {
    return new URL(url).protocol;
  } catch {
    return null;
  }
}

export function stripWWW(hostname) {
  return hostname.replace(/^www\./, '');
}

// =====================
// TIME HELPERS
// =====================

export function formatTimestamp(ts) {
  if (!ts) return 'Unknown';
  const date = new Date(ts);
  return date.toLocaleString();
}

export function timeAgo(ts) {
  if (!ts) return '';
  const seconds = Math.floor((Date.now() - ts) / 1000);
  if (seconds < 60)  return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// =====================
// SANITIZER
// Prevent XSS — always sanitize before inserting into DOM
// =====================

export function sanitize(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

// =====================
// SCORE DISPLAY
// =====================

export function getCategoryLabel(score, maxScore) {
  const pct = (score / maxScore) * 100;
  if (pct >= 90) return 'LOW';
  if (pct >= 75) return 'LOW';
  if (pct >= 50) return 'MODERATE';
  if (pct >= 25) return 'HIGH';
  return 'CRITICAL';
}

export function getCategoryLevel(score, maxScore) {
  const pct = (score / maxScore) * 100;
  if (pct >= 90) return 'very-low';
  if (pct >= 75) return 'low';
  if (pct >= 50) return 'moderate';
  if (pct >= 25) return 'high';
  return 'critical';
}

// =====================
// TRUNCATE
// =====================

export function truncate(str, maxLen = 60) {
  if (!str) return '';
  return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
}

// =====================
// PLURALIZE
// =====================

export function pluralize(count, singular, plural) {
  return count === 1 ? `${count} ${singular}` : `${count} ${plural || singular + 's'}`;
}
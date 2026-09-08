// dashboard/dashboard.js
// Renders the full analysis dashboard.
// Receives scan result from background service worker via tabId URL param.

import { generateExplanation } from '../explanation/explanation-engine.js';

// =====================
// UTILITIES
// =====================

function el(id) { return document.getElementById(id); }
function setText(id, text) { const e = el(id); if (e) e.textContent = text; }

function sanitize(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

function getRiskLevel(score) {
  if (score >= 90) return 'very-low';
  if (score >= 75) return 'low';
  if (score >= 50) return 'moderate';
  if (score >= 25) return 'high';
  return 'critical';
}

function getCategoryLevel(score, max) {
  const pct = (score / max) * 100;
  if (pct >= 90) return 'very-low';
  if (pct >= 75) return 'low';
  if (pct >= 50) return 'moderate';
  if (pct >= 25) return 'high';
  return 'critical';
}

function getCategoryLabel(score, max) {
  const pct = (score / max) * 100;
  if (pct >= 90) return 'LOW';
  if (pct >= 75) return 'LOW';
  if (pct >= 50) return 'MODERATE';
  if (pct >= 25) return 'HIGH';
  return 'CRITICAL';
}

function formatTime(ts) {
  if (!ts) return '';
  return 'Scanned ' + new Date(ts).toLocaleTimeString();
}

// =====================
// TAB NAVIGATION
// =====================

function initTabs() {
  const buttons = document.querySelectorAll('.tab-btn');
  const panels  = document.querySelectorAll('.tab-panel');

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;

      buttons.forEach(b => b.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const panel = document.getElementById(`tab-${target}`);
      if (panel) panel.classList.add('active');
    });
  });
}

// =====================
// RENDER FUNCTIONS
// =====================

function renderHeader(result) {
  setText('site-domain', result.domain || 'Unknown');
  setText('site-url', result.url || '');
  setText('scan-time', formatTime(result.scannedAt));

  const scoreEl = el('score-number');
  const level   = getRiskLevel(result.score);
  scoreEl.textContent = result.score;
  scoreEl.className   = `score-number ${level}`;

  const badge = el('risk-badge');
  badge.textContent = result.riskLabel || '';
  badge.className   = `risk-badge ${level}`;
}

function renderCategoryCard(name, score, maxScore) {
  const pct   = Math.round((score / maxScore) * 100);
  const level = getCategoryLevel(score, maxScore);
  const label = getCategoryLabel(score, maxScore);

  setText(`ov-${name}-score`, `${score}/${maxScore}`);

  const levelEl = el(`ov-${name}-level`);
  if (levelEl) {
    levelEl.textContent = label;
    levelEl.className   = `card-level ${level}`;
  }

  const barEl = el(`ov-${name}-bar`);
  if (barEl) {
    barEl.style.width = `${pct}%`;
    const colors = {
      'very-low': '#22c55e', 'low': '#22c55e',
      'moderate': '#eab308', 'high': '#f97316', 'critical': '#ef4444'
    };
    barEl.style.background = colors[level] || '#64748b';
  }
}

function renderOverview(result, explanation) {
  // Category cards
  if (result.categories) {
    renderCategoryCard('security',  result.categories.security.score,  25);
    renderCategoryCard('privacy',   result.categories.privacy.score,   30);
    renderCategoryCard('phishing',  result.categories.phishing.score,  25);
    renderCategoryCard('resources', result.categories.resources.score, 20);
  }

  // Summary
  setText('summary-text', explanation?.summary?.text || 'Analysis complete.');

  // Key findings (top 8)
  renderFindingsList('ov-findings', result.findings?.slice(0, 8) || [], explanation);
}

function renderFindingsList(elementId, findings, explanation) {
  const list = el(elementId);
  if (!list) return;

  if (!findings.length) {
    list.innerHTML = `<li class="finding-item neutral">
      <span class="finding-icon">ℹ</span>
      <div class="finding-body">
        <div class="finding-text">No findings for this category.</div>
      </div>
    </li>`;
    return;
  }

  list.innerHTML = findings.map(f => {
    const expEntry = explanation?.findingDetails?.find(d => d.text === f.text);
    const expText  = expEntry?.explanation || '';
    return `
      <li class="finding-item ${sanitize(f.type || 'neutral')}">
        <span class="finding-icon">${sanitize(f.icon || 'ℹ')}</span>
        <div class="finding-body">
          <div class="finding-text">${sanitize(f.text || '')}</div>
          ${expText ? `<div class="finding-explanation">${sanitize(expText)}</div>` : ''}
        </div>
      </li>`;
  }).join('');
}

function renderSecurityTab(result, explanation) {
  const sec = result.categories?.security;
  setText('sec-score', sec ? `${sec.score} / ${sec.maxScore}` : '--');

  const findings = result.findings?.filter(f => f.category === 'security') || [];
  renderFindingsList('sec-findings', findings, explanation);
}

function renderPrivacyTab(result, explanation) {
  const priv = result.categories?.privacy;
  setText('priv-score', priv ? `${priv.score} / ${priv.maxScore}` : '--');

  const findings = result.findings?.filter(f => f.category === 'privacy') || [];
  renderFindingsList('priv-findings', findings, explanation);

  // Third-party domain tags
  const domainList = el('domain-list');
  const domains    = result.pageData?.thirdPartyDomains || [];
  if (domainList) {
    if (domains.length === 0) {
      domainList.innerHTML = '<span class="muted">No third-party domains detected.</span>';
    } else {
      domainList.innerHTML = domains
        .map(d => `<span class="domain-tag">${sanitize(d)}</span>`)
        .join('');
    }
  }
}

function renderPhishingTab(result, explanation) {
  const phi = result.categories?.phishing;
  setText('phi-score', phi ? `${phi.score} / ${phi.maxScore}` : '--');

  const findings = result.findings?.filter(f => f.category === 'phishing') || [];
  renderFindingsList('phi-findings', findings, explanation);
}

function renderResourcesTab(result, explanation) {
  const res = result.categories?.resources;
  setText('res-score', res ? `${res.score} / ${res.maxScore}` : '--');

  const pd = result.pageData || {};
  setText('stat-scripts',       pd.scripts?.length       ?? '--');
  setText('stat-third-scripts', pd.thirdPartyScripts?.length ?? '--');
  setText('stat-iframes',       pd.iframes?.length        ?? '--');
  setText('stat-third-domains', pd.thirdPartyDomains?.length ?? '--');

  const findings = result.findings?.filter(f => f.category === 'resources') || [];
  renderFindingsList('res-findings', findings, explanation);
}

function renderRecommendations(explanation) {
  const recList = el('rec-list');
  const recs    = explanation?.recommendations || [];

  if (recList) {
    if (!recs.length) {
      recList.innerHTML = '<li class="finding-item neutral"><span class="finding-icon">✓</span><div class="finding-body"><div class="finding-text">No specific recommendations.</div></div></li>';
    } else {
      recList.innerHTML = recs.map(r => `
        <li class="rec-item ${sanitize(r.priority || 'info')}">
          <span class="rec-icon">${sanitize(r.icon || 'ℹ')}</span>
          <span class="rec-text">${sanitize(r.text || '')}</span>
        </li>`).join('');
    }
  }

  const eduList = el('edu-list');
  const notes   = explanation?.educationalNotes || [];
  if (eduList) {
    if (!notes.length) {
      eduList.innerHTML = '<span class="muted">No additional notes.</span>';
    } else {
      eduList.innerHTML = notes.map(n => `
        <div class="edu-item">
          <div class="edu-title">${sanitize(n.title || '')}</div>
          <div class="edu-text">${sanitize(n.text || '')}</div>
        </div>`).join('');
    }
  }
}

function renderError(message) {
  setText('site-domain', 'Analysis Unavailable');
  setText('site-url', message || 'Could not load scan result.');
  setText('summary-text', message || 'No data available.');
}

// =====================
// MAIN
// =====================

document.addEventListener('DOMContentLoaded', async () => {
  initTabs();

  const params = new URLSearchParams(window.location.search);
  const tabId  = parseInt(params.get('tabId'));

  if (!tabId) {
    renderError('No tab ID provided. Open WebGuard from the extension popup.');
    return;
  }

  // Poll for result — retry up to 5 times with 800ms delay
  let attempts = 0;
  const maxAttempts = 5;

  function tryLoad() {
  attempts++;

  // First try session storage (most reliable — set by popup before opening dashboard)
  chrome.storage.session.get([`webguard_result_${tabId}`], (sessionData) => {
    const sessionResult = sessionData?.[`webguard_result_${tabId}`];

    if (sessionResult && sessionResult.status === 'complete') {
      const explanation = generateExplanation(sessionResult);
      renderHeader(sessionResult);
      renderOverview(sessionResult, explanation);
      renderSecurityTab(sessionResult, explanation);
      renderPrivacyTab(sessionResult, explanation);
      renderPhishingTab(sessionResult, explanation);
      renderResourcesTab(sessionResult, explanation);
      renderRecommendations(explanation);
      return;
    }

    // Fall back to service worker message
    chrome.runtime.sendMessage({ type: 'GET_SCAN_RESULT', tabId }, (response) => {
      if (chrome.runtime.lastError) {
        renderError('Could not connect to WebGuard service worker.');
        return;
      }

      const result = response?.result;

      if (!result || result.status === 'scanning') {
        if (attempts < maxAttempts) {
          setTimeout(tryLoad, 800);
        } else {
          renderError('Scan timed out. Close this tab and click View Full Analysis again.');
        }
        return;
      }

      if (result.status === 'error') {
        renderError(result.error || 'Analysis failed.');
        return;
      }

      if (result.status === 'complete') {
        const explanation = generateExplanation(result);
        renderHeader(result);
        renderOverview(result, explanation);
        renderSecurityTab(result, explanation);
        renderPrivacyTab(result, explanation);
        renderPhishingTab(result, explanation);
        renderResourcesTab(result, explanation);
        renderRecommendations(explanation);
      }
    });
  });
}
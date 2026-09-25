// dashboard/dashboard.js
import { generateExplanation } from '../explanation/explanation-engine.js';
import { getRiskLevel, getRiskColor, getCategoryLevel, getCategoryLabel, createEl } from '../utils/helpers.js';

// =====================
// UTILITIES
// =====================

function el(id) { return document.getElementById(id); }
function setText(id, text) { const e = el(id); if (e) e.textContent = text; }

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
    barEl.style.background = getRiskColor(level);
  }
}

function renderOverview(result, explanation) {
  if (result.categories) {
    renderCategoryCard('security',  result.categories.security.score,  25);
    renderCategoryCard('privacy',   result.categories.privacy.score,   30);
    renderCategoryCard('phishing',  result.categories.phishing.score,  25);
    renderCategoryCard('resources', result.categories.resources.score, 20);
  }
  setText('summary-text', explanation?.summary?.text || 'Analysis complete.');
  renderFindingsList('ov-findings', result.findings?.slice(0, 8) || [], explanation);
}

function renderFindingsList(elementId, findings, explanation) {
  const list = el(elementId);
  if (!list) return;

  if (!findings.length) {
    list.replaceChildren(findingItem('neutral', 'ℹ', 'No findings for this category.'));
    return;
  }

  list.replaceChildren(...findings.map(f => {
    const expEntry = explanation?.findingDetails?.find(d => d.text === f.text);
    return findingItem(f.type || 'neutral', f.icon || 'ℹ', f.text || '', expEntry?.explanation || '');
  }));
}

function findingItem(type, icon, text, explanationText = '') {
  const body = createEl('div', 'finding-body');
  body.append(createEl('div', 'finding-text', text));
  if (explanationText) body.append(createEl('div', 'finding-explanation', explanationText));

  const li = createEl('li', `finding-item ${type}`);
  li.append(createEl('span', 'finding-icon', icon), body);
  return li;
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

  const domainList = el('domain-list');
  const domains    = result.pageData?.thirdPartyDomains || [];
  if (domainList) {
    domainList.replaceChildren(...(domains.length
      ? domains.map(d => createEl('span', 'domain-tag', d))
      : [createEl('span', 'muted', 'No third-party domains detected.')]));
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
  setText('stat-scripts',       pd.scripts?.length            ?? '--');
  setText('stat-third-scripts', pd.thirdPartyScripts?.length  ?? '--');
  setText('stat-iframes',       pd.iframes?.length            ?? '--');
  setText('stat-third-domains', pd.thirdPartyDomains?.length  ?? '--');

  const findings = result.findings?.filter(f => f.category === 'resources') || [];
  renderFindingsList('res-findings', findings, explanation);
}

function renderRecommendations(explanation) {
  const recList = el('rec-list');
  const recs    = explanation?.recommendations || [];

  if (recList) {
    recList.replaceChildren(...(recs.length
      ? recs.map(r => {
          const li = createEl('li', `rec-item ${r.priority || 'info'}`);
          li.append(createEl('span', 'rec-icon', r.icon || 'ℹ'), createEl('span', 'rec-text', r.text || ''));
          return li;
        })
      : [findingItem('neutral', '✓', 'No specific recommendations.')]));
  }

  const eduList = el('edu-list');
  const notes   = explanation?.educationalNotes || [];
  if (eduList) {
    eduList.replaceChildren(...(notes.length
      ? notes.map(n => {
          const item = createEl('div', 'edu-item');
          item.append(createEl('div', 'edu-title', n.title || ''), createEl('div', 'edu-text', n.text || ''));
          return item;
        })
      : [createEl('span', 'muted', 'No additional notes.')]));
  }
}

function renderVerdict(verdict) {
  const box = el('verdict');
  if (!box) return;

  const icons = { no: '⛔', caution: '⚠', ok: '✓' };
  if (!verdict || !icons[verdict.level]) {
    box.className = 'verdict hidden';
    return;
  }

  box.className = `verdict ${verdict.level}`;
  setText('verdict-label', `${icons[verdict.level]} ${verdict.label}`);

  const list = el('verdict-reasons');
  if (list) {
    list.replaceChildren(...(verdict.reasons || []).map(r => createEl('li', '', r)));
  }
}

function renderError(message) {
  setText('site-domain', 'Analysis Unavailable');
  setText('site-url', message || 'Could not load scan result.');
  setText('summary-text', message || 'No data available.');
}

function renderResult(result) {
  const explanation = generateExplanation(result);
  renderHeader(result);
  renderVerdict(result.verdict);
  renderOverview(result, explanation);
  renderSecurityTab(result, explanation);
  renderPrivacyTab(result, explanation);
  renderPhishingTab(result, explanation);
  renderResourcesTab(result, explanation);
  renderRecommendations(explanation);
}

// =====================
// MAIN
// =====================

document.addEventListener('DOMContentLoaded', () => {
  initTabs();

  const params = new URLSearchParams(window.location.search);
  const tabId  = parseInt(params.get('tabId'));

  if (!tabId) {
    renderError('No tab ID provided. Open WebGuard from the extension popup.');
    return;
  }

  let attempts    = 0;
  const maxAttempts = 6;

  function tryLoad() {
    attempts++;

    // First try session storage (set by popup before opening dashboard)
    chrome.storage.session.get([`webguard_result_${tabId}`], (sessionData) => {
      const sessionResult = sessionData?.[`webguard_result_${tabId}`];

      if (sessionResult && sessionResult.status === 'complete') {
        renderResult(sessionResult);
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
          renderResult(result);
        }
      });
    });
  }

  tryLoad();

  // Rescan button
  el('btn-rescan')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'RESCAN', tabId }, () => {
      // Drop the popup's snapshot so the reload shows the new scan
      chrome.storage.session.remove(`webguard_result_${tabId}`, () => {
        setTimeout(() => window.location.reload(), 2500);
      });
    });
  });
});
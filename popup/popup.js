// popup/popup.js
// Wires the popup UI to the background service worker.
// Fetches scan result for the current tab and renders it.

import { getCategoryLevel, getCategoryLabel, isAnalyzableUrl, createEl } from '../utils/helpers.js';

// =====================
// DOM HELPERS
// =====================

function el(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const e = el(id);
  if (e) e.textContent = text;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

// Icons are built with DOM APIs (no innerHTML). The verdict icons are filled shapes,
// so each state also differs in shape, not just colour.
const VERDICT_ICONS = {
  no:      [['circle', { cx: 12, cy: 12, r: 10, class: 'vi-shape' }], ['rect', { x: 6.5, y: 10.25, width: 11, height: 3.5, rx: 1.75, class: 'vi-mark' }]],
  caution: [['path', { d: 'M12 3.4 21.2 20H2.8z', class: 'vi-shape' }], ['rect', { x: 11, y: 9, width: 2, height: 6, rx: 1, class: 'vi-mark' }], ['circle', { cx: 12, cy: 17.4, r: 1.2, class: 'vi-mark' }]],
  ok:      [['circle', { cx: 12, cy: 12, r: 10, class: 'vi-shape' }], ['path', { d: 'm7.5 12.4 3 3 6-6.8', class: 'vi-stroke' }]]
};

function svgIcon(className, nodes) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', className);
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  for (const [tag, attrs] of nodes) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
    svg.append(node);
  }
  return svg;
}

function findingItem(type, icon, text) {
  const li = createEl('li', `finding-item ${type}`);
  li.append(createEl('span', 'finding-icon', icon), createEl('span', 'finding-text', text));
  return li;
}

// =====================
// RENDER FUNCTIONS
// =====================

const CATEGORIES = ['security', 'privacy', 'phishing', 'resources'];

function renderScanning() {
  setText('site-domain', 'Scanning...');
  setText('site-url', '');
  setText('score-number', '--');
  setText('risk-label', 'Please wait');
  el('risk-badge').className = 'risk-badge';

  resetCategories();

  el('findings-list').replaceChildren(findingItem('neutral', '⏳', 'Analysis in progress...'));

    renderVerdict(null);
}

function renderError(message) {
  setText('site-domain', 'Unable to analyze');
  setText('site-url', message || 'This page cannot be scanned.');
  setText('score-number', '?');
  setText('risk-label', 'UNAVAILABLE');
  el('risk-badge').className = 'risk-badge';

  resetCategories();
  el('findings-list').replaceChildren(findingItem('neutral', 'ℹ', message || 'Page could not be analyzed.'));

    renderVerdict(null);
}

function renderResult(result) {
  const { score, riskLevel, riskLabel, domain, url, findings, categories } = result;

  // Site info
  setText('site-domain', domain || 'Unknown');
  setText('site-url', url || '');

  // Score
  const scoreEl = el('score-number');
  scoreEl.textContent = score;
  scoreEl.className = `score-number ${riskLevel}`;

  // Risk badge
  const badge = el('risk-badge');
  badge.className = `risk-badge ${riskLevel}`;
  setText('risk-label', riskLabel);
  renderVerdict(result.verdict);

  // Show limited analysis note if applicable (and hide it again after a full rescan)
  const limited = !!result.pageData?.limitedAnalysis;
  el('limited-note')?.classList.toggle('hidden', !limited);
  document.body.classList.toggle('is-limited', limited);

  // Category scores
  if (categories) {
    renderCategory('security',  categories.security,  25);
    renderCategory('privacy',   categories.privacy,   30);
    renderCategory('phishing',  categories.phishing,  25);
    renderCategory('resources', categories.resources, 20);
  } else {
    // Fallback — no category breakdown yet
    resetCategories();
  }

  // Findings list
  renderFindings(findings || []);
}

function resetCategories() {
  CATEGORIES.forEach(resetCategory);
}

function renderCategory(name, catObj, max) {
  // catObj comes in as { score: X, maxScore: Y } — extract the number
  const score = (typeof catObj === 'object' && catObj !== null)
    ? catObj.score
    : catObj;

  if (score === undefined || score === null) {
    resetCategory(name);
    return;
  }
  const level = getCategoryLevel(score, max);
  const pct = Math.max(0, Math.min(100, Math.round((score / max) * 100)));

  setText(`cat-${name}`, `${score}/${max}`);
  const levelEl = el(`cat-${name}-level`);
  levelEl.textContent = getCategoryLabel(score, max);
  levelEl.className = `category-level ${level}`;

  const bar = el(`cat-${name}-bar`);
  bar.style.width = `${pct}%`;
  bar.className = `cat-bar-fill ${level}`;
  el(`cat-${name}-meter`).setAttribute('aria-valuenow', String(score));
}

function resetCategory(name) {
  setText(`cat-${name}`, '--');
  setText(`cat-${name}-level`, '--');
  el(`cat-${name}-level`).className = 'category-level';
  const bar = el(`cat-${name}-bar`);
  bar.style.width = '0%';
  bar.className = 'cat-bar-fill';
  el(`cat-${name}-meter`).removeAttribute('aria-valuenow');
}
function renderVerdict(verdict) {
  const box = el('verdict');
  if (!box) return;

  if (!verdict || !VERDICT_ICONS[verdict.level]) {
    box.className = 'verdict hidden';
    return;
  }

  // Two reasons share the space, so each is clamped tighter (full text in the tooltip).
  const multi = (verdict.reasons || []).length > 1 ? ' multi' : '';
  box.className = `verdict ${verdict.level}${multi}`;
  const icon = svgIcon('verdict-icon', VERDICT_ICONS[verdict.level]);
  el('verdict-icon').replaceChildren(icon);
  setText('verdict-label', verdict.label || '');
  el('verdict-reasons').replaceChildren(
    ...(verdict.reasons || []).slice(0, 2).map(r => {
      const p = createEl('p', 'verdict-reason', r);
      p.title = r;
      return p;
    }));
}

function renderFindings(findings) {
  const list = el('findings-list');
  if (!findings.length) {
    list.replaceChildren(findingItem('neutral', 'ℹ', 'No significant findings.'));
    return;
  }

  // Show max 6 findings in popup (full list in dashboard)
  list.replaceChildren(...findings.slice(0, 6).map(f =>
    findingItem(f.type || 'neutral', f.icon || 'ℹ', f.text || '')));
}

// =====================
// OPEN FULL DASHBOARD
// =====================

function openDashboard(tabId, result) {
  const open = () => {
    const params = new URLSearchParams({ tabId: String(tabId) });
    chrome.tabs.create({
      url: chrome.runtime.getURL(`dashboard/dashboard.html?${params}`)
    });
  };
  if (result && result.status === 'complete') {
    // Store result in chrome.storage.session so dashboard can retrieve it
    chrome.storage.session.set({ [`webguard_result_${tabId}`]: result }, open);
  } else {
    open();
  }
}

// =====================
// MAIN — runs on popup open
// =====================

document.addEventListener('DOMContentLoaded', async () => {

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    renderError('Could not detect current tab.');
    return;
  }

  const tabId = tab.id;
  const tabUrl = tab.url || '';

  // Skip non-analyzable pages
  if (!isAnalyzableUrl(tabUrl)) {
    renderError('WebGuard cannot analyze browser internal pages.');
    return;
  }

  // Show scanning state immediately
  renderScanning();
  setText('site-domain', new URL(tabUrl).hostname || tabUrl);
  setText('site-url', tabUrl);

  // Request scan result from service worker
  chrome.runtime.sendMessage(
    { type: 'GET_SCAN_RESULT', tabId },
    (response) => {
      if (chrome.runtime.lastError) {
        renderError('WebGuard service worker is not responding. Try reloading the extension.');
        return;
      }

      const result = response?.result;

      if (!result || result.status === 'scanning') {
        // Still scanning — poll once after a short delay
        setTimeout(() => {
          chrome.runtime.sendMessage(
            { type: 'GET_SCAN_RESULT', tabId },
            (resp2) => {
              const r2 = resp2?.result;
              if (r2 && r2.status === 'complete') {
                renderResult(r2);
              } else if (r2 && r2.status === 'error') {
                renderError(r2.error);
              } else {
                renderError('Analysis is taking longer than expected. Try rescanning.');
              }
            }
          );
        }, 1500);
        return;
      }

      if (result.status === 'error') {
        renderError(result.error);
        return;
      }

      if (result.status === 'complete') {
        renderResult(result);
        return;
      }

      renderError('Unexpected state. Try rescanning.');
    }
  );

  // =====================
  // BUTTON: Rescan
  // =====================
  const rescanBtn = el('btn-rescan');
  rescanBtn.addEventListener('click', () => {
    rescanBtn.classList.add('is-rescanning');
    const done = () => rescanBtn.classList.remove('is-rescanning');
    renderScanning();
    setText('site-domain', new URL(tabUrl).hostname || tabUrl);
    setText('site-url', tabUrl);

    chrome.runtime.sendMessage(
      { type: 'RESCAN', tabId },
      () => {
        // Poll for result after rescan
        setTimeout(() => {
          chrome.runtime.sendMessage(
            { type: 'GET_SCAN_RESULT', tabId },
            (resp) => {
              done();
              const r = resp?.result;
              if (r && r.status === 'complete') renderResult(r);
              else if (r && r.status === 'error') renderError(r.error);
              else renderError('Rescan timed out. Please try again.');
            }
          );
        }, 2000);
      }
    );
  });

  // =====================
  // BUTTON: Full Report
  // =====================
  el('btn-full-report').addEventListener('click', () => {
    chrome.runtime.sendMessage(
      { type: 'GET_SCAN_RESULT', tabId },
      (response) => {
        openDashboard(tabId, response?.result);
      }
    );
  });

});
// popup/popup.js
// Wires the popup UI to the background service worker.
// Fetches scan result for the current tab and renders it.

// =====================
// RISK LEVEL HELPERS
// =====================

function getRiskLevel(score) {
  if (score >= 90) return 'very-low';
  if (score >= 75) return 'low';
  if (score >= 50) return 'moderate';
  if (score >= 25) return 'high';
  return 'critical';
}

function getRiskLabel(score) {
  if (score >= 90) return 'VERY LOW RISK';
  if (score >= 75) return 'LOW RISK';
  if (score >= 50) return 'MODERATE RISK';
  if (score >= 25) return 'HIGH RISK';
  return 'CRITICAL RISK';
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

function setClass(id, className) {
  const e = el(id);
  if (e) e.className = className;
}

// =====================
// RENDER FUNCTIONS
// =====================

function renderScanning() {
  setText('site-domain', 'Scanning...');
  setText('site-url', '');
  setText('score-number', '--');
  setText('risk-label', 'Please wait');
  el('risk-badge').className = 'risk-badge';

  setText('cat-security', '--');
  setText('cat-security-level', '--');
  setText('cat-privacy', '--');
  setText('cat-privacy-level', '--');
  setText('cat-phishing', '--');
  setText('cat-phishing-level', '--');
  setText('cat-resources', '--');
  setText('cat-resources-level', '--');

  const list = el('findings-list');
  list.innerHTML = `
    <li class="finding-item neutral">
      <span class="finding-icon">⏳</span>
      <span class="finding-text">Analysis in progress...</span>
    </li>`;

    renderVerdict(null);
}

function renderError(message) {
  setText('site-domain', 'Unable to analyze');
  setText('site-url', message || 'This page cannot be scanned.');
  setText('score-number', '?');
  setText('risk-label', 'UNAVAILABLE');
  el('risk-badge').className = 'risk-badge';

  const list = el('findings-list');
  list.innerHTML = `
    <li class="finding-item neutral">
      <span class="finding-icon">ℹ</span>
      <span class="finding-text">${sanitize(message || 'Page could not be analyzed.')}</span>
    </li>`;

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

  // Show limited analysis note if applicable
  const noteEl = document.getElementById('limited-note');
  if (result.pageData?.limitedAnalysis && noteEl) {
  noteEl.classList.remove('hidden');
  }

  // Category scores
  if (categories) {
    renderCategory('security',  categories.security,  25);
    renderCategory('privacy',   categories.privacy,   30);
    renderCategory('phishing',  categories.phishing,  25);
    renderCategory('resources', categories.resources, 20);
  } else {
    // Fallback — no category breakdown yet
    ['security', 'privacy', 'phishing', 'resources'].forEach(cat => {
      setText(`cat-${cat}`, '--');
      setText(`cat-${cat}-level`, '--');
    });
  }

  // Findings list
  renderFindings(findings || []);
}

function renderCategory(name, catObj, max) {
  // catObj comes in as { score: X, maxScore: Y } — extract the number
  const score = (typeof catObj === 'object' && catObj !== null)
    ? catObj.score
    : catObj;

  if (score === undefined || score === null) {
    setText(`cat-${name}`, '--');
    setText(`cat-${name}-level`, '--');
    return;
  }
  setText(`cat-${name}`, `${score}/${max}`);
  const levelEl = el(`cat-${name}-level`);
  if (levelEl) {
    const level = getCategoryLevel(score, max);
    const label = getCategoryLabel(score, max);
    levelEl.textContent = label;
    levelEl.className = `category-level ${level}`;
  }
}
function renderVerdict(verdict) {
  const box = el('verdict');
  if (!box) return;

  const levels = { no: '⛔', caution: '⚠', ok: '✓' };
  if (!verdict || !levels[verdict.level]) {
    box.className = 'verdict hidden';
    return;
  }

  box.className = `verdict ${verdict.level}`;
  setText('verdict-label', `${levels[verdict.level]} ${verdict.label}`);
  setText('verdict-reason', (verdict.reasons || [])[0] || '');
}

function renderFindings(findings) {
  const list = el('findings-list');
  if (!findings.length) {
    list.innerHTML = `
      <li class="finding-item neutral">
        <span class="finding-icon">ℹ</span>
        <span class="finding-text">No significant findings.</span>
      </li>`;
    return;
  }

  // Show max 6 findings in popup (full list in dashboard)
  const shown = findings.slice(0, 6);
  list.innerHTML = shown.map(f => `
    <li class="finding-item ${sanitize(f.type || 'neutral')}">
      <span class="finding-icon">${sanitize(f.icon || 'ℹ')}</span>
      <span class="finding-text">${sanitize(f.text || '')}</span>
    </li>
  `).join('');
}

// =====================
// SANITIZER
// Prevent XSS — all dynamic text must go through this
// =====================

function sanitize(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

// =====================
// OPEN FULL DASHBOARD
// =====================

function openDashboard(tabId, result) {
  if (result && result.status === 'complete') {
    // Store result in chrome.storage.session so dashboard can retrieve it
    chrome.storage.session.set({ [`webguard_result_${tabId}`]: result }, () => {
      const params = new URLSearchParams({ tabId: String(tabId) });
      chrome.tabs.create({
        url: chrome.runtime.getURL(`dashboard/dashboard.html?${params}`)
      });
    });
  } else {
    const params = new URLSearchParams({ tabId: String(tabId) });
    chrome.tabs.create({
      url: chrome.runtime.getURL(`dashboard/dashboard.html?${params}`)
    });
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
  if (
    tabUrl.startsWith('chrome://') ||
    tabUrl.startsWith('chrome-extension://') ||
    tabUrl === 'about:blank' ||
    tabUrl === ''
  ) {
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
  el('btn-rescan').addEventListener('click', () => {
    renderScanning();
    setText('site-domain', new URL(tabUrl).hostname || tabUrl);
    setText('site-url', tabUrl);

    chrome.runtime.sendMessage(
      { type: 'RESCAN', tabId, url: tabUrl },
      () => {
        // Poll for result after rescan
        setTimeout(() => {
          chrome.runtime.sendMessage(
            { type: 'GET_SCAN_RESULT', tabId },
            (resp) => {
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
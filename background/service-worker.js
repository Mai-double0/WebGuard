// background/service-worker.js
// Coordinates tab detection, triggers analysis, updates toolbar badge.

// =====================
// BADGE COLORS
// =====================
const BADGE_COLORS = {
  'very-low': '#22c55e',
  'low':      '#22c55e',
  'moderate': '#eab308',
  'high':     '#f97316',
  'critical': '#ef4444',
  'default':  '#64748b'
};

// =====================
// RISK LEVEL HELPER
// =====================
function getRiskLevel(score) {
  if (score >= 90) return 'very-low';
  if (score >= 75) return 'low';
  if (score >= 50) return 'moderate';
  if (score >= 25) return 'high';
  return 'critical';
}

function getRiskLabel(score) {
  if (score >= 90) return 'VERY LOW';
  if (score >= 75) return 'LOW';
  if (score >= 50) return 'MODERATE';
  if (score >= 25) return 'HIGH';
  return 'CRITICAL';
}

// =====================
// BADGE UPDATER
// =====================
function updateBadge(tabId, score) {
  if (score === null || score === undefined) {
    chrome.action.setBadgeText({ tabId, text: '...' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS['default'] });
    return;
  }

  const level = getRiskLevel(score);
  chrome.action.setBadgeText({ tabId, text: String(score) });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[level] });
}

// =====================
// SCAN STATE PER TAB
// =====================
const tabScanState = {};

function setScanState(tabId, state) {
  tabScanState[tabId] = state;
}

function getScanState(tabId) {
  return tabScanState[tabId] || null;
}

// =====================
// TRIGGER ANALYSIS
// =====================
async function triggerAnalysis(tabId, url) {
  // Skip chrome:// pages, extension pages, and empty tabs
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url === 'about:blank') {
    chrome.action.setBadgeText({ tabId, text: '' });
    setScanState(tabId, null);
    return;
  }

  // Mark as scanning
  setScanState(tabId, { status: 'scanning', url });
  updateBadge(tabId, null);

  try {
    // Inject content script to collect page data
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content/content.js']
    });
  } catch (err) {
    // Content script injection failed (e.g. restricted page)
    console.warn(`WebGuard: Could not inject content script on tab ${tabId}:`, err.message);
    setScanState(tabId, {
      status: 'error',
      url,
      error: 'Page could not be analyzed (restricted page or extension page).'
    });
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS['default'] });
  }
}

// =====================
// TAB EVENT LISTENERS
// =====================

// When navigation completes in a tab
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return; // Main frame only
  triggerAnalysis(details.tabId, details.url);
});

// When user switches tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    const state = getScanState(activeInfo.tabId);

    if (state && state.score !== undefined) {
      // Already have a result — restore badge
      updateBadge(activeInfo.tabId, state.score);
    } else {
      // No result yet — trigger analysis
      triggerAnalysis(activeInfo.tabId, tab.url);
    }
  } catch (err) {
    console.warn('WebGuard: Tab activation error:', err.message);
  }
});

// When a tab is closed — clean up state
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabScanState[tabId];
});

// =====================
// MESSAGE HANDLER
// =====================
// Receives results from content.js and requests from popup.js

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // Content script finished collecting page data
  if (message.type === 'PAGE_DATA_COLLECTED') {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    const pageData = message.data;

    // Run analysis engines
    analyzeAndScore(tabId, pageData);
    sendResponse({ status: 'received' });
    return true;
  }

  // Popup is requesting the current scan result
  if (message.type === 'GET_SCAN_RESULT') {
    const { tabId } = message;
    const state = getScanState(tabId);
    sendResponse({ result: state });
    return true;
  }

  // Popup requested a rescan
  if (message.type === 'RESCAN') {
    const { tabId, url } = message;
    triggerAnalysis(tabId, url);
    sendResponse({ status: 'rescanning' });
    return true;
  }

});

// =====================
// ANALYSIS COORDINATOR
// =====================
// Imports will be added as we build each analyzer.
// For now: placeholder scoring so the badge works end-to-end.

async function analyzeAndScore(tabId, pageData) {
  try {
    // --- Placeholder until analyzers are built ---
    // We calculate a basic score from raw page data directly.

    let score = 100;
    const findings = [];

    // HTTPS check
    if (pageData.protocol === 'https:') {
      findings.push({ type: 'positive', icon: '✓', text: 'HTTPS connection detected' });
    } else {
      score -= 20;
      findings.push({ type: 'danger', icon: '✗', text: 'No HTTPS — connection is not encrypted' });
    }

    // Third-party domains
    const thirdPartyCount = pageData.thirdPartyDomains?.length || 0;
    if (thirdPartyCount > 10) {
      score -= 15;
      findings.push({ type: 'warning', icon: '⚠', text: `${thirdPartyCount} third-party domains detected` });
    } else if (thirdPartyCount > 0) {
      score -= 5;
      findings.push({ type: 'warning', icon: '⚠', text: `${thirdPartyCount} third-party domains detected` });
    }

    // Password/login form
    if (pageData.hasPasswordField) {
      score -= 5;
      findings.push({ type: 'warning', icon: '⚠', text: 'Login form detected — verify site authenticity' });
    }

    // iFrames
    const iframeCount = pageData.iframes?.length || 0;
    if (iframeCount > 3) {
      score -= 10;
      findings.push({ type: 'warning', icon: '⚠', text: `${iframeCount} iframes detected` });
    }

    // Security headers
    if (!pageData.hasCSP) {
      score -= 8;
      findings.push({ type: 'warning', icon: '⚠', text: 'Content-Security-Policy not detected' });
    }

    // Clamp score between 0–100
    score = Math.max(0, Math.min(100, score));

    const riskLevel = getRiskLevel(score);
    const riskLabel = getRiskLabel(score);

    const result = {
      status: 'complete',
      url: pageData.url,
      domain: pageData.domain,
      score,
      riskLevel,
      riskLabel,
      findings,
      pageData,
      scannedAt: Date.now()
    };

    setScanState(tabId, result);
    updateBadge(tabId, score);

  } catch (err) {
    console.error('WebGuard: Analysis error:', err);
    setScanState(tabId, { status: 'error', error: err.message });
  }
}
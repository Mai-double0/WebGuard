// background/service-worker.js
import { runRiskEngine } from '../scoring/risk-engine.js';

const BADGE_COLORS = {
  'very-low': '#22c55e',
  'low':      '#22c55e',
  'moderate': '#eab308',
  'high':     '#f97316',
  'critical': '#ef4444',
  'default':  '#64748b'
};

function getRiskLevel(score) {
  if (score >= 90) return 'very-low';
  if (score >= 75) return 'low';
  if (score >= 50) return 'moderate';
  if (score >= 25) return 'high';
  return 'critical';
}

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
// SCAN STATE — persists results per tab
// =====================
const tabScanState = {};

function setScanState(tabId, state) {
  tabScanState[tabId] = state;
}

function getScanState(tabId) {
  return tabScanState[tabId] || null;
}

// =====================
// TRIGGER ANALYSIS — always re-runs on navigation
// =====================
async function triggerAnalysis(tabId, url) {
  if (!url ||
      url.startsWith('chrome://') ||
      url.startsWith('chrome-extension://') ||
      url === 'about:blank' ||
      url === '') {
    chrome.action.setBadgeText({ tabId, text: '' });
    setScanState(tabId, null);
    return;
  }

  // Always reset state on new navigation so popup doesn't show stale data
  setScanState(tabId, { status: 'scanning', url });
  updateBadge(tabId, null);

  try {
    // Force re-injection by using scripting API directly
    await chrome.scripting.executeScript({
      target: { tabId },
      func: () => { delete window.__webguardInjected; }
    });
  } catch (_) { /* page may not be ready yet — ignore */ }

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content/content.js']
    });
  } catch (err) {
    console.warn(`WebGuard: Content script blocked on tab ${tabId}:`, err.message);
    // Fallback: URL-only analysis
    try {
      const urlObj = new URL(url);
      const fallbackData = buildFallbackData(url, urlObj);
      analyzeAndScore(tabId, fallbackData);
    } catch (parseErr) {
      setScanState(tabId, {
        status: 'error',
        url,
        error: 'Page could not be analyzed (blocked by site security policy).'
      });
      chrome.action.setBadgeText({ tabId, text: '?' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS['default'] });
    }
  }
}

function buildFallbackData(url, urlObj) {
  return {
    url,
    domain:                 urlObj.hostname,
    protocol:               urlObj.protocol,
    scripts:                [],
    thirdPartyScripts:      [],
    stylesheets:            [],
    iframes:                [],
    thirdPartyIframes:      [],
    hiddenIframes:          [],
    thirdPartyImages:       [],
    thirdPartyDomains:      [],
    trackingResources:      [],
    adResources:            [],
    analyticsResources:     [],
    hasPasswordField:       false,
    hasEmailField:          false,
    hasCreditCard:          false,
    externalFormActions:    [],
    formCount:              0,
    metaTags:               {},
    hasMetaCSP:             false,
    mixedContentIndicators: [],
    subdomainCount:         urlObj.hostname.split('.').length - 2,
    hasIPAddress:           /^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname),
    hasPunycode:            urlObj.hostname.includes('xn--'),
    hasSuspiciousChars:     /[^a-z0-9\-.]/.test(urlObj.hostname),
    urlLength:              url.length,
    hasEncodedChars:        url.includes('%'),
    hasDownloadLinks:       false,
    hasBeforeUnload:        false,
    externalLinks:          [],
    collectedAt:            Date.now(),
    limitedAnalysis:        true
  };
}

// =====================
// TAB EVENTS — always re-trigger on navigation
// =====================

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  triggerAnalysis(details.tabId, details.url);
});

// Re-trigger when switching tabs so badge is always current
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    const state = getScanState(activeInfo.tabId);

    if (state && state.status === 'complete') {
      // Restore badge from cached result
      updateBadge(activeInfo.tabId, state.score);
    } else {
      // No complete result — trigger fresh analysis
      triggerAnalysis(activeInfo.tabId, tab.url);
    }
  } catch (err) {
    console.warn('WebGuard: Tab activation error:', err.message);
  }
});

// Clear state when tab is updated (URL changed by user)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    setScanState(tabId, { status: 'scanning', url: changeInfo.url });
    updateBadge(tabId, null);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabScanState[tabId];
});

// =====================
// MESSAGE HANDLER
// =====================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === 'PAGE_DATA_COLLECTED') {
    const tabId = sender.tab?.id;
    if (!tabId) { sendResponse({ status: 'no-tab' }); return true; }
    analyzeAndScore(tabId, message.data);
    sendResponse({ status: 'received' });
    return true;
  }

  if (message.type === 'GET_SCAN_RESULT') {
    const state = getScanState(message.tabId);
    sendResponse({ result: state });
    return true;
  }

  if (message.type === 'RESCAN') {
    // Clear existing state so popup shows scanning immediately
    setScanState(message.tabId, { status: 'scanning', url: message.url });
    triggerAnalysis(message.tabId, message.url);
    sendResponse({ status: 'rescanning' });
    return true;
  }

});

// =====================
// ANALYSIS COORDINATOR
// =====================
async function analyzeAndScore(tabId, pageData) {
  try {
    const result = runRiskEngine(pageData);

    const finalResult = {
      status:     'complete',
      url:        pageData.url,
      domain:     pageData.domain,
      score:      result.score,
      riskLevel:  result.riskLevel,
      riskLabel:  result.riskLabel,
      categories: result.categories,
      findings:   result.findings,
      details:    result.details,
      pageData,
      scannedAt:  Date.now()
    };

    setScanState(tabId, finalResult);
    updateBadge(tabId, result.score);

  } catch (err) {
    console.error('WebGuard: Analysis error:', err);
    setScanState(tabId, { status: 'error', error: err.message });
  }
}
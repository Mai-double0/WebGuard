// background/service-worker.js
// Coordinates tab detection, triggers analysis, updates toolbar badge.

import { runRiskEngine } from '../scoring/risk-engine.js';

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
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url === 'about:blank') {
    chrome.action.setBadgeText({ tabId, text: '' });
    setScanState(tabId, null);
    return;
  }

  setScanState(tabId, { status: 'scanning', url });
  updateBadge(tabId, null);

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content/content.js']
    });
  } catch (err) {
    console.warn(`WebGuard: Could not inject content script on tab ${tabId}:`, err.message);
    setScanState(tabId, {
      status: 'error',
      url,
      error: 'Page could not be analyzed (restricted or protected page).'
    });
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS['default'] });
  }
}

// =====================
// TAB EVENT LISTENERS
// =====================
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  triggerAnalysis(details.tabId, details.url);
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    const state = getScanState(activeInfo.tabId);
    if (state && state.score !== undefined) {
      updateBadge(activeInfo.tabId, state.score);
    } else {
      triggerAnalysis(activeInfo.tabId, tab.url);
    }
  } catch (err) {
    console.warn('WebGuard: Tab activation error:', err.message);
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
    if (!tabId) return;
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
    // Run the full risk engine (all 4 analyzers)
    const result = runRiskEngine(pageData);

    const finalResult = {
      status: 'complete',
      url:       pageData.url,
      domain:    pageData.domain,
      score:     result.score,
      riskLevel: result.riskLevel,
      riskLabel: result.riskLabel,
      categories: result.categories,
      findings:   result.findings,
      details:    result.details,
      pageData,
      scannedAt: Date.now()
    };

    setScanState(tabId, finalResult);
    updateBadge(tabId, result.score);

  } catch (err) {
    console.error('WebGuard: Analysis error:', err);
    setScanState(tabId, { status: 'error', error: err.message });
  }
}
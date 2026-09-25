// background/service-worker.js
// Coordinates tab detection, response-header capture, analysis, and the toolbar badge.

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
// SCAN STATE PER TAB
// =====================
const tabScanState = {};

function setScanState(tabId, state) { tabScanState[tabId] = state; }
function getScanState(tabId) { return tabScanState[tabId] || null; }

// =====================
// RESPONSE HEADER CAPTURE (main document only)
// Read-only observation — WebGuard never modifies or blocks requests.
// =====================
const tabHeaders = {};

// Keep cookie name and flags, drop the value — WebGuard never stores cookie contents.
function redactCookie(raw) {
  return String(raw).replace(/^([^=;]*)=[^;]*/, '$1=[redacted]');
}

function captureHeaders(details) {
  if (details.tabId < 0) return;

  const headers = {};
  const setCookies = [];

  for (const h of details.responseHeaders || []) {
    const name  = (h.name || '').toLowerCase();
    const value = h.value || '';
    if (name === 'set-cookie') {
      value.split('\n').forEach(c => { if (c.trim()) setCookies.push(redactCookie(c.trim())); });
    } else {
      headers[name] = value;
    }
  }

  tabHeaders[details.tabId] = {
    url:        details.url,
    statusCode: details.statusCode,
    headers,
    setCookies,
    capturedAt: Date.now()
  };
}

const HEADER_FILTER = { urls: ['<all_urls>'], types: ['main_frame'] };
try {
  // 'extraHeaders' is needed in Chrome to see Set-Cookie
  chrome.webRequest.onHeadersReceived.addListener(captureHeaders, HEADER_FILTER, ['responseHeaders', 'extraHeaders']);
} catch (err) {
  // Browsers without 'extraHeaders' (e.g. Firefox) still get the other headers
  chrome.webRequest.onHeadersReceived.addListener(captureHeaders, HEADER_FILTER, ['responseHeaders']);
}

// Only use captured headers if they belong to the same site as the analyzed page
function getHeadersForPage(tabId, pageUrl) {
  const h = tabHeaders[tabId];
  if (!h) return null;
  try {
    return new URL(h.url).origin === new URL(pageUrl).origin ? h : null;
  } catch {
    return null;
  }
}

// =====================
// CERTIFICATE ERROR CAPTURE
// Chrome does not expose certificate details to extensions, but when it blocks
// a page with a certificate warning, the failed request reports the error code.
// Stored per hostname in session storage (cleared when the browser closes).
// =====================
const CERT_KEY = 'webguard_cert_errors';

chrome.webRequest.onErrorOccurred.addListener(async (details) => {
  const err = details.error || '';
  if (!/ERR_CERT_|ERR_SSL_/i.test(err)) return;
  try {
    const host = new URL(details.url).hostname;
    const data = await chrome.storage.session.get(CERT_KEY);
    const map  = data[CERT_KEY] || {};
    map[host]  = { error: err, seenAt: Date.now() };
    await chrome.storage.session.set({ [CERT_KEY]: map });
  } catch (e) {
    console.warn('WebGuard: could not record certificate error', e);
  }
}, { urls: ['<all_urls>'], types: ['main_frame'] });

async function getCertErrorForHost(host) {
  try {
    const data = await chrome.storage.session.get(CERT_KEY);
    return (data[CERT_KEY] || {})[host] || null;
  } catch {
    return null;
  }
}

// =====================
// TRIGGER ANALYSIS
// =====================
async function triggerAnalysis(tabId, url) {
  if (!url ||
      url.startsWith('chrome://') ||
      url.startsWith('chrome-extension://') ||
      url === 'about:blank') {
    chrome.action.setBadgeText({ tabId, text: '' });
    setScanState(tabId, null);
    return;
  }

  setScanState(tabId, { status: 'scanning', url });
  updateBadge(tabId, null);

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: () => { delete window.__webguardInjected; }
    });
  } catch (_) { /* page may not be ready — ignore */ }

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content/content.js']
    });
  } catch (err) {
    console.warn(`WebGuard: Content script blocked on tab ${tabId}:`, err.message);
    try {
      const urlObj = new URL(url);
      analyzeAndScore(tabId, buildFallbackData(url, urlObj));
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
    downloadLinks:          [],
    hasBeforeUnload:        false,
    externalLinks:          [],
    collectedAt:            Date.now(),
    limitedAnalysis:        true
  };
}

// =====================
// TAB EVENTS
// =====================
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  triggerAnalysis(details.tabId, details.url);
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    const state = getScanState(activeInfo.tabId);
    if (state && state.status === 'complete') {
      updateBadge(activeInfo.tabId, state.score);
    } else {
      triggerAnalysis(activeInfo.tabId, tab.url);
    }
  } catch (err) {
    console.warn('WebGuard: Tab activation error:', err.message);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    setScanState(tabId, { status: 'scanning', url: changeInfo.url });
    updateBadge(tabId, null);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabScanState[tabId];
  delete tabHeaders[tabId];
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
    sendResponse({ result: getScanState(message.tabId) });
    return true;
  }

  if (message.type === 'RESCAN') {
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
    pageData.responseHeaders = getHeadersForPage(tabId, pageData.url);
    pageData.certError       = await getCertErrorForHost(pageData.domain);

    const result = runRiskEngine(pageData);

    setScanState(tabId, {
      status:     'complete',
      url:        pageData.url,
      domain:     pageData.domain,
      score:      result.score,
      riskLevel:  result.riskLevel,
      riskLabel:  result.riskLabel,
      verdict:    result.verdict,
      categories: result.categories,
      findings:   result.findings,
      details:    result.details,
      pageData,
      scannedAt:  Date.now()
    });
    updateBadge(tabId, result.score);

  } catch (err) {
    console.error('WebGuard: Analysis error:', err);
    setScanState(tabId, { status: 'error', error: err.message });
  }
}
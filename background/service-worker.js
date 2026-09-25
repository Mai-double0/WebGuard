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
// Headers are kept in session storage so they survive the service worker
// going to sleep. Cleared automatically when the browser closes.
const HEADERS_KEY = (tabId) => `webguard_headers_${tabId}`;

// Only the headers the analyzers read are kept; anything else (e.g. tokens in
// custom headers) is never stored.
const KEPT_HEADERS = new Set([
  'content-security-policy', 'strict-transport-security', 'x-frame-options',
  'x-content-type-options', 'referrer-policy', 'server', 'x-powered-by'
]);

// Keep cookie name and flags only — WebGuard never stores cookie values.
// A Set-Cookie without '=' in its first part is a nameless cookie whose value is that part.
function parseCookie(raw) {
  const [first, ...attrs] = raw.split(';');
  const eq = first.indexOf('=');
  const flags = attrs.map(a => a.split('=')[0].trim().toLowerCase());
  return {
    name:     eq >= 0 ? first.slice(0, eq).trim() : '',
    secure:   flags.includes('secure'),
    httpOnly: flags.includes('httponly')
  };
}

function captureHeaders(details) {
  if (details.tabId < 0) return;

  const headers = {};
  const cookies = [];

  for (const h of details.responseHeaders || []) {
    const name  = (h.name || '').toLowerCase();
    const value = h.value || '';
    if (name === 'set-cookie') {
      value.split('\n').forEach(c => { if (c.trim()) cookies.push(parseCookie(c.trim())); });
    } else if (KEPT_HEADERS.has(name)) {
      // Repeated headers are combined as HTTP defines (e.g. two CSP policies)
      headers[name] = name in headers ? `${headers[name]}, ${value}` : value;
    }
  }

  let origin;
  try { origin = new URL(details.url).origin; } catch { return; }

  chrome.storage.session.set({
    [HEADERS_KEY(details.tabId)]: {
      origin,
      statusCode: details.statusCode,
      headers,
      cookies,
      capturedAt: Date.now()
    }
  }).catch(err => console.warn('WebGuard: could not store headers', err));
}

const HEADER_FILTER = { urls: ['<all_urls>'], types: ['main_frame'] };
try {
  chrome.webRequest.onHeadersReceived.addListener(captureHeaders, HEADER_FILTER, ['responseHeaders', 'extraHeaders']);
} catch (err) {
  chrome.webRequest.onHeadersReceived.addListener(captureHeaders, HEADER_FILTER, ['responseHeaders']);
}

// Only use captured headers if they belong to the same site as the analyzed page
async function getHeadersForPage(tabId, pageUrl) {
  try {
    const key  = HEADERS_KEY(tabId);
    const data = await chrome.storage.session.get(key);
    const h    = data[key];
    if (!h) return null;
    return h.origin === new URL(pageUrl).origin ? h : null;
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
    iframes:                [],
    thirdPartyIframes:      [],
    hiddenIframes:          [],
    thirdPartyImages:       [],
    thirdPartyDomains:      [],
    trackingResources:      [],
    adResources:            [],
    analyticsResources:     [],
    hasPasswordField:       false,
    hasCreditCard:          false,
    externalFormActions:    [],
    hasMetaCSP:             false,
    mixedContentIndicators: [],
    subdomainCount:         urlObj.hostname.split('.').length - 2,
    hasIPAddress:           /^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname),
    hasPunycode:            urlObj.hostname.includes('xn--'),
    hasSuspiciousChars:     /[^a-z0-9\-.]/.test(urlObj.hostname),
    urlLength:              url.length,
    hasEncodedChars:        url.includes('%') && !url.includes('%20'),  // same rule as content.js
    hasDownloadLinks:       false,
    downloadLinks:          [],
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
  chrome.storage.session.remove([HEADERS_KEY(tabId), `webguard_result_${tabId}`]);
});

// =====================
// MESSAGE VALIDATION
// Content scripts run inside web pages, so their messages are treated as
// untrusted input: only the fields the analyzers read are kept, each with
// the expected type. Scan results and rescans are only for extension pages.
// =====================
const isString  = v => typeof v === 'string';
const optString = v => (isString(v) ? v : null);
const strings   = v => (Array.isArray(v) ? v.filter(isString) : []);
const objects   = (v, pick) => (Array.isArray(v) ? v.filter(o => o && typeof o === 'object').map(pick) : []);
const count     = v => (Number.isFinite(v) ? v : 0);

const frame = f => ({ src: optString(f.src), sandbox: optString(f.sandbox), hidden: f.hidden === true });

function isExtensionPage(sender) {
  return sender.id === chrome.runtime.id &&
         isString(sender.url) && sender.url.startsWith(chrome.runtime.getURL(''));
}

function isOwnContentScript(sender) {
  return sender.id === chrome.runtime.id &&
         Number.isInteger(sender.tab?.id) && sender.frameId === 0;
}

// Returns clean page data, or null if the message does not describe the sender's page.
function normalizePageData(raw, sender) {
  if (!raw || typeof raw !== 'object' || !isString(raw.url)) return null;
  let url;
  try {
    url = new URL(raw.url);
    if (url.origin !== new URL(sender.url).origin) return null;
  } catch {
    return null;
  }

  return {
    url:                    raw.url,
    domain:                 url.hostname,
    protocol:               url.protocol,
    scripts:                strings(raw.scripts),
    thirdPartyScripts:      strings(raw.thirdPartyScripts),
    iframes:                objects(raw.iframes, frame),
    thirdPartyIframes:      objects(raw.thirdPartyIframes, frame),
    hiddenIframes:          objects(raw.hiddenIframes, frame),
    thirdPartyImages:       strings(raw.thirdPartyImages),
    thirdPartyDomains:      strings(raw.thirdPartyDomains),
    trackingResources:      strings(raw.trackingResources),
    adResources:            strings(raw.adResources),
    analyticsResources:     strings(raw.analyticsResources),
    hasPasswordField:       raw.hasPasswordField === true,
    hasCreditCard:          raw.hasCreditCard === true,
    externalFormActions:    strings(raw.externalFormActions),
    hasMetaCSP:             raw.hasMetaCSP === true,
    mixedContentIndicators: strings(raw.mixedContentIndicators),
    subdomainCount:         count(raw.subdomainCount),
    hasIPAddress:           raw.hasIPAddress === true,
    hasPunycode:            raw.hasPunycode === true,
    hasSuspiciousChars:     raw.hasSuspiciousChars === true,
    urlLength:              count(raw.urlLength),
    hasEncodedChars:        raw.hasEncodedChars === true,
    hasDownloadLinks:       raw.hasDownloadLinks === true,
    downloadLinks:          objects(raw.downloadLinks, d => ({
      host:      optString(d.host),
      protocol:  optString(d.protocol),
      sameSite:  d.sameSite === true,
      isIP:      d.isIP === true,
      doubleExt: d.doubleExt === true
    })),
    passwordForms:          objects(raw.passwordForms, f => ({
      method:         isString(f.method) ? f.method : 'get',
      actionProtocol: optString(f.actionProtocol),
      actionExternal: f.actionExternal === true
    })),
    thirdPartyNoSRI:        count(raw.thirdPartyNoSRI),
    sessionIdInUrl:         raw.sessionIdInUrl === true
  };
}

// =====================
// MESSAGE HANDLER
// =====================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') return;

  if (message.type === 'PAGE_DATA_COLLECTED') {
    if (!isOwnContentScript(sender)) return;
    const pageData = normalizePageData(message.data, sender);
    if (!pageData) { sendResponse({ status: 'invalid' }); return; }
    analyzeAndScore(sender.tab.id, pageData);
    sendResponse({ status: 'received' });
    return;
  }

  if (!isExtensionPage(sender) || !Number.isInteger(message.tabId)) return;
  const tabId = message.tabId;

  if (message.type === 'GET_SCAN_RESULT') {
    const state = getScanState(tabId);
    // Scan state is in memory and lost when the service worker is stopped;
    // start a new scan so the caller's next poll finds a result.
    if (!state) {
      chrome.tabs.get(tabId)
        .then(tab => { if (!getScanState(tabId)) triggerAnalysis(tabId, tab.url); })
        .catch(() => {});
    }
    sendResponse({ result: state });
    return;
  }

  if (message.type === 'RESCAN') {
    // Use the tab's real URL rather than one supplied in the message
    chrome.tabs.get(tabId)
      .then(tab => triggerAnalysis(tabId, tab.url))
      .catch(err => console.warn('WebGuard: rescan failed:', err.message));
    sendResponse({ status: 'rescanning' });
    return;
  }
});

// =====================
// ANALYSIS COORDINATOR
// =====================
async function analyzeAndScore(tabId, pageData) {
  try {
    pageData.responseHeaders = await getHeadersForPage(tabId, pageData.url);
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
    setScanState(tabId, { status: 'error', url: pageData.url, error: err.message });
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS['default'] });
  }
}
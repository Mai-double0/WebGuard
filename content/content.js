// content/content.js
// Injected into every page. Collects observable page data and sends it
// to the background service worker for analysis.
// Runs at document_idle (after page has loaded).

(function () {
  // Prevent double-injection
  if (window.__webguardInjected) return;
  window.__webguardInjected = true;

  // =====================
  // HELPERS
  // =====================

  function getHostname(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return null;
    }
  }

  function getProtocol(url) {
    try {
      return new URL(url).protocol;
    } catch {
      return null;
    }
  }

  function isThirdParty(resourceUrl, pageHostname) {
    const host = getHostname(resourceUrl);
    if (!host) return false;
    // Strip www. for comparison
    const clean = (h) => h.replace(/^www\./, '');
    return clean(host) !== clean(pageHostname);
  }

  // =====================
  // PAGE BASICS
  // =====================

  const pageUrl  = window.location.href;
  const domain   = window.location.hostname;
  const protocol = window.location.protocol;
  const pageHost = domain.replace(/^www\./, '');

  // =====================
  // SCRIPTS
  // =====================

  const scripts = Array.from(document.querySelectorAll('script[src]'))
    .map(s => s.src)
    .filter(Boolean);

  const thirdPartyScripts = scripts.filter(s => isThirdParty(s, pageHost));

  // =====================
  // STYLESHEETS
  // =====================

  const stylesheets = Array.from(document.querySelectorAll('link[rel="stylesheet"][href]'))
    .map(l => l.href)
    .filter(Boolean);

  // =====================
  // IFRAMES
  // =====================

  const iframes = Array.from(document.querySelectorAll('iframe'))
    .map(f => ({
      src:      f.src      || null,
      sandbox:  f.sandbox  ? f.sandbox.value : null,
      hidden:   f.offsetWidth === 0 || f.offsetHeight === 0
    }));

  const thirdPartyIframes = iframes.filter(f => f.src && isThirdParty(f.src, pageHost));
  const hiddenIframes      = iframes.filter(f => f.hidden);

  // =====================
  // IMAGES
  // =====================

  const images = Array.from(document.querySelectorAll('img[src]'))
    .map(i => i.src)
    .filter(Boolean);

  const thirdPartyImages = images.filter(i => isThirdParty(i, pageHost));

  // =====================
  // LINKS & EXTERNAL DOMAINS
  // =====================

  const links = Array.from(document.querySelectorAll('a[href]'))
    .map(a => a.href)
    .filter(Boolean);

  const externalLinks = links.filter(l => isThirdParty(l, pageHost));

  // =====================
  // ALL THIRD-PARTY DOMAINS
  // =====================

  const allResources = [...scripts, ...stylesheets, ...images,
    ...iframes.map(f => f.src).filter(Boolean)];

  const thirdPartyDomains = [...new Set(
    allResources
      .filter(r => isThirdParty(r, pageHost))
      .map(r => getHostname(r))
      .filter(Boolean)
  )];

  // =====================
  // TRACKER DETECTION
  // (keyword-based heuristic)
  // =====================

  const TRACKER_KEYWORDS = [
    'google-analytics', 'googletagmanager', 'doubleclick',
    'facebook.net', 'connect.facebook', 'analytics',
    'hotjar', 'mixpanel', 'segment.com', 'amplitude',
    'adroll', 'criteo', 'taboola', 'outbrain',
    'scorecardresearch', 'quantserve', 'chartbeat',
    'newrelic', 'clarity.ms', 'mouseflow', 'fullstory',
    'intercom', 'hubspot', 'marketo', 'pardot',
    'tiktok', 'twitter', 'linkedin', 'pinterest',
    'snapchat', 'amazon-adsystem', 'adsystem'
  ];

  const AD_KEYWORDS = [
    'doubleclick', 'googlesyndication', 'adnxs', 'adroll',
    'criteo', 'taboola', 'outbrain', 'amazon-adsystem',
    'adsystem', 'adtech', 'advertising', 'ads.', '.ads'
  ];

  const ANALYTICS_KEYWORDS = [
    'google-analytics', 'googletagmanager', 'analytics',
    'hotjar', 'mixpanel', 'segment', 'amplitude',
    'chartbeat', 'newrelic', 'clarity.ms'
  ];

  function matchesKeywords(url, keywords) {
    const lower = url.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }

  const trackingResources  = allResources.filter(r => matchesKeywords(r, TRACKER_KEYWORDS));
  const adResources        = allResources.filter(r => matchesKeywords(r, AD_KEYWORDS));
  const analyticsResources = allResources.filter(r => matchesKeywords(r, ANALYTICS_KEYWORDS));

  // =====================
  // FORMS & SENSITIVE FIELDS
  // =====================

  const forms = Array.from(document.querySelectorAll('form'));

  const hasPasswordField = document.querySelector('input[type="password"]') !== null;
  const hasEmailField    = document.querySelector('input[type="email"]')    !== null;
  const hasCreditCard    = Array.from(document.querySelectorAll('input'))
    .some(i => /card|credit|cvv|cvc|expir/i.test(i.name + i.id + i.placeholder));

  const formActions = forms.map(f => f.action).filter(Boolean);
  const externalFormActions = formActions.filter(a => isThirdParty(a, pageHost));

  // =====================
  // META TAGS
  // =====================

  const metaTags = {};
  document.querySelectorAll('meta').forEach(m => {
    const name = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv');
    const content = m.getAttribute('content');
    if (name && content) metaTags[name.toLowerCase()] = content;
  });

  // CSP via meta tag
  const hasMetaCSP = !!document.querySelector(
    'meta[http-equiv="Content-Security-Policy"]'
  );

  // =====================
  // MIXED CONTENT INDICATORS
  // =====================

  const mixedContentIndicators = (protocol === 'https:')
    ? allResources.filter(r => r.startsWith('http://'))
    : [];

  // =====================
  // URL / DOMAIN ANALYSIS
  // =====================

  const subdomainCount = domain.split('.').length - 2;

  const hasIPAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);

  // Punycode / IDN indicator
  const hasPunycode = domain.includes('xn--');

  // Suspicious characters in domain
  const hasSuspiciousChars = /[^a-z0-9\-.]/.test(domain);

  // Excessive URL length
  const urlLength = pageUrl.length;

  // URL contains encoded characters
  const hasEncodedChars = pageUrl.includes('%') && pageUrl.includes('%20') === false;

  // =====================
  // PAGE BEHAVIOR
  // =====================

  // Executable download links — collect details so the analyzer can judge context
  const EXEC_EXT = /\.(exe|msi|dmg|pkg|bat|cmd|sh|scr|jar|apk|ps1|vbs)(\?|#|$)/i;
  const DOUBLE_EXT = /\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(exe|scr|bat|cmd|js|vbs)(\?|#|$)/i;

  const downloadLinks = Array.from(document.querySelectorAll('a[href]'))
    .map(a => a.href)
    .filter(href => EXEC_EXT.test(href))
    .slice(0, 30)
    .map(href => {
      let host = null, proto = null;
      try { const u = new URL(href); host = u.hostname; proto = u.protocol; } catch {}
      return {
        host,
        protocol: proto,
        sameSite:  host ? !isThirdParty(href, pageHost) : false,
        isIP:      host ? /^(\d{1,3}\.){3}\d{1,3}$/.test(host) : false,
        doubleExt: DOUBLE_EXT.test(href)
      };
    });

  const hasDownloadLinks = downloadLinks.length > 0;

  // Check for pop-up / redirect scripts (heuristic: onbeforeunload)
  const hasBeforeUnload = typeof window.onbeforeunload === 'function';

  // =====================
  // ASSEMBLE PAYLOAD
  // =====================

  const pageData = {
    // Basics
    url:      pageUrl,
    domain,
    protocol,

    // Scripts
    scripts,
    thirdPartyScripts,

    // Stylesheets
    stylesheets,

    // Iframes
    iframes,
    thirdPartyIframes,
    hiddenIframes,

    // Images
    thirdPartyImages,

    // Domains
    thirdPartyDomains,

    // Trackers
    trackingResources,
    adResources,
    analyticsResources,

    // Forms
    hasPasswordField,
    hasEmailField,
    hasCreditCard,
    externalFormActions,
    formCount: forms.length,

    // Meta
    metaTags,
    hasMetaCSP,

    // Mixed content
    mixedContentIndicators,

    // URL analysis
    subdomainCount,
    hasIPAddress,
    hasPunycode,
    hasSuspiciousChars,
    urlLength,
    hasEncodedChars,

    // Behavior
    hasDownloadLinks,
    downloadLinks,
    hasBeforeUnload,

    // Links
    externalLinks: externalLinks.slice(0, 50), // cap to avoid huge payloads

    // Timestamp
    collectedAt: Date.now()
  };

  // =====================
  // SEND TO SERVICE WORKER
  // =====================

  chrome.runtime.sendMessage({
    type: 'PAGE_DATA_COLLECTED',
    data: pageData
  }, (response) => {
    if (chrome.runtime.lastError) {
      // Extension context may have reloaded — safe to ignore
      console.warn('WebGuard content script:', chrome.runtime.lastError.message);
    }
  });

})();
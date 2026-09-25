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

  // A form exposes its named controls as properties, so <input name="action">
  // or <input name="method"> replaces form.action / form.method, and can even
  // replace form.getAttribute. Read forms through the Element prototype.
  const formAttr = (f, name) => Element.prototype.getAttribute.call(f, name);
  const formHas  = (f, selector) => Element.prototype.querySelector.call(f, selector) !== null;

  // Same result as form.action: the document URL when the attribute is empty
  function formAction(f) {
    const attr = formAttr(f, 'action');
    if (!attr) return pageUrl;
    try { return new URL(attr, document.baseURI).href; } catch { return pageUrl; }
  }

  // Same result as form.method: invalid or missing values mean GET
  function formMethod(f) {
    const m = (formAttr(f, 'method') || '').toLowerCase();
    return m === 'post' || m === 'dialog' ? m : 'get';
  }

  const hasPasswordField = document.querySelector('input[type="password"]') !== null;
  const hasCreditCard    = Array.from(document.querySelectorAll('input'))
    .some(i => /card|credit|cvv|cvc|expir/i.test(i.name + i.id + i.placeholder));

  const formActions = forms.map(formAction);
  const externalFormActions = formActions.filter(a => isThirdParty(a, pageHost));

  // =====================
  // CSP VIA META TAG
  // =====================

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

  // =====================
  // DEEP CHECK DATA (passive)
  // =====================

  // Forms containing a password field: how and where do they submit?
  const passwordForms = forms
    .filter(f => formHas(f, 'input[type="password"]'))
    .map(f => ({
      method:         formMethod(f),
      actionProtocol: getProtocol(formAction(f)),
      actionExternal: isThirdParty(formAction(f), pageHost)
    }));

  // Third-party scripts loaded without Subresource Integrity
  const thirdPartyNoSRI = Array.from(document.querySelectorAll('script[src]'))
    .filter(s => isThirdParty(s.src, pageHost) && !s.integrity)
    .length;

  // Session identifiers exposed in the page URL or same-site links
  const SESSION_IN_URL = /[;?&](jsessionid|phpsessid|sessionid|session_id|sid)=/i;
  const sessionIdInUrl =
    SESSION_IN_URL.test(pageUrl) ||
    links.some(l => !isThirdParty(l, pageHost) && SESSION_IN_URL.test(l));


  // =====================
  // ASSEMBLE PAYLOAD
  // Only what the analyzers use. Meta tag contents, link lists and other
  // page text are not collected (meta tags often hold CSRF tokens).
  // =====================

  const pageData = {
    // Basics
    url:      pageUrl,
    domain,
    protocol,

    // Scripts
    scripts,
    thirdPartyScripts,

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
    hasCreditCard,
    externalFormActions,

    // CSP
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

    // Deep checks
    passwordForms,
    thirdPartyNoSRI,
    sessionIdInUrl
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
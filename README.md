# 🛡️ WebGuard — Explainable Website Security & Privacy Auditor

A browser extension that gives an **explainable security and privacy risk assessment** of the website you are currently visiting, and tells you **whether to trust it with sensitive data, and why**.

![Chrome](https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![JavaScript](https://img.shields.io/badge/JavaScript-ES%20Modules-F7DF1E?logo=javascript&logoColor=black)

---

## 🔍 Why WebGuard?

Browser protection such as Chrome Safe Browsing answers:
> *"Is this website known to be dangerous?"*

WebGuard answers a different question:
> *"What security and privacy weaknesses does this page actually have, and should I trust it with my password or card?"*

It does not replace Safe Browsing or antivirus software. It adds an explainable layer on top: every point deducted, every cap applied, and every verdict comes with a plain-language reason.

---

## ✨ Features

### Trust verdict
A clear answer next to the score, with up to two reasons. The first rule that matches wins:

| Verdict | When it appears |
|---|---|
| ⛔ **Do not enter passwords or payment details** | At least one *blocker* was found (see below) |
| ⚠ **Use with caution** | No blocker, but a *caution* finding exists (see below); or Security is below 75% of its maximum (hardening gaps); or the overall score is below 75 |
| ⚠ **Not fully checked** | No blocker or caution, but some checks could not run: response headers were not captured, or the site blocked content-script access. Reload the page for a full verdict |
| ✓ **No blocking issues found** | None of the above. Never presented as a guarantee of safety |

**Blockers** (⛔):
- A certificate error was recorded for the site
- A login form sends the password with `GET`
- An HTTPS page has a login form that submits to `http://`
- A password field on an HTTP page
- A password field on a page where a form submits to another domain
- An executable download that is unencrypted, hosted on an IP address, or has a disguised double extension (e.g. `.pdf.exe`)
- A password field together with another phishing indicator (IP-address host, punycode domain, 3+ subdomains, non-HTTPS page, or a form posting to another domain)

**Cautions** (⚠):
- No HTTPS, mixed content, or a site accessed by IP address
- A form that submits to another domain (without a password field)
- A login page without HSTS (when headers were captured)
- A known-vulnerable JavaScript library
- A session ID in URLs
- A well-known session cookie missing `HttpOnly` or `Secure`, or a "maybe" session cookie missing one on a page with a login form

### Deep checks
Passive checks for concrete weaknesses that browsers do not surface in their UI. WebGuard only reads what the page, its response headers, and the browser already expose; it sends no extra requests.

| Check | Why it matters | Penalty |
|---|---|---|
| Certificate error (see below) | The site's identity could not be verified; the connection could be intercepted | −15, blocker |
| Login form submitted via `GET` | Password ends up in history, logs, and Referer headers | −5, blocker |
| Login form posting to `http://` from an HTTPS page | Password sent unencrypted | −6, blocker |
| Login page on HTTPS without HSTS | An attacker on an untrusted network could strip HTTPS | caution only |
| Known-vulnerable libraries, read from the script URL: jQuery < 3.5.0, Bootstrap < 3.4.1 (or 4.x < 4.3.1), any AngularJS 1.x, Lodash < 4.17.21 | Public CVEs, or end-of-life with no security fixes | −3 each, max −6, caution |
| Session IDs in the page URL or same-site links (`jsessionid`, `phpsessid`, `sessionid`, `session_id`, `sid`) | Session hijacking through leaked links | −3, caution |
| CSP that allows `'unsafe-inline'` scripts (with no nonce, hash, or `'strict-dynamic'`) | Removes most of the CSP's protection against XSS | −1 |
| HSTS `max-age` under 180 days; third-party scripts without Subresource Integrity | Weaker than recommended | informational, not scored |

The standard header checks (on pages where headers were captured) are: missing Content-Security-Policy (−3, a `<meta>` CSP counts), missing HSTS on HTTPS (−2), no clickjacking protection from `X-Frame-Options` or CSP `frame-ancestors` (−2), missing `nosniff` (−1), and a version number in the `Server` or `X-Powered-By` header (−1). A missing `Referrer-Policy` is informational. If headers were not captured, these are reported as "not available" and not scored.

### Certificate-error capture
Chrome does not expose certificate details to extensions. Instead, WebGuard listens for failed main-frame requests and records errors whose code starts with `ERR_CERT_` or `ERR_SSL_`, per hostname, in `chrome.storage.session`. If you then proceed past Chrome's warning page and WebGuard analyses that site, the error is reported as a blocker. WebGuard can therefore only flag a certificate problem it was running to see; it never inspects certificates itself.

### Session-cookie detection
Cookie names are matched strictly, so unrelated cookies (e.g. `SIDCC`, `_ga`, `csrf_token`, `activitySessionId`) are never treated as sessions.

| Class | Matches | Effect |
|---|---|---|
| **Known** | Exact names: `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`, `connect.sid`, `laravel_session`, `ci_session`, `sessionid`, `session_id`, `sid`; plus `ASPSESSIONID…` and any `*_session`. Case-insensitive; `__Host-` / `__Secure-` prefixes are ignored | Missing `HttpOnly` (any page) or `Secure` (HTTPS pages): −2 each, caution |
| **Maybe** | "session" as a whole word (`session`, `app-session-token`), or `auth_` / `access_` / `refresh_` / `login_` followed by `token` | Counts (−2 per missing flag, caution) **only when the page has a login form**. Otherwise informational and not scored |
| Neither | Everything else | Ignored |

Cookie **values are never stored**: Set-Cookie headers are reduced to the name, the `Secure` flag, and the `HttpOnly` flag at capture.

### Four analysis engines
- 🔐 **Security**: HTTPS, mixed content, response headers, cookie flags, forms, downloads, hidden iframes, IP-address hosts, deep checks
- 🕵️ **Privacy**: third-party domains, trackers, advertising and analytics resources, third-party iframes, payment fields
- 🎣 **Phishing**: IP-address hosts, punycode, suspicious characters, excessive subdomains, very long or encoded URLs, login forms combined with other indicators
- 🌐 **Resources**: third-party scripts, total scripts, iframes, third-party images, mixed content

Tracker, ad, and analytics detection is a keyword match on resource URLs.

### Explainability
- Every finding is labelled as positive, informational, warning, or danger
- The full dashboard explains each finding in plain language and gives recommendations
- Score caps are listed as findings, so the user always sees **why** a score was limited

---

## 📊 How scoring works

**1. Category scores.** Each analyzer starts at its maximum and deducts points only for real risk signals. The overall score is the sum of each category's share of its weight (each rounded to a whole number):

| Category | Shown as | Weight in overall score |
|---|---|---|
| Security | /25 | 35 |
| Privacy | /30 | 25 |
| Phishing | /25 | 25 |
| Resources | /20 | 15 |

**2. Context over presence.** An observation alone is informational. A download link, a login form, or a CDN script costs nothing by itself. Points are deducted only when it appears together with a real risk signal:

| Observation | Alone | With a risk signal |
|---|---|---|
| Executable download | Same site over HTTPS: free. Another domain: −1 | Unencrypted, IP-address host, or double extension: −6, blocker |
| Form submitting to another domain | −2, caution | Page also has a password field: −6, blocker |
| Password field | Informational | On an HTTP page: −8, blocker. With other phishing indicators: −8, blocker |
| "Maybe" session cookie missing a flag | Informational | Page has a login form: −2 per flag, caution |
| Hidden third-party iframes | Informational | More than 2: −2 |
| Missing security headers | Not scored if headers were not captured | Scored only when headers were captured |
| Referrer-Policy, SRI, short HSTS | Informational | Never scored |

**3. Transparent caps.** Missing evidence never produces a "perfect" score. Caps apply in this order, each only if the score is above it:

| Cap | Limit | Reason |
|---|---|---|
| Ceiling | 95 | Passive analysis can't rule out server-side flaws |
| Coverage | 85 | Some checks could not run (headers not captured, or page content could not be inspected) |
| Blocker | 49 | A serious issue makes the page unsafe for sensitive data |
| Weakest link | 49 / 74 | Security or Phishing below 40% of its maximum caps the score at 49; below 60%, at 74. Strong Privacy or Resources scores can't average it away |

**4. Risk levels.** Higher score = lower observed risk:

| Score | Level |
|---|---|
| 90–100 | 🟢 Very Low Risk |
| 75–89 | 🟢 Low Risk |
| 50–74 | 🟡 Moderate Risk |
| 25–49 | 🟠 High Risk |
| 0–24 | 🔴 Critical Risk |

The score is a **risk assessment**, never a "percentage safe".

---

## 🎨 User interface

- **Dashboard** with pill-shaped tabs (Overview, Security, Privacy, Phishing, Resources, Advice). The tabs follow the ARIA tab pattern: ← / → move between tabs (wrapping around), Home / End jump to the first or last, and only the selected tab is in the Tab order.
- **CursorGrid background.** A canvas behind the dashboard shows a faint grid. Lines near the pointer light up in the accent colour and fade, and a click sends a ring across the grid. It is decorative, never blocks clicks or text selection, only animates while something is lit, and pauses while the tab is hidden. Inspired by React Bits' CursorGrid.
- **Palette.** Warm stone with an orchid accent, defined once in `styles/tokens.css` and shared by the popup and dashboard. Text and colour pairs are chosen to meet WCAG AA (4.5:1): for example body text 16.7:1, muted text 6.2–7.7:1, accent text 7.0–7.6:1, risk badges 4.7–5.2:1. The grid's brightness is capped so muted and accent text stay above 4.5:1 even on its brightest pixel.
- **Popup.** A fixed 360px panel with the score, verdict, four category bars, and the top four findings ("+N more in full analysis"). The footer buttons (View Full Analysis, Rescan) stay pinned at the bottom; only the findings list scrolls. While a scan runs, grey loading skeletons stand in for the score, verdict, categories, and findings, and a screen-reader status announces the scan and its result.
- **`prefers-reduced-motion`.** The popup turns off all animations and transitions, the dashboard turns off the tab-pill transitions and the rescan spinner, and CursorGrid draws only the static grid, with no pointer tracking.

---

## 🧪 Test results

| Site | Score | Verdict | Main finding |
|---|---|---|---|
| demo.testfire.net (intentionally vulnerable demo bank) | 49 High | ⛔ Do not enter sensitive data | Certificate error (`ERR_CERT_AUTHORITY_INVALID`) bypassed; CSP, HSTS, clickjacking protection missing |
| github.com | 93 Very Low | ✓ No blocking issues | Strong security headers; third-party scripts without SRI (informational) |

---

## 🏗️ Architecture

```
Content script (DOM data) ─┐
Response headers ──────────┼─► Service worker ─► Security / Privacy / Phishing / Resources analyzers
Certificate errors ────────┘                                   │
                                                               ▼
                                             Risk engine (weights, caps, verdict)
                                                               │
                                                               ▼
                                   Explanation engine ─► Popup + Dashboard + Toolbar badge
```

```
webguard/
├── manifest.json               # Chrome MV3 manifest
├── package.json                # Test script only: no dependencies, ignored by Chrome
├── LICENSE                     # MIT
├── background/
│   └── service-worker.js       # Tab events, header + certificate-error capture, badge, messaging
├── content/
│   └── content.js              # Passive DOM data collection
├── analyzers/
│   ├── security.js             # HTTPS, headers, cookies (incl. session-cookie rules), forms, downloads
│   ├── deep-checks.js          # Certificate errors, vulnerable libraries, login-form flaws, session leaks
│   ├── privacy.js              # Third parties, trackers, ads, analytics
│   ├── phishing.js             # URL and login-form phishing indicators
│   └── resources.js            # Scripts, iframes, resource complexity
├── scoring/
│   └── risk-engine.js          # Weighted score, caps, trust verdict
├── explanation/
│   └── explanation-engine.js   # Plain-language explanations and recommendations
├── popup/                      # Toolbar popup UI (html, css, js)
├── dashboard/
│   ├── dashboard.html/.css/.js # Full analysis page with pill tabs
│   └── cursor-grid.js          # CursorGrid canvas background
├── styles/
│   └── tokens.css              # Shared colour tokens (palette)
├── tests/
│   └── session-cookies.test.mjs  # Dependency-free tests for session-cookie detection
├── storage/
│   └── storage.js              # Local scan-history module (not yet wired in)
├── utils/
│   └── helpers.js              # Shared risk-level, colour, URL, and DOM helpers
└── icons/                      # Icon PNGs, plus generate-icons.js (dev-only: needs the `canvas` package, and must be a .cjs file to run under the root package.json)
```

---

## 🚀 Installation (developer mode)

1. Clone the repository:
```bash
   git clone https://github.com/Mai-double0/WebGuard.git
```
2. Open `chrome://extensions` and enable **Developer mode**
3. Click **Load unpacked** and select the `WebGuard` folder
4. Pin WebGuard from the extensions menu (🧩)
5. Visit any website and click the WebGuard icon

Tested on Google Chrome. Microsoft Edge (Chromium) should work with the same build; Firefox support is planned.

---

## 🧪 Running the tests

The tests are plain Node scripts. They use only built-in Node modules and were tested on Node 22; there is nothing to install.

```bash
npm test
# or, without npm:
node tests/session-cookies.test.mjs
```

The tests currently cover session-cookie detection (known vs. "maybe" names, the login-form rule, and that cookie values are never read).

The root `package.json` exists only to run the tests and let Node load the extension's ES modules. It has no dependencies, and Chrome ignores it.

---

## 🔒 Privacy & security of WebGuard itself

- **All analysis is local.** No browsing data is sent to any server, and the code contains no network calls.
- **Passive only.** WebGuard never sends extra requests to, or probes, the sites you visit. It observes response headers and never modifies or blocks requests.
- **Cookie values are never stored.** Set-Cookie headers are reduced to the cookie name and its `Secure` / `HttpOnly` flags at capture.
- **Minimal data.** Only the seven security headers the analyzers read are kept, with the response origin instead of its full URL. The content script sends counts, flags, resource URLs, and the page URL. It does not send form values, meta-tag contents, or link lists.
- **Short-lived storage.** Captured headers, certificate errors, and the scan result the popup hands to the dashboard live in `chrome.storage.session`, which is cleared when the browser closes. Headers and the dashboard's copy of the result are also removed when the tab closes. Certificate-error records are kept per hostname until the browser closes. Nothing is written to persistent storage.
- Strict Content Security Policy on all extension pages, with no inline scripts or styles and no `eval()`. No extension page is web-accessible, so websites cannot frame or detect the dashboard.
- Dynamic text is rendered only with `textContent` and DOM APIs; the UI never uses `innerHTML`.
- Messages from content scripts are treated as untrusted: the service worker checks the sender and rebuilds the page data with the expected types. Only extension pages can read results or trigger a rescan.

---

## ⚠️ Known limitations

- **Server-side vulnerabilities** (SQL injection, reflected XSS, broken access control) cannot be detected. They require active testing, which WebGuard deliberately does not perform on other people's servers.
- **Certificate details are not exposed to Chrome extensions.** WebGuard can only flag a certificate problem when Chrome shows its warning page while WebGuard is running. A recorded error is not cleared until the browser closes, so a site whose certificate is later fixed stays flagged for the rest of that session.
- **Headers are only captured on a full page load.** Pages opened before WebGuard started, or restored from cache, show "not available" and a "Not fully checked" verdict until reloaded.
- **Only the top-level page is analysed**, as a snapshot taken after load. The contents of iframes, and resources added later, are not inspected until a rescan.
- **Library detection** relies on the version appearing in the script URL; bundled or renamed libraries are not detected.
- **Tracker, ad, and analytics detection** is a URL keyword match, so it can miss unlisted services and occasionally flag unrelated ones.
- Some sites block content-script access; WebGuard then falls back to a limited URL-and-header analysis, caps the score at 85, and shows a "Limited analysis" note in the popup.
- The assessment is **heuristic**: it helps users judge risk, but it is not proof that a site is safe or malicious.

---

## 🛠️ Built with

HTML, CSS, JavaScript (ES modules) · Chrome Extension Manifest V3 · `chrome.scripting`, `chrome.webRequest`, `chrome.webNavigation`, `chrome.storage`

---

## 📄 License

MIT. See [LICENSE](LICENSE).

---

## 👨‍💻 Author

**Mai Tun Lin Ko**
BSc (Hons) Cyber Security, Asia Pacific University of Technology & Innovation (APU)

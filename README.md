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
A clear answer next to the score:
- ⛔ **Do not enter passwords or payment details**: a concrete, serious issue was found
- ⚠ **Use with caution**: weaknesses were found, or not every check could run
- ✓ **No blocking issues found**: nothing observed suggests avoiding the page (never presented as a guarantee)

### Flaws browsers don't show you
Passive checks for concrete weaknesses that browsers do not surface in their UI:

| Check | Why it matters |
|---|---|
| Certificate errors the user bypassed | The site's identity could not be verified; the connection could be intercepted |
| Known-vulnerable JS libraries (jQuery, Bootstrap, AngularJS, Lodash) | Public CVEs with known exploits |
| Login form submitted via `GET` | Password ends up in history, logs, and Referer headers |
| Login form posting to `http://` from an HTTPS page | Password sent unencrypted |
| Session IDs in URLs (`;jsessionid=`) | Session hijacking through leaked links |
| Session cookies without `HttpOnly` / `Secure` | Session theft via XSS or plain HTTP |
| Missing / weak security headers (CSP, HSTS, X-Frame-Options, nosniff) | Reduced protection against XSS, clickjacking, and downgrade attacks |
| Server version disclosure | Makes known-vulnerability lookup easier |

### Four analysis engines
- 🔐 **Security**: HTTPS, mixed content, response headers, cookie flags, forms, downloads, deep checks
- 🕵️ **Privacy**: third-party domains, trackers, advertising and analytics resources
- 🎣 **Phishing**: IP-address hosts, punycode, excessive subdomains, login forms combined with other indicators
- 🌐 **Resources**: third-party scripts, iframes, overall page complexity

### Explainability
- Every finding is labelled as positive, informational, warning, or danger
- The full dashboard explains each finding in plain language and gives recommendations
- Score caps are listed as findings, so the user always sees **why** a score was limited

---

## 📊 How scoring works

**1. Category scores.** Each analyzer starts at its maximum and deducts points only for real risk signals:

| Category | Shown as | Weight in overall score |
|---|---|---|
| Security | /25 | 35 |
| Privacy | /30 | 25 |
| Phishing | /25 | 25 |
| Resources | /20 | 15 |

**2. Context over presence.** An observation alone is informational. A download link, a login form, or a CDN script costs nothing by itself. Points are deducted only when it appears together with a real risk signal (e.g. a login form on HTTP, a download from an IP address, a disguised `.pdf.exe`).

**3. Transparent caps.** Missing evidence never produces a "perfect" score:

| Cap | Limit | Reason |
|---|---|---|
| Ceiling | 95 | Passive analysis can't rule out server-side flaws |
| Coverage | 85 | Some checks could not run (e.g. headers not captured) |
| Blocker | 49 | A serious issue makes the page unsafe for sensitive data |
| Weakest link | 74 / 49 | A weak Security or Phishing score can't be averaged away by strong Privacy |

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
├── background/
│   └── service-worker.js       # Tab events, header + certificate-error capture, badge, messaging
├── content/
│   └── content.js              # Passive DOM data collection
├── analyzers/
│   ├── security.js             # HTTPS, headers, cookies, forms, downloads
│   ├── deep-checks.js          # Certificate errors, vulnerable libraries, login-form flaws, session leaks
│   ├── privacy.js              # Third parties, trackers, ads, analytics
│   ├── phishing.js             # URL and login-form phishing indicators
│   └── resources.js            # Scripts, iframes, resource complexity
├── scoring/
│   └── risk-engine.js          # Weighted score, caps, trust verdict
├── explanation/
│   └── explanation-engine.js   # Plain-language explanations and recommendations
├── popup/                      # Toolbar popup UI
├── dashboard/                  # Full analysis page
├── storage/
│   └── storage.js              # Local scan-history module (not yet wired in)
├── utils/
│   └── helpers.js              # Shared risk-level, colour, URL, and DOM helpers
└── icons/
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

## 🔒 Privacy & security of WebGuard itself

- **All analysis is local.** No browsing data is sent to any server.
- **Cookie values are never stored.** Set-Cookie headers are reduced to the cookie name and its `Secure` / `HttpOnly` flags at capture.
- **Minimal data.** Only the seven security headers the analyzers read are kept, with the response origin instead of its full URL. The content script sends counts, flags, and resource URLs. It never reads form values, meta-tag contents, or link lists.
- Captured headers and certificate errors live in `chrome.storage.session`, which is cleared when the browser closes. Per-tab data is removed when the tab closes.
- **Passive only.** WebGuard never sends extra requests to, or probes, the sites you visit.
- Strict Content Security Policy on all extension pages, with no inline scripts and no `eval()`. No extension page is web-accessible, so websites cannot frame or detect the dashboard.
- Dynamic text is rendered only with `textContent`; the UI never uses `innerHTML`.
- Messages from content scripts are treated as untrusted: the service worker checks the sender and rebuilds the page data with the expected types. Only extension pages can read results or trigger a rescan.

---

## ⚠️ Known limitations

- **Server-side vulnerabilities** (SQL injection, reflected XSS, broken access control) cannot be detected. They require active testing, which WebGuard deliberately does not perform on other people's servers.
- **Certificate details are not exposed to Chrome extensions.** WebGuard can only flag a certificate problem when Chrome shows its warning page while WebGuard is running. Errors are remembered per site for the current browser session only.
- **Headers are only captured on a full page load.** Pages opened before WebGuard started, or restored from cache, show "not available" until reloaded.
- **Library detection** relies on the version appearing in the script URL; bundled or renamed libraries are not detected.
- Some sites block content-script access; WebGuard then falls back to a limited URL-and-header analysis and says so.
- The assessment is **heuristic**: it helps users judge risk, but it is not proof that a site is safe or malicious.

---

## 🛠️ Built with

HTML, CSS, JavaScript (ES modules) · Chrome Extension Manifest V3 · `chrome.scripting`, `chrome.webRequest`, `chrome.webNavigation`, `chrome.storage`

---

## 👨‍💻 Author

**Mai Tun Lin Ko**
BSc (Hons) Cyber Security, Asia Pacific University of Technology & Innovation (APU)
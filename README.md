# 🛡️ WebGuard — Explainable Website Security & Privacy Auditor

A cross-browser extension that provides an explainable security and privacy risk assessment of the currently visited website — going beyond conventional browser safety warnings.


---

## 🔍 What is WebGuard?

Chrome and other browsers tell you:
> *"Is this website known to be dangerous?"*

WebGuard answers a different question:
> *"What security and privacy indicators does this website have — and why should I be cautious?"*

WebGuard analyzes the active browser tab and provides an **understandable, explainable risk assessment** with real findings — not just a pass/fail verdict.

---

## ✨ Features

- 🔐 **Security Analysis** — HTTPS, mixed content, security headers, suspicious downloads, form security
- 🕵️ **Privacy Analysis** — third-party domains, trackers, advertising scripts, analytics services
- 🎣 **Phishing Analysis** — URL structure, suspicious domains, login forms, punycode detection
- 🌐 **Resource Analysis** — scripts, iframes, third-party resource complexity
- 📊 **Risk Scoring Engine** — transparent 0–100 score across 4 categories
- 💬 **Explanation Engine** — plain-language explanations for every finding
- 🏷️ **Toolbar Badge** — live risk indicator updated per tab
- 📋 **Full Dashboard** — tabbed analysis with findings, recommendations, and educational notes
- 🔒 **Privacy-First** — all analysis runs locally in the browser. No data is sent to external servers.

---

## 🎯 Risk Levels

| Score | Level |
|-------|-------|
| 90–100 | 🟢 Very Low Risk |
| 75–89 | 🟢 Low Risk |
| 50–74 | 🟡 Moderate Risk |
| 25–49 | 🟠 High Risk |
| 0–24 | 🔴 Critical Risk |

---

## 🏗️ Architecture

```
webguard/
├── manifest.json               # Chrome MV3 extension manifest
├── background/
│   └── service-worker.js       # Tab detection, badge updates, message hub
├── content/
│   └── content.js              # DOM data collection (injected into pages)
├── popup/
│   ├── popup.html              # Extension toolbar popup UI
│   ├── popup.css               # Popup styles
│   └── popup.js                # Popup logic and service worker communication
├── dashboard/
│   ├── dashboard.html          # Full analysis dashboard
│   ├── dashboard.css           # Dashboard styles
│   └── dashboard.js            # Dashboard logic and rendering
├── analyzers/
│   ├── security.js             # Security indicators engine
│   ├── privacy.js              # Privacy indicators engine
│   ├── phishing.js             # Phishing indicators engine
│   └── resources.js            # Resource/network analysis engine
├── scoring/
│   └── risk-engine.js          # Combines all analyzers into final score
├── explanation/
│   └── explanation-engine.js   # Generates plain-language explanations
├── storage/
│   └── storage.js              # Local scan history (chrome.storage.local)
├── utils/
│   └── helpers.js              # Shared utility functions
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## 🚀 Installation (Developer Mode)

1. Clone this repository:
```bash
   git clone https://github.com/Mai-double0/WebGuard.git
```

2. Open Chrome and navigate to `chrome://extensions`

3. Enable **Developer mode** (top right toggle)

4. Click **Load unpacked** and select the `WebGuard` folder

5. Pin WebGuard from the extensions menu (🧩)

6. Visit any website — WebGuard will automatically analyze it

---

## 🧪 How It Works

1. When you visit a page, the **content script** collects observable data from the DOM — scripts, iframes, forms, third-party resources, URL structure, and more.

2. The data is sent to the **background service worker**, which runs all four analysis engines.

3. Each engine returns a **score and list of findings**.

4. The **risk engine** combines all scores into a final 0–100 score.

5. The **explanation engine** generates plain-language descriptions for every finding.

6. Results are displayed in the **popup** (summary) and **dashboard** (full analysis).

For sites that block content script injection (e.g. claude.ai, WhatsApp Web), WebGuard performs a **URL-based fallback analysis** using only the page URL and domain.

---

## ⚠️ Important Disclaimer

WebGuard is a **heuristic risk assessment tool**. It:

- ✅ Analyzes observable security and privacy indicators
- ✅ Helps users understand potential risks
- ✅ Complements existing browser security features
- ❌ Does **not** replace antivirus software or browser Safe Browsing
- ❌ Does **not** definitively identify malicious websites
- ❌ Does **not** guarantee a website is safe

---

## 🔒 Security & Privacy

WebGuard follows its own security principles:

- Least privilege — only requests necessary browser permissions
- No `eval()` or unsafe dynamic code execution
- Strict Content Security Policy on all extension pages
- All analysis is local — no browsing data sent to external servers
- Input validation and output sanitization throughout

---

## 🛠️ Built With

- HTML, CSS, JavaScript (ES Modules)
- Chrome Extension Manifest V3
- WebExtension APIs (`chrome.scripting`, `chrome.storage`, `chrome.webNavigation`, `chrome.webRequest`)

---

## 👨‍💻 Author

**Mai Tun Lin Ko**  
BSc (Hons) Cyber Security  
Asia Pacific University of Technology & Innovation (APU)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
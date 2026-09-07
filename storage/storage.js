// storage/storage.js
// Handles local scan history using chrome.storage.local.
// Stores the last 50 scan results — no data leaves the browser.

const STORAGE_KEY = 'webguard_scan_history';
const MAX_HISTORY = 50;

// =====================
// SAVE A SCAN RESULT
// =====================

export async function saveScanResult(result) {
  try {
    const history = await getHistory();

    const entry = {
      domain:    result.domain,
      url:       result.url,
      score:     result.score,
      riskLevel: result.riskLevel,
      riskLabel: result.riskLabel,
      scannedAt: result.scannedAt || Date.now(),
      categories: result.categories
    };

    // Remove existing entry for same domain (keep most recent)
    const filtered = history.filter(h => h.domain !== entry.domain);

    // Add new entry at the front
    const updated = [entry, ...filtered].slice(0, MAX_HISTORY);

    await chrome.storage.local.set({ [STORAGE_KEY]: updated });
    return true;
  } catch (err) {
    console.warn('WebGuard storage: save failed', err);
    return false;
  }
}

// =====================
// GET FULL HISTORY
// =====================

export async function getHistory() {
  try {
    const data = await chrome.storage.local.get(STORAGE_KEY);
    return data[STORAGE_KEY] || [];
  } catch (err) {
    console.warn('WebGuard storage: read failed', err);
    return [];
  }
}

// =====================
// GET RESULT FOR DOMAIN
// =====================

export async function getResultForDomain(domain) {
  try {
    const history = await getHistory();
    return history.find(h => h.domain === domain) || null;
  } catch (err) {
    console.warn('WebGuard storage: domain lookup failed', err);
    return null;
  }
}

// =====================
// CLEAR ALL HISTORY
// =====================

export async function clearHistory() {
  try {
    await chrome.storage.local.remove(STORAGE_KEY);
    return true;
  } catch (err) {
    console.warn('WebGuard storage: clear failed', err);
    return false;
  }
}

// =====================
// GET STORAGE STATS
// =====================

export async function getStorageStats() {
  try {
    const history = await getHistory();
    return {
      totalScans:  history.length,
      maxScans:    MAX_HISTORY,
      oldestScan:  history.length ? history[history.length - 1].scannedAt : null,
      newestScan:  history.length ? history[0].scannedAt : null
    };
  } catch (err) {
    return { totalScans: 0, maxScans: MAX_HISTORY };
  }
}
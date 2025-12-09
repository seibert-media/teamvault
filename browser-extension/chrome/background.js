// TeamVault Chrome Extension - Background Service Worker (MV3)

// Storage keys
const SETTINGS_KEY = 'settings';
// settings: { baseUrl: string, autoSubmit: boolean, inlineAutofill: boolean, theme: 'auto'|'light'|'dark', preferPinned?: boolean, prewarmEnabled?: boolean, sitePrefs?: Record<string, {autoSubmit?: boolean, inlineAutofill?: boolean, pinnedHashid?: string, prewarm?: boolean}> }

// In-memory auth status cache (ephemeral)
let authOk = false;
let authCache = { ok: null, time: 0, error: null };
const CACHE_TTL = { auth: 300000, suggestions: 600000, search: 15000 };
const suggestionCache = new Map(); // key: host => { data, time }
const searchCache = new Map(); // key: term => { data, time }

// Helpers
const getOrigin = (url) => {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
};

async function getSettings() {
  const { [SETTINGS_KEY]: stored } = await chrome.storage.sync.get(SETTINGS_KEY);
  return stored || { baseUrl: '', autoSubmit: false, inlineAutofill: true, theme: 'auto', preferPinned: false, prewarmEnabled: false, sitePrefs: {}, allowHttpDev: false };
}

async function setSettings(next) {
  await chrome.storage.sync.set({ [SETTINGS_KEY]: next });
  return next;
}

async function ensureHostPermissionFor(baseUrl) {
  const origin = getOrigin(baseUrl);
  if (!origin) return false;
  try {
    const s = await getSettings();
    const u = new URL(origin);
    if (u.protocol === 'http:' && !s.allowHttpDev) {
      return false; // HTTP origin not allowed unless explicitly enabled
    }
  } catch {}
  const has = await chrome.permissions.contains({ origins: [origin + '/*'] });
  if (has) return true;
  try {
    const granted = await chrome.permissions.request({ origins: [origin + '/*'] });
    return granted;
  } catch {
    return false;
  }
}

function hostFromUrl(u) {
  try { return new URL(u).hostname.toLowerCase(); } catch { return ''; }
}

function normalizeHost(host) {
  return (host || '').toLowerCase();
}

function effectiveForUrl(settings, url) {
  const host = normalizeHost(hostFromUrl(url));
  const prefs = settings.sitePrefs || {};
  const site = prefs[host] || {};
  return {
    autoSubmit: site.autoSubmit ?? settings.autoSubmit ?? false,
    inlineAutofill: site.inlineAutofill ?? settings.inlineAutofill ?? true,
    pinnedHashid: site.pinnedHashid || null,
    prewarm: site.prewarm ?? settings.prewarmEnabled ?? false,
  };
}

// Security: path validation helpers for server-provided URLs
function assertMatch(re, path, code) {
  const p = String(path || '');
  if (!re.test(p)) {
    const err = new Error(code || 'DISALLOWED_PATH');
    err.path = p;
    throw err;
  }
}

async function apiFetch(path, init = {}) {
  const { baseUrl } = await getSettings();
  if (!baseUrl) throw new Error('BASE_URL_NOT_CONFIGURED');
  const ok = await ensureHostPermissionFor(baseUrl);
  if (!ok) throw new Error('HOST_PERMISSION_DENIED');
  const url = baseUrl.replace(/\/$/, '') + path;
  const res = await fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers: { 'Accept': 'application/json', ...(init.headers || {}) },
    ...init,
  });
  if (res.status === 401 || res.status === 403) {
    authOk = false;
    authCache = { ok: false, time: Date.now(), error: 'UNAUTHENTICATED' };
    throw new Error('UNAUTHENTICATED');
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`API_ERROR_${res.status}`);
    err.responseText = text;
    throw err;
  }
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) return res.json();
  return res.text();
}

async function withOriginTab(baseUrl) {
  const u = new URL(baseUrl);
  const base = `${u.protocol}//${u.host}${u.pathname.replace(/\/$/, '')}`;
  const pattern = base + '/*';
  let [tab] = await chrome.tabs.query({ url: [pattern] });
  if (!tab) {
    tab = await chrome.tabs.create({ url: base + '/', active: false });
  }
  return tab;
}

async function apiFetchViaPage(path, init = {}) {
  const { baseUrl } = await getSettings();
  if (!baseUrl) throw new Error('BASE_URL_NOT_CONFIGURED');
  const ok = await ensureHostPermissionFor(baseUrl);
  if (!ok) throw new Error('HOST_PERMISSION_DENIED');
  const tab = await withOriginTab(baseUrl);

  const args = { path, init, baseUrl };
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: async ({ path, init, baseUrl }) => {
      try {
        const url = new URL(path, baseUrl).toString();
        const res = await fetch(url, {
          method: init.method || 'GET',
          credentials: 'include',
          headers: { 'Accept': 'application/json', ...(init.headers || {}) },
          body: init.body,
        });
        const contentType = res.headers.get('content-type') || '';
        const status = res.status;
        if (!res.ok) {
          let text = '';
          try { text = await res.text(); } catch {}
          return { ok: false, status, error: 'API_ERROR_' + status, text };
        }
        if (contentType.includes('application/json')) {
          const json = await res.json();
          return { ok: true, status, json, contentType };
        }
        const text = await res.text();
        return { ok: true, status, text, contentType };
      } catch (e) {
        return { ok: false, error: e && e.message ? e.message : String(e) };
      }
    },
    args: [args],
    world: 'ISOLATED',
  });

  if (!result?.ok) {
    if (result?.error && /API_ERROR_(401|403)/.test(result.error)) {
      authOk = false;
      authCache = { ok: false, time: Date.now(), error: 'UNAUTHENTICATED' };
    }
    const err = new Error(result?.error || 'UNKNOWN_ERROR');
    err.responseText = result?.text;
    throw err;
  }
  if (result.contentType?.includes('application/json')) return result.json;
  return result.text;
}

async function apiFetchWithFallback(path, init = {}) {
  try {
    return await apiFetch(path, init);
  } catch (e) {
    // Retry via page context to bypass SameSite restrictions
    return await apiFetchViaPage(path, init);
  }
}

async function checkAuth(force = false) {
  const now = Date.now();
  if (!force && authCache.ok !== null && now - authCache.time < CACHE_TTL.auth) {
    authOk = !!authCache.ok;
    return { ok: authOk };
  }
  try {
    await apiFetchWithFallback('/api/secrets/?page=1');
    authOk = true;
    authCache = { ok: true, time: now, error: null };
    return { ok: true };
  } catch (e) {
    const msg = (e && e.message) ? e.message : '';
    const details = (e && e.responseText) ? String(e.responseText) : '';

    // If the API says "Authentication credentials were not provided.", user is not logged in
    const notProvided = /authentication credentials were not provided\./i.test(details);
    // Treat any other 403 as authenticated (user might just lack list permission)
    const is403 = /API_ERROR_403/.test(msg);
    const is401 = /API_ERROR_401/.test(msg);

    if (notProvided || is401) {
      authOk = false;
      authCache = { ok: false, time: now, error: 'UNAUTHENTICATED' };
      return { ok: false, error: 'UNAUTHENTICATED', details };
    }

    if (is403) {
      // Forbidden but authenticated (e.g., lacks permission to list secrets)
      authOk = true;
      authCache = { ok: true, time: now, error: null };
      return { ok: true };
    }

    // Unknown error – treat as unauthenticated failure
    authOk = false;
    authCache = { ok: false, time: now, error: msg };
    return { ok: false, error: msg, details };
  }
}

async function searchSecrets(term, page = 1) {
  const q = term ? `&search=${encodeURIComponent(term)}` : '';
  const key = (term || '').trim().toLowerCase();
  const now = Date.now();
  if (key && searchCache.has(key)) {
    const c = searchCache.get(key);
    if (now - c.time < CACHE_TTL.search) return c.data;
  }
  const data = await apiFetchWithFallback(`/api/secrets/?page=${page}${q}`);
  if (key) searchCache.set(key, { data, time: now });
  return data;
}

// Removed unused getSecretDetail helper (avoid unvalidated paths)

async function getRevisionDetail(revisionApiUrl) {
  const path = new URL(revisionApiUrl).pathname;
  // Only allow expected secret revision detail path
  assertMatch(/^\/api\/secret-revisions\/[^/]+\/?$/, path, 'DISALLOWED_REV_PATH');
  return apiFetchWithFallback(path);
}

async function getSecretPasswordBySecret(secret) {
  if (!secret.current_revision) throw new Error('NO_CURRENT_REVISION');
  const rev = await getRevisionDetail(secret.current_revision);
  if (!rev || !rev.data_url) throw new Error('NO_DATA_URL');
  const dataPath = new URL(rev.data_url).pathname;
  // Allow only data endpoints for the revision
  assertMatch(/^\/api\/secret-revisions\/[^/]+\/data(\/|$)/, dataPath, 'DISALLOWED_DATA_PATH');
  const data = await apiFetchWithFallback(dataPath);
  // For password content type, API returns { password: '...' }
  if (data && typeof data === 'object' && Object.prototype.hasOwnProperty.call(data, 'password')) {
    return data.password ?? '';
  }
  // For CC/file, ignore
  throw new Error('NO_PASSWORD_DATA');
}

async function getSecretOtpBySecret(secret) {
  if (!secret.current_revision) throw new Error('NO_CURRENT_REVISION');
  // Build /api/secret-revisions/<hashid>/data/otp from current_revision URL
  const revUrl = new URL(secret.current_revision);
  const otpUrl = revUrl.pathname.replace(/\/secret-revisions\/([^/]+)\/?$/, '/secret-revisions/$1/data/otp');
  // Validate OTP path
  assertMatch(/^\/api\/secret-revisions\/[^/]+\/data\/otp\/?$/, otpUrl, 'DISALLOWED_OTP_PATH');
  const code = await apiFetchWithFallback(otpUrl);
  if (typeof code === 'string') return code;
  return String(code);
}

async function getSecretByHashid(hashid) {
  if (!hashid) throw new Error('NO_HASHID');
  return apiFetchWithFallback(`/api/secrets/${encodeURIComponent(hashid)}/`);
}

async function getPasswordByHashid(hashid) {
  const secret = await getSecretByHashid(hashid);
  return getSecretPasswordBySecret(secret);
}

function urlHostname(u) {
  try { return new URL(u).hostname; } catch { return ''; }
}

function stripWww(host) {
  return (host || '').replace(/^www\./i, '');
}

function isReadable(val) {
  return Number(val) > 0;
}

function suggestionCacheKey(url) {
  const host = urlHostname(url);
  return host ? `host:${host.toLowerCase()}` : null;
}

async function getSuggestionsForUrl(pageUrl, limit = 25) {
  const host = urlHostname(pageUrl);
  if (!host) return { results: [] };
  const now = Date.now();
  const cacheKey = `host:${host.toLowerCase()}`;
  if (suggestionCache.has(cacheKey)) {
    const c = suggestionCache.get(cacheKey);
    if (now - c.time < CACHE_TTL.suggestions) return c.data;
  }

  // Server-side search across name/url/username/hashid
  const lists = [];
  let hadSuccess = false;
  let lastError = null;
  try {
    lists.push(await searchSecrets(host));
    hadSuccess = true;
  } catch (e) {
    lastError = e;
  }
  const hostNoWww = stripWww(host);
  if (hostNoWww && hostNoWww !== host) {
    try {
      lists.push(await searchSecrets(hostNoWww));
      hadSuccess = true;
    } catch (e) {
      lastError = e;
    }
  }
  if (!hadSuccess) {
    throw lastError || new Error('SUGGESTIONS_UNAVAILABLE');
  }
  // Merge and de-duplicate
  const merged = [];
  const seen = new Set();
  for (const l of lists) {
    for (const s of (l?.results || [])) {
      const key = s.hashid || s.api_url || s.web_url || s.name + '|' + (s.username || '');
      if (!seen.has(key)) { seen.add(key); merged.push(s); }
    }
  }
  const results = merged.filter(s => s.content_type === 'password');

  // Prefer those with matching hostname (treat www. as equivalent to bare domain)
  const [exact, others] = results.reduce((acc, s) => {
    const h = s.url ? urlHostname(s.url) : '';
    const hNo = stripWww(h);
    const pageNo = stripWww(host);
    if (h && (h === host || hNo === pageNo || host.endsWith('.' + h) || h.endsWith('.' + host))) acc[0].push(s);
    else acc[1].push(s);
    return acc;
  }, [[], []]);
  let ordered = [...exact, ...others];

  // Pinned goes first if configured
  try {
    const s = await getSettings();
    const eff = effectiveForUrl(s, pageUrl);
    if (eff.pinnedHashid) {
      const idx = ordered.findIndex(x => x.hashid === eff.pinnedHashid);
      if (idx > 0) {
        const [spliced] = ordered.splice(idx, 1);
        ordered.unshift(spliced);
      } else if (idx === -1) {
        try {
          const pinned = await getSecretByHashid(eff.pinnedHashid);
          if (pinned && pinned.content_type === 'password') ordered.unshift(pinned);
        } catch {}
      }
    }
  } catch {}

  // Move unreadable items to the end, but keep pinned (if present) at the very front
  try {
    const s = await getSettings();
    const eff = effectiveForUrl(s, pageUrl);
    if (ordered.length > 1) {
      if (eff.pinnedHashid && ordered[0] && ordered[0].hashid === eff.pinnedHashid) {
        const rest = ordered.slice(1);
        const readable = rest.filter(x => isReadable(x.data_readable));
        const unreadable = rest.filter(x => !isReadable(x.data_readable));
        ordered = [ordered[0], ...readable, ...unreadable];
      } else {
        const readable = ordered.filter(x => isReadable(x.data_readable));
        const unreadable = ordered.filter(x => !isReadable(x.data_readable));
        ordered = [...readable, ...unreadable];
      }
    }
  } catch {}

  const out = { results: ordered.slice(0, limit) };
  suggestionCache.set(cacheKey, { data: out, time: now });
  return out;
}

// Generate action icon dynamically to match inline button (accent circle + TV)
async function setDynamicActionIcon() {
  try {
    const sizes = [16, 32];
    const images = {};
    for (const sz of sizes) {
      const c = new OffscreenCanvas(sz, sz);
      const ctx = c.getContext('2d');
      // circle
      ctx.fillStyle = '#f8592c';
      ctx.beginPath();
      ctx.arc(sz/2, sz/2, sz/2 - 1, 0, Math.PI*2);
      ctx.fill();
      // text TV
      ctx.fillStyle = '#ffffff';
      ctx.font = `bold ${Math.floor(sz*0.56)}px system-ui, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('TV', sz/2, Math.round(sz/2)+1);
      const img = ctx.getImageData(0,0,sz,sz);
      images[sz] = img;
    }
    await chrome.action.setIcon({ imageData: images });
  } catch {}
}

function invalidateAuthCache() {
  authOk = false;
  authCache = { ok: null, time: 0, error: 'INVALIDATED' };
}

async function fillActiveTab(tabId, creds, submit) {
  try {
    const resp = await chrome.tabs.sendMessage(tabId, { type: 'teamvault.fill', creds, submit: !!submit });
    if (resp && typeof resp === 'object') return resp;
    return { ok: false, error: 'NO_RESPONSE' };
  } catch (e) {
    return { ok: false, error: e?.message || String(e) };
  }
}

async function fillOtpActiveTab(tabId, code) {
  try {
    const resp = await chrome.tabs.sendMessage(tabId, { type: 'teamvault.fillOtp', code });
    if (resp && typeof resp === 'object') return resp;
    return { ok: false, error: 'NO_RESPONSE' };
  } catch (e) {
    return { ok: false, error: e?.message || String(e) };
  }
}

// Context menu (optional helper)
chrome.runtime.onInstalled.addListener(async () => {
  chrome.contextMenus.create({ id: 'teamvault-fill', title: 'Fill with TeamVault', contexts: ['page', 'editable'] });
  await setDynamicActionIcon();
});

chrome.runtime.onStartup.addListener(async () => {
  await setDynamicActionIcon();
  // On startup, schedule auth refresh based on cookie
  try { await scheduleAuthRefreshFromCookie(); } catch {}
});

// Invalidate auth quickly when the TeamVault session cookie changes
chrome.cookies.onChanged.addListener(async (changeInfo) => {
  try {
    const { cookie } = changeInfo || {};
    if (!cookie || cookie.name !== 'sessionid') return;
    const { baseUrl } = await getSettings();
    const origin = getOrigin(baseUrl);
    if (!origin) return;
    const host = new URL(origin).hostname.replace(/^\./, '');
    const cDomain = (cookie.domain || '').replace(/^\./, '');
    if (!cDomain.endsWith(host)) return;
    invalidateAuthCache();
    scheduleAuthRefreshFromCookie().catch(() => {});
  } catch {}
});

// Pre-warm caches when switching tabs or URL changes
async function prewarmForTab(tab) {
  try {
    if (!tab || !tab.url) return;
    const s = await getSettings();
    const eff = effectiveForUrl(s, tab.url);
    if (!eff.prewarm) return;
    await checkAuth();
    await getSuggestionsForUrl(tab.url);
  } catch {}
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try { const tab = await chrome.tabs.get(tabId); await prewarmForTab(tab); } catch {}
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') await prewarmForTab(tab);
});

// Cookie-aware auth refresh
let authRefreshTimer = null;
async function scheduleAuthRefreshFromCookie() {
  try {
    if (authRefreshTimer) { clearTimeout(authRefreshTimer); authRefreshTimer = null; }
    const { baseUrl } = await getSettings();
    const origin = getOrigin(baseUrl);
    if (!origin) return;
    const cookie = await chrome.cookies.get({ url: origin + '/', name: 'sessionid' });
    if (!cookie || !cookie.expirationDate) return; // session cookie without expiry; do not auto-refresh
    const expiryMs = cookie.expirationDate * 1000;
    const now = Date.now();
    // Refresh 60s before expiry (min 30s from now)
    const delay = Math.max(30000, expiryMs - now - 60000);
    authRefreshTimer = setTimeout(async () => {
      try { await checkAuth(); } finally { scheduleAuthRefreshFromCookie().catch(() => {}); }
    }, delay);
  } catch {}
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'teamvault-fill' || !tab?.id) return;
  const { ok } = await checkAuth();
  if (!ok) {
    chrome.action.openPopup();
    return;
  }
  const suggestions = await getSuggestionsForUrl(tab.url || '');
  const first = suggestions.results?.[0];
  if (!first) return;
  try {
    const password = await getSecretPasswordBySecret(first);
    const creds = { username: first.username || '', password };
    const { autoSubmit } = await getSettings();
    await fillActiveTab(tab.id, creds, autoSubmit);
  } catch (e) {
    // silently ignore
  }
});

// Runtime messages from popup/options
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'settings.get': {
          const s = await getSettings();
          sendResponse({ ok: true, settings: s, authOk });
          break;
        }
        case 'settings.set': {
          const currentSettings = await getSettings();
          const mergedSettings = { ...currentSettings, ...(msg.settings || {}) };
          const baseChanged = currentSettings.baseUrl !== mergedSettings.baseUrl;
          const s = await setSettings(mergedSettings);
          if (baseChanged) {
            suggestionCache.clear();
            searchCache.clear();
            invalidateAuthCache();
          }
          // Attempt host permission on change
          if (s.baseUrl) await ensureHostPermissionFor(s.baseUrl);
          // Reschedule auth refresh when settings change
          scheduleAuthRefreshFromCookie().catch(() => {});
          sendResponse({ ok: true, settings: s });
          break;
        }
        case 'settings.effectiveForUrl': {
          const s = await getSettings();
          const eff = effectiveForUrl(s, msg.url || '');
          sendResponse({ ok: true, settings: s, effective: eff });
          break;
        }
        case 'sitePrefs.set': {
          const s = await getSettings();
          const host = normalizeHost(msg.host || hostFromUrl(msg.url || ''));
          if (!host) throw new Error('NO_HOST');
          s.sitePrefs = s.sitePrefs || {};
          s.sitePrefs[host] = { ...(s.sitePrefs[host] || {}), ...(msg.prefs || {}) };
          await setSettings(s);
          sendResponse({ ok: true });
          break;
        }
        case 'sitePrefs.clear': {
          const s = await getSettings();
          const host = normalizeHost(msg.host || hostFromUrl(msg.url || ''));
          if (!host) throw new Error('NO_HOST');
          if (s.sitePrefs) delete s.sitePrefs[host];
          await setSettings(s);
          sendResponse({ ok: true });
          break;
        }
        case 'auth.check': {
          const r = await checkAuth(!!msg.force);
          sendResponse(r);
          break;
        }
        case 'auth.login': {
          const { baseUrl } = await getSettings();
          if (!baseUrl) throw new Error('BASE_URL_NOT_CONFIGURED');
          const loginUrl = baseUrl.replace(/\/$/, '') + '/login/';
          await chrome.tabs.create({ url: loginUrl, active: true });
          // try to schedule refresh shortly after, to pick up the new cookie
          setTimeout(() => scheduleAuthRefreshFromCookie().catch(() => {}), 1000);
          sendResponse({ ok: true });
          break;
        }
        case 'search': {
          const data = await searchSecrets(msg.term || '');
          sendResponse({ ok: true, data });
          break;
        }
        case 'suggestions.forUrl': {
          const data = await getSuggestionsForUrl(msg.url || '');
          sendResponse({ ok: true, data });
          break;
        }
        case 'cache.suggestions.info': {
          const key = suggestionCacheKey(msg.url || '');
          const now = Date.now();
          let exists = false, time = 0, ageMs = 0, active = false, source = 'global';
          const s = await getSettings();
          const eff = effectiveForUrl(s, msg.url || '');
          active = !!eff.prewarm;
          const host = normalizeHost(hostFromUrl(msg.url || ''));
          const site = (s.sitePrefs || {})[host] || {};
          source = (site.prewarm !== undefined) ? 'site' : 'global';
          if (key && suggestionCache.has(key)) {
            const c = suggestionCache.get(key);
            exists = true; time = c.time; ageMs = Math.max(0, now - c.time);
          }
          sendResponse({ ok: true, exists, time, ageMs, active, source });
          break;
        }
        case 'cache.suggestions.refresh': {
          const key = suggestionCacheKey(msg.url || '');
          if (key) suggestionCache.delete(key);
          const data = await getSuggestionsForUrl(msg.url || '');
          const c = suggestionCache.get(key);
          const now = Date.now();
          const time = c?.time || now;
          sendResponse({ ok: true, data, time, ageMs: 0 });
          break;
        }
        case 'secret.password': {
          const password = await getSecretPasswordBySecret(msg.secret);
          sendResponse({ ok: true, password });
          break;
        }
        case 'secret.getByHashid': {
          const secret = await getSecretByHashid(msg.hashid);
          sendResponse({ ok: true, secret });
          break;
        }
        case 'secret.passwordByHashid': {
          const password = await getPasswordByHashid(msg.hashid);
          sendResponse({ ok: true, password });
          break;
        }
        case 'secret.otp': {
          const code = await getSecretOtpBySecret(msg.secret);
          sendResponse({ ok: true, code });
          break;
        }
        case 'tab.fill': {
          const tabId = msg.tabId || sender?.tab?.id;
          const { creds, submit } = msg;
          if (!tabId) throw new Error('NO_TAB');
          const result = await fillActiveTab(tabId, creds, submit);
          sendResponse(result);
          break;
        }
        case 'tab.fillOtp': {
          const tabId = msg.tabId || sender?.tab?.id;
          if (!tabId) throw new Error('NO_TAB');
          const result = await fillOtpActiveTab(tabId, msg.code);
          sendResponse(result);
          break;
        }
        case 'sitePrefs.pin': {
          const s = await getSettings();
          const host = normalizeHost(msg.host || hostFromUrl(msg.url || ''));
          if (!host) throw new Error('NO_HOST');
          s.sitePrefs = s.sitePrefs || {};
          s.sitePrefs[host] = { ...(s.sitePrefs[host] || {}), pinnedHashid: msg.hashid };
          await setSettings(s);
          sendResponse({ ok: true });
          break;
        }
        case 'sitePrefs.unpin': {
          const s = await getSettings();
          const host = normalizeHost(msg.host || hostFromUrl(msg.url || ''));
          if (!host) throw new Error('NO_HOST');
          if (s.sitePrefs && s.sitePrefs[host]) delete s.sitePrefs[host].pinnedHashid;
          await setSettings(s);
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: 'UNKNOWN_MESSAGE' });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e && e.message ? e.message : String(e) });
    }
  })();
  // Keep channel open for async
  return true;
});

const baseUrlInput = document.getElementById('baseUrl');
const saveBtn = document.getElementById('saveBtn');
const loginBtn = document.getElementById('loginBtn');
const checkBtn = document.getElementById('checkBtn');
const statusEl = document.getElementById('status');
const grantBtn = document.getElementById('grantBtn');
const permStatusEl = document.getElementById('permStatus');
const inlineToggle = document.getElementById('inlineToggle');
const themeSelect = document.getElementById('themeSelect');
const preferPinned = document.getElementById('preferPinned');
const allowHttpDev = document.getElementById('allowHttpDev');
const prewarmToggle = document.getElementById('prewarmToggle');
const siteHostEl = document.getElementById('siteHost');
const siteAutoSubmit = document.getElementById('siteAutoSubmit');
const siteInline = document.getElementById('siteInline');
const sitePrewarm = document.getElementById('sitePrewarm');
const siteSave = document.getElementById('siteSave');
const siteClear = document.getElementById('siteClear');
const siteRefresh = document.getElementById('siteRefresh');
const sitePrewarmStatus = document.getElementById('sitePrewarmStatus');

async function send(type, payload = {}) {
  return new Promise((resolve) => chrome.runtime.sendMessage({ type, ...payload }, (r) => resolve(r || { ok: false })));
}

async function load() {
  const r = await send('settings.get');
  if (r.ok && r.settings) baseUrlInput.value = r.settings.baseUrl || '';
  // also probe auth on load for better feedback
  const chk = await send('auth.check');
  statusEl.textContent = chk.ok ? 'Authenticated' : `Not signed in${chk.error ? `: ${chk.error}` : ''}`;
  inlineToggle.value = (r.settings?.inlineAutofill === false) ? 'off' : 'on';
  prewarmToggle.value = r.settings?.prewarmEnabled ? 'on' : 'off';
  themeSelect.value = r.settings?.theme || 'auto';
  applyTheme(r.settings?.theme || 'auto');
  preferPinned.value = r.settings?.preferPinned ? 'on' : 'off';
  allowHttpDev.value = r.settings?.allowHttpDev ? 'on' : 'off';
  await updatePermissionStatus();
  await loadSitePrefs();
}

async function save() {
  let url = (baseUrlInput.value || '').trim();
  if (url && !/^https?:\/\//i.test(url)) url = 'https://' + url;
  if (url.endsWith('/')) url = url.slice(0, -1);
  const r = await send('settings.set', { settings: { baseUrl: url } });
  if (!r.ok) return alert('Failed to save settings: ' + (r.error || 'unknown'));
  // Request host permission as part of save (user gesture)
  await requestHostPermission();
  await checkAuth();
}

async function login() {
  const r = await send('auth.login');
  if (!r.ok) alert('Configure Base URL first in Options.');
}

async function checkAuth() {
  statusEl.textContent = 'Checking…';
  const r = await send('auth.check');
  statusEl.textContent = r.ok ? 'Authenticated' : `Not signed in${r.error ? `: ${r.error}` : ''}`;
  if (!r.ok && r.details) {
    // show short tail of details for debugging
    const tail = String(r.details).slice(0, 120).replace(/\s+/g, ' ');
    statusEl.textContent += ` [${tail}]`;
  }
}

function getOriginPattern() {
  try {
    const u = new URL(baseUrlInput.value.trim());
    return `${u.protocol}//${u.host}/*`;
  } catch { return null; }
}

async function updatePermissionStatus() {
  const pattern = getOriginPattern();
  if (!pattern) { permStatusEl.textContent = ''; return; }
  // Gate HTTP by setting
  let httpBlocked = false;
  try { const u = new URL(baseUrlInput.value.trim()); httpBlocked = (u.protocol === 'http:') && (allowHttpDev.value !== 'on'); } catch {}
  if (httpBlocked) {
    permStatusEl.textContent = `Permission: HTTP blocked by setting (${pattern})`;
    return;
  }
  const granted = await chrome.permissions.contains({ origins: [pattern] });
  permStatusEl.textContent = granted ? `Permission: Granted (${pattern})` : `Permission: Not granted (${pattern})`;
}

async function requestHostPermission() {
  const pattern = getOriginPattern();
  if (!pattern) return false;
  // Disallow HTTP unless explicitly enabled
  try { const u = new URL(baseUrlInput.value.trim()); if (u.protocol === 'http:' && allowHttpDev.value !== 'on') return false; } catch {}
  const has = await chrome.permissions.contains({ origins: [pattern] });
  if (has) return true;
  try {
    const granted = await chrome.permissions.request({ origins: [pattern] });
    await updatePermissionStatus();
    return granted;
  } catch { return false; }
}

saveBtn.addEventListener('click', save);
loginBtn.addEventListener('click', login);
checkBtn.addEventListener('click', checkAuth);
grantBtn.addEventListener('click', async () => { await requestHostPermission(); await checkAuth(); });
inlineToggle.addEventListener('change', async () => { await send('settings.set', { settings: { inlineAutofill: inlineToggle.value === 'on' } }); });
prewarmToggle.addEventListener('change', async () => { await send('settings.set', { settings: { prewarmEnabled: prewarmToggle.value === 'on' } }); });
themeSelect.addEventListener('change', async () => { const v = themeSelect.value; await send('settings.set', { settings: { theme: v } }); applyTheme(v); });
preferPinned.addEventListener('change', async () => { await send('settings.set', { settings: { preferPinned: preferPinned.value === 'on' } }); });
allowHttpDev.addEventListener('change', async () => { await send('settings.set', { settings: { allowHttpDev: allowHttpDev.value === 'on' } }); await updatePermissionStatus(); });

load();

function applyTheme(theme) {
  document.body.classList.remove('force-dark', 'force-light');
  if (theme === 'dark') document.body.classList.add('force-dark');
  else if (theme === 'light') document.body.classList.add('force-light');
}

async function getActiveHost() {
  // Find most recently accessed http(s) tab across all windows
  const tabs = await chrome.tabs.query({});
  const httpTabs = tabs.filter(t => t.url && /^https?:\/\//i.test(t.url));
  if (httpTabs.length) {
    httpTabs.sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0));
    try { return new URL(httpTabs[0].url).hostname; } catch { /* ignore */ }
  }
  return '';
}

async function loadSitePrefs() {
  const host = await getActiveHost();
  siteHostEl.textContent = host ? `Current site: ${host}` : 'No active site';
  const eff = await send('settings.effectiveForUrl', { url: `https://${host}/` });
  if (eff.ok) {
    // Determine whether a site override exists by comparing with global
    const globalAuto = eff.settings?.autoSubmit ?? false;
    const globalInline = eff.settings?.inlineAutofill ?? true;
    const prefs = (eff.settings?.sitePrefs || {})[(host || '').toLowerCase()] || {};
    siteAutoSubmit.value = prefs.autoSubmit === undefined ? 'unset' : (prefs.autoSubmit ? 'on' : 'off');
    siteInline.value = prefs.inlineAutofill === undefined ? 'unset' : (prefs.inlineAutofill ? 'on' : 'off');
    sitePrewarm.value = prefs.prewarm === undefined ? 'unset' : (prefs.prewarm ? 'on' : 'off');

    // Effective prewarm status indicator
    const effectiveOn = !!eff.effective?.prewarm;
    const src = (prefs.prewarm !== undefined) ? 'site' : 'global';
    sitePrewarmStatus.textContent = effectiveOn ? `Active (${src})` : `Inactive (${src})`;
  }
}

siteSave.addEventListener('click', async () => {
  const host = await getActiveHost();
  if (!host) return;
  const prefs = {};
  if (siteAutoSubmit.value !== 'unset') prefs.autoSubmit = siteAutoSubmit.value === 'on';
  if (siteInline.value !== 'unset') prefs.inlineAutofill = siteInline.value === 'on';
  if (sitePrewarm.value !== 'unset') prefs.prewarm = sitePrewarm.value === 'on';
  await send('sitePrefs.set', { host, prefs });
  await loadSitePrefs();
});

siteClear.addEventListener('click', async () => {
  const host = await getActiveHost();
  if (!host) return;
  await send('sitePrefs.clear', { host });
  await loadSitePrefs();
});

siteRefresh.addEventListener('click', async () => { await loadSitePrefs(); });

window.addEventListener('focus', async () => { await loadSitePrefs(); });
document.addEventListener('visibilitychange', async () => { if (!document.hidden) await loadSitePrefs(); });

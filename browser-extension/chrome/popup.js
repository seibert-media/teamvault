const $ = (sel) => document.querySelector(sel);
const resultsEl = $('#results');
const statusText = $('#statusText');
const searchInput = $('#searchInput');
const loginBtn = $('#loginBtn');
const grantPermBtn = $('#grantPermBtn');
const openOptionsBtn = $('#openOptions');
const autoSubmitToggle = $('#autoSubmitToggle');
const siteAutoSubmitToggle = document.getElementById('siteAutoSubmitToggle');
const siteResetBtn = document.getElementById('siteResetBtn');
const prewarmStatusEl = document.getElementById('prewarmStatus');
const siteTop = document.getElementById('siteTop');

let settings = { baseUrl: '', autoSubmit: false };
let effective = { autoSubmit: false, inlineAutofill: true, pinnedHashid: null };
let currentResults = [];
let activeIndex = -1;
let currentTab = null;
let currentHost = '';
let pinnedHashid = null;

async function send(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, (resp) => resolve(resp || { ok: false, error: 'NO_RESPONSE' }));
  });
}

function fmtUrl(u) { try { const x = new URL(u); return x.host; } catch { return u || ''; } }

function isReadableVal(v) { return Number(v) > 0; }

function renderItem(secret) {
  const div = document.createElement('div');
  div.className = 'item';
  const name = secret.name || '(no name)';
  const username = secret.username || '';
  const url = secret.url || '';
  const iconFill = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v10m0 0l-4-4m4 4l4-4M4 20h16" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const iconSubmit = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12h10m0 0l-3-3m3 3l-3 3M20 5v14" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const iconKey = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="12" r="3"/><path d="M12 12h9M18 12v3M21 12v3" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const iconUser = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm-7 8a7 7 0 0 1 14 0Z" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const iconOtp = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 8v5l3 2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  // Build safe DOM instead of using innerHTML
  const titleDiv = document.createElement('div');
  titleDiv.className = 'title';
  if (pinnedHashid === secret.hashid) {
    const pinSpan = document.createElement('span');
    pinSpan.className = 'pinned';
    pinSpan.textContent = '★';
    titleDiv.appendChild(pinSpan);
  }
  if (!secret.data_readable) {
    const lockSpan = document.createElement('span');
    lockSpan.className = 'lock';
    lockSpan.title = 'No access';
    lockSpan.textContent = '🔒';
    titleDiv.appendChild(lockSpan);
  }
  const nameLink = document.createElement('a');
  nameLink.href = '#';
  nameLink.className = 'name';
  nameLink.dataset.url = secret.web_url || '';
  nameLink.textContent = name;
  titleDiv.appendChild(nameLink);

  const metaDiv = document.createElement('div');
  metaDiv.className = 'meta';
  if (username) {
    const userPill = document.createElement('span');
    userPill.className = 'pill';
    userPill.textContent = username;
    metaDiv.appendChild(userPill);
  }
  if (url) {
    const urlA = document.createElement('a');
    urlA.href = '#';
    urlA.className = 'url-link';
    urlA.title = `Open ${fmtUrl(url)}`;
    urlA.dataset.url = url;
    urlA.textContent = fmtUrl(url);
    metaDiv.appendChild(urlA);
  }

  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'actions';
  const btnFill = document.createElement('button');
  btnFill.className = 'primary';
  btnFill.dataset.act = 'fill';
  btnFill.title = 'Fill';
  btnFill.setAttribute('aria-label', 'Fill');
  btnFill.innerHTML = iconFill;
  const btnFillSubmit = document.createElement('button');
  btnFillSubmit.className = 'primary';
  btnFillSubmit.dataset.act = 'fill-submit';
  btnFillSubmit.title = 'Fill and submit';
  btnFillSubmit.setAttribute('aria-label', 'Fill and submit');
  btnFillSubmit.innerHTML = iconSubmit;
  const btnCopy = document.createElement('button');
  btnCopy.dataset.act = 'copy';
  btnCopy.title = 'Copy password';
  btnCopy.setAttribute('aria-label', 'Copy password');
  btnCopy.innerHTML = iconKey;
  const btnCopyUser = document.createElement('button');
  btnCopyUser.dataset.act = 'copy-user';
  btnCopyUser.title = 'Copy username';
  btnCopyUser.setAttribute('aria-label', 'Copy username');
  if (!username) btnCopyUser.disabled = true;
  btnCopyUser.innerHTML = iconUser;
  const btnOtp = document.createElement('button');
  btnOtp.dataset.act = 'otp';
  btnOtp.title = 'Fill or copy OTP';
  btnOtp.setAttribute('aria-label', 'Fill or copy OTP');
  btnOtp.innerHTML = iconOtp;
  const btnPin = document.createElement('button');
  btnPin.dataset.act = 'pin';
  btnPin.title = `${pinnedHashid === secret.hashid ? 'Unpin' : 'Pin'} this secret for this site`;
  btnPin.setAttribute('aria-label', pinnedHashid === secret.hashid ? 'Unpin' : 'Pin');
  btnPin.textContent = pinnedHashid === secret.hashid ? '📌' : '📍';
  actionsDiv.append(btnFill, btnFillSubmit, btnCopy, btnCopyUser, btnOtp, btnPin);

  div.append(titleDiv, metaDiv, actionsDiv);

  div.addEventListener('click', async (e) => {
    const link = e.target.closest && (e.target.closest('a.name') || e.target.closest('a.url-link'));
    if (link) {
      e.preventDefault();
      const href = link.getAttribute('data-url');
      if (href) {
        try {
          const u = new URL(href);
          if (u.protocol === 'http:' || u.protocol === 'https:') {
            await chrome.tabs.create({ url: u.toString(), active: true });
          }
        } catch { /* ignore invalid or disallowed schemes */ }
      }
      return;
    }
    const btn = e.target.closest && e.target.closest('button[data-act]');
    const act = btn?.getAttribute?.('data-act');
    if (!act) return;
    e.preventDefault();
    if (!currentTab) return;
    // visual feedback
    if (btn) {
      btn.classList.add('pulse'); setTimeout(() => btn.classList.remove('pulse'), 220);
      // ripple
      const rect = btn.getBoundingClientRect();
      const r = document.createElement('span');
      r.className = 'ripple';
      const size = Math.max(rect.width, rect.height) * 1.8;
      const x = (e.clientX || (rect.left + rect.width / 2)) - rect.left - size / 2;
      const y = (e.clientY || (rect.top + rect.height / 2)) - rect.top - size / 2;
      r.style.width = r.style.height = size + 'px';
      r.style.left = x + 'px';
      r.style.top = y + 'px';
      btn.appendChild(r);
      setTimeout(() => r.remove(), 450);
    }
    if (act === 'copy-user') {
      if (secret.username) {
        try { await navigator.clipboard.writeText(secret.username); if (btn) { const old = btn.title; btn.title = 'Copied!'; setTimeout(() => btn.title = old, 1200); } } catch {}
      }
    } else if (act === 'copy' || act === 'fill' || act === 'fill-submit') {
      const resp = await send('secret.password', { secret });
      if (!resp.ok) { showToast(`Password error: ${resp.error}`, 'error'); return; }
      const password = resp.password;
      if (act === 'copy') {
        try { await navigator.clipboard.writeText(password); if (btn) { const old = btn.title; btn.title = 'Copied!'; setTimeout(() => btn.title = old, 1200); } } catch { /* ignore */ }
      } else {
        const creds = { username: secret.username || '', password };
        const submit = act === 'fill-submit' ? true : !!effective.autoSubmit;
        await send('tab.fill', { tabId: currentTab.id, creds, submit });
        if (btn) { const old = btn.title; btn.title = submit ? 'Filled + submitted!' : 'Filled!'; setTimeout(() => btn.title = old, 1200); }
      }
    } else if (act === 'otp') {
      const resp = await send('secret.otp', { secret });
      if (!resp.ok) { showToast(`OTP error: ${resp.error}`, 'error'); return; }
      const code = resp.code;
      // Try fill OTP field, else copy
      const filled = await send('tab.fillOtp', { tabId: currentTab.id, code });
      if (!filled?.ok) try { await navigator.clipboard.writeText(code); } catch {}
      if (btn) { const old = btn.title; btn.title = filled?.ok ? 'Filled!' : 'Copied!'; setTimeout(() => btn.title = old, 1200); }
    } else if (act === 'pin') {
      if (!currentHost) return;
      if (pinnedHashid === secret.hashid) {
        await send('sitePrefs.unpin', { host: currentHost });
        pinnedHashid = null;
      } else {
        await send('sitePrefs.pin', { host: currentHost, hashid: secret.hashid });
        pinnedHashid = secret.hashid;
      }
      await loadSuggestions();
    }
  });

  return div;
}

function setStatus(text, ok) {
  statusText.textContent = text;
  statusText.style.opacity = ok ? '1' : '0.9';
}

let isAuthed = false;
async function refreshAuth() {
  const r = await send('auth.check', { force: true });
  if (r.ok) {
    setStatus('🔓', true);
    isAuthed = true;
    statusText.title = 'Authenticated';
    grantPermBtn.style.display = 'none';
    loginBtn.style.display = 'none';
  } else {
    setStatus('🔒', false);
    isAuthed = false;
    statusText.title = `Not signed in${r.error ? `: ${r.error}` : ''}`;
    if ((r.error || '').includes('HOST_PERMISSION_DENIED')) {
      grantPermBtn.style.display = '';
    } else {
      grantPermBtn.style.display = 'none';
    }
    loginBtn.style.display = '';
  }
  return !!r.ok;
}

function getOriginPattern(u) {
  try { const x = new URL(u); return `${x.protocol}//${x.host}/*`; } catch { return null; }
}

async function requestHostPermissionFromPopup() {
  const resp = await send('settings.get');
  const baseUrl = resp?.settings?.baseUrl;
  const allowHttpDev = !!resp?.settings?.allowHttpDev;
  const pattern = baseUrl ? getOriginPattern(baseUrl) : null;
  if (!pattern) return false;
  try {
    const u = new URL(baseUrl);
    if (u.protocol === 'http:' && !allowHttpDev) {
      showToast('HTTP origin blocked. Enable "Allow HTTP (dev)" in Options.', 'error');
      return false;
    }
  } catch {}
  const has = await chrome.permissions.contains({ origins: [pattern] });
  if (has) return true;
  try {
    const granted = await chrome.permissions.request({ origins: [pattern] });
    return granted;
  } catch { return false; }
}

async function loadSettings() {
  const resp = await send('settings.get');
  if (resp.ok) {
    settings = resp.settings || settings;
    autoSubmitToggle.checked = !!settings.autoSubmit;
    applyTheme(settings.theme || 'auto');
    preferPinned = !!settings.preferPinned;
  }
}

async function saveSettingsPartial(partial) {
  settings = { ...(settings || {}), ...(partial || {}) };
  await send('settings.set', { settings });
}

async function loadTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tabs[0];
  if (currentTab?.url) {
    const eff = await send('settings.effectiveForUrl', { url: currentTab.url });
    if (eff.ok) {
      effective = eff.effective || effective;
      autoSubmitToggle.checked = !!effective.autoSubmit;
      pinnedHashid = effective.pinnedHashid || null;
    }
    try { currentHost = new URL(currentTab.url).hostname; } catch { currentHost = ''; }
    if (siteTop) siteTop.textContent = currentHost ? `Site: ${currentHost}` : '';
    const all = await send('settings.get');
    const prefs = (all.settings?.sitePrefs || {})[(currentHost || '').toLowerCase()] || {};
    if (siteAutoSubmitToggle) siteAutoSubmitToggle.checked = prefs.autoSubmit === true;
    const src = (prefs.prewarm !== undefined) ? 'site' : 'global';
    const prewarmOn = !!effective.prewarm;
    if (prewarmStatusEl) {
      prewarmStatusEl.textContent = prewarmOn ? '🔥' : '💤';
      prewarmStatusEl.title = `Pre-warm: ${prewarmOn ? 'Active' : 'Inactive'} (${src})`;
    }
  }
}

function renderResults(list) {
  resultsEl.innerHTML = '';
  currentResults = list || [];
  activeIndex = currentResults.length ? 0 : -1;
  currentResults.forEach((s, idx) => {
    const el = renderItem(s);
    if (idx === activeIndex) el.classList.add('active');
    el.dataset.idx = String(idx);
    resultsEl.appendChild(el);
  });
}

async function loadSuggestions() {
  if (!currentTab?.url) return renderResults([]);
  const resp = await send('suggestions.forUrl', { url: currentTab.url });
  if (resp.ok) renderResults(resp.data.results || []);
}

async function performSearch(term) {
  if (!term) { await loadSuggestions(); return 0; }
  const r = await send('search', { term });
  if (r.ok) {
    let items = (r.data.results || []).filter(x => x.content_type === 'password');
    if (preferPinned && pinnedHashid) {
      const idx = items.findIndex(x => x.hashid === pinnedHashid);
      if (idx > 0) {
        const [spliced] = items.splice(idx, 1);
        items.unshift(spliced);
      } else if (idx === -1) {
        try {
          const pr = await send('secret.getByHashid', { hashid: pinnedHashid });
          if (pr.ok && pr.secret && pr.secret.content_type === 'password') {
            items.unshift(pr.secret);
          }
        } catch {}
      }
    }
    // Move unreadable items to the end (keep pinned first if present)
    if (items.length > 1) {
      const start = (preferPinned && pinnedHashid && items[0]?.hashid === pinnedHashid) ? [items.shift()] : [];
      const readable = items.filter(x => isReadableVal(x.data_readable));
      const unreadable = items.filter(x => !isReadableVal(x.data_readable));
      items = [...start, ...readable, ...unreadable];
    }
    renderResults(items);
    return items.length;
  }
  return 0;
}

function wireEvents() {
  searchInput.addEventListener('input', () => { performSearch(searchInput.value.trim()); });
  loginBtn.addEventListener('click', async () => { await send('auth.login'); });
  statusText.addEventListener('click', async () => { if (!isAuthed) await send('auth.login'); });
  grantPermBtn.addEventListener('click', async () => {
    const ok = await requestHostPermissionFromPopup();
    if (!ok) return;
    await refreshAuth();
    await loadSuggestions();
  });
  openOptionsBtn.addEventListener('click', () => chrome.runtime.openOptionsPage());
  autoSubmitToggle.addEventListener('change', async () => { await saveSettingsPartial({ autoSubmit: autoSubmitToggle.checked }); });

  if (siteAutoSubmitToggle) siteAutoSubmitToggle.addEventListener('change', async () => {
    if (!currentHost) return;
    await send('sitePrefs.set', { host: currentHost, prefs: { autoSubmit: siteAutoSubmitToggle.checked } });
    const eff = await send('settings.effectiveForUrl', { url: currentTab?.url || '' });
    if (eff.ok) effective = eff.effective || effective;
  });
  if (siteResetBtn) siteResetBtn.addEventListener('click', async () => {
    if (!currentHost) return;
    await send('sitePrefs.clear', { host: currentHost });
    const all = await send('settings.get');
    const prefs = (all.settings?.sitePrefs || {})[(currentHost || '').toLowerCase()] || {};
    siteAutoSubmitToggle.checked = prefs.autoSubmit === true;
  });
  if (prewarmStatusEl) prewarmStatusEl.addEventListener('click', async () => { await refreshPrewarm(); });

  // Keyboard navigation
  document.addEventListener('keydown', async (e) => {
    const key = e.key;
    if (!currentResults.length) return;
    if (key === 'ArrowDown' || key === 'ArrowUp') {
      e.preventDefault();
      const prev = activeIndex;
      if (key === 'ArrowDown') activeIndex = (activeIndex + 1) % currentResults.length;
      else activeIndex = (activeIndex - 1 + currentResults.length) % currentResults.length;
      const children = Array.from(resultsEl.children);
      if (children[prev]) children[prev].classList.remove('active');
      if (children[activeIndex]) children[activeIndex].classList.add('active');
      children[activeIndex]?.scrollIntoView({ block: 'nearest' });
    } else if (key === 'Enter') {
      e.preventDefault();
      const s = currentResults[activeIndex] || currentResults[0];
      if (!s || !currentTab) return;
      const resp = await send('secret.password', { secret: s });
      if (!resp.ok) return;
      const password = resp.password;
      const creds = { username: s.username || '', password };
      const submit = e.ctrlKey || e.metaKey || e.shiftKey || !!effective.autoSubmit;
      await send('tab.fill', { tabId: currentTab.id, creds, submit });
    }
  });
}

(async function init() {
  wireEvents();
  await loadSettings();
  await loadTab();
  await refreshAuth();
  await updatePrewarmIndicator();
  // Auto-search by current hostname for ergonomics
  let host = '';
  try { host = new URL(currentTab?.url || '').hostname; } catch {}
  const hostForSearch = host.replace(/^www\./i, '');
  if (host) {
    searchInput.value = hostForSearch;
    const count = await performSearch(hostForSearch);
    if (count === 0) await loadSuggestions();
  } else {
    await loadSuggestions();
  }
})();

function applyTheme(theme) {
  document.body.classList.remove('force-dark', 'force-light');
  if (theme === 'dark') document.body.classList.add('force-dark');
  else if (theme === 'light') document.body.classList.add('force-light');
}

// Popup toast
let toastTimer = null;
function showToast(message, type = 'info') {
  let wrap = document.getElementById('tvToast');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.id = 'tvToast';
    document.querySelector('.card')?.appendChild(wrap);
  }
  wrap.innerHTML = '';
  const t = document.createElement('div');
  t.className = 'toast ' + (type === 'error' ? 'error' : type === 'success' ? 'success' : '');
  const span = document.createElement('span');
  span.textContent = message;
  const close = document.createElement('button');
  close.className = 'close';
  close.textContent = '×';
  close.title = 'Close';
  close.onclick = () => { if (toastTimer) clearTimeout(toastTimer); wrap.remove(); toastTimer = null; };
  t.append(span, close);
  wrap.appendChild(t);
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { wrap.remove(); toastTimer = null; }, 3000);
}

// Keep pre-warm indicator in sync if settings change (e.g., toggled in Options)
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === 'sync' && changes && changes.settings) {
    await updatePrewarmIndicator();
  }
});

function formatAge(ms) {
  if (!ms || ms < 1000) return 'just now';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m > 0) return `${m}m ${rs}s ago`;
  return `${s}s ago`;
}

async function updatePrewarmIndicator() {
  if (!prewarmStatusEl || !currentTab?.url) return;
  const info = await send('cache.suggestions.info', { url: currentTab.url });
  const icon = info.active ? '🔥' : '💤';
  const cached = info.exists ? `, cached ${formatAge(info.ageMs)}` : '';
  prewarmStatusEl.textContent = icon;
  prewarmStatusEl.title = `Pre-warm: ${info.active ? 'Active' : 'Inactive'} (${info.source})${cached}`;
}

async function refreshPrewarm() {
  if (!currentTab?.url) return;
  await send('cache.suggestions.refresh', { url: currentTab.url });
  await updatePrewarmIndicator();
  await loadSuggestions();
  showToast('Suggestions refreshed', 'success');
}

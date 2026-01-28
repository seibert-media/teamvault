// TeamVault Content Script: autofill helpers

function findClosestForm(el) {
  while (el) {
    if (el.tagName === 'FORM') return el;
    el = el.parentElement;
  }
  return null;
}

function findLoginFields() {
  const passwords = Array.from(document.querySelectorAll('input[type="password"]'));
  if (!passwords.length) return null;
  // Choose the most visible password field
  const pass = passwords.find(el => el.offsetParent !== null) || passwords[0];
  const form = findClosestForm(pass) || document;
  // Candidate username fields in form
  const userCandidates = Array.from(form.querySelectorAll('input'))
    .filter(i => {
      const t = (i.getAttribute('type') || 'text').toLowerCase();
      if (t === 'password' || t === 'hidden' || i.disabled || i.readOnly) return false;
      const n = (i.name || '').toLowerCase();
      const id = (i.id || '').toLowerCase();
      const ph = (i.getAttribute('placeholder') || '').toLowerCase();
      return (
        t === 'text' || t === 'email' || t === 'tel' || t === 'username'
      ) && (n.includes('user') || n.includes('email') || n.includes('login') || id.includes('user') || id.includes('email') || ph.includes('email') || ph.includes('user'));
    });
  const username = userCandidates[0] || Array.from(form.querySelectorAll('input[type="text"],input[type="email"]'))[0] || null;
  return { form: form === document ? null : form, username, password: pass };
}

function findOtpField() {
  const sels = [
    'input[name*="otp" i]',
    'input[id*="otp" i]',
    'input[name*="2fa" i]',
    'input[id*="2fa" i]',
    'input[name*="totp" i]',
    'input[id*="totp" i]',
    'input[name*="code" i]',
    'input[id*="code" i]'
  ];
  const fields = sels.flatMap(s => Array.from(document.querySelectorAll(s)));
  return fields.find(i => (i.type === 'text' || i.type === 'tel' || i.type === 'number' || !i.type) && !i.disabled) || null;
}

function setValue(el, value) {
  if (!el) return;
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
  if (setter) setter.call(el, value);
  else el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

async function fillCredentials({ username, password }, submit = false) {
  const fields = findLoginFields();
  if (!fields || !fields.password) return false;
  if (fields.username && username) setValue(fields.username, username);
  if (password) setValue(fields.password, password);
  if (submit) {
    const form = fields.form || findClosestForm(fields.password) || findClosestForm(fields.username);
    if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
    else if (form) form.submit();
  }
  return true;
}

async function fillOtp(code) {
  const f = findOtpField();
  if (!f) return false;
  setValue(f, code);
  return true;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === 'teamvault.fill') {
        const ok = await fillCredentials(msg.creds || {}, msg.submit);
        sendResponse({ ok });
      } else if (msg.type === 'teamvault.fillOtp') {
        const ok = await fillOtp(msg.code);
        sendResponse({ ok });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();
  return true;
});

// --- Inline autofill button ---
let tvBtn = null;
let tvBtnTarget = null;
let tvMenu = null;
let repositionRaf = null;
let inlineEnabled = true;
let pressTimer = null;
const LONG_PRESS_MS = 450;

function showToast(message, x, y) {
  const el = document.createElement('div');
  el.className = 'tv-autofill-toaster';
  el.textContent = message;
  el.style.left = Math.max(8, x - 60) + 'px';
  el.style.top = Math.max(8, y - 40) + 'px';
  document.documentElement.appendChild(el);
  setTimeout(() => el.remove(), 1600);
}

function positionBtn() {
  if (!tvBtn || !tvBtnTarget) return;
  const r = tvBtnTarget.getBoundingClientRect();
  if (!r || r.width === 0 || r.height === 0) { tvBtn.style.display = 'none'; return; }
  tvBtn.style.display = 'inline-flex';
  // Place inside the right end of the input, with small inset
  const inset = 4;
  const x = Math.round(r.right - 26 - inset);
  const y = Math.round(r.top + (r.height - 26) / 2);
  tvBtn.style.left = x + 'px';
  tvBtn.style.top = y + 'px';
}

function scheduleReposition() {
  if (repositionRaf) return;
  repositionRaf = requestAnimationFrame(() => {
    repositionRaf = null;
    positionBtn();
  });
}

async function handleBtnClick(ev) {
  ev.preventDefault();
  // Ask background for best match and fill
  try {
    // Prefer pinned if configured
    let username = '';
    let password = '';
    const eff = await new Promise(res => chrome.runtime.sendMessage({ type: 'settings.effectiveForUrl', url: location.href }, res));
    if (eff?.ok && eff.effective?.pinnedHashid) {
      const hid = eff.effective.pinnedHashid;
      const sresp = await new Promise(res => chrome.runtime.sendMessage({ type: 'secret.getByHashid', hashid: hid }, res));
      const pwresp = await new Promise(res => chrome.runtime.sendMessage({ type: 'secret.passwordByHashid', hashid: hid }, res));
      if (sresp?.ok && pwresp?.ok) {
        username = sresp.secret?.username || '';
        password = pwresp.password || '';
      }
    }
    if (!password) {
      const sugg = await new Promise(res => chrome.runtime.sendMessage({ type: 'suggestions.forUrl', url: location.href }, res));
      if (!sugg?.ok) {
        const err = sugg?.error || '';
        if (err === 'UNAUTHENTICATED') { showToast('TeamVault: Not signed in', ev.pageX, ev.pageY); return; }
        showToast('TeamVault: Lookup failed', ev.pageX, ev.pageY);
        return;
      }
      const first = sugg?.data?.results?.[0];
      if (!first) { showToast('TeamVault: No secret found', ev.pageX, ev.pageY); return; }
      const pw = await new Promise(res => chrome.runtime.sendMessage({ type: 'secret.password', secret: first }, res));
      if (!pw?.ok) { showToast('TeamVault: Password error', ev.pageX, ev.pageY); return; }
      username = first.username || '';
      password = pw.password;
    }
    await fillCredentials({ username, password }, false);
    showToast('Filled from TeamVault', ev.pageX, ev.pageY);
  } catch {
    showToast('TeamVault: Not signed in', ev.pageX, ev.pageY);
  }
}

function hideMenu() {
  if (tvMenu) { tvMenu.remove(); tvMenu = null; }
}

function createMenu(items, anchorRect) {
  hideMenu();
  const menu = document.createElement('div');
  menu.className = 'tv-autofill-menu';
  const max = Math.min(6, items.length);
  for (let i = 0; i < max; i++) {
    const s = items[i];
    const el = document.createElement('div');
    el.className = 'tv-item';
    // Safe DOM construction without innerHTML
    const title = document.createElement('div');
    title.className = 'tv-title';
    title.textContent = s.name || '';
    const sub = document.createElement('div');
    sub.className = 'tv-sub';
    sub.textContent = s.username || '';
    el.append(title, sub);
    el.addEventListener('click', async (e) => {
      e.preventDefault(); hideMenu();
      try {
        const pw = await new Promise(res => chrome.runtime.sendMessage({ type: 'secret.password', secret: s }, res));
        if (!pw?.ok) { showToast('TeamVault: Password error', e.pageX, e.pageY); return; }
        await fillCredentials({ username: s.username || '', password: pw.password }, false);
        showToast('Filled from TeamVault', e.pageX, e.pageY);
      } catch {}
    });
    menu.appendChild(el);
  }
  const r = anchorRect;
  menu.style.left = Math.round(r.left + window.scrollX) + 'px';
  menu.style.top = Math.round(r.bottom + 6 + window.scrollY) + 'px';
  document.documentElement.appendChild(menu);
  tvMenu = menu;
  const onDoc = (e) => { if (!menu.contains(e.target) && e.target !== tvBtn) { hideMenu(); document.removeEventListener('mousedown', onDoc, true); } };
  setTimeout(() => document.addEventListener('mousedown', onDoc, true), 0);
}

async function showChooser() {
  try {
    const rect = tvBtn.getBoundingClientRect();
    const [sugg, eff] = await Promise.all([
      new Promise(res => chrome.runtime.sendMessage({ type: 'suggestions.forUrl', url: location.href }, res)),
      new Promise(res => chrome.runtime.sendMessage({ type: 'settings.effectiveForUrl', url: location.href }, res)),
    ]);
    const toastX = Math.round(rect.left + window.scrollX);
    const toastY = Math.round(rect.top + window.scrollY);
    if (!sugg?.ok) {
      const err = sugg?.error || '';
      if (err === 'UNAUTHENTICATED') { showToast('TeamVault: Not signed in', toastX, toastY); return; }
      showToast('TeamVault: Lookup failed', toastX, toastY);
      return;
    }
    const items = sugg?.data?.results || [];
    const pinned = eff?.effective?.pinnedHashid || null;
    if (!items.length) { showToast('TeamVault: No matches', toastX, toastY); return; }
    // annotate menu with pinned label by injecting into title
    hideMenu();
    const menu = document.createElement('div');
    menu.className = 'tv-autofill-menu';
    const max = Math.min(6, items.length);
    for (let i = 0; i < max; i++) {
      const s = items[i];
      const el = document.createElement('div');
      el.className = 'tv-item';
      // Build title safely
      const title = document.createElement('div');
      title.className = 'tv-title';
      title.textContent = s.name || '';
      if (!s.data_readable) {
        title.appendChild(document.createTextNode(' 🔒'));
      }
      if (pinned && s.hashid === pinned) {
        const pinEl = document.createElement('span');
        pinEl.className = 'tv-pin';
        pinEl.textContent = 'Pinned';
        title.appendChild(document.createTextNode(' '));
        title.appendChild(pinEl);
      }
      const sub = document.createElement('div');
      sub.className = 'tv-sub';
      sub.textContent = s.username || '';
      el.append(title, sub);
      el.addEventListener('click', async (e) => {
        e.preventDefault(); hideMenu();
        try {
          const pw = await new Promise(res => chrome.runtime.sendMessage({ type: 'secret.password', secret: s }, res));
          if (!pw?.ok) { showToast('TeamVault: Password error', e.pageX, e.pageY); return; }
          await fillCredentials({ username: s.username || '', password: pw.password }, false);
          showToast('Filled from TeamVault', e.pageX, e.pageY);
        } catch {}
      });
      menu.appendChild(el);
    }
    menu.style.left = Math.round(rect.left + window.scrollX) + 'px';
    menu.style.top = Math.round(rect.bottom + 6 + window.scrollY) + 'px';
    document.documentElement.appendChild(menu);
    tvMenu = menu;
    const onDoc = (e) => { if (!menu.contains(e.target) && e.target !== tvBtn) { hideMenu(); document.removeEventListener('mousedown', onDoc, true); } };
    setTimeout(() => document.addEventListener('mousedown', onDoc, true), 0);
  } catch {}
}

function ensureAutofillButton() {
  if (!inlineEnabled) {
    if (tvBtn) tvBtn.style.display = 'none';
    tvBtnTarget = null;
    hideMenu();
    return;
  }
  const fields = findLoginFields();
  if (!fields || !fields.password) {
    if (tvBtn) tvBtn.style.display = 'none';
    tvBtnTarget = null;
    return;
  }
  const target = fields.password;
  tvBtnTarget = target;
  if (!tvBtn) {
    tvBtn = document.createElement('div');
    tvBtn.className = 'tv-autofill-btn';
    tvBtn.textContent = 'TV';
    tvBtn.title = 'Fill with TeamVault';
    tvBtn.addEventListener('mousedown', (e) => {
      pressTimer = setTimeout(() => { pressTimer = null; showChooser(); }, LONG_PRESS_MS);
    });
    ['mouseup', 'mouseleave'].forEach(evt => tvBtn.addEventListener(evt, (e) => {
      if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; handleBtnClick(e); }
    }));
    tvBtn.addEventListener('touchstart', (e) => { pressTimer = setTimeout(() => { pressTimer = null; showChooser(); }, LONG_PRESS_MS); }, { passive: true });
    tvBtn.addEventListener('touchend', (e) => { if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; handleBtnClick(e.changedTouches[0] || e); } }, { passive: true });
    document.documentElement.appendChild(tvBtn);
    window.addEventListener('scroll', scheduleReposition, { passive: true });
    window.addEventListener('resize', scheduleReposition, { passive: true });
  }
  scheduleReposition();
}

const mo = new MutationObserver(() => ensureAutofillButton());
mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'class'] });
document.addEventListener('DOMContentLoaded', ensureAutofillButton);
window.addEventListener('load', ensureAutofillButton, { once: true });
setInterval(ensureAutofillButton, 2000); // fallback for SPAs

// Settings: inline button toggle
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === 'sync' && changes && changes.settings) {
    try {
      const resp = await new Promise(res => chrome.runtime.sendMessage({ type: 'settings.effectiveForUrl', url: location.href }, res));
      inlineEnabled = resp?.effective?.inlineAutofill !== false;
    } catch { /* ignore */ }
    if (!inlineEnabled && tvBtn) { tvBtn.style.display = 'none'; hideMenu(); }
    else ensureAutofillButton();
  }
});

(async () => {
  try {
    const resp = await new Promise(res => chrome.runtime.sendMessage({ type: 'settings.effectiveForUrl', url: location.href }, res));
    inlineEnabled = resp?.effective?.inlineAutofill !== false;
  } catch { inlineEnabled = true; }
  ensureAutofillButton();
})();

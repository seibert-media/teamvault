TeamVault Chrome Extension
==========================

This is a Manifest V3 Chrome extension that integrates with TeamVault to search, view, and autofill credentials on websites. It uses TeamVault's session-based auth and REST API under `/api/`.

Features
- Configurable TeamVault base URL in Options
- Session authentication via normal web login flow
- Popup search with per-site suggestions (auto-search by hostname)
- Autofill username/password on the active page
- One-time password (OTP) fill when available (copies to clipboard if no OTP field is present)
- Inline "TV" button on login fields for 1‑click fill (long‑press for quick chooser, shows pinned label)
- Pin a secret per site to make it the default
- Copy actions: password and username from the popup
- Light/Dark/Auto theme for popup and options
- Prefer pinned option (global) to always place pinned first, even when searching
- Per‑site preferences: auto‑submit and inline button overrides
  - Plus pin a default secret for the current site
- Privacy: Optional pre-warming (global or per-site), off by default, with live status + refresh in the popup
- Performance: Cookie-aware auth refresh, caching for auth/suggestions/search (auto-clears when the Base URL changes)
 - Polished popup: shows current site on top, iconized auth (🔓/🔒) and pre-warm (🔥/💤), accent-colored links
 - Keyboard navigation in popup: Up/Down to select, Enter to Fill (hold Shift/Ctrl/⌘ for Fill+Submit)

How auth works
- The extension never stores your password; it relies on your TeamVault web session cookie.
- Click "Sign in" in Options to open your TeamVault login page. After logging in, the extension can call the API with `credentials: include`.
- The extension checks auth by calling `GET <BASE_URL>/api/secrets/`.

SameSite cookies note
- Chrome treats extension requests as cross-site. If your Django session cookie uses `SameSite=Lax/Strict` (default), it won’t be sent to extension-origin fetches.
- The extension falls back to performing API requests from a tab at your TeamVault origin (page context) with `credentials: include`, which receives your session cookie. Use HTTPS in production.
- For local development over HTTP, enable "Allow HTTP (dev)" in Options to permit non-HTTPS Base URLs and origin permissions.

Install (Unpacked)
1. In Chrome, open `chrome://extensions` and enable Developer Mode.
2. Click "Load unpacked" and select the `browser-extension` folder.
3. Click the extension icon and open Options to set your TeamVault Base URL (e.g. `https://vault.example.com`).
4. Click "Sign in" to authenticate in a new tab. When done, return to the popup.
5. If you later change the Base URL, the extension clears cached suggestions/search results, resets auth state, and may prompt again for host permissions.

Usage
- Navigate to a login page.
- Use the inline button:
  - Click the small "TV" button near the password field to fill the best match.
  - Long‑press the "TV" button to pick among the top matches.
- Or use the popup:
  - Click the extension icon: you’ll see auto-searched results for the site and a search box.
  - Actions: Fill, Fill + Submit, Copy pass, Copy user, OTP, Pin/Unpin.
  - Keyboard: Up/Down to move selection. Enter to Fill. Hold Shift/Ctrl/⌘ to Fill + Submit.
  - Click the secret name to open it in TeamVault; click the URL to open the site.
  - Use the 🔥/💤 button in the header to view and refresh the pre-warm cache for the current site.

Permissions
- Host permission is requested only for your TeamVault origin (approve via Options → Grant site permission, or from the popup when prompted). By default, HTTP origins are blocked unless you enable "Allow HTTP (dev)".
- The extension uses `storage` for settings, `tabs`/`scripting` for messaging/injection, and `cookies` for cookie-aware auth refresh scheduling.
- If you enable pre‑warming, the extension may fetch suggestions for the active site in the background. You can restrict this globally or per‑site.

Notes
- Only GET API endpoints are used (no secret creation/deletion). CSRF is not required.
- Matching uses the secret `url` field; the popup auto-searches by hostname and treats `www.` as equivalent to the bare domain.
- You can disable the inline button or change the theme in Options.
 - Per‑site settings (Options): override auto‑submit and inline button for the active site.

import * as bootstrap from 'bootstrap';
import htmx from 'htmx.org';
import {scrollIfNeeded} from '../utils';

// Must match SEARCH_THRESHOLD in secrets/views.py
const SEARCH_THRESHOLD = 3;

export function initSearch() {
  const searchModal = document.getElementById('search-modal');
  if (!searchModal) return;

  const searchModalInput = document.getElementById('search-modal-input');
  const searchModalResults = document.getElementById('search-modal-results');
  const searchIndicator = document.getElementById('search-indicator');
  let selected = null;

  function select(item) {
    selected?.setAttribute('aria-selected', 'false');
    selected = item;
    if (item) {
      item.setAttribute('aria-selected', 'true');
      searchModalInput.setAttribute('aria-activedescendant', item.id);
      scrollIfNeeded(item, searchModalResults);
    } else {
      searchModalInput.removeAttribute('aria-activedescendant');
    }
  }

  searchModal.addEventListener('shown.bs.modal', () => {
    searchModalInput.focus();
    if (searchModalInput.value) {
      const searchTermLen = searchModalInput.value.length;
      searchModalInput.setSelectionRange(searchTermLen, searchTermLen);
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      bootstrap.Modal.getOrCreateInstance(searchModal).show();
    }
  });

  const isSearchable = () => searchModalInput.value.trim().length >= SEARCH_THRESHOLD;

  // A request that is still running belongs to an outdated query, even when the new
  // query is too short to send a request of its own.
  // The indicator is toggled after the abort, whose cleanup removes it.
  searchModalInput.addEventListener('input', () => {
    htmx.trigger(searchModalInput, 'htmx:abort');
    searchIndicator.classList.toggle('htmx-request', isSearchable());
  });

  searchModalInput.addEventListener('htmx:confirm', (e) => {
    if (isSearchable()) return;
    e.preventDefault();
    searchModalResults.replaceChildren();
    select(null);
  });

  searchModalResults.addEventListener('htmx:afterSwap', () => select(null));

  searchModalInput.addEventListener('keydown', (e) => {
    const items = [...searchModalResults.querySelectorAll('[role="option"]')];
    const index = items.indexOf(selected);
    if (e.key === 'ArrowDown' && items.length) {
      e.preventDefault();
      select(items[(index + 1) % items.length]);
    } else if (e.key === 'ArrowUp' && items.length) {
      e.preventDefault();
      select(items[index <= 0 ? items.length - 1 : index - 1]);
    } else if (e.key === 'Enter' && selected) {
      e.preventDefault();
      window.location.assign(selected.href);
    }
  });
}

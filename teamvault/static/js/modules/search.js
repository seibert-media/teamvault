import autoCompleteJS from '@tarekraafat/autocomplete.js';
import DOMPurify from 'dompurify';
import * as bootstrap from 'bootstrap';
import {scrollIfNeeded} from '../utils';

const SEARCH_ITEM_HTML = `<div class="col-auto me-1"><i class="fa fa-fw" data-search-icon></i></div>
<div class="col-10 search-modal-result-content">
    <span class="search-modal-result-content-title text-truncate" data-search-title></span>
    <span class="search-modal-result-content-extras text-muted" data-search-meta></span>
</div>
<div class="col-1 search-modal-result-action align-items-center">
    <i class="fa-solid fa-arrow-up-right-from-square search-modal-result-action-link p-2 rounded-5"></i>
</div>`;

const AUTOCOMPLETE_THRESHOLD = 3;
const AUTOCOMPLETE_DEBOUNCE = 500;

const ALLOWED_ICONS = new Set([
  'user',
  'file',
  'credit-card',
  'lock',
  'lock-open',
]);

function sanitizeIcon(icon) {
  return ALLOWED_ICONS.has(icon) ? icon : 'lock';
}

export function initSearch() {
  const searchModal = document.getElementById('search-modal');
  if (!searchModal) return;

  const searchUrl = searchModal.dataset.searchUrl;
  if (!searchUrl) return;

  const searchIndicator = document.getElementById('search-indicator');
  const searchModalFooter = document.getElementById('search-modal-footer');
  const searchModalResults = document.getElementById('search-modal-results');
  const searchResultCountLink = document.getElementById('search-modal-result-count-link');
  const searchResultCountSpan = document.getElementById('search-modal-result-count');

  // Track original data from API response
  let originalData = null;

  searchModal.addEventListener('shown.bs.modal', () => {
    const searchModalInput = document.getElementById('search-modal-input');
    searchModalInput.focus();
    if (searchModalInput.value) {
      const searchTermLen = searchModalInput.value.length;
      searchModalInput.setSelectionRange(searchTermLen, searchTermLen);
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      bootstrap.Modal.getOrCreateInstance('#search-modal').show();
    }
  });

  const autoComplete = new autoCompleteJS({
    name: 'secretSearchAutoComplete',
    data: {
      src: async (query) => {
        try {
          const source = await fetch(`${searchUrl}?q=${query}`);
          originalData = await source.json();
          return originalData.results;
        } catch (error) {
          return error;
        }
      },
      cache: false,
    },
    query: (input) => {
      return DOMPurify.sanitize(input);
    },
    selector: '#search-modal-input',
    threshold: AUTOCOMPLETE_THRESHOLD,
    debounce: AUTOCOMPLETE_DEBOUNCE,
    searchEngine: (query, record) => {
      return record;
    },
    wrapper: false,
    resultsList: {
      class: 'list-group px-2',
      destination: '#search-modal-results',
      position: 'afterbegin',
      element: (list, data) => {
        if (data.results.length > 0) {
          searchResultCountSpan.innerHTML = `Displaying <strong>${data.results.length}</strong> out of <strong>${originalData.count}</strong> results`;
        } else {
          searchResultCountSpan.innerHTML = `Found <strong>${data.matches.length}</strong> matching results for <strong>"${DOMPurify.sanitize(data.query)}"</strong>`;
        }
        searchModalFooter.style.display = 'block';

        let url = new URL(searchResultCountLink.href);
        url.searchParams.set('search', DOMPurify.sanitize(data.query));
        searchResultCountLink.href = url.href;
      },
      maxResults: undefined,
      noResults: true,
      tag: 'div',
    },
    resultItem: {
      class: 'list-group-item list-group-item-action d-flex justify-content-between align-items-center py-3',
      element: (item, data) => {
        item.href = data.value.url;
        item.innerHTML = SEARCH_ITEM_HTML;
        const iconEl = item.querySelector('[data-search-icon]');
        const titleEl = item.querySelector('[data-search-title]');
        const metaEl = item.querySelector('[data-search-meta]');

        iconEl.classList.add(`fa-${sanitizeIcon(data.value.icon)}`);
        titleEl.textContent = data.value.name ?? '';
        metaEl.textContent = data.value.meta ?? '';
        if (data.value.locked) {
          item.querySelector('.search-modal-result-action').insertAdjacentHTML(
            'afterbegin',
            '<i class="fa fa-lock fa-fw text-danger"></i>',
          );
        }
      },
      highlight: 'autoComplete_highlight',
      selected: 'autoComplete_selected',
      tag: 'a',
    },
    submit: true,
    events: {
      input: {
        input: (event) => {
          setTimeout(() => {
            autoComplete.start();
            if (event.target.value.length >= AUTOCOMPLETE_THRESHOLD) {
              searchIndicator.style.visibility = 'visible';
            }
          }, AUTOCOMPLETE_DEBOUNCE);
        },
        close: () => {
          searchModalResults.style.display = 'none';
          searchModalFooter.style.display = 'none';
        },
        selection: (event) => {
          autoComplete.input.blur();
          bootstrap.Modal.getInstance('#search-modal').hide();
          const feedback = event.detail;
          window.location.replace(feedback.selection.value['url']);
        },
        blur: (event) => {
          event.preventDefault();
        },
        response: () => {
          searchIndicator.style.visibility = 'hidden';
        },
        results: () => {
          searchModalResults.style.display = 'block';
        },
        navigate: (event) => {
          let el = searchModalResults.querySelector(`#autoComplete_result_${event.detail.selection.index}`);
          scrollIfNeeded(el, searchModalResults);
        },
      },
    },
  });
}

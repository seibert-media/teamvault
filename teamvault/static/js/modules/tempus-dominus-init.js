// Lazy-loads @eonasdan/tempus-dominus (~190 KB) on pages that may
// render a date picker. Currently only secret-detail uses this — the
// share modal's "expires on" picker. Imported by entries/secret-detail
// so the chunk download fires the moment the page's JS evaluates, in
// parallel with the htmx GET that swaps the share modal content in.
//
// Templates mark the picker root with `data-td-picker`; this module
// finds those roots after they appear in the DOM (initial load, htmx
// swaps, modal show) and initializes the picker exactly once per
// element.
//
// To add a new date picker:
//   1. Render an element with `data-td-picker` (typically the
//      tempus-dominus root div).
//   2. Make sure the element appears via one of the supported insertion
//      paths: present at DOMContentLoaded, swapped in by htmx, or shown
//      inside a Bootstrap modal. Other insertion paths require an
//      explicit `initIn(root)` call.
//   3. If a new entry needs date pickers, import + call
//      `initTempusDominus()` from that entry as well.

const tdReady = import(/* webpackChunkName: "tempus-dominus" */ '@eonasdan/tempus-dominus').then(m => m.TempusDominus);

const tdOptions = {
  display: {
    buttons: {
      clear: true,
      close: true,
    },
    icons: {
      time: 'fa fa-clock',
      date: 'fa fa-calendar',
      up: 'fa fa-arrow-up',
      down: 'fa fa-arrow-down',
      previous: 'fa fa-chevron-left',
      next: 'fa fa-chevron-right',
      today: 'fa fa-calendar-check',
      clear: 'fa fa-trash',
      close: 'fa fa-times-circle',
    },
  },
  localization: {
    format: 'yyyy-MM-dd HH:mm',
  },
};

async function initIn(root) {
  const els = root.querySelectorAll('[data-td-picker]:not([data-td-initialized])');
  if (!els.length) return;
  const TempusDominus = await tdReady;
  for (const el of els) {
    new TempusDominus(el, tdOptions);
    el.dataset.tdInitialized = 'true';
  }
}

export function initTempusDominus() {
  document.addEventListener('DOMContentLoaded', () => initIn(document));
  document.body.addEventListener('htmx:afterSwap', e => initIn(e.target));
  document.body.addEventListener('shown.bs.modal', e => initIn(e.target));
}

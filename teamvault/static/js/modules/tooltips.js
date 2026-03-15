import * as bootstrap from 'bootstrap';

const tooltipOptions = {container: 'body', html: true, trigger: 'hover'};

function refreshTooltips() {
  const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  [...tooltipTriggerList].map(el => bootstrap.Tooltip.getOrCreateInstance(el, tooltipOptions));
}

export function initTooltips() {
  document.addEventListener('htmx:load', () => {
    refreshTooltips();
  });
}

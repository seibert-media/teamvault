import {Notyf} from 'notyf';
import 'notyf/notyf.min.css';

let notyf;

function triggerNotyf(type, message) {
  notyf.open({
    dismissible: true,
    message: message,
    type: type,
  });
}

export function initNotifications() {
  notyf = new Notyf({position: {x: 'right', y: 'top'}});
  // Keep global for HTMX-loaded scripts (e.g. share_list_modal.html)
  window.notyf = notyf;

  // Process Django messages passed via data attribute
  const messagesEl = document.querySelector('[data-django-messages]');
  if (messagesEl) {
    try {
      const messages = JSON.parse(messagesEl.dataset.djangoMessages);
      for (const msg of messages) {
        triggerNotyf(msg.type, msg.message);
      }
    } catch (e) {
      // Ignore malformed message data
    }
  }

  // Listen for htmx message events
  document.addEventListener('django.contrib.messages', event => {
    for (const msg of event.detail.message_list) {
      triggerNotyf(msg.level, msg.message);
    }
  });
}

import $ from 'jquery';
import * as bootstrap from 'bootstrap';
import {getColorfulPasswordHTML} from '../utils';

let shouldShowModal;
let changeSecretModal;

export function initReveal(config) {
  const secretUrl = config.dataset.secretUrl;
  const placeholder = config.dataset.placeholder;
  shouldShowModal = config.dataset.showPasswordUpdateAlert === 'true';
  const hideTooltip = config.dataset.hideTooltip;
  const revealTooltip = config.dataset.revealTooltip;

  const changeSecretProgressBar = document.getElementById('changeSecretProgressBar');
  const changeSecretModalContinueButton = document.getElementById('changeSecretModalContinueButton');
  const needsChangingWaitingTime = 5;

  function getSecret(callback) {
    if (shouldShowModal) {
      showModal();
    } else {
      $.ajax({
        url: secretUrl,
        type: 'get',
        dataType: 'json',
        success: function (data) {
          callback(data['password']);
        },
      });
    }
  }

  function getSecretSync() {
    let secret;
    $.ajax({
      url: secretUrl,
      async: false,
      type: 'get',
      dataType: 'json',
      success: function (data) {
        secret = data;
      },
    });
    return secret;
  }

  function reveal(password) {
    const revBtnTooltip = bootstrap.Tooltip.getInstance('#revealButton');
    revBtnTooltip.setContent({'.tooltip-inner': hideTooltip});

    const revBtn = document.getElementById('revealButton');
    revBtn.querySelector('i').classList.remove('fa-magic');
    revBtn.querySelector('i').classList.add('fa-shield');

    const passwordField = document.getElementById('password-field');
    const passwordHTML = getColorfulPasswordHTML(password);
    passwordField.replaceChildren(...passwordHTML);

    // Switch handler to unreveal
    revBtn.onclick = () => unreveal();
  }

  function unreveal() {
    const revBtnTooltip = bootstrap.Tooltip.getInstance('#revealButton');
    revBtnTooltip.setContent({'.tooltip-inner': revealTooltip});

    const revBtn = document.getElementById('revealButton');
    revBtn.querySelector('i').classList.remove('fa-shield');
    revBtn.querySelector('i').classList.add('fa-magic');

    const passwordField = document.getElementById('password-field');
    passwordField.replaceChildren(document.createTextNode(placeholder));

    // Switch handler back to reveal
    revBtn.onclick = () => getSecret(reveal);
  }

  function initProgressBar() {
    changeSecretProgressBar.animate(
      {width: ['0%', '100%']},
      {duration: needsChangingWaitingTime * 1000, fill: 'forwards'}
    );
  }

  function showModal() {
    changeSecretModal = new bootstrap.Modal('#changeSecretModal');
    changeSecretModal.show();

    initProgressBar();
    window.setTimeout(
      () => {
        changeSecretModalContinueButton.style.display = '';
        changeSecretProgressBar.parentElement.remove();
      },
      needsChangingWaitingTime * 1000
    );
    shouldShowModal = false;
  }

  function closeModal() {
    changeSecretModal.hide();
    document.getElementById('copy-password').onclick = null;
    setUpPasswordClipboard();
  }

  if (changeSecretModalContinueButton) {
    changeSecretModalContinueButton.addEventListener('click', closeModal);
  }

  // Set up the initial reveal button handler
  const revealButton = document.getElementById('revealButton');
  if (revealButton) {
    revealButton.onclick = () => getSecret(reveal);
  }

  // Expose for use by other modules
  return {getSecret, getSecretSync, reveal, showModal, shouldShowModal: () => shouldShowModal};
}

function setUpPasswordClipboard() {
  // This is set up by the clipboard module
}

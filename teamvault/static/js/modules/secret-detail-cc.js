import ClipboardJS from 'clipboard';
import Card from 'card';
import 'card/lib/card.css';

export function init(config, revealApi) {
  const validDateText = config.dataset.ccValidDate;
  const monthYearText = config.dataset.ccMonthYear;
  const fullNameText = config.dataset.ccFullName;
  const codeMessage = config.dataset.ccCodeCopied;
  const passwordMessage = config.dataset.ccPasswordCopied;
  const revealText = config.dataset.ccRevealText;
  const hideText = config.dataset.ccHideText;

  function initializeCreditCard() {
    const el = document.querySelector('.card-wrapper');
    el.card = new Card({
      form: '#ccform',
      container: '.card-wrapper',
      formSelectors: {
        numberInput: 'input#id_number',
        expiryInput: 'input#id_expiration_month, input#id_expiration_year',
        cvcInput: 'input#id_security_code',
        nameInput: 'input#id_holder',
      },
      messages: {
        validDate: validDateText,
        monthYear: monthYearText,
      },
      formatting: true,
      placeholders: {
        number: '\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022',
        name: fullNameText,
        expiry: '\u2022\u2022/\u2022\u2022\u2022\u2022',
        cvc: '\u2022\u2022\u2022',
      },
    });
  }

  function clearCreditCard() {
    const el = document.querySelector('.card-wrapper');
    el.innerHTML = '';
    el.card.render();
  }

  function fillCreditCard(number, name, expirationMonth, expirationYear) {
    const numEl = document.querySelector('.jp-card-number');
    const nameEl = document.querySelector('.jp-card-name');
    const expiryEl = document.querySelector('.jp-card-expiry');
    numEl.innerHTML = number;
    nameEl.innerHTML = name;
    expiryEl.innerHTML = expirationMonth + '/' + expirationYear;
  }

  let ccCodeClipboard;
  let ccPasswordClipboard;
  let revealToggled = false;

  function initializeClipboards() {
    ccCodeClipboard = new ClipboardJS('#copy-ccCode').on('success', function (e) {
      e.clearSelection();
      window.notyf.success(codeMessage);
    });

    ccPasswordClipboard = new ClipboardJS('#copy-ccPassword').on('success', function (e) {
      e.clearSelection();
      window.notyf.success(passwordMessage);
    });
  }

  function toggleReveal() {
    const revealBtn = document.getElementById('revealButton');
    const revealBtnSpan = revealBtn.querySelector('span');
    const revealBtnIcon = revealBtn.querySelector('i');

    if (revealToggled) {
      revealBtnSpan.textContent = revealText;
      revealBtnIcon.classList.remove('fa-shield');
      revealBtnIcon.classList.add('fa-magic');

      clearCreditCard();
      document.getElementById('id_security_code').value = '';
      document.getElementById('id_password').value = '';
      document.getElementById('copy-ccCode').disabled = true;
      document.getElementById('copy-ccPassword').disabled = true;
      revealToggled = false;

      ccCodeClipboard.destroy();
      ccPasswordClipboard.destroy();
    } else {
      const data = revealApi.getSecretSync();
      revealBtnSpan.textContent = hideText;
      revealBtnIcon.classList.remove('fa-magic');
      revealBtnIcon.classList.add('fa-shield');
      fillCreditCard(data['number'], data['holder'], data['expiration_month'], data['expiration_year']);

      document.getElementById('id_security_code').value = data['security_code'];
      document.getElementById('id_password').value = data['password'];
      document.getElementById('copy-ccCode').disabled = false;
      document.getElementById('copy-ccPassword').disabled = false;

      initializeClipboards();
      revealToggled = true;
    }
  }

  document.getElementById('copy-ccCode').disabled = true;
  document.getElementById('copy-ccPassword').disabled = true;
  initializeCreditCard();

  // Set up toggle button
  const revealButton = document.getElementById('revealButton');
  if (revealButton) {
    revealButton.onclick = toggleReveal;
  }
}

export function init(config) {
  const Card = require('card');

  const validDateText = config.dataset.ccValidDate;
  const monthYearText = config.dataset.ccMonthYear;
  const fullNameText = config.dataset.ccFullName;

  new Card({
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
    placeholders: {
      number: '\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022',
      name: fullNameText,
      expiry: '\u2022\u2022/\u2022\u2022\u2022\u2022',
      cvc: '\u2022\u2022\u2022',
    },
  });

  // Automatically split card number input into separate blocks
  const ccNumberField = document.getElementById('id_number');
  ccNumberField.addEventListener('input', () => {
    const result = ccNumberField.value.match(/\d{1,4}/g) ?? [];
    ccNumberField.value = result.join(' ');
  });
}

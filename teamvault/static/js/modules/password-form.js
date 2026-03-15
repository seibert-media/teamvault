import * as bootstrap from 'bootstrap';
import {initZxcvbn} from '../zxcvbn.ts';

const zxcvbn = initZxcvbn();

export function init(config) {
  const generatePasswordUrl = config.dataset.generatePasswordUrl;
  const switchToQrTooltip = config.dataset.switchToQrTooltip;
  const switchToTextTooltip = config.dataset.switchToTextTooltip;
  const otpFieldId = config.dataset.otpFieldId;
  const otpKeyDataId = config.dataset.otpKeyDataId;

  const passwordField = document.getElementById('id_password');
  const passwordGeneratorField = document.getElementById('id_pwgen');
  const passwordStrengthField = document.getElementById('id_password_strength');
  const otpField = document.getElementById(otpFieldId);
  const otpKeyData = document.getElementById(otpKeyDataId);
  const typeBtn = document.getElementById('key-input-type');

  passwordField.generated = false;

  function ratePassword() {
    let score = zxcvbn(passwordField.value.toString()).score + 1;
    let color = 'text-warning-bright';
    if (!passwordField.value) {
      color = 'text-muted';
      score = 0;
    } else if (score <= 2) {
      color = 'text-danger-bright';
    } else if (score === 5) {
      color = 'text-success-bright';
    }
    const filledStar = `<i class='fas fa-star ${color}'></i>`;
    const hollowStar = `<i class='far fa-star ${color}'></i>`;
    passwordStrengthField.innerHTML = filledStar.repeat(score) + hollowStar.repeat(5 - score);
  }

  async function generatePassword() {
    const source = await fetch(generatePasswordUrl);
    return source.json();
  }

  function keyInputText() {
    const typeBtnTooltip = bootstrap.Tooltip.getInstance('#key-input-type');
    typeBtnTooltip.setContent({
      '.tooltip-inner': switchToTextTooltip,
    });

    typeBtn.querySelector('i').classList.remove('fa-qrcode');
    typeBtn.querySelector('i').classList.add('fa-keyboard');
    otpField.title = 'Enter OTP key as QR image or paste from clipboard';
    otpField.type = 'file';
  }

  function keyInputQr() {
    const typeBtnTooltip = bootstrap.Tooltip.getInstance('#key-input-type');
    typeBtnTooltip.setContent({
      '.tooltip-inner': switchToQrTooltip,
    });
    typeBtn.querySelector('i').classList.remove('fa-keyboard');
    typeBtn.querySelector('i').classList.add('fa-qrcode');
    otpField.title = 'Enter OTP secret key manually';
    otpField.type = 'text';
  }

  document.addEventListener('paste', e => {
    if (otpField.type === 'file') {
      otpField.files = e.clipboardData.files;
      otpField.dispatchEvent(new Event('change'));
    }
  });

  document.addEventListener('submit', () => {
    if (otpField.value && !otpKeyData.value) {
      let data = otpField.value;
      if (!data.includes('?secret=')) {
        data = '?secret=' + data + '&';
      }
      if (!data.includes('digits=')) {
        data += 'digits=6&';
      }
      if (!data.includes('algorithm=')) {
        data += 'algorithm=SHA1&';
      }
      otpKeyData.value = data;
    }
  });

  ratePassword();

  otpField.addEventListener('change', () => {
    if (otpField.type !== 'file') {
      return;
    }
    const file = otpField.files[0];
    if (!file) {
      return;
    }
    const qrScanner = require('jsqr');
    const reader = new FileReader();
    reader.onload = function (event) {
      const img = new Image();
      img.onload = function () {
        const canvas = document.getElementById('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.fillStyle = 'rgb(255, 255, 255)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        try {
          const code = qrScanner(imageData.data, imageData.width, imageData.height);
          keyInputQr();
          let data = new URL(code.data.toString());
          otpKeyData.value = data;
          otpField.value = data.searchParams.get('secret');
        } catch (e) {
          keyInputText();
          window.notyf.error('Error. No QR code found. Please try again.');
        }
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  });

  passwordField.addEventListener('keyup', () => {
    ratePassword();
    passwordField.generated = false;
    setTimeout(function () {
      if (!passwordField.generated) {
        passwordField.type = 'password';
      }
    }, 2000);
  });

  passwordGeneratorField.addEventListener('focusout', () => {
    setTimeout(function () {
      if (document.activeElement !== passwordField) {
        passwordField.type = 'password';
      }
    }, 1000);
  });

  passwordGeneratorField.addEventListener('click', async () => {
    passwordField.value = await generatePassword();
    ratePassword();
    passwordField.type = 'text';
    passwordField.generated = true;
  });

  typeBtn.addEventListener('click', () => {
    if (otpField.type === 'file') {
      keyInputQr();
    } else {
      keyInputText();
    }
  });
}

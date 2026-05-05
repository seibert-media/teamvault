import * as bootstrap from 'bootstrap';

// zxcvbn dictionaries (~1.6 MB) and the jsqr QR scanner (~250 KB) start
// downloading the moment this module evaluates — the secret-addedit
// entry imports this file, so the fetch begins as soon as the page's
// JS runs, in parallel with everything else. Use sites await the saved
// promise so first interaction never waits on network.
const zxcvbnReady = import(/* webpackChunkName: "zxcvbn" */ '../zxcvbn.ts').then(m => m.initZxcvbn());
const jsqrReady = import(/* webpackChunkName: "jsqr" */ 'jsqr').then(m => m.default);

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

  async function ratePassword() {
    let score = 0;
    let color = 'text-muted';
    if (passwordField.value) {
      const zxcvbn = await zxcvbnReady;
      // Re-check after the await: the user may have cleared the field
      // while the zxcvbn chunk was still downloading.
      if (passwordField.value) {
        score = zxcvbn(passwordField.value.toString()).score + 1;
        if (score <= 2) {
          color = 'text-danger-bright';
        } else if (score === 5) {
          color = 'text-success-bright';
        } else {
          color = 'text-warning-bright';
        }
      }
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

  let qrDecodePending = false;

  document.addEventListener('submit', e => {
    // Only intervene for submits of the form that owns the OTP field.
    // Don't preventDefault on unrelated forms (e.g. nav search).
    if (!e.target.contains(otpField)) {
      return;
    }
    if (qrDecodePending) {
      // QR scanner chunk or decode still in flight; otpField.value is
      // the file-input pseudo-path right now, not a usable OTP secret.
      e.preventDefault();
      window.notyf.error('Still decoding QR code, please try again.');
      return;
    }
    if (otpField.type !== 'text') {
      return;
    }
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

  otpField.addEventListener('change', async () => {
    if (otpField.type !== 'file') {
      return;
    }
    const file = otpField.files[0];
    if (!file) {
      return;
    }
    qrDecodePending = true;
    try {
      const qrScanner = await jsqrReady;
      // Wrap the FileReader/Image chain in a promise so the
      // qrDecodePending flag covers the entire async pipeline, not
      // just the jsqr chunk download.
      await new Promise(resolve => {
        const reader = new FileReader();
        reader.onerror = () => resolve();
        reader.onload = function (event) {
          const img = new Image();
          img.onerror = () => resolve();
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
            resolve();
          };
          img.src = event.target.result;
        };
        reader.readAsDataURL(file);
      });
    } finally {
      qrDecodePending = false;
    }
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

import {getColorfulPasswordHTML} from '../utils';
import {otpCountdown} from '../otp';

function fitText(container) {
  const maxWidth = container.offsetWidth;
  const maxFontSize = 528;
  // Only resize text lines, not the countdown timer
  const targets = container.querySelectorAll(':scope > .lt-password:not(.invisible), :scope > .lt-otp:not(.invisible)');

  for (const target of targets) {
    // Clone single element off-screen for measurement
    const clone = target.cloneNode(true);
    clone.style.cssText = 'position:absolute;left:-9999px;top:-9999px;white-space:nowrap;display:block;float:left;';
    document.body.appendChild(clone);

    const baseFontSize = parseFloat(getComputedStyle(clone).fontSize) || 16;
    const baseWidth = clone.offsetWidth;
    if (baseWidth === 0) { clone.remove(); continue; }

    const ratio = baseWidth / baseFontSize;
    let fontSize = Math.floor(maxWidth / ratio) - 2;
    fontSize = Math.min(fontSize, maxFontSize);
    fontSize = Math.max(fontSize, 1);

    // Refine: increase until we overshoot, then back off
    clone.style.fontSize = fontSize + 'px';
    while (clone.offsetWidth < maxWidth && fontSize < maxFontSize) {
      fontSize++;
      clone.style.fontSize = fontSize + 'px';
    }
    if (clone.offsetWidth > maxWidth) {
      fontSize--;
    }

    clone.remove();
    target.style.fontSize = fontSize + 'px';
    target.style.whiteSpace = 'nowrap';
  }
}

export function init(config, revealApi) {
  const secretUrl = config.dataset.secretUrl;
  const otpEnabled = config.dataset.otpEnabled === 'true';

  const largeTypeElement = document.querySelector('.large-type');
  const largeTypePassword = document.querySelector('.lt-password');
  const largeTypeOTPCountdown = document.querySelector('.lt-otp-countdown');
  const largeTypeOTP = document.querySelector('.lt-otp');

  function largeType(data, type = 'password', otpCountdownField = null) {
    if (type === 'password') {
      largeTypePassword.classList.remove('invisible');
      const largeTypeHTML = getColorfulPasswordHTML(data);
      largeTypePassword.append(...largeTypeHTML);
    } else {
      largeTypeOTPCountdown.classList.remove('invisible');
      largeTypeOTP.classList.remove('invisible');
      largeTypeOTPCountdown.innerHTML = otpCountdownField;
      largeTypeOTP.innerHTML = data.replace('mx-1', 'mx-3');
      otpCountdown(
        largeTypeOTPCountdown.children[0],
        largeTypeOTPCountdown.children[0].children[0],
        largeTypeOTP,
        secretUrl,
        largeTypeElement
      );
    }
    largeTypeElement.classList.remove('invisible');
    fitText(largeTypeElement);
  }

  // Large type button for OTP
  if (otpEnabled) {
    const largeTypeButtonOtp = document.getElementById('large-type-button-otp');
    if (largeTypeButtonOtp) {
      largeTypeButtonOtp.addEventListener('click', () => {
        largeType(
          document.getElementById('otp-field').innerHTML,
          'otp',
          document.getElementById('countdown').outerHTML
        );
      });
    }
  }

  // Click on large type overlay to dismiss
  if (largeTypeElement) {
    largeTypeElement.addEventListener('mousedown', () => {
      [largeTypeElement, largeTypePassword, largeTypeOTPCountdown, largeTypeOTP].forEach(el => el.classList.add('invisible'));
      [largeTypePassword, largeTypeOTPCountdown, largeTypeOTP].forEach(el => el.innerHTML = '');
    });
  }

  // Large type button for password
  const largeTypePasswordBtn = document.querySelector('[data-action="large-type-password"]');
  if (largeTypePasswordBtn) {
    largeTypePasswordBtn.addEventListener('click', () => {
      revealApi.getSecret((password) => largeType(password, 'password'));
    });
  }
}

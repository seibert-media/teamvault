import {getColorfulPasswordHTML} from '../utils';
import {otpCountdown} from '../otp';
import $ from 'jquery';

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

    // TODO: Replace bigtext with something non-jquery
    $('.large-type').bigtext();
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

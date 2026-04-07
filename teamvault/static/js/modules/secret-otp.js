import {refreshOtpEvery30Sec, otpCountdown} from '../otp';

export function initOtp(secretUrl) {
  const textElement = document.getElementById('otp-field');
  const countdownContainerEl = document.getElementById('countdown');
  const countdownNumberEl = document.getElementById('countdown-number');
  const bigElement = document.querySelector('.large-type');

  if (!textElement || !countdownContainerEl || !countdownNumberEl || !bigElement) return;

  refreshOtpEvery30Sec(textElement, secretUrl, bigElement);
  otpCountdown(countdownContainerEl, countdownNumberEl, textElement, secretUrl, bigElement);
  setInterval(() => {
    otpCountdown(
      countdownContainerEl, countdownNumberEl,
      textElement, secretUrl,
      bigElement);
  }, 1_000);
}

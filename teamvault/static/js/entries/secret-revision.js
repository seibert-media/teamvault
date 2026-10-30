import {initOtp} from '../modules/secret-otp';

document.addEventListener('DOMContentLoaded', () => {
  const config = document.getElementById('secret-revision-config');
  if (config?.dataset.otpEnabled === 'true') {
    initOtp(config.dataset.secretUrl);
  }
});

import {initReveal} from '../modules/secret-reveal';
import {setUpPasswordClipboard, setUpOtpClipboard, setUpAdditionalClipboards} from '../modules/secret-clipboard';
import {initOtp} from '../modules/secret-otp';
import * as bootstrap from 'bootstrap';

document.addEventListener('DOMContentLoaded', () => {
  const config = document.getElementById('secret-detail-config');
  if (!config) return;

  const contentType = config.dataset.contentType;
  const secretUrl = config.dataset.secretUrl;
  const otpEnabled = config.dataset.otpEnabled === 'true';
  const suAccess = config.dataset.suAccess === 'true';

  // Initialize the reveal API (shared between password and CC detail pages)
  const revealApi = initReveal(config);

  if (contentType === 'password') {
    // Set up clipboards
    setUpAdditionalClipboards(
      config.dataset.urlCopied,
      config.dataset.usernameCopied
    );

    if (revealApi.shouldShowModal()) {
      // When modal is needed, show it on clipboard button clicks
      const copyPassword = document.getElementById('copy-password');
      if (copyPassword) {
        copyPassword.addEventListener('click', () => revealApi.showModal());
      }
      const copyOtp = document.getElementById('copy-otp');
      if (copyOtp) {
        copyOtp.addEventListener('click', () => revealApi.showModal());
      }
    } else {
      setUpPasswordClipboard(revealApi.getSecretSync, config.dataset.passwordCopied);
      if (otpEnabled) {
        setUpOtpClipboard(config.dataset.otpCopied);
      }
    }

    // OTP countdown
    if (otpEnabled) {
      initOtp(secretUrl);
    }

    // Password-specific features (large type, OTP button)
    import('../modules/secret-detail-password').then(m => m.init(config, revealApi));
  } else if (contentType === 'cc') {
    import('../modules/secret-detail-cc').then(m => m.init(config, revealApi));
  }

  // Superuser confirmation modal
  if (suAccess) {
    new bootstrap.Modal('#su-confirm-modal', {}).show();
  }
});

import {initReveal} from '../modules/secret-reveal';
import {setUpPasswordClipboard, setUpOtpClipboard, setUpAdditionalClipboards} from '../modules/secret-clipboard';
import {initOtp} from '../modules/secret-otp';
import {init as initPasswordDetail} from '../modules/secret-detail-password';
import {init as initCCDetail} from '../modules/secret-detail-cc';
import {initTempusDominus} from '../modules/tempus-dominus-init';
import * as bootstrap from 'bootstrap';

// Kick off the tempus-dominus chunk download immediately and register
// listeners that initialize the date picker once the share modal swaps in.
initTempusDominus();

document.addEventListener('DOMContentLoaded', () => {
  const config = document.getElementById('secret-detail-config');
  if (!config) return;

  const contentType = config.dataset.contentType;
  const secretUrl = config.dataset.secretUrl;
  const otpEnabled = config.dataset.otpEnabled === 'true';
  const suAccess = config.dataset.suAccess === 'true';

  function wireUpClipboards(revealApi) {
    setUpPasswordClipboard(revealApi.getSecretSync, config.dataset.passwordCopied);
    if (otpEnabled) {
      setUpOtpClipboard(config.dataset.otpCopied);
    }
  }

  if (contentType === 'password') {
    // Initialize reveal with modal close callback for clipboard wiring
    const revealApi = initReveal(config, {
      onModalClose: () => wireUpClipboards(revealApi),
    });

    // Set up clipboards
    setUpAdditionalClipboards(
      config.dataset.urlCopied,
      config.dataset.usernameCopied
    );

    if (revealApi.shouldShowModal()) {
      // When modal is needed, show it on clipboard button clicks
      const copyPassword = document.getElementById('copy-password');
      if (copyPassword) {
        copyPassword.onclick = () => revealApi.showModal();
      }
      const copyOtp = document.getElementById('copy-otp');
      if (copyOtp) {
        copyOtp.onclick = () => revealApi.showModal();
      }
    } else {
      wireUpClipboards(revealApi);
    }

    // OTP countdown
    if (otpEnabled) {
      initOtp(secretUrl);
    }

    // Password-specific features (large type, OTP button)
    initPasswordDetail(config, revealApi);
  } else if (contentType === 'cc') {
    const revealApi = initReveal(config);
    initCCDetail(config, revealApi);
  }

  // Superuser confirmation modal
  if (suAccess) {
    new bootstrap.Modal('#su-confirm-modal', {}).show();
  }
});

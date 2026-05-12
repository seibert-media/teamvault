import {initAddeditCommon} from '../modules/addedit-common';
import {init as initPasswordForm} from '../modules/password-form';
import {init as initCCForm} from '../modules/cc-form';
import {init as initFileForm} from '../modules/file-form';

document.addEventListener('DOMContentLoaded', () => {
  const config = document.getElementById('secret-addedit-config');
  if (!config) return;

  initAddeditCommon(config);

  const contentType = config.dataset.contentType;
  if (contentType === 'password') {
    initPasswordForm(config);
  } else if (contentType === 'cc') {
    initCCForm(config);
  } else if (contentType === 'file') {
    initFileForm();
  }
});

import {initAddeditCommon} from '../modules/addedit-common';

document.addEventListener('DOMContentLoaded', () => {
  const config = document.getElementById('secret-addedit-config');
  if (!config) return;

  initAddeditCommon(config);

  const contentType = config.dataset.contentType;
  if (contentType === 'password') {
    import('../modules/password-form').then(m => m.init(config));
  } else if (contentType === 'cc') {
    import('../modules/cc-form').then(m => m.init(config));
  } else if (contentType === 'file') {
    import('../modules/file-form').then(m => m.init());
  }
});

import ClipboardJS from 'clipboard';

export function setUpPasswordClipboard(getSecretSync, successMessage) {
  new ClipboardJS('#copy-password', {
    text: function () {
      return getSecretSync()['password'];
    },
  }).on('success', function (e) {
    e.clearSelection();
    window.notyf.success(successMessage);
  });
}

export function setUpOtpClipboard(successMessage) {
  new ClipboardJS('#copy-otp', {
    text: function () {
      return document.getElementById('otp-field').textContent;
    },
  }).on('success', function (e) {
    e.clearSelection();
    window.notyf.success(successMessage);
  });
}

export function setUpAdditionalClipboards(urlMessage, usernameMessage) {
  const copyUrl = document.getElementById('copy-url');
  if (copyUrl) {
    new ClipboardJS('#copy-url').on('success', function (e) {
      e.clearSelection();
      window.notyf.success(urlMessage);
    });
  }

  const copyUsername = document.getElementById('copy-username');
  if (copyUsername) {
    new ClipboardJS('#copy-username').on('success', function (e) {
      e.clearSelection();
      window.notyf.success(usernameMessage);
    });
  }
}

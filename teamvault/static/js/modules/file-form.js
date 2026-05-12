export function init() {
  const fileInput = document.getElementById('id_file');
  const fileNameInput = document.getElementById('file-text');
  if (!fileInput || !fileNameInput) return;

  fileInput.addEventListener('change', () => {
    fileNameInput.value = fileInput.files[0].name;
  });

  window.addEventListener('load', () => {
    // Set file name even after going back in browser history
    if (fileInput.files.length === 1) {
      fileNameInput.value = fileInput.files[0].name;
    }
  });
}

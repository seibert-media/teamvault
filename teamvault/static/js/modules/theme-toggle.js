function getSystemTheme() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function updateThemeIcon(isAuto, theme) {
  const icon = document.getElementById('theme-icon');
  const autoIcon = document.getElementById('theme-icon-auto');
  if (!icon || !autoIcon) return;

  if (isAuto) {
    icon.style.display = 'none';
    autoIcon.style.display = '';
  } else {
    autoIcon.style.display = 'none';
    icon.style.display = '';
    icon.classList.remove('fa-sun', 'fa-moon');
    icon.classList.add(theme === 'dark' ? 'fa-moon' : 'fa-sun');
  }
}

function toggleTheme() {
  const storedTheme = localStorage.getItem('theme');

  let newStoredTheme;
  if (!storedTheme || storedTheme === 'auto') {
    newStoredTheme = 'light';
  } else if (storedTheme === 'light') {
    newStoredTheme = 'dark';
  } else {
    newStoredTheme = 'auto';
  }

  if (newStoredTheme === 'auto') {
    localStorage.removeItem('theme');
    document.documentElement.setAttribute('data-bs-theme', getSystemTheme());
    updateThemeIcon(true);
  } else {
    localStorage.setItem('theme', newStoredTheme);
    document.documentElement.setAttribute('data-bs-theme', newStoredTheme);
    updateThemeIcon(false, newStoredTheme);
  }
}

export function initThemeToggle() {
  const storedTheme = localStorage.getItem('theme');
  const isAuto = !storedTheme || storedTheme === 'auto';
  if (isAuto) {
    updateThemeIcon(true);
  } else {
    updateThemeIcon(false, storedTheme);
  }

  const toggleButton = document.querySelector('[data-theme-toggle]');
  if (toggleButton) {
    toggleButton.addEventListener('click', toggleTheme);
  }
}

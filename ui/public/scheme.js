// Runs before the page paints. Reads the stored choice (auto, light or dark)
// and sets the attribute the theme listens to. If storage is blocked, the
// page follows the system setting.
(function () {
  var mode = 'system';
  try {
    mode = window.localStorage.getItem('ritueel-mode') || 'system';
  } catch (e) {
    mode = 'system';
  }
  var dark = mode === 'dark';
  if (mode !== 'dark' && mode !== 'light') {
    try {
      dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    } catch (e) {
      dark = false;
    }
  }
  // the attributes the MUI theme (colorSchemeSelector: 'data') listens to
  var root = document.documentElement;
  root.removeAttribute(dark ? 'data-light' : 'data-dark');
  root.setAttribute(dark ? 'data-dark' : 'data-light', '');
})();

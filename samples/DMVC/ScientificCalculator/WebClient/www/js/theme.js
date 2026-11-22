// Restores the saved theme before the first paint (loaded synchronously in <head>)
(function () {
  var theme = 'dark';
  try { theme = localStorage.getItem('calcweb-theme') || 'dark'; } catch (e) { /* storage blocked */ }
  document.documentElement.setAttribute('data-bs-theme', theme);
})();

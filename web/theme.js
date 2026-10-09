const themeKey = 'oopsie-theme';
function setTheme(value) {
  const theme = value === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  document.body.dataset.theme = theme;
  document.querySelectorAll('.theme-toggle').forEach(button => {
    button.setAttribute('aria-label', theme === 'dark' ? 'switch to light mode' : 'switch to dark mode');
    button.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
  });
}
try { setTheme(localStorage.getItem(themeKey)); } catch { setTheme('dark'); }
document.addEventListener('click', event => {
  if (!event.target.closest('.theme-toggle')) return;
  const next = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem(themeKey,next); } catch {}
  setTheme(next);
});
new MutationObserver(() => setTheme(document.body.dataset.theme)).observe(document.body,{childList:true,subtree:true});

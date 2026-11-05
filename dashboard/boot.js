/* Theme bootstrap. Runs synchronously in <head>, before the stylesheet is
   applied, so the first paint already uses the resolved light/dark theme.
   A stored explicit choice wins; otherwise the OS preference is followed. */
(function(){
  var PREF_KEY = "res-theme-pref";
  var pref = "system";
  try {
    var stored = localStorage.getItem(PREF_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") pref = stored;
  } catch(_) {}
  var dark = true;
  try {
    if (window.matchMedia) dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  } catch(_) {}
  var root = document.documentElement;
  root.setAttribute("data-theme-pref", pref);
  root.setAttribute("data-theme", pref === "system" ? (dark ? "dark" : "light") : pref);
})();

/* Headless-CI error probe: any uncaught error/rejection is mirrored into the
   DOM (data-js-errors + #js-errors) so `chrome --headless --dump-dom` can
   assert a clean render. */
window.__jsErrors = [];
function __reportJsError(msg){
  window.__jsErrors.push(String(msg));
  document.documentElement.setAttribute('data-js-errors', String(window.__jsErrors.length));
  var el = document.getElementById('js-errors');
  if (el) el.textContent = window.__jsErrors.join(' | ');
}
window.addEventListener('error', function(e){ __reportJsError(e.message || e.type); });
window.addEventListener('unhandledrejection', function(e){
  __reportJsError('promise: ' + (e.reason && e.reason.message || e.reason));
});

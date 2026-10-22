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

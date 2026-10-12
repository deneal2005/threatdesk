/**
 * ThreatDesk - Client-side interactions
 * Complies with strict CSP (no inline scripts).
 */
document.addEventListener('DOMContentLoaded', function() {
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      document.body.classList.remove('drawer-open');
    }
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      var s = document.getElementById('global-search');
      if (s) {
        e.preventDefault();
        s.focus();
        s.select();
      }
    }
  });
});

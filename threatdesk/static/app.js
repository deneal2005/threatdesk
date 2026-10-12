/**
 * ThreatDesk - Client-side interactions
 * Complies strictly with CSP (no inline scripts, no eval).
 */
document.addEventListener('DOMContentLoaded', function() {
  // Mobile drawer controls
  var drawerToggle = document.querySelector('.drawer-toggle');
  var drawerClose = document.querySelector('.drawer-close');
  var backdrop = document.querySelector('.sidebar-backdrop');

  if (drawerToggle) {
    drawerToggle.addEventListener('click', function() {
      document.body.classList.toggle('drawer-open');
    });
  }

  if (drawerClose) {
    drawerClose.addEventListener('click', function() {
      document.body.classList.remove('drawer-open');
    });
  }

  if (backdrop) {
    backdrop.addEventListener('click', function() {
      document.body.classList.remove('drawer-open');
    });
  }

  // Keyboard navigation & shortcuts
  document.addEventListener('keydown', function(e) {
    // ESC closes mobile navigation drawer
    if (e.key === 'Escape') {
      document.body.classList.remove('drawer-open');
    }
    // Command+K / Ctrl+K focuses global search bar
    if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
      var s = document.getElementById('global-search') || document.getElementById('search-input');
      if (s) {
        e.preventDefault();
        s.focus();
        s.select();
      }
    }
  });

  // Highlight search input on slash key if not already focused in an input
  document.addEventListener('keydown', function(e) {
    if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
      var s = document.getElementById('global-search') || document.getElementById('search-input');
      if (s) {
        e.preventDefault();
        s.focus();
        s.select();
      }
    }
  });

  // Table row select-all helper
  var selectAll = document.getElementById('select-all-rows');
  if (selectAll) {
    selectAll.addEventListener('change', function() {
      var checkboxes = document.querySelectorAll('.rowcheck');
      checkboxes.forEach(function(cb) {
        cb.checked = selectAll.checked;
      });
    });
  }
});

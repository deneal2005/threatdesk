/**
 * ThreatDesk - client-side interactions.
 * Progressive enhancement only: every page works without this file.
 * Complies with the CSP (no inline scripts, no eval, no inline style attributes in markup).
 */
(function () {
  'use strict';

  var root = document.documentElement;
  var isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

  function isTyping(el) {
    if (!el) return false;
    var tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
  }

  function store(key, value) {
    try {
      if (value === undefined) return window.localStorage.getItem(key);
      window.localStorage.setItem(key, value);
    } catch (e) { /* private mode or blocked storage: the default state is fine */ }
    return null;
  }

  /* Toast: one short message at the bottom of the screen */
  var toastEl, toastTimer;
  function toast(text) {
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.className = 'toast';
      toastEl.setAttribute('role', 'status');
      toastEl.setAttribute('aria-live', 'polite');
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = text;
    // Force a reflow so the transition replays for repeated toasts
    void toastEl.offsetWidth;
    toastEl.classList.add('is-on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.remove('is-on'); }, 2200);
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'sr';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy') ? resolve() : reject(); } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }

  /* Mobile navigation drawer ------------------------------------------------------------------ */
  function initDrawer() {
    var body = document.body;
    var toggle = document.querySelector('.drawer-toggle');
    var close = document.querySelector('.drawer-close');
    var backdrop = document.querySelector('.sidebar-backdrop');
    var nav = document.getElementById('sidebar-nav');
    if (!toggle || !nav) return;

    function setOpen(open) {
      body.classList.toggle('drawer-open', open);
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        var first = nav.querySelector('a[aria-current="page"]') || nav.querySelector('a');
        if (first) first.focus({ preventScroll: true });
      }
    }

    toggle.setAttribute('aria-controls', 'sidebar-nav');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.addEventListener('click', function () { setOpen(!body.classList.contains('drawer-open')); });
    if (close) close.addEventListener('click', function () { setOpen(false); toggle.focus(); });
    if (backdrop) backdrop.addEventListener('click', function () { setOpen(false); });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && body.classList.contains('drawer-open')) { setOpen(false); toggle.focus(); }
    });
    // Leaving the drawer layout (rotating a tablet, resizing) closes it
    var wide = window.matchMedia('(min-width: 901px)');
    var onWide = function (e) { if (e.matches) setOpen(false); };
    if (wide.addEventListener) wide.addEventListener('change', onWide); else if (wide.addListener) wide.addListener(onWide);
  }

  /* Keyboard shortcuts: Ctrl/Cmd+K or "/" focuses search --------------------------------------- */
  function initShortcuts() {
    var hint = document.querySelector('.kbd-hint');
    if (hint && !isMac) hint.textContent = 'Ctrl K';

    function focusSearch() {
      var s = document.getElementById('search-input') || document.getElementById('global-search');
      if (!s) return false;
      s.focus();
      s.select();
      return true;
    }
    document.addEventListener('keydown', function (e) {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        if (focusSearch()) e.preventDefault();
      } else if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey && !isTyping(document.activeElement)) {
        if (focusSearch()) e.preventDefault();
      } else if (e.key === 'Escape' && isTyping(document.activeElement) && document.activeElement.type === 'search') {
        document.activeElement.blur();
      }
    });
  }

  /* Disclosure popovers (menus, filter panel): close on outside click and on Escape -------------- */
  function initPopovers() {
    var selector = 'details.menu[open], details.filter-toggle[open]';
    document.addEventListener('click', function (e) {
      document.querySelectorAll(selector).forEach(function (d) {
        // The findings filter panel starts open when filters are active; leave it alone unless the user opened it
        if (d.classList.contains('filter-toggle') && !d.hasAttribute('data-user-opened')) return;
        if (!d.contains(e.target)) d.removeAttribute('open');
      });
    });
    document.addEventListener('toggle', function (e) {
      var d = e.target;
      if (d.matches && d.matches('details.filter-toggle') && d.open) d.setAttribute('data-user-opened', '');
    }, true);
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      document.querySelectorAll(selector).forEach(function (d) {
        if (d.contains(document.activeElement) || d.classList.contains('menu')) {
          d.removeAttribute('open');
          var s = d.querySelector('summary');
          if (s && d.contains(document.activeElement)) s.focus();
        }
      });
    });
  }

  /* Forms: confirmation prompts and busy buttons ------------------------------------------------ */
  function initForms() {
    document.addEventListener('submit', function (e) {
      var form = e.target;
      if (!(form instanceof HTMLFormElement)) return;
      var question = form.getAttribute('data-confirm');
      if (question && !window.confirm(question)) { e.preventDefault(); return; }
      if (form.method.toLowerCase() !== 'post') return;
      if (form.dataset.submitting === '1') { e.preventDefault(); return; }
      form.dataset.submitting = '1';
      // Mark the pressed button as busy (not disabled, so its name/value still submits)
      var btn = e.submitter || form.querySelector('button:not([type="button"])');
      if (btn && btn.classList.contains('btn')) {
        btn.classList.add('is-busy');
        btn.setAttribute('aria-busy', 'true');
      }
    });
    // Coming back with the Back button restores the page from cache: clear busy states
    window.addEventListener('pageshow', function () {
      document.querySelectorAll('form[data-submitting]').forEach(function (f) { delete f.dataset.submitting; });
      document.querySelectorAll('.btn.is-busy').forEach(function (b) { b.classList.remove('is-busy'); b.removeAttribute('aria-busy'); });
    });
  }

  /* Tables: select-all with range selection, and whole-row links -------------------------------- */
  function initTables() {
    var all = document.getElementById('select-all-rows');
    var boxes = Array.prototype.slice.call(document.querySelectorAll('.rowcheck'));
    var last = null;

    function syncAll() {
      if (!all) return;
      var on = boxes.filter(function (b) { return b.checked; }).length;
      all.checked = on > 0 && on === boxes.length;
      all.indeterminate = on > 0 && on < boxes.length;
    }
    if (all) {
      all.addEventListener('change', function () {
        boxes.forEach(function (b) { b.checked = all.checked; });
        all.indeterminate = false;
      });
    }
    boxes.forEach(function (box) {
      box.addEventListener('click', function (e) {
        // Shift-click selects every row between this one and the last one clicked
        if (e.shiftKey && last && last !== box) {
          var a = boxes.indexOf(last), b = boxes.indexOf(box);
          var lo = Math.min(a, b), hi = Math.max(a, b);
          for (var i = lo; i <= hi; i++) boxes[i].checked = box.checked;
        }
        last = box;
        syncAll();
      });
    });
    syncAll();

    // A row whose main cell links to a case opens it when clicked anywhere (but not on controls)
    document.querySelectorAll('tbody tr').forEach(function (tr) {
      var link = tr.querySelector('a.cell-main');
      if (!link || tr.querySelector('form')) return;
      tr.setAttribute('data-href', link.getAttribute('href'));
    });
    document.addEventListener('click', function (e) {
      var tr = e.target.closest && e.target.closest('tr[data-href]');
      if (!tr || e.defaultPrevented) return;
      if (e.target.closest('a, button, input, select, textarea, label, summary, details')) return;
      if (window.getSelection && String(window.getSelection()).length) return;   // user is selecting text
      var href = tr.getAttribute('data-href');
      if (e.metaKey || e.ctrlKey || e.button === 1) window.open(href, '_blank', 'noopener');
      else window.location.href = href;
    });
  }

  /* Flash messages: dismiss button, auto-hide success, tidy the URL ----------------------------- */
  function initFlashes() {
    document.querySelectorAll('.flash, .alert').forEach(function (el) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'flash-close';
      btn.setAttribute('aria-label', 'Dismiss message');
      btn.textContent = '×';
      btn.addEventListener('click', function () { dismiss(el); });
      el.appendChild(btn);
      // Success messages fade after a while; errors stay until dismissed
      if (el.classList.contains('flash') && !el.querySelector('code')) {
        setTimeout(function () { if (!el.matches(':hover') && !el.contains(document.activeElement)) dismiss(el); }, 7000);
      }
    });
    function dismiss(el) {
      el.classList.add('is-leaving');
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 260);
    }
    // ?m=… only carries the flash; drop it so a reload or a shared link doesn't repeat it
    if (window.history && window.history.replaceState && /[?&]m=/.test(window.location.search)) {
      var params = new URLSearchParams(window.location.search);
      params.delete('m');
      var q = params.toString();
      window.history.replaceState(null, '', window.location.pathname + (q ? '?' + q : '') + window.location.hash);
    }
  }

  /* Copy to clipboard: read-only inputs (report links) and code.copy snippets ------------------- */
  function markCopyable() {
    document.querySelectorAll('input[readonly]:not([data-copy]), code.copy:not([data-copy]), .key-once code:not([data-copy])').forEach(function (el) {
      el.setAttribute('data-copy', '');
      if (el.tagName !== 'INPUT') el.setAttribute('title', 'Click to copy');
    });
  }
  function initCopy() {
    markCopyable();
    document.addEventListener('click', function (e) {
      var el = e.target.closest && e.target.closest('[data-copy]');
      if (!el) return;
      var text = el.tagName === 'INPUT' ? el.value : el.textContent.trim();
      if (el.tagName === 'INPUT') el.select();
      copyText(text).then(function () { toast('Copied to clipboard'); }, function () { /* selection stays for manual copy */ });
    });
  }

  /* Remember collapsed panels (e.g. the dashboard "how it works" strip) ------------------------- */
  function initRemembered() {
    document.querySelectorAll('details[data-remember]').forEach(function (d) {
      var key = 'td:' + d.getAttribute('data-remember');
      var saved = store(key);
      if (saved === 'closed') d.removeAttribute('open');
      else if (saved === 'open') d.setAttribute('open', '');
      // No saved choice yet: on phones, start collapsed so the numbers come first
      else if (d.hasAttribute('data-collapse-mobile') && window.matchMedia('(max-width: 640px)').matches) d.removeAttribute('open');
      d.addEventListener('toggle', function () { store(key, d.open ? 'open' : 'closed'); });
    });
  }

  function init() {
    root.classList.add('js');
    initDrawer();
    initShortcuts();
    initPopovers();
    initForms();
    initTables();
    initFlashes();
    initCopy();
    initRemembered();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

  // Content swapped in by htmx (investigation results) gets the same treatment
  document.addEventListener('htmx:afterSwap', markCopyable);
})();

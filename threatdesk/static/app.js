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

  /* Disclosure popovers (menus, filter panel): close on outside click, on Escape and when focus leaves */
  function initPopovers() {
    var selector = 'details.menu[open], details.filter-toggle[open]';
    function closeAll(except) {
      document.querySelectorAll(selector).forEach(function (d) {
        if (d !== except && !d.contains(except)) d.removeAttribute('open');
      });
    }
    // pointerdown (not click) so a drag that starts outside, or a click on a row link, still closes the panel first
    document.addEventListener('pointerdown', function (e) { closeAll(e.target); });
    document.addEventListener('click', function (e) { closeAll(e.target); });   // keyboard-activated clicks
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      document.querySelectorAll(selector).forEach(function (d) {
        var hadFocus = d.contains(document.activeElement);
        d.removeAttribute('open');
        var s = d.querySelector('summary');
        if (s && hadFocus) s.focus();
      });
    });
    // Tabbing past the end of an open panel closes it (relatedTarget is null for clicks on plain text: ignore those)
    document.addEventListener('focusout', function (e) {
      var d = e.target.closest && e.target.closest('details.menu[open], details.filter-toggle[open]');
      if (d && e.relatedTarget && !d.contains(e.relatedTarget)) d.removeAttribute('open');
    });
  }

  /* Findings filter panel: choosing a value applies it straight away and closes the panel ------- */
  function initFilterPanel() {
    var details = document.querySelector('details.filter-toggle');
    var form = details && details.querySelector('form.filter-panel');
    if (!form) return;
    // Arrow keys on a closed <select> change its value one step at a time: only auto-apply pointer choices,
    // keyboard users confirm with the Apply button as before
    var viaKeyboard = false;
    form.addEventListener('keydown', function (e) { if (e.key !== 'Tab') viaKeyboard = true; });
    form.addEventListener('pointerdown', function () { viaKeyboard = false; });
    form.addEventListener('change', function (e) {
      if (viaKeyboard || !e.target.matches('select, input[type="checkbox"]')) return;
      if (form.requestSubmit) form.requestSubmit(); else form.submit();
    });
    form.addEventListener('submit', function () {
      details.removeAttribute('open');
      var summary = details.querySelector('summary');
      if (summary) { summary.classList.add('is-busy'); summary.setAttribute('aria-busy', 'true'); }
    });
    // Back/forward cache restores the page as it was left: clear the busy state
    window.addEventListener('pageshow', function () {
      var summary = details.querySelector('summary');
      if (summary) { summary.classList.remove('is-busy'); summary.removeAttribute('aria-busy'); }
    });
  }

  /* Alerts dropdown: loads the latest alerts each time it opens; shows a retry when loading fails ---- */
  function initNotifications() {
    var menu = document.getElementById('notif-menu');
    var pop = document.getElementById('notif-pop');
    if (!menu || !pop) return;
    function load() {
      if (!window.htmx) return;           // without htmx the placeholder keeps its "View all alerts" link
      pop.setAttribute('aria-busy', 'true');
      window.htmx.ajax('GET', '/notifications/menu', { target: '#notif-pop', swap: 'innerHTML' });
    }
    function failed() {
      pop.removeAttribute('aria-busy');
      pop.innerHTML = '';
      var box = document.createElement('div');
      box.className = 'notif-error';
      box.setAttribute('role', 'alert');
      var p = document.createElement('p');
      p.className = 'small';
      p.textContent = 'Alerts could not be loaded. Check your connection and try again.';
      var retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'btn quiet sm';
      retry.textContent = 'Try again';
      retry.addEventListener('click', function (e) { e.stopPropagation(); load(); });
      var all = document.createElement('a');
      all.href = '/notifications';
      all.className = 'small';
      all.textContent = 'Open the alerts page';
      box.appendChild(p); box.appendChild(retry); box.appendChild(all);
      pop.appendChild(box);
    }
    menu.addEventListener('toggle', function () { if (menu.open) load(); });
    document.addEventListener('htmx:afterSwap', function (e) { if (e.target === pop) pop.removeAttribute('aria-busy'); });
    ['htmx:responseError', 'htmx:sendError', 'htmx:timeout'].forEach(function (name) {
      document.addEventListener(name, function (e) {
        var t = e.detail && (e.detail.target || e.detail.elt);
        if (t && (t === pop || pop.contains(t))) failed();
      });
    });
  }

  /* Bulk false-positive confirmation (CSP compliant, no inline script) */
  function initBulk() {
    var bulkForm = document.querySelector('form[action="/findings/bulk"]');
    if (bulkForm) {
      bulkForm.addEventListener('submit', function (e) {
        var checked = document.querySelectorAll('.rowcheck:checked');
        if (checked.length === 0) {
          e.preventDefault();
          window.alert('Please select at least one finding to mark as false positive.');
          return;
        }
        if (!window.confirm('Are you sure you want to mark ' + checked.length + ' selected finding(s) as false positives?')) {
          e.preventDefault();
        }
      });
    }
  }

  /* Forms: confirmation prompts and busy buttons ------------------------------------------------ */
  function initForms() {
    document.addEventListener('submit', function (e) {
      var form = e.target;
      if (!(form instanceof HTMLFormElement) || e.defaultPrevented) return;   // a form's own handler said no
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
    initFilterPanel();
    initForms();
    initTables();
    initFlashes();
    initCopy();
    initRemembered();
    initBulk();
    initNotifications();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

  // Content swapped in by htmx (investigation results) gets the same treatment
  document.addEventListener('htmx:afterSwap', markCopyable);
})();

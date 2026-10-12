/* ThreatDesk welcome / sign-in screen: intro animation, password toggle, submit feedback. */
(function () {
  'use strict';

  var body = document.body;
  var loader = document.getElementById('loaderOverlay');
  var container = document.getElementById('mainContainer');
  var video = document.getElementById('loaderVideo');
  var canvas = document.getElementById('loaderCanvas');
  var ctx = null;
  var INTRO_MS = 1050;   // the accelerated clip plays once in ~0.95s

  function revealLogin() {
    if (loader && !loader.classList.contains('fade-out')) {
      loader.classList.add('fade-out');
    }
    if (container) container.classList.add('loaded');
  }

  // Draw the clip onto the canvas, keying out its near-white background so the
  // shield floats on the page colour with no box around it.
  function renderFrame() {
    if (ctx && video.readyState >= 2 && video.videoWidth > 0) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(video, 0, 0, video.videoWidth, video.videoHeight, 0, 0, canvas.width, canvas.height);
      var frame;
      try {
        frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
      } catch (e) {
        return;   // tainted canvas: leave the raw frame
      }
      var d = frame.data;
      for (var i = 0; i < d.length; i += 4) {
        var r = d[i], g = d[i + 1], b = d[i + 2];
        if (r > 238 && g > 238 && b > 235) {
          d[i + 3] = 0;
        } else if (r > 200 && g > 200 && b > 195) {
          var avg = (r + g + b) / 3;
          d[i + 3] = Math.max(0, Math.min(255, Math.round((245 - avg) * 6.2)));
        }
      }
      ctx.putImageData(frame, 0, 0);
    }
    if (!video.ended && !loader.classList.contains('fade-out')) {
      requestAnimationFrame(renderFrame);
    }
  }

  if (loader) {
    body.classList.add('intro-js');   // JS drives the intro; disable the CSS fallback timer
    var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduceMotion || !video || !canvas) {
      revealLogin();
    } else {
      ctx = canvas.getContext('2d', { willReadFrequently: true });
      var started = false;
      var start = function () {
        video.playbackRate = 1.55;
        if (!started) {
          started = true;
          requestAnimationFrame(renderFrame);
        }
      };
      video.addEventListener('loadeddata', start);
      video.addEventListener('play', start);
      video.addEventListener('ended', revealLogin);
      video.addEventListener('error', revealLogin, true);
      var p = video.play();
      if (p && p.catch) p.catch(function () { revealLogin(); });
      setTimeout(revealLogin, INTRO_MS);
    }
    // Any key or click skips straight to the form.
    window.addEventListener('keydown', revealLogin);
    loader.addEventListener('click', revealLogin);
  }

  // Show / hide password
  var pwdInput = document.getElementById('password');
  var toggleBtn = document.getElementById('togglePwd');
  if (toggleBtn && pwdInput) {
    toggleBtn.addEventListener('click', function () {
      var show = pwdInput.type === 'password';
      pwdInput.type = show ? 'text' : 'password';
      toggleBtn.setAttribute('aria-pressed', show ? 'true' : 'false');
      toggleBtn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      pwdInput.focus();
    });
  }

  // Submit feedback (and guard against double submits)
  var form = document.getElementById('loginForm');
  var submitBtn = document.getElementById('submitBtn');
  if (form && submitBtn) {
    form.addEventListener('submit', function (e) {
      if (submitBtn.getAttribute('aria-busy') === 'true') {
        e.preventDefault();
        return;
      }
      if (pwdInput) pwdInput.type = 'password';   // never leave the password visible on the next page
      submitBtn.setAttribute('aria-busy', 'true');
      submitBtn.firstElementChild.textContent = 'Signing in…';
    });
  }

  // Coming back via the browser's back/forward cache: reset the button.
  window.addEventListener('pageshow', function (e) {
    if (e.persisted && submitBtn) {
      submitBtn.removeAttribute('aria-busy');
      submitBtn.firstElementChild.textContent = 'Sign in';
    }
  });
})();

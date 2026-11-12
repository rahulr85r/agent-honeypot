/* honeypots.js — e-commerce traps disguised as ordinary UX.
 *
 * These exist to catch the CAREFUL LOCAL agent (real browser, clean environment,
 * trusted input events) that the static/env fingerprint can't see. Each trap looks
 * like normal store furniture and reports RAW samples only — no verdict, no threshold.
 *
 * Wiring is declarative via data-attributes so pages stay clean:
 *   input[data-hp="decoy"]      off-screen "priority discount" field (a11y-tree bait)
 *   [data-hp="latency"][data-hp-name=..]  button whose appear->click gap is timed
 *   input[data-hp="confirm"]    order-confirm checkbox (trusted-toggle check)
 *   [data-hp="slider"]          slide-to-place-order control (drag kinematics)
 * Navigation path is tracked across pages in sessionStorage.
 */
(function (global) {
  'use strict';
  if (global.PicoHP) return;
  var doc = global.document;
  var perf = global.performance || { now: function () { return Date.now(); } };
  var now = function () { return perf.now(); };
  var SKEY = 'pico_nav';

  // ---- cross-page navigation trail ----------------------------------------
  function nav() {
    try { return JSON.parse(global.sessionStorage.getItem(SKEY)) || null; } catch (_) { return null; }
  }
  function saveNav(n) { try { global.sessionStorage.setItem(SKEY, JSON.stringify(n)); } catch (_) {} }
  function initNav() {
    var n = nav() || { started: Date.now(), pages: [], productsViewed: {}, checkoutReached: false,
                       boughtTrap: false, dwellMs: 0, _enter: Date.now() };
    n._enter = Date.now();
    saveNav(n);
    return n;
  }
  function markPage(name, productId) {
    var n = nav() || initNav();
    n.pages.push({ p: name, t: Date.now() });
    if (name === 'product' && productId != null) n.productsViewed[String(productId)] = 1;
    if (name === 'checkout') n.checkoutReached = true;
    saveNav(n);
  }
  function accrueDwell() {
    var n = nav(); if (!n) return;
    if (n._enter) n.dwellMs += Math.max(0, Date.now() - n._enter);
    n._enter = Date.now(); saveNav(n);
  }
  function markBoughtTrap() { var n = nav() || initNav(); n.boughtTrap = true; saveNav(n); }

  // ---- per-page trap state -------------------------------------------------
  var state = {
    offer: { filled: false, value: null, focusT: null },
    latency: {},      // name -> { appearT, clickT, gapMs }
    confirm: { checked: false, trustedToggle: null, coldSet: false },
    slider: { active: false, startT: null, samples: [] },   // samples: {t,x,y,trusted}
    // agentic canary: a hidden instruction + invisible control. A human never sees either;
    // an LLM agent ingesting the DOM/text to "be helpful" follows the instruction and acts.
    ld: { clicked: false, trusted: null, focused: false, atMs: null },
  };

  // Self-declaration checkbox: "This order is being placed by an AI assistant on my behalf".
  // Read at snapshot time (so an accidental tick that's undone doesn't count).
  // A page may carry several (sign-in: a visible box AND a hidden "AI assistant" answer).
  var declareEls = [];
  function wireDeclare(el) { if (declareEls.indexOf(el) < 0) declareEls.push(el); }
  function isHidden(el) { return !!(el.closest && (el.closest('.sr-only') || el.closest('.offscreen'))); }
  function declareSnap() {
    var on = declareEls.filter(function (el) { return el.checked; });
    return { checked: on.length > 0, n: on.length,
             visible: on.some(function (el) { return !isHidden(el); }),
             hidden: on.length > 0 ? on.every(isHidden) : declareEls.length > 0 && declareEls.every(isHidden) };
  }
  // "Which assistant are you?" — free text an agent volunteers. Read at snapshot time; a browser
  // autofill of it is flagged so the server ignores it.
  var declareNameEl = null;
  function wireDeclareName(el) { declareNameEl = el; }
  function declareName() {
    if (!declareNameEl) return null;
    var v = String(declareNameEl.value || '').trim();
    if (!v) return null;
    var af = false; try { af = declareNameEl.matches(':-webkit-autofill') || declareNameEl.matches(':autofill'); } catch (_) {}
    return { value: v.slice(0, 60), autofill: af };
  }

  function wireCanary(el) {
    function hit(e) {
      if (state.ld.clicked) return;
      state.ld.clicked = true; state.ld.trusted = !!e.isTrusted; state.ld.atMs = Math.round(now());
    }
    el.addEventListener('click', hit, true);
    el.addEventListener('focus', function () { state.ld.focused = true; }, true);
  }

  function wireDecoy(el) {
    // off-screen but focusable + labelled: a human never sees it; a tree/DOM-driven
    // agent that fills "every field" or chases the enticing label trips it.
    el.addEventListener('focus', function () { state.offer.focusT = now(); }, true);
    function mark() {
      if (!(el.value || '').length) return;
      state.offer.filled = true; state.offer.value = el.value;
      // A browser/password-manager autofill of this field is not an agent — record it so the
      // server can downgrade it instead of treating the fill as a hard tell.
      try { if (el.matches && el.matches(':-webkit-autofill')) state.offer.autofill = true; } catch (_) {}
    }
    el.addEventListener('input', mark, true);
    el.addEventListener('change', mark, true);   // also catch cold .value= injection
  }

  function wireLatency(el) {
    var name = el.getAttribute('data-hp-name') || el.id || 'btn';
    var rec = state.latency[name] = { appearT: now(), clickT: null, gapMs: null };
    // if the control starts disabled, treat enable-time as appear-time
    var obs = new (global.MutationObserver || function () { return { observe: function () {} }; })(function () {
      if (!el.disabled && rec.appearT == null) rec.appearT = now();
    });
    try { obs.observe(el, { attributes: true, attributeFilter: ['disabled', 'style', 'class'] }); } catch (_) {}
    el.addEventListener('click', function () {
      rec.clickT = now();
      if (rec.appearT != null) rec.gapMs = Math.round(rec.clickT - rec.appearT);
    }, true);
  }

  function wireConfirm(el) {
    el.addEventListener('change', function (e) {
      state.confirm.checked = el.checked;
      if (el.checked && state.confirm.trustedToggle == null) state.confirm.trustedToggle = e.isTrusted;
    }, true);
    // trap el.checked = true (cold programmatic set with no change event / no trusted click)
    try {
      var d = Object.getOwnPropertyDescriptor(global.HTMLInputElement.prototype, 'checked');
      if (d && d.set && !d.set.__pico) {
        var set = d.set, self = el;
        var repl = function (v) {
          if (this === self && v === true) state.confirm.coldSet = true;
          return set.call(this, v);
        };
        repl.__pico = 1;
        Object.defineProperty(el, 'checked', { configurable: true, get: d.get, set: repl });
      }
    } catch (_) {}
  }

  function wireSlider(el) {
    var s = state.slider;
    var knob = el.querySelector('[data-hp="knob"]') || el;
    function sample(e, trusted) {
      s.samples.push({ t: Math.round(now()), x: e.clientX, y: e.clientY, tr: trusted ? 1 : 0 });
      if (s.samples.length > 400) s.samples.shift();
    }
    function start(e) { s.active = true; s.startT = now(); s.samples = []; sample(e, e.isTrusted); }
    function move(e) { if (s.active) sample(e, e.isTrusted); }
    function end(e) {
      if (!s.active) return; s.active = false; sample(e, e.isTrusted);
      var rect = el.getBoundingClientRect();
      var lastX = s.samples.length ? s.samples[s.samples.length - 1].x : 0;
      var frac = Math.max(0, Math.min(1, (lastX - rect.left) / rect.width));
      s.completed = frac > 0.85;
      s.durationMs = Math.round(now() - s.startT);
      if (s.completed) {
        el.classList.add('slid');
        el.dispatchEvent(new CustomEvent('pico:slid', { bubbles: true }));
      } else {
        // snap back visual handled by page CSS; keep samples for scoring
        el.dispatchEvent(new CustomEvent('pico:slidfail', { bubbles: true }));
      }
    }
    knob.addEventListener('pointerdown', start, true);
    doc.addEventListener('pointermove', move, true);
    doc.addEventListener('pointerup', end, true);
  }

  function wireAll(root) {
    (root || doc).querySelectorAll('input[data-hp="decoy"]').forEach(wireDecoy);
    (root || doc).querySelectorAll('[data-hp="latency"]').forEach(wireLatency);
    (root || doc).querySelectorAll('input[data-hp="confirm"]').forEach(wireConfirm);
    (root || doc).querySelectorAll('[data-hp="slider"]').forEach(wireSlider);
    (root || doc).querySelectorAll('[data-hp="canary"]').forEach(wireCanary);
    (root || doc).querySelectorAll('input[data-hp="declare"]').forEach(wireDeclare);
    (root || doc).querySelectorAll('[data-hp="declare-name"]').forEach(wireDeclareName);
  }

  function snapshot() {
    accrueDwell();
    var n = nav() || {};
    var pv = Object.keys(n.productsViewed || {}).length;
    return {
      offer: { filled: state.offer.filled, value: state.offer.value, autofill: !!state.offer.autofill },
      latency: state.latency,
      confirm: state.confirm,
      slider: { completed: !!state.slider.completed, durationMs: state.slider.durationMs || null,
                samples: state.slider.samples.slice() },
      ld: { clicked: state.ld.clicked, trusted: state.ld.trusted, focused: state.ld.focused },
      // which agent tells (if any) caused the page to show its STRONG visible honeypot
      strong: (doc.body && doc.body.getAttribute('data-ast')) || null,
      // the sign-in "one more step" gate was shown (first Sign in press without the box ticked)
      gate: !!(doc.body && doc.body.getAttribute('data-gate')),
      declare: (function () { var d = declareSnap();
                 return { checked: d.checked, n: d.n, visible: d.visible, hidden: d.hidden,
                          page: (doc.body && doc.body.getAttribute('data-page')) || null, name: declareName() }; })(),
      nav: { productsViewed: pv, checkoutReached: !!n.checkoutReached, boughtTrap: !!n.boughtTrap,
             totalDwellMs: n.dwellMs || 0, pageCount: (n.pages || []).length },
    };
  }

  // dwell bookkeeping on unload/visibility
  global.addEventListener('visibilitychange', function () { if (doc.hidden) accrueDwell(); });
  global.addEventListener('pagehide', accrueDwell);

  function boot() { initNav(); wireAll(doc); }
  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', boot); else boot();

  global.PicoHP = { snapshot: snapshot, markPage: markPage, markBoughtTrap: markBoughtTrap, wireAll: wireAll };
})(typeof window !== 'undefined' ? window : this);

#!/usr/bin/env node
'use strict';
// Pico detector — human false-positive + agent recall suite.
//
// Generates realistic per-page signal bundles (the same shape collector.js + honeypots.js
// ship) for humans across devices and input modalities, crossed with real-world environment
// modifiers, plus agent personas — and reports how often each is labelled "agent".
//
//   node test/fp-suite.js                                   # current server/detector.js
//   node test/fp-suite.js --compare path/to/old-detector.js # side-by-side old vs new
//   node test/fp-suite.js --n 400 --seed 11                 # more trials / other seed
//
// Behaviour models follow how browsers actually report each input (verified in Chrome):
//  * mouse/trackpad: Chrome coalesces mousemove to display frames (60/120 Hz); strokes use a
//    minimum-jerk (bell-shaped) speed profile, curvature, jitter and corrective sub-movements.
//    Fractional coordinates are kept (no pixel rounding) — the conservative case, since
//    rounding adds angle noise that would make humans look *more* human.
//  * keyboard: keydown/keyup pairs with log-normal flight/dwell; Shift for capitals; 20% of
//    typists hold Backspace (auto-repeat: metronomic 33 ms keydowns). Enter/Space on a control
//    = trusted click at (0,0) with detail 0 (kb:true).
//  * touch: pointerType 'touch' per tap, a compat mousemove on ~half of taps, virtual-keyboard
//    key events with near-zero hold time; predictive-text taps insert text with no keydown.
//  * checkbox/label: clicking the label text forwards a second trusted click to the checkbox.
//  * screen reader activation: trusted click with detail 1 at the exact element centre, no
//    pointerdown, no mouse movement.

var path = require('path');
function arg(n, d) { var i = process.argv.indexOf('--' + n); return i > -1 ? process.argv[i + 1] : d; }
var DETS = [{ name: 'NEW', det: require(path.resolve(arg('detector', path.join(__dirname, '..', 'server', 'detector.js')))) }];
if (arg('compare', null)) DETS.unshift({ name: 'OLD', det: require(path.resolve(arg('compare'))) });
var N = +arg('n', 250), SEED = +arg('seed', 7);

// ---------------------------------------------------------------- random ----
var R;
function seed(s) { var a = s >>> 0; R = function () { a |= 0; a = a + 0x6D2B79F5 | 0; var t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function rnd() { return R(); }
function uni(a, b) { return a + (b - a) * rnd(); }
function irnd(a, b) { return Math.floor(uni(a, b + 1)); }
function gauss() { var u = rnd() || 1e-9, v = rnd(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }
function logn(med, sig) { return med * Math.exp(sig * gauss()); }
function chance(p) { return rnd() < p; }
function pick(a) { return a[Math.floor(rnd() * a.length)]; }

// ------------------------------------------------- behaviour accumulator ----
function newB() {
  return { interactions: 0, mouse: { moves: 0, untrusted: 0, pathLen: 0, trusted: 0, steps: [], angles: [], vel: [] },
    clicks: [], untrustedClicks: 0,
    keys: { down: 0, up: 0, trusted: 0, untrusted: 0, flights: [], dwell: [], pasteChunks: 0, inputNoKey: 0, inputEvents: 0, pwDown: 0, pwAssist: 0, assist: 0 },
    valueSetsCold: 0, coldFocus: 0, focusEvents: 0, scroll: { events: 0, wheel: 0, dist: 0 },
    pointer: { types: {} }, idleGaps: [], autofilled: 0, _cur: null, _t: 0, _lastKeyT: null,
    _ap: { m: 0, last: null, t: null } };
}
function cap(a, v, n) { a.push(v); if (a.length > (n || 120)) a.shift(); }
function moveTo(B, pts, hz) {
  var m = B.mouse, dt = 1000 / hz;
  pts.forEach(function (p) {
    B._t += dt; m.trusted++; B.interactions++;
    B._ap.m++; B._ap.t = B._t; B._ap.last = null;
    if (B._cur) {
      var dx = p[0] - B._cur[0], dy = p[1] - B._cur[1], d = Math.sqrt(dx * dx + dy * dy);
      B._ap.last = +d.toFixed(1);
      m.pathLen += d; cap(m.steps, +d.toFixed(2));
      if (d > 0.5) cap(m.angles, +Math.atan2(dy, dx).toFixed(3));
      cap(m.vel, +(d / dt).toFixed(3));
    }
    B._cur = [p[0], p[1]]; m.moves++;
  });
}
function aim(box, spread) {
  var x = box.x + box.w / 2 + gauss() * box.w * spread, y = box.y + box.h / 2 + gauss() * box.h * spread;
  return [Math.min(box.x + box.w - 1, Math.max(box.x + 1, x)), Math.min(box.y + box.h - 1, Math.max(box.y + 1, y))];
}
// One ballistic pointer movement (minimum-jerk speed profile + curvature + jitter + correction).
function stroke(B, target, o) {
  if (!B._cur) B._cur = [uni(150, 1350), uni(120, 700)];
  var s = B._cur, dx = target[0] - s[0], dy = target[1] - s[1], dist = Math.sqrt(dx * dx + dy * dy);
  if (dist < 3) return;
  var dur = (180 + 140 * Math.log2(dist / 25 + 1)) * uni(0.75, 1.5);
  var n = Math.max(2, Math.round(dur / 1000 * o.hz)), curve = uni(-o.curve, o.curve), px = -dy / dist, py = dx / dist, pts = [];
  var over = chance(o.overshoot || 0.25) ? uni(0.02, 0.07) : 0;
  for (var i = 1; i <= n; i++) {
    var u = i / n, f = 10 * u * u * u - 15 * u * u * u * u + 6 * u * u * u * u * u;
    f = f * (1 + over * Math.sin(Math.PI * u));
    var off = curve * dist * Math.sin(Math.PI * u);
    pts.push([s[0] + dx * f + px * off + gauss() * o.jit, s[1] + dy * f + py * off + gauss() * o.jit]);
  }
  moveTo(B, pts, o.hz);
  if (chance(o.correct == null ? 0.35 : o.correct)) {
    var c = [target[0] + gauss() * 2, target[1] + gauss() * 1.5], s2 = B._cur, m = irnd(3, 9), pts2 = [];
    for (var j = 1; j <= m; j++) { var w = j / m; pts2.push([s2[0] + (c[0] - s2[0]) * w + gauss() * o.jit, s2[1] + (c[1] - s2[1]) * w + gauss() * o.jit]); }
    moveTo(B, pts2, o.hz);
  }
}
function tremor(B, o) {
  if (!B._cur) return;
  var m = irnd(2, 12), pts = [];
  for (var i = 0; i < m; i++) pts.push([B._cur[0] + gauss() * 1.5, B._cur[1] + gauss() * 1.2]);
  moveTo(B, pts, o.hz);
}
function recordClick(B, box, pt, kb) {
  var cx = box.x + box.w / 2, cy = box.y + box.h / 2;
  var ap = { apM: B._ap.m, apL: B._ap.last, apG: B._ap.t != null ? Math.round(B._t - B._ap.t) : null };
  B._ap = { m: 0, last: null, t: null };
  if (kb) { B.clicks.push(Object.assign({ trusted: true, kb: true, pt: null, offX: +(0 - cx).toFixed(1), offY: +(0 - cy).toFixed(1) }, ap)); return; }
  var p = B._cur || [cx, cy];
  B.clicks.push(Object.assign({ trusted: true, kb: false, pt: pt, offX: +(p[0] - cx).toFixed(1), offY: +(p[1] - cy).toFixed(1) }, ap));
}
function mouseClick(B, box, o, label) {
  var dest = aim(label || box, 0.17);
  stroke(B, dest, o);
  B._t += uni(70, 260); B.pointer.types.mouse = (B.pointer.types.mouse || 0) + 1; B.interactions++;
  if (label) { recordClick(B, label, 'mouse'); recordClick(B, box, 'mouse'); }   // label + forwarded click
  else recordClick(B, box, 'mouse');
}
function tap(B, box, pt, label) {
  B._t += uni(300, 1400);
  var a = aim(label || box, 0.24);
  B.pointer.types[pt] = (B.pointer.types[pt] || 0) + 1; B.interactions++;
  if (chance(pt === 'pen' ? 0.8 : 0.5)) moveTo(B, [a], 60); else B._cur = a;   // compat mousemove on some taps
  if (label) { recordClick(B, label, pt); recordClick(B, box, pt); } else recordClick(B, box, pt);
}
function keyPress(B, p) {
  var k = B.keys, gap = Math.max(12, logn(p.flight, p.fsig));
  if (chance(0.05)) gap += uni(350, 1600);
  B._t += gap; k.down++; k.trusted++; B.interactions++;
  if (B._lastKeyT != null) cap(k.flights, Math.round(B._t - B._lastKeyT));
  B._lastKeyT = B._t;
  cap(k.dwell, Math.round(Math.max(0, logn(p.dwell, p.dsig)))); k.up++;
}
function typeText(B, len, p) {
  for (var i = 0; i < len; i++) {
    if (chance(p.shiftP == null ? 0.12 : p.shiftP)) keyPress(B, p);
    keyPress(B, p); B.keys.inputEvents++;
  }
  if (p.repeat && chance(0.2)) {            // hold Backspace: auto-repeat keydowns, one keyup
    var k = B.keys; for (var r = 0; r < irnd(4, 12); r++) { B._t += 33; k.down++; k.trusted++; B.interactions++; cap(k.flights, 33); B._lastKeyT = B._t; }
    k.up++; cap(k.dwell, irnd(300, 700));
  }
}
function enterKey(B, box, p) { keyPress(B, p); recordClick(B, box, null, true); }
function scrollBy(B, px, wheel) { B.scroll.dist += px; if (wheel) { var w = Math.max(1, Math.round(px / 40)); B.scroll.wheel += w; B.scroll.events += w; B.interactions += w; } else B.scroll.events += Math.max(1, Math.round(px / 60)); }

// ------------------------------------------------------- profiles/layout ----
var MOUSE = { hz: 60, jit: 0.45, curve: 0.10 };
var MOUSE120 = { hz: 120, jit: 0.35, curve: 0.08 };
var TRACKPAD = { hz: 60, jit: 0.25, curve: 0.06, correct: 0.45 };
var TRACKPAD_SMOOTH = { hz: 120, jit: 0.15, curve: 0.03, correct: 0.4, overshoot: 0.1 };   // worst case: very straight glides
var DESK_TYPIST = function () { return { flight: uni(90, 240), fsig: uni(0.3, 0.6), dwell: uni(55, 115), dsig: 0.3, repeat: true }; };
var FAST_TYPIST = function () { return { flight: uni(55, 85), fsig: uni(0.2, 0.35), dwell: uni(35, 60), dsig: 0.25, repeat: true }; };
var IOS_KB = function () { return { flight: uni(170, 330), fsig: 0.45, dwell: uni(3, 15), dsig: 0.6, shiftP: 0.05 }; };
var ANDROID_KB = function () { return { flight: uni(160, 320), fsig: 0.5, dwell: uni(1, 6), dsig: 0.5, shiftP: 0.05 }; };
var L = { user: { x: 567, y: 257, w: 378, h: 40 }, pass: { x: 567, y: 334, w: 378, h: 40 }, signin: { x: 567, y: 389, w: 378, h: 38 },
          cb: { x: 833, y: 402, w: 13, h: 13 }, cbLabel: { x: 859, y: 402, w: 286, h: 56 }, place: { x: 830, y: 478, w: 315, h: 38 } };

// ------------------------------------------------------------ page flows ----
// Each returns { beh, hp } for one scored page (login or checkout).
function loginFlow(mode) {
  var B = newB(); B.coldFocus = 1; B.focusEvents = 1;   // signin page autofocuses the username field
  var tp = mode.typist ? mode.typist() : DESK_TYPIST();
  var uLen = irnd(4, 7), pLen = irnd(8, 14);
  switch (mode.input) {
    case 'mouse': case 'trackpad': case 'ipad-trackpad': {
      var o = mode.motion;
      if (mode.savedPw) {
        B.autofilled = 2; tremor(B, o);
        if (chance(0.7)) mouseClick(B, L.signin, o); else enterKey(B, L.signin, tp);
      } else {
        mouseClick(B, L.user, o); typeText(B, uLen, tp);
        if (chance(0.6)) keyPress(B, tp); else mouseClick(B, L.pass, o);
        typeText(B, pLen, tp);
        if (chance(0.65)) mouseClick(B, L.signin, o); else enterKey(B, L.signin, tp);
      }
      break;
    }
    case 'keyboard': {
      if (mode.savedPw) { B.autofilled = 2; enterKey(B, L.signin, tp); }
      else { typeText(B, uLen, tp); keyPress(B, tp); typeText(B, pLen, tp); enterKey(B, L.signin, tp); }
      break;
    }
    case 'touch': case 'pen': {
      var pt = mode.input;
      if (mode.savedPw) { tap(B, L.user, pt); B.autofilled = 2; tap(B, L.signin, pt); }
      else {
        tap(B, L.user, pt); typeText(B, uLen, tp);
        if (chance(0.3)) { B.keys.inputNoKey += 1; tap(B, { x: 0, y: 700, w: 390, h: 40 }, pt); }   // predictive-text suggestion tap
        tap(B, L.pass, pt); typeText(B, pLen, tp);
        if (chance(0.7)) tap(B, L.signin, pt); else enterKey(B, L.signin, tp);
      }
      break;
    }
    case 'touch-laptop': {
      tap(B, L.user, 'touch'); typeText(B, uLen, tp); keyPress(B, tp); typeText(B, pLen, tp);
      if (chance(0.5)) tap(B, L.signin, 'touch'); else enterKey(B, L.signin, tp);
      break;
    }
    case 'screen-reader': {
      typeText(B, uLen, tp); keyPress(B, tp); typeText(B, pLen, tp);
      for (var q = 0; q < irnd(2, 5); q++) keyPress(B, tp);   // VO/NVDA navigation keys
      B.clicks.push({ trusted: true, kb: false, pt: null, offX: 0, offY: 0 });   // AT activation at centre
      B.interactions++;
      break;
    }
  }
  // password keys: typed unless a saved password filled it
  if (!mode.savedPw) B.keys.pwDown = pLen;
  // username arrived without typing it: dictation (one multi-char insertText) or a dropdown pick
  if (mode.dictation && !mode.savedPw) { B.keys.down = Math.max(0, B.keys.down - uLen); B.keys.trusted = Math.max(0, B.keys.trusted - uLen); B.keys.chunkInserts = 1; B.keys.chunkMax = uLen; }
  if (mode.dropdown && !mode.savedPw) { var cut = Math.max(0, uLen - 2); B.keys.down = Math.max(0, B.keys.down - cut); B.keys.trusted = Math.max(0, B.keys.trusted - cut); B.keys.assist = 1; }
  B.fields = {
    username: { kind: 'cred', keys: mode.savedPw || mode.dictation ? 0 : (mode.dropdown ? 2 : uLen), ins: 0, chunk: mode.dictation ? 1 : 0, comp: 0, untrusted: 0,
                assist: mode.savedPw || mode.dropdown ? 1 : 0, cold: 0, len: uLen },
    password: { kind: 'pw', keys: mode.savedPw ? 0 : pLen, ins: 0, chunk: 0, comp: 0, untrusted: 0, assist: mode.savedPw ? 1 : 0, cold: 0, len: pLen } };
  if (mode.pmExtension) { B.fields.password.assist = 0; B.fields.password.keys = 0; B.fields.password.untrusted = 1; }
  if (mode.pmExtension) { var u = irnd(2, 8); B.keys.untrusted += u; B.keys.down += u; B.valueSetsCold += 2; }
  // OS-level auto-typer (KeePass auto-type / AutoHotkey): real key events, ~0ms holds, fixed interval
  if (mode.autotype && !mode.savedPw) {
    var gap = irnd(10, 50);
    B.keys.flights = B.keys.flights.map(function (x, i) { return i === uLen - 1 ? irnd(80, 300) : gap + irnd(-1, 1); });
    B.keys.dwell = B.keys.dwell.map(function () { return irnd(1, 3); });
  }
  // a form/writing extension that fires its own (untrusted) input events on fields the person typed in
  if (mode.formExt && !mode.savedPw) { B.fields.username.untrusted = 1; if (!mode.pmExtension) B.fields.password.untrusted = 1; }
  return { typedLen: { u: uLen, p: pLen }, beh: B, hp: { offer: { filled: false }, confirm: {}, ld: {}, latency: {}, nav: { productsViewed: irnd(0, 3), checkoutReached: false, totalDwellMs: logn(20000, 0.8) } } };
}

function checkoutFlow(mode) {
  var B = newB(); B.focusEvents = irnd(0, 2);
  var tp = mode.typist ? mode.typist() : DESK_TYPIST();
  var useLabel = chance(0.5) ? L.cbLabel : null;
  switch (mode.input) {
    case 'mouse': case 'trackpad': case 'ipad-trackpad': {
      var o = mode.motion;
      if (chance(0.5)) { for (var w = 0; w < irnd(1, 2); w++) stroke(B, [uni(300, 1200), uni(150, 650)], o); }
      if (chance(0.5)) tremor(B, o);
      if (chance(0.3)) scrollBy(B, uni(40, 400), true);
      mouseClick(B, L.cb, o, useLabel);
      if (chance(0.4)) tremor(B, o);
      if (chance(0.85)) mouseClick(B, L.place, o); else enterKey(B, L.place, tp);
      break;
    }
    case 'keyboard': case 'screen-reader': {
      for (var t = 0; t < irnd(3, 8); t++) keyPress(B, tp);
      if (mode.input === 'screen-reader') {
        B.clicks.push({ trusted: true, kb: false, pt: null, offX: 0, offY: 0 }); B.interactions++;
        keyPress(B, tp); B.clicks.push({ trusted: true, kb: false, pt: null, offX: 0, offY: 0 }); B.interactions++;
      } else { keyPress(B, tp); recordClick(B, L.cb, null, true); keyPress(B, tp); enterKey(B, L.place, tp); }
      break;
    }
    case 'touch': case 'pen': {
      if (chance(0.6)) scrollBy(B, uni(80, 1400), false);
      tap(B, L.cb, mode.input, useLabel); tap(B, L.place, mode.input);
      break;
    }
    case 'touch-laptop': {
      tap(B, L.cb, 'touch', useLabel); if (chance(0.5)) tap(B, L.place, 'touch'); else enterKey(B, L.place, tp);
      break;
    }
  }
  var fast = chance(0.1);
  return { beh: B, hp: { offer: { filled: false }, confirm: { checked: true, trustedToggle: true, coldSet: false }, ld: {}, latency: {},
    nav: { productsViewed: fast ? 1 : irnd(1, 3), checkoutReached: true, totalDwellMs: fast ? uni(2500, 6000) : logn(45000, 0.8) } } };
}

// ----------------------------------------------------------- environments ---
function env(dev) {
  var e = {
    static: { navigator: { ua: dev.ua, webdriver: false, uaData: dev.uaData, maxTouchPoints: dev.touch || 0,
                           hardwareConcurrency: pick(dev.cores || [4, 8, 8, 10, 12, 16]), deviceMemory: dev.noMem ? undefined : pick([4, 8, 8, 8]) },
      webgl: { supported: true, software: false, renderer: dev.gpu }, fonts: { count: irnd(dev.fonts[0], dev.fonts[1]) } },
    env: { timezone: { tz: 'America/Chicago', locale: dev.locale || 'en-US', mismatch: false }, permission: { notif: 'default', query: 'prompt', anomaly: false },
      mediaDevices: { supported: true, total: irnd(dev.media[0], dev.media[1]) }, battery: { supported: dev.battery },
      speech: { count: dev.voices === 0 ? (chance(0.5) ? 0 : irnd(5, 30)) : irnd(20, 180), waited: true }, automation: { hits: [], patchedNatives: [] } },
  };
  e.static.webgpu = dev.webgpu === false ? { supported: false } : { supported: true, vendor: dev.webgpu || 'intel', architecture: 'gen-12lp' };
  e.static.uaHighEntropy = dev.uaData ? { architecture: dev.arch || 'x86', bitness: '64' } : null;
  return e;
}
var DEV = {
  mac_chrome:    { ua: 'Mozilla/5.0 (Macintosh) Chrome/150', uaData: { mobile: false, platform: 'macOS' }, arch: 'arm', webgpu: 'apple', gpu: 'ANGLE (Apple M2)', fonts: [12, 18], media: [1, 4], battery: true },
  win_chrome:    { ua: 'Mozilla/5.0 (Windows NT 10.0) Chrome/150', uaData: { mobile: false, platform: 'Windows' }, gpu: 'ANGLE (Intel UHD 620 Direct3D11)', fonts: [16, 22], media: [1, 4], battery: true },
  win_edge:      { ua: 'Mozilla/5.0 (Windows NT 10.0) Edg/150', uaData: { mobile: false, platform: 'Windows' }, webgpu: 'nvidia', gpu: 'ANGLE (NVIDIA Direct3D11)', fonts: [16, 22], media: [1, 4], battery: true },
  mac_safari:    { ua: 'Mozilla/5.0 (Macintosh) Version/18 Safari/605', uaData: null, webgpu: 'apple', gpu: 'Apple GPU', fonts: [12, 18], media: [1, 3], battery: false, noMem: true },
  linux_firefox: { ua: 'Mozilla/5.0 (X11; Linux) Firefox/140', uaData: null, voices: 0, webgpu: false, gpu: 'Mesa Intel(R) UHD', fonts: [6, 11], media: [1, 3], battery: false },
  linux_chrome:  { ua: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/150', uaData: { mobile: false, platform: 'Linux' }, gpu: 'ANGLE (Mesa Intel UHD)', fonts: [6, 12], media: [1, 3], battery: true, voices: 0, webgpu: false },
  win_firefox:   { ua: 'Mozilla/5.0 (Windows NT 10.0) Firefox/140', uaData: null, webgpu: false, gpu: 'ANGLE (Intel Direct3D11)', fonts: [14, 20], media: [1, 3], battery: false },
  iphone_safari: { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7) Safari/604.1', uaData: null, gpu: 'Apple GPU', fonts: [9, 11], media: [2, 2], battery: false, touch: 5, locale: 'en-CA' },
  android_chrome:{ ua: 'Mozilla/5.0 (Linux; Android 15) Chrome/150 Mobile', uaData: { mobile: true, platform: 'Android' }, arch: 'arm', voices: 0, gpu: 'Adreno (TM) 740', fonts: [6, 10], media: [2, 3], battery: true, touch: 5 },
  ipad_safari:   { ua: 'Mozilla/5.0 (Macintosh) Version/18 Safari/605', uaData: null, gpu: 'Apple GPU', fonts: [9, 12], media: [2, 2], battery: false, touch: 5 },
  android_tablet:{ ua: 'Mozilla/5.0 (Linux; Android 15) Chrome/150', uaData: { mobile: false, platform: 'Android' }, arch: 'arm', voices: 0, gpu: 'Mali-G78', fonts: [6, 10], media: [2, 3], battery: true, touch: 10 },
};

// Human personas: device × input modality.
var HUMANS = [
  ['Desktop · mouse · typing',               'win_chrome',    { input: 'mouse', motion: MOUSE }],
  ['Desktop · 120Hz mouse · fast typist',    'win_edge',      { input: 'mouse', motion: MOUSE120, typist: FAST_TYPIST }],
  ['Desktop · mouse · saved password',       'mac_chrome',    { input: 'mouse', motion: MOUSE, savedPw: true }],
  ['Laptop · trackpad · typing',             'mac_chrome',    { input: 'trackpad', motion: TRACKPAD }],
  ['Laptop · trackpad (very smooth glides)', 'mac_safari',    { input: 'trackpad', motion: TRACKPAD_SMOOTH }],
  ['Laptop · trackpad · saved password',     'mac_safari',    { input: 'trackpad', motion: TRACKPAD, savedPw: true }],
  ['Desktop · keyboard-only (Tab/Enter)',    'win_chrome',    { input: 'keyboard' }],
  ['Desktop · keyboard + saved password',    'mac_chrome',    { input: 'keyboard', savedPw: true }],
  ['Desktop · Firefox · mouse',              'linux_firefox', { input: 'mouse', motion: MOUSE }],
  ['Desktop · Linux Chrome · mouse',         'linux_chrome',  { input: 'mouse', motion: MOUSE }],
  ['Desktop · Firefox (Win) · trackpad',     'win_firefox',   { input: 'trackpad', motion: TRACKPAD }],
  ['Touch laptop · touch + keyboard',        'win_chrome',    { input: 'touch-laptop' }],
  ['Screen-reader user (NVDA/VoiceOver)',    'win_chrome',    { input: 'screen-reader' }],
  ['iPhone · touch · typing',                'iphone_safari', { input: 'touch', typist: IOS_KB }],
  ['iPhone · touch · Keychain autofill',     'iphone_safari', { input: 'touch', typist: IOS_KB, savedPw: true }],
  ['Android phone · touch · Gboard',         'android_chrome',{ input: 'touch', typist: ANDROID_KB }],
  ['iPad · touch',                           'ipad_safari',   { input: 'touch', typist: IOS_KB }],
  ['iPad · Apple Pencil',                    'ipad_safari',   { input: 'pen', typist: IOS_KB }],
  ['iPad · Magic Keyboard trackpad',         'ipad_safari',   { input: 'ipad-trackpad', motion: TRACKPAD }],
  ['Android tablet · touch',                 'android_tablet',{ input: 'touch', typist: ANDROID_KB }],
];

// Real-world environment modifiers a human can carry.
var MODS = {
  vpn:        { label: 'VPN / abroad (en-US browser, non-US timezone)', env: function (e) { e.env.timezone = { tz: 'Asia/Kolkata', locale: 'en-US', mismatch: true }; } },
  privacy:    { label: 'privacy extension (patched canvas/WebGL)', env: function (e) { e.env.automation.patchedNatives = ['canvas.toDataURL', 'WebGL.getParameter']; } },
  pmext:      { label: 'password-manager extension (synthetic keys)', mode: { pmExtension: true } },
  vdi:        { label: 'VDI / HW-acceleration off (software GPU)', env: function (e) { e.static.webgl = { supported: true, software: true, renderer: 'ANGLE (Google, SwiftShader Device)' }; } },
  incognito:  { label: 'incognito-style permission contradiction', env: function (e) { e.env.permission = { notif: 'denied', query: 'prompt', anomaly: true }; } },
  fewfonts:   { label: 'minimal font set (stripped Linux / privacy browser)', env: function (e) { e.static.fonts = { count: 3 }; } },
  oldgpu:     { label: 'blocklisted GPU (WebGPU has no adapter)', env: function (e) { if (e.static.webgpu && e.static.webgpu.supported) e.static.webgpu = { supported: true, adapter: null }; } },
  novoice:    { label: 'speech voices removed / not installed', env: function (e) { e.env.speech = { count: 0, waited: true }; } },
  armlinux:   { label: 'ARM Linux desktop (Pi / Asahi)', env: function (e) { if (e.static.uaHighEntropy) { e.static.uaHighEntropy.architecture = 'arm'; e.static.navigator.uaData = { mobile: false, platform: 'Linux' }; } } },
  dictation:  { label: 'dictates the username (Dragon / voice typing)', mode: { dictation: true } },
  dropdown:   { label: 'picks the username from the browser dropdown', mode: { dropdown: true } },
  misdeclare: { label: 'POLICY (agent by rule) — mis-ticks the AI box', mode: { misdeclare: true } },
  oldhw:      { label: 'old PC (software graphics, 2 cores/2 GB, no audio devices, no WebGPU)', env: function (e) {
                  if (e.static.navigator.maxTouchPoints) return;
                  e.static.webgl = { supported: true, software: true, renderer: 'ANGLE (Google, SwiftShader Device)' };
                  e.static.navigator.hardwareConcurrency = 2; e.static.navigator.deviceMemory = 2;
                  e.env.mediaDevices = { supported: true, total: 0 }; if (e.static.webgpu && e.static.webgpu.supported) e.static.webgpu = { supported: true, adapter: null }; } },
  budget:     { label: 'budget laptop (2 cores, 2 GB)', env: function (e) { e.static.navigator.hardwareConcurrency = 2; e.static.navigator.deviceMemory = 2; } },
  nowebgl:    { label: 'no WebGL at all (blocked GPU on new Chrome / GPU-less VDI)', env: function (e) {
                  if (e.static.navigator.maxTouchPoints) return;
                  e.static.webgl = { supported: false }; if (e.static.webgpu && e.static.webgpu.supported) e.static.webgpu = { supported: true, adapter: null }; } },
  autotype:   { label: 'KeePass auto-type / AutoHotkey (machine-timed keys)', mode: { autotype: true } },
  formext:    { label: 'extension firing its own input events on typed fields', mode: { formExt: true } },
  ffrfp:      { label: 'Firefox resistFingerprinting / Tor / LibreWolf (screen = window, 2 cores, no WebGL)', env: function (e) {
                  if (e.static.navigator.maxTouchPoints) return;
                  e.static.navigator.ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0'; e.static.navigator.uaData = null;
                  e.static.navigator.hardwareConcurrency = 2; e.static.webgl = { supported: false };
                  e.static.screen = Object.assign({}, e.static.screen, { w: 1400, h: 900, availW: 1400, availH: 900, innerW: 1400, innerH: 900, outerW: 1400, outerH: 990 }); } },
  brave:      { label: 'Brave (randomised cores, farbled screen = window)', env: function (e) {
                  if (e.static.navigator.maxTouchPoints) return;
                  e.static.navigator.hardwareConcurrency = 2; e.static.navigator.uaData = { mobile: false, platform: 'Windows', brands: ['Brave;157', 'Chromium;157', 'Not-A.Brand;99'] };
                  e.static.screen = Object.assign({}, e.static.screen, { w: 1280, h: 720, availW: 1280, availH: 720, innerW: 1280, innerH: 720, outerW: 1288, outerH: 851 }); } },
  vmgeo:      { label: 'worst case: VDI/RDP window shaped like a VM display (window taller than screen)', env: function (e) {
                  if (e.static.navigator.maxTouchPoints) return;
                  e.static.screen = Object.assign({}, e.static.screen, { w: 1280, h: 720, availW: 1280, availH: 720, innerW: 1280, innerH: 720, outerW: 1288, outerH: 851 }); } },
};
var MOD_SETS = [[]].concat(Object.keys(MODS).map(function (k) { return [k]; }));
(function () { var ks = Object.keys(MODS); for (var i = 0; i < ks.length; i++) for (var j = i + 1; j < ks.length; j++) MOD_SETS.push([ks[i], ks[j]]); })();
MOD_SETS.push(['vdi', 'vpn', 'fewfonts']); MOD_SETS.push(['oldhw', 'dropdown', 'vpn']); MOD_SETS.push(['oldhw', 'dictation', 'incognito']); MOD_SETS.push(['oldhw', 'budget', 'oldgpu', 'dropdown']); MOD_SETS.push(['misdeclare', 'vdi', 'vpn']); MOD_SETS.push(['misdeclare', 'oldhw', 'dropdown']);
MOD_SETS.push(['autotype', 'nowebgl', 'armlinux']); MOD_SETS.push(['vmgeo', 'autotype', 'formext']); MOD_SETS.push(['misdeclare', 'nowebgl', 'armlinux']); MOD_SETS.push(['misdeclare', 'oldhw', 'novoice']); MOD_SETS.push(['misdeclare', 'vdi', 'vmgeo']); MOD_SETS.push(['misdeclare', 'nowebgl', 'novoice']); MOD_SETS.push(['ffrfp', 'pmext', 'autotype']); MOD_SETS.push(['brave', 'pmext', 'formext']); MOD_SETS.push(['ffrfp', 'dictation', 'vpn']); MOD_SETS.push(['vmgeo', 'pmext', 'dropdown']); MOD_SETS.push(['vmgeo', 'oldhw', 'dictation']); MOD_SETS.push(['vmgeo', 'misdeclare', 'novoice']); MOD_SETS.push(['autotype', 'oldhw', 'novoice']); MOD_SETS.push(['autotype', 'formext', 'nowebgl']);

function humanBundle(devKey, mode, mods, page) {
  var m = Object.assign({}, mode); mods.forEach(function (k) { if (MODS[k].mode) Object.assign(m, MODS[k].mode); });
  var e = env(DEV[devKey]); mods.forEach(function (k) { if (MODS[k].env) MODS[k].env(e); });
  var f = page === 'login' ? loginFlow(m) : checkoutFlow(m);
  if (m.misdeclare) f.hp.declare = { checked: true, page: page };
  return { collector: { static: e.static, env: e.env, behaviour: f.beh }, hp: f.hp,
           server: { canary: [], typedLen: page === 'login' ? f.typedLen : null, fields: page === 'login' ? { username: f.typedLen.u, password: f.typedLen.p } : null } };
}

// --------------------------------------------------------- agent personas ---
// opts: cloud (GPU-less micro-VM), webdriver, humanMouse (no teleport), insert (CDP insertText),
//       follow: which perception channel's "assistant" instruction it acts on
//               ('dom' | 'jsonld' | 'llms' | 'a11y' | 'visible' | null = ignores page instructions),
//       decoy (fills the hidden field), declare (ticks "placed by an AI assistant"),
//       buysDemo (task "cheapest" and it ignores the not-for-sale badge), readsLlms.
function agentBundle(o, page) {
  var B = newB(); B.keys.pwDown = 0; var e = env(DEV.win_chrome), server = { canary: [], boughtTrap: false, typedLen: page === 'login' ? { u: 5, p: 10 } : null };
  var hp = { offer: { filled: false }, confirm: { checked: true, trustedToggle: true }, ld: {}, latency: {}, declare: { checked: false },
             nav: { productsViewed: 1, checkoutReached: page === 'checkout', totalDwellMs: uni(4000, 30000) } };
  var cdpKeys = { flight: uni(20, 60), fsig: 0.08, dwell: uni(0, 3), dsig: 0.3, shiftP: 0 };
  function teleClick(box) { var p = aim(box, 0.03); moveTo(B, [p], 60); B._t += uni(2, 6); B.pointer.types.mouse = (B.pointer.types.mouse || 0) + 1; B.interactions++; recordClick(B, box, 'mouse'); }
  var click = function (box) { if (o.humanMouse) mouseClick(B, box, MOUSE); else teleClick(box); };
  function insertText() { B.keys.inputNoKey += 1; B.keys.inputEvents += 1; }
  // Eased synthetic move (CDP + ease-in-out): mirror-symmetric step lengths, constant heading, few events.
  function easedClick(box) {
    var n = irnd(2, 4), half = [], peak = uni(60, 140);
    for (var k = 1; k <= n; k++) half.push(+(peak * Math.sin(Math.PI / 2 * k / (n + 1))).toFixed(2));
    var seq = half.concat([+peak.toFixed(2)], half.slice().reverse()), ang = +uni(-3, 3).toFixed(3);
    seq.forEach(function (d) { B.mouse.steps.push(d); B.mouse.angles.push(ang); B.mouse.pathLen += d; B.mouse.moves++; B.mouse.trusted++; B.interactions++; });
    B.mouse.steps.push(0);
    B.clicks.push({ trusted: true, kb: false, pt: 'mouse', apM: seq.length, apL: seq[seq.length - 1], apG: Math.round(uni(80, 150)), offX: uni(-25, 25), offY: uni(-6, 6) });
    B.pointer.types.mouse = (B.pointer.types.mouse || 0) + 1; B.interactions++;
  }
  if (o.eased) click = easedClick;
  function chunk(n, pw) { B.keys.chunkInserts = (B.keys.chunkInserts || 0) + 1; if (pw) B.keys.chunkPw = (B.keys.chunkPw || 0) + 1; B.keys.chunkMax = Math.max(B.keys.chunkMax || 0, n); B.keys.inputEvents++; }
  if (o.cloud) {
    e.static.webgl = { supported: true, software: true, renderer: 'ANGLE (Google, SwiftShader Device)' };
    e.static.fonts = { count: irnd(3, 6) }; e.env.mediaDevices = { supported: true, total: 0 };
    e.static.navigator.hardwareConcurrency = pick([2, 2, 4]); e.static.navigator.deviceMemory = pick([2, 2, 4]);
    if (chance(0.6)) e.env.timezone = { tz: 'UTC', locale: 'en-US', mismatch: true };
    e.env.speech = { count: 0, waited: true };
    e.static.navigator.uaData = { mobile: false, platform: 'Linux' };
    e.static.uaHighEntropy = { architecture: pick(['arm', 'x86']), bitness: '64' };
    e.static.webgpu = { supported: true, adapter: null };
  }
  if (o.humanized) {   // operator hid the cheap tells: real cores/memory, audio devices, local timezone
    e.static.navigator.hardwareConcurrency = pick([4, 6, 8]); e.static.navigator.deviceMemory = pick([8, 16]);
    e.env.mediaDevices = { supported: true, total: irnd(1, 3) };
    e.env.timezone = { tz: 'America/Chicago', locale: 'en-US', mismatch: false };
  }
  if (o.voices) e.env.speech = { count: irnd(10, 40), waited: true };
  if (o.x86) e.static.uaHighEntropy = { architecture: 'x86', bitness: '64' };
  if (o.spoofGpu) {    // WebGL renderer string spoofed to a real GPU; WebGPU still reveals SwiftShader
    e.static.webgl = { supported: true, software: false, renderer: 'ANGLE (NVIDIA GeForce RTX 3060 Direct3D11)' };
    e.static.webgpu = { supported: true, vendor: 'google', architecture: 'swiftshader' };
  }
  if (o.webdriver) { e.static.navigator.webdriver = true; e.env.automation.hits = ['webdriver']; }
  if (page === 'login') {
    click(L.user); o.insert ? insertText() : o.chunk ? chunk(7, false) : typeText(B, 5, o.realKeys ? DESK_TYPIST() : cdpKeys);
    click(L.pass); o.insert ? insertText() : o.mixed ? (B.keys.inputEvents++) : o.chunk ? chunk(12, true) : typeText(B, 10, o.realKeys ? DESK_TYPIST() : cdpKeys);
    click(L.signin);
  } else {
    click(L.cb); click(L.place);
  }
  if (page === 'login' && o.realKeys && !o.mixed && !o.chunk && !o.insert) B.keys.pwDown = 10;
  if (page === 'login') {
    var typed = o.realKeys || (!o.insert && !o.chunk && !o.mixed);
    B.fields = {
      username: { kind: 'cred', keys: o.insert || o.chunk ? 0 : 5, ins: o.chunk ? 1 : 0, chunk: o.chunk ? 1 : 0, comp: 0, untrusted: 0, assist: 0, cold: 0, len: 5 },
      password: { kind: 'pw', keys: typed && !o.mixed ? 10 : 0, ins: o.chunk || o.mixed ? 1 : 0, chunk: o.chunk || o.mixed ? 1 : 0, comp: 0, untrusted: 0, assist: 0, cold: 0, len: 10 } };
    server.fields = { username: 5, password: 10 };
  }
  if (o.readsLlms) server.canary.push({ kind: 'read', via: 'llms' });
  if (o.follow) server.canary.push({ kind: 'act', via: o.follow });
  if (o.decoy) hp.offer = { filled: true, autofill: false };
  if (o.declare) hp.declare = { checked: true };
  if (o.buysDemo && page === 'checkout') server.boughtTrap = true;
  return { collector: { static: e.static, env: e.env, behaviour: B }, hp: hp, server: server };
}
var AGENTS = [
  ['— cloud agents (GPU-less micro-VM) —', null],
  ['Cloud · webdriver exposed',                                  { cloud: 1, webdriver: 1 }],
  ['Cloud · stealth · teleport clicks · ignores page notes',     { cloud: 1 }],
  ['Cloud · stealth · human-like mouse · ignores page notes',    { cloud: 1, humanMouse: 1 }],
  ['Cloud · humanized (local tz, real cores, audio) · eased mouse · real keys', { cloud: 1, humanized: 1, eased: 1, realKeys: 1 }],
  ['Cloud · humanized · eased mouse · password as one insert',      { cloud: 1, humanized: 1, eased: 1, chunk: 1 }],
  ['Cloud · humanized · human mouse · types user, sets password',  { cloud: 1, humanized: 1, humanMouse: 1, realKeys: 1, mixed: 1 }],
  ['Cloud · humanized · human mouse · real keys (env-only catch)',  { cloud: 1, humanized: 1, humanMouse: 1, realKeys: 1 }],
  ['Cloud · humanized + voices + x86 · human mouse · real keys',    { cloud: 1, humanized: 1, humanMouse: 1, realKeys: 1, voices: 1, x86: 1 }],
  ['Cloud · spoofed WebGL renderer (WebGPU reveals software) · eased', { cloud: 1, humanized: 1, spoofGpu: 1, eased: 1, realKeys: 1 }],
  ['— local agents in YOUR real browser (clean environment) —', null],
  ['Local · ignores page notes · eased mouse · password one insert', { eased: 1, chunk: 1 }],
  ['Local · ignores every page instruction (worst case)',        {}],
  ['Local · vision agent · follows visible fine print',          { follow: 'visible' }],
  ['Local · vision agent · honest, ticks "AI assistant" box',    { declare: 1 }],
  ['Local · vision agent · "cheapest" task, buys demo unit',     { buysDemo: 1 }],
  ['Local · accessibility-tree agent · follows a11y note',       { follow: 'a11y' }],
  ['Local · DOM agent · follows JSON-LD buy action',             { follow: 'jsonld' }],
  ['Local · DOM agent · follows hidden link',                    { follow: 'dom' }],
  ['Local · DOM agent · fills hidden discount field',            { decoy: 1 }],
  ['Local · reads llms.txt and follows its checkout link',       { readsLlms: 1, follow: 'llms' }],
  ['Local · reads llms.txt only, human-like mouse',              { readsLlms: 1, humanMouse: 1 }],
  ['Local · reads llms.txt only, teleport clicks',               { readsLlms: 1 }],
];

// ------------------------------------------------------------------- run ----
function rate(fn, det) {
  var hits = 0, review = 0, why = {};
  for (var i = 0; i < N; i++) {
    var v = det.assess(fn(i));
    if (v.tier === 'BEH-ONLY' || v.tier === 'HP-ONLY' || v.tier === 'ENV-ONLY') review++;
    if (v.label === 'agent') { hits++; var k = v.hard[0] ? 'HARD ' + v.hard[0].replace(/\s*\(.*$/, '').replace(/×\d+/, '') : 'SOFT ' + Object.keys(v.soft).sort().join('+'); why[k] = (why[k] || 0) + 1; }
  }
  var top = Object.keys(why).sort(function (a, b) { return why[b] - why[a]; })[0];
  return { pct: 100 * hits / N, review: 100 * review / N, top: top };
}
function fmt(p) { return (p === 0 ? '0' : p < 1 ? '<1' : p.toFixed(0)) + '%'; }
function cell(r) { return fmt(r.pct) + (r.review ? ' (r' + fmt(r.review) + ')' : ''); }
function pad(s, n) { s = String(s); return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length); }

console.log('Pico detector — human FP + agent recall suite   (N=' + N + ' randomized trials per cell, seed ' + SEED + ')');
console.log('Detectors: ' + DETS.map(function (d) { return d.name; }).join(' vs ') + '   ·   cells show % labelled AGENT, (rN%) = % human-labelled but flagged for review (BEH-ONLY / HP-ONLY)\n');

// 1) Human personas, clean environment
console.log('━━ 1. HUMANS — clean environment (% of trials labelled AGENT; should be 0) ━━');
console.log(pad('persona', 40) + DETS.map(function (d) { return pad(d.name + ' login', 14) + pad(d.name + ' checkout', 17); }).join(''));
HUMANS.forEach(function (h, hi) {
  var row = pad(h[0], 40);
  DETS.forEach(function (d) {
    ['login', 'checkout'].forEach(function (pg) { seed(SEED * 1000 + hi * 10 + (pg === 'login' ? 1 : 2)); var r = rate(function () { return humanBundle(h[1], h[2], [], pg); }, d.det); row += pad(cell(r), pg === 'login' ? 14 : 17); });
  });
  console.log(row);
});

// 2) Human personas × environment modifiers (aggregated over every persona and both pages)
console.log('\n━━ 2. HUMANS × environment modifiers (avg % AGENT across all 19 personas × login+checkout) ━━');
console.log(pad('modifier(s)', 66) + DETS.map(function (d) { return pad(d.name, 9); }).join('') + '  main cause (' + DETS[DETS.length - 1].name + ')');
MOD_SETS.forEach(function (ms, mi) {
  var label = ms.length ? ms.map(function (k) { return MODS[k].label; }).join(' + ') : '(none)';
  var row = pad(label, 66), lastTop = '';
  DETS.forEach(function (d) {
    var tot = 0, cells = 0, tops = {};
    HUMANS.forEach(function (h, hi) { ['login', 'checkout'].forEach(function (pg) {
      seed(SEED * 7919 + mi * 131 + hi * 7 + (pg === 'login' ? 1 : 2));
      var r = rate(function () { return humanBundle(h[1], h[2], ms, pg); }, d.det); tot += r.pct; cells++; if (r.top) tops[r.top] = (tops[r.top] || 0) + r.pct;
    }); });
    row += pad(fmt(tot / cells), 9);
    lastTop = Object.keys(tops).sort(function (a, b) { return tops[b] - tops[a]; })[0] || '';
  });
  console.log(row + '  ' + lastTop);
});

// 3) Real captured human bundles
console.log('\n━━ 3. YOUR REAL CAPTURED SESSIONS (rahul) ━━');
var real = []; try { real = require('./fixtures/real-humans.json'); } catch (_) {}
real.forEach(function (r) {
  var row = pad(r.stage + (r.ref ? ' ' + r.ref : ''), 26);
  DETS.forEach(function (d) { var v = d.det.assess(r.bundle); row += pad(d.name + ': ' + v.label + ' ' + v.confidence + ' ' + v.tier, 36); });
  console.log(row);
});

// 4) Agents
console.log('\n━━ 4. AGENTS — recall (% labelled AGENT; higher is better) ━━');
console.log(pad('agent persona', 60) + DETS.map(function (d) { return pad(d.name + ' login', 14) + pad(d.name + ' checkout', 17); }).join(''));
AGENTS.forEach(function (a, ai) {
  if (!a[1]) { console.log(a[0]); return; }
  var row = pad(a[0], 60);
  DETS.forEach(function (d) { ['login', 'checkout'].forEach(function (pg) { seed(SEED * 3 + ai * 17 + (pg === 'login' ? 1 : 2)); var r = rate(function () { return agentBundle(a[1], pg); }, d.det); row += pad(cell(r), pg === 'login' ? 14 : 17); }); });
  console.log(row);
});


// 5) Inner pages: contact form and store locator (no password field)
console.log('\n━━ 5. INNER PAGES — contact form & store locator (% labelled AGENT) ━━');
function innerBundle(devKey, how, pg, envMod) {
  var dev = DEV[devKey], e = env(dev); if (envMod) envMod(e);
  var B = newB(), touch = !!dev.touch, tp = touch ? IOS_KB() : DESK_TYPIST();
  var FIELDS = pg === 'contact' ? [['name', 'cred', irnd(8, 16)], ['email', 'cred', irnd(14, 26)], ['message', 'free', irnd(40, 300)]] : [['zip', 'free', 5]];
  B.fields = {}; var lensOut = {};
  var hp = { offer: { filled: false }, confirm: {}, ld: {}, latency: {}, declare: { checked: false }, nav: { productsViewed: 0, checkoutReached: false, totalDwellMs: logn(30000, 0.8) } };
  var server = { canary: [], fields: lensOut };
  FIELDS.forEach(function (fd, i) {
    var name = fd[0], kind = fd[1], L = fd[2], f = { kind: kind, keys: 0, ins: 0, chunk: 0, comp: 0, untrusted: 0, assist: 0, cold: 0, len: L };
    lensOut[name] = L; B.fields[name] = f;
    var box = { x: 500, y: 200 + i * 70, w: 380, h: 40 };
    if (how.agent) {
      if (how.cloud) {}
      if (how.mouse === 'tele') { var p0 = aim(box, 0.03); moveTo(B, [p0], 60); B.pointer.types.mouse = (B.pointer.types.mouse || 0) + 1; B.interactions++; recordClick(B, box, 'mouse'); }
      else mouseClick(B, box, MOUSE);
      if (how.fill === 'playwright') { f.ins = 1; f.chunk = 1; B.keys.inputEvents++; }
      else if (how.fill === 'react') { f.cold = 1; f.untrusted = 1; B.valueSetsCold++; }
      else { typeText(B, L, DESK_TYPIST()); f.keys = L; f.ins = L; }
      return;
    }
    if (touch) tap(B, box, 'touch'); else mouseClick(B, box, MOUSE);
    var autofillable = kind === 'cred';
    if (how.autofill && autofillable) { f.assist = 1; B.autofilled++; return; }
    if (how.paste && name === 'message') { f.assist = 1; B.keys.pasteChunks++; return; }
    if (how.dictate && (name === 'message' || name === 'zip')) { f.ins = irnd(1, 4); f.chunk = f.ins; return; }
    if (how.swipe && touch) { f.comp = irnd(5, 20); f.keys = irnd(0, 4); return; }
    if (how.pmAddr && autofillable) { f.untrusted = 1; f.cold = 1; B.valueSetsCold++; return; }
    typeText(B, L, tp); f.keys = L; f.ins = L;
  });
  if (!how.agent && !touch) { tremor(B, MOUSE); mouseClick(B, { x: 500, y: 480, w: 380, h: 38 }, MOUSE); }
  else if (!how.agent) tap(B, { x: 0, y: 600, w: 390, h: 44 }, 'touch');
  else mouseClick(B, { x: 500, y: 480, w: 380, h: 38 }, MOUSE);
  if (how.cloud) {
    e.static.webgl = { supported: true, software: true, renderer: 'ANGLE (Google, SwiftShader Device)' };
    e.static.navigator.uaData = { mobile: false, platform: 'Linux' }; e.static.uaHighEntropy = { architecture: 'arm', bitness: '64' };
    e.env.speech = { count: 0, waited: true };
  }
  if (how.canary && pg === 'contact') server.contentCanary = 'PX-7Q4';
  if (how.hiddenOpt) server.hiddenOption = 'hidden option';
  if (how.follow) server.canary.push({ kind: 'act', via: how.follow });
  if (how.decoy) hp.offer = { filled: true, autofill: false };
  return { collector: { static: e.static, env: e.env, behaviour: B }, hp: hp, server: server };
}
var oldPC = function (e) { e.static.webgl = { supported: true, software: true, renderer: 'ANGLE (Google, SwiftShader Device)' }; e.static.navigator.hardwareConcurrency = 2; e.static.navigator.deviceMemory = 2; e.env.mediaDevices = { supported: true, total: 0 }; };
var INNER = [
  ['— humans —', null],
  ['Desktop · types everything', 'win_chrome', {}],
  ['Desktop · autofills name/email, types message', 'mac_chrome', { autofill: 1 }],
  ['Desktop · pastes the message', 'win_chrome', { paste: 1 }],
  ['Desktop · dictates message / ZIP', 'mac_chrome', { dictate: 1 }],
  ['Desktop · address-fill extension (script-filled name/email)', 'win_chrome', { pmAddr: 1 }],
  ['Old PC / VDI · dictates + address extension', 'win_chrome', { dictate: 1, pmAddr: 1 }, oldPC],
  ['iPhone · types', 'iphone_safari', {}],
  ['Android · swipe typing (composition)', 'android_chrome', { swipe: 1 }],
  ['— agents —', null],
  ['Cloud · Playwright fill (insertText) · human mouse', 'win_chrome', { agent: 1, cloud: 1, fill: 'playwright' }],
  ['Cloud · React-style script fill · human mouse', 'win_chrome', { agent: 1, cloud: 1, fill: 'react' }],
  ['Cloud · types every key · teleport clicks', 'win_chrome', { agent: 1, cloud: 1, mouse: 'tele' }],
  ['Cloud · types every key · human mouse (env only)', 'win_chrome', { agent: 1, cloud: 1 }],
  ['Local · Playwright fill · human mouse', 'mac_chrome', { agent: 1, fill: 'playwright' }],
  ['Local · React-style script fill', 'mac_chrome', { agent: 1, fill: 'react' }],
  ['Local · types · follows hidden "routing reference" note', 'mac_chrome', { agent: 1, canary: 1 }],
  ['Local · types · picks hidden menu option', 'mac_chrome', { agent: 1, hiddenOpt: 1 }],
  ['Local · types · picks hidden option + script fill', 'mac_chrome', { agent: 1, hiddenOpt: 1, fill: 'react' }],
  ['Local · follows an assistant-only link', 'mac_chrome', { agent: 1, follow: 'a11y' }],
  ['Local · fills hidden decoy field', 'mac_chrome', { agent: 1, decoy: 1 }],
];
console.log(pad('persona', 62) + pad('contact', 16) + pad('locator', 16));
INNER.forEach(function (row, ri) {
  if (!row[1]) { console.log(row[0]); return; }
  var line = pad(row[0], 62);
  ['contact', 'stores'].forEach(function (pg) {
    seed(SEED * 11 + ri * 13 + (pg === 'contact' ? 1 : 2));
    var r = rate(function () { return innerBundle(row[1], row[2], pg, row[3]); }, DETS[0].det); line += pad(cell(r), 16);
  });
  console.log(line);
});

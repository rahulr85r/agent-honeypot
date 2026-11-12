/* collector.js — Pico Mobile elaborate signal collector.
 *
 * Fresh, comprehensive agent/bot detection surface. Three domains:
 *   STATIC    browser-property fingerprint (identity surface)
 *   ENV       runtime/environment tells (datacenter vs personal device)
 *   BEHAVIOUR live accumulator (mouse kinematics, keystroke dynamics, scroll, pointer)
 *
 * The collector ONLY observes and reports raw-ish signals. It makes NO agent/human
 * decision and ships NO thresholds — all derivation is server-side (detector.js).
 *
 * Privacy: never reads or transmits IP / WebRTC candidate addresses. WebRTC is probed
 * for stack PRESENCE only. No PII beyond what the page's own forms already collect.
 *
 * Every probe is individually try/caught so one failure can't abort the bundle; a probe
 * that throws is itself a (recorded) signal.
 */
(function (global) {
  'use strict';
  if (global.Collector) return;
  var doc = global.document;
  var nav = global.navigator || {};
  var scr = global.screen || {};
  var perf = global.performance || { now: function () { return Date.now(); } };
  var now = function () { return perf.now ? perf.now() : Date.now(); };
  var T0 = now();

  function safe(fn, dflt) { try { var v = fn(); return v === undefined ? dflt : v; } catch (e) { return dflt; } }
  function hashStr(s) { s = String(s); var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
    return ('00000000' + h.toString(16)).slice(-8); }
  function isNative(fn) { return safe(function () { return /\[native code\]/.test(Function.prototype.toString.call(fn)); }, null); }

  // ===================================================================
  // STATIC — browser property fingerprint
  // ===================================================================
  function navigatorBlock() {
    var u = nav.userAgentData || null;
    return {
      ua: safe(function () { return nav.userAgent; }, null),
      platform: safe(function () { return nav.platform; }, null),
      vendor: safe(function () { return nav.vendor; }, null),
      language: safe(function () { return nav.language; }, null),
      languages: safe(function () { return Array.prototype.slice.call(nav.languages || [], 0, 10); }, null),
      hardwareConcurrency: safe(function () { return nav.hardwareConcurrency; }, null),
      deviceMemory: safe(function () { return nav.deviceMemory; }, null),
      maxTouchPoints: safe(function () { return nav.maxTouchPoints; }, 0),
      cookieEnabled: safe(function () { return nav.cookieEnabled; }, null),
      doNotTrack: safe(function () { return nav.doNotTrack; }, null),
      gpc: safe(function () { return nav.globalPrivacyControl; }, null),
      pdfViewerEnabled: safe(function () { return nav.pdfViewerEnabled; }, null),
      productSub: safe(function () { return nav.productSub; }, null),
      oscpu: safe(function () { return nav.oscpu; }, null),
      webdriver: safe(function () { return nav.webdriver === true; }, false),
      // stealth shims often redefine navigator.webdriver; a non-native getter is itself a tell
      webdriverGetterNonNative: safe(function () {
        var d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(nav), 'webdriver');
        return d && d.get ? isNative(d.get) === false : false;
      }, false),
      uaData: u ? {
        brands: safe(function () { return u.brands.map(function (b) { return b.brand + ';' + b.version; }); }, null),
        mobile: safe(function () { return u.mobile; }, null),
        platform: safe(function () { return u.platform; }, null),
      } : null,
    };
  }

  function uaHighEntropy() {
    return new Promise(function (resolve) {
      var u = nav.userAgentData;
      if (!u || !u.getHighEntropyValues) return resolve(null);
      u.getHighEntropyValues(['architecture', 'bitness', 'model', 'platformVersion', 'uaFullVersion', 'fullVersionList', 'wow64'])
        .then(function (hv) {
          resolve({ architecture: hv.architecture, bitness: hv.bitness, model: hv.model,
            platformVersion: hv.platformVersion, uaFullVersion: hv.uaFullVersion,
            fullVersionList: (hv.fullVersionList || []).map(function (b) { return b.brand + ';' + b.version; }), wow64: hv.wow64 });
        }).catch(function () { resolve(null); });
    });
  }

  function pluginsBlock() {
    return safe(function () {
      var out = [];
      for (var i = 0; i < (nav.plugins ? nav.plugins.length : 0); i++) out.push(nav.plugins[i].name);
      var mimes = 0; for (var j = 0; j < (nav.mimeTypes ? nav.mimeTypes.length : 0); j++) mimes++;
      return { count: out.length, names: out.slice(0, 12), mimeCount: mimes };
    }, { count: 0, names: [], mimeCount: 0 });
  }

  function screenBlock() {
    return { w: scr.width, h: scr.height, availW: scr.availWidth, availH: scr.availHeight,
      colorDepth: scr.colorDepth, pixelDepth: scr.pixelDepth,
      dpr: safe(function () { return global.devicePixelRatio; }, null),
      innerW: global.innerWidth, innerH: global.innerHeight, outerW: global.outerWidth, outerH: global.outerHeight,
      screenX: global.screenX, screenY: global.screenY,
      orientation: safe(function () { return (scr.orientation || {}).type; }, null) };
  }

  function canvasFP() {
    return safe(function () {
      var c = doc.createElement('canvas'); c.width = 240; c.height = 60;
      var ctx = c.getContext('2d');
      ctx.textBaseline = 'top'; ctx.font = "16px 'Arial'";
      ctx.fillStyle = '#f60'; ctx.fillRect(10, 1, 100, 40);
      ctx.fillStyle = '#069'; ctx.fillText('Pico(TM) phone 9.8', 12, 14);
      ctx.fillStyle = 'rgba(102,0,153,0.6)'; ctx.fillText('Pico(TM) phone 9.8', 14, 16);
      var data = c.toDataURL();
      return { hash: hashStr(data), len: data.length };
    }, null);
  }

  function webglBlock() {
    return safe(function () {
      var c = doc.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { supported: false };
      var dbg = gl.getExtension('WEBGL_debug_renderer_info');
      var vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      var renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      var params = {};
      ['MAX_TEXTURE_SIZE', 'MAX_RENDERBUFFER_SIZE', 'MAX_VERTEX_ATTRIBS', 'MAX_VARYING_VECTORS',
       'MAX_VERTEX_UNIFORM_VECTORS', 'MAX_FRAGMENT_UNIFORM_VECTORS'].forEach(function (p) {
        params[p] = safe(function () { return gl.getParameter(gl[p]); }, null);
      });
      var exts = safe(function () { return (gl.getSupportedExtensions() || []).length; }, null);
      var r = String(renderer || '');
      // RegExp-from-string (not a literal) so the obfuscator's string-array can encode the tell-words
      return { supported: true, vendor: vendor, renderer: renderer, extCount: exts, params: params,
        software: new RegExp('swiftshader|llvmpipe|software|mesa offscreen|basic render', 'i').test(r),
        angle: /angle/i.test(r) };
    }, { supported: false });
  }

  function webgpuBlock() {
    return new Promise(function (resolve) {
      if (!nav.gpu || !nav.gpu.requestAdapter) return resolve({ supported: false });
      nav.gpu.requestAdapter().then(function (ad) {
        if (!ad) return resolve({ supported: true, adapter: null });
        if (ad.requestAdapterInfo) {
          ad.requestAdapterInfo().then(function (i) {
            resolve({ supported: true, vendor: i.vendor, architecture: i.architecture, device: i.device });
          }).catch(function () { resolve({ supported: true, adapter: '?' }); });
        } else {
          var info = ad.info || {};
          resolve({ supported: true, vendor: info.vendor, architecture: info.architecture });
        }
      }).catch(function () { resolve({ supported: false }); });
    });
  }

  function audioFP() {
    return new Promise(function (resolve) {
      try {
        var OAC = global.OfflineAudioContext || global.webkitOfflineAudioContext;
        if (!OAC) return resolve({ supported: false });
        var ctx = new OAC(1, 44100, 44100);
        var osc = ctx.createOscillator(); osc.type = 'triangle'; osc.frequency.value = 10000;
        var comp = ctx.createDynamicsCompressor();
        osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
        var done = false;
        ctx.oncomplete = function (e) { if (done) return; done = true;
          var buf = e.renderedBuffer.getChannelData(0);
          var acc = 0; for (var i = 4500; i < 5000; i++) acc += Math.abs(buf[i]);
          resolve({ supported: true, hash: hashStr(acc.toString()) }); };
        ctx.startRendering();
        setTimeout(function () { if (!done) { done = true; resolve({ supported: true, hash: null, timeout: true }); } }, 800);
      } catch (e) { resolve({ supported: false }); }
    });
  }

  function fontsBlock() {
    return safe(function () {
      var base = ['monospace', 'sans-serif', 'serif'];
      var test = ['Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Georgia', 'Verdana', 'Comic Sans MS',
        'Trebuchet MS', 'Arial Black', 'Impact', 'Tahoma', 'Palatino', 'Segoe UI', 'Roboto', 'Calibri', 'Cambria',
        'Consolas', 'Menlo', 'Monaco', 'Noto Sans', 'Ubuntu', 'DejaVu Sans', 'Liberation Sans'];
      var span = doc.createElement('span');
      span.style.cssText = 'position:absolute;left:-9999px;top:0;font-size:72px';
      span.textContent = 'mmmmmmmmmmlli';
      doc.body.appendChild(span);
      var baseW = {}, baseH = {};
      base.forEach(function (b) { span.style.fontFamily = b; baseW[b] = span.offsetWidth; baseH[b] = span.offsetHeight; });
      var detected = [];
      test.forEach(function (f) {
        var hit = base.some(function (b) { span.style.fontFamily = "'" + f + "'," + b;
          return span.offsetWidth !== baseW[b] || span.offsetHeight !== baseH[b]; });
        if (hit) detected.push(f);
      });
      doc.body.removeChild(span);
      return { count: detected.length, names: detected };
    }, { count: null, names: [] });
  }

  // ===================================================================
  // ENV — runtime / environment tells + API-surface probes
  // ===================================================================
  function timezoneBlock() {
    return safe(function () {
      var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      var offset = new Date().getTimezoneOffset();
      var loc = (nav.language || '').toLowerCase();
      var mismatch = false;
      if (loc.indexOf('en-us') === 0 && tz && !/america|us\/|pacific|mountain|central|eastern/i.test(tz)) mismatch = true;
      return { tz: tz, offsetMin: offset, locale: nav.language, mismatch: mismatch,
        calendar: safe(function () { return Intl.DateTimeFormat().resolvedOptions().calendar; }, null) };
    }, null);
  }

  function permissionAnomaly() {
    return new Promise(function (resolve) {
      try {
        var notif = (global.Notification && Notification.permission) || null;
        if (!nav.permissions || !nav.permissions.query) return resolve({ notif: notif, query: null, anomaly: false });
        nav.permissions.query({ name: 'notifications' }).then(function (st) {
          resolve({ notif: notif, query: st.state, anomaly: (notif === 'denied' && st.state === 'prompt') });
        }).catch(function () { resolve({ notif: notif, query: null, anomaly: false }); });
      } catch (e) { resolve({ notif: null, query: null, anomaly: false }); }
    });
  }

  function mediaDevicesBlock() {
    return new Promise(function (resolve) {
      if (!nav.mediaDevices || !nav.mediaDevices.enumerateDevices) return resolve({ supported: false });
      nav.mediaDevices.enumerateDevices().then(function (list) {
        var k = { audioinput: 0, audiooutput: 0, videoinput: 0 };
        list.forEach(function (d) { if (k[d.kind] != null) k[d.kind]++; });
        resolve({ supported: true, total: list.length, kinds: k });
      }).catch(function () { resolve({ supported: true, total: null }); });
    });
  }

  function batteryBlock() {
    return new Promise(function (resolve) {
      if (!nav.getBattery) return resolve({ supported: false });
      nav.getBattery().then(function (b) {
        resolve({ supported: true, charging: b.charging, level: b.level,
          chargingTime: b.chargingTime, dischargingTime: b.dischargingTime });
      }).catch(function () { resolve({ supported: false }); });
    });
  }

  // Speech voices load asynchronously: a first getVoices() call returns [] even on real Macs and
  // iPhones. Voices are requested at page load (see bottom) and re-counted here after waiting for
  // 'voiceschanged' (<=900 ms), so `count: 0, waited: true` really means "no voices installed" —
  // typical of a cloud VM with no speech engine.
  function speechVoices() {
    return new Promise(function (resolve) {
      var ss = global.speechSynthesis;
      if (!ss || !ss.getVoices) return resolve({ count: null, waited: false });
      var now0 = safe(function () { return ss.getVoices().length; }, 0);
      if (now0) return resolve({ count: now0, waited: true });
      var done = false;
      function fin() { if (done) return; done = true; resolve({ count: safe(function () { return ss.getVoices().length; }, 0), waited: true }); }
      try { if (ss.addEventListener) ss.addEventListener('voiceschanged', fin); else ss.onvoiceschanged = fin; } catch (_) {}
      setTimeout(fin, 900);
    });
  }

  function storageBlock() {
    return new Promise(function (resolve) {
      var out = {
        localStorage: safe(function () { global.localStorage.setItem('_p', '1'); global.localStorage.removeItem('_p'); return true; }, false),
        indexedDB: safe(function () { return !!global.indexedDB; }, false), quota: null };
      if (nav.storage && nav.storage.estimate) {
        nav.storage.estimate().then(function (e) { out.quota = e.quota; out.usage = e.usage; resolve(out); }).catch(function () { resolve(out); });
      } else resolve(out);
    });
  }

  function apiSurface() {
    return {
      bluetooth: !!nav.bluetooth, usb: !!nav.usb, serial: !!nav.serial, hid: !!nav.hid,
      gamepad: !!nav.getGamepads, share: !!nav.share, clipboard: !!nav.clipboard,
      webrtc: !!(global.RTCPeerConnection || global.webkitRTCPeerConnection), // PRESENCE only; no candidates read
      mediaSource: !!global.MediaSource,
      connection: safe(function () { var c = nav.connection || {};
        return { effectiveType: c.effectiveType, rtt: c.rtt, downlink: c.downlink, saveData: c.saveData }; }, null),
      perfMemory: safe(function () { return !!perf.memory; }, false),
      chromeObj: safe(function () { return !!global.chrome; }, false),
      chromeRuntime: safe(function () { return !!(global.chrome && global.chrome.runtime); }, false),
      codecs: safe(function () { var v = doc.createElement('video');
        return { h264: v.canPlayType('video/mp4; codecs="avc1.42E01E"'), webm: v.canPlayType('video/webm; codecs="vp9"') }; }, null),
    };
  }

  function automationBlock() {
    var hits = [], g = global, d = doc;
    [['webdriver', function () { return nav.webdriver === true; }],
     ['cdc_', function () { var re = new RegExp('\\$?cdc_|\\$chrome_asyncScriptInfo'); for (var k in d) if (re.test(k)) return true; return false; }],
     ['__webdriver', function () { return !!(d.__webdriver_evaluate || d.__selenium_evaluate || d.__webdriver_script_fn); }],
     ['__playwright', function () { return !!(g.__playwright || g.__pw_manual || g.__PW_inspect); }],
     ['__puppeteer', function () { return !!(g.__puppeteer_utility_world__ || g.puppeteer); }],
     ['phantom', function () { return !!(g._phantom || g.callPhantom || g.phantom); }],
     ['nightmare', function () { return !!g.__nightmare; }],
     ['domAutomation', function () { return !!(g.domAutomation || g.domAutomationController); }],
     ['selenium', function () { return !!(g.__selenium_unwrapped || g.__fxdriver_unwrapped ||
        d.documentElement.getAttribute('selenium') || d.documentElement.getAttribute('webdriver')); }],
    ].forEach(function (p) { if (safe(p[1], false)) hits.push(p[0]); });

    var patched = [];
    [['Function.toString', g.Function.prototype.toString],
     ['permissions.query', nav.permissions && nav.permissions.query],
     ['WebGL.getParameter', g.WebGLRenderingContext && g.WebGLRenderingContext.prototype.getParameter],
     ['canvas.toDataURL', g.HTMLCanvasElement && g.HTMLCanvasElement.prototype.toDataURL],
     ['Element.attachShadow', g.Element && g.Element.prototype.attachShadow],
    ].forEach(function (p) { if (p[1] && isNative(p[1]) === false) patched.push(p[0]); });

    return { hits: hits, patchedNatives: patched,
      permissionsMissing: !(nav.permissions && nav.permissions.query), notificationMissing: !global.Notification };
  }

  // ===================================================================
  // BEHAVIOUR — live accumulator
  // ===================================================================
  var B = {
    firstInteractT: null, interactions: 0,
    mouse: { moves: 0, pathLen: 0, last: null, steps: [], angles: [], vel: [], trusted: 0, untrusted: 0, lastT: null },
    clicks: [], untrustedClicks: 0,
    keys: { down: 0, up: 0, trusted: 0, untrusted: 0, flights: [], dwell: [], _down: {}, lastT: null,
            pasteChunks: 0, inputNoKey: 0, inputEvents: 0, chunkInserts: 0, chunkPw: 0, chunkMax: 0, pwDown: 0, pwAssist: 0, assist: 0, log: [] },
    valueSetsCold: 0, coldFocus: 0, focusEvents: 0, fields: {},
    scroll: { events: 0, wheel: 0, lastY: null, dist: 0 },
    pointer: { types: {}, pressures: [] },
    visibility: { hidden: 0, blurs: 0 },
    idleGaps: [], _lastActT: null,
    autofilled: 0, _afSeen: (typeof WeakSet !== 'undefined' ? new WeakSet() : null),
    _ap: { m: 0, last: null, t: null },   // cursor approach since the previous click
  };
  function markInteract(trusted) {
    B.interactions++;
    if (trusted && B.firstInteractT == null) B.firstInteractT = now();
    var t = now();
    if (B._lastActT != null) { var gap = t - B._lastActT; if (gap > 400) B.idleGaps.push(Math.round(gap)); }
    B._lastActT = t;
  }
  function cap(arr, v, n) { arr.push(v); if (arr.length > (n || 200)) arr.shift(); }
  function isTextEntry(t) {
    if (!t) return false;
    if (t.isContentEditable) return true;
    var tag = (t.tagName || '').toLowerCase();
    if (tag === 'textarea') return true;
    if (tag !== 'input') return false;
    return /^(text|email|password|search|tel|url|number)$/.test((t.type || 'text').toLowerCase());
  }

  // ---- per-field entry record (any page: sign-in, contact form, ZIP search) ----
  // kind: pw (password) · cred (autofillable: username/email/name/tel/address — password managers
  // and address autofill write these) · free (textarea, search, autocomplete=off: nothing but a
  // person or a script ever writes here) · other.
  function fieldKind(t) {
    var type = (t.type || '').toLowerCase(), ac = ((t.getAttribute && t.getAttribute('autocomplete')) || '').toLowerCase();
    if (type === 'password') return 'pw';
    if ((t.tagName || '').toLowerCase() === 'textarea' || type === 'search' || ac === 'off') return 'free';
    if (/user|email|name|tel|street|address|postal|country|cc-|organization/.test(ac) || type === 'email' || type === 'tel') return 'cred';
    return 'other';
  }
  function F(t) {
    if (!t || !isTextEntry(t) || t.isContentEditable) return null;
    var key = t.name || t.id || '?';
    var f = B.fields[key];
    if (!f) { if (Object.keys(B.fields).length >= 20) return null;
      f = B.fields[key] = { kind: fieldKind(t), keys: 0, ins: 0, chunk: 0, comp: 0, untrusted: 0, assist: 0, cold: 0, len: 0 }; }
    return f;
  }

  function installBehaviour() {
    if (!doc) return;
    // Browser/password-manager autofill detector: Chromium applies :-webkit-autofill to
    // autofilled fields, firing this no-op animation. Lets us tell a saved-password/autofill
    // fill (fires a keystroke-less input event) apart from a CDP agent's insertText.
    try {
      var st = doc.createElement('style');
      st.textContent = '@keyframes pxAF{from{}to{}}input:-webkit-autofill,textarea:-webkit-autofill,select:-webkit-autofill{animation-name:pxAF;animation-duration:.01s;}';
      (doc.head || doc.documentElement).appendChild(st);
      doc.addEventListener('animationstart', function (e) {
        if (e.animationName === 'pxAF') { var t = e.target;
          if (t && B._afSeen && !B._afSeen.has(t)) { B._afSeen.add(t); B.autofilled++; }
          else if (!B._afSeen) B.autofilled++; }
      }, true);
    } catch (_) {}
    doc.addEventListener('mousemove', function (e) {
      var m = B.mouse; if (e.isTrusted) { m.trusted++; markInteract(true); } else m.untrusted++;
      if (e.isTrusted) { B._ap.m++; B._ap.t = now(); B._ap.last = null; }
      if (m.last) {
        var dx = e.clientX - m.last.x, dy = e.clientY - m.last.y, d = Math.sqrt(dx * dx + dy * dy);
        if (e.isTrusted) B._ap.last = +d.toFixed(1);
        m.pathLen += d; cap(m.steps, +d.toFixed(2));
        if (d > 0.5) cap(m.angles, +Math.atan2(dy, dx).toFixed(3));
        if (m.lastT != null) { var dt = now() - m.lastT; if (dt > 0) cap(m.vel, +(d / dt).toFixed(3)); }
      }
      m.last = { x: e.clientX, y: e.clientY }; m.lastT = now(); m.moves++;
    }, { capture: true, passive: true });

    doc.addEventListener('click', function (e) {
      if (e.isTrusted) markInteract(true); else B.untrustedClicks++;
      try {
        var t = e.target, r = t.getBoundingClientRect ? t.getBoundingClientRect() : null;
        // kb: keyboard-activated (Enter/Space on a control) — fires a trusted click at (0,0) with
        // detail 0, so it must never count as a "click with no cursor travel".
        // pt: pointer type of the press that produced this click (mouse/touch/pen), if recent.
        var lp = B._lastPtr;
        var rec = { trusted: e.isTrusted, t: Math.round(now() - T0), kb: e.detail === 0,
                    pt: (lp && (now() - lp.t) < 1500) ? lp.type : null,
                    // approach: mousemoves since the previous click, size of the LAST step before
                    // this click (px; null if unknown), ms since that move. A CDP click is one
                    // giant jump then the click ~2-5 ms later; a human ends on small steps.
                    apM: B._ap.m, apL: B._ap.last, apG: B._ap.t != null ? Math.round(now() - B._ap.t) : null };
        B._ap = { m: 0, last: null, t: null };
        if (r) { rec.offX = +(e.clientX - (r.left + r.width / 2)).toFixed(1); rec.offY = +(e.clientY - (r.top + r.height / 2)).toFixed(1); }
        cap(B.clicks, rec, 60);
      } catch (_) {}
    }, true);

    doc.addEventListener('keydown', function (e) {
      var k = B.keys; k.down++;
      if (e.isTrusted) { k.trusted++; markInteract(true); } else k.untrusted++;
      // Printable keystrokes landing in a password field (compared server-side with the submitted
      // password length). Password fields get no dictation, autocomplete dropdown or prediction,
      // so a human's password arrives either by keys or by a detectable autofill/paste.
      var tg = e.target;
      if (e.isTrusted && tg && (tg.type || '').toLowerCase() === 'password' && e.key && e.key.length === 1) k.pwDown++;
      if (e.isTrusted && e.key && e.key.length === 1) { var fk = F(tg); if (fk) fk.keys++; }
      var code = e.code || e.key; k._down[code] = now();
      if (k.lastT != null) cap(k.flights, Math.round(now() - k.lastT)); k.lastT = now();
    }, true);
    doc.addEventListener('keyup', function (e) {
      var k = B.keys, code = e.code || e.key, d = k._down[code];
      if (d != null) { k.up++; cap(k.dwell, Math.round(now() - d)); delete k._down[code]; }
    }, true);
    doc.addEventListener('input', function (e) {
      var k = B.keys; k.inputEvents++;
      var it = e.inputType || '', t = e.target;
      if (it === 'insertFromPaste' || it === 'insertFromDrop') k.pasteChunks++;
      // Only genuine typed-text insertion counts. Checkboxes, radios, selects and ranges also
      // fire `input` on a click/tap (inputType empty) — those are NOT text injection. Autofilled
      // fields (:-webkit-autofill) and paste/drop/autocorrect replacements are excluded too.
      var typedInsert = it === 'insertText' || it === 'insertCompositionText';
      var autofill = false;
      try { autofill = !!(t && t.matches && t.matches(':-webkit-autofill')); } catch (_) {}
      if (e.isTrusted && typedInsert && isTextEntry(t) && !autofill &&
          (k.lastT == null || (now() - k.lastT) > 1200)) k.inputNoKey++;
      // Multi-character insertText: a person typing produces ONE character per input event;
      // CDP insertText / Playwright fill deliver whole strings in one event. (Paste, drop,
      // autocorrect and IME composition use other inputTypes and are not counted here.)
      var dl = (e.data || '').length, pw = !!(t && (t.type || '').toLowerCase() === 'password');
      // Browser- or user-assisted entry (dropdown pick, paste, drop, autofill): never injection.
      if (autofill || /^insert(ReplacementText|FromPaste|FromDrop|FromYank)$/.test(it)) { if (pw) k.pwAssist++; else k.assist++; }
      var fi = F(t);
      if (fi) {
        if (!e.isTrusted) fi.untrusted++;
        else if (autofill || /^insert(ReplacementText|FromPaste|FromDrop|FromYank)$/.test(it)) fi.assist++;
        else if (it === 'insertCompositionText') fi.comp++;
        else if (it === 'insertText') { fi.ins++; if (dl > 1) fi.chunk++; }
      }
      if (e.isTrusted && it === 'insertText' && isTextEntry(t) && !autofill && dl > 1) {
        k.chunkInserts++; if (pw) k.chunkPw++; if (dl > k.chunkMax) k.chunkMax = dl;
      }
      cap(k.log, { it: it || '-', n: dl, pw: pw ? 1 : 0, tr: e.isTrusted ? 1 : 0, af: autofill ? 1 : 0,
                   k: k.lastT == null ? null : Math.round(now() - k.lastT) }, 40);
    }, true);

    doc.addEventListener('focusin', function () {
      B.focusEvents++;
      if (B._lastActT == null || (now() - B._lastActT) > 700) B.coldFocus++;
    }, true);

    doc.addEventListener('wheel', function () { B.scroll.wheel++; B.scroll.events++; markInteract(true); }, { capture: true, passive: true });
    global.addEventListener('scroll', function () {
      var y = global.scrollY, s = B.scroll;
      if (s.lastY != null) s.dist += Math.abs(y - s.lastY);
      s.lastY = y; s.events++;
    }, { capture: true, passive: true });

    doc.addEventListener('pointerdown', function (e) {
      var p = B.pointer; p.types[e.pointerType || '?'] = (p.types[e.pointerType || '?'] || 0) + 1;
      B._lastPtr = { t: now(), type: e.pointerType || '?' };
      if (typeof e.pressure === 'number') cap(p.pressures, +e.pressure.toFixed(3));
    }, true);

    doc.addEventListener('visibilitychange', function () { if (doc.hidden) B.visibility.hidden++; }, true);
    global.addEventListener('blur', function () { B.visibility.blurs++; }, true);

    try {
      [global.HTMLInputElement, global.HTMLTextAreaElement].forEach(function (C) {
        var d = Object.getOwnPropertyDescriptor(C.prototype, 'value');
        if (!d || !d.set || d.set.__pico) return;
        var set = d.set;
        var repl = function (v) {
          try { var k = B.keys;
            if ((k.lastT == null || (now() - k.lastT) > 500) && v != null && String(v).length) {
              B.valueSetsCold++; var fc = F(this); if (fc) fc.cold++; }
          } catch (_) {}
          return set.call(this, v);
        };
        repl.__pico = 1;
        Object.defineProperty(C.prototype, 'value', { configurable: true, enumerable: d.enumerable, get: d.get, set: repl });
      });
    } catch (_) {}
  }

  function behaviourSnapshot() {
    var k = B.keys, m = B.mouse;
    return {
      interactions: B.interactions,
      firstInteractMs: B.firstInteractT != null ? Math.round(B.firstInteractT - T0) : null,
      sessionMs: Math.round(now() - T0),
      mouse: { moves: m.moves, pathLen: Math.round(m.pathLen), trusted: m.trusted, untrusted: m.untrusted,
        steps: m.steps.slice(-120), angles: m.angles.slice(-120), vel: m.vel.slice(-120) },
      clicks: B.clicks.slice(), untrustedClicks: B.untrustedClicks,
      keys: { down: k.down, up: k.up, trusted: k.trusted, untrusted: k.untrusted,
        flights: k.flights.slice(-120), dwell: k.dwell.slice(-120),
        pasteChunks: k.pasteChunks, inputNoKey: k.inputNoKey, inputEvents: k.inputEvents,
        chunkInserts: k.chunkInserts, chunkPw: k.chunkPw, chunkMax: k.chunkMax,
        pwDown: k.pwDown, pwAssist: k.pwAssist, assist: k.assist, log: k.log.slice() },
      valueSetsCold: B.valueSetsCold, coldFocus: B.coldFocus, focusEvents: B.focusEvents,
      fields: (function () { var out = {};
        try { Array.prototype.forEach.call(doc.querySelectorAll('input,textarea'), function (el) {
          var f = F(el); if (!f) return; f.len = (el.value || '').length;
          try { if (el.matches(':-webkit-autofill')) f.assist++; } catch (_) {}
        }); } catch (_) {}
        Object.keys(B.fields).forEach(function (k2) { out[k2] = Object.assign({}, B.fields[k2]); });
        return out; })(),
      autofilled: (function () { var af = B.autofilled;
        try { af = Math.max(af, doc.querySelectorAll('input:-webkit-autofill,textarea:-webkit-autofill,select:-webkit-autofill').length); } catch (_) {}
        return af; })(),
      scroll: B.scroll, pointer: { types: B.pointer.types, pressures: B.pointer.pressures.slice(-40) },
      visibility: B.visibility, idleGaps: B.idleGaps.slice(-40),
    };
  }

  // ===================================================================
  // ASSEMBLE
  // ===================================================================
  function collect() {
    return Promise.all([uaHighEntropy(), webgpuBlock(), audioFP(), permissionAnomaly(), speechVoices(),
                        mediaDevicesBlock(), batteryBlock(), storageBlock()])
      .then(function (a) {
        return {
          v: 2, ts: Date.now(), collectMs: Math.round(now() - T0),
          static: { navigator: navigatorBlock(), uaHighEntropy: a[0], plugins: pluginsBlock(),
            screen: screenBlock(), canvas: canvasFP(), webgl: webglBlock(), webgpu: a[1], audio: a[2], fonts: fontsBlock() },
          env: { timezone: timezoneBlock(), permission: a[3], speech: a[4], mediaDevices: a[5], battery: a[6],
            storage: a[7], api: apiSurface(), automation: automationBlock() },
          behaviour: behaviourSnapshot(),
        };
      });
  }

  installBehaviour();
  try { if (global.speechSynthesis && global.speechSynthesis.getVoices) global.speechSynthesis.getVoices(); } catch (_) {}
  global.Collector = { collect: collect, _behaviour: behaviourSnapshot };
})(typeof window !== 'undefined' ? window : this);

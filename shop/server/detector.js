'use strict';
// Pico Mobile — server-side fused scorer. The browser only COLLECTS; every
// threshold and the verdict live here, so a visiting agent cannot read how it is judged.
//
// DESIGN PRINCIPLE (why this is not the old demo): PRECISION FIRST.
//   * HARD tells  — things a human physically cannot produce (untrusted input events,
//                   automation globals, a honeypot field a human can't see, a cold
//                   .checked=true). ANY one ⇒ agent. Human false-positive ≈ 0.
//   * SOFT tells  — things fast/automated clients TEND to do but humans sometimes do too
//                   (fast fill, rigid cadence, cold .value=, no mouse, software GPU,
//                   direct navigation). A soft tell NEVER flags alone — it needs a second
//                   INDEPENDENT family. This is exactly what the old instrument got wrong:
//                   autofill / fast typing tripped it solo. Here they can't.
//
// Four signal domains fuse: browser fingerprint (STATIC), environment (ENV),
// behaviour kinematics (BEH), and e-commerce honeypots (HP).

// ---- de-obfuscation (mirror of bundle.js) : base64 -> reverse -> XOR 0x5a ----
function decodeBundle(enc) {
  try {
    var b = Buffer.from(String(enc), 'base64');
    var out = Buffer.alloc(b.length);
    for (var i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i] ^ 0x5a;
    return JSON.parse(out.toString('utf8'));
  } catch (_) { return null; }
}

// ---- small stats ----------------------------------------------------------
function mean(a) { return a.length ? a.reduce(function (s, x) { return s + x; }, 0) / a.length : null; }
function std(a) { var m = mean(a); if (m == null) return null; return Math.sqrt(mean(a.map(function (x) { return (x - m) * (x - m); }))); }
function cv(a) { a = (a || []).filter(function (x) { return isFinite(x); }); if (a.length < 4) return null; var m = mean(a); if (!m) return null; return std(a) / m; }

// ---- slide-to-order kinematics (catches the careful local agent) ----------
function scoreSlide(slider) {
  if (!slider || !slider.samples || slider.samples.length < 4) return { present: false };
  var s = slider.samples;
  var xs = s.map(function (p) { return p.x; }), ys = s.map(function (p) { return p.y; }), ts = s.map(function (p) { return p.t; });
  var travel = Math.max.apply(null, xs) - Math.min.apply(null, xs);
  if (travel < 30) return { present: false };
  var untrusted = s.some(function (p) { return p.tr === 0; });   // dispatched pointer events
  var dx = [], dt = [], vel = [];
  for (var i = 1; i < s.length; i++) {
    var ddx = xs[i] - xs[i - 1], ddt = Math.max(1, ts[i] - ts[i - 1]);
    dx.push(ddx); dt.push(ddt); vel.push(ddx / ddt);
  }
  var velCV = cv(vel.map(Math.abs)), dtCV = cv(dt), yStd = std(ys);
  var flat = yStd != null && yStd < 1.5;             // no vertical wobble
  var steady = velCV != null && velCV < 0.15;        // constant speed
  var robotic = dtCV != null && dtCV < 0.08;         // machine-even sampling
  var teleport = s.length < 6 && travel > 120;       // few points across a wide slide
  var syntheticCount = [flat, steady, robotic].filter(Boolean).length;
  return {
    present: true, untrusted: untrusted, samples: s.length, travel: Math.round(travel),
    velCV: velCV, dtCV: dtCV, yStd: yStd, teleport: teleport,
    hard: untrusted || syntheticCount === 3,          // dispatched OR perfectly machine path
    soft: !untrusted && (teleport || syntheticCount === 2),
  };
}

// ---- mouse kinematics -----------------------------------------------------
function scoreMouse(b) {
  var m = (b && b.mouse) || { moves: 0 };
  var clicks = (b && b.clicks) || [];
  // Only genuine MOUSE clicks are analysed for cursor kinematics. Excluded:
  //   kb    — keyboard-activated (Enter/Space): trusted click at (0,0), detail 0
  //   touch/pen — taps have no cursor travel by nature, and iOS snaps taps toward centres
  var mouseClicks = clicks.filter(function (c) { return c.trusted && !c.kb && c.pt !== 'touch' && c.pt !== 'pen'; });
  // Robot path: a ruler-straight direction AND a constant speed across many samples. Humans can
  // glide straight on a trackpad, but their speed rises and falls (bell-shaped profile), so the
  // step-size CV stays high; linear-interpolation bots move at near-constant step size.
  var angStd = std((m.angles || []).map(Number));
  var stepCV = cv((m.steps || []).map(Number).filter(function (x) { return x > 0.5; }));
  var straight = m.moves > 25 && angStd != null && angStd < 0.08 && stepCV != null && stepCV < 0.2;
  // mouse clicks that happened with no cursor travel at all
  var clickNoMove = mouseClicks.length >= 1 && m.moves === 0;
  // center-locked mouse clicks: repeatedly hitting dead-centre of targets
  var centered = mouseClicks.filter(function (c) { return Math.abs(c.offX || 0) < 1.5 && Math.abs(c.offY || 0) < 1.5; }).length;
  var centerLock = mouseClicks.length >= 3 && centered / mouseClicks.length > 0.8;
  // Teleport clicks (verified on a real CDP-driven browser): the cursor arrives in ONE jump of
  // hundreds of px and the click lands ~2-5 ms later. A human's last move before a click is a
  // small decelerating step. Counted when the last step is a big jump with <=2 approach moves,
  // or (first move on the page, step unknown) a single move followed by a click within 25 ms.
  var tele = mouseClicks.filter(function (c) {
    if (c.apM == null) return false;
    if (c.apM >= 1 && c.apM <= 2 && c.apL != null && c.apL >= 60) return true;
    return c.apM === 1 && c.apL == null && c.apG != null && c.apG <= 25;
  }).length;
  var teleport = tele >= 2;
  // Scripted easing: synthetic movers (CDP Input.dispatchMouseEvent with an ease-in-out curve,
  // ghost-cursor, Playwright `steps`) produce a velocity profile that is EXACTLY mirror-symmetric
  // — step lengths rise and fall through identical values (6.32, 53.14, 75.61, 119.27, 75.61,
  // 53.14, 6.32). A hand's acceleration and deceleration phases never match to 0.01 px.
  // Counted per segment: a contiguous run of >=5 non-zero steps that reads the same backwards,
  // with a peak >20 px (excludes jitter of 1-2 px, where integer-pixel repeats are common).
  var st = (m.steps || []).map(Number), mirrored = 0, i = 0;
  while (i < st.length) {
    if (!(st[i] > 0)) { i++; continue; }
    var j = i; while (j + 1 < st.length && st[j + 1] > 0) j++;
    for (var a = i; a <= j; a++) for (var b2 = j; b2 - a + 1 >= 5; b2--) {
      var ok = true, pk = 0;
      for (var q = 0; q < (b2 - a + 1); q++) { if (st[a + q] !== st[b2 - q]) { ok = false; break; } if (st[a + q] > pk) pk = st[a + q]; }
      if (ok && pk > 20) { mirrored++; a = b2; break; }
    }
    i = j + 1;
  }
  // Sparse cursor: a real mouse reports ~60-120 moves/s, so travelling to a target yields
  // dozens of events. Agents emit a handful per click. (Remote desktops coalesce events too, so
  // this is informational, never verdict-bearing.)
  var perClick = mouseClicks.length ? (m.moves || 0) / mouseClicks.length : null;
  var sparse = mouseClicks.length >= 2 && perClick != null && perClick < 8;
  return { moves: m.moves, straight: straight, clickNoMove: clickNoMove, centerLock: centerLock, teleport: teleport,
           tele: tele, angStd: angStd, stepCV: stepCV, mirrored: mirrored, sparse: sparse, perClick: perClick };
}

// ===========================================================================
// MAIN
// ===========================================================================
function assess(bundle) {
  // Evidence is split by DOMAIN. Environment (ENV) and honeypot (HP) evidence carry the verdict;
  // behaviour (BEH) is supporting evidence only and never produces "agent" on its own.
  var envHard = [], hpHard = [], behHard = [], soft = {};   // soft keyed by FAMILY (counts once)
  function addSoft(family, why) { (soft[family] = soft[family] || []).push(why); }

  if (!bundle || !bundle.collector) {
    return { label: 'agent', confidence: 72, tier: 'OPAQUE',
             hard: ['no telemetry bundle — client posted the API with no instrumentation'],
             soft: {}, reasons: ['OPAQUE: no signal bundle attached (direct API call or scripts stripped)'],
             boughtTrap: !!(bundle && bundle.hp && bundle.hp.nav && bundle.hp.nav.boughtTrap) };
  }
  var C = bundle.collector, HP = bundle.hp || {};
  var S = C.static || {}, E = C.env || {}, B = C.behaviour || {};

  // Pointer / keyboard context used by several checks below.
  var ptypes = (B.pointer && B.pointer.types) || {};
  var touchOrPen = (ptypes.touch || 0) > 0 || (ptypes.pen || 0) > 0;
  var mouseMove = B.mouse && (B.mouse.moves || 0) > 15 && (B.mouse.untrusted || 0) === 0;
  var kbClicks = (B.clicks || []).filter(function (c) { return c.trusted && c.kb; }).length;
  var keyboardNav = (B.keys && (B.keys.trusted || 0) >= 2) || kbClicks > 0;   // Tab/Enter-driven use

  // ---------- BEH hard: untrusted pointer events (supporting evidence only) ----------
  if ((B.untrustedClicks || 0) > 0) behHard.push('untrusted click events (isTrusted=false ×' + B.untrustedClicks + ')');
  if (B.mouse && (B.mouse.untrusted || 0) > 0) behHard.push('dispatched mousemove events ×' + B.mouse.untrusted);
  // Untrusted KEY events are WEAK: password-manager extensions (Bitwarden, LastPass, 1Password,
  // Dashlane) fill fields by dispatching synthetic keydown/keyup events. Informational only.
  if (B.keys && (B.keys.untrusted || 0) > 0) addSoft('synthetic', 'untrusted key events ×' + B.keys.untrusted + ' (also password-manager extensions)');

  // Keystroke-less typed-text insert. The collector now counts ONLY real text insertion
  // (inputType insertText/insertCompositionText on a text field, not autofilled) — checkbox,
  // select and radio `input` events, paste and autocorrect no longer count. Still corroborated:
  // HARD only when there is no organic pointer activity (cursor movement, touch or pen) —
  // dictation and predictive-text users still interact with the page; a CDP bulk-fill doesn't.
  if (B.keys) {
    var ink = B.keys.inputNoKey || 0;
    if (ink > 0 && !(touchOrPen || mouseMove)) {
      behHard.push('text inserted with no keystrokes and no pointer activity (CDP insertText ×' + ink + ')');
    } else if (ink > 0) {
      addSoft('fill', 'text inserted without keystrokes ×' + ink + ' (dictation / predictive-text pattern, pointer active)');
    }
  }

  // Multi-character insertText: one trusted input event carrying a whole string. Keyboards
  // deliver one character per event; CDP Input.insertText / Playwright fill deliver the string.
  // In a PASSWORD field there is no autocorrect, prediction or dictation, so it is STRONG
  // behaviour (still needs environment or honeypot corroboration to flag).
  if (B.keys && (B.keys.chunkPw || 0) > 0)
    addSoft('inject', 'password entered as a whole string in one input event (×' + B.keys.chunkPw + ', up to ' + B.keys.chunkMax + ' chars) — scripted insertText');
  else if (B.keys && (B.keys.chunkInserts || 0) > 0 && (B.keys.chunkMax || 0) >= 4)
    addSoft('fill', 'multi-character text inserts ×' + B.keys.chunkInserts + ' (also predictive text / dictation)');
  // ---- Per-field entry analysis (any form on any page) ----
  // For every text field the collector records how its text arrived: real keystrokes, typed
  // insertText events, IME composition, browser assists (autofill / dropdown pick / paste / drop),
  // untrusted (script-dispatched) input events, and cold JS `.value=` writes. The server supplies
  // the submitted length of each field. Verdict weight depends on the field KIND:
  //   pw   password — no dictation, dropdown or prediction exist here; a keystroke deficit with no
  //        autofill/paste/password-manager footprint is STRONG (desktop) — injection
  //   free textarea / search / autocomplete=off — no password manager or address autofill writes
  //        here, so script-dispatched input or a cold `.value=` write is STRONG
  //   cred / other — autofill, address extensions, dropdown picks and dictation are all normal →
  //        recorded as weak (informational)
  // Multi-character trusted insertText outside passwords stays weak: OS dictation produces it too.
  // Phones/tablets/touch: soft keyboards report keys unreliably, so everything here is weak.
  var SVk = bundle.server || {}, TL = SVk.typedLen, FL = SVk.fields || null;
  var mob = (S.navigator && ((S.navigator.uaData && S.navigator.uaData.mobile) || (S.navigator.maxTouchPoints || 0) > 0)) || touchOrPen;
  var pmTrace = (B.valueSetsCold || 0) > 0 || (B.keys && (B.keys.untrusted || 0) > 0);
  if (B.fields && Object.keys(B.fields).length) {
    Object.keys(B.fields).forEach(function (name) {
      var f = B.fields[name] || {};
      var L = FL && FL[name] != null ? FL[name] : (f.len || 0);
      if (L < 3 || (f.assist || 0) > 0) return;
      var keys = f.keys || 0, deficit = keys < L * 0.6;
      if (f.kind === 'pw') {
        if (deficit && !pmTrace && !((B.autofilled || 0) > 0) && !((B.keys && B.keys.pasteChunks) > 0))
          addSoft(mob ? 'fill' : 'inject', 'field "' + name + '" (password): ' + keys + ' keystrokes for ' + L + ' characters — no autofill, paste or password manager');
      } else if (f.kind === 'free') {
        if ((f.untrusted || 0) > 0 && deficit)
          addSoft(mob ? 'fill' : 'inject', 'field "' + name + '" (free text): filled by script-dispatched input events (×' + f.untrusted + '), ' + keys + ' keystrokes for ' + L + ' chars');
        else if ((f.cold || 0) > 0 && deficit && !(f.ins > 0) && !(f.comp > 0))
          addSoft(mob ? 'fill' : 'inject', 'field "' + name + '" (free text): value written by script (.value=) with ' + keys + ' keystrokes for ' + L + ' chars');
        else if (deficit && (f.chunk || 0) > 0)
          addSoft('fill', 'field "' + name + '": text arrived in multi-character inserts (' + keys + ' keys for ' + L + ' chars) — CDP insertText or dictation');
      } else if (deficit && L >= 4) {
        addSoft('fill', 'field "' + name + '" (' + f.kind + '): ' + keys + ' keystrokes for ' + L + ' chars (autofill / dictation / dropdown possible)');
      }
    });
  } else if (TL && B.keys) {
    // Older collector (no per-field record): password-only counts if present, else form-wide info.
    var assisted = (B.autofilled || 0) > 0 || (B.keys.pasteChunks || 0) > 0 || (B.keys.pwAssist || 0) > 0 || (HP.offer && HP.offer.autofill);
    if (typeof TL === 'object' && B.keys.pwDown != null) {
      if (TL.p >= 4 && !assisted && !pmTrace && B.keys.pwDown < TL.p * 0.6 && (B.keys.trusted || 0) > 0)
        addSoft(mob ? 'fill' : 'inject', 'password: ' + B.keys.pwDown + ' keystrokes for ' + TL.p + ' characters (no autofill, paste or password manager)');
    } else {
      var tot = typeof TL === 'object' ? TL.u + TL.p : TL, kd = B.keys.down || 0;
      if (kd > 0 && kd < tot * 0.6 && !assisted) addSoft('fill', 'only ' + kd + ' keystrokes for ' + tot + ' submitted characters (form-wide; informational)');
    }
  }

  // Server-observed form honeypots (contact / locator / sign-in)
  if (SVk.contentCanary) hpHard.push('message contains the reference code shown only to AI assistants (' + SVk.contentCanary + ')');
  if (SVk.hiddenOption) addSoft('declare', 'chose the hidden menu option "' + SVk.hiddenOption + '" (not shown in the visible dropdown)');

  // ---------- ENV hard: automation frameworks (verdict on their own) ----------
  var auto = E.automation || {};
  if ((auto.hits || []).length) envHard.push('automation globals: ' + auto.hits.join(', '));
  if (S.navigator && S.navigator.webdriver) envHard.push('navigator.webdriver=true');
  if (S.navigator && S.navigator.ua && /headlesschrome/i.test(S.navigator.ua)) envHard.push('HeadlessChrome UA');
  // STRONG env: native functions patched (stealth shims — but also privacy extensions).
  if ((auto.patchedNatives || []).length) addSoft('stealth', 'patched native fns: ' + auto.patchedNatives.join(', ') + ' (also privacy extensions)');
  // WEAK env: the notification/permission contradiction — modern headless no longer shows it,
  // and incognito-style profiles can, so it only ever corroborates.
  if (E.permission && E.permission.anomaly) addSoft('headless', 'notification/permission contradiction');

  // ---------- HP hard: honeypots a human can't trip (verdict on their own) ----------
  // The decoy is outside every form and carries password-manager ignore hints. If the browser
  // nonetheless AUTOFILLED it (:-webkit-autofill), that's strong-soft, not hard.
  if (HP.offer && HP.offer.filled && !HP.offer.autofill) hpHard.push('off-screen decoy promo field filled → DOM/tree-driven fill');
  if (HP.offer && HP.offer.filled && HP.offer.autofill) addSoft('honeypot', 'decoy field filled by browser autofill');
  if (HP.confirm && HP.confirm.coldSet) hpHard.push('order-confirm set via .checked=true (programmatic)');
  if (HP.confirm && HP.confirm.trustedToggle === false) hpHard.push('order-confirm toggled by untrusted event');
  var slide = scoreSlide(HP.slider);
  if (slide.present && slide.hard) hpHard.push('synthetic slide-to-order path (dispatched or machine-perfect)');
  // agentic canary: an invisible control reachable only by reading the DOM. A click is a
  // hard tell (humans can't see it); a mere focus (e.g. tabbed/scanned into it) is strong-soft.
  if (HP.ld && HP.ld.clicked) hpHard.push('clicked the hidden "loyalty discount" canary (invisible to humans; followed DOM instruction)');
  // Self-declaration: ticked "This order is placed by an AI assistant on my behalf".
  // Self-declaration is visible, so a person CAN tick it by accident (mis-tap, label click).
  // A tick alone is therefore review-only; it becomes "agent" with any independent corroboration
  // from behaviour or another honeypot — NOT hardware alone (VDI / old-PC users can mis-tick too).
  // Sign-in also asks a hidden "which assistant are you?" (free text). A browser autofill of it
  // is ignored. Two INDEPENDENT hidden declarations (e.g. answered "AI assistant" AND named the
  // product) are agent on their own: no person can see either control, and a screen-reader user
  // would have to deliberately claim to be an AI twice.
  var dName = HP.declare && HP.declare.name && !HP.declare.name.autofill ? HP.declare.name.value : null;
  var declBoxes = HP.declare && HP.declare.checked ? (HP.declare.n || 1) : 0;   // visible box and/or hidden answer
  var declN = declBoxes + (dName ? 1 : 0) + (bundle.server && bundle.server.hiddenOption ? 1 : 0);
  var declared = declN > 0;
  if (declBoxes) addSoft('declare', 'declared "I\'m an AI assistant" (' + (HP.declare.page || 'checkbox') + ': ' +
    (declBoxes > 1 ? 'visible box AND hidden answer' : (HP.declare.hidden ? 'visually hidden control — invisible to people' : 'visible box')) +
    ') — one declaration alone is review, agent with corroboration');
  if (dName) addSoft('declare', 'self-identified as assistant "' + dName + '" in the hidden "which assistant are you?" field');

  // ---------- HP: server-observed honeypots (attached by the server, not the client) ----------
  // Assistant-only URLs are published ONLY where a machine reads: JSON-LD structured data, a
  // hidden DOM link, /llms.txt, a visually-hidden accessibility note, and fine print addressed
  // to AI assistants. Following one ("act") is hard; merely fetching a machine-only guidance
  // file ("read": /llms.txt, /robots.txt) is strong-soft. `via` records which channel the agent
  // perceived — jsonld / dom / llms / a11y / visible.
  var SV = bundle.server || {};
  var seenVia = {};
  (SV.canary || []).forEach(function (c) {
    var key = c.kind + ':' + c.via; if (seenVia[key]) return; seenVia[key] = 1;
    if (c.kind === 'act') hpHard.push('followed an assistant-only link (channel: ' + c.via + ')');
    else addSoft('honeypot', 'fetched a machine-only guidance file (' + c.via + ')');
  });
  if (SV.boughtTrap) hpHard.push('bought the "Display only · Not for sale" unit');

  // ---------- SOFT families ----------
  // Families are split STRONG (humans almost never do this) vs WEAK (humans sometimes
  // do — fast typing, autofill, VPN, privacy browser). A soft flag needs >=1 STRONG
  // family; WEAK families alone, however many, never flag. This is the fix for the old
  // instrument tripping on autofill / fast typing.
  //
  // STRONG hardware/VM environment (family: envhw): a software GPU (SwiftShader / llvmpipe /
  // Basic Render). Cloud agents run on GPU-less micro-VMs (AWS, Cloudflare), so this is a
  // strong tell — but it still needs ONE corroborating signal, because VDI / HW-acceleration-off
  // humans show it too.
  var mobileUA = S.navigator && ((S.navigator.uaData && S.navigator.uaData.mobile) || (S.navigator.maxTouchPoints || 0) > 0);
  if (S.webgl && S.webgl.software && !mobileUA)
    addSoft('envhw', 'software WebGL on desktop (' + (S.webgl.renderer || '') + ')');
  // No WebGL at all on a desktop Chromium: newer Chrome no longer falls back to SwiftShader, so a
  // GPU-less VM now shows NO WebGL instead of software WebGL. Same class as above (also old PCs /
  // VDI with a blocked GPU), so the same rule applies: never decides alone, needs behaviour.
  // Browsers that disable WebGL by choice (Tor / Mullvad / LibreWolf: Firefox UA) are excluded.
  if (S.webgl && S.webgl.supported === false && !mobileUA && S.navigator && /Chrome\//.test(S.navigator.ua || '') && !/Firefox\//.test(S.navigator.ua || ''))
    addSoft('envhw', 'no WebGL at all on a desktop Chrome (no GPU and no software fallback — GPU-less VM shape)');
  // WEAK: micro-VM compute — a desktop reporting <=2 logical cores AND <=2 GB memory.
  // (Budget dual-core laptops exist, and Safari/Firefox hide deviceMemory, so both must be present.)
  var cores = S.navigator && S.navigator.hardwareConcurrency, memGB = S.navigator && S.navigator.deviceMemory;
  if (!mobileUA && cores != null && memGB != null && cores <= 2 && memGB <= 2)
    addSoft('vmcpu', 'micro-VM compute (' + cores + ' cores, ' + memGB + ' GB)');
  // WEAK: a desktop with zero media devices (no speakers, mic or camera) — container/VM-shaped.
  if (E.mediaDevices && E.mediaDevices.supported && E.mediaDevices.total === 0 && !mobileUA)
    addSoft('nomedia', 'no media devices at all (container/VM-shaped)');
  // GPU contradiction: WebGL claims hardware but WebGPU's adapter is a software one
  // (SwiftShader) — a spoofed WebGL renderer string over a GPU-less VM. STRONG (envhw).
  var wg = S.webgpu || {};
  if (S.webgl && !S.webgl.software && !mobileUA && /swiftshader|llvmpipe|google/i.test(wg.vendor || '') && /swiftshader|cpu|fallback/i.test((wg.architecture || '') + (wg.description || '')))
    addSoft('envhw', 'WebGL reports a hardware GPU but WebGPU adapter is software (' + wg.vendor + ') — spoofed renderer');
  // WEAK: WebGPU exposed but no adapter at all on a desktop that claims a hardware GPU.
  var plat = (S.navigator && S.navigator.uaData && S.navigator.uaData.platform) || '';
  if (wg.supported && wg.adapter === null && !mobileUA && S.webgl && !S.webgl.software && /mac|win/i.test(plat))
    addSoft('gpuless', 'WebGPU has no adapter on a ' + plat + ' desktop claiming a hardware GPU');
  // WEAK: ARM Linux desktop — Graviton/Ampere cloud hosts. (Real ARM-Linux desktops are rare:
  // Raspberry Pi, Asahi. Chrome's frozen UA always says "Linux x86_64", so UA-CH is the source.)
  var arch = S.uaHighEntropy && S.uaHighEntropy.architecture;
  if (!mobileUA && /linux/i.test(plat) && arch === 'arm')
    addSoft('dcarm', 'ARM Linux desktop (cloud-host shaped)');
  // WEAK, cloud-specific: impossible window geometry — the page viewport is exactly the whole
  // screen, yet the window around it still has a toolbar (so the window is taller than the
  // screen). A real browser window can't do that; a VM whose virtual display is sized to the
  // viewport can (Instinct: screen 1280x720, inner 1280x720, outer 1288x851). Page zoom changes
  // the viewport size, so an ordinary zoomed or maximised window won't match exactly.
  // Privacy browsers (Firefox resistFingerprinting / Tor / Mullvad / LibreWolf, Brave) report the
  // screen as the window size on purpose, so they are excluded.
  var SC = S.screen || {}, navS = S.navigator || {};
  var privacyBr = /Firefox\/|FxiOS/.test(navS.ua || '') ||
    ((navS.uaData && navS.uaData.brands) || []).some(function (b) { return /Brave/i.test(String(b)); });
  if (!mobileUA && !privacyBr && SC.w > 0 && SC.innerW === SC.w && SC.innerH === SC.h && SC.outerH > SC.innerH + 40)
    addSoft('vmgeo', 'browser window taller than the screen (viewport = full ' + SC.w + 'x' + SC.h + ' screen, window ' + SC.outerW + 'x' + SC.outerH + ') — virtual display');
  // WEAK: no speech voices after waiting for them to load. Every Mac, Windows, iOS and
  // ChromeOS install ships voices; a cloud VM's browser has no speech engine.
  // Linux desktops (real ones included) often have no speech engine, so there it is recorded but
  // not counted; on a browser claiming macOS/Windows it contradicts the claimed OS.
  var linuxUA = /linux/i.test(plat) || /x11|linux/i.test((S.navigator && S.navigator.ua) || '');
  if (E.speech && E.speech.waited && E.speech.count === 0 && !mobileUA)
    addSoft(linuxUA ? 'voice' : 'novoice', 'no speech-synthesis voices installed' + (linuxUA ? ' (Linux — informational)' : ' on a ' + (plat || 'desktop') + ' browser'));

  // WEAK locale/font environment (families: envloc, fonts) — VPNs, travellers, privacy browsers
  if (E.timezone && E.timezone.mismatch) addSoft('envloc', 'timezone/locale mismatch (' + E.timezone.tz + ' vs ' + E.timezone.locale + ')');
  if (S.fonts && S.fonts.count != null && S.fonts.count < 4 && !(S.navigator && S.navigator.uaData && S.navigator.uaData.mobile))
    addSoft('fonts', 'minimal font set (' + S.fonts.count + ')');

  // Behaviour kinematics.
  // STRONG (motor): real anomalies in cursor movement that IS present — a human's mouse path
  // is never ruler-straight over many samples, nor locked to exact target centres.
  var mz = scoreMouse(B);
  if (mz.straight) addSoft('motor', 'robot cursor path: straight at constant speed (angleStd ' + (mz.angStd || 0).toFixed(3) + ', stepCV ' + (mz.stepCV || 0).toFixed(2) + ')');
  if (mz.centerLock) addSoft('motor', 'mouse clicks locked to target centre');
  if (mz.teleport) addSoft('motor', 'teleport clicks: cursor jumped straight onto ' + mz.tele + ' targets with no approach path');
  if (mz.mirrored >= 1) addSoft('motor', 'scripted easing: ' + mz.mirrored + ' cursor segment(s) with an exactly mirror-symmetric speed profile');
  if (mz.sparse) addSoft('tempo', 'sparse cursor: ' + mz.perClick.toFixed(1) + ' mouse moves per click (a hand produces dozens)');
  // Think-then-act: long silence after load, then the whole task in a burst — a model reasoning
  // over a screenshot, then executing. Informational (people pause too).
  if (B.firstInteractMs != null && B.sessionMs != null && B.firstInteractMs > 20000 &&
      (B.sessionMs - B.firstInteractMs) < 8000 && (B.interactions || 0) >= 5 && !(B.visibility && B.visibility.hidden > 0))
    addSoft('tempo', 'think-then-act: idle ' + Math.round(B.firstInteractMs / 1000) + 's after load, then the whole task in ' + ((B.sessionMs - B.firstInteractMs) / 1000).toFixed(1) + 's');
  // WEAK (nomouse): ABSENCE of a mouse. Keyboard users, touch/pen users, screen-reader and
  // voice-control users all produce this, so it is weak — and suppressed entirely when touch,
  // pen or organic keyboard navigation explains the missing cursor.
  if (!touchOrPen && !keyboardNav) {
    if (mz.clickNoMove) addSoft('nomouse', 'mouse clicks with zero cursor travel');
    if ((B.mouse && B.mouse.moves === 0) && (B.interactions || 0) > 3 && (B.scroll && B.scroll.dist === 0))
      addSoft('nomouse', 'multi-step session with no mouse movement and no scroll');
  }

  // Typing cadence (family: cadence) — SOFT on purpose; this is what over-fired before
  if (B.keys && B.keys.flights && B.keys.flights.length >= 6) {
    var fcv = cv(B.keys.flights);
    if (fcv != null && fcv < 0.12) addSoft('cadence', 'metronomic keystroke timing (CV ' + fcv.toFixed(3) + ')');
    var dmean = mean(B.keys.dwell || []);
    if (dmean != null && dmean < 8) addSoft('cadence', 'near-zero key-hold time (' + dmean.toFixed(1) + 'ms)');
  }
  // Machine typing: real (trusted) key events with ~0ms holds at a fixed interval, judged robustly
  // (field switches and odd pauses don't hide it). On its own this stays weak — OS-level auto-typers
  // (KeePass auto-type, AutoHotkey) type like this for real people. It becomes STRONG only when the
  // same typed field ALSO received a script-dispatched input event: an OS auto-typer can't create
  // page events, and a password-manager extension creates events but never real keystrokes —
  // only a browser-automation agent produces both on one field.
  if (B.keys && (B.keys.trusted || 0) >= 8 && B.keys.flights && B.keys.dwell) {
    var inF = B.keys.flights.filter(function (x) { return x > 0 && x < 500; });
    var dw = B.keys.dwell.slice().sort(function (a, b) { return a - b; });
    var dMed = dw.length ? dw[Math.floor(dw.length / 2)] : null;
    var fs = inF.slice().sort(function (a, b) { return a - b; }), fMed = fs.length ? fs[Math.floor(fs.length / 2)] : null;
    var tight = fMed != null ? inF.filter(function (x) { return Math.abs(x - fMed) <= 4; }).length / inF.length : 0;
    if (inF.length >= 8 && dMed != null && dMed < 8 && tight >= 0.7) {
      var dispatched = Object.keys(B.fields || {}).filter(function (k) {
        var f = B.fields[k]; return f && (f.untrusted || 0) > 0 && (f.keys || 0) >= Math.max(3, (f.len || 0)) && !(f.assist > 0);
      });
      var desc = 'machine typing: ' + Math.round(tight * 100) + '% of keystrokes exactly ' + fMed + '±4ms apart, key held ' + dMed + 'ms';
      if (dispatched.length && !mob) addSoft('machinetype', desc + ', and script-dispatched input events on the same typed field(s) (' + dispatched.join(', ') + ')');
      else addSoft('cadence', desc + ' (OS auto-typers like KeePass do this too — informational)');
    }
  }

  // Injection-ish but passive-possible (family: fill)
  if ((B.valueSetsCold || 0) > 0) addSoft('fill', 'cold el.value= writes ×' + B.valueSetsCold + ' (also autofill — corroboration required)');
  if ((B.coldFocus || 0) > 0 && (B.mouse && B.mouse.moves === 0)) addSoft('fill', 'programmatic focus with no pointer activity');

  // Honeypot soft (family: honeypot)
  if (HP.ld && HP.ld.focused && !HP.ld.clicked) addSoft('honeypot', 'focused the hidden canary control (invisible to humans)');
  if (slide.present && slide.soft) addSoft('honeypot', 'suspicious slide kinematics (velCV ' + (slide.velCV || 0).toFixed(3) + ', yStd ' + (slide.yStd || 0).toFixed(2) + ')');
  var lat = HP.latency || {}; var fast = Object.keys(lat).filter(function (k) { return lat[k] && lat[k].gapMs != null && lat[k].gapMs < 120; });
  if (fast.length >= 2) addSoft('honeypot', 'sub-human reaction on ' + fast.length + ' buttons (<120ms)');
  if (HP.nav && HP.nav.checkoutReached && HP.nav.productsViewed <= 1 && (HP.nav.totalDwellMs || 0) < 4000)
    addSoft('path', 'direct-to-checkout, almost no browsing (' + HP.nav.productsViewed + ' product, ' + Math.round((HP.nav.totalDwellMs || 0) / 100) / 10 + 's)');

  // ---------- fusion: honeypots + GPU lead; behaviour and weak env corroborate ----------
  //   HP   honeypot (STRONG) — plus the HP hard tells above (decoy, canaries, self-declaration,
  //        assistant-only URLs, buying the not-for-sale unit)
  //   ENV  envhw — software GPU, or a WebGL/WebGPU contradiction (STRONG: GPU-less cloud VMs)
  //        nomedia, vmcpu, envloc, headless, novoice, dcarm, gpuless (WEAK, corroborate) · stealth, fonts (informational only)
  //        exposed automation (webdriver / automation globals / HeadlessChrome) is hard
  //   BEH  motor (STRONG: teleport / robot path / centre-lock / scripted easing), inject (STRONG:
  //        whole-string password insert) · fill, nomouse, cadence, path, synthetic, tempo (WEAK, informational)
  // agent when:
  //   1. any HP hard tell or ENV hard tell
  //   2. STRONG honeypot + any corroboration (behaviour, software GPU or a weak env signal)
  //   3. software GPU + behaviour evidence          (GPU-less VM driving teleport clicks)
  //   4. behaviour evidence + two weak env signals, at least one cloud-specific (dcarm/novoice)
  // Behaviour alone, environment alone (GPU + weak env → ENV-ONLY review), or a strong honeypot
  // read alone never produce "agent".
  // Corroborating env signals. Privacy-extension patches (stealth) and font counts are recorded
  // but deliberately NOT counted — both are cheap to change and common among real people.
  var WEAK_ENV = { nomedia: 1, vmcpu: 1, envloc: 1, headless: 1, novoice: 1, dcarm: 1, gpuless: 1, vmgeo: 1 };
  var softFamilies = Object.keys(soft);
  var hpStrong = !!soft.honeypot, gpu = !!soft.envhw;
  var envWeak = softFamilies.filter(function (f) { return WEAK_ENV[f]; });
  var cloudSig = !!(soft.dcarm || soft.novoice || soft.vmgeo);
  // Desktop Linux (not Android / ChromeOS / phones): where cloud agents run (Muse, Hark) and only a
  // few percent of real customers are. Used ONLY to corroborate automation evidence, never alone.
  var uaS = (S.navigator && S.navigator.ua) || '';
  var linuxDesk = !mobileUA && /linux/i.test(uaS + ' ' + plat) && !/android|cros/i.test(uaS);
  // Machine typing + dispatched events counts as automation only on a cloud-shaped or Linux host:
  // elsewhere it could be a person combining an OS auto-typer with an event-firing extension.
  // (KeePassXC auto-type is common on ordinary Linux desktops, so Linux alone is not enough here.)
  // (vmgeo deliberately not counted here: a VDI user running KeePass auto-type + an event-firing
  // extension would otherwise look identical — only the real cloud-host signals qualify.)
  var machineTyped = !!soft.machinetype && !!(soft.dcarm || soft.novoice);
  var behEvidence = behHard.length > 0 || !!soft.motor || !!soft.inject || machineTyped;
  var gate = envHard.length + hpHard.length;
  var hard = envHard.concat(hpHard, behHard);

  var isAgent = false, tier = 'NONE';
  if (gate > 0) {
    isAgent = true;
    tier = (envHard.length && hpHard.length) || gate >= 2 ? 'MULTI' : (envHard.length ? 'ENV' : 'HP');
  } else if (hpStrong && (behEvidence || gpu || envWeak.length >= 1)) { isAgent = true; tier = 'HP+CORR'; }
  else if (declared && (behEvidence || hpStrong)) { isAgent = true; tier = 'DECLARE+CORR'; }
  // POLICY (owner's call): any honeypot taken is agent — including the visible "an AI assistant is
  // completing this" box ticked on its own. Accepted cost: a person who mis-ticks it is flagged.
  else if (declared) { isAgent = true; tier = declN >= 2 ? 'DECLARE×2' : 'DECLARE'; }
  else if (gpu && behEvidence) { isAgent = true; tier = 'GPU+BEH'; }
  // Linux desktop + automation evidence (user rule): every automation signal counted in
  // behEvidence already excludes the human look-alikes (autofill, dictation, password managers,
  // OS auto-typers), so on a Linux desktop it is agent without needing the GPU signal.
  else if (behEvidence && linuxDesk) { isAgent = true; tier = 'BEH+LINUX'; }
  // Same idea for a virtual display: a window taller than its own screen doesn't occur on a real
  // desktop (zoom/maximise can't produce it), so with automation evidence it is agent.
  else if (behEvidence && soft.vmgeo) { isAgent = true; tier = 'BEH+VMGEO'; }
  // Old office PCs can look VM-like on hardware alone (software graphics, 2 cores, no audio
  // devices, no WebGPU). Environment-only and behaviour+environment verdicts therefore need at
  // least one CLOUD-specific signal that old hardware doesn't produce (ARM Linux host, no speech
  // engine on a Mac/Windows browser). The private-browsing permission quirk does not qualify.
  else if (behEvidence && envWeak.length >= 2 && cloudSig) { isAgent = true; tier = 'BEH+ENV'; }
  else if (behEvidence) { tier = 'BEH-ONLY'; }
  // Environment alone never decides (old office PCs share every VM hardware trait) — review only.
  else if (gpu && envWeak.length >= 2 && cloudSig) { tier = 'ENV-ONLY'; }
  else if (hpStrong) { tier = 'HP-ONLY'; }

  var confidence;
  if (gate > 0) confidence = Math.min(99, 90 + (gate - 1) * 3 + Math.min(6, (behHard.length + envWeak.length + (gpu ? 1 : 0)) * 2));
  else if (isAgent) confidence = Math.min(88, 70 + (hpStrong || declared ? 6 : 0) + (gpu ? 6 : 0) + (behEvidence ? 6 : 0) + envWeak.length * 3);
  else {
    // human: more organic evidence => higher confidence it's human
    var organic = 0;
    if (B.mouse && B.mouse.moves > 30) organic += 2;
    if (B.scroll && B.scroll.dist > 200) organic += 1;
    if (B.keys && cv(B.keys.flights) != null && cv(B.keys.flights) > 0.25) organic += 2;
    if ((B.idleGaps || []).length > 0) organic += 1;
    confidence = Math.min(97, 70 + organic * 5 - softFamilies.length * 4);
    if (tier === 'BEH-ONLY' || tier === 'HP-ONLY' || tier === 'ENV-ONLY') confidence = Math.min(confidence, 55);   // human, but review-worthy
  }

  var reasons = [];
  envHard.forEach(function (h) { reasons.push('HARD[env]: ' + h); });
  hpHard.forEach(function (h) { reasons.push('HARD[honeypot]: ' + h); });
  behHard.forEach(function (h) { reasons.push('BEH: ' + h + (isAgent ? '' : ' (uncorroborated — behaviour alone does not flag)')); });
  softFamilies.forEach(function (f) { reasons.push('SOFT[' + f + ']: ' + soft[f].join(' · ')); });
  if (!reasons.length) reasons.push('organic fingerprint, kinematics and honeypot response — no agent tells');
  // informational only (never scored): the page showed its STRONG visible honeypot because the
  // browser had an agent tell — tells whether the agent saw it and ignored it, or acted on it.
  if (HP.strong) reasons.push('INFO: strong assistant notice was shown (browser tells: ' + String(HP.strong).slice(0, 80) + ')' +
    (HP.gate ? ' · first Sign in press was gated (' + (HP.declare && HP.declare.checked ? 'box ticked afterwards' : 'pressed again without ticking') + ')' : ''));

  return {
    label: isAgent ? 'agent' : 'human', confidence: confidence, tier: tier,
    hard: hard, soft: soft, reasons: reasons,
    boughtTrap: !!((bundle.server && bundle.server.boughtTrap) || (HP.nav && HP.nav.boughtTrap)),
  };
}

function classifyTier(h) {
  if (/webdriver|automation|stealth|headless|permission/i.test(h)) return 'ENV';
  if (/decoy|confirm|slide|canary|hidden|honeypot|demo unit/i.test(h)) return 'HP';
  return 'BEH';
}

module.exports = { decodeBundle: decodeBundle, assess: assess, scoreSlide: scoreSlide };

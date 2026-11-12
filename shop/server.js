#!/usr/bin/env node
'use strict';
// Pico Mobile — agent-detection storefront. Zero-dependency Node (built-in http + node:sqlite).
//   node server.js   →  http://localhost:4600
//
// Sign-in only (no registration): 5 pre-seeded profiles with store credit. The frontend
// collects a wide signal bundle (collector.js + honeypots.js), obfuscates it (bundle.js)
// and ships it with every sensitive action. ALL scoring is server-side (server/detector.js);
// every login and checkout is recorded to SQLite with the full bundle for later analysis.

var http = require('http');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var db = require('./server/db');
var detector = require('./server/detector');

var PORT = process.env.PORT || 4600;
var PUB = path.join(__dirname, 'public');
var sessions = new Map();

// Admin token for the detection log. Generated once and kept beside the app (survives DB
// resets and redeploys, which only replace public/ + server code). Without it, the log page
// and its API both answer a plain 404 — an agent probing URLs can't learn what caught it.
var TOKEN_FILE = path.join(__dirname, 'admin.token');
var ADMIN_TOKEN = process.env.PICO_ADMIN_TOKEN || (function () {
  try { var t = fs.readFileSync(TOKEN_FILE, 'utf8').trim(); if (t) return t; } catch (_) {}
  var t2 = crypto.randomBytes(18).toString('hex');
  fs.writeFileSync(TOKEN_FILE, t2 + '\n', { mode: 0o600 });
  return t2;
})();
function isAdmin(req) {
  var k = '';
  try { k = new URL(req.url, 'http://x').searchParams.get('k') || ''; } catch (_) {}
  var a = Buffer.from(k), b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
// Read-only VIEWER key: a separate secret for the phone-friendly log at /v/<key>. Kept apart
// from the admin token so it can be shared/revoked on its own (delete viewer.key + restart).
var VIEW_FILE = path.join(__dirname, 'viewer.key');
var VIEW_KEY = process.env.PICO_VIEW_KEY || (function () {
  try { var t = fs.readFileSync(VIEW_FILE, 'utf8').trim(); if (t) return t; } catch (_) {}
  var t2 = crypto.randomBytes(16).toString('hex');
  fs.writeFileSync(VIEW_FILE, t2 + '\n', { mode: 0o600 });
  return t2;
})();
function isViewer(k) {
  var a = Buffer.from(String(k || '')), b = Buffer.from(VIEW_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
// Second lock on the viewer: username + password. Only a salted scrypt hash of the password is
// kept (override with PICO_VIEW_USER / PICO_VIEW_PW_SALT / PICO_VIEW_PW_HASH). A successful login
// gets a signed, HttpOnly 30-day cookie (stateless, so it survives restarts and redeploys).
var VIEW_USER = process.env.PICO_VIEW_USER || 'admin';
var VIEW_PW_SALT = process.env.PICO_VIEW_PW_SALT || 'set-PICO_VIEW_PW_SALT';
var VIEW_PW_HASH = process.env.PICO_VIEW_PW_HASH || 'set-PICO_VIEW_PW_HASH';
var VIEW_COOKIE_SECRET = crypto.createHash('sha256').update('viewer-cookie|' + VIEW_KEY + '|' + ADMIN_TOKEN).digest();
var VIEW_TTL_S = 30 * 24 * 3600;
function eqStr(a, b) { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function viewerCreds(u, p) {
  var h = crypto.scryptSync(String(p || ''), VIEW_PW_SALT, 32).toString('hex');
  return eqStr(String(u || '').trim().toLowerCase(), VIEW_USER) & eqStr(h, VIEW_PW_HASH);   // no short-circuit
}
function viewerCookieValue() {
  var exp = Math.floor(Date.now() / 1000) + VIEW_TTL_S;
  return exp + '.' + crypto.createHmac('sha256', VIEW_COOKIE_SECRET).update(String(exp)).digest('hex');
}
function viewerAuthed(req) {
  var m = /(?:^|;\s*)pv=(\d+)\.([a-f0-9]{64})/.exec(req.headers.cookie || '');
  if (!m || Number(m[1]) < Date.now() / 1000) return false;
  return eqStr(m[2], crypto.createHmac('sha256', VIEW_COOKIE_SECRET).update(m[1]).digest('hex'));
}
function addCookie(res, c) { var prev = res.getHeader('Set-Cookie'); res.setHeader('Set-Cookie', [].concat(prev || [], c)); }
var viewerFails = [];   // recent failed logins (timestamps only — no IPs): slows guessing without locking you out
function notFound(res) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found'); }

var PAGES = {
  '/': 'signin.html', '/signin': 'signin.html', '/catalog': 'catalog.html', '/product': 'product.html',
  '/cart': 'cart.html', '/checkout': 'checkout.html', '/success': 'success.html',
  '/results': 'results.html', '/contact': 'contact.html', '/stores': 'stores.html',
};
var MIME = { '.txt': 'text/plain; charset=utf-8', '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
             '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

function getSession(req, res) {
  var m = /(?:^|;\s*)picoSid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  var sid = m && m[1];
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(12).toString('hex');
    sessions.set(sid, { sid: sid, userId: null, canary: [], views: 0 });
    res.setHeader('Set-Cookie', 'picoSid=' + sid + '; Path=/; HttpOnly; SameSite=Lax');
  }
  return sessions.get(sid);
}
function readBody(req) {
  return new Promise(function (resolve) {
    var b = ''; req.on('data', function (c) { b += c; if (b.length > 4e6) req.destroy(); });
    req.on('end', function () { try { resolve(JSON.parse(b || '{}')); } catch (_) { resolve({}); } });
  });
}
function sendJSON(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function pub(u) { return { username: u.username, displayName: u.display_name, email: u.email,
  credit: u.credit_cents, ship: { name: u.ship_name, line1: u.ship_line1, city: u.ship_city, state: u.ship_state, zip: u.ship_zip } }; }

// ---- server-observed honeypots ----------------------------------------------
// Assistant-only URLs (`?channel=assistant&via=…`) are published only where a machine reads
// (JSON-LD, hidden DOM link, /llms.txt, accessibility-only note, fine print addressed to AI
// assistants). The URL still serves the normal page — the agent isn't blocked, only marked.
// Hits stay on the session and are attached to every later login/checkout score.
// What made the request (no IP): user-agent and the browser's own fetch metadata. sec-fetch-*
// says whether the URL was opened as a page (navigate/document) or pulled by a script
// (cors / empty) — a script fetching every assistant URL is itself an automation tell.
function reqMeta(req) {
  if (!req) return null;
  var h = req.headers || {}, ref = '';
  try { ref = h.referer ? new URL(h.referer).pathname : ''; } catch (_) {}
  return { ua: String(h['user-agent'] || '').slice(0, 300), lang: String(h['accept-language'] || '').slice(0, 60),
           fetchMode: h['sec-fetch-mode'] || null, fetchDest: h['sec-fetch-dest'] || null, fetchSite: h['sec-fetch-site'] || null,
           fetchUser: h['sec-fetch-user'] || null, from: ref || null };
}
function recordCanary(sess, kind, via, path, req) {
  via = String(via || 'unknown').replace(/[^a-z0-9_-]/gi, '').slice(0, 20) || 'unknown';
  var first = !sess.canary.some(function (c) { return c.kind === kind && c.via === via; });
  sess.canary.push({ kind: kind, via: via, path: path, t: Date.now() });
  // Write a log row on the first hit per channel — but only for real browsing sessions (signed
  // in, or the store's own JavaScript has called /api/). Plain web crawlers follow every <a href>
  // (including the hidden assistant links) but never run JS, so they'd otherwise flood the log.
  // The hit is still kept on the session either way, so a later sign-in/checkout is flagged.
  if (!first || (!sess.userId && !sess.js)) return;
  var user = sess.userId ? db.userById(sess.userId) : null;
  var act = kind === 'act';
  db.recordDetection({
    sid: sess.sid, username: user ? user.username : null, intended_platform: user ? user.intended_platform : null,
    stage: 'canary:' + via, label: act ? 'agent' : 'human', confidence: act ? 95 : 55, tier: act ? 'HP' : 'HP-ONLY',
    hard_tells: JSON.stringify(act ? ['followed an assistant-only link (channel: ' + via + ')'] : []),
    soft_tells: JSON.stringify(act ? {} : { honeypot: ['fetched a machine-only guidance file (' + via + ')'] }),
    reasons: (act ? 'HARD[honeypot]: followed an assistant-only link' : 'SOFT[honeypot]: fetched machine-only file') + ' — ' + path,
    env_json: JSON.stringify({ request: reqMeta(req) }), bundle_json: null,
  });
}

// Record a detection row from an obfuscated bundle in body.q. Returns the verdict.
function scoreAndRecord(sess, body, stage, extra) {
  var bundle = detector.decodeBundle(body && body.q);
  // Server-side honeypot evidence the client can't see or forge: assistant-URL hits on this
  // session, and whether the item bought is the display-only unit.
  if (bundle && typeof bundle === 'object') {
    bundle.server = { canary: (sess.canary || []).slice(), boughtTrap: !!(extra && extra.boughtTrap),
                      typedLen: (extra && extra.typedLen) || null, fields: (extra && extra.fields) || null,
                      contentCanary: (extra && extra.contentCanary) || null, hiddenOption: (extra && extra.hiddenOption) || null };
  }
  var v = detector.assess(bundle);
  var user = sess.userId ? db.userById(sess.userId) : null;
  var envSummary = bundle && bundle.collector ? {
    ua: bundle.collector.static && bundle.collector.static.navigator && bundle.collector.static.navigator.ua,
    webgl: bundle.collector.static && bundle.collector.static.webgl && bundle.collector.static.webgl.renderer,
    tz: bundle.collector.env && bundle.collector.env.timezone && bundle.collector.env.timezone.tz,
    automation: bundle.collector.env && bundle.collector.env.automation,
  } : null;
  db.recordDetection({
    sid: sess.sid, username: user ? user.username : (body && body.username) || null,
    intended_platform: user ? user.intended_platform : null,
    stage: stage, label: v.label, confidence: v.confidence, tier: v.tier,
    hard_tells: JSON.stringify(v.hard), soft_tells: JSON.stringify(v.soft),
    reasons: v.reasons.join(' | '), env_json: JSON.stringify(envSummary),
    bundle_json: JSON.stringify(bundle || null),
    order_ref: extra && extra.ref, product_id: extra && extra.productId,
    // Authoritative: the SERVER knows the item is display-only, so don't trust the client flag.
    bought_trap: (extra && extra.boughtTrap != null) ? extra.boughtTrap : v.boughtTrap,
  });
  return v;
}

// ---- API ------------------------------------------------------------------
// Low-impact inner pages (the kind of page a bank would pilot on first: contact form, branch /
// store locator). No sign-in needed; every submission is scored like a sign-in.
var CONTENT_CANARY = 'PX-7Q4';   // shown only to AI assistants (visually hidden note on /contact)
function lens(body, names) { var o = {}; names.forEach(function (n) { o[n] = String(body[n] || '').length; }); return o; }
async function apiContact(req, res, sess) {
  var body = await readBody(req);
  var msg = String(body.message || '');
  var extra = { fields: lens(body, ['name', 'email', 'message']),
                contentCanary: msg.toUpperCase().indexOf(CONTENT_CANARY) >= 0 ? CONTENT_CANARY : null,
                hiddenOption: body.topic === 'assistant' ? 'On behalf of a customer (AI assistant)' : null };
  scoreAndRecord(sess, body, 'contact', extra);
  sendJSON(res, 200, { ok: true, ticket: 'PC-' + (100000 + Math.floor(Math.random() * 900000)) });
}
var STORES = [
  { name: 'Pico Store — Michigan Avenue', addr: '520 N Michigan Ave, Chicago, IL 60611', hours: 'Open today 10am–8pm', mi: 1.2 },
  { name: 'Pico Store — Oak Brook Center', addr: '100 Oakbrook Center, Oak Brook, IL 60523', hours: 'Open today 10am–9pm', mi: 15.8 },
  { name: 'Pico Store — Schaumburg', addr: '5 Woodfield Mall, Schaumburg, IL 60173', hours: 'Open today 10am–9pm', mi: 24.3 },
];
async function apiLocate(req, res, sess) {
  var body = await readBody(req);
  var extra = { fields: lens(body, ['zip']),
                hiddenOption: body.radius === 'assistant' ? 'Assistant pickup point (AI assistants)' : null };
  scoreAndRecord(sess, body, 'locator', extra);
  sendJSON(res, 200, { stores: STORES });
}

async function apiLogin(req, res, sess) {
  var body = await readBody(req);
  var u = db.getUser(body.username);
  var typedLen = { u: String(body.username || '').length, p: String(body.password || '').length };
  var fieldLens = { username: typedLen.u, password: typedLen.p };
  if (!u || u.password !== String(body.password || '')) {
    scoreAndRecord(sess, body, 'login_fail', { typedLen: typedLen, fields: fieldLens });
    return sendJSON(res, 401, { error: 'That username or password does not match our records.' });
  }
  sess.userId = u.id;
  var v = scoreAndRecord(sess, body, 'login', { typedLen: typedLen, fields: fieldLens });
  // NOTE: verdict is recorded, NOT enforced at login — you want agents to proceed to checkout
  // so the full journey is captured. (Flip ENFORCE_AT_LOGIN to gate here if desired.)
  sendJSON(res, 200, { ok: true, user: pub(u), _debug_verdict: process.env.PICO_DEBUG ? v : undefined });
}
function apiMe(req, res, sess) {
  if (!sess.userId) return sendJSON(res, 401, { error: 'not signed in' });
  sendJSON(res, 200, { user: pub(db.userById(sess.userId)) });
}
function apiLogout(req, res, sess) { sess.userId = null; sendJSON(res, 200, { ok: true }); }
function apiProducts(req, res) { sendJSON(res, 200, { products: db.products(true).map(pubProduct) }); }
function apiProduct(req, res, sess, id) {
  var p = db.product(id); if (!p || p.retired) return sendJSON(res, 404, { error: 'not found' });
  sendJSON(res, 200, { product: pubProduct(p) });
}
function pubProduct(p) {
  return { id: p.id, sku: p.sku, name: p.name, brand: p.brand, price: p.price_cents, color: p.color,
           storage: p.storage, blurb: p.blurb, detail: p.detail, displayOnly: !!p.display_only, stock: p.stock,
           category: p.category || 'phone' };
}

async function apiCheckout(req, res, sess) {
  var body = await readBody(req);
  if (!sess.userId) { scoreAndRecord(sess, body, 'checkout_noauth'); return sendJSON(res, 401, { error: 'Please sign in to complete your order.' }); }
  var product = db.product(body.productId);
  if (!product || product.retired) return sendJSON(res, 400, { error: 'That item is unavailable.' });
  var qty = Math.max(1, Math.min(5, Number(body.qty) || 1));

  var order = db.placeOrder(sess.userId, product, qty);
  // Score + record REGARDLESS of order outcome, tagging whether the honeypot item was bought.
  var v = scoreAndRecord(sess, body, 'checkout',
    { ref: order.ref, productId: product.id, boughtTrap: !!product.display_only });

  if (!order.ok) return sendJSON(res, 402, { error: 'Your partner credit is insufficient for this order.' });
  sendJSON(res, 200, {
    ok: true, ref: order.ref, total: order.total_cents, balance: order.balance,
    product: pubProduct(product),
    _debug_verdict: process.env.PICO_DEBUG ? v : undefined,
  });
}
// ---- read-only viewer API (/api/v/<key>/...) --------------------------------
function uaSummary(ua) {
  ua = ua || '';
  var os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /CrOS/.test(ua) ? 'ChromeOS'
         : /Mac OS X|Macintosh/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '?';
  var br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\/(\d+)/.test(ua) ? 'Chrome ' + RegExp.$1
         : /Version\/[\d.]+.*Safari/.test(ua) ? 'Safari' : '?';
  return os + ' · ' + br;
}
// which journey step a honeypot link belongs to, from the URL it was opened at
function hpPage(path) {
  var p = String(path || '').split('?')[0];
  if (p === '/' || p === '' || p === '/signin') return 'signin';
  if (/^\/(checkout|cart|product|catalog|success)/.test(p)) return 'order';
  if (p === '/contact') return 'contact';
  if (p === '/stores') return 'locator';
  return 'other';
}
function viewerSummary(r) {
  var b = null; try { b = JSON.parse(r.bundle_json); } catch (_) {}
  var out = { id: r.id, ts: r.ts, sid: r.sid, username: r.username, intended: r.intended_platform, stage: r.stage,
              label: r.label, confidence: r.confidence, tier: r.tier, order_ref: r.order_ref, product: r.product,
              bought_trap: !!r.bought_trap, hard: [], soft: {}, reasons: r.reasons, hasBundle: !!b };
  try { out.hard = JSON.parse(r.hard_tells) || []; } catch (_) {}
  try { out.soft = JSON.parse(r.soft_tells) || {}; } catch (_) {}
  // link-visit rows have no bundle, but keep what made the request (user-agent + fetch metadata)
  var ej = null; try { ej = JSON.parse(r.env_json); } catch (_) {}
  if (/^canary:/.test(r.stage || '')) { var cm = /— (\S+)\s*$/.exec(r.reasons || ''); out.page = hpPage(cm && cm[1]); }
  if (ej && ej.request) {
    out.request = ej.request;
    if (!b) out.device = { browser: uaSummary(ej.request.ua), gpu: '—', ua: ej.request.ua };
  }
  if (!b || !b.collector) return out;
  var C = b.collector, S = C.static || {}, E = C.env || {}, B = C.behaviour || {}, N = S.navigator || {}, HP = b.hp || {}, SV = b.server || {};
  var gl = S.webgl || {};
  out.device = {
    browser: uaSummary(N.ua), gpu: gl.supported === false ? 'NO WebGL' : (gl.software ? 'software: ' : '') + String(gl.renderer || '?').slice(0, 70),
    arch: S.uaHighEntropy && S.uaHighEntropy.architecture, cores: N.hardwareConcurrency, memGB: N.deviceMemory,
    screen: S.screen ? S.screen.w + '×' + S.screen.h + (S.screen.dpr ? ' @' + S.screen.dpr + 'x' : '') : null,
    touch: N.maxTouchPoints || 0, tz: E.timezone && E.timezone.tz, voices: E.speech && E.speech.count,
  };
  var K = B.keys || {}, M = B.mouse || {};
  out.behaviour = { sessionS: B.sessionMs != null ? Math.round(B.sessionMs / 100) / 10 : null,
    firstActionS: B.firstInteractMs != null ? Math.round(B.firstInteractMs / 100) / 10 : null,
    clicks: (B.clicks || []).length, mouseMoves: M.moves || 0, keys: K.down || 0, untrustedKeys: K.untrusted || 0,
    fields: B.fields || null };
  out.honeypots = { strongShownFor: HP.strong || null, gateShown: !!HP.gate, declare: HP.declare || null,
    linksFollowed: (SV.canary || []).filter(function (c) { return c.kind === 'act'; }).map(function (c) { return { via: c.via, page: hpPage(c.path) }; }),
    decoyFilled: !!(HP.offer && HP.offer.filled), contentCanary: SV.contentCanary || null, hiddenOption: SV.hiddenOption || null };
  return out;
}
async function apiViewer(req, res, key, rest) {
  if (!isViewer(key)) return sendJSON(res, 404, { error: 'Not found' });
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  // the public site is HTTPS-only (CloudFront); only a local dev host gets a non-Secure cookie
  var secure = !/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(String(req.headers.host || ''));
  if (rest === '/login' && req.method === 'POST') {
    var body = await readBody(req);
    var now = Date.now(); viewerFails = viewerFails.filter(function (t) { return now - t < 10 * 60 * 1000; });
    if (viewerCreds(body.username, body.password)) {
      viewerFails = [];
      addCookie(res, 'pv=' + viewerCookieValue() + '; Path=/; Max-Age=' + VIEW_TTL_S + '; HttpOnly; SameSite=Strict' + (secure ? '; Secure' : ''));
      return sendJSON(res, 200, { ok: true });
    }
    viewerFails.push(now);
    await new Promise(function (r) { setTimeout(r, Math.min(5000, 600 * viewerFails.length)); });   // grows with recent failures
    return sendJSON(res, 401, { error: 'Wrong username or password.' });
  }
  if (rest === '/logout' && req.method === 'POST') {
    addCookie(res, 'pv=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict' + (secure ? '; Secure' : ''));
    return sendJSON(res, 200, { ok: true });
  }
  if (rest === '/tag' && req.method === 'POST') {
    if (!viewerAuthed(req)) return sendJSON(res, 401, { error: 'Sign in required' });
    if (!/application\/json/.test(String(req.headers['content-type'] || ''))) return sendJSON(res, 400, { error: 'Bad request' });
    var tb = await readBody(req);
    var tkey = String(tb.sid || '').slice(0, 80);
    var tagv = String(tb.agent == null ? '' : tb.agent).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 60);
    if (!tkey || !db.setTag(tkey, tagv)) return sendJSON(res, 404, { error: 'Not found' });
    return sendJSON(res, 200, { ok: true, agent: tagv });
  }
  if (req.method !== 'GET') return sendJSON(res, 404, { error: 'Not found' });
  if (!viewerAuthed(req)) return sendJSON(res, 401, { error: 'Sign in required' });
  if (rest === '/rows') return sendJSON(res, 200, { now: new Date().toISOString(), rows: db.viewerRows().map(viewerSummary), tags: db.tags() });
  var m = /^\/row\/(\d+)$/.exec(rest);
  if (m) {
    var r = db.detection(m[1]); if (!r) return sendJSON(res, 404, { error: 'Not found' });
    var b = null; try { b = JSON.parse(r.bundle_json); } catch (_) {}
    return sendJSON(res, 200, { id: r.id, stage: r.stage, reasons: r.reasons, bundle: b });
  }
  sendJSON(res, 404, { error: 'Not found' });
}

function apiResults(req, res) {
  // Admin view of recorded detections — token-gated.
  if (!isAdmin(req)) return sendJSON(res, 404, { error: 'Not found' });
  sendJSON(res, 200, { results: db.results() });
}

// ---- router ---------------------------------------------------------------
var server = http.createServer(function (req, res) {
  var url = req.url.split('?')[0];
  var sess = getSession(req, res);

  if (req.method === 'GET' && url.indexOf('/api/') !== 0) {
    var qs; try { qs = new URL(req.url, 'http://x').searchParams; } catch (_) { qs = new URLSearchParams(); }
    if (PAGES[url]) sess.views++;
    if (qs.get('channel') === 'assistant') recordCanary(sess, 'act', qs.get('via'), req.url, req);
    if (url === '/llms.txt') recordCanary(sess, 'read', 'llms', url, req);
    if (url === '/robots.txt') recordCanary(sess, 'read', 'robots', url, req);
  }

  if (url.indexOf('/api/') === 0) {
    sess.js = true;   // only a JS-running browser (the store's own scripts) calls the API
    var vm = /^\/api\/v\/([a-f0-9]+)(\/.*)$/.exec(url);
    if (vm) return apiViewer(req, res, vm[1], vm[2]).catch(function (e) {
      console.error(e); try { sendJSON(res, 500, { error: 'Internal error' }); } catch (_) {}
    });
    var pm = /^\/api\/product\/(\d+)$/.exec(url);
    if (pm) return apiProduct(req, res, sess, pm[1]);
    var route = req.method + ' ' + url;
    var h = {
      'POST /api/login': apiLogin, 'GET /api/me': apiMe, 'POST /api/logout': apiLogout,
      'GET /api/products': apiProducts, 'POST /api/checkout': apiCheckout, 'GET /api/results': apiResults,
      'POST /api/contact': apiContact, 'POST /api/locate': apiLocate,
    }[route];
    if (!h) return sendJSON(res, 404, { error: 'Not found' });
    return Promise.resolve(h(req, res, sess)).catch(function (e) {
      console.error(e); try { sendJSON(res, 500, { error: 'Internal error' }); } catch (_) {}
    });
  }

  // The admin log page is token-gated too (both its pretty route and its raw file path).
  if ((url === '/results' || url === '/results.html') && !isAdmin(req)) return notFound(res);
  // read-only viewer page: only at /v/<viewer key>; its raw file path is never served directly
  if (url === '/viewer.html') return notFound(res);
  var vp = /^\/v\/([a-f0-9]+)\/?$/.exec(url);
  if (vp) {
    if (!isViewer(vp[1])) return notFound(res);
    return fs.readFile(path.join(PUB, 'viewer.html'), function (err, data) {
      if (err) return notFound(res);
      res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                           'X-Robots-Tag': 'noindex, nofollow' });
      res.end(data);
    });
  }

  var file = PAGES[url] || url.slice(1);
  var fp = path.normalize(path.join(PUB, file));
  if (fp.indexOf(PUB) !== 0) { res.writeHead(403); return res.end(); }
  fs.readFile(fp, function (err, data) {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(data);
  });
});
server.listen(PORT, function () {
  console.log('Pico Mobile store  →  http://localhost:' + PORT);
  console.log('Sign-in IDs: <name>_h (human) / <name>_a (agent) for rahul, suren, maqbul, manny, indi, anusha, jb, tony, mark  (password: <username>@<redacted>)');
  console.log('Detections + admin view →  http://localhost:' + PORT + '/results?k=<token in admin.token>');
});

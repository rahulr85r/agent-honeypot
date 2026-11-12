/* bundle.js — assemble + obfuscate the signal bundle, ship it with sensitive actions.
 *
 * The browser does NO scoring. It gathers the collector + honeypot snapshots into one
 * blob and lightly obfuscates it (base64 of XOR'd, reversed JSON) so a visiting agent
 * skimming the request body can't eyeball "am I being fingerprinted". This is obfuscation,
 * NOT security — the server (detector.js) holds all logic and treats the client as untrusted.
 */
(function (global) {
  'use strict';
  if (global.PicoBundle) return;

  function encode(obj) {
    var json = JSON.stringify(obj);
    // utf8 bytes
    var utf8 = unescape(encodeURIComponent(json));
    var bytes = new Uint8Array(utf8.length);
    for (var i = 0; i < utf8.length; i++) bytes[i] = utf8.charCodeAt(i) ^ 0x5a;   // XOR
    // reverse, then base64 of the byte string
    var bin = '';
    for (var j = bytes.length - 1; j >= 0; j--) bin += String.fromCharCode(bytes[j]);
    return btoa(bin);
  }

  var COLLECT_TIMEOUT_MS = 1500;

  // Behaviour-only fallback, used if the full probe set is slow or throws. Marked `partial`
  // so the server scores what it has instead of treating the request as opaque.
  function partialCollector(reason) {
    var beh = null;
    try { beh = global.Collector && global.Collector._behaviour ? global.Collector._behaviour() : null; } catch (_) {}
    return { v: 2, partial: true, reason: reason, behaviour: beh };
  }

  // Never rejects and never waits longer than COLLECT_TIMEOUT_MS: a probe that hangs in some
  // browser must not stall the user's sign-in or checkout.
  function make(ctx) {
    var hp = {};
    try { hp = (global.PicoHP && global.PicoHP.snapshot()) || {}; } catch (_) {}
    var full = new Promise(function (resolve) {
      try {
        Promise.resolve(global.Collector ? global.Collector.collect() : null)
          .then(resolve, function () { resolve(partialCollector('error')); });
      } catch (_) { resolve(partialCollector('error')); }
    });
    var timeout = new Promise(function (resolve) {
      setTimeout(function () { resolve(partialCollector('timeout')); }, COLLECT_TIMEOUT_MS);
    });
    return Promise.race([full, timeout]).then(function (collector) {
      try { return encode({ v: 2, ts: Date.now(), ctx: ctx || {}, collector: collector || partialCollector('empty'), hp: hp }); }
      catch (_) { return encode({ v: 2, ts: Date.now(), ctx: ctx || {}, collector: partialCollector('encode'), hp: {} }); }
    });
  }

  // POST helper: puts the obfuscated bundle under an innocuous field `q` alongside the
  // real action payload. A network failure resolves to an error result so the page can show
  // a message instead of silently doing nothing.
  function post(url, payload, ctx) {
    return make(ctx).then(function (enc) {
      var body = Object.assign({}, payload || {}, { q: enc });
      return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }).then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); });
    }).catch(function () {
      return { status: 0, body: { error: 'Something went wrong. Please try again.' } };
    });
  }

  global.PicoBundle = { make: make, post: post, _encode: encode };
})(typeof window !== 'undefined' ? window : this);

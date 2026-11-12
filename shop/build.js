#!/usr/bin/env node
'use strict';
// Build step (dev-only). Turns readable src/ into de-telled, obfuscated public/ output so a
// visiting agent inspecting the page can't tell it's being fingerprinted/trapped:
//   * global API names  -> bland tokens      (Collector -> _px, PicoHP -> _ph, ...)
//   * honeypot DOM hooks -> coded attributes  (data-hp="decoy" -> data-k="p", ...)
//   * all 4 client libs -> ONE obfuscated bundle served at a bland path (/assets/app.js)
//   * HTML comments stripped; the 4 <script> tags collapse to one.
// The runtime server stays zero-dependency; javascript-obfuscator is used here only.

var fs = require('fs');
var path = require('path');
var JO = require('javascript-obfuscator');

var ROOT = __dirname, SRC = path.join(ROOT, 'src'), PUB = path.join(ROOT, 'public');
var ASSET = 'assets/app.js';

// ---- rename maps ----------------------------------------------------------
// Exact-string swaps for the honeypot DOM hooks (applied to BOTH html attrs and js selectors).
var ATTR = [
  ['data-hp="decoy"',   'data-k="p"'],
  ['data-hp="latency"', 'data-k="t"'],
  ['data-hp="confirm"', 'data-k="a"'],
  ['data-hp="slider"',  'data-k="s"'],
  ['data-hp="knob"',    'data-k="b"'],
  ['data-hp="canary"',  'data-k="g"'],
  ['data-hp="declare"', 'data-k="d"'],
  ['data-hp="declare-name"', 'data-k="n"'],
  ['data-hp-name',      'data-kn'],
];
// Word-boundary swaps for the public global API names.
var GLOBAL = [
  ['Collector',  '_px'],
  ['PicoBundle', '_pb'],
  ['PicoHP',     '_ph'],
  ['Shop',       '_ui'],
];
function applyMaps(s) {
  ATTR.forEach(function (m) { s = s.split(m[0]).join(m[1]); });
  // Dot-anchored: the globals are ALWAYS used as `Name.method` or defined as `obj.Name` —
  // never as a bare word. Anchoring to the dot renames every real usage while leaving any
  // visible prose that happens to contain the word (e.g. the "Shop Pico One" button) untouched.
  GLOBAL.forEach(function (m) {
    s = s.split('.' + m[0]).join('.' + m[1]);   // .Shop  -> ._ui   (property definition)
    s = s.split(m[0] + '.').join(m[1] + '.');   // Shop.  -> _ui.   (method access)
  });
  return s;
}

// ---- JS bundle: concat (order matters) -> rename -> obfuscate --------------
var LIB_ORDER = ['collector.js', 'honeypots.js', 'shop-ui.js', 'bundle.js'];
var concat = LIB_ORDER.map(function (f) {
  return '/* ' + f + ' */\n' + fs.readFileSync(path.join(SRC, 'js', f), 'utf8');
}).join('\n;\n');
concat = applyMaps(concat);

var result = JO.obfuscate(concat, {
  // Conservative, stable preset: hides strings (base64 string-array) + mangles identifiers,
  // WITHOUT the aggressive transforms (control-flow flattening / splitStrings / numbersToExpressions)
  // that corrupted the string-array decoder and threw "charAt of undefined" at runtime.
  // Minimal, bulletproof: whitespace/comment removal + local identifier mangling ONLY.
  // No string array / control-flow / dead-code transforms — those all miscompiled this code
  // in-browser (string-array accessor returned wrong strings / threw charAt). The revealing
  // names (globals, honeypot DOM hooks, filenames, comments) were already removed at SOURCE,
  // so the served bundle reads as obfuscated without any fragile runtime decoder.
  compact: true,
  controlFlowFlattening: false,
  deadCodeInjection: false,
  stringArray: false,
  splitStrings: false,
  numbersToExpressions: false, simplify: false,
  identifierNamesGenerator: 'mangled',
  renameGlobals: false,          // keep window._px/_ph/_pb/_ui reachable from inline HTML
  transformObjectKeys: false,    // CRITICAL: snapshot keys are read by the server detector
  selfDefending: false,          // avoids breaking our own Function.toString native checks
  unicodeEscapeSequence: false,
});
fs.mkdirSync(path.join(PUB, 'assets'), { recursive: true });
fs.writeFileSync(path.join(PUB, ASSET), result.getObfuscatedCode());

// ---- HTML: rename -> strip comments -> collapse script tags ---------------
var htmlDir = path.join(SRC, 'html');
var LIB_TAG = /\s*<script src="\/(?:collector|honeypots|bundle|shop-ui)\.js"><\/script>/g;
fs.readdirSync(htmlDir).filter(function (f) { return /\.html$/.test(f); }).forEach(function (f) {
  var h = fs.readFileSync(path.join(htmlDir, f), 'utf8');
  h = applyMaps(h);
  h = h.replace(LIB_TAG, '');                                   // drop the individual lib tags
  h = h.replace(/<!--[\s\S]*?-->/g, '');                        // strip HTML comments (incl. design notes)
  // minify inline page scripts (no src) so their comments/whitespace don't leak intent
  h = h.replace(/<script>([\s\S]*?)<\/script>/g, function (_, body) {
    var out = JO.obfuscate(body, { compact: true, simplify: true, renameGlobals: false,
      transformObjectKeys: false, selfDefending: false, identifierNamesGenerator: 'mangled' }).getObfuscatedCode();
    return '<script>' + out + '</script>';
  });
  if (f !== 'viewer.html') h = h.replace('</head>', '<script src="/' + ASSET + '"></script>\n</head>');   // inject the one bundle (not on the read-only log viewer)
  fs.writeFileSync(path.join(PUB, f), h);
});

// ---- machine-only text files (honeypot channel: agents that read site guidance) ----
['llms.txt', 'robots.txt'].forEach(function (f) {
  var srcp = path.join(SRC, f); if (fs.existsSync(srcp)) fs.copyFileSync(srcp, path.join(PUB, f));
});

// ---- static ---------------------------------------------------------------
// strip CSS comments so design notes ("honeypot", "decoy") don't ship in the stylesheet
var css = fs.readFileSync(path.join(SRC, 'store.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
fs.writeFileSync(path.join(PUB, 'store.css'), css);

var bytes = fs.statSync(path.join(PUB, ASSET)).size;
console.log('built → public/' + ASSET + ' (' + (bytes / 1024).toFixed(1) + ' KB obfuscated)');
console.log('pages → ' + fs.readdirSync(htmlDir).filter(function (f) { return /\.html$/.test(f); }).length + ' html + store.css');

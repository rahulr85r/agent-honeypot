#!/usr/bin/env node
'use strict';
// rescore.js — re-run the CURRENT detector over every saved signal bundle.
//
// Every login/checkout stores its full raw bundle (detections.bundle_json). Because the verdict
// is a pure function of that bundle, you can tune server/detector.js and replay history to see
// how past sessions reclassify — the correction loop for ambiguous verdicts. Nothing is mutated
// unless you pass --write, which updates each row's label/confidence/tier/tells in place.
//
//   node rescore.js            # dry run: print only the rows whose verdict changed
//   node rescore.js --all      # print every row, changed or not
//   node rescore.js --write     # persist the re-scored verdicts back into the detections table

var path = require('path');
var { DatabaseSync } = require('node:sqlite');
var detector = require('./server/detector');

var db = new DatabaseSync(path.join(__dirname, 'data', 'store.db'));
var rows = db.prepare('SELECT * FROM detections ORDER BY id').all();
var write = process.argv.includes('--write');
var all = process.argv.includes('--all');

var changed = 0;
rows.forEach(function (r) {
  var bundle; try { bundle = JSON.parse(r.bundle_json); } catch (_) { bundle = null; }
  var v = detector.assess(bundle);
  var diff = v.label !== r.label || v.confidence !== r.confidence || v.tier !== r.tier;
  if (diff) changed++;
  if (diff || all) {
    console.log((diff ? '~ ' : '  ') + '#' + r.id + ' [' + r.stage + '] ' + (r.username || '—') +
      '  ' + r.label + '/' + r.confidence + '/' + r.tier + (diff ? '  ->  ' + v.label + '/' + v.confidence + '/' + v.tier : '') +
      (diff ? '\n      now: ' + (v.hard.concat(Object.keys(v.soft).map(function (k) { return k + '(' + v.soft[k].length + ')'; })).join(' · ') || 'no tells') : ''));
  }
  if (write && diff) {
    db.prepare('UPDATE detections SET label=?, confidence=?, tier=?, hard_tells=?, soft_tells=?, reasons=? WHERE id=?')
      .run(v.label, v.confidence, v.tier, JSON.stringify(v.hard), JSON.stringify(v.soft), v.reasons.join(' | '), r.id);
  }
});
console.log('\n' + rows.length + ' rows scored, ' + changed + ' changed' + (write ? ' (written)' : ' (dry run — pass --write to persist)'));

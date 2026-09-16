/* Independent interval verification using concatenations of RFC3629 byte
 * templates. Does not import the searcher or its finite automata.
 * node solver/verify_utf8_decimal.cjs [pairs]
 */
'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), base = path.join(root, '_work', 'utf8_decimal_2026-09-16');
const strict = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const cont = [0x80, 0xbf];
const patterns = [
  [[0, 0x7f]], [[0xc2, 0xdf], cont], [[0xe0, 0xe0], [0xa0, 0xbf], cont],
  [[0xe1, 0xec], cont, cont], [[0xed, 0xed], [0x80, 0x9f], cont], [[0xee, 0xef], cont, cont],
  [[0xf0, 0xf0], [0x90, 0xbf], cont, cont], [[0xf1, 0xf3], cont, cont, cont],
  [[0xf4, 0xf4], [0x80, 0x8f], cont, cont],
];
const templates = {};
for (const order of ['big', 'little']) templates[order] = patterns.map(p => {
  const ranges = order === 'little' ? [...p].reverse() : p;
  const suffix = Array(ranges.length + 1).fill(1n);
  for (let i = ranges.length - 1; i >= 0; i--) suffix[i] = suffix[i + 1] * BigInt(ranges[i][1] - ranges[i][0] + 1);
  return {ranges, suffix};
});
const all = [1n];
function ensure(length) {
  while (all.length <= length) {
    const len = all.length;
    all.push(templates.big.reduce((n, p) => p.ranges.length <= len ? n + p.suffix[0] * all[len - p.ranges.length] : n, 0n));
  }
}
function bytesOf(n) {
  const result = []; do {result.unshift(Number(n % 256n)); n /= 256n;} while (n); return result;
}
function countUtf8(n, order) {
  if (n < 0n) return 0n;
  const bytes = bytesOf(n); ensure(bytes.length);
  const memo = new Map();
  function from(pos) {
    if (pos === bytes.length) return 1n;
    if (memo.has(pos)) return memo.get(pos);
    let total = 0n;
    for (const p of templates[order]) {
      const len = p.ranges.length; if (pos + len > bytes.length) continue;
      let smaller = 0n, equal = true;
      for (let i = 0; i < len; i++) {
        const [lo, hi] = p.ranges[i], b = bytes[pos + i];
        smaller += BigInt(Math.max(0, Math.min(b - lo, hi - lo + 1))) * p.suffix[i + 1];
        if (b < lo || b > hi) {equal = false; break;}
      }
      total += smaller * all[bytes.length - pos - len];
      if (equal) total += from(pos + len);
    }
    memo.set(pos, total); return total;
  }
  // Leading zero padding adds U+0000 at one end and preserves validity in
  // both orders, so the fixed-width count also counts canonical integers.
  return from(0);
}
function controls() {
  let exactCounts = 0, randomMembership = 0;
  for (const order of ['big', 'little']) {
    let expected = 0n;
    for (let n = 0; n < 65536; n++) {
      const b = Buffer.from(bytesOf(BigInt(n))); if (order === 'little') b.reverse();
      try {strict.decode(b); expected++;} catch {}
      assert.equal(countUtf8(BigInt(n), order), expected); exactCounts++;
    }
    // Defined scalar boundaries, malformed/overlong encodings and longer
    // deterministic random byte strings, checked through a runtime decoder.
    let rng = 17092026;
    for (let sample = 0; sample < 3000; sample++) {
      const b = Buffer.alloc(1 + sample % 32);
      for (let i = 0; i < b.length; i++) {rng ^= rng << 13; rng ^= rng >>> 17; rng ^= rng << 5; b[i] = rng & 255;}
      const n = BigInt('0x' + b.toString('hex')), canonical = Buffer.from(bytesOf(n)); if (order === 'little') canonical.reverse();
      let valid = 0n; try {strict.decode(canonical); valid = 1n;} catch {}
      assert.equal(countUtf8(n, order) - countUtf8(n - 1n, order), valid); randomMembership++;
    }
    for (const text of ['é𝄞🔑', '\u0000¡\ud7ff\ue000\u{10ffff}', 'matrixsumlist']) {
      const b = Buffer.from(text); if (order === 'little') b.reverse();
      const n = BigInt('0x' + b.toString('hex'));
      assert.equal(countUtf8(n, order) - countUtf8(n - 1n, order), 1n); randomMembership++;
    }
  }
  for (let length = 1; length <= 237; length++) {
    ensure(length);
    for (const order of ['big', 'little']) assert.equal(countUtf8(256n ** BigInt(length) - 1n, order), all[length]);
  }
  return {exactCounts, randomMembership, fullWidthCounts: 474};
}
function main() {
  const paired = process.argv[2] === 'pairs'; assert(process.argv[2] === undefined || paired);
  const directory = paired ? path.join(base, 'two_symbols') : base;
  const reportBytes = fs.readFileSync(path.join(directory, 'results.json')), cases = JSON.parse(reportBytes);
  const specBytes = fs.readFileSync(path.join(directory, 'spec.json')), spec = JSON.parse(specBytes);
  const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json')), input = JSON.parse(inputBytes);
  assert.equal(sha(inputBytes), spec.inputSHA256);
  assert.equal(sha(fs.readFileSync(path.join(root, 'solver', 'utf8_decimal_constraints.cjs'))), spec.sourceSHA256);
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  const line = readme.split(/\r?\n/).find(l => l.startsWith('> d b b i')).slice(2).replace(/[ *]/g, '');
  assert.equal(input.dbbi, line.slice(0, 91)); assert.equal(input.faed, line.slice(195, 765));
  const checked = controls(), ids = new Set(); let certificates = 0, hits = 0;
  for (const r of cases) {
    assert(['dbbi', 'faed'].includes(r.field) && typeof r.reverse === 'boolean');
    assert(['big', 'little'].includes(r.order)); assert.match(r.alias, paired ? /^[a-i]{2}$/ : /^[a-i]$/);
    assert.equal(new Set(r.alias).size, r.alias.length); assert.equal([...r.alias].sort().join(''), r.alias);
    const id = [r.field, r.reverse, r.alias, r.order].join('/'); assert(!ids.has(id)); ids.add(id);
    const source = r.reverse ? [...input[r.field]].reverse().join('') : input[r.field];
    const ambiguous = [...source].filter(c => r.alias.includes(c)).length; assert.equal(ambiguous, r.ambiguous);
    function endpoint(mask, high) {
      let i = 0;
      return BigInt([...source].map(c => {
        const d = c.charCodeAt(0) - 96; if (!r.alias.includes(c)) return d;
        const branch = i < mask.length ? mask[i] === '1' : high; i++; return branch ? d : 0;
      }).join(''));
    }
    const leaves = []; let excluded = 0n, pending = 0n;
    for (const c of r.certificates) {
      assert.match(c.mask, /^[01]*$/); assert(c.mask.length <= ambiguous); leaves.push(c.mask);
      const lo = endpoint(c.mask, false), hi = endpoint(c.mask, true);
      assert.equal(lo.toString(), c.lo); assert.equal(hi.toString(), c.hi);
      assert.equal(countUtf8(hi, r.order) - countUtf8(lo - 1n, r.order), 0n);
      const next = BigInt(c.next); assert(next > hi);
      assert.equal(countUtf8(next, r.order) - countUtf8(lo - 1n, r.order), 1n);
      assert.equal(countUtf8(next, r.order) - countUtf8(next - 1n, r.order), 1n);
      excluded += 1n << BigInt(ambiguous - c.mask.length); certificates++;
    }
    for (const h of r.hits) {
      assert.match(h.mask, /^[01]*$/); assert.equal(h.mask.length, ambiguous); leaves.push(h.mask);
      const n = endpoint(h.mask, false), bytes = Buffer.from(bytesOf(n)); if (r.order === 'little') bytes.reverse();
      assert.equal(n.toString(), h.decimal); assert.equal(bytes.toString('hex'), h.hex);
      assert.equal(strict.decode(bytes), h.text); hits++;
    }
    for (const mask of r.pending) {assert.match(mask, /^[01]*$/); assert(mask.length <= ambiguous); leaves.push(mask); pending += 1n << BigInt(ambiguous - mask.length);}
    leaves.sort(); for (let i = 1; i < leaves.length; i++) assert(!leaves[i].startsWith(leaves[i - 1]));
    assert.equal(excluded.toString(), r.excluded); assert.equal(pending.toString(), r.pendingAssignments);
    assert.equal(excluded + BigInt(r.hits.length) + pending, 1n << BigInt(ambiguous));
    assert.equal(r.complete, r.pending.length === 0); assert(r.complete);
  }
  assert.equal(ids.size, paired ? 288 : 72);
  const summaryBytes = fs.readFileSync(path.join(directory, 'summary.json')), summary = JSON.parse(summaryBytes);
  const candidates = cases.flatMap(r => r.hits.map(h => ({field: r.field, reverse: r.reverse, alias: r.alias, order: r.order, ...h})));
  assert.equal(summary.resultsSHA256, sha(reportBytes)); assert.equal(summary.cases, cases.length);
  assert.equal(summary.complete, cases.filter(r => r.complete).length);
  assert.equal(summary.nodes, cases.reduce((n, r) => n + r.nodes, 0)); assert.equal(summary.certificates, certificates);
  assert.deepEqual(summary.candidates, candidates); assert.deepEqual(summary.incomplete, []);
  const result = {allPassed: true, method: 'Independent scalar-byte-template counting, interval endpoints and prefix-free complete mask coverage; UTF-8 candidates checked by fatal TextDecoder.',
    controls: checked, cases: ids.size, certificates, hits, summaryMatchesAllCases: true,
    resultsSHA256: sha(reportBytes), specSHA256: sha(specBytes), summarySHA256: sha(summaryBytes), verifierSHA256: sha(fs.readFileSync(__filename))};
  fs.writeFileSync(path.join(directory, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
if (require.main === module) main();
module.exports = {countUtf8};

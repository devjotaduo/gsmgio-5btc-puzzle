'use strict';
// Whole-domain certificate, preserving the old partial journal unchanged.
// Fixed radix-prefix digits are checked once and removed from child intervals.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/radix127_completion_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const allowed = [9, 10, 13, ...Array.from({ length: 95 }, (_, i) => i + 32)];
function tables(base, maximum) {
  const digits = allowed.filter(d => d < base), legal = new Uint8Array(base), counts = new Uint16Array(base + 1), powers = [1n], low = [0n], high = [0n];
  digits.forEach(d => { legal[d] = 1; }); for (let d = 0; d < base; d++) counts[d + 1] = counts[d] + legal[d];
  while (powers.at(-1) <= maximum) { powers.push(powers.at(-1) * BigInt(base)); low.push(low.at(-1) * BigInt(base) + BigInt(digits[0])); high.push(high.at(-1) * BigInt(base) + BigInt(digits.at(-1))); }
  return { powers, low, high, legal, counts, base };
}
function reduceInterval(lo, hi, k, t) {
  while (k) {
    const p = t.powers[k - 1], a = Number(lo / p), b = Number(hi / p), x = lo % p, y = hi % p;
    if (a === b) { if (!t.legal[a]) return null; lo = x; hi = y; k--; continue; }
    // An allowed interior digit admits its entire legal suffix range.
    const middle = t.counts[b] - t.counts[a + 1] > 0;
    const lower = t.legal[a] && x <= t.high[k - 1];
    const upper = t.legal[b] && y >= t.low[k - 1];
    return middle || lower || upper ? { lo, k } : null;
  }
  return { lo: 0n, k: 0 };
}
function digitsOf(n, base) { const b = BigInt(base), ds = []; do { ds.push(Number(n % b)); n /= b; } while (n); return ds.reverse(); }
function solve(pattern, base, maxNodes = 30000000) {
  const minimum = BigInt(pattern.replaceAll('?', '0')), weights = [...pattern].flatMap((c, i) => c === '?' ? [7n * 10n ** BigInt(pattern.length - i - 1)] : []), tail = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) tail[i] = tail[i + 1] + weights[i];
  const t = tables(base, minimum + tail[0]), length = t.powers.length - 1, flags = Buffer.alloc(maxNodes), hits = [], pending = [];
  assert(minimum >= t.powers[length - 1], 'Split the root by digit length before using fixed-length intervals');
  let nodes = 0, excluded = 0n, started = Date.now();
  function visit(i, suffix, k, value) {
    if (nodes >= maxNodes) { pending.push({ i, lo: String(value), suffix: String(suffix), k }); return; }
    const position = nodes++, r = reduceInterval(suffix, suffix + tail[i], k, t);
    if (!r) { flags[position] = 1; excluded += 1n << BigInt(weights.length - i); return; }
    if (i === weights.length) {
      assert.equal(r.k, 0); flags[position] = 2; const digits = digitsOf(value, base); assert(digits.every(d => allowed.includes(d))); assert.equal(digits.length, length);
      hits.push({ decimal: String(value), ascii: Buffer.from(digits).toString('ascii') }); return;
    }
    flags[position] = 0; visit(i + 1, r.lo, r.k, value); visit(i + 1, r.lo + weights[i], r.k, value + weights[i]);
  }
  visit(0, minimum, length, minimum);
  const unresolved = pending.reduce((s, p) => s + (1n << BigInt(weights.length - p.i)), 0n);
  assert.equal(excluded + BigInt(hits.length) + unresolved, 1n << BigInt(weights.length));
  return { result: { complete: pending.length === 0, base, length, ambiguous: weights.length, assignments: String(1n << BigInt(weights.length)), nodes, excludedAssignments: String(excluded), unresolvedAssignments: String(unresolved), pending, hits, elapsedMs: Date.now() - started }, flags: flags.subarray(0, nodes) };
}
function controls() {
  let intervals = 0, masks = 0, plants = 0;
  for (const base of [41, 127, 128, 257]) {
    const legal = allowed.filter(v => v < base), values = [];
    for (const a of legal) for (const b of legal) values.push(BigInt(a * base + b));
    values.sort((a, b) => a < b ? -1 : a > b ? 1 : 0); const max = BigInt(base * base - 1), t = tables(base, max);
    for (let i = 0; i < 400; i++) {
      const lo = BigInt((i * 7919 + 17) % Number(max)), hi = lo + BigInt((i * 17 + 31) % Number(max - lo + 1n));
      const expected = values.some(n => n >= lo && n <= hi); assert.equal(Boolean(reduceInterval(lo, hi, 2, t)), expected); intervals++;
    }
    for (const pattern of ['1??', '2?7?', '2?0??', '987?', '1?????']) {
      const count = [...pattern].filter(c => c === '?').length, expected = [];
      for (let mask = 0; mask < 2 ** count; mask++) { let j = 0; const n = BigInt(pattern.replaceAll('?', () => mask >> j++ & 1 ? '7' : '0')); if (digitsOf(n, base).every(d => legal.includes(d))) expected.push(String(n)); }
      const min = BigInt(pattern.replaceAll('?', '0')), maxv = BigInt(pattern.replaceAll('?', '7')); if (digitsOf(min, base).length !== digitsOf(maxv, base).length) continue;
      const r = solve(pattern, base, 10000).result; assert(r.complete); assert.deepEqual(r.hits.map(h => h.decimal).sort(), expected.sort()); masks++;
    }
    const text = 'THE MATRIX HAS YOU'; let n = 0n; for (const c of Buffer.from(text)) { if (c >= base) { n = 0n; break; } n = n * BigInt(base) + BigInt(c); }
    if (n) { const r = solve(String(n).replace(/[07]/g, '?'), base, 100000).result; assert(r.complete && r.hits.some(h => h.ascii === text)); plants++; }
  }
  return { intervalComparisons: intervals, exhaustiveMaskCases: masks, plantedTexts: plants };
}
function main() {
  fs.mkdirSync(out, { recursive: true }); assert(!fs.existsSync(path.join(out, 'summary.json')), 'Existing results must be inspected before restarting');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), oldRaw = fs.readFileSync(path.join(root, '_work/shared_numeric_2026-09-11/prime_radix_results.json'));
  const old = JSON.parse(oldRaw).results.find(r => r.field === 'faed' && r.base === 127); assert(!old.complete && old.resumeMinDecimal && old.hits.length === 177);
  const pattern = [...input.faed].map(c => c === 'g' ? '?' : String(c.charCodeAt(0) - 96)).join('');
  const spec = { scope: 'Original FAED only, fixed a..i=1..9 and every g independently0/7, full minimum decimal integer -> minimum MSB-first base127 digits, all in TAB/LF/CR/ASCII32..126. Entire domain regenerated with a prefix-sharing interval proof, preserving and cross-checking the old partial journal. No trimming, additional substitution or language assumptions.', controls: controls(), pattern, allowed, maxNodes: 30000000, inputSHA256: sha(inputRaw), previousResultsSHA256: sha(oldRaw), previousNodes: old.nodes, previousCandidates: old.hits.length, previousCheckpoint: old.resumeMinDecimal, sourceSHA256: sha(fs.readFileSync(__filename)) };
  fs.writeFileSync(path.join(out, 'spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const { result, flags } = solve(pattern, 127, spec.maxNodes); const found = new Map(result.hits.map(h => [h.decimal, h.ascii]));
  for (const hit of old.hits) if (result.complete || BigInt(hit.decimal) < BigInt(result.pending[0].lo)) assert.equal(found.get(hit.decimal), hit.ascii);
  fs.writeFileSync(path.join(out, 'tree.bin'), flags); fs.writeFileSync(path.join(out, 'hits.json'), JSON.stringify(result.hits, null, 2) + '\n');
  const { hits, ...summary } = result;
  Object.assign(summary, { hits: hits.length, oldCandidatesRecovered: old.hits.filter(h => found.get(h.decimal) === h.ascii).length, newCandidates: hits.filter(h => !old.hits.some(v => v.decimal === h.decimal)).length, treeSHA256: sha(flags), hitsSHA256: sha(fs.readFileSync(path.join(out, 'hits.json'))) });
  fs.writeFileSync(path.join(out, 'summary.json'), JSON.stringify(summary, null, 2) + '\n'); console.log(JSON.stringify(summary));
}
if (require.main === module) main();
module.exports = { tables, reduceInterval, digitsOf, solve };

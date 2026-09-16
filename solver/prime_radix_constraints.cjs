/* Whole decimal integer -> prime radix ASCII, with every g independently 0/7.
 * node solver/prime_radix_constraints.cjs [--resume]
 * Interval pruning is exact. Resource-capped searches are labelled incomplete.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '_work', 'shared_numeric_2026-09-11');
const allowedAscii = [9, 10, 13, ...Array.from({length: 95}, (_, i) => i + 32)];
const prime = n => n >= 2 && Array.from({length: Math.max(0, Math.floor(Math.sqrt(n)) - 1)}, (_, i) => i + 2).every(d => n % d);
const bases = Array.from({length: 258}, (_, i) => i).filter(prime);
function fromDigits(digits, base) {
  const b = BigInt(base);
  return digits.reduce((n, d) => n * b + BigInt(d), 0n);
}
function toDigits(n, base) {
  assert(n >= 0n && base >= 2);
  const b = BigInt(base), result = [];
  do { result.push(Number(n % b)); n /= b; } while (n);
  return result.reverse();
}
const radixCaches = new Map();
function nextAllowed(n, base) {
  if (!radixCaches.has(base)) {
    const allowed = allowedAscii.filter(x => x < base);
    radixCaches.set(base, {allowed, set: new Set(allowed), b: BigInt(base), powers: [1n], suffix: [0n],
      next: Array.from({length: base}, (_, d) => allowed.find(a => a > d))});
  }
  const {allowed, set, b, powers, suffix, next} = radixCaches.get(base);
  if (!allowed.length) return null;
  // Inspect only the prefix up to the first forbidden digit. The uninspected
  // suffix is replaced by the smallest legal suffix, computed exactly.
  while (powers.at(-1) <= n || powers.length < 2) {
    powers.push(powers.at(-1) * b); suffix.push(suffix.at(-1) * b + BigInt(allowed[0]));
  }
  let lo = 1, hi = powers.length - 1;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (powers[mid] > n) hi = mid; else lo = mid + 1; }
  const length = lo, digits = [], prefixes = [0n];
  let rest = n;
  for (let i = length - 1; i >= 0; i--) {
    const d = Number(rest / powers[i]); rest %= powers[i];
    if (set.has(d)) { digits.push(d); prefixes.push(prefixes.at(-1) * b + BigInt(d)); continue; }
    if (next[d] !== undefined) return (prefixes.at(-1) * b + BigInt(next[d])) * powers[i] + suffix[i];
    for (let j = digits.length - 1; j >= 0; j--) {
      if (next[digits[j]] !== undefined) {
        const remaining = length - j - 1;
        return (prefixes[j] * b + BigInt(next[digits[j]])) * powers[remaining] + suffix[remaining];
      }
    }
    return suffix[length] * b + BigInt(allowed[0]);
  }
  return n;
}
function solve(pattern, base, {maxNodes = 200000, maxMs = 8000, minDecimal = 0n} = {}) {
  assert.match(pattern, /^[0-9?]+$/);
  const minimum = BigInt(pattern.replaceAll('?', '0'));
  const weights = [...pattern].flatMap((c, i) => c === '?' ? [7n * 10n ** BigInt(pattern.length - i - 1)] : []);
  const remaining = Array(weights.length + 1).fill(0n);
  for (let i = weights.length - 1; i >= 0; i--) remaining[i] = remaining[i + 1] + weights[i];
  const start = Date.now(), hits = [];
  let nodes = 0, pruned = 0, complete = true, stopReason = null, resumeMinDecimal = null;
  function visit(i, lo) {
    if (nodes >= maxNodes || Date.now() - start > maxMs) {
      complete = false; stopReason = nodes >= maxNodes ? 'node limit' : 'time limit'; resumeMinDecimal = lo.toString(); return;
    }
    nodes++;
    if (lo + remaining[i] < minDecimal) { pruned++; return; }
    const candidate = nextAllowed(lo < minDecimal ? minDecimal : lo, base);
    if (candidate === null || candidate > lo + remaining[i]) { pruned++; return; }
    if (i === weights.length) {
      const digits = toDigits(lo, base);
      assert(digits.every(d => allowedAscii.includes(d)));
      hits.push({decimal: lo.toString(), ascii: Buffer.from(digits).toString('ascii')}); return;
    }
    visit(i + 1, lo);
    if (complete) visit(i + 1, lo + weights[i]);
  }
  visit(0, minimum);
  return {base, ambiguous: weights.length, assignments: (1n << BigInt(weights.length)).toString(),
    minPrefix: toDigits(minimum, base).slice(0, 10), maxPrefix: toDigits(minimum + remaining[0], base).slice(0, 10),
    nodes, pruned, complete, stopReason, resumeMinDecimal, elapsedMs: Date.now() - start, hits};
}
function controls() {
  let successorChecks = 0, maskChecks = 0;
  assert.equal(nextAllowed(12345n, 7), null);
  for (const base of [11, 41, 101, 163, 257]) {
    const allowed = allowedAscii.filter(x => x < base);
    // Independently enumerate legal strings, rather than enumerating integer gaps.
    const limit = allowed.length > 10 ? 2 : 4;
    const legal = [];
    function enumerate(ds, length) {
      if (ds.length === length) { legal.push(fromDigits(ds, base)); return; }
      for (const a of allowed) enumerate([...ds, a], length);
    }
    for (let length = 1; length <= limit; length++) enumerate([], length);
    legal.sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
    for (const n of [0n, 1n, 8n, 9n, 10n, 11n, 31n, 127n, 255n, 256n, BigInt(base * base - 1)]) {
      const expected = legal.find(x => x >= n);
      if (expected !== undefined) { assert.equal(nextAllowed(n, base), expected); successorChecks++; }
    }
    for (const pattern of ['?2?', '1???', '?7?3?', '??????', '00?99?']) {
      const count = [...pattern].filter(x => x === '?').length, expected = [];
      for (let mask = 0; mask < 2 ** count; mask++) {
        let i = 0;
        const n = BigInt(pattern.replaceAll('?', () => mask & (1 << i++) ? '7' : '0'));
        if (toDigits(n, base).every(d => allowedAscii.includes(d))) expected.push(n.toString());
      }
      const result = solve(pattern, base);
      assert(result.complete); assert.deepEqual(result.hits.map(x => x.decimal).sort(), expected.sort()); maskChecks++;
    }
  }
  const planted = [];
  for (const base of [101, 163, 257]) {
    const text = 'SENDTHEBLUETOSETHEX';
    const decimal = fromDigits([...Buffer.from(text)], base).toString();
    const result = solve(decimal.replace(/[07]/g, '?'), base);
    assert(result.complete); assert(result.hits.some(x => x.ascii === text));
    planted.push({base, ambiguous: result.ambiguous, nodes: result.nodes, recovered: true});
    const partial = solve(decimal.replace(/[07]/g, '?'), base, {maxNodes: 10});
    assert(!partial.complete && partial.resumeMinDecimal !== null);
    const resumed = solve(decimal.replace(/[07]/g, '?'), base, {minDecimal: BigInt(partial.resumeMinDecimal)});
    assert(resumed.complete);
    assert.deepEqual([...partial.hits, ...resumed.hits].map(x => x.decimal).sort(), result.hits.map(x => x.decimal).sort());
  }
  return {successorChecks, maskChecks, planted};
}
function main() {
  fs.mkdirSync(out, {recursive: true});
  const inputBytes = fs.readFileSync(path.join(root, '_work', 'prime_geometry_2026-09-11', 'inputs.json'));
  const data = JSON.parse(inputBytes);
  const previous = process.argv.includes('--resume') ? JSON.parse(fs.readFileSync(path.join(out, 'prime_radix_results.json'))).results : [];
  const hash = x => crypto.createHash('sha256').update(x).digest('hex');
  const spec = {
    hypothesis: 'g independently 0/7; other a..i symbols 1..9; whole decimal integer -> minimal most-significant-first prime radix digits interpreted directly as ASCII.',
    motivation: 'The page already converts a decimal integer to base 16 and bytes. Primes might specify a different radix instead of positions.',
    bases, acceptedDigits: allowedAscii, inputs_sha256: hash(inputBytes), source_sha256: hash(fs.readFileSync(__filename)),
    limitsPerFieldAndBase: {nodes: 200000, milliseconds: 8000, faedBase127: {nodes: 20000000, milliseconds: 180000}},
    scope: 'Whole original DBBI and FAED, unchanged order. No stripping bytes, shifting character codes, alternate symbol maps, or inferred English substitution.',
  };
  fs.writeFileSync(path.join(out, 'prime_radix_spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const checked = controls(), results = [];
  const independent = JSON.parse(fs.readFileSync(path.join(out, 'dbbi_prime_radices.json')));
  for (const field of ['dbbi', 'faed']) for (const base of bases) {
    const pattern = [...data[field]].map(c => c === 'g' ? '?' : String(c.charCodeAt(0) - 96)).join('');
    const limits = field === 'faed' && base === 127 ? {maxNodes: 20000000, maxMs: 180000} : {};
    const old = previous.find(x => x.field === field && x.base === base);
    if (old?.complete) { results.push(old); continue; }
    if (old) {
      // The traversal is in ascending integer order. For an older report
      // without a checkpoint, everything through its last hit was exhausted.
      assert(old.resumeMinDecimal || old.hits.length);
      limits.minDecimal = old.resumeMinDecimal ? BigInt(old.resumeMinDecimal) : BigInt(old.hits.at(-1).decimal) + 1n;
    }
    const result = {field, ...solve(pattern, base, limits)};
    if (old) {
      result.hits = [...old.hits, ...result.hits]; result.nodes += old.nodes; result.pruned += old.pruned;
      result.elapsedMs += old.elapsedMs; result.segments = (old.segments || 1) + 1; result.resumedFrom = limits.minDecimal.toString();
    }
    results.push(result);
    if (field === 'dbbi' && result.complete) assert.equal(result.hits.length, independent.full_ascii_count_by_base[String(base)]);
    fs.writeFileSync(path.join(out, 'prime_radix_results.json'), JSON.stringify({controls: checked, results}, null, 2) + '\n');
    if (!result.complete || result.hits.length || result.nodes > 1000) console.log(JSON.stringify({field, base, nodes: result.nodes, complete: result.complete, hits: result.hits.length}));
  }
  fs.writeFileSync(path.join(out, 'prime_radix_results.json'), JSON.stringify({controls: checked, results}, null, 2) + '\n');
  const summary = {controls: checked, searches: results.length, completed: results.filter(x => x.complete).length,
    incomplete: results.filter(x => !x.complete).map(x => ({field: x.field, base: x.base, nodes: x.nodes, reason: x.stopReason})),
    nodes: results.reduce((n, x) => n + x.nodes, 0), hits: results.flatMap(x => x.hits.map(h => ({field: x.field, base: x.base, ...h}))),
    dbbiCrossCheck: 'All completed DBBI bases agree with independent Python exhaustive enumeration.'};
  fs.writeFileSync(path.join(out, 'prime_radix_summary.json'), JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify({...summary, hits: summary.hits.length, firstPreviews: summary.hits.slice(0, 2).map(x => ({field: x.field, base: x.base, length: x.ascii.length, preview: x.ascii.slice(0, 30)}))}, null, 2));
}
if (require.main === module) main();
module.exports = {toDigits, fromDigits, nextAllowed, solve};

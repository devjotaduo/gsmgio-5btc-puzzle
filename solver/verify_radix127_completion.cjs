'use strict';
// Independent rank counting of legal base127 strings in every certified interval.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/radix127_completion_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const chars = [9, 10, 13, ...Array.from({ length: 95 }, (_, i) => i + 32)], charset = new Set(chars), below = Array.from({ length: 127 }, (_, d) => chars.filter(v => v < d).length);
const powers = [1n], counts = [1n]; for (let i = 1; i <= 300; i++) { powers.push(powers[i - 1] * 127n); counts.push(counts[i - 1] * 98n); }
function rank(n, size) {
  if (n < 0n) return 0n;
  if (n >= powers[size]) return counts[size];
  let total = 0n;
  for (let i = size - 1; i >= 0; i--) {
    const d = Number(n / powers[i]); n %= powers[i]; total += BigInt(below[d]) * counts[i];
    if (!charset.has(d)) return total;
  }
  return total + 1n;
}
function normalized(lo, hi, size) {
  while (size > 0) {
    const p = powers[size - 1], a = lo / p, b = hi / p;
    if (a !== b) break;
    if (!charset.has(Number(a))) return { count: 0n, lo, hi, size };
    lo -= a * p; hi -= b * p; size--;
  }
  return { lo, hi, size, count: rank(hi, size) - rank(lo - 1n, size) };
}
function controls() {
  const all = []; for (const a of chars) for (const b of chars) all.push(BigInt(a * 127 + b)); all.sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  let checked = 0;
  for (let i = 0; i < 1000; i++) {
    const lo = BigInt((i * 7919 + 31) % (127 * 127)), hi = lo + BigInt((i * 17 + 11) % (127 * 127 - Number(lo)));
    const expected = BigInt(all.filter(v => v >= lo && v <= hi).length);
    assert.equal(rank(hi, 2) - rank(lo - 1n, 2), expected); assert.equal(normalized(lo, hi, 2).count, expected); checked++;
  }
  return checked;
}
function main() {
  const spec = JSON.parse(fs.readFileSync(path.join(out, 'spec.json'))), summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json')));
  assert(summary.complete && summary.pending.length === 0);
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), source = input.faed;
  assert.equal(sha(inputRaw), spec.inputSHA256); assert.equal(sha(fs.readFileSync(path.join(__dirname, 'radix127_completion.cjs'))), spec.sourceSHA256);
  const flags = fs.readFileSync(path.join(out, 'tree.bin')), hitsRaw = fs.readFileSync(path.join(out, 'hits.json')), hits = JSON.parse(hitsRaw);
  assert.equal(sha(flags), summary.treeSHA256); assert.equal(sha(hitsRaw), summary.hitsSHA256);
  const weights = []; let minimum = 0n;
  for (let i = 0; i < source.length; i++) { minimum *= 10n; if (source[i] === 'g') weights.push(7n * 10n ** BigInt(source.length - 1 - i)); else minimum += BigInt(source.charCodeAt(i) - 96); }
  const tail = [0n]; for (let i = weights.length - 1; i >= 0; i--) tail.unshift(weights[i] + tail[0]);
  let size = 1; while (powers[size] <= minimum + tail[0]) size++; assert(minimum >= powers[size - 1]); assert.equal(size, 271);
  const checked = controls(), byDecimal = new Map(hits.map(r => [r.decimal, r.ascii])); assert.equal(byDecimal.size, hits.length);
  let position = 0, leaves = 0, rejected = 0, covered = 0n; const start = Date.now();
  function visit(i, lo, hi, k, value) {
    assert(position < flags.length); const flag = flags[position++], r = normalized(lo, hi, k);
    if (flag === 1) { assert.equal(r.count, 0n); covered += 1n << BigInt(weights.length - i); rejected++; return; }
    assert(r.count > 0n);
    if (flag === 2) {
      assert.equal(i, weights.length); assert.equal(r.count, 1n); assert.equal(lo, hi);
      const decimal = String(value), expected = byDecimal.get(decimal); assert.notEqual(expected, undefined); byDecimal.delete(decimal);
      for (let j = 0; j < source.length; j++) assert(source[j] === 'g' ? decimal[j] === '0' || decimal[j] === '7' : +decimal[j] === source.charCodeAt(j) - 96);
      let reconstructed = 0n; for (const b of Buffer.from(expected, 'ascii')) { assert(charset.has(b)); reconstructed = reconstructed * 127n + BigInt(b); }
      assert.equal(reconstructed, value); assert.equal(expected.length, size); leaves++; return;
    }
    assert.equal(flag, 0); assert(i < weights.length);
    visit(i + 1, r.lo, r.lo + tail[i + 1], r.size, value);
    visit(i + 1, r.lo + weights[i], r.lo + weights[i] + tail[i + 1], r.size, value + weights[i]);
  }
  visit(0, minimum, minimum + tail[0], size, minimum);
  assert.equal(position, flags.length); assert.equal(byDecimal.size, 0); assert.equal(leaves, summary.hits); assert.equal(String(covered), summary.excludedAssignments); assert.equal(covered + BigInt(leaves), 1n << 107n);
  const oldRaw = fs.readFileSync(path.join(root, '_work/shared_numeric_2026-09-11/prime_radix_results.json')); assert.equal(sha(oldRaw), spec.previousResultsSHA256);
  const old = JSON.parse(oldRaw).results.find(r => r.field === 'faed' && r.base === 127), current = new Map(hits.map(r => [r.decimal, r.ascii])); for (const h of old.hits) assert.equal(current.get(h.decimal), h.ascii);
  const result = { complete: true, nodes: position, rejectedIntervals: rejected, allAssignments: String(1n << 107n), excludedAssignments: String(covered), candidateLeaves: leaves, oldCandidates: old.hits.length, newCandidates: leaves - old.hits.length, controlIntervals: checked, treeSHA256: sha(flags), hitsSHA256: sha(hitsRaw), verifierSHA256: sha(fs.readFileSync(__filename)), elapsedMs: Date.now() - start, method: 'Independent exact rank counting in fixed-length base127. Every preorder-tree node and rejected interval checked; coverage of all2^107 assignments and every candidate reconstructed. Previous partial journal hash unchanged and all177 old candidates recovered.' };
  fs.writeFileSync(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
main();

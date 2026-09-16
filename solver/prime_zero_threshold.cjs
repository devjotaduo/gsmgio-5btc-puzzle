'use strict';
// Minimum alias cardinality in the surviving prime-alphabet/space-zero model.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { machine, parse } = require('./prime_space_dfa.cjs');
const { machine: reverseMachine } = require('./verify_rsa_pending_dfa.cjs');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/unbounded_zero_codepoints_2026-09-16'), sha = b => crypto.createHash('sha256').update(b).digest('hex');
function subsets(k) { const out = []; for (let mask = 0; mask < 512; mask++) if (mask.toString(2).replace(/0/g, '').length === k) out.push(mask); return out; }
function search(sources, k, m, reverse = false, stopAtFirst = true) {
  const masks = subsets(k), mapping = new Uint8Array(9), used = new Uint8Array(10), codes = new Uint8Array(9), found = [null, null], comparisons = [0, 0]; let permutations = 0;
  const transition = reverse ? m.transitions : m.transition, accept = s => reverse ? m.accepting[s] : s & 1;
  function test() {
    for (const mask of masks) {
      for (let i = 0; i < 9; i++) codes[i] = mapping[i] - 1 + (mask >> i & 1 ? 9 : 0);
      for (let f = 0; f < 2; f++) if (!stopAtFirst || !found[f]) {
        comparisons[f]++; let state = 1; for (const c of sources[f]) { state = transition[state * 18 + codes[c]]; if (!state) break; }
        if (accept(state) && !found[f]) found[f] = { mapping: [...mapping], mask };
      }
    }
    permutations++;
  }
  function lex(at) { if (stopAtFirst && found.every(Boolean)) return; if (at === 9) { test(); return; } for (let d = 1; d <= 9; d++) if (!used[d]) { used[d] = 1; mapping[at] = d; lex(at + 1); used[d] = 0; } }
  function heap(n) { if (n === 1) { test(); return; } heap(n - 1); for (let i = 0; i < n - 1; i++) { const j = n % 2 ? 0 : i; [mapping[j], mapping[n - 1]] = [mapping[n - 1], mapping[j]]; heap(n - 1); } }
  if (reverse) { mapping.set([1, 2, 3, 4, 5, 6, 7, 8, 9]); heap(9); } else lex(0);
  const full = 362880 * masks.length; for (let f = 0; f < 2; f++) if (!found[f]) assert.equal(comparisons[f], full);
  return { zeroCapacity: k, subsets: masks.length, fullDomainPerDirection: full, permutations, comparisons, found };
}
function main() {
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), m = machine(), src = [[...input.faed], [...input.faed].reverse()].map(s => s.map(c => c.charCodeAt(0) - 97));
  const prior = JSON.parse(fs.readFileSync(path.join(root, '_work/prime_codepoints_2026-09-16/space_dfa_verification.json'))); assert(prior.complete); assert.deepEqual(prior.positiveConfigurations.slice(2), [0, 0]);
  const records = [], start = Date.now(); let solved = false;
  for (let k = 3; k <= 9 && !solved; k++) {
    const r = search(src, k, m); records.push(r); console.log(JSON.stringify({ k, comparisons: r.comparisons, positive: r.found.map(Boolean), elapsedMs: Date.now() - start }));
    if (r.found.some(Boolean)) { assert(r.found.every(Boolean), 'Different thresholds require per-direction continuation'); solved = true; }
  }
  assert(solved);
  const sieve = new Uint8Array(102), primes = []; for (let n = 2; n < 102; n++) if (!sieve[n]) { primes.push(n); for (let k = n * n; k < 102; k += n) sieve[k] = 1; }
  const words = [{ word: '0', m: 32 }, ...primes.map((p, i) => ({ word: String(p), m: 65 + i }))], reversed = reverseMachine(words), checks = [];
  for (const r of records.slice(0, -1)) { const v = search(src.map(s => [...s].reverse()), r.zeroCapacity, reversed, true, false); assert(v.found.every(x => x === null)); checks.push(v); }
  const last = records.at(-1), witnesses = [];
  for (let f = 0; f < 2; f++) {
    const r = last.found[f], pair = Array.from({ length: 9 }, (_, i) => i).filter(i => r.mask >> i & 1), w = parse(src[f], r.mapping, pair, m.words); assert(w);
    let at = 0; const usedZeros = new Set(); for (const b of w.blocks) { const word = words.find(x => x.m === b.m).word; assert.equal(b.start, at); for (const d of word) { if (d === '0') { assert(pair.includes(src[f][at])); usedZeros.add(src[f][at]); } else assert.equal(+d, r.mapping[src[f][at]]); at++; } assert.equal(at, b.end); }
    assert.equal(at, src[f].length); assert.equal(usedZeros.size, last.zeroCapacity); witnesses.push({ field: 'faed', reverse: Boolean(f), mapping: r.mapping, zeroLetters: pair.map(i => String.fromCharCode(97 + i)).join(''), ...w });
  }
  const result = { complete: true, model: 'Canonical A=p1..Z=p26, space=0, minimal decimal, any positive-digit bijection, optional zero per occurrence. FAED both directions; excludes trivial all-space reading at the reported threshold because fewer than9 letters are zero-capable.', minimumZeroCapacities: [last.zeroCapacity, last.zeroCapacity], producer: records, independentNegativeChecks: checks, priorTwoAliasVerificationSHA256: sha(fs.readFileSync(path.join(root, '_work/prime_codepoints_2026-09-16/space_dfa_verification.json'))), witnesses, sourceSHA256: sha(fs.readFileSync(__filename)), inputSHA256: sha(inputRaw), elapsedMs: Date.now() - start };
  fs.writeFileSync(path.join(out, 'prime_zero_threshold.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify({ complete: true, minimumZeroCapacities: result.minimumZeroCapacities, witnesses: witnesses.map(w => ({ zeroLetters: w.zeroLetters, paths: w.paths, text: Buffer.from(w.witnessHex, 'hex').toString('ascii') })), elapsedMs: result.elapsedMs }));
}
if (require.main === module) main();
module.exports = { subsets, search };

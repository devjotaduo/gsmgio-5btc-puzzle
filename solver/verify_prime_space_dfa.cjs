'use strict';
// Independent reverse-word automaton and non-lexicographic permutation order.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/prime_codepoints_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function main() {
  const spec = JSON.parse(fs.readFileSync(path.join(out, 'space_dfa_spec.json'))), summary = JSON.parse(fs.readFileSync(path.join(out, 'space_dfa_summary.json'))), inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw);
  assert(summary.complete); assert.equal(sha(inputRaw), spec.inputSHA256); assert.equal(sha(fs.readFileSync(path.join(__dirname, 'prime_space_dfa.cjs'))), spec.sourceSHA256);
  const flags = fs.readFileSync(path.join(out, 'space_dfa_flags.bin')), recordsRaw = fs.readFileSync(path.join(out, 'space_dfa_results.jsonl')), records = recordsRaw.toString().trim().split(/\r?\n/).map(JSON.parse), positives = new Map(records.map(r => [[r.permutation, r.pairIndex, r.fieldIndex].join('/'), r]));
  assert.equal(sha(flags), summary.flagsSHA256); assert.equal(sha(recordsRaw), summary.resultsSHA256); assert.equal(positives.size, records.length);
  const sieve = Array(102).fill(true); sieve[0] = sieve[1] = false; for (let n = 2; n < 102; n++) if (sieve[n]) for (let k = n * n; k < 102; k += n) sieve[k] = false;
  const ps = sieve.flatMap((yes, n) => yes ? [n] : []); assert.equal(ps.length, 26);
  const words = [{ word: '0', m: 32 }, ...ps.map((p, i) => ({ word: String(p), m: 65 + i }))]; assert.deepEqual(words, spec.words);
  const reversed = words.map(w => w.word.split('').reverse().join('')), prefix = [''];
  for (const word of reversed) for (let i = 1; i < word.length; i++) if (!prefix.includes(word.slice(0, i))) prefix.push(word.slice(0, i));
  assert.equal(prefix.length, 6); const states = 1 << prefix.length, transitions = new Uint8Array(states * 18), acceptsWord = new Set(reversed);
  for (let state = 0; state < states; state++) for (let option = 0; option < 18; option++) {
    const digits = option < 9 ? [option + 1] : [option - 8, 0]; let result = 0;
    for (let at = 0; at < prefix.length; at++) if (state & (1 << at)) for (const digit of digits) {
      const next = prefix[at] + digit; if (acceptsWord.has(next)) result |= 1; const p = prefix.indexOf(next); if (p > 0) result |= 1 << p;
    }
    transitions[state * 18 + option] = result;
  }
  const sources = spec.fields.map(r => [...(r.reverse ? input[r.field] : [...input[r.field]].reverse().join(''))].map(c => c.charCodeAt(0) - 97));
  const factorial = [1]; for (let i = 1; i <= 9; i++) factorial.push(factorial[i - 1] * i);
  const permutation = Array.from({ length: 9 }, (_, i) => i + 1), visited = new Uint8Array(362880), counts = [0, 0, 0, 0], groups = counts.map(() => 0n), options = new Uint8Array(9); let permutations = 0, comparisons = 0, witnesses = 0; const start = Date.now();
  function rank(p) { let n = 0; for (let i = 0; i < 9; i++) for (let j = i + 1; j < 9; j++) if (p[j] < p[i]) n += factorial[8 - i]; return n; }
  function checkRecord(r, pair) {
    const source = [...(r.reverse ? [...input[r.field]].reverse().join('') : input[r.field])].map(c => c.charCodeAt(0) - 97), tail = Array(source.length + 1).fill(0n); tail[source.length] = 1n;
    for (let at = source.length - 1; at >= 0; at--) for (const w of words) {
      const end = at + w.word.length; if (end > source.length || !tail[end]) continue; let okay = true;
      for (let k = 0; k < w.word.length; k++) if (w.word[k] === '0' ? !pair.includes(source[at + k]) : permutation[source[at + k]] !== +w.word[k]) { okay = false; break; }
      if (okay) tail[at] += tail[end];
    }
    assert.equal(String(tail[0]), r.paths); let at = 0; const text = [];
    for (const b of r.blocks) {
      assert.equal(b.start, at); const word = b.m === 32 ? '0' : String(ps[b.m - 65]); assert.equal(b.c, +word); assert.equal(b.end, at + word.length);
      for (let k = 0; k < word.length; k++) assert(word[k] === '0' ? pair.includes(source[at + k]) : permutation[source[at + k]] === +word[k]);
      at = b.end; text.push(b.m);
    }
    assert.equal(at, source.length); assert.equal(Buffer.from(text).toString('hex'), r.witnessHex); witnesses++; return tail[0];
  }
  function test() {
    const pi = rank(permutation); assert(!visited[pi]); visited[pi] = 1;
    for (let a = 0; a < 9; a++) for (let b = a + 1; b < 9; b++) {
      const pairIndex = a * (17 - a) / 2 + b - a - 1;
      for (let i = 0; i < 9; i++) options[i] = permutation[i] - 1 + (i === a || i === b ? 9 : 0);
      for (let field = 0; field < 4; field++) {
        let state = 1; for (const symbol of sources[field]) { state = transitions[state * 18 + options[symbol]]; if (!state) break; }
        const okay = Number(Boolean(state & 1)); assert.equal(flags[(pi * 36 + pairIndex) * 4 + field], okay); comparisons++;
        if (okay) {
          const key = [pi, pairIndex, field].join('/'), r = positives.get(key); assert(r); positives.delete(key); assert.deepEqual(r.mapping, permutation); assert.equal(r.zeroLetters, String.fromCharCode(97 + a, 97 + b)); groups[field] += checkRecord(r, [a, b]); counts[field]++;
        }
      }
    }
    permutations++;
  }
  // Heap's permutation algorithm; index each result by an independent Lehmer rank.
  function heap(n) { if (n === 1) { test(); return; } heap(n - 1); for (let i = 0; i < n - 1; i++) { const j = n % 2 ? 0 : i; [permutation[j], permutation[n - 1]] = [permutation[n - 1], permutation[j]]; heap(n - 1); } }
  heap(9); assert(visited.every(Boolean)); assert.equal(positives.size, 0); assert.equal(comparisons, summary.configurations); assert.equal(witnesses, records.length);
  for (let i = 0; i < 4; i++) { assert.equal(counts[i], summary.groups[i].compatible); assert.equal(String(groups[i]), summary.groups[i].paths); }
  const result = { complete: true, permutations, comparisons, reversedNFAStates: prefix.length, positiveConfigurations: counts, verifiedPathCounts: witnesses, checkedWitnesses: witnesses, flagsSHA256: sha(flags), resultsSHA256: sha(recordsRaw), verifierSHA256: sha(fs.readFileSync(__filename)), elapsedMs: Date.now() - start, method: 'Reverse every decimal word and source; independent six-state NFA, sieve prime table, Heap permutations with Lehmer indexing. All52,254,720 decisions matched; suffix DP reproduces each positive path count and every stored witness is recoded.' };
  fs.writeFileSync(path.join(out, 'space_dfa_verification.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
}
main();

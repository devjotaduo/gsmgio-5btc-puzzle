'use strict';
// Exhaustive bijections/zero-pair configurations using a precomputed digit NFA.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..'), out = path.join(root, '_work/prime_codepoints_2026-09-16');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function prime(n) { if (n < 2) return false; for (let k = 2; k * k <= n; k++) if (n % k === 0) return false; return true; }
function machine() {
  const ps = []; for (let n = 2; ps.length < 26; n++) if (prime(n)) ps.push(n);
  const words = [{ word: '0', m: 32 }, ...ps.map((p, i) => ({ word: String(p), m: 65 + i }))];
  const prefixes = ['']; for (const w of words) for (let k = 1; k < w.word.length; k++) if (!prefixes.includes(w.word.slice(0, k))) prefixes.push(w.word.slice(0, k));
  assert.equal(prefixes.length, 11); const lookup = new Map(words.map(w => [w.word, w.m])), one = Array.from({ length: prefixes.length }, () => new Uint16Array(10));
  for (const [i, p] of prefixes.entries()) for (let d = 0; d <= 9; d++) { const value = p + d; if (lookup.has(value)) one[i][d] |= 1; const at = prefixes.indexOf(value); if (at > 0) one[i][d] |= 1 << at; }
  const stateCount = 1 << prefixes.length, transition = new Uint16Array(stateCount * 18);
  for (let state = 0; state < stateCount; state++) {
    const next = new Uint16Array(10); for (let i = 0; i < prefixes.length; i++) if (state >> i & 1) for (let d = 0; d <= 9; d++) next[d] |= one[i][d];
    for (let d = 1; d <= 9; d++) { transition[state * 18 + d - 1] = next[d]; transition[state * 18 + d + 8] = next[d] | next[0]; }
  }
  return { words, prefixes, transition, stateCount };
}
function accepts(source, mapping, zeroPair, transition) {
  const code = mapping.map((d, i) => d - 1 + (zeroPair.includes(i) ? 9 : 0)); let state = 1;
  for (const symbol of source) { state = transition[state * 18 + code[symbol]]; if (!state) return false; }
  return Boolean(state & 1);
}
function parse(source, mapping, zeroPair, words) {
  const dp = Array(source.length + 1).fill(0n), parent = Array(source.length + 1).fill(null); dp[0] = 1n;
  for (let at = 0; at < source.length; at++) if (dp[at]) for (const w of words) {
    if (at + w.word.length > source.length) continue; let okay = true;
    for (let i = 0; i < w.word.length; i++) if (w.word[i] === '0' ? !zeroPair.includes(source[at + i]) : +w.word[i] !== mapping[source[at + i]]) { okay = false; break; }
    if (okay) { const end = at + w.word.length; dp[end] += dp[at]; if (!parent[end]) parent[end] = { at, m: w.m, c: +w.word }; }
  }
  if (!dp[source.length]) return null;
  const blocks = []; let end = source.length; while (end) { const p = parent[end]; assert(p); blocks.push({ start: p.at, end, m: p.m, c: p.c }); end = p.at; }
  blocks.reverse(); return { paths: String(dp[source.length]), witnessHex: Buffer.from(blocks.map(b => b.m)).toString('hex'), blocks };
}
function controls(m) {
  let checked = 0;
  for (let seed = 0; seed < 180; seed++) {
    const mapping = Array.from({ length: 9 }, (_, i) => (i + seed % 9) % 9 + 1), pair = [seed % 9, (seed % 9 + 1 + Math.floor(seed / 9) % 8) % 9];
    const source = Array.from({ length: 3 + seed % 12 }, (_, i) => (seed * 7 + i * i + 3 * i) % 9);
    assert.equal(accepts(source, mapping, pair, m.transition), Boolean(parse(source, mapping, pair, m.words))); checked++;
  }
  for (const text of ['THE MATRIX HAS YOU', 'PRIME BASICS', 'HELLO WORLD']) {
    const mapping = [6, 2, 7, 1, 8, 4, 9, 5, 3], inverse = new Map(mapping.map((d, i) => [String(d), i])), pair = [1, 4], codes = new Map(m.words.map(w => [w.m, w.word])); let z = 0;
    const source = [...Buffer.from(text)].flatMap(b => [...codes.get(b)].map(d => d === '0' ? pair[z++ % 2] : inverse.get(d)));
    assert(accepts(source, mapping, pair, m.transition)); assert(parse(source, mapping, pair, m.words)); checked++;
  }
  return checked;
}
function main() {
  assert(!fs.existsSync(path.join(out, 'space_dfa_results.jsonl')), 'Inspect previous enumeration first');
  const inputRaw = fs.readFileSync(path.join(root, '_work/prime_geometry_2026-09-11/inputs.json')), input = JSON.parse(inputRaw), m = machine(), checked = controls(m), pairs = [];
  for (let a = 0; a < 9; a++) for (let b = a + 1; b < 9; b++) pairs.push([a, b]);
  const fields = []; for (const field of ['dbbi', 'faed']) for (const reverse of [false, true]) fields.push({ field, reverse, source: [...(reverse ? [...input[field]].reverse().join('') : input[field])].map(c => c.charCodeAt(0) - 97) });
  const spec = { scope: 'Canonical A=p1..Z=p26, space=0, minimal decimal words. Every one of9! positive-digit bijections, every pair of distinct zero-capable letters, four full fields/directions. Exactly-two capability sets include all none/one/two actual-zero cases because unused capability imposes no requirement. The NFA unions positive and zero choices and all token boundaries; accepting states prove only grammar. Saves one witness and an exact path count for each compatible configuration, not every plaintext.', fields: fields.map(({ source, ...r }) => ({ ...r, length: source.length })), zeroPairs: pairs, prefixes: m.prefixes, words: m.words, controls: checked, inputSHA256: sha(inputRaw), sourceSHA256: sha(fs.readFileSync(__filename)), transitionSHA256: sha(Buffer.from(m.transition.buffer)) };
  fs.writeFileSync(path.join(out, 'space_dfa_spec.json'), JSON.stringify(spec, null, 2) + '\n');
  const fd = fs.openSync(path.join(out, 'space_dfa_results.jsonl'), 'wx'), flags = Buffer.alloc(362880 * 36 * 4), groups = fields.map(f => ({ field: f.field, reverse: f.reverse, configurations: 0, compatible: 0, paths: 0n }));
  let permutations = 0, offset = 0; const start = Date.now(), mapping = new Uint8Array(9), used = new Uint8Array(10), codes = new Uint8Array(9);
  function visit(at) {
    if (at < 9) { for (let d = 1; d <= 9; d++) if (!used[d]) { used[d] = 1; mapping[at] = d; visit(at + 1); used[d] = 0; } return; }
    for (const [pairIndex, pair] of pairs.entries()) {
      for (let i = 0; i < 9; i++) codes[i] = mapping[i] - 1 + (pair[0] === i || pair[1] === i ? 9 : 0);
      for (const [fieldIndex, f] of fields.entries()) {
        let state = 1; for (let i = 0; i < f.source.length && state; i++) state = m.transition[state * 18 + codes[f.source[i]]];
        const okay = Boolean(state & 1); flags[offset++] = Number(okay); groups[fieldIndex].configurations++;
        if (okay) {
          const r = parse(f.source, [...mapping], pair, m.words); assert(r); groups[fieldIndex].compatible++; groups[fieldIndex].paths += BigInt(r.paths);
          fs.writeSync(fd, JSON.stringify({ permutation: permutations, pairIndex, fieldIndex, field: f.field, reverse: f.reverse, mapping: [...mapping], zeroLetters: pair.map(i => String.fromCharCode(97 + i)).join(''), ...r }) + '\n');
        }
      }
    }
    permutations++; if (permutations % 100000 === 0) console.log(JSON.stringify({ permutations, configurations: offset, compatible: groups.map(g => g.compatible), elapsedMs: Date.now() - start }));
  }
  visit(0); fs.closeSync(fd); assert.equal(permutations, 362880); assert.equal(offset, flags.length); fs.writeFileSync(path.join(out, 'space_dfa_flags.bin'), flags);
  const result = { complete: true, permutations, zeroPairs: pairs.length, configurations: offset, groups, elapsedMs: Date.now() - start, flagsSHA256: sha(flags), resultsSHA256: sha(fs.readFileSync(path.join(out, 'space_dfa_results.jsonl'))) };
  fs.writeFileSync(path.join(out, 'space_dfa_summary.json'), JSON.stringify(result, (_, v) => typeof v === 'bigint' ? String(v) : v, 2) + '\n'); console.log(JSON.stringify(result, (_, v) => typeof v === 'bigint' ? String(v) : v));
}
if (require.main === module) main();
module.exports = { machine, accepts, parse };
